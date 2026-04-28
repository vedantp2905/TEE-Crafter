import socket
import sys
import json
import logging
import ssl
import os
import hashlib
import base64
import struct
import signal
import subprocess

_shutdown = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

LISTEN_PORT = 5005
MAX_PAYLOAD_SIZE = 64 * 1024 * 1024  # 64 MB

# ==========================================
# PROXY IMPORTS (injected by TEE-Crafter at staging time)
# ==========================================
{user_imports}

# ==========================================
# process_request body (injected by TEE-Crafter — proxy or batch runner)
# ==========================================
def process_request(data):
    """Platform-owned dispatch slot (injected at deploy time).

    Persistent: forwards attested requests to the user container.
    Batch: wired to the batch runner when applicable.
    Operators never implement this function.
    """
{user_logic}

# ==========================================

# ==========================================
# RUNTIME AUDIT LOGGING (injected by TEE-Crafter)
# ==========================================
try:
    import tee_crafter_audit_logger
    process_request = tee_crafter_audit_logger.wrap_process_request(process_request)
except ImportError:
    pass

try:
    import siem_health
    process_request = siem_health.fail_closed_wrap(process_request)
except ImportError:
    pass

# BYOK fail-closed gate.  Production default (TEE_CRAFTER_BYOK_FAIL_OPEN=0):
# refuses requests when BYOK was requested but the attested DEK release did
# not land.  Dev hatch TEE_CRAFTER_BYOK_FAIL_OPEN=1 disables.
try:
    import byok_health
    process_request = byok_health.fail_closed_wrap(process_request)
except ImportError:
    pass

try:
    import tee_crafter_handler_sandbox
    process_request = tee_crafter_handler_sandbox.sandbox_wrap(process_request)
except ImportError:
    pass

# ==========================================
# TEMPLATE CODE (TCB) — all security-critical logic below
# ==========================================

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import time as _time
import threading as _threading

# ---------------------------------------------------------------------------
# AUD-3: audit-log chain-key commitment + attestation binding preimage
# ---------------------------------------------------------------------------
# The in-TEE runtime audit log is an HMAC hash chain whose key exists only
# in encrypted guest memory.  tee_crafter_audit_logger computes a SHA-256
# commitment to that key and writes it into the log's genesis entry.  On its
# own that is self-referential: a host-level adversary who controls the VM
# can throw the log away, mint a fresh HMAC key, write a fresh genesis entry
# and a fresh chain, and publish the matching commitment.  Folding the
# commitment into the attestation binding preimage puts it under the
# hardware signature, which finally gives an external verifier a value it
# can pin.  See templates/common/tee_crafter_audit_logger.py.
_CHAIN_KEY_COMMITMENT = ""
try:
    import tee_crafter_runtime_bootstrap as _tc_bootstrap
    # Returns the commitment hex *and* publishes it to tmpfs for the SIEM
    # sidecar (siem_export.read_chain_key_commitment) in one call.
    _CHAIN_KEY_COMMITMENT = _tc_bootstrap.bootstrap_chain_commitment()
except Exception as _cc_exc:
    logging.warning("[SNP/Azure] chain-commitment bootstrap unavailable: %r", _cc_exc)
if not _CHAIN_KEY_COMMITMENT:
    # Publication can fail on a read-only /run while the key itself is
    # perfectly good.  Read it straight out of the in-process logger so the
    # hardware binding still happens.
    try:
        _CHAIN_KEY_COMMITMENT = tee_crafter_audit_logger.get_chain_key_commitment()
    except Exception:
        _CHAIN_KEY_COMMITMENT = ""
if _CHAIN_KEY_COMMITMENT:
    logging.info("[SNP/Azure] audit-log chain-key commitment bound into attestation "
                 "evidence: %s", _CHAIN_KEY_COMMITMENT)
else:
    logging.warning(
        "[SNP/Azure] no audit-log chain-key commitment is available; attestation "
        "evidence will declare an empty commitment and clients fail closed "
        "unless TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1 is set")

_ATTEST_BINDING_LABEL = b"tee-crafter/attest-binding/v2"


def _attest_binding_preimage(*fields: bytes) -> bytes:
    """Encode *fields* into one unambiguous attestation-binding preimage.

    v1 concatenated the fields raw (``nonce || tls_spki_der``), which is
    ambiguous: ``nonce=b"ab", spki=b"cd"`` and ``nonce=b"abc", spki=b"d"``
    hash to the same value, so evidence minted for one field split could be
    presented as satisfying a different one.  Here every field carries its
    own big-endian uint32 length prefix, the field *count* is prefixed too
    (so a short field list cannot be padded out into a longer one), and the
    whole encoding is prefixed with a version label so a v1 preimage can
    never be reinterpreted as a v2 one.  Clients recompute this
    byte-for-byte, which is why the label is part of the hashed bytes
    rather than just a comment.
    """
    parts = [struct.pack("!I", len(_ATTEST_BINDING_LABEL)),
             _ATTEST_BINDING_LABEL,
             struct.pack("!I", len(fields))]
    for _field in fields:
        parts.append(struct.pack("!I", len(_field)))
        parts.append(_field)
    return b"".join(parts)


def _attest_binding_digest(*fields: bytes) -> bytes:
    """SHA-256 over :func:`_attest_binding_preimage`."""
    return hashlib.sha256(_attest_binding_preimage(*fields)).digest()


#: Machine-readable description of the live-challenge preimage, echoed to
#: clients so they never have to guess which bytes to recompute.  ``lp(x)``
#: means ``uint32be(len(x)) || x``.
_LIVE_CHALLENGE_BINDING_DESC = (
    "sha256(lp('tee-crafter/attest-binding/v2') || uint32be(3) || "
    "lp(nonce_ascii) || lp(tls_spki_der) || lp(chain_key_commitment_hex_ascii))")


_MAX_CONN_PER_SEC = 10
_conn_timestamps: list[float] = []

# Serialise all SNP attestation calls inside this process (request handler
# vs. attestation-monitor background thread).  See SNP-GCP template for
# the original race-condition incident write-up.
_SNP_ATTEST_LOCK = _threading.Lock()


def _rate_limit_check() -> bool:
    """Return True if the connection should be accepted (within rate limit)."""
    now = _time.monotonic()
    _conn_timestamps[:] = [t for t in _conn_timestamps if now - t < 1.0]
    if len(_conn_timestamps) >= _MAX_CONN_PER_SEC:
        return False
    _conn_timestamps.append(now)
    return True


_ECDH_KEY = ec.generate_private_key(ec.SECP256R1())
_ECDH_PUB = _ECDH_KEY.public_key()
_ECDH_PUB_BYTES = _ECDH_PUB.public_bytes(
    serialization.Encoding.X962,
    serialization.PublicFormat.UncompressedPoint,
)
_ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode("utf-8")


def _rotate_ecdh_key():
    """Regenerate the ECDH keypair (call before refreshing RA-TLS cert)."""
    global _ECDH_KEY, _ECDH_PUB, _ECDH_PUB_BYTES, _ECDH_PUB_B64
    _ECDH_KEY = ec.generate_private_key(ec.SECP256R1())
    _ECDH_PUB = _ECDH_KEY.public_key()
    _ECDH_PUB_BYTES = _ECDH_PUB.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    _ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode("utf-8")
    logging.info("[SNP/Azure] ECDH keypair rotated")


_CERT_ROTATION_SECS = 3600

# --- Key rotation manager integration ---
try:
    import tee_crafter_key_rotation as _kr
    _kr.configure(rotation_interval_secs=_CERT_ROTATION_SECS)
    _kr.record_key_birth("ecdh-boot-0", _ECDH_PUB_BYTES, key_type="ECDH-P256")
    _kr_available = True
except ImportError:
    _kr_available = False


# ---------------------------------------------------------------------------
# AMD SEV-SNP attestation for Azure
#
# Azure Hyper-V CVMs do NOT expose /dev/sev-guest (that device is for KVM
# guests).  Instead the SNP attestation report is obtained via the vTPM:
#
#   vTPM NV index 0x01400001 — contains an HCL (Hyper-V Compatibility Layer)
#   report whose first 32 bytes are a header (magic "HCLA"), followed by the
#   standard 1184-byte AMD SNP attestation report.
#
# VCEK certificates come from Azure IMDS:
#   http://169.254.169.254/metadata/THIM/amd/certification
#
# Attestation probe order:
#   1. vTPM HCL report  (primary — works on all Azure CVMs)
#   2. /dev/sev-guest ioctl  (fallback for KVM-based environments)
#   3. snpguest CLI  (best-effort fallback)
# ---------------------------------------------------------------------------

def _sev_guest_device() -> str | None:
    for path in ("/dev/sev-guest", "/dev/sev"):
        if os.path.exists(path):
            return path
    return None

_SNP_REPORT_USER_DATA_SIZE = 64
_SNP_REPORT_REQ_SIZE = 96
_SNP_REPORT_RESP_SIZE = 4000
_SNP_ATTESTATION_REPORT_SIZE = 1184

_HCL_HEADER_SIZE = 32
_HCL_MAGIC = b"HCLA"

_OFF_VERSION = 0x00
_OFF_GUEST_SVN = 0x04
_OFF_POLICY = 0x08
_OFF_VMPL = 0x30
_OFF_SIG_ALGO = 0x34
_OFF_CURRENT_TCB = 0x38
_OFF_PLAT_INFO = 0x40
_OFF_REPORT_DATA = 0x50
_OFF_MEASUREMENT = 0x90
_OFF_HOST_DATA = 0xC0
_OFF_ID_KEY_DIGEST = 0xE0
_OFF_AUTHOR_KEY_DIGEST = 0x110
_OFF_REPORT_ID = 0x140
_OFF_REPORTED_TCB = 0x180
_OFF_CHIP_ID = 0x1A0
_OFF_COMMITTED_TCB = 0x1E0
_OFF_LAUNCH_TCB = 0x1F0
_OFF_SIGNATURE = 0x2A0

_TPM_NV_INDEX_HCL = "0x01400001"

_AESGCM_AAD_REQ = b"tee-crafter-snp-v1-req"
_AESGCM_AAD_RESP = b"tee-crafter-snp-v1-resp"

# AMD ABI 56860: REPORTED_TCB bits 55:48 = SNP firmware SVN (Milan/Genoa/Bergamo class).
# AMD-SB-3015 minimum mitigated SPL is per family: Genoa-class 0x16, Milan-class 0x17.
# This boot-time gate enforces the single Genoa-class floor (0x16) and nothing higher:
# the guest has no trustworthy CPU-family signal to branch on.  The family-aware floor
# is applied client-side, where the AMD root chain that validated the endorsement cert
# identifies the family (see verify_tcb_version in snp/<cloud>/client.template.py).
_MIN_SNP_FIRMWARE_SVN = 0x16
_PLATFORM_INFO_ALIAS_CHECK_COMPLETE = 1 << 5


def _generate_snp_report_data(user_data: bytes) -> bytes:
    digest = hashlib.sha256(user_data).digest()
    return digest.ljust(_SNP_REPORT_USER_DATA_SIZE, b'\x00')[:_SNP_REPORT_USER_DATA_SIZE]


def _find_snpguest() -> str | None:
    import shutil
    path = shutil.which("snpguest")
    if path:
        return path
    for candidate in ["/usr/local/bin/snpguest", "/opt/snpguest/target/release/snpguest"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _get_snp_report_via_vtpm() -> bytes | None:
    """
    Primary Azure path: read the HCL attestation report from vTPM NV
    index 0x01400001 and extract the embedded SNP attestation report.

    The HCL report layout is:
      Bytes  0-31:  HCL header (magic "HCLA", version, size, type)
      Bytes 32-1215: AMD SNP attestation report (1184 bytes)
    """
    try:
        result = subprocess.run(
            ["tpm2_nvread", _TPM_NV_INDEX_HCL, "-C", "o", "-s", "2600"],
            capture_output=True, timeout=15,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace").strip()
            logging.warning("[SNP/Azure] tpm2_nvread 0x01400001 failed: %s", stderr)
            return None

        hcl_report = result.stdout
        min_size = _HCL_HEADER_SIZE + _SNP_ATTESTATION_REPORT_SIZE
        if len(hcl_report) < min_size:
            logging.warning("[SNP/Azure] HCL report too small: %d bytes (need %d)",
                            len(hcl_report), min_size)
            return None

        if hcl_report[:4] != _HCL_MAGIC:
            logging.warning("[SNP/Azure] Bad HCL magic: %s", hcl_report[:4].hex())
            return None

        snp_report = hcl_report[_HCL_HEADER_SIZE:_HCL_HEADER_SIZE + _SNP_ATTESTATION_REPORT_SIZE]

        version = struct.unpack_from("<I", snp_report, 0)[0]
        if version < 2:
            logging.warning("[SNP/Azure] Unexpected SNP report version: %d", version)
            return None

        logging.info("[SNP/Azure] SNP report from vTPM HCL (version=%d, %d bytes)",
                     version, len(snp_report))
        return snp_report

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logging.warning("[SNP/Azure] vTPM read error: %s", e)
    return None



def _get_hcl_runtime_data() -> bytes | None:
    """Return the HCL *runtime data* blob the SNP report's REPORT_DATA commits to.

    This is what makes the vTPM attestation key cryptographically bound to the
    AMD-signed report, rather than merely presented alongside it.

    Layout, confirmed byte-for-byte on a live `Standard_DC2as_v5` on
    2026-08-23 (`tpm2_nvread 0x01400001`, 2600 bytes returned):

      * bytes 0..31      HCL header, magic ``HCLA``, version 2
      * bytes 32..1215   AMD SNP attestation report (1184 bytes)
      * bytes 1216..     framing, then a little-endian ``uint32`` length
                         immediately before a JSON document

    And the load-bearing fact::

        sha256(runtime_data) == snp_report[REPORT_DATA : REPORT_DATA + 32]

    which was verified on that host (`5901fcb0925d6ff4...`, with the remaining
    32 bytes of REPORT_DATA zero). The JSON carries
    ``keys[kid == "HCLAkPub"]`` -- a JWK for the RSA-2048 attestation key whose
    private half signs the TPM quote -- plus ``vm-configuration`` and
    ``user-data``.

    So AMD signs the report, the report commits to this JSON, and this JSON
    names the AK. Without it the client can only check that *some* AK signed a
    quote over the right nonce, which a foreign vTPM can also do; with it the
    AK is pinned by the AMD signature. See the client's
    ``verify_hcl_ak_binding``.

    Returns ``None`` rather than raising: on a host where the HCL framing is not
    what we expect, the caller degrades to the weaker binding and says so, which
    is better than failing to attest at all.
    """
    import subprocess as _sp

    try:
        result = _sp.run(
            ["tpm2_nvread", _TPM_NV_INDEX_HCL, "-C", "o", "-s", "2600"],
            capture_output=True, timeout=15,
        )
        if result.returncode != 0:
            return None
        blob = result.stdout
        if len(blob) < _HCL_HEADER_SIZE + _SNP_ATTESTATION_REPORT_SIZE + 8:
            return None
        if blob[:4] != _HCL_MAGIC:
            return None
        tail = blob[_HCL_HEADER_SIZE + _SNP_ATTESTATION_REPORT_SIZE:]
        start = tail.find(b"{")
        # Need 4 bytes of length prefix ahead of the JSON to trust the framing.
        if start < 4:
            return None
        declared = struct.unpack_from("<I", tail, start - 4)[0]
        if declared <= 0 or start + declared > len(tail):
            return None
        runtime_data = tail[start:start + declared]
        logging.info("[SNP/Azure] HCL runtime data: %d bytes", len(runtime_data))
        return runtime_data
    except Exception as exc:  # noqa: BLE001 - degrade, never block attestation
        logging.warning("[SNP/Azure] HCL runtime data unavailable: %s", exc)
        return None


def _get_snp_report_via_snpguest(report_data: bytes) -> bytes:
    """Obtain SNP attestation report using snpguest CLI (requires /dev/sev-guest)."""
    import tempfile

    rd_file = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    report_file = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    rd_file.close()
    report_file.close()

    try:
        with open(rd_file.name, "wb") as f:
            f.write(report_data)

        snpguest = _find_snpguest()
        if not snpguest:
            raise RuntimeError("snpguest not found in PATH or /usr/local/bin")

        result = subprocess.run(
            [snpguest, "report", report_file.name, rd_file.name],
            capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"snpguest report failed: {result.stderr.decode(errors='replace')}")

        with open(report_file.name, "rb") as f:
            report = f.read()

        if len(report) < _SNP_ATTESTATION_REPORT_SIZE:
            raise RuntimeError(f"SNP report too short: {len(report)} bytes")

        return report[:_SNP_ATTESTATION_REPORT_SIZE]
    finally:
        for p in (rd_file.name, report_file.name):
            try:
                os.unlink(p)
            except OSError:
                pass


def _get_snp_report_via_ioctl(report_data: bytes) -> bytes:
    """Obtain SNP attestation report via /dev/sev-guest ioctl (KVM path)."""
    import fcntl
    import ctypes

    dev = _sev_guest_device()
    if not dev:
        raise RuntimeError("/dev/sev-guest and /dev/sev not found")

    req = bytearray(_SNP_REPORT_REQ_SIZE)
    req[:_SNP_REPORT_USER_DATA_SIZE] = report_data[:_SNP_REPORT_USER_DATA_SIZE]
    struct.pack_into("<I", req, _SNP_REPORT_USER_DATA_SIZE, 0)  # vmpl = 0

    resp = bytearray(_SNP_REPORT_RESP_SIZE)
    req_buf = (ctypes.c_char * len(req)).from_buffer(req)
    resp_buf = (ctypes.c_char * len(resp)).from_buffer(resp)

    ioctl_struct = struct.pack(
        "<B7xQQQ",
        1,  # msg_version
        ctypes.addressof(req_buf),
        ctypes.addressof(resp_buf),
        0,  # fw_err
    )

    _SNP_GET_REPORT = 0xC0205300

    fd = os.open(dev, os.O_RDWR)
    try:
        fcntl.ioctl(fd, _SNP_GET_REPORT, ioctl_struct)
    finally:
        os.close(fd)

    status = struct.unpack_from("<I", resp, 0)[0]
    if status != 0:
        raise RuntimeError(f"SNP_GET_REPORT failed: status=0x{status:X}")

    report_offset = 32
    return bytes(resp[report_offset:report_offset + _SNP_ATTESTATION_REPORT_SIZE])


def _get_vcek_cert_from_imds() -> bytes:
    """
    Retrieve the VCEK certificate chain from Azure IMDS.
    Endpoint: http://169.254.169.254/metadata/THIM/amd/certification
    """
    import urllib.request
    url = "http://169.254.169.254/metadata/THIM/amd/certification"
    req = urllib.request.Request(url, headers={"Metadata": "true"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vcek_pem = data.get("vcekCert", "")
            cert_chain = data.get("certificateChain", "")
            combined = vcek_pem
            if cert_chain:
                combined += "\n" + cert_chain
            return combined.encode("utf-8")
    except Exception as e:
        logging.warning("[SNP/Azure] Failed to retrieve VCEK from IMDS: %s", e)
        return b""


_SNP_GET_EXT_REPORT = 0xC0205302

# Mixed-endian (GHCB ioctl) and RFC 4122 (configfs TSM) GUID variants
_GUID_VLEK_ME = bytes.fromhex("c24b07a8" "5aa2" "3e48" "aae639c045a0b8a1")
_GUID_VCEK_ME = bytes.fromhex("8d75da63" "64e6" "6445" "adc5f4b93be8accd")
_GUID_ASK_ME  = bytes.fromhex("79b3b74a" "acbb" "e44f" "a02f05aef327c782")
_GUID_ARK_ME  = bytes.fromhex("a406b4c0" "03a8" "5249" "97433fb6014b0ae8")


def _guid_to_rfc4122(me: bytes) -> bytes:
    return me[3::-1] + me[5:3:-1] + me[7:5:-1] + me[8:16]


_GUID_VLEK_BE = _guid_to_rfc4122(_GUID_VLEK_ME)
_GUID_VCEK_BE = _guid_to_rfc4122(_GUID_VCEK_ME)
_GUID_ASK_BE  = _guid_to_rfc4122(_GUID_ASK_ME)
_GUID_ARK_BE  = _guid_to_rfc4122(_GUID_ARK_ME)

_GUID_VLEK = {_GUID_VLEK_ME, _GUID_VLEK_BE}
_GUID_VCEK = {_GUID_VCEK_ME, _GUID_VCEK_BE}
_GUID_ASK  = {_GUID_ASK_ME,  _GUID_ASK_BE}
_GUID_ARK  = {_GUID_ARK_ME,  _GUID_ARK_BE}


def _do_ext_report_ioctl(dev: str, report_data: bytes, cert_buf_size: int) -> tuple[bytearray, bytes, int]:
    """Low-level SNP_GET_EXT_REPORT ioctl (two-phase capable)."""
    import fcntl
    import ctypes
    import errno as _errno

    req = bytearray(_SNP_REPORT_REQ_SIZE)
    req[:_SNP_REPORT_USER_DATA_SIZE] = report_data[:_SNP_REPORT_USER_DATA_SIZE]
    struct.pack_into("<I", req, _SNP_REPORT_USER_DATA_SIZE, 0)

    _EXT_REQ_SIZE = _SNP_REPORT_REQ_SIZE + 8 + 4 + 4
    ext_req = bytearray(_EXT_REQ_SIZE)
    ext_req[:_SNP_REPORT_REQ_SIZE] = req

    if cert_buf_size > 0:
        cert_buf = (ctypes.c_char * cert_buf_size)()
        struct.pack_into("<Q", ext_req, _SNP_REPORT_REQ_SIZE, ctypes.addressof(cert_buf))
    else:
        cert_buf = None
        struct.pack_into("<Q", ext_req, _SNP_REPORT_REQ_SIZE, 0)
    struct.pack_into("<I", ext_req, _SNP_REPORT_REQ_SIZE + 8, cert_buf_size)

    resp = bytearray(_SNP_REPORT_RESP_SIZE)
    req_buf = (ctypes.c_char * len(ext_req)).from_buffer(ext_req)
    resp_buf = (ctypes.c_char * len(resp)).from_buffer(resp)

    ioctl_buf = bytearray(struct.pack(
        "<I4xQQQ", 1,
        ctypes.addressof(req_buf), ctypes.addressof(resp_buf), 0,
    ))

    fd = os.open(dev, os.O_RDWR)
    try:
        fcntl.ioctl(fd, _SNP_GET_EXT_REPORT, ioctl_buf)
    except OSError as e:
        returned_len = struct.unpack_from("<I", ext_req, _SNP_REPORT_REQ_SIZE + 8)[0]
        logging.warning("[SNP/Azure] ext_report ioctl error: errno=%d, returned_certs_len=%d",
                        e.errno, returned_len)
        e.snp_required_certs_len = returned_len  # type: ignore[attr-defined]
        raise
    finally:
        os.close(fd)

    returned_len = struct.unpack_from("<I", ext_req, _SNP_REPORT_REQ_SIZE + 8)[0]
    logging.info("[SNP/Azure] ext_report ioctl OK: returned_certs_len=%d (buf=%d)",
                 returned_len, cert_buf_size)

    cert_bytes = bytes(cert_buf) if cert_buf else b""
    return resp, cert_bytes, returned_len


def _get_report_and_certs_via_ext_ioctl(report_data: bytes) -> tuple[bytes, bytes]:
    """Two-phase SNP_GET_EXT_REPORT (phase 1: probe size, phase 2: fetch)."""
    import errno as _errno

    dev = _sev_guest_device()
    if not dev:
        raise RuntimeError("/dev/sev-guest and /dev/sev not found")

    required_len = 0
    try:
        resp, _, returned_len = _do_ext_report_ioctl(dev, report_data, 0)
    except OSError as e:
        if e.errno == _errno.ENOSPC:
            required_len = getattr(e, "snp_required_certs_len", 0)
            logging.info("[SNP/Azure] ext_report phase 1: kernel needs %d bytes", required_len)
        else:
            returned_len = getattr(e, "snp_required_certs_len", 0)
            logging.warning("[SNP/Azure] ext_report phase 1 failed: errno=%d, "
                            "returned_certs_len=%d — retrying with buffer",
                            e.errno, returned_len)
            if returned_len > 0:
                required_len = returned_len

    # Honour the size the kernel asked for; do not substitute a larger floor.
    # SNP_GET_EXT_REPORT validates certs_len, and a value the VMM did not ask
    # for is rejected.  Measured on real AWS SEV-SNP (m6a, 2026-08-20) with the
    # old `max(required_len, 8 * 4096)`: phase 1 (certs_len=0) returned EIO /
    # vmm_err=0x1 (INVALID_LEN) with returned_certs_len=4096, phase 2 then asked
    # for 32768 and got EINVAL, so no report was ever produced and RA-TLS failed
    # with SSLEOFError.  The 32 KiB guess is kept only for the case where the
    # kernel reported no required length at all.
    buf_size = required_len if required_len > 0 else 8 * 4096
    resp, cert_bytes, returned_len = _do_ext_report_ioctl(dev, report_data, buf_size)

    status = struct.unpack_from("<I", resp, 0)[0]
    if status != 0:
        raise RuntimeError(f"SNP_GET_EXT_REPORT: firmware status=0x{status:X}")

    report_bytes = bytes(resp[32:32 + _SNP_ATTESTATION_REPORT_SIZE])

    non_zero = sum(1 for b in cert_bytes if b != 0)
    if non_zero == 0:
        raise RuntimeError("SNP_GET_EXT_REPORT succeeded but cert buffer is all zeros")

    endorsement_pem = _parse_cert_table(cert_bytes)
    return report_bytes, endorsement_pem


def _classify_guid(guid: bytes) -> str | None:
    for name, guid_set in (("VLEK", _GUID_VLEK), ("VCEK", _GUID_VCEK),
                           ("ASK", _GUID_ASK), ("ARK", _GUID_ARK)):
        if guid in guid_set:
            return name
    return None


def _parse_cert_table(raw: bytes) -> bytes:
    """Parse GHCB cert table → PEM chain. Handles both GUID byte orders."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    ENTRY_SIZE = 24
    pos = 0
    certs_by_type: dict[str, bytes] = {}

    while pos + ENTRY_SIZE <= len(raw):
        guid = raw[pos:pos + 16]
        offset = struct.unpack_from("<I", raw, pos + 16)[0]
        length = struct.unpack_from("<I", raw, pos + 20)[0]
        pos += ENTRY_SIZE
        if guid == b'\x00' * 16 and offset == 0 and length == 0:
            break
        if offset + length <= len(raw) and length > 0:
            cert_type = _classify_guid(guid)
            if cert_type:
                certs_by_type[cert_type] = raw[offset:offset + length]

    logging.info("[SNP/Azure] cert table: %d typed entries (VLEK=%s, VCEK=%s, ASK=%s, ARK=%s)",
                 len(certs_by_type),
                 "yes" if "VLEK" in certs_by_type else "no",
                 "yes" if "VCEK" in certs_by_type else "no",
                 "yes" if "ASK" in certs_by_type else "no",
                 "yes" if "ARK" in certs_by_type else "no")

    if not certs_by_type:
        raise RuntimeError("Certificate table is empty or has no recognized GUIDs")

    endorsement_der = certs_by_type.get("VLEK") or certs_by_type.get("VCEK")
    if not endorsement_der:
        raise RuntimeError("No VLEK or VCEK found in certificate table")

    def _der_to_pem(der: bytes) -> bytes:
        cert = x509.load_der_x509_certificate(der, default_backend())
        from cryptography.hazmat.primitives import serialization as _ser
        return cert.public_bytes(_ser.Encoding.PEM)

    parts = [_der_to_pem(endorsement_der)]
    for cert_name in ("ASK", "ARK"):
        if cert_name in certs_by_type:
            try:
                parts.append(_der_to_pem(certs_by_type[cert_name]))
            except Exception:
                pass

    return b"\n".join(parts)


def _get_vcek_certs_snpguest() -> bytes:
    """Retrieve VCEK certificate using snpguest certificates command (fallback)."""
    import tempfile, shutil

    cert_dir = tempfile.mkdtemp(prefix="snp_certs_")
    try:
        snpguest = _find_snpguest()
        if not snpguest:
            raise RuntimeError("snpguest not found")

        result = subprocess.run(
            [snpguest, "certificates", "pem", cert_dir],
            capture_output=True, timeout=30,
        )
        logging.info("[SNP/Azure] snpguest certificates rc=%d", result.returncode)

        for name in ("vcek.pem", "vlek.pem"):
            path = os.path.join(cert_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    return f.read()

        raise RuntimeError("No VCEK/VLEK certificate found")
    finally:
        shutil.rmtree(cert_dir, ignore_errors=True)


def _generate_tpm_quote(qualifying_data: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Generate a TPM2 Quote binding qualifying_data to the vTPM.

    Creates an ephemeral signing key in the owner hierarchy, then quotes
    PCR banks 0-3 with qualifying_data as the nonce.  The vTPM is
    hardware-attested by the SNP report, so a valid quote transitively
    proves that qualifying_data was signed inside this CVM.

    SNP-3: this function is the legacy single-shot path.  New code paths
    must use `_tpm_create_ak` + `_tpm_quote_with_ctx` so that the AK's
    public key can be hashed into the SNP report's user_data *before*
    the quote is produced, which binds the ephemeral AK cryptographically
    to the AMD-signed SNP attestation report and closes the AK-forgery
    gap where a rogue TPM outside the CVM could otherwise produce a
    valid-looking quote.

    Returns (quote_message, quote_signature, ak_pub_pem) or None.
    """
    ak_pub, ctx_dir, primary_ctx = _tpm_create_ak()
    try:
        msg, sig = _tpm_quote_with_ctx(primary_ctx, qualifying_data)
        logging.info("[SNP/Azure] TPM Quote generated (%d-byte msg, %d-byte sig)",
                     len(msg), len(sig))
        return msg, sig, ak_pub
    except Exception as e:
        logging.fatal("[SNP/Azure] TPM Quote generation failed — cannot bind ECDH key to vTPM: %s", e)
        sys.exit(1)
    finally:
        import shutil
        shutil.rmtree(ctx_dir, ignore_errors=True)


def _tpm_create_ak() -> tuple[bytes, str, str]:
    """SNP-3 helper: create an ephemeral RSA-2048 primary key in the
    owner hierarchy and read its public part.

    Returns (ak_pub_pem, ctx_dir, primary_ctx_path).  The caller is
    responsible for removing ``ctx_dir`` when finished with the context.
    """
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="tpm_ak_")
    try:
        primary_ctx = os.path.join(tmpdir, "primary.ctx")
        ak_pub_path = os.path.join(tmpdir, "ak.pub")
        subprocess.run(
            ["tpm2_createprimary", "-C", "o", "-G", "rsa2048", "-g", "sha256",
             "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
             "-c", primary_ctx],
            capture_output=True, timeout=15, check=True,
        )
        subprocess.run(
            ["tpm2_readpublic", "-c", primary_ctx, "-o", ak_pub_path, "-f", "pem"],
            capture_output=True, timeout=15, check=True,
        )
        with open(ak_pub_path, "rb") as f:
            pub = f.read()
        return pub, tmpdir, primary_ctx
    except Exception as e:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
        logging.fatal("[SNP/Azure] TPM AK creation failed: %s", e)
        sys.exit(1)


#: The paravisor's own attestation key.  Not an arbitrary choice and not a
#: key this guest creates: it is the key whose public half the HCL publishes
#: as ``keys[kid == "HCLAkPub"]`` inside the runtime data that
#: ``REPORT_DATA`` hashes, which is the only reason a verifier can root it in
#: AMD's signature.  Confirmed on tee-crafter-snp-vm-3515abcc, 2026-08-23:
#: the RSA modulus at this handle (``8CB54C6000007485B8D0563451E077DE...``)
#: is byte-identical to the HCLAkPub modulus in NV 0x01400001, and
#: ``REPORT_DATA[:32] == sha256(runtime_data)`` held on the same read.
_TPM_HCL_AK_HANDLE = "0x81000003"


def _tpm_hcl_ak() -> tuple[bytes, str] | None:
    """Return ``(ak_pub_pem, handle)`` for the AK the HCL vouches for, or None.

    Why this exists at all: an AK this guest mints itself cannot be attested.
    On the Azure vTPM path ``REPORT_DATA`` is fixed by the paravisor to
    ``sha256(runtime_data)``, so the guest cannot inject ``sha256(ak_pub)``
    into the AMD-signed region -- which leaves a verifier no way to tell a
    quote from *this* CVM's vTPM from a quote signed by an attacker's own TPM
    paired with a replayed SNP report.  The HCL AK closes that: it is already
    named in the runtime data that REPORT_DATA commits to, so the chain runs
    VCEK -> report -> REPORT_DATA -> runtime_data -> HCLAkPub -> quote.

    The handle is *verified*, not assumed.  We compare the modulus at the
    handle against the HCLAkPub modulus from the runtime data and only use it
    on an exact match, so an Azure change of handle layout degrades to the
    weaker ephemeral-AK path (which the client's strict gate then refuses)
    rather than silently quoting with a key nothing vouches for.
    """
    runtime_data = _get_hcl_runtime_data()
    if not runtime_data:
        logging.warning("[SNP/Azure] no HCL runtime data; cannot identify an "
                        "attested AK")
        return None
    try:
        doc = json.loads(runtime_data)
        wanted = None
        for key in doc.get("keys", []):
            if isinstance(key, dict) and key.get("kid") == "HCLAkPub":
                n = key.get("n", "")
                wanted = base64.urlsafe_b64decode(n + "=" * (-len(n) % 4))
                break
        if not wanted:
            logging.warning("[SNP/Azure] runtime data carries no HCLAkPub key")
            return None
    except Exception as exc:
        logging.warning("[SNP/Azure] could not parse HCL runtime data: %s", exc)
        return None

    candidates = [_TPM_HCL_AK_HANDLE]
    try:
        listed = subprocess.run(
            ["tpm2_getcap", "handles-persistent"],
            capture_output=True, timeout=15, check=True,
        ).stdout.decode("utf-8", "replace")
        for line in listed.splitlines():
            handle = line.strip().lstrip("-").strip()
            if handle.startswith("0x") and handle not in candidates:
                candidates.append(handle)
    except Exception as exc:
        logging.info("[SNP/Azure] could not enumerate persistent handles "
                     "(%s); trying %s only", exc, _TPM_HCL_AK_HANDLE)

    import shutil
    import tempfile
    for handle in candidates:
        tmpdir = tempfile.mkdtemp(prefix="tpm_hclak_")
        try:
            pub_path = os.path.join(tmpdir, "ak.pem")
            subprocess.run(
                ["tpm2_readpublic", "-c", handle, "-o", pub_path, "-f", "pem"],
                capture_output=True, timeout=15, check=True,
            )
            with open(pub_path, "rb") as f:
                pem = f.read()
            loaded = serialization.load_pem_public_key(pem)
            modulus = loaded.public_numbers().n.to_bytes(
                (loaded.public_numbers().n.bit_length() + 7) // 8, "big")
            if modulus == wanted.lstrip(b"\x00").rjust(len(modulus), b"\x00"):
                logging.info("[SNP/Azure] AK %s matches HCLAkPub — quoting with "
                             "the AMD-attested paravisor AK", handle)
                return pem, handle
        except Exception:
            continue
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    logging.warning(
        "[SNP/Azure] no persistent handle matched HCLAkPub; falling back to an "
        "ephemeral AK, which the client cannot root in AMD's signature")
    return None


def _tpm_quote_with_ctx(primary_ctx: str, qualifying_data: bytes) -> tuple[bytes, bytes]:
    """SNP-3 helper: run tpm2_quote against an existing primary context.

    ``primary_ctx`` is passed straight to ``tpm2_quote -c``, which accepts
    either a context file or a persistent handle, so this serves both the
    ephemeral-AK path and the HCL-AK path unchanged.

    The caller is expected to have already obtained ak_pub via
    `_tpm_create_ak` or :func:`_tpm_hcl_ak` so the qualifying_data can be
    computed to include sha256(ak_pub) before the quote is signed.
    """
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="tpm_quote_")
    try:
        nonce_path = os.path.join(tmpdir, "nonce.bin")
        msg_path = os.path.join(tmpdir, "quote.msg")
        sig_path = os.path.join(tmpdir, "quote.sig")
        with open(nonce_path, "wb") as f:
            f.write(qualifying_data)
        subprocess.run(
            ["tpm2_quote", "-c", primary_ctx, "-l", "sha256:0,1,2,3",
             "-q", nonce_path, "-m", msg_path, "-s", sig_path],
            capture_output=True, timeout=15, check=True,
        )
        subprocess.run(
            ["tpm2_flushcontext", "-t"],
            capture_output=True, timeout=5,
        )
        with open(msg_path, "rb") as f:
            msg = f.read()
        with open(sig_path, "rb") as f:
            sig = f.read()
        return msg, sig
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def _read_tcb_from_report(report: bytes) -> int:
    if len(report) < _OFF_REPORTED_TCB + 8:
        return 0
    return struct.unpack_from("<Q", report, _OFF_REPORTED_TCB)[0]


def _read_plat_info_from_report(report: bytes) -> int:
    if len(report) < _OFF_PLAT_INFO + 8:
        return 0
    return struct.unpack_from("<Q", report, _OFF_PLAT_INFO)[0]


def generate_snp_attestation(user_data: bytes) -> tuple[bytes, bytes]:
    """Serialised SNP attestation entrypoint (see ``_SNP_ATTEST_LOCK``)."""
    with _SNP_ATTEST_LOCK:
        return _generate_snp_attestation_locked(user_data)


def _generate_snp_attestation_locked(user_data: bytes) -> tuple[bytes, bytes]:
    """
    Generate an AMD SEV-SNP attestation report binding user_data.
    Returns (report_bytes, endorsement_cert_pem).

    On Azure Hyper-V CVMs the primary path is the vTPM HCL report
    (NV 0x01400001) because /dev/sev-guest does not exist under Hyper-V.

    Probe order:
      1. vTPM HCL report  (Azure Hyper-V primary path)
      2. SNP_GET_EXT_REPORT ioctl  (KVM fallback, report + certs)
      3. SNP_GET_REPORT ioctl  (KVM fallback, report only)
      4. snpguest CLI  (best-effort)
    """
    report_data = _generate_snp_report_data(user_data)

    report = None

    # Method 1 — Azure vTPM (works on all Azure Hyper-V CVMs)
    try:
        report = _get_snp_report_via_vtpm()
        if report:
            logging.info("[SNP/Azure] Got SNP report via vTPM HCL")
    except Exception as e:
        logging.warning("[SNP/Azure] vTPM path failed: %s", e)

    dev = _sev_guest_device()

    # Method 2 — KVM ext_report ioctl (report + certs in one call)
    if report is None and dev:
        try:
            logging.info("[SNP/Azure] Trying SNP_GET_EXT_REPORT on %s", dev)
            return _get_report_and_certs_via_ext_ioctl(report_data)
        except Exception as e:
            logging.warning("[SNP/Azure] SNP_GET_EXT_REPORT failed: %s", e)

    # Method 3 — KVM basic ioctl
    if report is None and dev:
        try:
            report = _get_snp_report_via_ioctl(report_data)
        except (OSError, RuntimeError) as e:
            logging.warning("[SNP/Azure] GET_REPORT ioctl failed: %s", e)

    # Method 4 — snpguest CLI
    if report is None:
        try:
            report = _get_snp_report_via_snpguest(report_data)
        except Exception as e:
            logging.warning("[SNP/Azure] snpguest report failed: %s", e)

    if report is None:
        raise RuntimeError("All SNP attestation paths failed")

    certs = _get_vcek_cert_from_imds()
    if not certs:
        try:
            certs = _get_vcek_certs_snpguest()
        except Exception as e:
            logging.warning("[SNP/Azure] snpguest certs failed: %s", e)

    if not certs:
        # Do NOT sys.exit(1) here.  This runs in the request-handler main
        # thread; SystemExit would tear down the entire RA-TLS server.
        raise RuntimeError(
            "All endorsement cert retrieval methods failed — cannot prove SNP report authenticity")

    return report, certs


def _read_measurement_from_report(report: bytes) -> str:
    if len(report) < _OFF_MEASUREMENT + 48:
        return "unknown"
    return report[_OFF_MEASUREMENT:_OFF_MEASUREMENT + 48].hex()


def _read_policy_from_report(report: bytes) -> int:
    if len(report) < _OFF_POLICY + 8:
        return 0
    return struct.unpack_from("<Q", report, _OFF_POLICY)[0]


# ---------------------------------------------------------------------------
# RA-TLS with embedded SNP attestation
# ---------------------------------------------------------------------------

_SNP_QUOTE_OID = "1.3.6.1.4.1.3704.1.1.1"
_CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"


# M-02: SubjectPublicKeyInfo (DER) of the TLS key currently loaded into the
# server's SSLContext.  Neither the certificate-embedded SNP report nor the
# TPM quote binds this key, so the TLS layer carries no attested identity on
# its own.  The `get_attestation` handler mixes it into a fresh report's
# user_data so a client can tie AMD-signed evidence to this TLS channel —
# but note that on the Azure vTPM HCL path REPORT_DATA is fixed by the HCL
# and will not reflect it; see the handler comment.  Set by
# _create_ratls_context().
_TLS_SPKI_DER: bytes = b""


def _create_ratls_context():
    """Create the attested-TLS context with SNP report + TPM Quote in the certificate.

    The SNP report binds SHA-256(ECDH pubkey [+ container digest] +
    sha256(ak_pub)) — the ECDH and TPM AK keys, *not* the ephemeral TLS key
    generated below.
    """
    global _TLS_SPKI_DER
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    import tempfile
    _tmp_dir = tempfile.mkdtemp(prefix="ratls_")
    cert_path = os.path.join(_tmp_dir, "cert.pem")
    key_path = os.path.join(_tmp_dir, "key.pem")

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime as _dt

    tls_key = ec.generate_private_key(ec.SECP384R1())

    _container_digest = ""
    _cd_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "container_digest.txt")
    if os.path.isfile(_cd_path):
        with open(_cd_path) as _cdf:
            _container_digest = _cdf.read().strip()
        logging.info("[SNP/Azure] Container image digest bound to attestation: %s", _container_digest)

    # SNP-3: two-phase TPM AK/quote flow.  Generate the AK first so its
    # public key can be hashed into the SNP report's user_data, which
    # on the /dev/sev-guest path is copied verbatim into REPORT_DATA
    # and signed by AMD's VCEK.  This binds the ephemeral AK to the
    # AMD-attested CVM and prevents an attacker from pairing a captured
    # SNP report with a quote signed by a foreign TPM they control.
    _TLS_SPKI_DER = tls_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Prefer the AK the HCL already vouches for.  On this platform an AK we
    # mint ourselves is unattestable (REPORT_DATA is not ours to fill), so the
    # ephemeral path below is a fallback that the client's strict gate is
    # expected to refuse -- it is kept so the failure is a clear verifier
    # refusal rather than a crashed server.
    _hcl_ak = _tpm_hcl_ak()
    if _hcl_ak:
        ak_pub, _ak_primary_ctx = _hcl_ak
        _ak_ctx_dir = None
    else:
        ak_pub, _ak_ctx_dir, _ak_primary_ctx = _tpm_create_ak()
    try:
        ak_pub_hash = hashlib.sha256(ak_pub).digest()

        _att_input = _ECDH_PUB_BYTES + _container_digest.encode() if _container_digest else _ECDH_PUB_BYTES
        _att_input += ak_pub_hash
        report, endorsement_cert = generate_snp_attestation(_att_input)

        cert_len = len(endorsement_cert)
        extension_blob = report + struct.pack("<I", cert_len) + endorsement_cert

        # On the vTPM HCL path, SNP REPORT_DATA is fixed by the HCL and
        # won't reflect _att_input.  The client therefore also verifies
        # the TPM quote, whose nonce is SHA256(_att_input) and now
        # transitively includes sha256(ak_pub) — preventing a replay
        # with a substituted AK.
        tpm_qualifying = hashlib.sha256(_att_input).digest()
        quote_msg, quote_sig = _tpm_quote_with_ctx(_ak_primary_ctx, tpm_qualifying)
    finally:
        # Only the ephemeral path has a context directory to remove; the HCL AK
        # is a persistent handle owned by the paravisor, not ours to clean up.
        if _ak_ctx_dir:
            import shutil as _shutil
            _shutil.rmtree(_ak_ctx_dir, ignore_errors=True)

    tpm_blob = (struct.pack("<I", len(quote_msg)) + quote_msg +
                struct.pack("<I", len(quote_sig)) + quote_sig +
                struct.pack("<I", len(ak_pub)) + ak_pub)
    extension_blob += struct.pack("<I", len(tpm_blob)) + tpm_blob

    # Append the HCL runtime data so the client can bind the AK to the
    # AMD signature instead of trusting it because it showed up.  Appended
    # rather than inserted: every field in this blob is length-prefixed, so an
    # older client stops after the TPM blob and simply does not see this one.
    _runtime_data = _get_hcl_runtime_data()
    if _runtime_data:
        extension_blob += struct.pack("<I", len(_runtime_data)) + _runtime_data
        logging.info("[RA-TLS/SNP-Azure] HCL runtime data included "
                     "(%d bytes) — AK is AMD-attested", len(_runtime_data))
    else:
        logging.warning(
            "[RA-TLS/SNP-Azure] HCL runtime data unavailable; the client will "
            "fall back to the weaker TPM-quote-only AK binding")
    logging.info("[RA-TLS/SNP-Azure] TPM Quote included in certificate "
                 "(AK bound to SNP user_data via ak_pub_hash=%s...)", ak_pub_hash.hex()[:16])

    quote_oid = x509.ObjectIdentifier(_SNP_QUOTE_OID)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "snp-azure-vm.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEECrafter-SNP-Azure"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow())
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(hours=1))
        .add_extension(
            x509.UnrecognizedExtension(quote_oid, extension_blob),
            critical=False,
        )
    )

    if _container_digest:
        cd_oid = x509.ObjectIdentifier(_CONTAINER_DIGEST_OID)
        builder = builder.add_extension(
            x509.UnrecognizedExtension(cd_oid, _container_digest.encode("utf-8")), critical=False)

    cert = builder.sign(tls_key, hashes.SHA384())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = tls_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)
    os.chmod(key_path, 0o600)

    ctx.load_cert_chain(cert_path, key_path)
    os.unlink(cert_path)
    os.unlink(key_path)
    os.rmdir(_tmp_dir)
    logging.info("[RA-TLS/SNP-Azure] Certificate generated with SNP attestation "
                 "(key files removed from disk)")
    return ctx


def _ecdh_decrypt(client_pub_bytes: bytes, nonce: bytes, ciphertext: bytes, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive shared AES-256-GCM keys via ECDH, decrypt the payload, and return (plaintext, response_key)."""
    client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)
    shared_secret = _ECDH_KEY.exchange(ec.ECDH(), client_pub)
    req_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"tee-crafter-snp-v1",
    ).derive(shared_secret)
    resp_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"tee-crafter-snp-v1-resp",
    ).derive(shared_secret)
    return AESGCM(req_key).decrypt(nonce, ciphertext, _AESGCM_AAD_REQ), resp_key


def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(min(n - len(buf), 65536))
        except socket.timeout:
            raise ConnectionError(f"Timed out after {len(buf)}/{n} bytes")
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _handle_connection(conn):
    """Handle a single client connection."""
    try:
        conn.settimeout(60)

        hdr = _recv_exactly(conn, 4)
        msg_len = struct.unpack("!I", hdr)[0]
        if msg_len > MAX_PAYLOAD_SIZE:
            logging.warning("[SNP/Azure] Payload %d exceeds limit, rejecting", msg_len)
            conn.close()
            return
        payload = _recv_exactly(conn, msg_len)

        logging.info("[SNP/Azure] Received payload: %d bytes", len(payload))
        data = json.loads(payload.decode("utf-8"))

        if isinstance(data, dict) and data.get("action") == "get_attestation":
            logging.info("[SNP/Azure] -> Attestation path")
            # M-02: bind the fresh report to BOTH the client's nonce
            # (freshness) and this server's own TLS SPKI (channel binding).
            #
            # Azure caveat: this only takes effect on the /dev/sev-guest
            # paths, where user_data is copied verbatim into REPORT_DATA.
            # On the vTPM HCL path (`_get_snp_report_via_vtpm`) the report is
            # minted by the HCL at boot with a REPORT_DATA the guest cannot
            # influence, so the challenge below is ignored and the client
            # will report that freshness could not be established rather
            # than pretending it was.
            #
            # AUD-3: the preimage carries a third field, the runtime audit
            # log's chain-key commitment, so the hardware signs over it.
            # Fields are length-prefixed (see _attest_binding_preimage)
            # because raw concatenation of variable-length fields can be
            # spliced.
            nonce = data.get("nonce", "").encode("utf-8")
            challenge = _attest_binding_preimage(
                nonce, _TLS_SPKI_DER, _CHAIN_KEY_COMMITMENT.encode("ascii"))
            report, _ = generate_snp_attestation(challenge)
            report_hex = report.hex()
            measurement = _read_measurement_from_report(report)
            response = json.dumps({
                "report_hex": report_hex,
                "measurement": measurement,
                "enclave_public_key": _ECDH_PUB_B64,
                # Self-describing so a client can tell which preimage to
                # recompute without guessing.
                "challenge_binding": _LIVE_CHALLENGE_BINDING_DESC,
                "challenge_binding_label": _ATTEST_BINDING_LABEL.decode("ascii"),
                "tls_spki_sha256": hashlib.sha256(_TLS_SPKI_DER).hexdigest(),
                # AUD-3: the exact value the hardware signed over.  A
                # verifier that pins this can reject any later audit log
                # whose genesis entry commits to a different HMAC key.
                "chain_key_commitment": _CHAIN_KEY_COMMITMENT,
            })

        elif isinstance(data, dict) and data.get("encrypted_payload"):
            logging.info("[SNP/Azure] -> Encrypted data processing path")
            client_pub_b64 = data.get("client_public_key")
            nonce_b64 = data.get("nonce")
            ct_b64 = data.get("encrypted_payload")

            if not all([client_pub_b64, nonce_b64, ct_b64]):
                raise ValueError("Encrypted request requires all fields")

            client_pub_bytes = base64.b64decode(client_pub_b64)
            nonce_bytes = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ct_b64)
            salt_b64 = data.get("hkdf_salt")
            salt = base64.b64decode(salt_b64) if salt_b64 else None

            plaintext_bytes, resp_key = _ecdh_decrypt(client_pub_bytes, nonce_bytes, ciphertext, salt=salt)
            plaintext_data = json.loads(plaintext_bytes.decode("utf-8"))

            results = process_request(plaintext_data)
            logging.info("[SNP/Azure] process_request returned type=%s", type(results).__name__)


            result_bytes = json.dumps(results, default=str).encode("utf-8")
            resp_nonce = os.urandom(12)
            resp_ct = AESGCM(resp_key).encrypt(resp_nonce, result_bytes, _AESGCM_AAD_RESP)
            response = json.dumps({
                "encrypted_response": base64.b64encode(resp_ct).decode(),
                "response_nonce": base64.b64encode(resp_nonce).decode(),
            })
        else:
            raise ValueError("Request must include 'action' or 'encrypted_payload'")

        resp_bytes = response.encode("utf-8")
        conn.sendall(struct.pack("!I", len(resp_bytes)))
        conn.sendall(resp_bytes)
        logging.info("[SNP/Azure] Response sent (%d bytes)", len(resp_bytes))
        if _kr_available:
            _kr.tick_request()

    except ConnectionError:
        logging.warning("[SNP/Azure] Client disconnected")
    except Exception as e:
        logging.error("Error processing request: %s", type(e).__name__)
        try:
            error_detail = json.dumps({"error": "Internal processing error"}).encode("utf-8")
            conn.sendall(struct.pack("!I", len(error_detail)))
            conn.sendall(error_detail)
        except Exception:
            pass
    finally:
        conn.close()


def run_snp_server():
    """Main entry point: start RA-TLS server inside an AMD SEV-SNP Azure VM."""
    logging.info("[SNP/Azure] AMD SEV-SNP Confidential VM server starting (Azure)...")

    try:
        boot_report, _ = generate_snp_attestation(b"startup-probe")
        measurement = _read_measurement_from_report(boot_report)
        policy = _read_policy_from_report(boot_report)
        reported_tcb = _read_tcb_from_report(boot_report)
        plat_info = _read_plat_info_from_report(boot_report)
        snp_svn = (reported_tcb >> 48) & 0xFF
        logging.info("[SNP/Azure] Launch measurement: %s", measurement)
        logging.info("[SNP/Azure] Guest policy: 0x%016X", policy)
        logging.info("[SNP/Azure] Reported TCB: 0x%016X (SNP SVN bits 55:48 = 0x%02X, PLATFORM_INFO = 0x%016X)",
                       reported_tcb, snp_svn, plat_info)
        if not (plat_info & _PLATFORM_INFO_ALIAS_CHECK_COMPLETE):
            logging.critical("[SNP/Azure] PLATFORM_INFO ALIAS_CHECK_COMPLETE (bit 5) is clear — "
                             "AMD-SB-3015 (CVE-2024-21944) mitigation not confirmed; refusing startup.")
            sys.exit(1)
        if snp_svn < _MIN_SNP_FIRMWARE_SVN:
            logging.critical("[SNP/Azure] SNP firmware SVN 0x%02X is below minimum 0x%02X (AMD-SB-3015 / ABI 56860)",
                             snp_svn, _MIN_SNP_FIRMWARE_SVN)
            sys.exit(1)
    except Exception as e:
        logging.fatal("[SNP/Azure] Boot-time SNP attestation FAILED: %s — "
                      "cannot prove TEE integrity. Aborting.", e)
        sys.exit(1)


    for attempt in range(1, 4):
        try:
            ctx = _create_ratls_context()
            break
        except Exception as e:
            logging.error("[SNP/Azure] RA-TLS context creation failed (attempt %d/3): %s",
                          attempt, e)
            if attempt == 3:
                raise
            _time.sleep(5)

    _ratls_created_at = _time.monotonic()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    logging.info("[SNP/Azure] RA-TLS server listening on port %d", LISTEN_PORT)

    try:
        startup_report = {
            "audit": "snp_azure_vm_startup",
            "steps": [
                "ecdh_keypair_generated",
                "snp_attestation_generated",
                "vcek_retrieved_from_imds",
                "measurement_read",
                "ratls_cert_generated",
                "report_data_bound_to_ecdh_pubkey",
                "tls_server_listening",
            ],
        }
        print(json.dumps(startup_report), flush=True)
    except Exception:
        pass

    # --- Continuous attestation monitor ---
    try:
        import tee_crafter_attestation_monitor

        def _snp_azure_attest_for_monitor():
            report, _ = generate_snp_attestation(b"monitor-probe")
            m = _read_measurement_from_report(report)
            return {"measurement": m, "report_hash": hashlib.sha256(report).hexdigest()}

        tee_crafter_attestation_monitor.configure(_snp_azure_attest_for_monitor)
        tee_crafter_attestation_monitor.start(baseline_measurement=measurement)
        logging.info("[SNP/Azure] Continuous attestation monitor started")
    except ImportError:
        pass
    except Exception as _mon_err:
        logging.warning("[SNP/Azure] Attestation monitor startup failed: %s", _mon_err)

    def _sigterm_handler(signum, frame):
        global _shutdown
        logging.info("[SNP/Azure] SIGTERM received, shutting down...")
        _shutdown = True

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGINT, _sigterm_handler)
    srv.settimeout(1.0)

    while not _shutdown:
        _do_rotate = False
        _rotate_reason = "time_based"
        if _kr_available:
            _do_rotate, _rotate_reason = _kr.should_rotate()
        elif _time.monotonic() - _ratls_created_at > _CERT_ROTATION_SECS:
            _do_rotate = True
        if _do_rotate:
            try:
                _t0 = _time.monotonic()
                _rotate_ecdh_key()
                ctx = _create_ratls_context()
                _ratls_created_at = _time.monotonic()
                _rot_ms = (_time.monotonic() - _t0) * 1000
                if _kr_available:
                    _kr.record_rotation(
                        f"ecdh-{_kr._total_rotations + 1}", _ECDH_PUB_BYTES,
                        new_key_type="ECDH-P256", reason=_rotate_reason,
                        rotation_latency_ms=_rot_ms,
                    )
                logging.info("[SNP/Azure] RA-TLS certificate rotated")
            except Exception as e:
                logging.fatal("[SNP/Azure] Certificate rotation failed — attestation no longer provable: %s", e)
                sys.exit(1)

        try:
            raw_conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError as e:
            if _shutdown:
                break
            logging.warning("[SNP/Azure] TCP accept error: %s", e)
            continue

        if not _rate_limit_check():
            logging.warning("[SNP/Azure] Rate limit exceeded, dropping connection")
            try:
                raw_conn.close()
            except Exception:
                pass
            continue

        raw_conn.settimeout(10)
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except (ssl.SSLError, ConnectionResetError, OSError) as e:
            logging.warning("[SNP/Azure] Rejected connection (TLS failed): %s", type(e).__name__)
            try:
                raw_conn.close()
            except Exception:
                pass
            continue

        logging.info("[SNP/Azure] Client connected")
        _handle_connection(conn)

    srv.close()
    logging.info("[SNP/Azure] Server shut down gracefully.")


if __name__ == "__main__":
    run_snp_server()
