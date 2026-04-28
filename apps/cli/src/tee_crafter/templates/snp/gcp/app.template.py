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
import uuid as _uuid

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
    logging.warning("[SNP/GCP] chain-commitment bootstrap unavailable: %r", _cc_exc)
if not _CHAIN_KEY_COMMITMENT:
    # Publication can fail on a read-only /run while the key itself is
    # perfectly good.  Read it straight out of the in-process logger so the
    # hardware binding still happens.
    try:
        _CHAIN_KEY_COMMITMENT = tee_crafter_audit_logger.get_chain_key_commitment()
    except Exception:
        _CHAIN_KEY_COMMITMENT = ""
if _CHAIN_KEY_COMMITMENT:
    logging.info("[SNP/GCP] audit-log chain-key commitment bound into attestation "
                 "evidence: %s", _CHAIN_KEY_COMMITMENT)
else:
    logging.warning(
        "[SNP/GCP] no audit-log chain-key commitment is available; attestation "
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

# Serialise *all* SNP attestation calls inside this process.  The kernel
# configfs-TSM interface uses a single shared report-entry directory per
# process, so two concurrent attestation calls (e.g. main-thread request
# handler + background attestation-monitor) race on the same path and
# the loser falls through to network-bound fallbacks (GCE metadata) that
# fail on locked-down egress, ultimately killing the whole process.
# A coarse module-level lock costs only the ~2 s of one attestation call
# and is strictly faster than the worst-case fallback path.
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

_CERT_ROTATION_SECS = 3600
_AESGCM_AAD_REQ = b"tee-crafter-snp-v1-req"
_AESGCM_AAD_RESP = b"tee-crafter-snp-v1-resp"


def _rotate_ecdh_key():
    global _ECDH_KEY, _ECDH_PUB, _ECDH_PUB_BYTES, _ECDH_PUB_B64
    _ECDH_KEY = ec.generate_private_key(ec.SECP256R1())
    _ECDH_PUB = _ECDH_KEY.public_key()
    _ECDH_PUB_BYTES = _ECDH_PUB.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    _ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode("utf-8")
    logging.info("[SNP/GCP] ECDH keypair rotated")


# --- Key rotation manager integration ---
try:
    import tee_crafter_key_rotation as _kr
    _kr.configure(rotation_interval_secs=_CERT_ROTATION_SECS)
    _kr.record_key_birth("ecdh-boot-0", _ECDH_PUB_BYTES, key_type="ECDH-P256")
    _kr_available = True
except ImportError:
    _kr_available = False


# ---------------------------------------------------------------------------
# AMD SEV-SNP attestation for GCP
#
# GCP Confidential VMs use VCEK (per-chip) certificates.
# VCEK certs are retrieved from the GCE metadata service:
#   http://metadata.google.internal/computeMetadata/v1/instance/
#     confidential-computing/
# Attestation reports via /dev/sev-guest ioctl (same as AWS/Azure).
# ---------------------------------------------------------------------------

def _sev_guest_device() -> str | None:
    """Return the SEV guest device path, or None if not found.

    Kernel <6.8 uses /dev/sev-guest; kernel >=6.8 renamed it to /dev/sev.
    """
    for path in ("/dev/sev-guest", "/dev/sev"):
        if os.path.exists(path):
            return path
    return None

_SNP_REPORT_USER_DATA_SIZE = 64
_SNP_REPORT_REQ_SIZE = 96
_SNP_REPORT_RESP_SIZE = 4000
_SNP_ATTESTATION_REPORT_SIZE = 1184

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

# AMD ABI 56860: REPORTED_TCB bits 55:48 = SNP firmware SVN (Milan/Genoa/Bergamo class).
# AMD-SB-3015 minimum mitigated SPL is per family: Genoa-class 0x16, Milan-class 0x17.
# This boot-time gate enforces the single Genoa-class floor (0x16) and nothing higher:
# the guest has no trustworthy CPU-family signal to branch on.  The family-aware floor
# is applied client-side, where the AMD root chain that validated the endorsement cert
# identifies the family (see verify_tcb_version in snp/<cloud>/client.template.py).
_MIN_SNP_FIRMWARE_SVN = 0x16
_PLATFORM_INFO_ALIAS_CHECK_COMPLETE = 1 << 5


def _generate_snp_report_data(user_data: bytes) -> bytes:
    """Hash user data into 64-byte report_data for the attestation request."""
    digest = hashlib.sha256(user_data).digest()
    return digest.ljust(_SNP_REPORT_USER_DATA_SIZE, b'\x00')[:_SNP_REPORT_USER_DATA_SIZE]


def _find_snpguest() -> str | None:
    """Find the snpguest binary."""
    import shutil
    path = shutil.which("snpguest")
    if path:
        return path
    for candidate in ["/usr/local/bin/snpguest", "/opt/snpguest/target/release/snpguest"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _get_snp_report_via_snpguest(report_data: bytes) -> bytes:
    """Obtain SNP attestation report using snpguest CLI."""
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
    """Obtain SNP attestation report via /dev/sev-guest ioctl."""
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


def _get_vcek_cert_from_gce_metadata() -> bytes:
    """
    Retrieve the VCEK certificate chain from GCE metadata service.

    GCP Confidential VMs expose attestation-related metadata under:
      http://metadata.google.internal/computeMetadata/v1/instance/
        confidential-computing/

    The signing-key-cert endpoint returns the VCEK certificate in PEM format,
    and the signing-key-cert-chain returns the intermediate + root chain.
    """
    import urllib.request

    base_url = "http://metadata.google.internal/computeMetadata/v1/instance/confidential-computing"
    headers = {"Metadata-Flavor": "Google"}

    vcek_pem = ""
    chain_pem = ""

    # Use a short timeout — when deploy egress is locked down (the default for
    # confidential workloads) GCE metadata is reachable but the AMD VCEK/chain
    # endpoints sometimes hang.  We never need this path when configfs-TSM
    # already returned VCEK+ASK, so 2 s is plenty.
    try:
        req = urllib.request.Request(f"{base_url}/signing-key-cert", headers=headers)
        with urllib.request.urlopen(req, timeout=2) as resp:
            vcek_pem = resp.read().decode("utf-8")
        logging.info("[SNP/GCP] Retrieved VCEK cert from GCE metadata (%d bytes)", len(vcek_pem))
    except Exception as e:
        logging.warning("[SNP/GCP] Failed to retrieve VCEK from GCE metadata: %s", e)

    try:
        req = urllib.request.Request(f"{base_url}/signing-key-cert-chain", headers=headers)
        with urllib.request.urlopen(req, timeout=2) as resp:
            chain_pem = resp.read().decode("utf-8")
        logging.info("[SNP/GCP] Retrieved cert chain from GCE metadata (%d bytes)", len(chain_pem))
    except Exception as e:
        logging.warning("[SNP/GCP] Failed to retrieve cert chain from GCE metadata: %s", e)

    if not vcek_pem:
        return b""

    combined = vcek_pem
    if chain_pem:
        combined += "\n" + chain_pem
    return combined.encode("utf-8")


_SNP_GET_EXT_REPORT = 0xC0205302

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
        logging.warning("[SNP/GCP] ext_report ioctl error: errno=%d, returned_certs_len=%d",
                        e.errno, returned_len)
        e.snp_required_certs_len = returned_len  # type: ignore[attr-defined]
        raise
    finally:
        os.close(fd)

    returned_len = struct.unpack_from("<I", ext_req, _SNP_REPORT_REQ_SIZE + 8)[0]
    logging.info("[SNP/GCP] ext_report ioctl OK: returned_certs_len=%d (buf=%d)",
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
            logging.info("[SNP/GCP] ext_report phase 1: kernel needs %d bytes", required_len)
        else:
            returned_len = getattr(e, "snp_required_certs_len", 0)
            logging.warning("[SNP/GCP] ext_report phase 1 failed: errno=%d, "
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
    """Parse GHCB cert table -> PEM chain. Handles both GUID byte orders."""
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

    logging.info("[SNP/GCP] cert table: %d typed entries (VLEK=%s, VCEK=%s, ASK=%s, ARK=%s)",
                 len(certs_by_type),
                 "yes" if "VLEK" in certs_by_type else "no",
                 "yes" if "VCEK" in certs_by_type else "no",
                 "yes" if "ASK" in certs_by_type else "no",
                 "yes" if "ARK" in certs_by_type else "no")

    if not certs_by_type:
        raise RuntimeError("Certificate table is empty or has no recognized GUIDs")

    endorsement_der = certs_by_type.get("VCEK") or certs_by_type.get("VLEK")
    if not endorsement_der:
        raise RuntimeError("No VCEK or VLEK found in certificate table")

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


def _get_report_and_certs_via_configfs_tsm(report_data: bytes) -> tuple[bytes, bytes]:
    """
    Retrieve both an attestation report and endorsement certs via
    the kernel configfs TSM interface (kernel 6.7+).
    Write report_data to inblob -> read outblob (report) + auxblob (certs).
    Returns (report_bytes, cert_pem).
    """
    tsm_report_dir = "/sys/kernel/config/tsm/report"
    if not os.path.isdir(tsm_report_dir):
        raise RuntimeError("configfs TSM report dir not found")

    # The configfs-TSM report dir is shared between all callers in this
    # process.  Using PID alone causes concurrent attestation calls (main
    # request handler + background attestation monitor) to collide with
    # "File exists" and one of them falls through to slow / network-bound
    # fallbacks.  Add a per-call UUID so each caller has its own entry.
    entry_name = f"teecrafter_{os.getpid()}_{_uuid.uuid4().hex[:12]}"
    entry_dir = os.path.join(tsm_report_dir, entry_name)
    try:
        os.makedirs(entry_dir)
    except OSError as e:
        raise RuntimeError(f"Cannot create TSM report entry: {e}")

    try:
        with open(os.path.join(entry_dir, "inblob"), "wb") as f:
            f.write(report_data[:64].ljust(64, b'\x00'))

        outblob_path = os.path.join(entry_dir, "outblob")
        report_bytes = b""
        if os.path.exists(outblob_path):
            with open(outblob_path, "rb") as f:
                report_bytes = f.read()
            logging.info("[SNP/GCP] configfs TSM: got %d bytes from outblob", len(report_bytes))

        auxblob_path = os.path.join(entry_dir, "auxblob")
        cert_pem = b""
        if os.path.exists(auxblob_path):
            with open(auxblob_path, "rb") as f:
                cert_data = f.read()
            if cert_data and not all(b == 0 for b in cert_data):
                logging.info("[SNP/GCP] configfs TSM: got %d bytes from auxblob", len(cert_data))
                cert_pem = _parse_cert_table(cert_data)

        if not report_bytes or len(report_bytes) < _SNP_ATTESTATION_REPORT_SIZE:
            raise RuntimeError(f"configfs TSM outblob too short ({len(report_bytes)} bytes)")

        return report_bytes[:_SNP_ATTESTATION_REPORT_SIZE], cert_pem
    finally:
        try:
            os.rmdir(entry_dir)
        except OSError:
            pass


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
        logging.info("[SNP/GCP] snpguest certificates rc=%d", result.returncode)

        for name in ("vcek.pem", "vlek.pem"):
            path = os.path.join(cert_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    return f.read()

        raise RuntimeError("No VCEK/VLEK certificate found")
    finally:
        shutil.rmtree(cert_dir, ignore_errors=True)


def generate_snp_attestation(user_data: bytes) -> tuple[bytes, bytes]:
    """
    Generate an AMD SEV-SNP attestation report binding user_data.

    Serialised across all in-process callers (see ``_SNP_ATTEST_LOCK``).
    """
    with _SNP_ATTEST_LOCK:
        return _generate_snp_attestation_locked(user_data)


def _generate_snp_attestation_locked(user_data: bytes) -> tuple[bytes, bytes]:
    """
    Generate an AMD SEV-SNP attestation report binding user_data.
    Returns (report_bytes, endorsement_cert_pem).

    On GCP, probes in order:
      1. SNP_GET_EXT_REPORT ioctl (two-phase, report + certs)
      2. configfs TSM (kernel 6.7+, report + certs via outblob/auxblob)
      3. SNP_GET_REPORT ioctl + GCE metadata for VCEK
      4. SNP_GET_REPORT ioctl + snpguest for certs
      5. snpguest CLI for report
      6. Pre-baked certs (last resort)
    """
    report_data = _generate_snp_report_data(user_data)

    dev = _sev_guest_device()

    # Method 1: ext_report ioctl (report + certs in one call)
    if dev:
        try:
            logging.info("[SNP/GCP] Trying SNP_GET_EXT_REPORT (two-phase) on %s", dev)
            return _get_report_and_certs_via_ext_ioctl(report_data)
        except Exception as e:
            logging.warning("[SNP/GCP] SNP_GET_EXT_REPORT failed: %s", e)

    # Method 2: configfs TSM (kernel 6.7+)
    try:
        logging.info("[SNP/GCP] Trying configfs TSM for report + certs")
        report, certs = _get_report_and_certs_via_configfs_tsm(report_data)
        if certs:
            return report, certs
        logging.warning("[SNP/GCP] configfs TSM: report OK but no certs from auxblob")
    except Exception as e:
        logging.warning("[SNP/GCP] configfs TSM failed: %s", e)

    # Get report separately, then try cert sources
    report = None
    if dev:
        try:
            report = _get_snp_report_via_ioctl(report_data)
        except (OSError, RuntimeError) as e:
            logging.warning("[SNP/GCP] GET_REPORT ioctl failed: %s", e)

    if report is None:
        try:
            logging.info("[SNP/GCP] Getting report via configfs TSM outblob")
            report, _ = _get_report_and_certs_via_configfs_tsm(report_data)
        except Exception as e:
            logging.warning("[SNP/GCP] configfs TSM report failed: %s", e)

    if report is None:
        try:
            report = _get_snp_report_via_snpguest(report_data)
        except Exception as e:
            logging.warning("[SNP/GCP] snpguest report failed: %s", e)

    if report is None:
        raise RuntimeError("All SNP attestation report paths failed")

    # Try cert sources: GCE metadata -> snpguest -> pre-baked
    certs = _get_vcek_cert_from_gce_metadata()
    if not certs:
        try:
            certs = _get_vcek_certs_snpguest()
        except Exception as e:
            logging.warning("[SNP/GCP] snpguest certs failed: %s", e)
            certs = b""

    if not certs:
        bake_cert_dir = "/opt/tee-crafter-snp/certs"
        for name in ("vcek.pem", "vlek.pem"):
            path = os.path.join(bake_cert_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    data = f.read()
                if data and len(data) > 100:
                    logging.info("[SNP/GCP] Using pre-baked cert %s (%d bytes)", path, len(data))
                    certs = data
                    break

    if not certs:
        # Do NOT sys.exit(1) here.  This function is called from the request
        # handler in the main thread; a SystemExit would propagate to the
        # interpreter and tear down the entire RA-TLS server, dropping every
        # in-flight client connection and killing future requests too.  Raise
        # so the caller's try/except can return a structured error response.
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


def _read_tcb_from_report(report: bytes) -> int:
    if len(report) < _OFF_REPORTED_TCB + 8:
        return 0
    return struct.unpack_from("<Q", report, _OFF_REPORTED_TCB)[0]


def _read_plat_info_from_report(report: bytes) -> int:
    if len(report) < _OFF_PLAT_INFO + 8:
        return 0
    return struct.unpack_from("<Q", report, _OFF_PLAT_INFO)[0]


# ---------------------------------------------------------------------------
# RA-TLS with embedded SNP attestation
# ---------------------------------------------------------------------------

_SNP_QUOTE_OID = "1.3.6.1.4.1.3704.1.1.1"
_CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"

# M-02: SubjectPublicKeyInfo (DER) of the TLS key currently loaded into the
# server's SSLContext.  The certificate-embedded SNP report binds the *ECDH*
# key, not this one, so the TLS layer carries no attested identity on its
# own.  The `get_attestation` handler mixes this value into a fresh report's
# user_data, which is what lets a client tie the AMD-signed evidence to the
# specific TLS channel it is talking over.  Set by _create_ratls_context().
_TLS_SPKI_DER: bytes = b""


def _create_ratls_context():
    """Create the attested-TLS context with the SNP report in the certificate.

    The report's report_data binds SHA-256(ECDH pubkey [+ container digest])
    — the ECDH key, not the ephemeral TLS key generated below.  See
    `_TLS_SPKI_DER` and the `get_attestation` handler for how a client ties
    the attested VM to this specific TLS channel.
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
        logging.info("[SNP/GCP] Container image digest bound to attestation: %s", _container_digest)

    _TLS_SPKI_DER = tls_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # C3: the certificate quote binds with the v2 preimage, same as the live
    # challenge below.  This used to be a raw concatenation
    # (``_ECDH_PUB_BYTES + digest``), which is v1 and ambiguous by construction:
    # nothing in the hashed bytes says where the key ends and the digest begins.
    # It was not exploitable -- both fields are fixed-length here, a 97-byte
    # uncompressed P-384 point and a ``sha256:...`` string -- but "unambiguous
    # because of a length coincidence" is exactly the property the v2 encoding
    # exists to stop relying on.  Add a third field, or make the key length
    # vary, and the coincidence goes away.
    #
    # ``_generate_snp_report_data`` hashes whatever it is given, so passing the
    # *preimage* (not the digest) makes report_data[:32] equal
    # ``_attest_binding_digest(pub, digest)`` with exactly one hash applied.
    # Both fields are always present, empty digest included: the length prefixes
    # make an empty field unambiguous, so the field count never varies and the
    # client does not have to branch to match.
    _att_input = _attest_binding_preimage(
        _ECDH_PUB_BYTES, _container_digest.encode())
    report, endorsement_cert = generate_snp_attestation(_att_input)

    cert_len = len(endorsement_cert)
    extension_blob = report + struct.pack("<I", cert_len) + endorsement_cert

    quote_oid = x509.ObjectIdentifier(_SNP_QUOTE_OID)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "snp-gcp-vm.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEECrafter-SNP-GCP"),
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
    logging.info("[RA-TLS/SNP-GCP] Certificate generated with SNP attestation "
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
            logging.warning("[SNP/GCP] Payload %d exceeds limit, rejecting", msg_len)
            conn.close()
            return
        payload = _recv_exactly(conn, msg_len)

        logging.info("[SNP/GCP] Received payload: %d bytes", len(payload))
        data = json.loads(payload.decode("utf-8"))

        if isinstance(data, dict) and data.get("action") == "get_attestation":
            logging.info("[SNP/GCP] -> Attestation path")
            # M-02: bind the fresh report to BOTH the client's nonce
            # (freshness) and this server's own TLS SPKI (channel binding),
            # so a captured report cannot be replayed and a relaying
            # man-in-the-middle cannot pass off the real VM's evidence as
            # its own.  The nonce is hashed as the ASCII bytes the client
            # sent so both sides hash the same preimage.
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
            logging.info("[SNP/GCP] -> Encrypted data processing path")
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
            logging.info("[SNP/GCP] process_request returned type=%s", type(results).__name__)


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
        logging.info("[SNP/GCP] Response sent (%d bytes)", len(resp_bytes))
        if _kr_available:
            _kr.tick_request()

    except ConnectionError:
        logging.warning("[SNP/GCP] Client disconnected")
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
    """Main entry point: start RA-TLS server inside an AMD SEV-SNP GCP VM."""
    logging.info("[SNP/GCP] AMD SEV-SNP Confidential VM server starting (GCP)...")

    try:
        boot_report, _ = generate_snp_attestation(b"startup-probe")
        measurement = _read_measurement_from_report(boot_report)
        policy = _read_policy_from_report(boot_report)
        reported_tcb = _read_tcb_from_report(boot_report)
        plat_info = _read_plat_info_from_report(boot_report)
        snp_svn = (reported_tcb >> 48) & 0xFF
        logging.info("[SNP/GCP] Launch measurement: %s", measurement)
        logging.info("[SNP/GCP] Guest policy: 0x%016X", policy)
        logging.info("[SNP/GCP] Reported TCB: 0x%016X (SNP SVN bits 55:48 = 0x%02X, PLATFORM_INFO = 0x%016X)",
                       reported_tcb, snp_svn, plat_info)
        if not (plat_info & _PLATFORM_INFO_ALIAS_CHECK_COMPLETE):
            logging.critical("[SNP/GCP] PLATFORM_INFO ALIAS_CHECK_COMPLETE (bit 5) is clear — "
                             "AMD-SB-3015 (CVE-2024-21944) mitigation not confirmed; refusing startup.")
            sys.exit(1)
        if snp_svn < _MIN_SNP_FIRMWARE_SVN:
            logging.critical("[SNP/GCP] SNP firmware SVN 0x%02X is below minimum 0x%02X (AMD-SB-3015 / ABI 56860)",
                             snp_svn, _MIN_SNP_FIRMWARE_SVN)
            sys.exit(1)
    except Exception as e:
        logging.fatal("[SNP/GCP] Boot-time SNP attestation FAILED: %s — "
                      "cannot prove TEE integrity. Aborting.", e)
        sys.exit(1)


    ctx = _create_ratls_context()
    _ratls_created_at = _time.monotonic()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    logging.info("[SNP/GCP] RA-TLS server listening on port %d", LISTEN_PORT)

    try:
        startup_report = {
            "audit": "snp_gcp_vm_startup",
            "steps": [
                "ecdh_keypair_generated",
                "snp_attestation_generated",
                "vcek_retrieved_from_gce_metadata",
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

        def _snp_gcp_attest_for_monitor():
            report, _ = generate_snp_attestation(b"monitor-probe")
            m = _read_measurement_from_report(report)
            return {"measurement": m, "report_hash": hashlib.sha256(report).hexdigest()}

        tee_crafter_attestation_monitor.configure(_snp_gcp_attest_for_monitor)
        tee_crafter_attestation_monitor.start(baseline_measurement=measurement)
        logging.info("[SNP/GCP] Continuous attestation monitor started")
    except ImportError:
        pass
    except Exception as _mon_err:
        logging.warning("[SNP/GCP] Attestation monitor startup failed: %s", _mon_err)

    def _sigterm_handler(signum, frame):
        global _shutdown
        logging.info("[SNP/GCP] SIGTERM received, shutting down...")
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
                logging.info("[SNP/GCP] RA-TLS certificate rotated")
            except Exception as e:
                logging.fatal("[SNP/GCP] Certificate rotation failed — attestation no longer provable: %s", e)
                sys.exit(1)

        try:
            raw_conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError as e:
            if _shutdown:
                break
            logging.warning("[SNP/GCP] TCP accept error: %s", e)
            continue

        if not _rate_limit_check():
            logging.warning("[SNP/GCP] Rate limit exceeded, dropping connection")
            try:
                raw_conn.close()
            except Exception:
                pass
            continue

        raw_conn.settimeout(10)
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except (ssl.SSLError, ConnectionResetError, OSError) as e:
            logging.warning("[SNP/GCP] Rejected connection (TLS failed): %s", type(e).__name__)
            try:
                raw_conn.close()
            except Exception:
                pass
            continue

        logging.info("[SNP/GCP] Client connected")
        _handle_connection(conn)

    srv.close()
    logging.info("[SNP/GCP] Server shut down gracefully.")


if __name__ == "__main__":
    run_snp_server()
