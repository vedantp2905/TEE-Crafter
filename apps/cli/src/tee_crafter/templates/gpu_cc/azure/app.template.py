import socket
import json
import logging
import ssl
import os
import hashlib
import base64
import struct
import subprocess
import signal
import sys

_shutdown = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

LISTEN_PORT = 5005
MAX_PAYLOAD_SIZE = 64 * 1024 * 1024

# ==========================================
# PROXY IMPORTS (injected by TEE-Crafter at staging time)
# ==========================================
{user_imports}

# ==========================================
# process_request body (injected by TEE-Crafter — proxy or batch runner)
# ==========================================

def _get_hcl_runtime_data() -> bytes | None:
    """Return the HCL runtime data the SNP report's REPORT_DATA commits to.

    Same mechanism as ``templates/snp/azure/app.template.py``, and needed for
    the same reason: this platform is SEV-SNP under the Azure paravisor, so the
    HCL fixes REPORT_DATA and no guest-chosen value can appear in it.  Without
    this blob the client can only check that *some* attestation key signed a
    quote over the right preimage -- which an attacker replaying a captured SNP
    report can also arrange, using a key they generated.

    Layout read off a live Azure SEV-SNP CVM on 2026-08-23: 32-byte ``HCLA``
    header, 1184-byte AMD report, then framing and a little-endian ``uint32``
    length immediately before a JSON document, where::

        sha256(runtime_data) == snp_report[REPORT_DATA : REPORT_DATA + 32]

    and the JSON's ``keys[kid == "HCLAkPub"]`` is the RSA-2048 attestation key
    that signs the quote.  That is what roots the AK in AMD's signature.

    Returns ``None`` on any unexpected framing so attestation degrades to the
    weaker binding rather than failing outright.
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
        if len(blob) < _HCL_HEADER_SIZE + _SNP_REPORT_SIZE + 8:
            return None
        if blob[:4] != _HCL_MAGIC:
            return None
        tail = blob[_HCL_HEADER_SIZE + _SNP_REPORT_SIZE:]
        start = tail.find(b"{")
        if start < 4:
            return None
        declared = struct.unpack_from("<I", tail, start - 4)[0]
        if declared <= 0 or start + declared > len(tail):
            return None
        runtime_data = tail[start:start + declared]
        logging.info("[GPU-CC/Azure] HCL runtime data: %d bytes",
                     len(runtime_data))
        return runtime_data
    except Exception as exc:  # noqa: BLE001 - degrade, never block attestation
        logging.warning("[GPU-CC/Azure] HCL runtime data unavailable: %s", exc)
        return None


def process_request(data):
    """Platform-owned dispatch slot (injected at deploy time).

    Persistent: forwards attested requests to the user container.
    Batch: wired to the batch runner when applicable.
    Operators never implement this function.
    """
{user_logic}

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
# TEMPLATE CODE (TCB) — GPU CC Azure (AMD SEV-SNP + NVIDIA CC)
# ==========================================

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import time as _time

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
    logging.warning("[GPU-CC/Azure] chain-commitment bootstrap unavailable: %r", _cc_exc)
if not _CHAIN_KEY_COMMITMENT:
    # Publication can fail on a read-only /run while the key itself is
    # perfectly good.  Read it straight out of the in-process logger so the
    # hardware binding still happens.
    try:
        _CHAIN_KEY_COMMITMENT = tee_crafter_audit_logger.get_chain_key_commitment()
    except Exception:
        _CHAIN_KEY_COMMITMENT = ""
if _CHAIN_KEY_COMMITMENT:
    logging.info("[GPU-CC/Azure] audit-log chain-key commitment bound into attestation "
                 "evidence: %s", _CHAIN_KEY_COMMITMENT)
else:
    logging.warning(
        "[GPU-CC/Azure] no audit-log chain-key commitment is available; attestation "
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


_MAX_CONN_PER_SEC = 10
_conn_timestamps: list[float] = []


def _rate_limit_check() -> bool:
    now = _time.monotonic()
    _conn_timestamps[:] = [t for t in _conn_timestamps if now - t < 1.0]
    if len(_conn_timestamps) >= _MAX_CONN_PER_SEC:
        return False
    _conn_timestamps.append(now)
    return True


_ECDH_KEY = ec.generate_private_key(ec.SECP256R1())
_ECDH_PUB = _ECDH_KEY.public_key()
_ECDH_PUB_BYTES = _ECDH_PUB.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
_ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode("utf-8")

_CERT_ROTATION_SECS = 3600
_AESGCM_AAD_REQ = b"tee-crafter-gpu-cc-v1-req"
_AESGCM_AAD_RESP = b"tee-crafter-gpu-cc-v1-resp"


def _rotate_ecdh_key():
    global _ECDH_KEY, _ECDH_PUB, _ECDH_PUB_BYTES, _ECDH_PUB_B64
    _ECDH_KEY = ec.generate_private_key(ec.SECP256R1())
    _ECDH_PUB = _ECDH_KEY.public_key()
    _ECDH_PUB_BYTES = _ECDH_PUB.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    _ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode("utf-8")
    logging.info("[GPU-CC/Azure] ECDH keypair rotated")


try:
    import tee_crafter_key_rotation as _kr
    _kr.configure(rotation_interval_secs=_CERT_ROTATION_SECS)
    _kr.record_key_birth("ecdh-boot-0", _ECDH_PUB_BYTES, key_type="ECDH-P256")
    _kr_available = True
except ImportError:
    _kr_available = False


# ---------------------------------------------------------------------------
# AMD SEV-SNP attestation primitives (CPU-TEE)
#
# Azure Hyper-V CVMs do NOT expose /dev/sev-guest (that device is for KVM
# guests).  Instead the SNP attestation report is obtained via the vTPM:
#
#   vTPM NV index 0x01400001 — contains an HCL (Hyper-V Compatibility Layer)
#   report whose first 32 bytes are a header (magic "HCLA"), followed by the
#   standard 1184-byte AMD SNP attestation report.
#
# The VCEK/VLEK endorsement certificate that signed that report comes from
# Azure IMDS:
#   http://169.254.169.254/metadata/THIM/amd/certification
# It is mandatory: without it the client cannot check the report signature,
# and an unverified report is not attestation.
#
# Attestation probe order:
#   1. vTPM HCL report  (primary — works on all Azure CVMs including GPU CC)
#   2. /dev/sev-guest ioctl  (fallback for KVM-based environments)
#   3. TSM configfs  (Linux 6.7+ fallback)
# ---------------------------------------------------------------------------

_SEV_GUEST_DEVS = ["/dev/sev-guest", "/dev/sev"]
_SNP_REPORT_SIZE = 1184
_TSM_REPORT_DIR = "/sys/kernel/config/tsm/report"

_HCL_HEADER_SIZE = 32
_HCL_MAGIC = b"HCLA"
_TPM_NV_INDEX_HCL = "0x01400001"


def _find_sev_device():
    for dev in _SEV_GUEST_DEVS:
        if os.path.exists(dev):
            return dev
    return None


def _get_snp_report_via_vtpm() -> bytes | None:
    """Primary Azure path: read HCL report from vTPM NV 0x01400001."""
    try:
        result = subprocess.run(
            ["tpm2_nvread", _TPM_NV_INDEX_HCL, "-C", "o", "-s", "2600"],
            capture_output=True, timeout=15,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace").strip()
            logging.warning("[GPU-CC/Azure] tpm2_nvread 0x01400001 failed: %s", stderr)
            return None

        hcl_report = result.stdout
        min_size = _HCL_HEADER_SIZE + _SNP_REPORT_SIZE
        if len(hcl_report) < min_size:
            logging.warning("[GPU-CC/Azure] HCL report too small: %d bytes (need %d)",
                            len(hcl_report), min_size)
            return None

        if hcl_report[:4] != _HCL_MAGIC:
            logging.warning("[GPU-CC/Azure] Bad HCL magic: %s", hcl_report[:4].hex())
            return None

        snp_report = hcl_report[_HCL_HEADER_SIZE:_HCL_HEADER_SIZE + _SNP_REPORT_SIZE]

        version = struct.unpack_from("<I", snp_report, 0)[0]
        if version < 2:
            logging.warning("[GPU-CC/Azure] Unexpected SNP report version: %d", version)
            return None

        logging.info("[GPU-CC/Azure] SNP report from vTPM HCL (version=%d, %d bytes)",
                     version, len(snp_report))
        return snp_report

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logging.warning("[GPU-CC/Azure] vTPM read error: %s", e)
    return None


def generate_snp_report(report_data_bytes: bytes) -> bytes:
    """Generate AMD SEV-SNP attestation report.

    Probe order (matching the SNP/Azure CPU-only template):
      1. vTPM HCL report — works on all Azure Hyper-V CVMs (primary)
      2. /dev/sev-guest ioctl — KVM-based environments
      3. TSM configfs — Linux 6.7+ kernels

    Note: the vTPM path does not honor custom report_data (the HCL report
    is generated at boot); for GPU CC VMs the GPU NRAS token is the primary
    attestation evidence, and the SNP report provides supplemental CPU-TEE
    proof.
    """
    # 1. Azure vTPM path (primary for Hyper-V CVMs)
    vtpm_report = _get_snp_report_via_vtpm()
    if vtpm_report:
        return vtpm_report

    # 2. /dev/sev-guest ioctl (KVM fallback)
    dev = _find_sev_device()
    if dev:
        import fcntl
        padded = report_data_bytes[:64].ljust(64, b'\x00')
        buf = bytearray(padded + b'\x00' * (_SNP_REPORT_SIZE - 64))
        fd = os.open(dev, os.O_RDWR)
        try:
            SNP_GET_REPORT = 0xC0A05300
            fcntl.ioctl(fd, SNP_GET_REPORT, buf)
        finally:
            os.close(fd)
        return bytes(buf)

    # 3. TSM configfs (Linux 6.7+ fallback)
    if os.path.isdir(_TSM_REPORT_DIR):
        import uuid, shutil
        entry = os.path.join(_TSM_REPORT_DIR, f"tee-crafter-{uuid.uuid4().hex[:8]}")
        try:
            os.makedirs(entry, exist_ok=True)
            with open(os.path.join(entry, "inblob"), "wb") as f:
                f.write(report_data_bytes[:64].ljust(64, b'\x00'))
            with open(os.path.join(entry, "outblob"), "rb") as f:
                return f.read()
        except OSError as e:
            logging.warning("[GPU-CC/Azure] TSM configfs failed: %s", e)
        finally:
            shutil.rmtree(entry, ignore_errors=True)

    raise RuntimeError(
        "No SNP attestation source found (tried vTPM 0x01400001, "
        "/dev/sev-guest, /dev/sev, and TSM configfs)")


def _find_snpguest() -> str | None:
    import shutil
    path = shutil.which("snpguest")
    if path:
        return path
    for candidate in ("/usr/local/bin/snpguest", "/opt/snpguest/target/release/snpguest"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _get_endorsement_certs_from_imds() -> bytes:
    """Fetch the VCEK certificate chain from Azure IMDS (THIM)."""
    import urllib.request
    url = "http://169.254.169.254/metadata/THIM/amd/certification"
    req = urllib.request.Request(url, headers={"Metadata": "true"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        combined = data.get("vcekCert", "")
        cert_chain = data.get("certificateChain", "")
        if cert_chain:
            combined += "\n" + cert_chain
        return combined.encode("utf-8")
    except Exception as e:
        logging.warning("[GPU-CC/Azure] Failed to retrieve VCEK from IMDS: %s", e)
        return b""


def _get_endorsement_certs_from_snpguest() -> bytes:
    """Fallback endorsement cert retrieval via the snpguest CLI."""
    import tempfile, shutil
    cert_dir = tempfile.mkdtemp(prefix="snp_certs_")
    try:
        snpguest = _find_snpguest()
        if not snpguest:
            return b""
        subprocess.run(
            [snpguest, "certificates", "pem", cert_dir],
            capture_output=True, timeout=30,
        )
        for name in ("vcek.pem", "vlek.pem"):
            path = os.path.join(cert_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    return f.read()
        return b""
    except Exception as e:
        logging.warning("[GPU-CC/Azure] snpguest certificate retrieval failed: %s", e)
        return b""
    finally:
        shutil.rmtree(cert_dir, ignore_errors=True)


def get_snp_endorsement_certs() -> bytes:
    """Return the PEM endorsement chain for the SNP report, or raise.

    Callers must treat failure as fatal: a report with no endorsement
    certificate cannot be verified by the client, and shipping one
    anyway is what let gpu-cc-azure claim dual attestation it never had.
    """
    certs = _get_endorsement_certs_from_imds()
    if not certs:
        certs = _get_endorsement_certs_from_snpguest()
    if not certs:
        raise RuntimeError(
            "No AMD endorsement certificate available (tried Azure IMDS THIM and "
            "snpguest) — the SNP report would be unverifiable by the client")
    return certs


def _read_measurement_from_snp(report: bytes) -> str:
    meas_offset = 0x90
    meas_len = 48
    if len(report) < meas_offset + meas_len:
        return "unknown"
    return report[meas_offset:meas_offset + meas_len].hex()


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
        logging.warning("[GPU-CC/Azure] no HCL runtime data; cannot identify an "
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
            logging.warning("[GPU-CC/Azure] runtime data carries no HCLAkPub key")
            return None
    except Exception as exc:
        logging.warning("[GPU-CC/Azure] could not parse HCL runtime data: %s", exc)
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
        logging.info("[GPU-CC/Azure] could not enumerate persistent handles "
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
                logging.info("[GPU-CC/Azure] AK %s matches HCLAkPub — quoting with "
                             "the AMD-attested paravisor AK", handle)
                return pem, handle
        except Exception:
            continue
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    logging.warning(
        "[GPU-CC/Azure] no persistent handle matched HCLAkPub; falling back to an "
        "ephemeral AK, which the client cannot root in AMD's signature")
    return None


def _generate_tpm_quote(qualifying_data: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Generate a TPM2 Quote binding qualifying_data to the vTPM.

    Prefers the attestation key the HCL vouches for -- the one published as
    ``keys[kid == "HCLAkPub"]`` in the runtime data that the AMD-signed
    ``REPORT_DATA`` hashes -- and only mints an ephemeral owner-hierarchy
    primary if no persistent handle matches it.

    That preference is the whole binding.  An AK this guest creates cannot be
    attested on the Azure vTPM path, because REPORT_DATA is fixed by the
    paravisor and the guest cannot write ``sha256(ak_pub)`` into it; a verifier
    then has no way to distinguish this CVM's vTPM from an attacker's own TPM
    paired with a replayed SNP report.  Using the HCL AK gives
    VCEK -> report -> REPORT_DATA -> runtime_data -> HCLAkPub -> quote.

    Ported from ``snp/azure/app.template.py``, where the chain was confirmed
    against real hardware (handle ``0x81000003`` matching HCLAkPub byte for
    byte, client reporting ``AK->SNP binding: PASSED``).  **Not verified on
    gpu-cc-azure**: the platform has had no ``NCCads`` capacity to deploy on
    (B6).  Written by symmetry with the platform that was measured, which is
    why the ephemeral path is kept rather than made fatal -- if the handle
    layout differs here, the client refuses the weaker binding instead of the
    server dying.

    Returns (quote_message, quote_signature, ak_pub_pem) or None.
    """
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="tpm_quote_")
    try:
        primary_ctx = os.path.join(tmpdir, "primary.ctx")
        ak_pub_path = os.path.join(tmpdir, "ak.pub.pem")
        nonce_path = os.path.join(tmpdir, "nonce.bin")
        msg_path = os.path.join(tmpdir, "quote.msg")
        sig_path = os.path.join(tmpdir, "quote.sig")

        with open(nonce_path, "wb") as f:
            f.write(qualifying_data)

        hcl_ak = _tpm_hcl_ak()
        if hcl_ak:
            ak_pub_pem, primary_ctx = hcl_ak
            with open(ak_pub_path, "wb") as f:
                f.write(ak_pub_pem)
        else:
            subprocess.run(
                ["tpm2_createprimary", "-C", "o", "-G", "rsa2048", "-g", "sha256",
                 "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
                 "-c", primary_ctx],
                capture_output=True, timeout=15, check=True,
            )
            subprocess.run(
                ["tpm2_readpublic", "-c", primary_ctx, "-o", ak_pub_path,
                 "-f", "pem"],
                capture_output=True, timeout=15, check=True,
            )
        # F-8: PCR 0-4 and 7 cover the full measured-boot chain.
        #   PCR 0: UEFI firmware code
        #   PCR 1: UEFI firmware config (variables, HOB)
        #   PCR 2: Extended option ROMs
        #   PCR 3: Extended option ROM configs
        #   PCR 4: MBR / bootloader (grub)
        #   PCR 7: Secure Boot policy (PK/KEK/db/dbx + measured events)
        # Quoting all six rather than just 0-3 binds boot-chain integrity
        # into the Azure GPU CC attestation so a bootloader swap after
        # kexec / A/B update is detectable by the client.
        subprocess.run(
            ["tpm2_quote", "-c", primary_ctx, "-l", "sha256:0,1,2,3,4,7",
             "-q", nonce_path, "-m", msg_path, "-s", sig_path],
            capture_output=True, timeout=15, check=True,
        )
        subprocess.run(
            ["tpm2_flushcontext", "-t"],
            capture_output=True, timeout=10,
        )

        with open(msg_path, "rb") as f:
            msg = f.read()
        with open(sig_path, "rb") as f:
            sig = f.read()
        with open(ak_pub_path, "rb") as f:
            pub = f.read()

        logging.info("[GPU-CC/Azure] TPM Quote generated (%d-byte msg, %d-byte sig)",
                     len(msg), len(sig))
        return msg, sig, pub
    except Exception as e:
        logging.fatal("[GPU-CC/Azure] TPM Quote generation failed — cannot bind ECDH key to vTPM: %s", e)
        sys.exit(1)
    finally:
        import shutil as _shutil_cleanup
        _shutil_cleanup.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# NVIDIA GPU attestation
# ---------------------------------------------------------------------------

def _initialize_gpu_cc():
    try:
        import nvidia_attestation
        cc_result = nvidia_attestation.initialize_gpu_cc_mode()
        if not cc_result.get("success"):
            logging.fatal("[GPU-CC/Azure] GPU CC mode init failed: %s", cc_result.get("error"))
            sys.exit(1)
        api_key = os.environ.get("NVIDIA_NRAS_API_KEY", "")
        if not api_key:
            logging.warning("[GPU-CC/Azure] NVIDIA_NRAS_API_KEY not set — proceeding without service key (NRAS v3 does not require it)")
        # F-7: bind NRAS nonce to the ECDH public key so the NRAS-signed EAT
        # cannot be relayed from a different host.
        # AUD-3: the NRAS nonce is SHA256(tls_binding || 32-byte salt)
        # (core/gpu/nvidia_attestation.compute_nras_nonce).  tls_binding is
        # now the length-prefixed v2 binding digest over the ECDH public key
        # AND the runtime audit log's chain-key commitment, so the value
        # NVIDIA echoes back in the NRAS-signed eat_nonce claim commits to
        # both.  A fixed 32-byte digest is used rather than the raw preimage
        # so both halves of the sha256 input stay fixed-length.
        _nras_binding = _attest_binding_digest(
            _ECDH_PUB_BYTES, _CHAIN_KEY_COMMITMENT.encode("ascii"))
        gpu_att = nvidia_attestation.get_gpu_attestation(
            api_key, tls_binding=_nras_binding,
        )
        if not gpu_att.get("verified"):
            logging.fatal("[GPU-CC/Azure] GPU attestation verification FAILED: %s", gpu_att.get("error", "unknown"))
            sys.exit(1)
        return gpu_att.get("token"), {**cc_result, **gpu_att}
    except ImportError:
        logging.fatal("[GPU-CC/Azure] nvidia_attestation module not available")
        sys.exit(1)
    except Exception as e:
        logging.fatal("[GPU-CC/Azure] GPU attestation fatal error: %s", e)
        sys.exit(1)


# ---------------------------------------------------------------------------
# RA-TLS with SNP report + GPU NRAS token
# ---------------------------------------------------------------------------

_SNP_REPORT_OID = "1.3.6.1.4.1.3704.1.3.1"
_GPU_ATT_OID = "1.3.6.1.4.1.59386.1.1"
_CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"
_SNP_QUOTE_OID = "1.3.6.1.4.1.3704.1.1.1"
# F-7: binding material that the client uses to recompute the NRAS nonce
# and compare it against the eat_nonce claim of the signed EAT.
_NRAS_NONCE_BINDING_OID = "1.3.6.1.4.1.59386.1.3"

_gpu_att_token = None
_gpu_att_info = {}


def _create_ratls_context():
    """Create RA-TLS context with SNP report + TPM Quote + GPU NRAS token."""
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
        logging.info("[GPU-CC/Azure] Container image digest bound to attestation: %s", _container_digest)

    # AUD-3: fold the audit log's chain-key commitment into the same
    # preimage as the ECDH key and container digest, length-prefixed (see
    # _attest_binding_preimage — the old `pub || digest` concatenation could
    # not distinguish a long key from a short key plus a digest prefix).
    # NB: on the primary Azure path `generate_snp_report` below returns the
    # vTPM HCL report, whose REPORT_DATA the guest cannot influence, so this
    # preimage only reaches AMD-signed evidence on the /dev/sev-guest and
    # configfs-TSM fallbacks.  The TPM Quote carries it in either case, and on
    # the primary path that quote *is* an anchor: `_tpm_hcl_ak` below signs with
    # the key the paravisor names in the HCL runtime data, and AMD-signed
    # REPORT_DATA is the digest of that runtime data, so the chain runs
    # VCEK -> report -> REPORT_DATA -> runtime_data -> HCLAkPub -> quote.  Only
    # when that key cannot be found does the quote fall back to an ephemeral
    # owner-hierarchy primary key, which has no certificate chain and anchors
    # nothing; the client fails closed on that case unless
    # TEE_CRAFTER_STRICT_SNP_AK_BINDING=0.
    _att_input = _attest_binding_preimage(
        _ECDH_PUB_BYTES,
        _container_digest.encode("utf-8"),
        _CHAIN_KEY_COMMITMENT.encode("ascii"),
    )
    report_data = hashlib.sha256(_att_input).digest().ljust(64, b'\x00')

    snp_report = generate_snp_report(report_data)
    endorsement_certs = get_snp_endorsement_certs()

    # vTPM HCL SNP reports do not honor custom report_data; bind via TPM Quote
    tpm_qualifying = hashlib.sha256(_att_input).digest()
    tpm_evidence = _generate_tpm_quote(tpm_qualifying)

    # SNP extension blob (must match the client's parser):
    #   report || u32 cert_len || endorsement PEM || u32 tpm_len || TPM quote
    # _generate_tpm_quote is fatal so tpm_evidence is always valid here
    extension_blob = snp_report + struct.pack("<I", len(endorsement_certs)) + endorsement_certs
    quote_msg, quote_sig, ak_pub = tpm_evidence
    tpm_blob = (struct.pack("<I", len(quote_msg)) + quote_msg +
                struct.pack("<I", len(quote_sig)) + quote_sig +
                struct.pack("<I", len(ak_pub)) + ak_pub)
    extension_blob += struct.pack("<I", len(tpm_blob)) + tpm_blob

    # Append the HCL runtime data so the client can root the TPM AK in AMD's
    # signature.  Every field here is length-prefixed, so a client built before
    # this existed stops after the TPM blob and never sees it.
    _runtime_data = _get_hcl_runtime_data()
    if _runtime_data:
        extension_blob += struct.pack("<I", len(_runtime_data)) + _runtime_data
    logging.info("[RA-TLS/GPU-CC-Azure] SNP report + %d-byte endorsement chain + "
                 "TPM Quote%s included in certificate", len(endorsement_certs),
                 " + HCL runtime data" if _runtime_data else "")

    snp_quote_oid = x509.ObjectIdentifier(_SNP_QUOTE_OID)
    gpu_oid = x509.ObjectIdentifier(_GPU_ATT_OID)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "gpu-cc-azure-vm.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEECrafter-GPU-CC-Azure"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow())
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(hours=1))
        .add_extension(x509.UnrecognizedExtension(snp_quote_oid, extension_blob), critical=False)
    )

    if _gpu_att_token:
        gpu_ext_data = _gpu_att_token.encode("utf-8") if isinstance(_gpu_att_token, str) else _gpu_att_token
        builder = builder.add_extension(x509.UnrecognizedExtension(gpu_oid, gpu_ext_data), critical=False)

    # F-14: belt-and-braces TLS SPKI binding (see aws/app.template.py).
    _tls_spki_der = tls_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _tls_spki_sha256 = hashlib.sha256(_tls_spki_der).hexdigest()

    nonce_salt_hex = (_gpu_att_info or {}).get("nras_nonce_salt_hex", "")
    if nonce_salt_hex:
        binding_payload = json.dumps({
            "ecdh_pub_b64": _ECDH_PUB_B64,
            "nonce_salt_hex": nonce_salt_hex,
            "nonce_hex": (_gpu_att_info or {}).get("nras_nonce", ""),
            # Self-describing so the client knows exactly which bytes to
            # recompute.  "lp(x)" == uint32be(len(x)) || x.
            "binding": (
                "sha256(sha256(lp('tee-crafter/attest-binding/v2') || "
                "uint32be(2) || lp(ecdh_pub) || "
                "lp(chain_key_commitment_hex_ascii)) || salt)"),
            "binding_label": _ATTEST_BINDING_LABEL.decode("ascii"),
            # AUD-3: the audit-log chain-key commitment folded into the
            # nonce NVIDIA signed into the EAT's eat_nonce claim.
            "chain_key_commitment": _CHAIN_KEY_COMMITMENT,
            "tls_spki_sha256": _tls_spki_sha256,  # F-14
        }).encode("utf-8")
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(_NRAS_NONCE_BINDING_OID), binding_payload,
            ),
            critical=False,
        )

    if _container_digest:
        cd_oid = x509.ObjectIdentifier(_CONTAINER_DIGEST_OID)
        builder = builder.add_extension(
            x509.UnrecognizedExtension(cd_oid, _container_digest.encode("utf-8")), critical=False)

    cert = builder.sign(tls_key, hashes.SHA384())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)
    os.chmod(key_path, 0o600)
    ctx.load_cert_chain(cert_path, key_path)
    os.unlink(cert_path)
    os.unlink(key_path)
    os.rmdir(_tmp_dir)
    logging.info("[RA-TLS/GPU-CC-Azure] Certificate generated with SNP report + TPM Quote + GPU NRAS token")
    return ctx


def _ecdh_decrypt(client_pub_bytes, nonce, ciphertext, salt=None):
    client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)
    shared_secret = _ECDH_KEY.exchange(ec.ECDH(), client_pub)
    req_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"tee-crafter-gpu-cc-v1").derive(shared_secret)
    resp_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"tee-crafter-gpu-cc-v1-resp").derive(shared_secret)
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
    try:
        conn.settimeout(60)
        hdr = _recv_exactly(conn, 4)
        msg_len = struct.unpack("!I", hdr)[0]
        if msg_len > MAX_PAYLOAD_SIZE:
            conn.close()
            return
        payload = _recv_exactly(conn, msg_len)
        data = json.loads(payload.decode("utf-8"))

        if isinstance(data, dict) and data.get("action") == "get_attestation":
            report_data = hashlib.sha256(_ECDH_PUB_BYTES).digest().ljust(64, b'\x00')
            snp_report = generate_snp_report(report_data)
            measurement = _read_measurement_from_snp(snp_report)
            report_hex = snp_report.hex()
            response = json.dumps({
                "report_hex": report_hex,
                "measurement": measurement,
                "enclave_public_key": _ECDH_PUB_B64,
                "gpu_attestation_token": _gpu_att_token or "",
                "gpu_info": {
                    "gpu_name": _gpu_att_info.get("gpu_name", "unknown"),
                    "gpu_count": _gpu_att_info.get("gpu_count", 0),
                    "cc_mode": _gpu_att_info.get("cc_mode", "unknown"),
                    "driver_version": _gpu_att_info.get("driver_version", "unknown"),
                },
                "attestation_type": "dual_snp_nras",
                "security_model": "full-confidential",
            })

        elif isinstance(data, dict) and data.get("encrypted_payload"):
            client_pub_bytes = base64.b64decode(data["client_public_key"])
            nonce_bytes = base64.b64decode(data["nonce"])
            ciphertext = base64.b64decode(data["encrypted_payload"])
            salt = base64.b64decode(data["hkdf_salt"]) if data.get("hkdf_salt") else None
            plaintext_bytes, resp_key = _ecdh_decrypt(client_pub_bytes, nonce_bytes, ciphertext, salt=salt)
            plaintext_data = json.loads(plaintext_bytes.decode("utf-8"))
            results = process_request(plaintext_data)
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
        if _kr_available:
            _kr.tick_request()
    except ConnectionError:
        logging.warning("[GPU-CC/Azure] Client disconnected")
    except Exception as e:
        logging.error("Error processing request: %s", type(e).__name__)
        try:
            err = json.dumps({"error": "Internal processing error"}).encode("utf-8")
            conn.sendall(struct.pack("!I", len(err)))
            conn.sendall(err)
        except Exception:
            pass
    finally:
        conn.close()


def run_gpu_cc_azure_server():
    global _gpu_att_token, _gpu_att_info
    logging.info("[GPU-CC/Azure] Confidential GPU VM server starting (Azure NCC H100 v5 SNP + NVIDIA CC)...")

    logging.info("[GPU-CC/Azure] Initializing NVIDIA Confidential Compute mode...")
    _gpu_att_token, _gpu_att_info = _initialize_gpu_cc()
    logging.info("[GPU-CC/Azure] GPU attestation token obtained via NRAS")

    report_data = hashlib.sha256(_ECDH_PUB_BYTES).digest().ljust(64, b'\x00')
    try:
        snp_report = generate_snp_report(report_data)
        measurement = _read_measurement_from_snp(snp_report)
        logging.info("[GPU-CC/Azure] SNP measurement: %s", measurement)
        # Fail at startup rather than serving certificates the client will
        # (correctly) reject for having no endorsement chain.
        _endorsement_probe = get_snp_endorsement_certs()
        logging.info("[GPU-CC/Azure] AMD endorsement chain retrieved (%d bytes)",
                     len(_endorsement_probe))
    except Exception as e:
        logging.fatal("[GPU-CC/Azure] SNP attestation failed — cannot prove CPU-TEE integrity: %s", e)
        sys.exit(1)


    ctx = _create_ratls_context()
    _ratls_created_at = _time.monotonic()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    logging.info("[GPU-CC/Azure] RA-TLS server listening on port %d", LISTEN_PORT)

    try:
        print(json.dumps({
            "audit": "gpu_cc_azure_vm_startup",
            "steps": ["ecdh_keypair_generated", "gpu_cc_mode_enabled", "nras_gpu_attestation",
                      "snp_report_generated", "ratls_cert_generated", "tls_server_listening"],
        }), flush=True)
    except Exception:
        pass

    try:
        import tee_crafter_attestation_monitor

        def _gpu_cc_azure_attest():
            rd = hashlib.sha256(b"monitor-probe").digest().ljust(64, b'\x00')
            report = generate_snp_report(rd)
            m = _read_measurement_from_snp(report)
            result = {"measurement": m, "report_hash": hashlib.sha256(report).hexdigest()}
            try:
                import nvidia_attestation
                result["gpu_health"] = nvidia_attestation.get_gpu_health()
            except Exception:
                pass
            return result

        tee_crafter_attestation_monitor.configure(_gpu_cc_azure_attest)
        tee_crafter_attestation_monitor.start(baseline_measurement=measurement)
    except ImportError:
        pass
    except Exception as _mon_err:
        logging.warning("[GPU-CC/Azure] Attestation monitor failed: %s", _mon_err)

    def _sigterm_handler(signum, frame):
        global _shutdown
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
                _rotate_ecdh_key()
                ctx = _create_ratls_context()
                _ratls_created_at = _time.monotonic()
            except Exception as e:
                logging.fatal("[GPU-CC/Azure] Certificate rotation failed — attestation no longer provable: %s", e)
                sys.exit(1)
        try:
            raw_conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError as e:
            if _shutdown:
                break
            continue
        if not _rate_limit_check():
            try:
                raw_conn.close()
            except Exception:
                pass
            continue
        raw_conn.settimeout(10)
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except (ssl.SSLError, ConnectionResetError, OSError):
            try:
                raw_conn.close()
            except Exception:
                pass
            continue
        _handle_connection(conn)

    srv.close()
    logging.info("[GPU-CC/Azure] Server shut down.")


if __name__ == "__main__":
    run_gpu_cc_azure_server()
