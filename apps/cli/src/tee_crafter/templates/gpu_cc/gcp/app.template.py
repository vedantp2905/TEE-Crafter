import socket
import json
import logging
import ssl
import os
import hashlib
import base64
import struct
import signal
import sys

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

# Serialise all TDX/GPU-CC quote calls in this process (request handler
# vs. attestation monitor).  See SNP-GCP template for the original
# race-condition incident write-up.
_TDX_ATTEST_LOCK = _threading.Lock()

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
    logging.warning("[GPU-CC/GCP] chain-commitment bootstrap unavailable: %r", _cc_exc)
if not _CHAIN_KEY_COMMITMENT:
    # Publication can fail on a read-only /run while the key itself is
    # perfectly good.  Read it straight out of the in-process logger so the
    # hardware binding still happens.
    try:
        _CHAIN_KEY_COMMITMENT = tee_crafter_audit_logger.get_chain_key_commitment()
    except Exception:
        _CHAIN_KEY_COMMITMENT = ""
if _CHAIN_KEY_COMMITMENT:
    logging.info("[GPU-CC/GCP] audit-log chain-key commitment bound into attestation "
                 "evidence: %s", _CHAIN_KEY_COMMITMENT)
else:
    logging.warning(
        "[GPU-CC/GCP] no audit-log chain-key commitment is available; attestation "
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
_AESGCM_AAD_REQ = b"tee-crafter-gpu-cc-v1-req"
_AESGCM_AAD_RESP = b"tee-crafter-gpu-cc-v1-resp"


def _rotate_ecdh_key():
    global _ECDH_KEY, _ECDH_PUB, _ECDH_PUB_BYTES, _ECDH_PUB_B64
    _ECDH_KEY = ec.generate_private_key(ec.SECP256R1())
    _ECDH_PUB = _ECDH_KEY.public_key()
    _ECDH_PUB_BYTES = _ECDH_PUB.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    _ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode("utf-8")
    logging.info("[GPU-CC/GCP] ECDH keypair rotated")


try:
    import tee_crafter_key_rotation as _kr
    _kr.configure(rotation_interval_secs=_CERT_ROTATION_SECS)
    _kr.record_key_birth("ecdh-boot-0", _ECDH_PUB_BYTES, key_type="ECDH-P256")
    _kr_available = True
except ImportError:
    _kr_available = False


# ---------------------------------------------------------------------------
# TDX attestation primitives for GCP (CPU-TEE)
# ---------------------------------------------------------------------------

_TSM_REPORT_DIR = "/sys/kernel/config/tsm/report"

#: Report entry pre-created by the unit's privileged ``ExecStartPre``.
#:
#: configfs creates a *new* entry's attribute files ``root:root`` with
#: ``inblob`` mode 0200, so handing the parent ``report/`` directory to a group
#: lets an unprivileged service ``mkdir`` an entry it then cannot write.
#: Measured on a GCP TDX C3 VM (kernel 6.8.0-1066-gcp): mkdir OK,
#: ``--w------- root root inblob``, write denied.  Only root can chown the
#: children, and only once they exist -- hence a pre-created entry.  Writing
#: ``inblob`` then reading ``outblob`` is one transaction, so a shared entry has
#: to be serialised; every caller here is a thread in one process, so a lock is
#: enough and no file locking is needed.
_TSM_SERVICE_ENTRY = os.path.join(_TSM_REPORT_DIR, "tee-crafter-0")
_TSM_ENTRY_LOCK = _threading.Lock()


def _pooled_tsm_entry():
    """The pre-created entry, if it exists and this process may write it."""
    try:
        if os.access(os.path.join(_TSM_SERVICE_ENTRY, "inblob"), os.W_OK):
            return _TSM_SERVICE_ENTRY
    except OSError:
        pass
    return None

_TDX_GUEST_DEVS = ["/dev/tdx-guest", "/dev/tdx_guest"]
_TDX_REPORT_DATA_SIZE = 64
_TDX_REPORT_SIZE = 1024
_TDX_REPORT_REQ_SIZE = _TDX_REPORT_DATA_SIZE + _TDX_REPORT_SIZE
_TDX_CMD_GET_REPORT0 = 0xC4405401
_TDX_CMD_GET_QUOTE = 0x80105404
_QUOTE_BUF_SIZE = 64 * 1024


def _generate_tdx_report_data(user_data: bytes) -> bytes:
    digest = hashlib.sha256(user_data).digest()
    return digest.ljust(_TDX_REPORT_DATA_SIZE, b'\x00')[:_TDX_REPORT_DATA_SIZE]


def _read_quote_from_tsm_entry(entry_path, report_data):
    import time as _time
    for _ in range(10):
        if os.path.exists(os.path.join(entry_path, "inblob")):
            break
        _time.sleep(0.01)
    with open(os.path.join(entry_path, "inblob"), "wb") as f:
        f.write(report_data)
    for _ in range(5):
        try:
            with open(os.path.join(entry_path, "outblob"), "rb") as f:
                quote = f.read()
            if quote:
                return quote
        except OSError:
            _time.sleep(0.1)
    raise RuntimeError("outblob empty or unreadable after writing inblob")

def _get_tdx_quote_configfs(report_data: bytes) -> bytes:
    """Obtain a TDX quote via configfs-tsm (Linux 6.7+)."""
    import uuid as _uuid_tdx

    entry = _pooled_tsm_entry()
    if entry is not None:
        with _TSM_ENTRY_LOCK:
            return _read_quote_from_tsm_entry(entry, report_data)

    # No pre-created entry (running as root, or an image whose unit
    # predates the pool).  Create a private one -- unique per call,
    # because concurrent callers would collide on one entry.
    entry_name = f"teecrafter_{os.getpid()}_{_uuid_tdx.uuid4().hex[:12]}"
    entry_path = os.path.join(_TSM_REPORT_DIR, entry_name)
    try:
        os.makedirs(entry_path)
        return _read_quote_from_tsm_entry(entry_path, report_data)
    finally:
        try:
            os.rmdir(entry_path)
        except OSError:
            pass


def _find_tdx_device():
    for dev in _TDX_GUEST_DEVS:
        if os.path.exists(dev):
            return dev
    return None


def _get_tdx_report_via_ioctl(dev_path, report_data):
    import fcntl
    fd = os.open(dev_path, os.O_RDWR)
    try:
        req = bytearray(_TDX_REPORT_REQ_SIZE)
        req[:_TDX_REPORT_DATA_SIZE] = report_data
        fcntl.ioctl(fd, _TDX_CMD_GET_REPORT0, req)
        return bytes(req[_TDX_REPORT_DATA_SIZE:_TDX_REPORT_REQ_SIZE])
    finally:
        os.close(fd)


def _get_tdx_quote_ioctl(report_data):
    import fcntl, ctypes
    dev_path = _find_tdx_device()
    if not dev_path:
        raise RuntimeError("No TDX guest device found")
    tdreport = _get_tdx_report_via_ioctl(dev_path, report_data)
    buf = (ctypes.c_char * _QUOTE_BUF_SIZE)()
    ctypes.memset(buf, 0, _QUOTE_BUF_SIZE)
    hdr = struct.pack("<QQII", 1, 0, _TDX_REPORT_SIZE, 0)
    hdr_len = len(hdr)
    ctypes.memmove(buf, hdr, hdr_len)
    ctypes.memmove(ctypes.addressof(buf) + hdr_len, tdreport, len(tdreport))
    buf_addr = ctypes.addressof(buf)
    quote_req = struct.pack("<QQ", buf_addr, _QUOTE_BUF_SIZE)
    fd = os.open(dev_path, os.O_RDWR)
    try:
        fcntl.ioctl(fd, _TDX_CMD_GET_QUOTE, quote_req)
    finally:
        os.close(fd)
    raw = bytes(buf)
    _, status, _, out_len = struct.unpack_from("<QQII", raw)
    if status != 0:
        raise RuntimeError(f"TDX_CMD_GET_QUOTE failed with status 0x{status:X}")
    if out_len < 632:
        raise RuntimeError(f"TDX quote too short: {out_len} bytes")
    return raw[hdr_len:hdr_len + out_len]


def generate_tdx_quote(user_data: bytes) -> bytes:
    """Serialised TDX quote entrypoint (see ``_TDX_ATTEST_LOCK``)."""
    with _TDX_ATTEST_LOCK:
        return _generate_tdx_quote_locked(user_data)


def _generate_tdx_quote_locked(user_data: bytes) -> bytes:
    """GPU-10: produce a TDX quote via configfs-tsm (preferred) or the
    userspace ioctl fallback.

    Production default: STRICT (``TEE_CRAFTER_STRICT_TSM=1``).  The
    ioctl fallback is disabled entirely — if configfs-tsm is missing
    or reports an error we fail closed rather than silently downgrade
    to a path the operator did not intend.  Dev hatch
    ``TEE_CRAFTER_STRICT_TSM=0`` re-enables the legacy best-effort
    ioctl fallback (for ad-hoc work on stale kernels).
    """
    report_data = _generate_tdx_report_data(user_data)
    # Production default is strict.  Only explicit "0" / "false" /
    # "no" opts INTO the legacy ioctl fallback.
    _tsm = os.environ.get("TEE_CRAFTER_STRICT_TSM", "1").strip().lower()
    strict = _tsm not in ("0", "false", "no", "off", "")

    if os.path.isdir(_TSM_REPORT_DIR):
        try:
            logging.info("[GPU-CC/GCP] Using configfs-tsm for TDX quote generation")
            return _get_tdx_quote_configfs(report_data)
        except (OSError, RuntimeError) as e:
            if strict:
                logging.fatal(
                    "[GPU-CC/GCP] configfs-tsm failed (%s) and "
                    "TEE_CRAFTER_STRICT_TSM=1 — refusing silent fallback "
                    "to /dev/tdx-guest ioctl (GPU-10). Investigate the "
                    "kernel configfs-tsm subsystem before retrying.",
                    e,
                )
                raise
            logging.warning("[GPU-CC/GCP] configfs-tsm failed (%s), trying ioctl", e)
    elif strict:
        logging.fatal(
            "[GPU-CC/GCP] %s is not present and "
            "TEE_CRAFTER_STRICT_TSM=1 — refusing silent fallback to "
            "/dev/tdx-guest ioctl (GPU-10).",
            _TSM_REPORT_DIR,
        )
        raise RuntimeError("configfs-tsm required but not available (strict mode)")

    dev = _find_tdx_device()
    if dev:
        logging.info("[GPU-CC/GCP] Using %s ioctl for TDX quote generation", dev)
        return _get_tdx_quote_ioctl(report_data)
    raise RuntimeError("TDX attestation not available on this VM")


def _read_mrtd_from_quote(quote):
    mrtd_offset = 48 + 136
    if len(quote) < mrtd_offset + 48:
        return "unknown"
    return quote[mrtd_offset:mrtd_offset + 48].hex()


# ---------------------------------------------------------------------------
# NVIDIA GPU attestation (GPU-TEE via NRAS)
# ---------------------------------------------------------------------------

def _initialize_gpu_cc():
    """Enable NVIDIA CC mode and return GPU attestation token.

    F-7: the NRAS nonce is deterministically derived from the ECDH public
    key so the NRAS-signed EAT cannot be paired with a different server
    identity by a relay attacker.
    """
    try:
        import nvidia_attestation
        cc_result = nvidia_attestation.initialize_gpu_cc_mode()
        if not cc_result.get("success"):
            logging.fatal("[GPU-CC/GCP] GPU CC mode init failed: %s", cc_result.get("error"))
            sys.exit(1)
        api_key = os.environ.get("NVIDIA_NRAS_API_KEY", "")
        if not api_key:
            logging.warning("[GPU-CC/GCP] NVIDIA_NRAS_API_KEY not set — proceeding without service key (NRAS v3 does not require it)")
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
            api_key,
            tls_binding=_nras_binding,
        )
        if not gpu_att.get("verified"):
            logging.fatal("[GPU-CC/GCP] GPU attestation verification FAILED: %s", gpu_att.get("error", "unknown"))
            sys.exit(1)
        return gpu_att.get("token"), {**cc_result, **gpu_att}
    except ImportError:
        logging.fatal("[GPU-CC/GCP] nvidia_attestation module not available")
        sys.exit(1)
    except Exception as e:
        logging.fatal("[GPU-CC/GCP] GPU attestation fatal error: %s", e)
        sys.exit(1)


# ---------------------------------------------------------------------------
# RA-TLS with embedded TDX quote + GPU attestation token
# ---------------------------------------------------------------------------

_TDX_QUOTE_OID = "1.2.840.113741.1.13.1"
_GPU_ATT_OID = "1.3.6.1.4.1.59386.1.1"
_CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"
# F-8: vTPM measured-boot PCR bundle OID (GCP Confidential VM vTPM).
_VTPM_PCRS_OID = "1.3.6.1.4.1.59386.2.2"
# F-7/AUD-3: salt used to derive the NRAS nonce =
# SHA256(v2_binding_digest(ECDH-pub, chain_key_commitment) || salt).  The
# client recomputes this and checks against the eat_nonce claim inside
# the NRAS-signed JWT.
_NRAS_NONCE_BINDING_OID = "1.3.6.1.4.1.59386.1.3"

_gpu_att_token = None
_gpu_att_info = {}


def _get_vtpm_pcrs():
    """F-8: read GCP Confidential VM vTPM PCRs 0-7 (SHA-256 bank).

    PCRs 0-7 cover firmware, secure-boot policy, the signed kernel, and
    the boot configuration.  They are placed in the RA-TLS certificate as
    plain JSON: there is no TPM2 quote over them and no attestation key
    involved, so they are **self-reported and unsigned**, not independent
    evidence.  Their only use is comparison against values an operator
    pinned out of band — the client says exactly this and fails closed
    when no such pin exists (see ``verify_vtpm_pcrs`` in
    gpu_cc/gcp/client.template.py).

    GCP's Confidential VMs always expose a vTPM via ``/dev/tpm0``; if the
    read fails we log FATAL rather than shipping a certificate with no
    PCR extension at all.
    """
    pcrs: dict = {}
    try:
        import subprocess as _subp
        result = _subp.run(
            ["tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            logging.fatal(
                "[GPU-CC/GCP] tpm2_pcrread failed (rc=%d): %s (F-8)",
                result.returncode, (result.stderr or "").strip()[:300],
            )
            sys.exit(1)
        for line in result.stdout.strip().splitlines():
            if ":" in line and "0x" in line:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    idx = parts[0].strip()
                    val = parts[1].strip().replace("0x", "").replace(" ", "")
                    pcrs[idx] = val
    except FileNotFoundError:
        logging.fatal(
            "[GPU-CC/GCP] tpm2-tools not installed — cannot read vTPM "
            "PCRs for measured-boot binding (F-8).",
        )
        sys.exit(1)
    except Exception as exc:
        logging.fatal("[GPU-CC/GCP] vTPM PCR read raised %s (F-8)", exc)
        sys.exit(1)
    if not pcrs:
        logging.fatal("[GPU-CC/GCP] vTPM PCR read returned empty bank (F-8)")
        sys.exit(1)
    return pcrs


def _create_ratls_context():
    """Create TLS context with cert embedding TDX quote and GPU NRAS token."""
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
        logging.info("[GPU-CC/GCP] Container image digest bound to attestation: %s", _container_digest)

    # AUD-3: the TDX quote's REPORT_DATA is guest-supplied, so the audit
    # log's chain-key commitment goes into it alongside the ECDH key and the
    # container digest.  Intel's quote signature therefore covers it.  All
    # three fields are length-prefixed (see _attest_binding_preimage): the
    # old `pub || digest` concatenation could not tell a long key from a
    # short key plus a digest prefix.
    _quote_input = _attest_binding_preimage(
        _ECDH_PUB_BYTES,
        _container_digest.encode("utf-8"),
        _CHAIN_KEY_COMMITMENT.encode("ascii"),
    )
    quote = generate_tdx_quote(_quote_input)
    quote_oid = x509.ObjectIdentifier(_TDX_QUOTE_OID)
    gpu_oid = x509.ObjectIdentifier(_GPU_ATT_OID)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "gpu-cc-gcp-vm.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEECrafter-GPU-CC-GCP"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow())
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(hours=1))
        .add_extension(x509.UnrecognizedExtension(quote_oid, quote), critical=False)
    )

    if _gpu_att_token:
        gpu_ext_data = _gpu_att_token.encode("utf-8") if isinstance(_gpu_att_token, str) else _gpu_att_token
        builder = builder.add_extension(
            x509.UnrecognizedExtension(gpu_oid, gpu_ext_data), critical=False,
        )

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

    # F-8: measured-boot binding via the GCP Confidential VM vTPM.  We
    # collect SHA-256 PCRs 0..7 (UEFI firmware + secure-boot state +
    # kernel + bootloader config) and embed a JSON blob in the RA-TLS
    # certificate so the client can compare against a trusted baseline
    # independently of the TDX MRTD.
    try:
        vtpm_pcrs = _get_vtpm_pcrs()
        vtpm_blob = json.dumps(
            {
                "schema": 1,
                "bank": "sha256",
                "pcrs": {k: vtpm_pcrs.get(k, "") for k in sorted(vtpm_pcrs.keys())},
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(_VTPM_PCRS_OID), vtpm_blob,
            ),
            critical=False,
        )
        logging.info(
            "[GPU-CC/GCP] F-8: embedded %d vTPM PCR(s) in RA-TLS cert",
            len(vtpm_pcrs),
        )
    except SystemExit:
        raise
    except Exception as exc:
        logging.fatal("[GPU-CC/GCP] F-8 vTPM PCR embedding failed: %s", exc)
        sys.exit(1)

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
    logging.info("[RA-TLS/GPU-CC-GCP] Certificate generated with TDX quote + GPU NRAS token")
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
            logging.warning("[GPU-CC/GCP] Payload size %d exceeds limit, rejecting", msg_len)
            conn.close()
            return
        payload = _recv_exactly(conn, msg_len)
        logging.info("[GPU-CC/GCP] Received payload: %d bytes", len(payload))
        data = json.loads(payload.decode("utf-8"))

        if isinstance(data, dict) and data.get("action") == "get_attestation":
            logging.info("[GPU-CC/GCP] -> Attestation path (dual: CPU TDX + GPU NRAS)")
            nonce = data.get("nonce", "").encode("utf-8")
            quote = generate_tdx_quote(nonce)
            quote_hex = quote.hex()
            mrtd = _read_mrtd_from_quote(quote)
            response = json.dumps({
                "quote_hex": quote_hex,
                "mrtd": mrtd,
                "enclave_public_key": _ECDH_PUB_B64,
                "gpu_attestation_token": _gpu_att_token or "",
                "gpu_info": {
                    "gpu_name": _gpu_att_info.get("gpu_name", "unknown"),
                    "gpu_count": _gpu_att_info.get("gpu_count", 0),
                    "cc_mode": _gpu_att_info.get("cc_mode", "unknown"),
                    "driver_version": _gpu_att_info.get("driver_version", "unknown"),
                },
                "attestation_type": "dual_tdx_nras",
                "security_model": "full-confidential",
            })

        elif isinstance(data, dict) and data.get("encrypted_payload"):
            logging.info("[GPU-CC/GCP] -> Encrypted data processing path")
            client_pub_b64 = data.get("client_public_key")
            nonce_b64 = data.get("nonce")
            ct_b64 = data.get("encrypted_payload")
            if not all([client_pub_b64, nonce_b64, ct_b64]):
                raise ValueError("Encrypted request requires 'encrypted_payload', 'client_public_key', and 'nonce'")
            client_pub_bytes = base64.b64decode(client_pub_b64)
            nonce_bytes = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ct_b64)
            salt_b64 = data.get("hkdf_salt")
            salt = base64.b64decode(salt_b64) if salt_b64 else None
            plaintext_bytes, resp_key = _ecdh_decrypt(client_pub_bytes, nonce_bytes, ciphertext, salt=salt)
            plaintext_data = json.loads(plaintext_bytes.decode("utf-8"))
            results = process_request(plaintext_data)
            logging.info("[GPU-CC/GCP] process_request returned type=%s", type(results).__name__)
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
        logging.info("[GPU-CC/GCP] Response sent successfully (%d bytes)", len(resp_bytes))
        if _kr_available:
            _kr.tick_request()
    except ConnectionError:
        logging.warning("[GPU-CC/GCP] Client disconnected during message exchange")
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


def run_gpu_cc_gcp_server():
    """Main entry point: RA-TLS server inside a GPU CC GCP confidential VM (Intel TDX + NVIDIA CC)."""
    global _gpu_att_token, _gpu_att_info
    logging.info("[GPU-CC/GCP] Confidential GPU VM server starting (GCP A3 TDX + NVIDIA CC)...")

    logging.info("[GPU-CC/GCP] Initializing NVIDIA Confidential Compute mode...")
    _gpu_att_token, _gpu_att_info = _initialize_gpu_cc()
    logging.info("[GPU-CC/GCP] GPU attestation token obtained via NRAS")

    try:
        boot_quote = generate_tdx_quote(b"startup-probe")
        mrtd = _read_mrtd_from_quote(boot_quote)
        logging.info("[GPU-CC/GCP] MRTD: %s", mrtd)
    except Exception as e:
        logging.fatal("[GPU-CC/GCP] Boot-time TDX quote generation FAILED: %s — "
                      "cannot prove TEE integrity. Aborting.", e)
        sys.exit(1)


    ctx = _create_ratls_context()
    _ratls_created_at = _time.monotonic()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    logging.info("[GPU-CC/GCP] RA-TLS server listening on port %d", LISTEN_PORT)

    try:
        startup_report = {
            "audit": "gpu_cc_gcp_vm_startup",
            "steps": [
                "ecdh_keypair_generated",
                "gpu_cc_mode_enabled",
                "nras_gpu_attestation",
                "tdx_quote_generated",
                "mrtd_read",
                "ratls_cert_generated_with_tdx_quote_and_gpu_token",
                "tls_server_listening",
            ],
        }
        print(json.dumps(startup_report), flush=True)
    except Exception:
        pass

    try:
        import tee_crafter_attestation_monitor

        def _gpu_cc_gcp_attest_for_monitor():
            quote = generate_tdx_quote(b"monitor-probe")
            m = _read_mrtd_from_quote(quote)
            result = {"measurement": m, "report_hash": hashlib.sha256(quote).hexdigest()}
            try:
                import nvidia_attestation
                gpu_health = nvidia_attestation.get_gpu_health()
                result["gpu_health"] = gpu_health
            except Exception:
                pass
            return result

        tee_crafter_attestation_monitor.configure(_gpu_cc_gcp_attest_for_monitor)
        tee_crafter_attestation_monitor.start(baseline_measurement=mrtd)
        logging.info("[GPU-CC/GCP] Continuous attestation monitor started (CPU + GPU)")
    except ImportError:
        pass
    except Exception as _mon_err:
        logging.warning("[GPU-CC/GCP] Attestation monitor startup failed: %s", _mon_err)

    def _sigterm_handler(signum, frame):
        global _shutdown
        logging.info("[GPU-CC/GCP] SIGTERM received, shutting down...")
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
                logging.info("[GPU-CC/GCP] RA-TLS certificate rotated")
            except Exception as e:
                logging.fatal("[GPU-CC/GCP] Certificate rotation failed — attestation no longer provable: %s", e)
                sys.exit(1)
        try:
            raw_conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError as e:
            if _shutdown:
                break
            logging.warning("[GPU-CC/GCP] TCP accept error: %s", e)
            continue
        if not _rate_limit_check():
            logging.warning("[GPU-CC/GCP] Rate limit exceeded, dropping connection")
            try:
                raw_conn.close()
            except Exception:
                pass
            continue
        raw_conn.settimeout(10)
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except (ssl.SSLError, ConnectionResetError, OSError) as e:
            logging.warning("[GPU-CC/GCP] TLS handshake failed: %s", type(e).__name__)
            try:
                raw_conn.close()
            except Exception:
                pass
            continue
        logging.info("[GPU-CC/GCP] Client connected")
        _handle_connection(conn)

    srv.close()
    logging.info("[GPU-CC/GCP] Server shut down gracefully.")


if __name__ == "__main__":
    run_gpu_cc_gcp_server()
