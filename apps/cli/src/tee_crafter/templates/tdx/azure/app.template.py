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

# Serialise all TDX quote calls in this process (request handler vs.
# attestation monitor).  See SNP-GCP template for the original
# race-condition incident write-up.
_TDX_ATTEST_LOCK = _threading.Lock()

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
_AESGCM_AAD_REQ = b"tee-crafter-tdx-v1-req"
_AESGCM_AAD_RESP = b"tee-crafter-tdx-v1-resp"


def _rotate_ecdh_key():
    global _ECDH_KEY, _ECDH_PUB, _ECDH_PUB_BYTES, _ECDH_PUB_B64
    _ECDH_KEY = ec.generate_private_key(ec.SECP256R1())
    _ECDH_PUB = _ECDH_KEY.public_key()
    _ECDH_PUB_BYTES = _ECDH_PUB.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    _ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode("utf-8")
    logging.info("[TDX] ECDH keypair rotated")


# --- Key rotation manager integration ---
try:
    import tee_crafter_key_rotation as _kr
    _kr.configure(rotation_interval_secs=_CERT_ROTATION_SECS)
    _kr.record_key_birth("ecdh-boot-0", _ECDH_PUB_BYTES, key_type="ECDH-P256")
    _kr_available = True
except ImportError:
    _kr_available = False


# ---------------------------------------------------------------------------
# TDX attestation primitives
# ---------------------------------------------------------------------------
# Three interfaces are probed in order (matching Intel's libtdx_attest):
#   1. configfs-tsm (/sys/kernel/config/tsm/report/) — Linux 6.7+
#   2. /dev/tdx-guest ioctl (hyphen) — kernel 6.x+
#   3. /dev/tdx_guest ioctl (underscore) — older kernels
#
# Reference: Intel SGXDataCenterAttestationPrimitives
#   QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c
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

# struct tdx_report_req { u8 reportdata[64]; u8 tdreport[1024]; }
_TDX_REPORT_DATA_SIZE = 64
_TDX_REPORT_SIZE = 1024
_TDX_REPORT_REQ_SIZE = _TDX_REPORT_DATA_SIZE + _TDX_REPORT_SIZE  # 1088

# ioctl constants — must match Linux kernel uapi headers.
# TDX_CMD_GET_REPORT0 = _IOWR('T', 1, struct tdx_report_req)
#   direction=3(RW), size=1088=0x440, type=0x54('T'), nr=1
_TDX_CMD_GET_REPORT0 = 0xC4405401

# TDX_CMD_GET_QUOTE = _IOR('T', 4, struct tdx_quote_req)
#   struct tdx_quote_req { u64 buf; u64 len; }  → 16 bytes
#   direction=2(R), size=16=0x10, type=0x54('T'), nr=4
_TDX_CMD_GET_QUOTE = 0x80105404

# tdx_quote_hdr used by the kernel's TDX_CMD_GET_QUOTE ioctl
_QUOTE_HDR_VERSION = 1
_QUOTE_BUF_SIZE = 64 * 1024  # 64KB — Intel reference uses this


def _generate_tdx_report_data(user_data: bytes) -> bytes:
    """Hash and zero-pad user data to 64 bytes for report_data field."""
    digest = hashlib.sha256(user_data).digest()
    return digest.ljust(_TDX_REPORT_DATA_SIZE, b'\x00')[:_TDX_REPORT_DATA_SIZE]


# ---------------------------------------------------------------------------
# AUD-3: bind the runtime audit log's genesis commitment into report_data
# ---------------------------------------------------------------------------
#
# The in-TD audit log is an HMAC hash chain whose key never leaves guest
# memory.  ``tee_crafter_audit_logger`` computes SHA-256(key) as the "chain key
# commitment" and writes it into the log's own genesis entry — which is purely
# self-referential: a host adversary who discards the log regenerates key,
# genesis, chain and commitment together, and no hardware-signed value
# contradicts them.  Hashing the commitment into ``report_data`` makes the TDX
# module sign it, so a verifier can pin the value out of an attested quote and
# later reject any log whose genesis entry disagrees.
#
# This works on the configfs-tsm and /dev/tdx-guest paths, both of which take
# guest-supplied ``report_data``.  It does NOT work on the Azure vTPM/HCLA
# fallback, whose REPORT_DATA the host mints — and that path is already
# refused outright by tdx/azure/client.template.py
# (``_verify_azure_attestation``), so there is no configuration in which the
# commitment silently goes unbound.

# Shared with snp/*/app.template.py and every client — one encoder, one label,
# so no two platforms can disagree about how a preimage is built.
_ATTEST_BINDING_LABEL = b"tee-crafter/attest-binding/v2"

# First field of the preimage.  The label above is platform-agnostic and the
# SNP templates already use it for their live-challenge binding, so a purpose
# string is what keeps *this* binding (the RA-TLS certificate's embedded quote,
# on tdx-azure specifically) from ever being confused with one of those, or
# with the tdx-gcp variant whose field list is otherwise identical.
_CERT_BINDING_PURPOSE = b"ratls-cert-report-data/tdx-azure"


def _attest_binding_preimage(*fields: bytes) -> bytes:
    """Encode *fields* into one unambiguous attestation-binding preimage.

    Raw concatenation is ambiguous: ``a=b"ab", b=b"cd"`` and ``a=b"abc",
    b=b"d"`` produce identical bytes, so evidence minted for one field split
    could be presented as satisfying a different one — here specifically the
    boundary between the container digest and the commitment.  Every field
    therefore carries its own big-endian uint32 length prefix, the field *count*
    is prefixed too (so a short field list cannot be padded out into a longer
    one), and the whole encoding is prefixed with a version label so a v1
    preimage — ``ecdh_pub || container_digest``, which carried no commitment —
    can never be reinterpreted as a v2 one.  Clients recompute this
    byte-for-byte, which is why the label is part of the hashed bytes rather
    than just a comment.
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


#: Machine-readable description of the certificate quote's report_data
#: preimage, echoed to clients so they never have to guess which bytes to
#: recompute.  ``lp(x)`` means ``uint32be(len(x)) || x``.  The commitment goes
#: in as its ASCII hex — the same string that crosses the wire and lands in the
#: SIEM events — so there is no hex-vs-raw ambiguity between the two sides, and
#: an absent commitment is a zero-length field rather than a missing one.
_CERT_REPORT_DATA_BINDING_DESC = (
    "sha256(lp('tee-crafter/attest-binding/v2') || uint32be(4) || "
    "lp('ratls-cert-report-data/tdx-azure') || lp(ecdh_pub) || "
    "lp(container_digest) || lp(chain_key_commitment_hex_ascii))")


_chain_commitment_hex = None


def _chain_key_commitment() -> str:
    """Return the runtime audit log's chain-key commitment hex, or ``""``.

    Resolved once and cached: the commitment hashes a per-process secret, so
    the value bound into the certificate's quote and the value reported
    alongside it must be the same string.
    """
    global _chain_commitment_hex
    if _chain_commitment_hex is not None:
        return _chain_commitment_hex

    commitment = ""
    # Preferred path — also publishes the commitment to tmpfs so the SIEM
    # sidecar attaches the identical value to every exported event.
    try:
        import tee_crafter_runtime_bootstrap as _rb
        commitment = _rb.bootstrap_chain_commitment() or ""
    except Exception as exc:
        logging.warning("[TDX] chain-commitment bootstrap unavailable: %r", exc)
    if not commitment:
        # Publication can fail on a read-only or missing /run; the commitment
        # itself is an in-process value that needs no filesystem, so read it
        # directly rather than losing the hardware binding over a failed
        # side-effect.
        try:
            import tee_crafter_audit_logger as _al
            commitment = _al.get_chain_key_commitment() or ""
        except Exception as exc:
            logging.error(
                "[TDX] runtime audit logger not importable (%r) — this quote "
                "will carry no audit-chain commitment and a client without "
                "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_COMMITMENT=1 will refuse it",
                exc)
    _chain_commitment_hex = commitment
    return commitment


def _read_quote_from_tsm_entry(entry_path, report_data):
    """Write ``report_data`` to ``inblob`` and read the quote from ``outblob``.

    Reference: Intel tdx_attest.c → configfs_get_quote()
    The kernel populates provider/generation/inblob/outblob inside the
    created directory.
    """
    import time as _time

    # Wait for kernel to populate the pseudo-files (Intel retries up to 5x)
    provider_path = os.path.join(entry_path, "provider")
    for _ in range(10):
        if os.path.exists(os.path.join(entry_path, "inblob")):
            break
        _time.sleep(0.01)

    # Verify provider is "tdx_guest" if file exists
    if os.path.exists(provider_path):
        prov = open(provider_path).read().strip()
        if prov and "tdx_guest" not in prov:
            raise RuntimeError(f"configfs-tsm provider is '{prov}', not tdx_guest")

    with open(os.path.join(entry_path, "inblob"), "wb") as f:
        f.write(report_data)

    # Read the quote — kernel may need a moment after inblob write
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


def _find_tdx_device() -> str | None:
    """Return the first available TDX guest device path, or None."""
    for dev in _TDX_GUEST_DEVS:
        if os.path.exists(dev):
            return dev
    return None


def _get_tdx_report_via_ioctl(dev_path: str, report_data: bytes) -> bytes:
    """
    Get TDREPORT via TDX_CMD_GET_REPORT0 ioctl.
    struct tdx_report_req { u8 reportdata[64]; u8 tdreport[1024]; }
    """
    import fcntl
    fd = os.open(dev_path, os.O_RDWR)
    try:
        req = bytearray(_TDX_REPORT_REQ_SIZE)
        req[:_TDX_REPORT_DATA_SIZE] = report_data
        fcntl.ioctl(fd, _TDX_CMD_GET_REPORT0, req)
        return bytes(req[_TDX_REPORT_DATA_SIZE:_TDX_REPORT_REQ_SIZE])
    finally:
        os.close(fd)


def _get_tdx_quote_ioctl(report_data: bytes) -> bytes:
    """
    Obtain a TDX quote via /dev/tdx-guest (or /dev/tdx_guest) ioctl.

    Flow (matching Intel tdx_attest.c):
      1. TDX_CMD_GET_REPORT0 → get TDREPORT from TDX module
      2. TDX_CMD_GET_QUOTE   → send TDREPORT to VMM to get a DCAP quote

    The TDX_CMD_GET_QUOTE ioctl uses a page-aligned buffer with a header:
      struct tdx_quote_hdr { u64 version; u64 status; u32 in_len; u32 out_len; u64 data[]; }
    """
    import fcntl, ctypes

    dev_path = _find_tdx_device()
    if not dev_path:
        raise RuntimeError("No TDX guest device found")

    tdreport = _get_tdx_report_via_ioctl(dev_path, report_data)

    # Allocate a page-aligned buffer for the quote request
    buf = (ctypes.c_char * _QUOTE_BUF_SIZE)()
    ctypes.memset(buf, 0, _QUOTE_BUF_SIZE)

    # Fill tdx_quote_hdr: { u64 version; u64 status; u32 in_len; u32 out_len; }
    hdr = struct.pack("<QQII",
                      _QUOTE_HDR_VERSION,   # version
                      0,                     # status (filled by VMM)
                      _TDX_REPORT_SIZE,      # in_len (size of TDREPORT)
                      0)                     # out_len (filled by VMM)
    hdr_len = len(hdr)  # 24 bytes
    ctypes.memmove(buf, hdr, hdr_len)
    ctypes.memmove(ctypes.addressof(buf) + hdr_len, tdreport, len(tdreport))

    # struct tdx_quote_req { u64 buf; u64 len; }
    buf_addr = ctypes.addressof(buf)
    quote_req = struct.pack("<QQ", buf_addr, _QUOTE_BUF_SIZE)

    fd = os.open(dev_path, os.O_RDWR)
    try:
        fcntl.ioctl(fd, _TDX_CMD_GET_QUOTE, quote_req)
    finally:
        os.close(fd)

    # Parse response header
    raw = bytes(buf)
    _, status, _, out_len = struct.unpack_from("<QQII", raw)
    if status != 0:
        raise RuntimeError(f"TDX_CMD_GET_QUOTE failed with status 0x{status:X}")
    if out_len < 632:
        raise RuntimeError(f"TDX quote too short: {out_len} bytes")

    return raw[hdr_len:hdr_len + out_len]


def _get_tdx_evidence_azure_vtpm() -> bytes:
    """
    Get TDX attestation evidence via Azure's vTPM (fallback for Azure CVMs
    where /dev/tdx-guest and configfs-tsm are not available).

    Azure confidential VMs store the hardware-backed attestation report at
    TPM NV index 0x01400001 (2600 bytes, HCLA format):
      - Header (32 bytes): signature 'HCLA', version 2
      - Report Payload (1024 bytes): raw Intel TDX REPORT
      - Runtime Data (variable): JSON with AK public key, VM config, user_data

    The NV index requires the owner hierarchy for auth (-C o). Azure CVMs
    leave the owner password empty by default.

    Reference: Azure CVM guest attestation design detail
    https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design
    """
    import subprocess as _sp

    if not _shutil_which("tpm2_nvread"):
        raise RuntimeError("tpm2_nvread not found — install tpm2-tools")

    # First discover the actual NV index size via tpm2_nvreadpublic
    nv_size = 2600
    try:
        pub_result = _sp.run(
            ["tpm2_nvreadpublic", "0x01400001"],
            capture_output=True, timeout=10,
        )
        if pub_result.returncode == 0:
            for line in pub_result.stdout.decode(errors="replace").splitlines():
                if "size" in line.lower():
                    parts = line.split(":")
                    if len(parts) >= 2:
                        try:
                            nv_size = int(parts[-1].strip())
                        except ValueError:
                            pass
            logging.info("[TDX] Azure vTPM NV 0x01400001: size=%d", nv_size)
    except Exception:
        pass

    # Try auth hierarchies in order: owner (-C o), NV index itself, platform (-C p)
    auth_attempts = [
        (["-C", "o"], "owner hierarchy"),
        ([], "default (NV index)"),
        (["-C", "p"], "platform hierarchy"),
    ]
    last_err = ""
    for auth_args, auth_label in auth_attempts:
        cmd = ["tpm2_nvread"] + auth_args + ["0x01400001", "-s", str(nv_size)]
        result = _sp.run(cmd, capture_output=True, timeout=15)
        if result.returncode == 0 and len(result.stdout) >= 32:
            report = result.stdout
            sig = report[:4]
            if sig == b"HCLA":
                logging.info("[TDX] Azure vTPM: read %d-byte HCLA report (auth: %s)",
                             len(report), auth_label)
                return report
            logging.info("[TDX] Azure vTPM: read %d bytes but header=%s (not HCLA), "
                         "returning raw report (auth: %s)", len(report), sig.hex(), auth_label)
            return report
        last_err = result.stderr.decode(errors="replace").strip()
        logging.debug("[TDX] tpm2_nvread with %s failed: %s", auth_label, last_err)

    raise RuntimeError(
        f"tpm2_nvread 0x01400001 failed with all auth methods. "
        f"Last error: {last_err}"
    )


def _shutil_which(cmd: str):
    import shutil
    return shutil.which(cmd)


# ---------------------------------------------------------------------------
# Azure Guest attestation (the only verifiable evidence a paravisor CVM offers)
# ---------------------------------------------------------------------------
#
# Fixed at build time by the deploy, never sniffed at runtime, for the same
# reason the client pins it: a TD that could pick its own evidence format could
# pick the one with the weakest verifier.
_EVIDENCE_FORMAT = "{evidence_format}"

#: The MAA instance this TD attests to, substituted at deploy time from
#: ``TEE_CRAFTER_MAA_ENDPOINT``.
#:
#: Baked into the source rather than read from the unit environment, and that is
#: the security-relevant choice: this string decides *who gets to vouch for this
#: trust domain*.  An environment variable is set by the host, and the host is
#: outside the TCB — a compromised one could point attestation at an MAA-shaped
#: endpoint it controls, which would issue whatever token it liked.  Baked, it
#: is part of the code the client's container-digest binding already covers, so
#: redirecting it means producing a different measured image.
_MAA_ENDPOINT = "{maa_endpoint}"

#: Runtime override, honoured **only** when nothing was baked in.  Present so a
#: development image can be pointed at a private provider without a rebuild; on
#: a real deploy the baked value wins and this is dead.
_MAA_ENDPOINT_ENV = "TEE_CRAFTER_MAA_ENDPOINT"


def _maa_endpoint() -> str:
    baked = (_MAA_ENDPOINT or "").strip()
    if baked:
        return baked
    return (os.environ.get(_MAA_ENDPOINT_ENV) or "").strip()


def _load_maa_module():
    """Import the MAA helper staged into this build by ``copy_runtime_modules``."""
    import importlib
    import importlib.util

    try:
        return importlib.import_module("tee_crafter_maa")
    except ImportError:
        pass
    for path in (
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "tee_crafter_maa.py"),
        "/etc/tee_crafter/tee_crafter_maa.py",
    ):
        if not os.path.exists(path):
            continue
        spec = importlib.util.spec_from_file_location("tee_crafter_maa", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules["tee_crafter_maa"] = module
        spec.loader.exec_module(module)
        return module
    raise RuntimeError(
        "tee_crafter_maa.py is not staged in this build, so this TD cannot "
        "exchange its vTPM report for an MAA token and has no verifiable "
        "evidence to offer. Refusing to start.")


def _generate_azure_guest_evidence(binding_input: bytes) -> bytes:
    """Return an MAA ``/attest/AzureGuest`` token bound to *binding_input*.

    This replaces quote generation on Azure rather than supplementing it.  The
    vTPM's 1024-byte payload is a raw ``TDREPORT`` whose MAC only the TDX module
    and the Quoting Enclave can check, so there is nothing for a client to
    verify and nothing ``/attest/TdxVm`` will accept.  What *is* verifiable is a
    token MAA signs after Microsoft's guest-attestation library has assembled
    the full vTPM evidence — TPM quote, AK certificate, event log and hardware
    report — and MAA has checked it against the Azure CA and the Intel PCK
    chain.

    The binding travels as the client-payload nonce because ``report_data`` is
    not ours on this platform: the paravisor spends it on the hash of its own
    runtime claims.  So the session is bound by MAA's signature over a value
    only this TD could have supplied, rather than by the hardware directly.  That
    is a real step down from the DCAP path and it is the best this platform
    offers; the client says so out loud when it verifies.
    """
    maa = _load_maa_module()
    endpoint = _maa_endpoint()
    if not endpoint:
        raise RuntimeError(
            "no MAA endpoint was baked into this image and "
            f"{_MAA_ENDPOINT_ENV} is unset, so this TD has no attestation "
            "service to vouch for it and cannot produce verifiable evidence. "
            f"Set {_MAA_ENDPOINT_ENV} before deploying (e.g. "
            "https://sharedwus.wus.attest.azure.net). Refusing to serve.")
    if not endpoint.startswith("https://"):
        raise RuntimeError(
            f"MAA endpoint {endpoint!r} is not https. Attestation evidence "
            "would cross the wire without transport authentication, letting "
            "anything on path answer as the attestation service. Refusing.")

    binding = hashlib.sha256(binding_input).digest()
    token = maa.azure_guest_token(endpoint=endpoint, binding=binding)
    logging.info("[TDX/Azure] MAA AzureGuest token obtained (%d bytes), "
                 "bound to %s", len(token), binding.hex()[:16] + "…")
    return token.encode("ascii")


def generate_tdx_quote(user_data: bytes) -> bytes:
    """Serialised TDX quote entrypoint (see ``_TDX_ATTEST_LOCK``)."""
    with _TDX_ATTEST_LOCK:
        return _generate_tdx_quote_locked(user_data)


def _generate_tdx_quote_locked(user_data: bytes) -> bytes:
    """
    Generate TDX attestation evidence binding the given user_data.

    Probes interfaces in order:
      1. configfs-tsm  (/sys/kernel/config/tsm/report/)
      2. /dev/tdx-guest or /dev/tdx_guest ioctl
      3. Azure vTPM    (tpm2_nvread NV 0x01400001) — fallback for Azure CVMs
    """
    report_data = _generate_tdx_report_data(user_data)

    # configfs-tsm: the directory may exist even when the TSM driver
    # cannot service requests (ENXIO / "No such device or address").
    if os.path.isdir(_TSM_REPORT_DIR):
        try:
            logging.info("[TDX] Using configfs-tsm for quote generation")
            return _get_tdx_quote_configfs(report_data)
        except (OSError, RuntimeError) as e:
            logging.warning("[TDX] configfs-tsm failed (%s), trying next method", e)

    dev = _find_tdx_device()
    if dev:
        logging.info("[TDX] Using %s ioctl for quote generation", dev)
        return _get_tdx_quote_ioctl(report_data)

    # Azure vTPM fallback — Azure CVM TDX VMs expose the TDX report
    # via the vTPM rather than through /dev/tdx-guest.
    if _shutil_which("tpm2_nvread"):
        try:
            logging.info("[TDX] Using Azure vTPM fallback (tpm2_nvread)")
            return _get_tdx_evidence_azure_vtpm()
        except (OSError, RuntimeError) as e:
            logging.warning("[TDX] Azure vTPM fallback failed: %s", e)

    raise RuntimeError(
        "TDX attestation not available: tried configfs-tsm, "
        "/dev/tdx-guest ioctl, and Azure vTPM (tpm2_nvread). "
        "Ensure this VM is an Intel TDX confidential VM "
        "(Azure DCesv5/DCesv6 or GCP C3)."
    )


def _read_mrtd_from_quote(quote: bytes) -> str:
    """Extract MRTD (48 bytes) from TDX attestation evidence.

    Handles both standard DCAP quote format and Azure HCLA format.
    """
    if len(quote) >= 36 and quote[:4] == b"HCLA":
        # Azure attestation report: TDREPORT at offset 32, MRTD at TDREPORT+528
        mrtd_offset = 32 + 528
        if len(quote) < mrtd_offset + 48:
            return "unknown"
        return quote[mrtd_offset:mrtd_offset + 48].hex()

    # Standard DCAP quote: TD Report Body at offset 48, MRTD at body+136
    mrtd_offset = 48 + 136
    if len(quote) < mrtd_offset + 48:
        return "unknown"
    return quote[mrtd_offset:mrtd_offset + 48].hex()


# ---------------------------------------------------------------------------
# TLS with embedded TDX quote (RA-TLS style)
# ---------------------------------------------------------------------------

# Reuse Intel's SGX quote OID for the embedded quote; the tee_type field
# in the quote header (0x81 for TDX vs 0x00 for SGX) distinguishes them.
_TDX_QUOTE_OID = "1.2.840.113741.1.13.1"
_CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"


def _create_ratls_context():
    """
    Create a TLS context with a self-signed certificate embedding a TDX quote.
    The quote's report_data is bound to SHA-256 of the v2 preimage
    (``_attest_binding_preimage``): the ECDH public key, the container image
    digest, and the runtime audit log's genesis commitment.  Clients can
    therefore verify that the data-encryption key, the container image identity
    and the audit log all belong to this trust domain.
    """
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
        logging.info("[TDX/Azure] Container image digest bound to attestation: %s", _container_digest)

    _commitment = _chain_key_commitment()
    _quote_input = _attest_binding_preimage(
        _CERT_BINDING_PURPOSE,
        _ECDH_PUB_BYTES,
        _container_digest.encode("utf-8"),
        _commitment.encode("ascii"),
    )
    if _EVIDENCE_FORMAT == "azure-guest":
        quote = _generate_azure_guest_evidence(_quote_input)
    else:
        quote = generate_tdx_quote(_quote_input)

    quote_oid = x509.ObjectIdentifier(_TDX_QUOTE_OID)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "tdx-vm.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEECrafter-TDX"),
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
            x509.UnrecognizedExtension(quote_oid, quote),
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
    logging.info("[RA-TLS/TDX] Generated certificate with embedded TDX quote "
                 "(report_data bound to ECDH public key, container digest and "
                 "audit-chain commitment %s; key files removed from disk)",
                 (_commitment[:16] + "...") if _commitment else "<absent>")
    return ctx


def _ecdh_decrypt(client_pub_bytes: bytes, nonce: bytes, ciphertext: bytes, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive shared AES-256-GCM keys via ECDH, decrypt the payload, and return (plaintext, response_key)."""
    client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)
    shared_secret = _ECDH_KEY.exchange(ec.ECDH(), client_pub)
    req_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"tee-crafter-tdx-v1",
    ).derive(shared_secret)
    resp_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"tee-crafter-tdx-v1-resp",
    ).derive(shared_secret)
    return AESGCM(req_key).decrypt(nonce, ciphertext, _AESGCM_AAD_REQ), resp_key


def _recv_exactly(sock, n):
    """Read exactly n bytes from a socket."""
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
    """Handle a single client connection (length-prefixed framing)."""
    try:
        conn.settimeout(60)

        hdr = _recv_exactly(conn, 4)
        msg_len = struct.unpack("!I", hdr)[0]
        if msg_len > MAX_PAYLOAD_SIZE:
            logging.warning("[TDX] Payload size %d exceeds limit %d, rejecting", msg_len, MAX_PAYLOAD_SIZE)
            conn.close()
            return
        payload = _recv_exactly(conn, msg_len)

        logging.info("[TDX] Received payload: %d bytes", len(payload))
        data = json.loads(payload.decode("utf-8"))

        if isinstance(data, dict) and data.get("action") == "get_attestation":
            logging.info("[TDX] -> Attestation path")
            nonce = data.get("nonce", "").encode("utf-8")
            quote = generate_tdx_quote(nonce)
            quote_hex = quote.hex()
            mrtd = _read_mrtd_from_quote(quote)
            response = json.dumps({
                "quote_hex": quote_hex,
                "mrtd": mrtd,
                "enclave_public_key": _ECDH_PUB_B64,
                # Self-describing so the client knows which preimage to
                # recompute instead of guessing — same convention as the SNP
                # templates' "challenge_binding".  This describes the quote
                # embedded in the RA-TLS *certificate* (the one the client
                # verifies), not `quote_hex` above, whose report_data is
                # SHA-256(nonce) and which no client currently consumes.
                "cert_report_data_binding": _CERT_REPORT_DATA_BINDING_DESC,
                "chain_key_commitment": _chain_key_commitment(),
            })

        elif isinstance(data, dict) and data.get("encrypted_payload"):
            logging.info("[TDX] -> Encrypted data processing path")
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
            logging.info("[TDX] process_request returned type=%s", type(results).__name__)


            result_bytes = json.dumps(results, default=str).encode("utf-8")
            resp_nonce = os.urandom(12)
            resp_ct = AESGCM(resp_key).encrypt(resp_nonce, result_bytes, _AESGCM_AAD_RESP)
            response = json.dumps({
                "encrypted_response": base64.b64encode(resp_ct).decode(),
                "response_nonce": base64.b64encode(resp_nonce).decode(),
            })
            logging.info("[TDX] Encrypted response size: %d bytes", len(resp_ct))

        else:
            raise ValueError("Request must include 'action' or 'encrypted_payload'")

        resp_bytes = response.encode("utf-8")
        conn.sendall(struct.pack("!I", len(resp_bytes)))
        conn.sendall(resp_bytes)
        logging.info("[TDX] Response sent successfully (%d bytes)", len(resp_bytes))
        if _kr_available:
            _kr.tick_request()

    except ConnectionError:
        logging.warning("[TDX] Client disconnected during message exchange")
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


def run_tdx_server():
    """Main entry point: start RA-TLS server inside a TDX confidential VM."""
    logging.info("[TDX] Confidential VM server starting...")

    # Read initial MRTD for logging
    try:
        boot_quote = generate_tdx_quote(b"startup-probe")
        mrtd = _read_mrtd_from_quote(boot_quote)
        logging.info("[TDX] MRTD: %s", mrtd)
    except Exception as e:
        logging.fatal("[TDX] Boot-time TDX quote generation FAILED: %s — "
                      "cannot prove TEE integrity. Aborting.", e)
        sys.exit(1)


    ctx = _create_ratls_context()
    _ratls_created_at = _time.monotonic()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    logging.info("[TDX] RA-TLS server listening on port %d", LISTEN_PORT)

    try:
        startup_report = {
            "audit": "tdx_vm_startup",
            "steps": [
                "ecdh_keypair_generated",
                "tdx_quote_generated",
                "mrtd_read",
                "ratls_cert_generated_with_tdx_quote",
                "report_data_bound_to_ecdh_pubkey",
                "report_data_bound_to_audit_chain_commitment",
                "tls_server_listening",
            ],
        }
        print(json.dumps(startup_report), flush=True)
    except Exception:
        pass

    # --- Continuous attestation monitor ---
    try:
        import tee_crafter_attestation_monitor

        def _tdx_attest_for_monitor():
            quote = generate_tdx_quote(b"monitor-probe")
            m = _read_mrtd_from_quote(quote)
            return {"measurement": m, "report_hash": hashlib.sha256(quote).hexdigest()}

        tee_crafter_attestation_monitor.configure(_tdx_attest_for_monitor)
        tee_crafter_attestation_monitor.start(baseline_measurement=mrtd)
        logging.info("[TDX] Continuous attestation monitor started")
    except ImportError:
        pass
    except Exception as _mon_err:
        logging.warning("[TDX] Attestation monitor startup failed: %s", _mon_err)

    def _sigterm_handler(signum, frame):
        global _shutdown
        logging.info("[TDX] SIGTERM received, draining and shutting down...")
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
                logging.info("[TDX] RA-TLS certificate rotated")
            except Exception as e:
                logging.fatal("[TDX] Certificate rotation failed — attestation no longer provable: %s", e)
                sys.exit(1)

        try:
            raw_conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError as e:
            if _shutdown:
                break
            logging.warning("[TDX] TCP accept error: %s", e)
            continue

        if not _rate_limit_check():
            logging.warning("[TDX] Rate limit exceeded, dropping connection")
            try:
                raw_conn.close()
            except Exception:
                pass
            continue

        raw_conn.settimeout(10)
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except (ssl.SSLError, ConnectionResetError, OSError) as e:
            logging.warning("[TDX] Rejected connection (TLS handshake failed): %s", type(e).__name__)
            try:
                raw_conn.close()
            except Exception:
                pass
            continue

        logging.info("[TDX] Client connected")
        _handle_connection(conn)

    srv.close()
    logging.info("[TDX] Server shut down gracefully.")


if __name__ == "__main__":
    run_tdx_server()
