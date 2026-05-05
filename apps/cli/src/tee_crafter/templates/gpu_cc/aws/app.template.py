import socket
import json
import logging
import ssl
import os
import sys
import hashlib
import base64
import struct
import signal

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
# TEMPLATE CODE (TCB) — GPU CC AWS (NitroTPM + NVIDIA CC)
# WEAKER SECURITY MODEL: No CPU-TEE, PCIe link not encrypted by hardware TEE
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
    logging.warning("[GPU-CC/AWS] chain-commitment bootstrap unavailable: %r", _cc_exc)
if not _CHAIN_KEY_COMMITMENT:
    # Publication can fail on a read-only /run while the key itself is
    # perfectly good.  Read it straight out of the in-process logger so the
    # hardware binding still happens.
    try:
        _CHAIN_KEY_COMMITMENT = tee_crafter_audit_logger.get_chain_key_commitment()
    except Exception:
        _CHAIN_KEY_COMMITMENT = ""
if _CHAIN_KEY_COMMITMENT:
    logging.info("[GPU-CC/AWS] audit-log chain-key commitment bound into attestation "
                 "evidence: %s", _CHAIN_KEY_COMMITMENT)
else:
    logging.warning(
        "[GPU-CC/AWS] no audit-log chain-key commitment is available; attestation "
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


try:
    import tee_crafter_key_rotation as _kr
    _kr.configure(rotation_interval_secs=_CERT_ROTATION_SECS)
    _kr.record_key_birth("ecdh-boot-0", _ECDH_PUB_BYTES, key_type="ECDH-P256")
    _kr_available = True
except ImportError:
    _kr_available = False


# ---------------------------------------------------------------------------
# NitroTPM attestation (instance integrity, NOT a full CPU-TEE)
# ---------------------------------------------------------------------------

def _get_nitrotpm_document(binding):
    """Return a signed NitroTPM attestation document, or exit.

    Unlike :func:`_get_nitrotpm_pcrs` this *is* evidence: the document is a
    COSE_Sign1 signed by the Nitro Hypervisor, and its certificate chain roots
    at ``CN=aws.nitro-enclaves`` -- the same certificate the client already
    pins for ``nitro-aws``.  The client verifies the chain and the signature
    itself, so nothing here has to be trusted.

    *binding* is written to the document's ``user_data`` field, and the ECDH
    public key to ``public_key``.  Both tie the document to this TLS channel:
    a document replayed from another instance, or from this instance under a
    different session key, fails the client's comparison.

    Fail closed.  The alternative -- shipping the certificate without a
    document -- is exactly the state that made this platform's CPU evidence
    self-asserted, and a client cannot tell a missing document from a
    deliberately withheld one.
    """
    import subprocess
    import tempfile

    try:
        with tempfile.TemporaryDirectory(prefix="nitrotpm-") as tmp:
            pub_path = os.path.join(tmp, "public-key")
            ud_path = os.path.join(tmp, "user-data")
            with open(pub_path, "wb") as handle:
                handle.write(_ECDH_PUB_BYTES)
            with open(ud_path, "wb") as handle:
                handle.write(binding)
            result = subprocess.run(
                ["/usr/bin/nitro-tpm-attest",
                 "--public-key", pub_path,
                 "--user-data", ud_path],
                capture_output=True, timeout=30,
            )
    except FileNotFoundError:
        logging.fatal(
            "[GPU-CC/AWS] /usr/bin/nitro-tpm-attest is missing, so this "
            "instance cannot produce CPU attestation evidence. Re-bake with a "
            "current image: the bake installs it and now refuses to complete "
            "without it.")
        sys.exit(1)
    except Exception as e:
        logging.fatal("[GPU-CC/AWS] NitroTPM attestation failed: %s", e)
        sys.exit(1)

    if result.returncode != 0:
        logging.fatal(
            "[GPU-CC/AWS] nitro-tpm-attest exited %d: %s", result.returncode,
            (result.stderr or b"").decode("utf-8", "replace").strip())
        sys.exit(1)
    document = result.stdout or b""
    if not document:
        logging.fatal("[GPU-CC/AWS] nitro-tpm-attest produced no document")
        sys.exit(1)
    return document


def _get_nitrotpm_pcrs():
    """Read NitroTPM PCR values for logging only.

    This is a plain ``tpm2_pcrread``: no TPM2 quote is requested and no
    attestation key signs the result, so these values are self-reported by this
    instance.  They are *not* what the client checks -- the attestation
    document carries hypervisor-signed PCRs, and those are the ones that
    matter.  Kept because a local operator reading the journal wants to see
    them without decoding CBOR.

    Reads the ``sha384`` bank because that is what the attestation document
    reports (``digest: SHA384``, 48-byte values); the ``sha256`` bank this used
    to read could never be compared against the document.
    """
    pcrs = {}
    try:
        import subprocess
        result = subprocess.run(
            ["tpm2_pcrread", "sha384:0,1,2,3,4,5,6,7"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                if ":" in line and "0x" in line:
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        pcr_idx = parts[0].strip()
                        pcr_val = parts[1].strip().replace("0x", "").replace(" ", "")
                        pcrs[pcr_idx] = pcr_val
    except Exception as e:
        logging.fatal("[GPU-CC/AWS] NitroTPM PCR read failed: %s", e)
        sys.exit(1)
    return pcrs


# ---------------------------------------------------------------------------
# NVIDIA GPU attestation
# ---------------------------------------------------------------------------

def _initialize_gpu_cc():
    try:
        import nvidia_attestation
        cc_result = nvidia_attestation.initialize_gpu_cc_mode()
        if not cc_result.get("success"):
            logging.fatal("[GPU-CC/AWS] GPU CC mode init failed: %s", cc_result.get("error"))
            sys.exit(1)
        api_key = os.environ.get("NVIDIA_NRAS_API_KEY", "")
        if not api_key:
            logging.warning("[GPU-CC/AWS] NVIDIA_NRAS_API_KEY not set — proceeding without service key (NRAS v3 does not require it)")
        # F-7: bind the NRAS nonce to the ECDH public key.
        # Even on AWS (partial-confidential), this still protects against NRAS
        # evidence-relay attacks between two AWS GPU hosts.
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
            logging.fatal("[GPU-CC/AWS] GPU attestation verification FAILED: %s", gpu_att.get("error", "unknown"))
            sys.exit(1)
        return gpu_att.get("token"), {**cc_result, **gpu_att}
    except ImportError:
        logging.fatal("[GPU-CC/AWS] nvidia_attestation module not available")
        sys.exit(1)
    except Exception as e:
        logging.fatal("[GPU-CC/AWS] GPU attestation fatal error: %s", e)
        sys.exit(1)


# ---------------------------------------------------------------------------
# RA-TLS with NitroTPM PCRs + GPU NRAS token
# ---------------------------------------------------------------------------

_NITROTPM_OID = "1.3.6.1.4.1.59386.2.1"
# The signed NitroTPM attestation document (raw CBOR/COSE_Sign1).  Distinct OID
# from _NITROTPM_OID, which carries the unsigned self-reported PCR JSON: a
# client must never confuse the two, so they are not the same extension.
# Numbered .2.3 rather than .2.2 because .2.2 is already the gpu-cc-gcp
# vTPM PCR bundle -- a different payload shape under the same arc.
_NITROTPM_DOC_OID = "1.3.6.1.4.1.59386.2.3"
_GPU_ATT_OID = "1.3.6.1.4.1.59386.1.1"
_CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"
# F-7: binding for NRAS nonce so the client can recompute it.
_NRAS_NONCE_BINDING_OID = "1.3.6.1.4.1.59386.1.3"

_gpu_att_token = None
_gpu_att_info = {}
_nitrotpm_pcrs = {}


def _create_ratls_context():
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
        logging.info("[GPU-CC/AWS] Container image digest bound to attestation: %s", _container_digest)

    nitrotpm_oid = x509.ObjectIdentifier(_NITROTPM_OID)
    nitrotpm_doc_oid = x509.ObjectIdentifier(_NITROTPM_DOC_OID)
    gpu_oid = x509.ObjectIdentifier(_GPU_ATT_OID)

    # Bind the attestation document to this session's ECDH key.  Regenerated
    # here rather than once at startup because _rotate_ecdh_key() re-enters
    # this function: a document bound to a retired key would fail the client's
    # channel-binding check, correctly but confusingly.
    _ecdh_binding = hashlib.sha256(_ECDH_PUB_BYTES).digest()
    _nitrotpm_doc = _get_nitrotpm_document(_ecdh_binding)
    logging.info("[GPU-CC/AWS] NitroTPM attestation document: %d bytes, bound "
                 "to sha256(ecdh_pub)=%s", len(_nitrotpm_doc),
                 _ecdh_binding.hex()[:16])

    pcr_data = json.dumps({
        "pcrs": _nitrotpm_pcrs,
        "ecdh_pub_hash": hashlib.sha256(_ECDH_PUB_BYTES).hexdigest(),
        **({"container_digest": _container_digest} if _container_digest else {}),
    }).encode("utf-8")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "gpu-cc-aws-vm.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEECrafter-GPU-CC-AWS"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow())
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(hours=1))
        .add_extension(x509.UnrecognizedExtension(nitrotpm_oid, pcr_data), critical=False)
        .add_extension(x509.UnrecognizedExtension(nitrotpm_doc_oid, _nitrotpm_doc), critical=False)
    )

    if _gpu_att_token:
        gpu_ext_data = _gpu_att_token.encode("utf-8") if isinstance(_gpu_att_token, str) else _gpu_att_token
        builder = builder.add_extension(x509.UnrecognizedExtension(gpu_oid, gpu_ext_data), critical=False)

    # F-14: belt-and-braces TLS SPKI binding.  The client does an
    # exact-equal comparison between sha256(peer_cert.SPKI) and the
    # value we publish here.  Mismatches indicate a cert-vs-key
    # inconsistency (mis-rotation, template bug, MITM fabrication) and
    # are fatal on the client side.
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
    logging.info("[RA-TLS/GPU-CC-AWS] Certificate generated with NitroTPM PCRs + GPU NRAS token")
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
            response = json.dumps({
                "nitrotpm_pcrs": _nitrotpm_pcrs,
                "enclave_public_key": _ECDH_PUB_B64,
                "gpu_attestation_token": _gpu_att_token or "",
                "gpu_info": {
                    "gpu_name": _gpu_att_info.get("gpu_name", "unknown"),
                    "gpu_count": _gpu_att_info.get("gpu_count", 0),
                    "cc_mode": _gpu_att_info.get("cc_mode", "unknown"),
                    "driver_version": _gpu_att_info.get("driver_version", "unknown"),
                },
                "attestation_type": "nitrotpm_nras",
                "security_model": "partial-confidential",
                "warning": "AWS does not have a hardware CPU-TEE. PCIe link is NOT encrypted by a TEE.",
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
        pass
    except Exception as e:
        logging.error("Error: %s", type(e).__name__)
        try:
            err = json.dumps({"error": "Internal processing error"}).encode("utf-8")
            conn.sendall(struct.pack("!I", len(err)))
            conn.sendall(err)
        except Exception:
            pass
    finally:
        conn.close()


def run_gpu_cc_aws_server():
    global _gpu_att_token, _gpu_att_info, _nitrotpm_pcrs
    logging.info("[GPU-CC/AWS] GPU VM server starting (AWS P5/P5en/P6 + NitroTPM + NVIDIA CC)")
    logging.info("[GPU-CC/AWS] WARNING: Weaker security model — no hardware CPU-TEE, PCIe link not encrypted by TEE")

    logging.info("[GPU-CC/AWS] Reading NitroTPM PCR values...")
    _nitrotpm_pcrs = _get_nitrotpm_pcrs()
    if _nitrotpm_pcrs:
        logging.info("[GPU-CC/AWS] NitroTPM PCRs: %d values read", len(_nitrotpm_pcrs))
    else:
        logging.fatal("[GPU-CC/AWS] NitroTPM PCRs not available — cannot attest instance integrity")
        sys.exit(1)

    logging.info("[GPU-CC/AWS] Initializing NVIDIA Confidential Compute mode...")
    _gpu_att_token, _gpu_att_info = _initialize_gpu_cc()
    logging.info("[GPU-CC/AWS] GPU attestation token obtained via NRAS")


    ctx = _create_ratls_context()
    _ratls_created_at = _time.monotonic()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    logging.info("[GPU-CC/AWS] RA-TLS server listening on port %d", LISTEN_PORT)

    try:
        print(json.dumps({
            "audit": "gpu_cc_aws_vm_startup",
            "security_model": "partial-confidential",
            "steps": ["ecdh_keypair_generated", "nitrotpm_pcrs_read", "gpu_cc_mode_enabled",
                      "nras_gpu_attestation", "ratls_cert_generated", "tls_server_listening"],
        }), flush=True)
    except Exception:
        pass

    try:
        import tee_crafter_attestation_monitor

        def _gpu_cc_aws_attest():
            pcrs = _get_nitrotpm_pcrs()
            result = {"measurement": json.dumps(pcrs), "report_hash": hashlib.sha256(json.dumps(pcrs).encode()).hexdigest()}
            try:
                import nvidia_attestation
                result["gpu_health"] = nvidia_attestation.get_gpu_health()
            except Exception:
                pass
            return result

        tee_crafter_attestation_monitor.configure(_gpu_cc_aws_attest)
        tee_crafter_attestation_monitor.start()
    except ImportError:
        pass
    except Exception as _mon_err:
        logging.warning("[GPU-CC/AWS] Attestation monitor failed: %s", _mon_err)

    def _sigterm_handler(signum, frame):
        global _shutdown
        _shutdown = True

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGINT, _sigterm_handler)
    srv.settimeout(1.0)

    while not _shutdown:
        _do_rotate = False
        if _kr_available:
            _do_rotate, _ = _kr.should_rotate()
        elif _time.monotonic() - _ratls_created_at > _CERT_ROTATION_SECS:
            _do_rotate = True
        if _do_rotate:
            try:
                _rotate_ecdh_key()
                _nitrotpm_pcrs = _get_nitrotpm_pcrs()
                ctx = _create_ratls_context()
                _ratls_created_at = _time.monotonic()
            except Exception as e:
                logging.fatal("[GPU-CC/AWS] Certificate rotation failed — attestation no longer provable: %s", e)
                sys.exit(1)
        try:
            raw_conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
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
    logging.info("[GPU-CC/AWS] Server shut down.")


if __name__ == "__main__":
    run_gpu_cc_aws_server()
