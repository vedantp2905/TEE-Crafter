import socket
import json
import logging
import subprocess
import base64
import signal

_shutdown = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

VSOCK_PORT = 5005
MAX_PAYLOAD_SIZE = 64 * 1024 * 1024  # 64 MB

# ==========================================
# PROXY IMPORTS (injected by TEE-Crafter at staging time)
# ==========================================
{user_imports}

# ==========================================
# process_request body (injected by TEE-Crafter — proxy or batch runner)
# ==========================================
def process_request(data):
    """
    Processes the payload from the client.
    Input 'data' can be a dictionary (single item) or a list (batch), 
    depending on what the client sends.
    Returns the processed result (dict or list).
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

import os
import time as _time
import hashlib
import struct

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
    logging.warning("[VSOCK] chain-commitment bootstrap unavailable: %r", _cc_exc)
if not _CHAIN_KEY_COMMITMENT:
    # Publication can fail on a read-only /run while the key itself is
    # perfectly good.  Read it straight out of the in-process logger so the
    # hardware binding still happens.
    try:
        _CHAIN_KEY_COMMITMENT = tee_crafter_audit_logger.get_chain_key_commitment()
    except Exception:
        _CHAIN_KEY_COMMITMENT = ""
if _CHAIN_KEY_COMMITMENT:
    logging.info("[VSOCK] audit-log chain-key commitment bound into attestation "
                 "evidence: %s", _CHAIN_KEY_COMMITMENT)
else:
    logging.warning(
        "[VSOCK] no audit-log chain-key commitment is available; attestation "
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


from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from asn1crypto import cms as asn1_cms, core as asn1_core
import boto3
from botocore.config import Config
import threading

# Generate RSA keypair for KMS Attestation on startup
_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=4096)
_RSA_PUB = _RSA_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
_RSA_PUB_B64 = base64.b64encode(_RSA_PUB).decode('utf-8')

# Generate ECDH keypair for E2E ECIES encryption (client <-> enclave)
_ECDH_KEY = ec.generate_private_key(ec.SECP384R1())
_ECDH_PUB_BYTES = _ECDH_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint,
)
_ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode('utf-8')

_KEY_ROTATION_SECS = 3600
_ecdh_created_at = _time.monotonic()


def _rotate_ecdh_key():
    global _ECDH_KEY, _ECDH_PUB_BYTES, _ECDH_PUB_B64, _ecdh_created_at
    _ECDH_KEY = ec.generate_private_key(ec.SECP384R1())
    _ECDH_PUB_BYTES = _ECDH_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    _ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode('utf-8')
    _ecdh_created_at = _time.monotonic()


# --- Key rotation manager integration ---
try:
    import tee_crafter_key_rotation as _kr
    _kr.configure(
        rotation_interval_secs=_KEY_ROTATION_SECS,
        # Base64, not the bare word: see handle_attestation_request.
        attest_fn=lambda: {"measurement": handle_attestation_request(
            nonce=base64.b64encode(b"rotation").decode("ascii"))[:64]},
    )
    _kr.record_key_birth("ecdh-boot-0", _ECDH_PUB_BYTES, key_type="ECDH-P384")
    _kr_available = True
except ImportError:
    _kr_available = False


_entropy_seeded = False


def _kms_client_kwargs(aws_creds, region):
    """Build the boto3 ``client('kms', ...)`` kwargs for *aws_creds*.

    SECURITY: we never set ``os.environ['AWS_*']`` inside the enclave.
    Process env vars are global state — any third-party library running
    in the same interpreter would see them, and if an exception fires
    between "set env vars" and "scrub env vars" the creds leak across
    requests.  Passing them as explicit boto3 client kwargs scopes the
    credentials to the single client object, which is GC'd as soon as
    the request handler returns.
    """
    kms_config = Config(
        connect_timeout=10, read_timeout=60,
        retries={'max_attempts': 2, 'mode': 'standard'},
    )
    kwargs = {"region_name": region, "config": kms_config}
    if aws_creds:
        kwargs["aws_access_key_id"] = aws_creds.get("access_key", "")
        kwargs["aws_secret_access_key"] = aws_creds.get("secret_key", "")
        token = aws_creds.get("token") or None
        if token:
            kwargs["aws_session_token"] = token
    return kwargs


def seed_entropy_from_kms(aws_creds=None, region=None):
    """Supplement enclave entropy with KMS GenerateRandom (called once after creds arrive).

    *aws_creds* and *region* are passed explicitly rather than read from
    ``os.environ`` (see ``_kms_client_kwargs`` for the rationale).
    """
    global _entropy_seeded
    if _entropy_seeded:
        logging.info("[ENTROPY] Already seeded, skipping")
        return
    if not aws_creds:
        logging.info("[ENTROPY] No AWS creds supplied; skipping KMS entropy seed.")
        return
    try:
        region = region or aws_creds.get("region") or "us-east-2"
        logging.info(f"[ENTROPY] Calling KMS GenerateRandom in region={region}...")
        client = boto3.client(
            "kms",
            **_kms_client_kwargs(aws_creds, region),
        )
        resp = client.generate_random(NumberOfBytes=256)
        with open('/dev/urandom', 'wb') as f:
            f.write(resp['Plaintext'])
        _entropy_seeded = True
        logging.info("[ENTROPY] Seeded entropy pool with 256 bytes from KMS GenerateRandom")
    except Exception as e:
        logging.warning(f"[ENTROPY] KMS GenerateRandom failed (non-fatal): {type(e).__name__}")

def _bring_up_loopback():
    """Bring up the loopback interface so 127.0.0.1 is routable."""
    for cmd in [
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'addr', 'add', '127.0.0.1/8', 'dev', 'lo'],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass
    try:
        test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test.settimeout(2)
        test.bind(('127.0.0.1', 0))
        test.close()
        logging.info("Loopback interface is up")
    except Exception as e:
        logging.warning(f"Loopback may not be functional: {e}")

#: vsock port the host forwards to the regional KMS endpoint.  Set up at bake
#: time by ``scripts/nitro_aws/setup_nitro.sh``.
_VSOCK_PORT_KMS = 8000
#: vsock port the host forwards to the SIEM collector, when ``--siem`` is in
#: play.  Added at *deploy* time, not bake time, because the collector endpoint
#: is deploy-time knowledge -- see ``siem_sidecar.install_enclave_egress``.
_VSOCK_PORT_SIEM = 8001

#: Each tunnelled destination gets its own loopback address rather than its own
#: port.  Ports would collide: the KMS tunnel owns 443, and a collector on 443
#: (Datadog, and any HTTPS collector on the default port) would land on it.
#:
#: Routing by address instead is what keeps TLS honest.  The redirect happens in
#: ``getaddrinfo``, which resolves the *host* and leaves the port and the
#: hostname alone, so urllib3 still wraps the socket with
#: ``server_hostname=<real collector>`` and still verifies the certificate
#: against it.  The enclave therefore terminates its own TLS to the collector:
#: the parent instance can drop the traffic, but it cannot read it, and it
#: cannot forge a delivery confirmation.  That is the property the whole
#: in-enclave export design rests on.
#:
#: 127.0.0.0/8 is entirely loopback and ``_bring_up_loopback`` adds the /8 to
#: ``lo``, so every address here is already routable inside the enclave.
_LOOPBACK_KMS = '127.0.0.1'
_LOOPBACK_SIEM = '127.0.0.2'


def _siem_collector_endpoint():
    """``(host, port)`` of the SIEM collector, or ``(None, 0)`` if not set.

    Read from the environment, which on Nitro means the measured
    ``siem.env.public`` baked into the EIF.  Host and port are not secrets --
    the token is, and it does not come this way.
    """
    host = os.environ.get('TEE_CRAFTER_SIEM_COLLECTOR_HOST', '').strip()
    raw_port = os.environ.get('TEE_CRAFTER_SIEM_COLLECTOR_PORT', '').strip()
    if not host:
        return None, 0
    try:
        port = int(raw_port)
    except ValueError:
        logging.warning(
            "[SIEM] ignoring non-integer TEE_CRAFTER_SIEM_COLLECTOR_PORT=%r",
            raw_port)
        return None, 0
    if not (0 < port < 65536):
        return None, 0
    return host, port


def start_vsock_proxy():
    """
    TCP-to-VSOCK tunnels giving the enclave outbound TLS to a fixed allowlist.

    Two destinations, one loopback address each (see ``_LOOPBACK_*``):

      127.0.0.1:<port> -> vsock CID 3:8000 -> kms.<region>.amazonaws.com
      127.0.0.2:<port> -> vsock CID 3:8001 -> the SIEM collector (if configured)

    The host's ``vsock-proxy`` runs in simple mode, so each vsock port is
    hard-wired to one destination host:port on the parent and the enclave cannot
    redirect it.  We patch DNS so the client libraries resolve each hostname to
    its own loopback address, giving them a direct TLS path with ordinary
    certificate verification -- no HTTP CONNECT, and no TLS termination outside
    the enclave.
    """
    _bring_up_loopback()

    siem_host, siem_port = _siem_collector_endpoint()

    _orig_getaddrinfo = socket.getaddrinfo
    def _patched_getaddrinfo(host, port, *args, **kwargs):
        if isinstance(host, str) and host.startswith('kms.') and host.endswith('.amazonaws.com'):
            logging.info(f"DNS redirect: {host}:{port} -> {_LOOPBACK_KMS}:{port}")
            return _orig_getaddrinfo(_LOOPBACK_KMS, port, *args, **kwargs)
        if siem_host and isinstance(host, str) and host == siem_host:
            logging.info(f"DNS redirect: {host}:{port} -> {_LOOPBACK_SIEM}:{port}")
            return _orig_getaddrinfo(_LOOPBACK_SIEM, port, *args, **kwargs)
        return _orig_getaddrinfo(host, port, *args, **kwargs)
    socket.getaddrinfo = _patched_getaddrinfo

    def _forward(src, dst, label):
        """Forward data in one direction using blocking recv (no select)."""
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass

    def _accept_loop(bind_ip, bind_port, vsock_port, label):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, bind_port))
        srv.listen(8)
        logging.info(
            f"TCP-to-VSOCK proxy listening on {bind_ip}:{bind_port} "
            f"-> CID 3:{vsock_port} ({label})")
        while True:
            tcp_sock = None
            try:
                tcp_sock, _ = srv.accept()
                vsock_sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
                vsock_sock.settimeout(10)
                vsock_sock.connect((3, vsock_port))
                vsock_sock.settimeout(None)
                logging.info(f"VSOCK tunnel established to CID 3:{vsock_port} ({label})")
                threading.Thread(target=_forward, args=(tcp_sock, vsock_sock, "tcp→vsock"), daemon=True).start()
                threading.Thread(target=_forward, args=(vsock_sock, tcp_sock, "vsock→tcp"), daemon=True).start()
            except Exception as e:
                logging.error(f"Proxy connect error ({label}): {e}")
                try:
                    if tcp_sock is not None:
                        tcp_sock.close()
                except Exception:
                    pass

    threading.Thread(
        target=_accept_loop,
        args=(_LOOPBACK_KMS, 443, _VSOCK_PORT_KMS, "kms"),
        daemon=True).start()

    if siem_host:
        # Bound on the collector's own port so the getaddrinfo redirect, which
        # only rewrites the host, still lands somewhere that is listening.
        threading.Thread(
            target=_accept_loop,
            args=(_LOOPBACK_SIEM, siem_port, _VSOCK_PORT_SIEM,
                  f"siem:{siem_host}"),
            daemon=True).start()
        logging.info(
            f"[SIEM] enclave egress armed for {siem_host}:{siem_port} "
            f"via CID 3:{_VSOCK_PORT_SIEM}")

    import time
    time.sleep(0.5)

    os.environ['AWS_DEFAULT_REGION'] = os.environ.get('AWS_REGION', 'us-east-2')
    logging.info("Started vsock proxy (simple TCP tunnel, no HTTP CONNECT)")

def handle_attestation_request(nonce: str = "", public_key_b64: str = "") -> str:
    """Fetch an NSM attestation document.

    ``nonce`` and ``public_key_b64`` are **base64**: ``nsm_main.rs`` decodes
    both with ``general_purpose::STANDARD.decode(..).expect(..)``, so a value
    that is not valid standard base64 panics the helper rather than returning
    an error.  The panic surfaces here only as a ``CalledProcessError``, which
    this function used to convert into a JSON ``{"error": ...}`` string --
    indistinguishable from a document to every caller, all of which slice it
    (``doc[:64]``) and record the slice as a "measurement".

    Two internal callers were passing raw ASCII labels.  ``"monitor"`` is 7
    characters, so ``len % 4 == 3`` and the decode always failed: the
    continuous attestation monitor has been recording a prefix of that error
    string as its measurement.  ``"rotation"`` is 8 characters, so it decoded
    -- to six unrelated bytes, not the ASCII the author intended.  Validating
    here turns a silent wrong answer into a loud one.
    """
    if nonce:
        try:
            base64.b64decode(nonce, validate=True)
        except Exception:
            raise ValueError(
                f"nonce must be standard base64 (nsm-cli panics otherwise); "
                f"got {nonce!r}")
    try:
        logging.info("Calling nsm-cli for attestation document")
        args = ['/usr/local/bin/nsm-cli']
        if nonce:
            args.extend(['--nonce', nonce])
        if public_key_b64:
            args.extend(['--public-key', public_key_b64])

        result = subprocess.run(args, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Attestation failed: {e.stderr}")
        return json.dumps({"error": "Attestation tool is not available or failed"})

def _decrypt_cms_enveloped_data(cms_bytes: bytes, private_key) -> bytes:
    """
    Parses CMS (RFC 5652) EnvelopedData returned by KMS CiphertextForRecipient,
    RSA-unwraps the content-encryption key, then AES-decrypts the payload.
    """
    logging.info(f"[CMS] Envelope size: {len(cms_bytes)} bytes")
    content_info = asn1_cms.ContentInfo.load(cms_bytes)
    logging.info(f"[CMS] ContentInfo type: {content_info['content_type'].native}")
    enveloped_data = content_info['content']

    ri = enveloped_data['recipient_infos'][0].chosen
    encrypted_key = ri['encrypted_key'].native
    logging.info(f"[CMS] Encrypted CEK size: {len(encrypted_key)} bytes")

    cek = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.info(f"[CMS] Decrypted CEK size: {len(cek)} bytes")

    enc_ci = enveloped_data['encrypted_content_info']
    algo = enc_ci['content_encryption_algorithm']
    encrypted_content = enc_ci['encrypted_content'].native

    algo_name = algo['algorithm'].native
    algo_oid = algo['algorithm'].dotted
    mode = algo.encryption_mode
    iv_or_nonce = algo.encryption_iv
    logging.info(f"[CMS] Algorithm: {algo_name} (OID {algo_oid}), mode={mode}, "
                 f"iv/nonce={len(iv_or_nonce)} bytes, ciphertext={len(encrypted_content)} bytes")

    if mode == 'gcm':
        plaintext = AESGCM(cek).decrypt(iv_or_nonce, encrypted_content, None)
    elif mode == 'cbc':
        decryptor = Cipher(algorithms.AES(cek), modes.CBC(iv_or_nonce)).decryptor()
        padded = decryptor.update(encrypted_content) + decryptor.finalize()
        if not padded:
            raise ValueError("CBC decryption produced empty output")
        pad_len = padded[-1]
        if pad_len < 1 or pad_len > 16 or len(padded) < pad_len:
            raise ValueError(f"Invalid PKCS#7 padding length: {pad_len}")
        if any(b != pad_len for b in padded[-pad_len:]):
            raise ValueError("Invalid PKCS#7 padding bytes")
        plaintext = padded[:-pad_len]
    else:
        raise ValueError(f"Unsupported encryption mode '{mode}' for algorithm {algo_name} (OID {algo_oid})")

    logging.info(f"[CMS] Decrypted plaintext size: {len(plaintext)} bytes")
    return plaintext

def _ecdh_decrypt(client_pub_bytes: bytes, nonce: bytes, ciphertext: bytes,
                  salt: bytes = None) -> tuple:
    """Derive shared AES-256-GCM keys via ECDH, decrypt the payload,
    and return (plaintext, response_key)."""
    client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_pub_bytes)
    shared_secret = _ECDH_KEY.exchange(ec.ECDH(), client_pub)
    hkdf_salt = salt or (b'\x00' * 32)
    req_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=hkdf_salt,
        info=b"tee-crafter-nitro-v1",
    ).derive(shared_secret)
    resp_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=hkdf_salt,
        info=b"tee-crafter-nitro-v1-resp",
    ).derive(shared_secret)
    plaintext = AESGCM(req_key).decrypt(nonce, ciphertext, b"tee-crafter-nitro-v1-req")
    return plaintext, resp_key


def kms_decrypt_with_attestation(ciphertext_b64: str, region: str = None,
                                  *, aws_creds=None) -> bytes:
    """
    Decrypts KMS ciphertext using AWS Nitro Enclave Attestation.
    Requests an attestation document with the enclave's generated public key,
    passes it to KMS, and unwraps the CMS envelope returned in CiphertextForRecipient.

    *aws_creds* (optional) is the per-request credentials dict forwarded by
    the host_proxy.  When given, we pass it to boto3 as explicit client
    kwargs — we never touch ``os.environ``, so credentials cannot leak to
    other code paths running in the same enclave interpreter.
    """
    logging.info("[KMS_DECRYPT] Step 1: Requesting attestation doc with RSA public key...")
    doc_b64 = handle_attestation_request(public_key_b64=_RSA_PUB_B64)
    logging.info(f"[KMS_DECRYPT] Attestation doc length: {len(doc_b64)} chars")
    if "error" in doc_b64:
        raise Exception(f"Failed to get attestation doc for KMS: {doc_b64}")
        
    doc_bytes = base64.b64decode(doc_b64)
    ciphertext_bytes = base64.b64decode(ciphertext_b64)
    logging.info(f"[KMS_DECRYPT] Step 2: Attestation doc: {len(doc_bytes)} bytes, ciphertext: {len(ciphertext_bytes)} bytes")
    
    if not region:
        # Prefer the region carried alongside the per-request creds; fall
        # back to the boot-time default.  We deliberately do NOT consult
        # ``os.environ`` because that would couple this request to whatever
        # global state a prior request might have left behind.
        region = (aws_creds or {}).get("region") or "us-east-2"
    
    logging.info(f"[KMS_DECRYPT] Step 3: Calling KMS Decrypt in region={region}")
    
    client = boto3.client(
        "kms",
        **_kms_client_kwargs(aws_creds, region),
    )

    response = client.decrypt(
        CiphertextBlob=ciphertext_bytes,
        Recipient={
            'KeyEncryptionAlgorithm': 'RSAES_OAEP_SHA_256',
            'AttestationDocument': doc_bytes
        }
    )
    
    cfr = response.get('CiphertextForRecipient')
    pt = response.get('Plaintext')
    logging.info(f"[KMS_DECRYPT] Step 4: KMS response keys={list(response.keys())}")
    logging.info(f"[KMS_DECRYPT]   CiphertextForRecipient: {type(cfr).__name__}, len={len(cfr) if cfr else 0}")
    logging.info(f"[KMS_DECRYPT]   Plaintext: {type(pt).__name__}, len={len(pt) if pt else 0}")
    
    if not cfr or len(cfr) == 0:
        raise Exception(f"KMS returned empty CiphertextForRecipient. Plaintext len={len(pt) if pt else 0}. "
                        f"This may mean the Recipient/attestation was ignored by KMS.")
    
    logging.info("[KMS_DECRYPT] Step 5: Unwrapping CMS envelope...")
    plaintext = _decrypt_cms_enveloped_data(cfr, _RSA_KEY)
    logging.info(f"[KMS_DECRYPT] Step 6: Done. Plaintext size: {len(plaintext)} bytes")
    return plaintext

def start_in_enclave_siem_export():
    """Run the attestation exporter *inside* the enclave, if SIEM is enabled.

    This is what makes the fail-closed gate real on Nitro rather than
    decorative.  Previously the exporter ran as a host-side sidecar, wrote
    ``/run/tee-crafter-nitro-aws/siem.health`` on the *parent instance*, and no
    SIEM variable crossed into the EIF at all -- so in here
    ``siem_health.is_fail_closed()`` returned False, ``fail_closed_wrap`` passed
    every request through, and the enclave could not have read that health file
    even if it had wanted to.  Continuous-attestation export was therefore a
    detective control on this platform: the SOC saw the stream stop, but nothing
    stopped the workload.

    Running it here fixes both halves at once.  The exporter writes its health
    file into the enclave's own tmpfs, which is the same namespace
    ``siem_health`` reads, and it delivers over the enclave's own TLS session
    through the vsock tunnel armed by ``start_vsock_proxy``.  A parent instance
    that wants to hide a blackout can drop the packets, but it cannot terminate
    that TLS session and it cannot fabricate a collector's acceptance -- so
    ``last_export_status`` finally means something in here.

    Never fatal: a failure to start the exporter must not take the workload
    down.  It does not need to, either -- the gate reads the health file, so an
    exporter that never starts leaves it absent and the enclave fail-closes on
    its own.
    """
    if os.environ.get('TEE_CRAFTER_SIEM_ENABLED', '').strip().lower() not in (
            '1', 'true', 'yes', 'on'):
        return
    def _run():
        try:
            import siem_export
            siem_export.main()
        except Exception as exc:
            logging.warning("[SIEM] in-enclave exporter stopped: %r", exc)
    threading.Thread(target=_run, name="siem-export", daemon=True).start()
    logging.info("[SIEM] in-enclave attestation exporter started")


def run_vsock_server():
    start_vsock_proxy()
    start_in_enclave_siem_export()

    server_sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server_sock.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
    server_sock.listen(5)
    logging.info(f"Listening on vsock port {VSOCK_PORT}")

    # One-time startup report for build provenance audit (stdout so nitro-cli console captures it)
    try:
        startup_report = {
            "audit": "enclave_startup",
            "steps": [
                "rsa_key_generated",
                "ecdh_key_generated_for_ecies",
                "loopback_interface_up",
                "dns_patch_kms_to_loopback",
                "tcp_to_vsock_proxy_listening",
                "vsock_server_listening",
            ],
        }
        print(json.dumps(startup_report), flush=True)
    except Exception:
        pass

    # --- Continuous attestation monitor ---
    try:
        import tee_crafter_attestation_monitor

        def _nitro_attest_for_monitor():
            # Base64, not the bare word "monitor" (7 chars => invalid base64,
            # which panicked nsm-cli on every single poll).
            doc_b64 = handle_attestation_request(
                nonce=base64.b64encode(b"monitor").decode("ascii"),
                public_key_b64=_ECDH_PUB_B64)
            # An error string sliced to 64 chars is not a measurement. Refuse
            # rather than record the prefix of a failure as evidence.
            if doc_b64.lstrip().startswith("{"):
                raise RuntimeError(
                    f"attestation monitor got an error instead of a document: "
                    f"{doc_b64[:200]}")
            return {"measurement": doc_b64[:64], "doc_b64_prefix": doc_b64[:128]}

        tee_crafter_attestation_monitor.configure(_nitro_attest_for_monitor)
        tee_crafter_attestation_monitor.start()
        logging.info("[VSOCK] Continuous attestation monitor started")
    except ImportError:
        pass
    except Exception as _mon_err:
        logging.warning("[VSOCK] Attestation monitor startup failed: %s", _mon_err)

    def _sigterm_handler(signum, frame):
        global _shutdown
        logging.info("[VSOCK] SIGTERM received, draining and shutting down...")
        _shutdown = True

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGINT, _sigterm_handler)
    server_sock.settimeout(1.0)

    while not _shutdown:
        _do_rotate = False
        _rotate_reason = "time_based"
        if _kr_available:
            _do_rotate, _rotate_reason = _kr.should_rotate()
        elif _time.monotonic() - _ecdh_created_at > _KEY_ROTATION_SECS:
            _do_rotate = True
        if _do_rotate:
            try:
                _t0 = _time.monotonic()
                _rotate_ecdh_key()
                _rot_ms = (_time.monotonic() - _t0) * 1000
                if _kr_available:
                    _kr.record_rotation(
                        f"ecdh-{_kr._total_rotations + 1}",
                        _ECDH_PUB_BYTES,
                        new_key_type="ECDH-P384",
                        reason=_rotate_reason,
                        rotation_latency_ms=_rot_ms,
                    )
                logging.info("[VSOCK] ECDH key rotated (forward secrecy)")
            except Exception as e:
                logging.error("[VSOCK] ECDH key rotation failed: %s", e)

        try:
            client_sock, addr = server_sock.accept()
        except socket.timeout:
            continue
        except OSError as e:
            if _shutdown:
                break
            logging.warning(f"[VSOCK] Accept error: {e}")
            continue
        if not _rate_limit_check():
            logging.warning("[VSOCK] Rate limit exceeded, dropping connection")
            try:
                client_sock.close()
            except Exception:
                pass
            continue

        logging.info("[VSOCK] Client connected")
        try:
            payload = b""
            while True:
                chunk = client_sock.recv(4096)
                if not chunk: break
                payload += chunk
                if len(payload) > MAX_PAYLOAD_SIZE:
                    logging.warning(f"[VSOCK] Payload exceeds {MAX_PAYLOAD_SIZE} bytes, rejecting")
                    client_sock.sendall(json.dumps({"error": "Payload too large"}).encode())
                    break

            if len(payload) > MAX_PAYLOAD_SIZE: continue
            if not payload: continue
            logging.info(f"[VSOCK] Received payload: {len(payload)} bytes")
            
            data = json.loads(payload.decode('utf-8'))
            data_keys = list(data.keys()) if isinstance(data, dict) else f"list[{len(data)}]"
            # SECURITY: never include the raw key list in production logs —
            # ``__aws_credentials`` would appear here.  Redact it.
            _safe_key_repr = (
                [k for k in data_keys if k != "__aws_credentials"]
                + (["__aws_credentials(redacted)"]
                   if isinstance(data, dict) and "__aws_credentials" in data
                   else [])
            ) if isinstance(data, dict) else data_keys
            logging.info(f"[VSOCK] Parsed JSON, keys/type: {_safe_key_repr}")

            # SEC-CREDS-1: extract per-request AWS credentials WITHOUT
            # ever touching ``os.environ``.  See ``_kms_client_kwargs``
            # for the rationale.  ``aws_creds`` is a local variable, GC'd
            # the moment this except/finally block returns; nothing else
            # in the interpreter can see it.
            aws_creds = data.pop('__aws_credentials', None)
            if aws_creds:
                # LOG-1: only emit region + expiry.  The access-key tail
                # is identifying material — combined with a wall-clock
                # timestamp it points back at a specific IAM principal
                # in CloudTrail, so do not emit it from inside the TEE
                # (which is more privileged than the host journal).
                logging.info(
                    "[VSOCK] Per-request AWS creds attached "
                    "(region=%s expires=%s)",
                    aws_creds.get("region"),
                    aws_creds.get("expiration", "?"),
                )
            else:
                # Not all paths need KMS (get_attestation, ECIES with
                # entropy already seeded).  This is a normal info log,
                # not a warning.
                logging.info("[VSOCK] No __aws_credentials in payload "
                             "(non-KMS path or creds-free smoke).")
            
            # 1. Attestation Path — include ECDH public key in the attestation doc
            #    so the client can verify it via the COSE_Sign1 signature.
            if isinstance(data, dict) and data.get("action") == "get_attestation":
                logging.info("[VSOCK] -> Attestation path (ECDH key embedded)")
                # AUD-3.  The NSM signs exactly three guest-supplied fields
                # into the attestation document — user_data, nonce and
                # public_key — and the nsm-cli helper staged into this image
                # (templates/common/nsm_main.rs) hardcodes user_data=None and
                # exposes no flag for it.  public_key must stay the raw ECDH
                # key the client extracts.  That leaves the nonce field, so
                # the audit-log chain-key commitment is folded into it:
                #
                #   doc.nonce == _attest_binding_digest(
                #       client_nonce_raw, chain_key_commitment_hex_ascii)
                #
                # The COSE_Sign1 signature from the Nitro Hypervisor
                # therefore covers the commitment.  Freshness is unchanged:
                # the digest is still a one-to-one function of the client's
                # 32 random bytes.
                _client_nonce_b64 = data.get("nonce", "")
                try:
                    _client_nonce = base64.b64decode(_client_nonce_b64, validate=True)
                except Exception:
                    # Preserve the historical shape: an unusable nonce yields
                    # a document the client will reject, not a 500.
                    _client_nonce = b""
                _bound_nonce = _attest_binding_digest(
                    _client_nonce, _CHAIN_KEY_COMMITMENT.encode("ascii"))
                doc_b64 = handle_attestation_request(
                    nonce=base64.b64encode(_bound_nonce).decode("ascii"),
                    public_key_b64=_ECDH_PUB_B64,
                )
                response = json.dumps({
                    "attestation_doc_b64": doc_b64,
                    "enclave_public_key": _ECDH_PUB_B64,
                    # Self-describing so a client knows exactly which bytes
                    # to recompute.  "lp(x)" == uint32be(len(x)) || x.
                    "nonce_binding": (
                        "sha256(lp('tee-crafter/attest-binding/v2') || "
                        "uint32be(2) || lp(client_nonce_raw) || "
                        "lp(chain_key_commitment_hex_ascii))"),
                    "nonce_binding_label": _ATTEST_BINDING_LABEL.decode("ascii"),
                    # AUD-3: the exact value the Nitro Hypervisor signed over.
                    "chain_key_commitment": _CHAIN_KEY_COMMITMENT,
                })

            # 2. ECIES Data Path — E2E encrypted data from the client
            elif isinstance(data, dict) and data.get("encrypted_payload"):
                logging.info("[VSOCK] -> ECIES data processing path")
                # Entropy seeding is best-effort and only runs once.  Pass
                # creds explicitly so KMS GenerateRandom is properly
                # authenticated when first invoked.
                seed_entropy_from_kms(aws_creds=aws_creds)

                client_pub_bytes = base64.b64decode(data["client_public_key"])
                nonce = base64.b64decode(data["nonce"])
                ciphertext = base64.b64decode(data["encrypted_payload"])
                hkdf_salt = base64.b64decode(data.get("hkdf_salt", "")) or None

                plaintext_bytes, resp_key = _ecdh_decrypt(
                    client_pub_bytes, nonce, ciphertext, hkdf_salt
                )
                plaintext_obj = json.loads(plaintext_bytes.decode("utf-8"))
                logging.info("[VSOCK] ECIES decrypted, calling process_request...")
                results = process_request(plaintext_obj)
                logging.info(f"[VSOCK] process_request returned type={type(results).__name__}")


                result_bytes = json.dumps(results, default=str).encode("utf-8")
                resp_nonce = os.urandom(12)
                resp_ct = AESGCM(resp_key).encrypt(resp_nonce, result_bytes, b"tee-crafter-nitro-v1-resp")
                response = json.dumps({
                    "nonce": base64.b64encode(resp_nonce).decode(),
                    "encrypted_response": base64.b64encode(resp_ct).decode(),
                })
                logging.info(f"[VSOCK] ECIES response size: {len(response)} bytes")

            # 3. KMS-encrypted data path
            elif isinstance(data, dict) and data.get("ciphertext_b64"):
                logging.info("[VSOCK] -> KMS data processing path")
                seed_entropy_from_kms(aws_creds=aws_creds)
                ciphertext_b64 = data["ciphertext_b64"]
                logging.info("[VSOCK] Decrypting ciphertext via KMS attestation...")
                plaintext_bytes = kms_decrypt_with_attestation(
                    ciphertext_b64, aws_creds=aws_creds,
                )
                plaintext_obj = json.loads(plaintext_bytes.decode("utf-8"))
                logging.info("[VSOCK] KMS decrypted, calling process_request...")
                results = process_request(plaintext_obj)
                logging.info(f"[VSOCK] process_request returned type={type(results).__name__}")


                response = json.dumps(results, default=str)
                logging.info(f"[VSOCK] Response JSON size: {len(response)} bytes")

            else:
                raise ValueError("Unrecognized request: must contain 'action', "
                                 "'encrypted_payload', or 'ciphertext_b64'")

            client_sock.sendall(response.encode('utf-8'))
            logging.info("[VSOCK] Response sent successfully")
            if _kr_available:
                _kr.tick_request()

        except Exception as e:
            logging.error("Error processing request: %s", type(e).__name__)
            error_detail = {
                "error": "Internal enclave processing error",
            }
            try:
                client_sock.sendall(json.dumps(error_detail).encode('utf-8'))
            except Exception:
                pass  # client may have already disconnected
        finally:
            # SEC-CREDS-1: ``aws_creds`` was a local variable scoped to
            # this request.  Drop the reference so the dict can be GC'd
            # promptly on EVERY exit path (success, error, or partial
            # write).  No global env vars were ever set, so there's
            # nothing else to scrub.
            try:
                del aws_creds
            except NameError:
                pass
            client_sock.close()

    server_sock.close()
    logging.info("[VSOCK] Server shut down gracefully.")

if __name__ == "__main__":
    run_vsock_server()