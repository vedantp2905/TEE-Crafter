import socket
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
_AESGCM_AAD_REQ = b"tee-crafter-sgx-v1-req"
_AESGCM_AAD_RESP = b"tee-crafter-sgx-v1-resp"


def _rotate_ecdh_key():
    global _ECDH_KEY, _ECDH_PUB, _ECDH_PUB_BYTES, _ECDH_PUB_B64
    _ECDH_KEY = ec.generate_private_key(ec.SECP256R1())
    _ECDH_PUB = _ECDH_KEY.public_key()
    _ECDH_PUB_BYTES = _ECDH_PUB.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    _ECDH_PUB_B64 = base64.b64encode(_ECDH_PUB_BYTES).decode("utf-8")
    logging.info("[SGX] ECDH keypair rotated")


# --- Key rotation manager integration ---
try:
    import tee_crafter_key_rotation as _kr
    _kr.configure(rotation_interval_secs=_CERT_ROTATION_SECS)
    _kr.record_key_birth("ecdh-boot-0", _ECDH_PUB_BYTES, key_type="ECDH-P256")
    _kr_available = True
except ImportError:
    _kr_available = False


def _read_sgx_target_info():
    """Read SGX target info from Gramine's pseudo-filesystem."""
    try:
        with open("/dev/attestation/target_info", "rb") as f:
            return f.read()
    except FileNotFoundError:
        logging.warning("[SGX] /dev/attestation/target_info not found — running outside SGX?")
        return None


def _generate_sgx_report(user_report_data: bytes) -> bytes:
    """
    Generate an SGX report by writing report data to Gramine's attestation
    pseudo-filesystem and reading the resulting report.
    """
    report_data = hashlib.sha256(user_report_data).digest()
    report_data = report_data.ljust(64, b'\x00')[:64]
    try:
        with open("/dev/attestation/user_report_data", "wb") as f:
            f.write(report_data)
        with open("/dev/attestation/report", "rb") as f:
            return f.read()
    except FileNotFoundError:
        logging.error("[SGX] Attestation pseudo-files not found")
        raise RuntimeError("SGX attestation not available — is Gramine-SGX running?")


def _generate_dcap_quote(user_report_data: bytes) -> bytes:
    """
    Generate a DCAP quote via Gramine's /dev/attestation/quote interface.
    The user_report_data (up to 64 bytes) is hashed and embedded in the quote.
    """
    report_data = hashlib.sha256(user_report_data).digest()
    report_data = report_data.ljust(64, b'\x00')[:64]
    try:
        with open("/dev/attestation/user_report_data", "wb") as f:
            f.write(report_data)
        with open("/dev/attestation/quote", "rb") as f:
            return f.read()
    except FileNotFoundError:
        logging.error("[SGX] /dev/attestation/quote not found")
        raise RuntimeError("DCAP quote generation not available — is Gramine-SGX with DCAP running?")


# ---------------------------------------------------------------------------
# AUD-3: bind the runtime audit log's genesis commitment into report_data
# ---------------------------------------------------------------------------
#
# The in-TEE audit log is an HMAC hash chain whose key never leaves enclave
# memory.  ``tee_crafter_audit_logger`` computes SHA-256(key) as the "chain key
# commitment" and writes it into the log's own genesis entry — which is purely
# self-referential: a host adversary who discards the log regenerates key,
# genesis, chain and commitment together, and no hardware-signed value
# contradicts them.  Hashing the commitment into ``report_data`` makes the SGX
# quote sign it, so a verifier can pin the value out of an attested quote and
# later reject any log whose genesis entry disagrees.

# Shared with snp/*/app.template.py and every client — one encoder, one label,
# so no two platforms can disagree about how a preimage is built.
_ATTEST_BINDING_LABEL = b"tee-crafter/attest-binding/v2"

# First field of the preimage.  The label above is platform-agnostic and the
# SNP templates already use it for their live-challenge binding, so a purpose
# string is what keeps *this* binding (the RA-TLS certificate's embedded quote,
# on sgx specifically) from ever being confused with one of those.
_CERT_BINDING_PURPOSE = b"ratls-cert-report-data/sgx"


def _attest_binding_preimage(*fields: bytes) -> bytes:
    """Encode *fields* into one unambiguous attestation-binding preimage.

    Raw concatenation is ambiguous: ``a=b"ab", b=b"cd"`` and ``a=b"abc",
    b=b"d"`` produce identical bytes, so evidence minted for one field split
    could be presented as satisfying a different one.  Here every field carries
    its own big-endian uint32 length prefix, the field *count* is prefixed too
    (so a short field list cannot be padded out into a longer one), and the
    whole encoding is prefixed with a version label so a v1 preimage — bare
    ``sha256(ecdh_pub)``, which carried no commitment — can never be
    reinterpreted as a v2 one.  Clients recompute this byte-for-byte, which is
    why the label is part of the hashed bytes rather than just a comment.
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
    "sha256(lp('tee-crafter/attest-binding/v2') || uint32be(3) || "
    "lp('ratls-cert-report-data/sgx') || lp(ecdh_pub) || "
    "lp(chain_key_commitment_hex_ascii))")


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
        logging.warning("[SGX] chain-commitment bootstrap unavailable: %r", exc)
    if not commitment:
        # Publication writes under /run, which manifest.template.toml does not
        # mount, so inside the Gramine enclave that write always fails and
        # bootstrap_chain_commitment() returns "".  The commitment itself is an
        # in-process value that needs no filesystem, so read it directly rather
        # than losing the hardware binding over a failed side-effect.
        try:
            import tee_crafter_audit_logger as _al
            commitment = _al.get_chain_key_commitment() or ""
        except Exception as exc:
            logging.error(
                "[SGX] runtime audit logger not importable (%r) — this quote "
                "will carry no audit-chain commitment and a client without "
                "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_COMMITMENT=1 will refuse it",
                exc)
    _chain_commitment_hex = commitment
    return commitment


def _read_mrenclave() -> str:
    """Read the MRENCLAVE measurement from Gramine's pseudo-filesystem."""
    try:
        with open("/dev/attestation/my_target_info", "rb") as f:
            target_info = f.read()
        return target_info[:32].hex()
    except Exception:
        return "unknown"


_RATLS_MATERIAL_DIR = "/ratls"


def _ratls_material_dir() -> str:
    """Return the in-enclave directory used for transient RA-TLS PEM files.

    ``/ratls`` is declared as a ``tmpfs`` mount in manifest.template.toml.
    Gramine tmpfs files live in enclave memory and "are not backed by
    host-level files", so the TLS private key written below never reaches
    host-visible storage.  ``/tmp`` must not be used for this: it is a
    ``chroot`` passthrough to the host's /tmp and is listed in the
    manifest's ``allowed_files`` (unmeasured, unencrypted host storage).

    Fails closed.  If the tmpfs mount is missing we would silently fall
    back to host storage, which is exactly the bug this replaces.
    """
    try:
        os.makedirs(_RATLS_MATERIAL_DIR, mode=0o700, exist_ok=True)
        probe = os.path.join(_RATLS_MATERIAL_DIR, ".writable")
        with open(probe, "wb") as fh:
            fh.write(b"")
        os.unlink(probe)
    except OSError as exc:
        raise RuntimeError(
            f"RA-TLS material directory {_RATLS_MATERIAL_DIR} is not usable "
            f"({exc}). It must be declared as a tmpfs mount in the Gramine "
            "manifest; refusing to write the TLS private key to host-visible "
            "storage instead."
        ) from exc
    return _RATLS_MATERIAL_DIR


def _create_ratls_context():
    """
    Create the enclave's attested-TLS SSL context.

    This is hand-rolled with ``cryptography`` — Gramine's own RA-TLS
    library is not used.  We build a self-signed certificate and embed the
    DCAP quote in an X.509 extension so the client can verify enclave
    identity from the handshake certificate.

    The DCAP quote's report_data is bound to SHA-256 of the v2 preimage
    (``_attest_binding_preimage``): the *ECDH* key plus the runtime audit
    log's genesis commitment, not the TLS key.  The TLS key below is
    unattested; it is the inner ECIES layer keyed to that ECDH key that
    carries the attested identity.  See the SNP clients' get_attestation
    challenge for the same distinction spelled out.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    _mat_dir = _ratls_material_dir()
    cert_path = os.path.join(_mat_dir, "cert.pem")
    key_path = os.path.join(_mat_dir, "key.pem")

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime as _dt

    tls_key = ec.generate_private_key(ec.SECP384R1())

    _commitment = _chain_key_commitment()
    quote = _generate_dcap_quote(_attest_binding_preimage(
        _CERT_BINDING_PURPOSE, _ECDH_PUB_BYTES, _commitment.encode("ascii")))

    SGX_QUOTE_OID = x509.ObjectIdentifier("1.2.840.113741.1.13.1")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "sgx-enclave.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEECrafter-SGX"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow())
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(hours=1))
        .add_extension(
            x509.UnrecognizedExtension(SGX_QUOTE_OID, quote),
            critical=False,
        )
        .sign(tls_key, hashes.SHA384())
    )

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
    logging.info("[RA-TLS] Generated attested TLS certificate with embedded DCAP "
                 "quote (report_data bound to the ECDH public key and the "
                 "audit-chain commitment %s; PEMs written to the %s tmpfs, which "
                 "never touches host storage, and unlinked)",
                 (_commitment[:16] + "...") if _commitment else "<absent>",
                 _RATLS_MATERIAL_DIR)
    return ctx


def _ecdh_decrypt(client_pub_bytes: bytes, nonce: bytes, ciphertext: bytes, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive shared AES-256-GCM keys via ECDH, decrypt the payload, and return (plaintext, response_key)."""
    client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)
    shared_secret = _ECDH_KEY.exchange(ec.ECDH(), client_pub)
    req_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"tee-crafter-sgx-v1",
    ).derive(shared_secret)
    resp_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"tee-crafter-sgx-v1-resp",
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
            logging.warning("[SGX] Payload size %d exceeds limit %d, rejecting", msg_len, MAX_PAYLOAD_SIZE)
            conn.close()
            return
        payload = _recv_exactly(conn, msg_len)

        logging.info("[SGX] Received payload: %d bytes", len(payload))
        data = json.loads(payload.decode("utf-8"))

        if isinstance(data, dict) and data.get("action") == "get_attestation":
            logging.info("[SGX] -> Attestation path")
            nonce = data.get("nonce", "").encode("utf-8")
            quote = _generate_dcap_quote(nonce)
            mrenclave = _read_mrenclave()
            response = json.dumps({
                "quote_hex": quote.hex(),
                "mrenclave": mrenclave,
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
            logging.info("[SGX] -> Encrypted data processing path")
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
            logging.info("[SGX] process_request returned type=%s", type(results).__name__)


            result_bytes = json.dumps(results, default=str).encode("utf-8")
            resp_nonce = os.urandom(12)
            resp_ct = AESGCM(resp_key).encrypt(resp_nonce, result_bytes, _AESGCM_AAD_RESP)
            response = json.dumps({
                "encrypted_response": base64.b64encode(resp_ct).decode(),
                "response_nonce": base64.b64encode(resp_nonce).decode(),
            })
            logging.info("[SGX] Encrypted response size: %d bytes", len(resp_ct))

        else:
            raise ValueError("Request must include 'action' or 'encrypted_payload'")

        resp_bytes = response.encode("utf-8")
        conn.sendall(struct.pack("!I", len(resp_bytes)))
        conn.sendall(resp_bytes)
        logging.info("[SGX] Response sent successfully (%d bytes)", len(resp_bytes))
        if _kr_available:
            _kr.tick_request()

    except ConnectionError:
        logging.warning("[SGX] Client disconnected during message exchange")
    except Exception as e:
        logging.error("Error processing request: %s", type(e).__name__)
        try:
            error_detail = json.dumps({"error": "Internal enclave processing error"}).encode("utf-8")
            conn.sendall(struct.pack("!I", len(error_detail)))
            conn.sendall(error_detail)
        except Exception:
            pass
    finally:
        conn.close()


def run_sgx_server():
    """Main entry point: start RA-TLS server inside the Gramine-SGX enclave."""
    logging.info("[SGX] Enclave server starting...")
    mrenclave = _read_mrenclave()
    logging.info("[SGX] MRENCLAVE: %s", mrenclave)


    ctx = _create_ratls_context()
    _ratls_created_at = _time.monotonic()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    logging.info("[SGX] RA-TLS server listening on port %d", LISTEN_PORT)

    try:
        startup_report = {
            "audit": "sgx_enclave_startup",
            "steps": [
                "ecdh_keypair_generated",
                "mrenclave_read",
                "ratls_cert_generated_with_dcap_quote",
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

        def _sgx_attest_for_monitor():
            m = _read_mrenclave()
            return {"measurement": m}

        tee_crafter_attestation_monitor.configure(_sgx_attest_for_monitor)
        tee_crafter_attestation_monitor.start(baseline_measurement=mrenclave)
        logging.info("[SGX] Continuous attestation monitor started")
    except ImportError:
        pass
    except Exception as _mon_err:
        logging.warning("[SGX] Attestation monitor startup failed: %s", _mon_err)

    def _sigterm_handler(signum, frame):
        global _shutdown
        logging.info("[SGX] SIGTERM received, draining and shutting down...")
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
                logging.info("[SGX] RA-TLS certificate rotated")
            except Exception as e:
                logging.error("[SGX] Certificate rotation failed: %s", e)

        try:
            raw_conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError as e:
            if _shutdown:
                break
            logging.warning("[SGX] TCP accept error: %s", e)
            continue

        if not _rate_limit_check():
            logging.warning("[SGX] Rate limit exceeded, dropping connection")
            try:
                raw_conn.close()
            except Exception:
                pass
            continue

        raw_conn.settimeout(10)
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except (ssl.SSLError, ConnectionResetError, OSError) as e:
            logging.warning("[SGX] Rejected connection (TLS handshake failed): %s", type(e).__name__)
            try:
                raw_conn.close()
            except Exception:
                pass
            continue

        logging.info("[SGX] Client connected")
        _handle_connection(conn)

    srv.close()
    logging.info("[SGX] Server shut down gracefully.")


if __name__ == "__main__":
    run_sgx_server()
