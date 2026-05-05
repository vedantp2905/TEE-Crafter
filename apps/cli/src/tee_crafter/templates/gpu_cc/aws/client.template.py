import sys
import json
import os
import ssl
import socket
import hashlib
import struct
import base64

# There is deliberately no EXPECTED_MEASUREMENT here, and that is not the same
# as having no CPU pin.  A SEV-SNP-style launch measurement does not exist on
# this platform — there is no CPU-TEE, so nothing measures RAM at launch.  What
# does exist is measured boot: EXPECTED_NITROTPM_PCRS below is compared against
# hypervisor-signed PCR values from a NitroTPM attestation document.  So the
# CPU pin is PCR4/PCR7, not a launch digest, and the two are not
# interchangeable.

# NVIDIA NRAS JWKS signing CA.  This file is the NRAS *intermediate* (the
# leaf's issuer), not a self-signed root — the x5c check below pins x5c[1]
# to it byte-for-byte, so "intermediate" is the accurate name.
_NVIDIA_NRAS_INTERMEDIATE_CA_PEM = """{nvidia_root_ca}"""

# The pinned AWS Nitro root.  A NitroTPM attestation document's cabundle roots
# at CN=aws.nitro-enclaves -- byte-for-byte this certificate, which the
# nitro-aws client already pins.  Measured 2026-08-24 against a real document
# from a live instance; the comment that used to sit here, claiming NitroTPM
# "endorses a different key hierarchy" and so could not be verified locally,
# was wrong and was the reason this platform reported unverified CPU evidence.
_AWS_NITRO_ROOT_CA_PEM = """{nitro_root_ca}"""

# Reference PCR values captured at bake, as "idx:hex,idx:hex".  Empty when the
# bake recorded none, in which case the document's authenticity is still
# verified but its PCRs are not compared against anything.
EXPECTED_NITROTPM_PCRS = "{expected_nitrotpm_pcrs}"

NITROTPM_OID = "1.3.6.1.4.1.59386.2.1"
# The signed attestation document, distinct from NITROTPM_OID's unsigned
# self-reported PCR JSON.  Separate OIDs so the two can never be confused.
# .2.3 not .2.2: gpu-cc-gcp already uses .2.2 for its vTPM PCR bundle.
NITROTPM_DOC_OID = "1.3.6.1.4.1.59386.2.3"
GPU_ATT_OID = "1.3.6.1.4.1.59386.1.1"
CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"
# F-7: NRAS nonce-binding extension (ecdh_pub_b64 + nonce_salt_hex).
NRAS_NONCE_BINDING_OID = "1.3.6.1.4.1.59386.1.3"
EXPECTED_CONTAINER_DIGEST = "{container_digest}"

# ---------------------------------------------------------------------------
# AUD-3: audit-log chain-key commitment binding
# ---------------------------------------------------------------------------
# The in-TEE runtime audit log is an HMAC hash chain whose key never leaves
# encrypted guest memory; the server publishes a SHA-256 commitment to that
# key.  Compared only against the log's own genesis entry that commitment
# proves nothing — a host-level adversary who replaces the log wholesale
# replaces the commitment along with it.  The server therefore folds the
# commitment into the preimage of the hardware-signed report_data, and this
# client recomputes that preimage and refuses the connection when it does
# not match.
_ATTEST_BINDING_LABEL = b"tee-crafter/attest-binding/v2"
_ALLOW_UNBOUND_AUDIT_CHAIN_ENV = "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN"


def _attest_binding_preimage(*fields: bytes) -> bytes:
    """Rebuild the server's attestation-binding preimage.

    Raw concatenation of variable-length fields is ambiguous —
    ``nonce=b"ab", spki=b"cd"`` and ``nonce=b"abc", spki=b"d"`` produce
    identical bytes — so evidence minted against one field split could be
    presented as satisfying a different one.  Every field therefore carries
    its own big-endian uint32 length prefix, the field *count* is prefixed
    as well (so a short field list cannot be padded out into a longer one),
    and a version label is hashed in so a v1 preimage can never be
    reinterpreted as a v2 one.  This must stay byte-for-byte identical to
    ``_attest_binding_preimage`` in the matching platform app template.
    """
    parts = [struct.pack("!I", len(_ATTEST_BINDING_LABEL)),
             _ATTEST_BINDING_LABEL,
             struct.pack("!I", len(fields))]
    for field in fields:
        parts.append(struct.pack("!I", len(field)))
        parts.append(field)
    return b"".join(parts)


def _attest_binding_digest(*fields: bytes) -> bytes:
    """SHA-256 over :func:`_attest_binding_preimage`."""
    return hashlib.sha256(_attest_binding_preimage(*fields)).digest()


def resolve_chain_key_commitment(declared) -> tuple:
    """Decide which commitment bytes belong in the binding preimage.

    *declared* is the ``chain_key_commitment`` the server published
    alongside its attestation evidence.  Returns
    ``(commitment_ascii, error)``; a non-empty *error* is fatal for the
    caller.

    An absent commitment is fatal by default.  With no hardware-signed
    commitment the audit log is unanchored, and a host-level adversary who
    replaces it wholesale — fresh HMAC key, fresh genesis entry, fresh
    chain, matching published commitment — is indistinguishable from an
    honest run.  ``TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1`` opts out with
    a loud warning, following the same convention as
    ``TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT``.
    """
    value = (declared or "").strip().lower()
    if not value:
        if os.environ.get(_ALLOW_UNBOUND_AUDIT_CHAIN_ENV) == "1":
            print("  WARNING: the server declared no runtime audit-log "
                  "chain-key commitment and "
                  f"{_ALLOW_UNBOUND_AUDIT_CHAIN_ENV}=1 is set. The audit log "
                  "this deployment produces is NOT anchored to any "
                  "hardware-signed value: a host-level adversary can discard "
                  "it and publish a self-consistent replacement, and nothing "
                  "here will notice. Development use only.", file=sys.stderr)
            return b"", ""
        return b"", (
            "the server declared no runtime audit-log chain-key commitment "
            "('chain_key_commitment' absent or empty), so its audit log has "
            "no hardware-signed anchor. Rebuild the TEE image from a commit "
            "that stages tee_crafter_audit_logger, or set "
            f"{_ALLOW_UNBOUND_AUDIT_CHAIN_ENV}=1 to accept an unanchored log "
            "(development only).")
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        return b"", (
            "'chain_key_commitment' is not a 64-character SHA-256 hex digest "
            f"(got {len(value)} character(s))")
    return value.encode("ascii"), ""



def extract_nitrotpm_claims_from_cert(cert_der: bytes):
    """Return the server's self-reported NitroTPM PCR JSON, or None.

    Deliberately *not* called "attestation".  The NITROTPM_OID extension is
    a plain JSON blob the server writes about itself: there is no TPM2
    quote, no attestation key, and no signature over it.  Anything that can
    terminate the TLS connection can put arbitrary values here, so these
    claims carry no evidentiary weight.  The evidence is the signed
    document — see :func:`verify_nitrotpm_document`.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(NITROTPM_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            return json.loads(ext.value.value.decode("utf-8"))
    return None


# CPU-side attestation on gpu-cc-aws is real, and this is where it happens.
#
# The instance produces a NitroTPM attestation document: a COSE_Sign1 signed by
# the Nitro Hypervisor, carrying hypervisor-signed PCR values.  Its certificate
# chain roots at CN=aws.nitro-enclaves, which this client pins above, so the
# document is verified here with no help from AWS and no AWS credentials.
#
# This replaced a fail-closed refusal whose stated reason -- "no AWS NitroTPM
# root certificate to chain to" -- was factually wrong.
#
# What it proves: the host booted under our Secure Boot policy (PCR7) running
# the boot chain we baked (PCR4), and the document is bound to this TLS
# session's ECDH key.  What it does not prove: memory encryption.  There is no
# CPU-TEE on AWS GPU instances, so RAM is visible to the hypervisor and the
# CPU-GPU PCIe link is not TEE-encrypted.  Measured boot is a real but strictly
# weaker property, and the banner below keeps saying so.
_AWS_CPU_ATTESTATION_OPT_OUT = "TEE_CRAFTER_ALLOW_UNVERIFIED_AWS_CPU_ATTESTATION"

# COSE algorithm ids (RFC 8152 §8.1) -> hash name.  Real documents carry -35.
_COSE_ES_ALGS = {-7: "SHA256", -35: "SHA384", -36: "SHA512"}


def extract_nitrotpm_document_from_cert(cert_der: bytes):
    """Return the raw NitroTPM attestation document, or None."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target = x509.ObjectIdentifier(NITROTPM_DOC_OID)
    for ext in cert.extensions:
        if ext.oid == target:
            return ext.value.value
    return None


def _parse_expected_pcrs(spec: str) -> dict:
    """Parse an ``"idx:hex,idx:hex"`` reference-PCR string."""
    out = {}
    for chunk in (spec or "").split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        idx, _, val = chunk.partition(":")
        try:
            out[int(idx)] = val.strip().lower().replace("0x", "")
        except ValueError:
            continue
    return out


def verify_nitrotpm_document(document: bytes, expected_binding: bytes) -> dict:
    """Verify a NitroTPM attestation document. Exits on any failure.

    Mirrors the ``nitro-aws`` client's ``verify_attestation``: walk the
    cabundle to the pinned root checking every signature and validity window,
    then check the COSE_Sign1 signature with the leaf key.  Only after that is
    anything in the payload read.

    Revocation is deliberately not checked, matching AWS's own guidance that
    CRL checking be disabled when validating Nitro attestation documents; the
    pinned root carries no CRL distribution point to follow.
    """
    import datetime
    import cbor2
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

    def die(msg):
        print(f"FATAL: NitroTPM attestation: {msg}", file=sys.stderr)
        sys.exit(1)

    try:
        cose = cbor2.loads(document)
    except Exception as e:
        die(f"document is not valid CBOR ({type(e).__name__})")
    inner = getattr(cose, "value", cose)
    if not isinstance(inner, (list, tuple)) or len(inner) != 4:
        die("document is not a COSE_Sign1 4-tuple")
    protected, _unprotected, payload_bytes, signature = inner
    try:
        payload = cbor2.loads(payload_bytes)
    except Exception:
        die("COSE payload is not valid CBOR")
    if not isinstance(payload, dict):
        die("COSE payload is not a map")

    root_pem = _AWS_NITRO_ROOT_CA_PEM.strip()
    if not root_pem:
        die("no pinned AWS Nitro root certificate compiled into this client")
    root_ca = x509.load_pem_x509_certificate(root_pem.encode("utf-8"),
                                             default_backend())
    leaf_der = payload.get("certificate")
    if not leaf_der:
        die("document carries no leaf certificate")
    cabundle = list(payload.get("cabundle") or [])

    # AWS orders cabundle [ROOT, INTERM_1, ..., INTERM_N].
    leaf = x509.load_der_x509_certificate(leaf_der, default_backend())
    chain = [leaf] + [x509.load_der_x509_certificate(c, default_backend())
                      for c in reversed(cabundle)]

    now = datetime.datetime.now(datetime.timezone.utc)
    for i, cert in enumerate(chain):
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            die(f"{'leaf' if i == 0 else f'chain[{i}]'} certificate outside "
                f"its validity window")

    for i in range(len(chain) - 1):
        subject, issuer = chain[i], chain[i + 1]
        if subject.issuer != issuer.subject:
            die(f"certificate chain broken at link {i} (issuer name mismatch)")
        pub = issuer.public_key()
        try:
            if isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(subject.signature, subject.tbs_certificate_bytes,
                           ec.ECDSA(subject.signature_hash_algorithm))
            else:
                pub.verify(subject.signature, subject.tbs_certificate_bytes,
                           padding.PKCS1v15(),
                           subject.signature_hash_algorithm)
        except Exception:
            die(f"certificate signature invalid at link {i}")

    if (chain[-1].public_bytes(serialization.Encoding.PEM)
            != root_ca.public_bytes(serialization.Encoding.PEM)):
        die("chain does not terminate at the pinned AWS Nitro root")

    try:
        alg = cbor2.loads(protected).get(1)
    except Exception:
        alg = None
    hash_name = _COSE_ES_ALGS.get(alg)
    if hash_name is None:
        die(f"unsupported COSE algorithm {alg!r}")

    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload_bytes])
    leaf_pub = leaf.public_key()
    if not isinstance(leaf_pub, ec.EllipticCurvePublicKey):
        die("leaf certificate does not carry an EC key")
    half = len(signature) // 2
    der_sig = utils.encode_dss_signature(
        int.from_bytes(signature[:half], "big"),
        int.from_bytes(signature[half:], "big"))
    try:
        leaf_pub.verify(der_sig, sig_structure,
                        ec.ECDSA(getattr(hashes, hash_name)()))
    except Exception:
        die("COSE_Sign1 signature does not verify")

    # Signature is good, so the payload can now be believed.
    pcrs = {}
    for k, v in (payload.get("nitrotpm_pcrs") or {}).items():
        if isinstance(v, (bytes, bytearray)):
            pcrs[int(k)] = bytes(v).hex()

    # Channel binding: the document must name this session's ECDH key.  Without
    # this a valid document from any other instance in the account would pass.
    user_data = payload.get("user_data")
    user_data = bytes(user_data) if isinstance(user_data, (bytes, bytearray)) else b""
    if user_data != expected_binding:
        die("document is not bound to this TLS session — user_data is "
            f"{user_data.hex()[:32] or '(absent)'}, expected "
            f"{expected_binding.hex()[:32]}. A document valid for a different "
            "session or instance does not attest this connection.")

    expected = _parse_expected_pcrs(
        os.environ.get("TEE_CRAFTER_EXPECTED_NITROTPM_PCRS",
                       EXPECTED_NITROTPM_PCRS))
    for idx, want in sorted(expected.items()):
        got = pcrs.get(idx, "")
        if got.lower() != want:
            die(f"PCR{idx} mismatch — expected {want[:32]}…, got "
                f"{(got or '(absent)')[:32]}…")

    return {
        "pcrs": pcrs,
        "module_id": payload.get("module_id", ""),
        "digest": payload.get("digest", ""),
        "timestamp": payload.get("timestamp", 0),
        "pcrs_compared": sorted(expected.keys()),
        "root": "certs/nitro-root.pem (CN=aws.nitro-enclaves)",
    }


def extract_gpu_token_from_cert(cert_der: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(GPU_ATT_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            return ext.value.value.decode("utf-8")
    return None


def extract_container_digest_from_cert(cert_der: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(CONTAINER_DIGEST_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            return ext.value.value.decode("utf-8")
    return None


def extract_nras_nonce_binding_from_cert(cert_der: bytes):
    """F-7: Return the NRAS nonce-binding payload from the RA-TLS cert, or None."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(NRAS_NONCE_BINDING_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            try:
                return json.loads(ext.value.value.decode("utf-8"))
            except Exception:
                return None
    return None


def _verify_nras_nonce_binding(binding: dict) -> dict:
    out = {"ok": False, "nonce_hex": "", "tls_spki_sha256": "",
           "chain_key_commitment": "", "error": ""}
    try:
        pub_b64 = binding.get("ecdh_pub_b64", "")
        salt_hex = binding.get("nonce_salt_hex", "")
        claimed = binding.get("nonce_hex", "")
        if not pub_b64 or not salt_hex or not claimed:
            out["error"] = "missing binding fields"
            return out
        # AUD-3: the server folds the runtime audit log's chain-key
        # commitment into the nonce preimage, so the value NVIDIA signs into
        # the EAT's eat_nonce claim commits to it.  Absent is fatal unless
        # the operator opted out; a tampered value changes the recomputed
        # nonce and fails the comparison below.
        commitment_ascii, commitment_error = resolve_chain_key_commitment(
            binding.get("chain_key_commitment", ""))
        if commitment_error:
            out["error"] = commitment_error
            return out
        pub_bytes = base64.b64decode(pub_b64)
        salt_bytes = bytes.fromhex(salt_hex)
        nonce_binding = _attest_binding_digest(pub_bytes, commitment_ascii)
        recomputed = hashlib.sha256(nonce_binding + salt_bytes).hexdigest()
        if recomputed != claimed:
            out["error"] = (
                "binding mismatch: recomputed="
                f"{recomputed[:16]}... claimed={claimed[:16]}... — the ECDH "
                "key, the audit-log chain-key commitment or the salt is not "
                "the one the NRAS nonce was built from")
            return out
        out["nonce_hex"] = recomputed
        out["chain_key_commitment"] = commitment_ascii.decode("ascii")
        # F-14: carry through the TLS SPKI hash so the caller can do
        # the belt-and-braces exact-equal comparison against the peer
        # certificate's actual SubjectPublicKeyInfo digest.
        out["tls_spki_sha256"] = binding.get("tls_spki_sha256", "")
        out["ok"] = True
        return out
    except Exception as exc:
        out["error"] = f"binding verification exception: {exc}"
        return out


def _compute_peer_spki_sha256(cert_der: bytes) -> str:
    """F-14: SHA-256 of the DER-encoded SubjectPublicKeyInfo of the peer cert.

    Uses the cryptography library so the SPKI bytes include the AlgorithmIdentifier
    exactly as DER encodes it, matching the server's computation.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    spki_der = cert.public_key().public_bytes(
        _ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


_NRAS_JWKS_URL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"

_NRAS_EXPECTED_ISSUER = "https://nras.attestation.nvidia.com"

_REQUIRED_GPU_CLAIMS = {
    "secboot": True,
    "dbgstat": "disabled",
    "measres": "success",
    "x-nvidia-gpu-attestation-report-signature-verified": True,
    "x-nvidia-gpu-attestation-report-parsed": True,
    "x-nvidia-gpu-attestation-report-nonce-match": True,
    "x-nvidia-gpu-attestation-report-cert-chain-validated": True,
    "x-nvidia-gpu-driver-rim-signature-verified": True,
    "x-nvidia-gpu-driver-rim-fetched": True,
    "x-nvidia-gpu-driver-rim-schema-validated": True,
    "x-nvidia-gpu-driver-rim-measurements-available": True,
    "x-nvidia-gpu-driver-rim-cert-validated": True,
    "x-nvidia-gpu-vbios-rim-signature-verified": True,
    "x-nvidia-gpu-vbios-rim-fetched": True,
    "x-nvidia-gpu-vbios-rim-schema-validated": True,
    "x-nvidia-gpu-vbios-rim-measurements-available": True,
    "x-nvidia-gpu-vbios-rim-cert-validated": True,
    "x-nvidia-gpu-vbios-index-no-conflict": True,
    "x-nvidia-gpu-arch-check": True,
}


def _verify_jwks_x5c_chain(jwk_data: dict) -> bool:
    """Verify the JWKS key's x5c certificate chain roots to our pinned NVIDIA CA."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    import base64, datetime

    x5c = jwk_data.get("x5c", [])
    if len(x5c) < 2:
        print("  x5c chain: FAILED (chain too short — need leaf + intermediate)", file=sys.stderr)
        return False

    if not _NVIDIA_NRAS_INTERMEDIATE_CA_PEM or not _NVIDIA_NRAS_INTERMEDIATE_CA_PEM.strip():
        print("  x5c chain: FAILED (no pinned NVIDIA CA in client)", file=sys.stderr)
        return False

    try:
        leaf_der = base64.b64decode(x5c[0])
        intermediate_der = base64.b64decode(x5c[1])
        leaf_cert = x509.load_der_x509_certificate(leaf_der, default_backend())
        intermediate_cert = x509.load_der_x509_certificate(intermediate_der, default_backend())
        pinned_cert = x509.load_pem_x509_certificate(
            _NVIDIA_NRAS_INTERMEDIATE_CA_PEM.strip().encode(), default_backend()
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        for label, c in [("leaf", leaf_cert), ("intermediate", intermediate_cert)]:
            if now < c.not_valid_before_utc or now > c.not_valid_after_utc:
                print(f"  x5c chain: FAIL ({label} cert expired)", file=sys.stderr)
                return False

        from cryptography.hazmat.primitives import serialization
        if intermediate_cert.public_bytes(serialization.Encoding.DER) != pinned_cert.public_bytes(serialization.Encoding.DER):
            print("  x5c chain: FAIL (intermediate does not match pinned NVIDIA CA)", file=sys.stderr)
            return False

        int_pub = intermediate_cert.public_key()
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_mod, ec as _ec_mod, padding as _padding
        if isinstance(int_pub, _rsa_mod.RSAPublicKey):
            int_pub.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                _padding.PKCS1v15(),
                leaf_cert.signature_hash_algorithm,
            )
        elif isinstance(int_pub, _ec_mod.EllipticCurvePublicKey):
            int_pub.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                _ec_mod.ECDSA(leaf_cert.signature_hash_algorithm),
            )
        else:
            raise TypeError(f"Unsupported public key type: {type(int_pub)}")
        print("  x5c chain: PASSED (leaf signed by pinned NVIDIA intermediate CA)", file=sys.stderr)
        return True
    except Exception as e:
        print(f"  x5c chain: FAIL ({e})", file=sys.stderr)
        return False


def _extract_overall_jwt(token_data: str) -> tuple:
    """Extract the NRAS overall JWT and per-GPU JWTs from a Detached EAT Bundle.

    The Python SDK ``get_token()`` returns a nested structure (RFC 9711):
        [
            ["JWT", "<sdk-wrapper-jwt>"],          # HS256 SDK-local wrapper
            {
                "REMOTE_GPU_CLAIMS": [             # (or LOCAL_GPU_CLAIMS)
                    ["JWT", "<nras-overall-jwt>"],  # ES384 NRAS-signed overall
                    {"GPU-0": "<jwt>", ...}         # per-GPU JWTs (strings)
                ]
            }
        ]

    The nvattest CLI wraps this slightly differently — handled below.
    """
    import json as _json
    try:
        bundle = _json.loads(token_data)
    except (ValueError, TypeError):
        return token_data, {}

    if isinstance(bundle, list) and len(bundle) >= 2:
        claims_section = bundle[1] if isinstance(bundle[1], dict) else {}

        for claim_key in ("REMOTE_GPU_CLAIMS", "LOCAL_GPU_CLAIMS"):
            nested = claims_section.get(claim_key)
            if not isinstance(nested, list) or len(nested) < 2:
                continue
            overall_jwt = (nested[0][1]
                           if isinstance(nested[0], list) and len(nested[0]) >= 2
                           else None)
            gpu_claims = {}
            detached = nested[1] if isinstance(nested[1], dict) else {}
            for k, v in detached.items():
                if isinstance(v, str):
                    gpu_claims[k] = v
                elif isinstance(v, list) and len(v) >= 2 and isinstance(v[1], str):
                    gpu_claims[k] = v[1]
            if overall_jwt:
                return overall_jwt, gpu_claims

        # Flat EAT bundle (nvattest CLI): [["JWT", "overall"], {"GPU-0": "jwt"}]
        first = bundle[0]
        overall_jwt = first[1] if isinstance(first, list) and len(first) >= 2 else None
        gpu_claims = {}
        detached = bundle[1] if isinstance(bundle[1], dict) else {}
        for k, v in detached.items():
            if isinstance(v, str):
                gpu_claims[k] = v
            elif isinstance(v, list) and len(v) >= 2 and isinstance(v[1], str):
                gpu_claims[k] = v[1]
        if overall_jwt:
            return overall_jwt, gpu_claims

    if isinstance(bundle, dict):
        eat = bundle.get("detached_eat")
        if isinstance(eat, list):
            return _extract_overall_jwt(_json.dumps(eat))

    return token_data, {}


def verify_gpu_nras_token(token: str, expected_nonce_hex: str = "") -> dict:
    """Verify the NVIDIA NRAS GPU attestation EAT JWT token via JWKS + x5c pinning.

    Performs:
    1. Fetch signing key from NRAS JWKS endpoint
    2. Verify x5c certificate chain roots to pinned NVIDIA intermediate CA
    3. ES384 signature verification of the overall JWT
    4. Expiry validation
    5. x-nvidia-overall-att-result check
    6. Per-GPU detached claim verification (secboot, dbgstat, measres, RIM sigs)
    7. F-7: if *expected_nonce_hex* is set, the overall JWT ``eat_nonce``
       claim must match exactly.
    """
    result = {"verified": False}
    if not token:
        result["error"] = "No GPU attestation token"
        return result
    try:
        import jwt
        import json as _json, urllib.request

        overall_jwt, gpu_claim_jwts = _extract_overall_jwt(token)

        header = jwt.get_unverified_header(overall_jwt)
        kid = header.get("kid")
        alg = header.get("alg", "ES384")

        raw_jwks = urllib.request.urlopen(_NRAS_JWKS_URL, timeout=10).read()
        jwks_data = _json.loads(raw_jwks)
        matched_jwk = None
        if kid:
            for k in jwks_data.get("keys", []):
                if k.get("kid") == kid:
                    matched_jwk = k
                    break
        if not matched_jwk:
            for k in jwks_data.get("keys", []):
                if k.get("kty") == "EC" and k.get("crv") == "P-384":
                    matched_jwk = k
                    break
        if not matched_jwk:
            result["error"] = f"No JWKS key found for kid={kid} or EC/P-384 fallback"
            return result

        if not _verify_jwks_x5c_chain(matched_jwk):
            result["error"] = "JWKS x5c certificate chain verification failed against pinned NVIDIA CA"
            return result

        from jwt import PyJWK as _PyJWK

        def _key_from_jwks(kid_val):
            if kid_val:
                for k in jwks_data.get("keys", []):
                    if k.get("kid") == kid_val:
                        return _PyJWK(k).key
            for k in jwks_data.get("keys", []):
                if k.get("kty") == "EC" and k.get("crv") == "P-384":
                    return _PyJWK(k).key
            return None

        signing_key = _key_from_jwks(kid)
        if not signing_key:
            result["error"] = f"Could not construct signing key for kid={kid}"
            return result
        claims = jwt.decode(
            overall_jwt, signing_key, algorithms=["ES384"],
            options={"verify_exp": True, "verify_iss": True},
            issuer=_NRAS_EXPECTED_ISSUER,
        )
        overall = claims.get("x-nvidia-overall-att-result")
        if overall is not True:
            result["error"] = f"x-nvidia-overall-att-result is {overall}, expected true"
            return result
        print(f"    Overall att-result: PASSED (issuer={claims.get('iss')})", file=sys.stderr)

        if expected_nonce_hex:
            overall_nonce = claims.get("eat_nonce") or claims.get("nonce")
            if not isinstance(overall_nonce, str):
                result["error"] = "NRAS overall JWT missing eat_nonce claim (relay?)"
                return result
            if overall_nonce.strip().lower() != expected_nonce_hex.strip().lower():
                result["error"] = (
                    f"NRAS eat_nonce mismatch: token={overall_nonce[:16]}..., "
                    f"expected={expected_nonce_hex[:16]}... (evidence-relay attack)"
                )
                return result
            print("    NRAS eat_nonce binding: PASSED", file=sys.stderr)

        submods = claims.get("submods", {})
        for gpu_id in submods:
            print(f"    {gpu_id}: digest present in overall token", file=sys.stderr)

        if not gpu_claim_jwts:
            print("    WARNING: No detached per-GPU claim JWTs found in EAT bundle", file=sys.stderr)

        for gpu_id, gpu_jwt in gpu_claim_jwts.items():
            try:
                gpu_header = jwt.get_unverified_header(gpu_jwt)
                gpu_key = _key_from_jwks(gpu_header.get("kid"))
                if not gpu_key:
                    result["error"] = f"No JWKS key for GPU claim {gpu_id} kid={gpu_header.get('kid')}"
                    return result
                gpu_claims = jwt.decode(
                    gpu_jwt, gpu_key, algorithms=["ES384"],
                    options={"verify_exp": True},
                )
                for claim_name, expected in _REQUIRED_GPU_CLAIMS.items():
                    actual = gpu_claims.get(claim_name)
                    if actual != expected:
                        result["error"] = f"{gpu_id}: {claim_name}={actual}, expected {expected}"
                        return result
                print(f"    {gpu_id}: secboot={gpu_claims.get('secboot')}, "
                      f"dbgstat={gpu_claims.get('dbgstat')}, "
                      f"measres={gpu_claims.get('measres')}, "
                      f"driver={gpu_claims.get('x-nvidia-gpu-driver-version')}, "
                      f"hwmodel={gpu_claims.get('hwmodel')}", file=sys.stderr)
            except Exception as gpu_err:
                result["error"] = f"Detached claim verification failed for {gpu_id}: {gpu_err}"
                return result
        result["verified"] = True
        result["claims"] = claims
    except ImportError:
        print("  GPU NRAS token verification: FAILED (PyJWT not installed)", file=sys.stderr)
        result["error"] = "PyJWT not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def _spki_sha256_from_der(cert_der: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def verify_ratls_connection(host: str, port: int, ratls_nonce: bytes | None = None) -> tuple:
    print("\n" + "=" * 70, file=sys.stderr)
    print("  WARNING: WEAKER SECURITY MODEL (gpu-cc-aws)", file=sys.stderr)
    print("  AWS does NOT have a hardware CPU-TEE for GPU instances.", file=sys.stderr)
    print("  The CPU-GPU PCIe link is NOT encrypted by a TEE.", file=sys.stderr)
    print("  CPU measured boot IS attested (NitroTPM, hypervisor-signed).", file=sys.stderr)
    print("  But CPU MEMORY is NOT encrypted — measured boot is weaker.", file=sys.stderr)
    print("  GPU memory is protected by NVIDIA CC mode.", file=sys.stderr)
    print("=" * 70 + "\n", file=sys.stderr)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(120)
    conn = ctx.wrap_socket(raw_sock, server_hostname=host)
    conn.connect((host, port))
    cert_der = conn.getpeercert(binary_form=True)
    if cert_der is None:
        conn.close()
        print("FATAL: No certificate.", file=sys.stderr)
        sys.exit(1)

    # CPU side: verify the NitroTPM attestation document against the pinned
    # AWS Nitro root.  The channel binding is sha256 over the server's ECDH
    # public key, which the server also publishes in the NITROTPM_OID blob —
    # read from there only to *locate* the binding, never trusted: the
    # comparison below is against the value inside the signed document.
    nitrotpm_claims = extract_nitrotpm_claims_from_cert(cert_der)
    document = extract_nitrotpm_document_from_cert(cert_der)
    nitrotpm_verified = None
    if document:
        # Only look for the channel-binding input once we know there is a
        # document to bind.  Checking it first reported "no ecdh_pub_b64" for a
        # certificate whose actual problem was carrying no attestation at all,
        # which points the operator at the wrong thing.
        ecdh_pub_b64 = (extract_nras_nonce_binding_from_cert(cert_der) or {}).get(
            "ecdh_pub_b64", "")
        if not ecdh_pub_b64:
            conn.close()
            print("FATAL: the certificate carries a NitroTPM attestation "
                  "document but no ecdh_pub_b64, so the document cannot be "
                  "bound to this channel and a replay from another session "
                  "would be indistinguishable.", file=sys.stderr)
            sys.exit(1)
        expected_binding = hashlib.sha256(base64.b64decode(ecdh_pub_b64)).digest()
        nitrotpm_verified = verify_nitrotpm_document(document, expected_binding)
        print("  NitroTPM attestation document: VERIFIED", file=sys.stderr)
        print(f"    trust root : {nitrotpm_verified['root']}", file=sys.stderr)
        print(f"    module_id  : {nitrotpm_verified['module_id']}", file=sys.stderr)
        print(f"    bank       : {nitrotpm_verified['digest']}", file=sys.stderr)
        print("    channel binding (user_data == sha256(ecdh_pub)): PASSED",
              file=sys.stderr)
        compared = nitrotpm_verified["pcrs_compared"]
        if compared:
            print(f"    PCRs compared against bake-time reference: "
                  f"{', '.join('PCR%d' % i for i in compared)}", file=sys.stderr)
        else:
            print("    PCRs: NOT compared — no bake-time reference was "
                  "recorded for this image, so the document proves the boot "
                  "chain is hypervisor-signed but not that it is *ours*.",
                  file=sys.stderr)
        for idx in sorted(nitrotpm_verified["pcrs"]):
            if idx in (0, 1, 4, 7):
                print(f"    PCR[{idx}]: {nitrotpm_verified['pcrs'][idx][:32]}...",
                      file=sys.stderr)
    elif os.environ.get(_AWS_CPU_ATTESTATION_OPT_OUT, "0") == "1":
        print("  ***********************************************************", file=sys.stderr)
        print("  CPU host: UNATTESTED.", file=sys.stderr)
        print("  The certificate carries no NitroTPM attestation document and", file=sys.stderr)
        print(f"  {_AWS_CPU_ATTESTATION_OPT_OUT}=1 is set, so this", file=sys.stderr)
        print("  connection proceeds on GPU (NVIDIA NRAS) attestation alone.", file=sys.stderr)
        print("  ***********************************************************", file=sys.stderr)
    else:
        conn.close()
        print("FATAL: the certificate carries no NitroTPM attestation document "
              f"(OID {NITROTPM_DOC_OID}), so this connection has no CPU-side "
              "evidence at all. The image was almost certainly baked before "
              "nitro-tpm-attest was installed by the bake — re-bake with a "
              f"current tree. Set {_AWS_CPU_ATTESTATION_OPT_OUT}=1 to proceed "
              "on GPU attestation alone with an explicitly unattested CPU "
              "host.", file=sys.stderr)
        sys.exit(1)

    # The unsigned self-reported blob, kept for operator context only.  Never
    # compared against anything: the signed document above is the evidence.
    pcrs = (nitrotpm_claims or {}).get("pcrs", {})
    if pcrs:
        print(f"  (self-reported PCR blob also present: {len(pcrs)} values, "
              "not used as evidence)", file=sys.stderr)

    # GPU attestation (NVIDIA NRAS) — the only verifiable evidence on AWS
    gpu_token = extract_gpu_token_from_cert(cert_der)
    if not gpu_token:
        conn.close()
        print("FATAL: GPU NRAS attestation NOT PRESENT in certificate (required for GPU CC).", file=sys.stderr)
        sys.exit(1)

    nonce_binding = extract_nras_nonce_binding_from_cert(cert_der)
    if nonce_binding is None:
        conn.close()
        print("FATAL: NRAS nonce-binding extension (OID 1.3.6.1.4.1.59386.1.3) missing.", file=sys.stderr)
        sys.exit(1)
    nb_result = _verify_nras_nonce_binding(nonce_binding)
    if not nb_result["ok"]:
        conn.close()
        print(f"FATAL: NRAS nonce-binding check failed: {nb_result['error']}", file=sys.stderr)
        sys.exit(1)
    expected_nonce_hex = nb_result["nonce_hex"]
    print("  NRAS nonce binding (local recompute): PASSED", file=sys.stderr)
    # AUD-3: the commitment is only trustworthy once verify_gpu_nras_token()
    # below confirms NVIDIA signed this exact nonce, so hold it and print it
    # after that check passes.
    attested_chain_commitment = nb_result.get("chain_key_commitment", "")

    # F-14: belt-and-braces TLS SPKI exact-equal check.  The nonce-binding
    # extension declares the SHA-256 of the server's TLS SubjectPublicKeyInfo;
    # we compute it independently from the cert we actually received on the
    # wire and require an exact match.  Any discrepancy indicates the RA-TLS
    # cert and the attested TLS key have drifted apart.
    claimed_spki_hash = nb_result.get("tls_spki_sha256", "")
    actual_spki_hash = _compute_peer_spki_sha256(cert_der)
    if claimed_spki_hash:
        if claimed_spki_hash != actual_spki_hash:
            conn.close()
            print(
                "FATAL: TLS SPKI mismatch (F-14). "
                f"claimed={claimed_spki_hash[:16]}... actual={actual_spki_hash[:16]}...",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            f"  TLS SPKI belt-and-braces (F-14): PASSED sha256={actual_spki_hash[:16]}...",
            file=sys.stderr,
        )
    else:
        # Older server templates predate F-14: refuse the connection
        # so roll-forward is observable rather than silently weaker.
        conn.close()
        print(
            "FATAL: NRAS nonce-binding extension missing 'tls_spki_sha256' (F-14). "
            "Server template is out of date.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Verifying GPU NRAS attestation token...", file=sys.stderr)
    gpu_result = verify_gpu_nras_token(gpu_token, expected_nonce_hex=expected_nonce_hex)
    if not gpu_result.get("verified"):
        conn.close()
        err = gpu_result.get("error", "verification failed")
        print(f"FATAL: GPU NRAS attestation failed: {err}", file=sys.stderr)
        sys.exit(1)
    print("  GPU NRAS attestation: PASSED", file=sys.stderr)
    # AUD-3: NVIDIA's signature over eat_nonce now covers this commitment,
    # so the audit log this VM exports can be tied back to signed evidence.
    # Note the anchor is the NVIDIA-signed GPU attestation, not the CPU
    # TEE's report_data: CPU-side attestation is refused on this platform, so
    # no CPU anchor exists.  The guarantee is 'NVIDIA attested this GPU
    # evidence', not 'the CPU TEE hardware signed this value'.  Stated in the
    # output for that reason.
    if attested_chain_commitment:
        print("  Audit-log chain-key commitment (NVIDIA-signed via eat_nonce): "
              f"{attested_chain_commitment}", file=sys.stderr)
    else:
        print("  Audit-log chain-key commitment: NONE (accepted via "
              "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1)", file=sys.stderr)

    server_cd = extract_container_digest_from_cert(cert_der)
    if server_cd:
        print(f"  Container digest: {server_cd}", file=sys.stderr)
        if EXPECTED_CONTAINER_DIGEST and EXPECTED_CONTAINER_DIGEST != "":
            if server_cd != EXPECTED_CONTAINER_DIGEST:
                conn.close()
                print(f"FATAL: Container digest mismatch! got={server_cd} expected={EXPECTED_CONTAINER_DIGEST}", file=sys.stderr)
                sys.exit(1)
            print("  Container binding: PASSED", file=sys.stderr)

    print("  GPU CC attestation: COMPLETE (CPU host UNATTESTED)", file=sys.stderr)
    print("  Security model: GPU-ONLY (no CPU TEE, no encrypted PCIe)", file=sys.stderr)

    att_info = {
        # Verified: hypervisor-signed PCRs from the attestation document,
        # chain-validated to the pinned AWS Nitro root and bound to this
        # session's ECDH key.
        "nitrotpm_pcrs": (nitrotpm_verified or {}).get("pcrs", {}),
        "nitrotpm_module_id": (nitrotpm_verified or {}).get("module_id", ""),
        "nitrotpm_pcrs_compared": (nitrotpm_verified or {}).get("pcrs_compared", []),
        # The unsigned blob the host wrote about itself, kept separate so no
        # downstream consumer can mistake it for the attested values above.
        "nitrotpm_pcrs_self_reported": pcrs,
        # This one *is* evidence: the ECDH public key whose hash NVIDIA
        # signed into the NRAS eat_nonce, checked above.
        "nras_bound_ecdh_pub_b64": nonce_binding.get("ecdh_pub_b64", ""),
        "container_digest": server_cd or "",
        "security_model": ("gpu-attested-cpu-measured-boot"
                           if nitrotpm_verified else "gpu-only-cpu-unattested"),
    }

    # AUD-7 / ATT-006 / ATT-007 / ATT-009 / ATT-010: structured
    # ATTESTATION_REPORT line.  Both halves are evidence now: the NRAS token
    # for the GPU, and the hypervisor-signed NitroTPM PCRs for the host's
    # measured boot.  PCR fields are empty only when the peer shipped no
    # document and the operator explicitly opted into an unattested CPU.
    try:
        spki = _spki_sha256_from_der(cert_der)
    except Exception:
        spki = ""
    try:
        attestation_report = {
            "platform": "gpu-cc-aws",
            "issuer": "nvidia-nras",
            "report_kind": "nras_eat",
            "quote_signature_alg": "ES384",
            "pcr0": (nitrotpm_verified or {}).get("pcrs", {}).get(0, ""),
            "pcr4": (nitrotpm_verified or {}).get("pcrs", {}).get(4, ""),
            "pcr7": (nitrotpm_verified or {}).get("pcrs", {}).get(7, ""),
            "cpu_attestation": ("nitrotpm-measured-boot" if nitrotpm_verified
                                else "unverifiable"),
            "nras_token_valid": True,
            "nras_token_kid": locals().get("nras_kid", "") or "",
            "nras_eat_digest": locals().get("nras_eat_digest", "") or "",
            # The NRAS eat_nonce is the one binding here that NVIDIA signed.
            "nonce_binding": expected_nonce_hex,
            # AUD-3: the audit-log chain-key commitment that same signed
            # eat_nonce commits to.  `_verify_nras_nonce_binding` already
            # recomputed the nonce over it and refused a mismatch, so this is
            # an attested value rather than a claim.  It was being computed and
            # then dropped, which left the provenance ledger with nothing for
            # `verify-siem-chain --expect-chain-commitment` to pin against.
            "chain_key_commitment": nb_result.get("chain_key_commitment", ""),
            "nonce": (ratls_nonce or b"").hex(),
            "spki_sha256": spki,
            "container_digest": server_cd or "",
        }
        print(f"ATTESTATION_REPORT {json.dumps(attestation_report, separators=(',', ':'))}")
    except Exception:
        pass

    return conn, att_info


def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def send_request(conn, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    conn.sendall(struct.pack("!I", len(data)))
    conn.sendall(data)
    hdr = _recv_exactly(conn, 4)
    resp_len = struct.unpack("!I", hdr)[0]
    if resp_len > 64 * 1024 * 1024:
        raise ValueError("Response too large")
    return json.loads(_recv_exactly(conn, resp_len).decode("utf-8"))


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 client_gpu_cc_aws.py <host_ip> [port]", file=sys.stderr)
        sys.exit(1)
    host_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5005
    ratls_nonce = os.urandom(32)
    print(f"Connecting to GPU CC AWS instance at {host_ip}:{port}...", file=sys.stderr)
    print("  Platform: AWS P5/P5en/P6 (NVIDIA CC; CPU host has no verifiable TEE)",
          file=sys.stderr)
    try:
        conn, att_info = verify_ratls_connection(host_ip, port, ratls_nonce=ratls_nonce)
        print("GPU Attestation Complete (GPU-ONLY; CPU host UNATTESTED)", file=sys.stderr)
    except Exception as e:
        print(f"Failed: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)

    print("Requesting instance public key...", file=sys.stderr)
    try:
        att_resp = send_request(conn, {"action": "get_attestation", "nonce": base64.b64encode(os.urandom(32)).decode()})
        enclave_pub_b64 = att_resp.get("enclave_public_key")
        if not enclave_pub_b64:
            print("FATAL: No public key.", file=sys.stderr)
            sys.exit(1)
        enclave_pub_bytes = base64.b64decode(enclave_pub_b64)
        gpu_info = att_resp.get("gpu_info", {})
        if gpu_info:
            print(f"  GPU: {gpu_info.get('gpu_name', 'N/A')} x{gpu_info.get('gpu_count', '?')}", file=sys.stderr)
        if att_resp.get("warning"):
            print(f"  SERVER WARNING: {att_resp['warning']}", file=sys.stderr)
    except Exception as e:
        print(f"Failed: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Bind the ECDH key we are about to use to the NRAS-signed evidence, not
    # to the server's own NitroTPM JSON (which it could set to anything).
    nras_bound_pub_b64 = att_info.get("nras_bound_ecdh_pub_b64", "")
    if not nras_bound_pub_b64:
        print("FATAL: no NRAS-bound ECDH public key — cannot bind the session key "
              "to attested evidence.", file=sys.stderr)
        sys.exit(1)
    if base64.b64decode(nras_bound_pub_b64) != enclave_pub_bytes:
        print("FATAL: instance public key does not match the ECDH key bound into "
              "the NVIDIA-signed NRAS nonce!", file=sys.stderr)
        sys.exit(1)
    print("  Public key binding: PASSED (matches NRAS-signed eat_nonce binding)",
          file=sys.stderr)

    cert_cd = att_info.get("container_digest", "")
    if cert_cd and EXPECTED_CONTAINER_DIGEST:
        if cert_cd != EXPECTED_CONTAINER_DIGEST:
            print(f"FATAL: container digest mismatch! got={cert_cd} expected={EXPECTED_CONTAINER_DIGEST}", file=sys.stderr)
            sys.exit(1)
        print("  Container binding: PASSED", file=sys.stderr)

    # Attestation + ECDH-key/container-digest binding verified above — that
    # is the deploy-time client's entire job: prove the TEE. Application data
    # flows separately: your own client sends real requests through this same
    # attested channel to your container's API; the framework neither defines
    # nor inspects it.
    print("Attestation verified.", file=sys.stderr)
    print(json.dumps({"status": "attestation_verified"}))
    sys.exit(0)


if __name__ == "__main__":
    main()
