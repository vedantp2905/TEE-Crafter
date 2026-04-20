import sys
import json
import os
import base64
import cbor2
import datetime
import hashlib
import struct
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils

ROOT_CA_PEM = """{root_ca}"""

EXPECTED_PCRS = {pcr_bindings}

# Nitro was the one platform with no unpinned-measurement gate, and it is the
# default.  `render_client_template` substitutes an empty dict literal when no
# PCRs are passed (core/builder/builder.py sets `pcr_bindings_str` to the two
# characters "{" "}"), so an unpinned build produced an EMPTY dict — and the
# verification loop below is
# `for pcr_key, expected_val in EXPECTED_PCRS.items()`, which iterates zero
# times, checks nothing, and falls through to print success.  Same
# empty-allowlist fail-open that `KeyReleasePolicy.allowed_measurement_sha256`
# was hardened against.  Fails closed now, with the house-style opt-out the
# other nine clients use.
_ALLOW_UNPINNED_ENV = "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT"


def _allow_unpinned_measurement() -> bool:
    return os.environ.get(_ALLOW_UNPINNED_ENV, "0") == "1"

# Maximum accepted skew between the attestation document's own ``timestamp``
# field (milliseconds since the Unix epoch, set by the NSM) and this client's
# clock.  The nonce already provides freshness; this is a second, independent
# bound so a document replayed from a captured session is rejected even if an
# attacker could somehow induce a nonce collision.  Five minutes is generous
# enough for ordinary NTP drift between the enclave and the verifier.
MAX_DOC_AGE_SECONDS = 300

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



def check_ca_certificate(cert, index, remaining_intermediates):
    """Validate the CA-ness of an issuing certificate (RFC 5280 §4.2.1.9/§4.2.1.3).

    Nitro attestation chains are pinned to a single AWS root, so these
    checks are defence-in-depth rather than the primary control — but a
    verifier that walks a chain without them will happily accept an
    end-entity certificate acting as a CA.

    ``remaining_intermediates`` is the number of CA certificates that
    appear *below* this one in the chain, i.e. what ``pathLenConstraint``
    bounds.

    Raises ``ValueError`` on any violation.
    """
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise ValueError(
            f"issuer certificate [{index}] has no basicConstraints extension, "
            "so it is not a CA"
        )
    if not bc.ca:
        raise ValueError(f"issuer certificate [{index}] has basicConstraints CA:FALSE")
    if bc.path_length is not None and remaining_intermediates > bc.path_length:
        raise ValueError(
            f"issuer certificate [{index}] has pathLenConstraint="
            f"{bc.path_length} but {remaining_intermediates} intermediate(s) "
            "follow it in the chain"
        )
    # keyUsage is optional in RFC 5280.  When present it is authoritative,
    # so a CA without keyCertSign must be rejected; when absent there is
    # nothing to check and rejecting would break a conforming chain.
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not ku.key_cert_sign:
        raise ValueError(
            f"issuer certificate [{index}] has a keyUsage extension without "
            "keyCertSign"
        )


def check_leaf_certificate(cert):
    """Reject a leaf that claims to be a CA.

    The NSM signing certificate is an end entity.  If it carried CA:TRUE it
    could mint further certificates under the pinned root, which is exactly
    the confusion basicConstraints exists to prevent.
    """
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return  # absent basicConstraints means "not a CA" (RFC 5280 §4.2.1.9)
    if bc.ca:
        raise ValueError("leaf (NSM signing) certificate asserts basicConstraints CA:TRUE")


def verify_cert_signature(issuer_cert, subject_cert):
    """Dynamically verifies a certificate signature supporting both RSA and ECDSA."""
    public_key = issuer_cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                subject_cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                ec.ECDSA(subject_cert.signature_hash_algorithm),
            )
        else:
            raise ValueError(f"Unsupported public key type: {type(public_key)}")
    except Exception as e:
        raise e

def expected_doc_nonce(client_nonce, chain_key_commitment=b""):
    """AUD-3: the value the enclave must have put in the document's nonce.

    nsm-cli cannot set ``user_data`` (it is hardcoded to ``None`` in
    ``templates/common/nsm_main.rs``) and ``public_key`` has to stay the raw
    ECDH key, so the enclave folds the audit-log chain-key commitment into
    the nonce field instead.  The COSE_Sign1 signature from the Nitro
    Hypervisor therefore covers the commitment, which is what makes an
    exported audit log checkable against hardware-signed evidence.

    Kept separate from :func:`verify_attestation` so it can be exercised
    without a full attestation document.
    """
    return _attest_binding_digest(client_nonce, chain_key_commitment)


def verify_attestation(attestation_doc_b64, client_nonce, chain_key_commitment=b""):
    print("Decoding attestation document...", file=sys.stderr)
    doc_bytes = base64.b64decode(attestation_doc_b64)
    cose_sign1 = cbor2.loads(doc_bytes)
    payload_bytes = cose_sign1[2]
    doc = cbor2.loads(payload_bytes)

    print("Verifying nonce (freshness + AUD-3 chain-key commitment)...", file=sys.stderr)
    expected_nonce = expected_doc_nonce(client_nonce, chain_key_commitment)
    received_nonce = doc.get('nonce')
    if received_nonce != expected_nonce:
        print("FATAL: Attestation-document nonce does not equal the v2 binding "
              "digest over (client_nonce, chain_key_commitment). The document "
              "is either a replay, or the enclave did not commit to the "
              "audit-log chain key it declared.", file=sys.stderr)
        print(f"  Expected {expected_nonce.hex()}, got "
              f"{received_nonce.hex() if isinstance(received_nonce, bytes) else received_nonce!r}",
              file=sys.stderr)
        sys.exit(1)

    # The document's own timestamp is inside the COSE-signed payload, so the
    # host cannot forge it.  Bounding it rejects a stale document even though
    # the nonce check above is the primary freshness control.  AWS documents
    # `timestamp` as milliseconds since the Unix epoch.
    print("Verifying document timestamp...", file=sys.stderr)
    doc_timestamp_ms = doc.get('timestamp')
    if not isinstance(doc_timestamp_ms, int):
        print(f"FATAL: Attestation document has no integer 'timestamp' field "
              f"(got {type(doc_timestamp_ms).__name__}).", file=sys.stderr)
        sys.exit(1)
    skew_seconds = abs(
        datetime.datetime.now(datetime.timezone.utc).timestamp()
        - doc_timestamp_ms / 1000.0
    )
    if skew_seconds > MAX_DOC_AGE_SECONDS:
        print(f"FATAL: Attestation document timestamp is {skew_seconds:.0f}s from "
              f"this client's clock, beyond the {MAX_DOC_AGE_SECONDS}s bound. "
              "Either the document is a replay or the two clocks disagree.",
              file=sys.stderr)
        sys.exit(1)
    print(f"  Timestamp within {MAX_DOC_AGE_SECONDS}s bound "
          f"(skew {skew_seconds:.1f}s).", file=sys.stderr)

    # The document also carries a `digest` field naming the PCR hash
    # algorithm ("SHA384").  It is not checked: the PCR values below are
    # compared byte-for-byte against a build-time pin, so a document that
    # claimed a different digest algorithm would fail that comparison
    # anyway.  Recording it here so the omission is deliberate, not
    # forgotten.

    print("Verifying PCRs...", file=sys.stderr)
    doc_pcrs = doc.get('pcrs', {})

    if not EXPECTED_PCRS:
        if not _allow_unpinned_measurement():
            print("FATAL: this client was built with no pinned PCRs, so the "
                  "loop below would verify nothing and report success. A Nitro "
                  "attestation document proves an enclave is genuine; only the "
                  "PCRs say WHICH enclave image booted. Rebuild after "
                  "`build-enclave` so the measurements are baked in, or set "
                  f"{_ALLOW_UNPINNED_ENV}=1 to accept an unmeasured enclave.",
                  file=sys.stderr)
            sys.exit(1)
        print("=" * 78, file=sys.stderr)
        print(f"WARNING: {_ALLOW_UNPINNED_ENV}=1 — no PCRs are pinned, so this "
              "connection is NOT bound to any particular enclave image. Any "
              "genuine Nitro enclave in the account will be accepted.",
              file=sys.stderr)
        print("=" * 78, file=sys.stderr)

    for pcr_key, expected_val in EXPECTED_PCRS.items():
        idx = int(pcr_key.replace("PCR", ""))
        received_val = doc_pcrs.get(idx, b'').hex()
        if received_val != expected_val:
            print(f"FATAL: PCR{idx} mismatch! Expected {expected_val}, got {received_val}", file=sys.stderr)
            sys.exit(1)

    print("Verifying Certificate Chain...", file=sys.stderr)
    cabundle = doc.get('cabundle', [])
    leaf_bytes = doc.get('certificate')

    if not leaf_bytes and cabundle:
        leaf_bytes = cabundle.pop(0)

    if not leaf_bytes:
        print("FATAL: Attestation document does not contain a leaf certificate.", file=sys.stderr)
        sys.exit(1)

    root_ca_pem = ROOT_CA_PEM.strip()
    if not root_ca_pem:
        print("FATAL: No AWS Nitro root CA certificate configured. Cannot verify attestation.", file=sys.stderr)
        sys.exit(1)

    try:
        root_ca = x509.load_pem_x509_certificate(root_ca_pem.encode('utf-8'), default_backend())

        leaf_cert = x509.load_der_x509_certificate(leaf_bytes, default_backend())

        # AWS cabundle order: [ROOT, INTERM_1, ..., INTERM_N]
        # Build verification chain: [LEAF, INTERM_N, ..., INTERM_1, ROOT]
        certs = [leaf_cert]
        for c_bytes in reversed(cabundle):
            certs.append(x509.load_der_x509_certificate(c_bytes, default_backend()))

        now = datetime.datetime.now(datetime.timezone.utc)
        for i, cert in enumerate(certs):
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                label = "Leaf" if i == 0 else f"Intermediate-{i}"
                print(f"FATAL: {label} certificate not valid at current time. "
                      f"Valid: {cert.not_valid_before_utc} – {cert.not_valid_after_utc}", file=sys.stderr)
                sys.exit(1)

        if now < root_ca.not_valid_before_utc or now > root_ca.not_valid_after_utc:
            print(f"FATAL: Root CA certificate not valid at current time. "
                  f"Valid: {root_ca.not_valid_before_utc} – {root_ca.not_valid_after_utc}", file=sys.stderr)
            sys.exit(1)

        # certs == [LEAF, INTERM_N, ..., INTERM_1, (ROOT)] — every entry
        # after index 0 must be a genuine CA.  `remaining` counts the CA
        # certificates below each issuer, which is what pathLenConstraint
        # bounds (RFC 5280 §4.2.1.9).
        check_leaf_certificate(certs[0])
        for i in range(1, len(certs)):
            check_ca_certificate(certs[i], i, remaining_intermediates=i - 1)

        for i in range(len(certs) - 1):
            subject = certs[i]
            issuer = certs[i + 1]
            if subject.issuer != issuer.subject:
                print(f"FATAL: Certificate {i} issuer {subject.issuer} "
                      f"does not match certificate {i+1} subject {issuer.subject}!", file=sys.stderr)
                sys.exit(1)
            verify_cert_signature(issuer, subject)

        last_cert = certs[-1]
        last_pem = last_cert.public_bytes(serialization.Encoding.PEM)
        root_pem = root_ca.public_bytes(serialization.Encoding.PEM)
        if last_pem == root_pem:
            print("  Root certificate in cabundle matches pinned root CA.", file=sys.stderr)
        else:
            if last_cert.issuer != root_ca.subject:
                print(f"FATAL: Top-of-chain issuer {last_cert.issuer} "
                      f"does not match Root CA subject {root_ca.subject}", file=sys.stderr)
                sys.exit(1)
            check_ca_certificate(root_ca, len(certs),
                                 remaining_intermediates=len(certs) - 1)
            verify_cert_signature(root_ca, last_cert)

        print("  Certificate chain verified "
              "(name chaining, signatures, validity windows, basicConstraints "
              "CA/pathLen, keyUsage keyCertSign).", file=sys.stderr)

        # NOT CHECKED, deliberately:
        #   * Revocation.  AWS's own validation guidance for Nitro attestation
        #     documents states "CRL must be disabled when doing the validation"
        #     and its reference implementation sets
        #     `setRevocationEnabled(false)` (AWS Nitro Enclaves User Guide,
        #     "Verifying the root of trust" -> "Certificate chain validity").
        #     Consistent with that, the pinned root at `certs/nitro-root.pem`
        #     carries only basicConstraints, subjectKeyIdentifier and keyUsage
        #     — no crlDistributionPoints and no authorityInfoAccess to follow.
        #     There is therefore no revocation source to consult; the residual
        #     risk is carried by the PCR pin and the short leaf lifetime.
        #   * Name constraints / policy constraints / EKU: absent from the AWS
        #     chain, so there is nothing to enforce.

        # Verify the COSE_Sign1 signature over the attestation payload
        print("Verifying COSE_Sign1 signature...", file=sys.stderr)
        protected_header = cose_sign1[0]
        signature = cose_sign1[3]
        sig_structure = cbor2.dumps([
            "Signature1",
            protected_header,
            b"",
            payload_bytes,
        ])

        leaf_pub_key = leaf_cert.public_key()
        if not isinstance(leaf_pub_key, ec.EllipticCurvePublicKey):
            raise ValueError(f"Leaf certificate has unexpected key type: {type(leaf_pub_key)}")

        # COSE signatures use IEEE P1363 format (r || s); cryptography expects DER
        coord_len = len(signature) // 2
        r = int.from_bytes(signature[:coord_len], 'big')
        s = int.from_bytes(signature[coord_len:], 'big')
        der_sig = utils.encode_dss_signature(r, s)
        leaf_pub_key.verify(der_sig, sig_structure, ec.ECDSA(hashes.SHA384()))

    except SystemExit:
        raise
    except Exception as e:
        print(f"FATAL: Attestation verification failed: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)

    print("Attestation Verification Passed!", file=sys.stderr)

    # AUD-7: emit a structured single-line ATTESTATION_REPORT for the deploy
    # orchestrator to record into the build provenance chain.  The deploy
    # phase's audit step parses this exact prefix (see
    # cli/deployment/common/attestation_report.py).  Sent to stdout because
    # stdout is what client_step.py captures and forwards to audit.record().
    try:
        attestation_report = {
            "platform": "nitro",
            "issuer": "aws-nitro",
            "report_kind": "cose_sign1",
            "cose_alg": "ES384",
            "nonce": client_nonce.hex(),
            "pcr0": doc_pcrs.get(0, b"").hex(),
            "pcr4": doc_pcrs.get(4, b"").hex(),
            "pcr7": doc_pcrs.get(7, b"").hex(),
            # Bind the certificate chain we just verified — verifiers can
            # later re-check that the same SPKI was used for ECIES.
            "spki_sha256": hashlib.sha256(
                leaf_cert.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest(),
            # AUD-3: the audit-log chain-key commitment the COSE_Sign1
            # signature covers.  Empty means the deployment was accepted
            # via TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1.
            "chain_key_commitment": chain_key_commitment.decode("ascii"),
        }
        print(f"ATTESTATION_REPORT {json.dumps(attestation_report, separators=(',', ':'))}")
    except Exception:
        # Audit emission is best-effort — never break the data path on a
        # serialization edge case.
        pass

    return doc


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 client.py <host_ip> [kms_key_arn]", file=sys.stderr)
        sys.exit(1)

    host_ip = sys.argv[1]
    proxy_url = f"https://{host_ip}/enclave"

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Phase 1: Attestation — verify the enclave and get its ECDH public key
    client_nonce = os.urandom(32)
    nonce_b64 = base64.b64encode(client_nonce).decode('utf-8')

    print(f"Connecting to enclave via proxy at {proxy_url} for attestation...", file=sys.stderr)
    try:
        req_payload = {"action": "get_attestation", "nonce": nonce_b64}
        resp = requests.post(proxy_url, json=req_payload, timeout=30, verify=False)
        resp.raise_for_status()

        resp_data = resp.json()
        if "error" in resp_data:
            print(f"Enclave returned error: {resp_data['error']}", file=sys.stderr)
            sys.exit(1)

        # AUD-3: fail closed when the enclave declares no chain-key
        # commitment, because then the audit log it produces has no
        # hardware-signed anchor.
        commitment_ascii, commitment_error = resolve_chain_key_commitment(
            resp_data.get("chain_key_commitment", ""))
        if commitment_error:
            print(f"FATAL: {commitment_error}", file=sys.stderr)
            sys.exit(1)

        verified_doc = verify_attestation(
            resp_data["attestation_doc_b64"], client_nonce, commitment_ascii)
        if commitment_ascii:
            print("  Audit-log chain-key commitment (Nitro-signed): "
                  f"{commitment_ascii.decode('ascii')}", file=sys.stderr)
        else:
            print("  Audit-log chain-key commitment: NONE (accepted via "
                  "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1)", file=sys.stderr)
    except SystemExit:
        raise
    except Exception as e:
        print(f"Failed to communicate with proxy for attestation: {e}", file=sys.stderr)
        sys.exit(1)

    # Extract the ECDH public key from the VERIFIED attestation document.
    # The key is authenticated by the COSE_Sign1 signature chain back to
    # the AWS Nitro root CA — the host proxy cannot forge or substitute it.
    enclave_pub_key = verified_doc.get('public_key')
    if not enclave_pub_key:
        print("FATAL: Attestation document does not contain enclave ECDH public key.", file=sys.stderr)
        sys.exit(1)

    print(f"  Enclave ECDH key extracted from verified attestation doc "
          f"(len={len(enclave_pub_key)} bytes)", file=sys.stderr)

    # Attestation + ECDH-key binding verified above — that is the deploy-time
    # client's entire job: prove the TEE. Application data flows separately:
    # your own client sends real requests through this same attested channel
    # to your container's API; the framework neither defines nor inspects it.
    print("Attestation verified.", file=sys.stderr)
    print(json.dumps({"status": "attestation_verified"}))
    sys.exit(0)


if __name__ == "__main__":
    main()