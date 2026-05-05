import sys
import json
import os
import ssl
import socket
import hashlib
import struct
import base64

EXPECTED_MRTD = "{mrtd}"

_INTEL_ROOT_CA_PEM = """{intel_root_ca}"""

# NVIDIA NRAS JWKS signing CA.  This file is the NRAS *intermediate* (the
# leaf's issuer), not a self-signed root — the x5c check below pins x5c[1]
# to it byte-for-byte, so "intermediate" is the accurate name.
_NVIDIA_NRAS_INTERMEDIATE_CA_PEM = """{nvidia_root_ca}"""

TDX_QUOTE_OID = "1.2.840.113741.1.13.1"
GPU_ATT_OID = "1.3.6.1.4.1.59386.1.1"
CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"
# F-7: server-provided binding material so the client can recompute the
# NRAS nonce sha256(v2_binding_digest(ECDH-pub, chain_key_commitment) ||
# salt) and check it against the
# NRAS-signed eat_nonce claim.
NRAS_NONCE_BINDING_OID = "1.3.6.1.4.1.59386.1.3"
# F-8: vTPM measured-boot PCR bundle OID (must match server template).
VTPM_PCRS_OID = "1.3.6.1.4.1.59386.2.2"
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

# F-8: expected vTPM PCR set, supplied as a comma-separated ``pcr:hex``
# string via the ``TEE_CRAFTER_EXPECTED_VTPM_PCRS`` env var, e.g.
# ``0:<hex>,7:<hex>``.  When no expected set is available the check fails
# closed — see ``verify_vtpm_pcrs``.
EXPECTED_VTPM_PCRS = "{expected_vtpm_pcrs}"

# Escape hatch shared by the vTPM PCR check and the MRTD pin.  Both
# describe *which software booted*; accepting whatever the server reports
# makes them decorative, so the default is to refuse and the opt-out is
# explicit and loud.
_ALLOW_UNPINNED_ENV = "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT"


def _allow_unpinned_measurement() -> bool:
    return os.environ.get(_ALLOW_UNPINNED_ENV, "0") == "1"

_TEE_TYPE_TDX = 0x81


def extract_quote_from_cert(cert_der: bytes) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(TDX_QUOTE_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            return ext.value.value
    raise ValueError("TLS certificate does not contain a TDX quote extension")


def extract_gpu_token_from_cert(cert_der: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(GPU_ATT_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            return ext.value.value.decode("utf-8")
    return None


def extract_nras_nonce_binding_from_cert(cert_der: bytes):
    """Return the F-7 NRAS nonce-binding payload from the RA-TLS cert, if any.

    Returns ``{"ecdh_pub_b64": str, "nonce_salt_hex": str, "nonce_hex": str,
               "binding": str}`` or ``None`` when absent.
    """
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


def extract_vtpm_pcrs_from_cert(cert_der: bytes):
    """F-8: return the server-embedded vTPM PCR map from the RA-TLS cert.

    Returns a dict of ``{pcr_index: sha256_hex}`` (strings) on success
    or ``None`` if the extension is missing / malformed.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(VTPM_PCRS_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            try:
                blob = json.loads(ext.value.value.decode("utf-8"))
                pcrs = blob.get("pcrs") or {}
                if isinstance(pcrs, dict) and pcrs:
                    return {str(k): str(v).lower() for k, v in pcrs.items()}
            except Exception:
                return None
    return None


def verify_vtpm_pcrs(pcrs):
    """F-8: check the server's vTPM PCR bundle against pinned expectations.

    Two things to be clear about, because the previous version of this
    function was misleading on both:

    1. These PCR values are *unsigned*.  The server writes them into a
       plain JSON certificate extension; there is no TPM2 quote over them
       and no attestation key involved.  They are only useful as a
       comparison against values an operator pinned out of band — they are
       not independent evidence, and a match is not proof the boot chain
       is intact, only that the server reports the values we expected.
    2. With no expected set, comparing them to nothing is a no-op.  That
       case now fails closed rather than printing a reassuring line.

    Expected values come from ``EXPECTED_VTPM_PCRS`` (build-time) or
    ``TEE_CRAFTER_EXPECTED_VTPM_PCRS`` (runtime), format
    ``idx:hex,idx:hex,...``.
    """
    if pcrs is None:
        print("  vTPM measured boot (F-8): FAILED (extension missing or malformed)",
              file=sys.stderr)
        return False
    if not isinstance(pcrs, dict) or not pcrs:
        print("  vTPM measured boot (F-8): FAILED (empty PCR map)", file=sys.stderr)
        return False
    expected_str = os.environ.get("TEE_CRAFTER_EXPECTED_VTPM_PCRS", EXPECTED_VTPM_PCRS)
    expected_str = (expected_str or "").strip()
    if not expected_str or expected_str == "unknown":
        if not _allow_unpinned_measurement():
            print(
                "  vTPM measured boot (F-8): FAILED — no expected PCR set is "
                "pinned, so the server's self-reported PCRs are compared "
                f"against nothing. Rebuild with expected PCRs, set "
                f"TEE_CRAFTER_EXPECTED_VTPM_PCRS, or set {_ALLOW_UNPINNED_ENV}=1 "
                "to accept an unchecked boot chain.",
                file=sys.stderr,
            )
            return False
        print("  ***********************************************************", file=sys.stderr)
        print("  WARNING: vTPM measured boot is NOT being checked.", file=sys.stderr)
        print(f"  {_ALLOW_UNPINNED_ENV}=1 is set and no expected", file=sys.stderr)
        print(f"  PCR set is pinned. The {len(pcrs)} PCR value(s) below are", file=sys.stderr)
        print("  self-reported by the server and unsigned — they prove nothing.", file=sys.stderr)
        print("  ***********************************************************", file=sys.stderr)
        return True
    expected: dict = {}
    for piece in expected_str.split(","):
        piece = piece.strip()
        if not piece or ":" not in piece:
            continue
        idx, val = piece.split(":", 1)
        expected[idx.strip()] = val.strip().lower()
    if not expected:
        print("  vTPM measured boot (F-8): expected spec invalid — refusing", file=sys.stderr)
        return False
    for idx, want in expected.items():
        got = str(pcrs.get(idx, "")).lower()
        if not got:
            print(f"  vTPM measured boot (F-8): PCR {idx} missing from server bundle",
                  file=sys.stderr)
            return False
        if got != want:
            print(f"  vTPM measured boot (F-8): PCR {idx} mismatch "
                  f"(expected {want[:16]}..., got {got[:16]}...)",
                  file=sys.stderr)
            return False
    print(f"  vTPM measured boot (F-8): PASSED ({len(expected)} of {len(pcrs)} "
          "self-reported PCR(s) matched the pinned set)", file=sys.stderr)
    return True


def _verify_nras_nonce_binding(binding: dict) -> dict:
    """Recompute the NRAS nonce and compare it to binding.nonce_hex.

    AUD-3: the nonce is sha256(v2_binding_digest(ECDH-pub,
    chain_key_commitment) || salt), so a server cannot declare one
    audit-log chain-key commitment and have NVIDIA sign another.

    Returns ``{"ok": bool, "nonce_hex": str, "error": str}``.  Failure here is
    a relay attack signal and must be treated as FATAL by the caller.
    """
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
        # F-14
        out["tls_spki_sha256"] = binding.get("tls_spki_sha256", "")
        out["ok"] = True
        return out
    except Exception as exc:
        out["error"] = f"binding verification exception: {exc}"
        return out


def _compute_peer_spki_sha256(cert_der: bytes) -> str:
    """F-14: SHA-256 of the peer cert's SubjectPublicKeyInfo."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    spki_der = cert.public_key().public_bytes(
        _ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def extract_container_digest_from_cert(cert_der: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(CONTAINER_DIGEST_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            return ext.value.value.decode("utf-8")
    return None


def parse_tdx_quote(quote_bytes: bytes) -> dict:
    if len(quote_bytes) < 632:
        raise ValueError(f"TDX quote too short: {len(quote_bytes)} bytes (need >= 632)")
    version = struct.unpack_from("<H", quote_bytes, 0)[0]
    att_key_type = struct.unpack_from("<H", quote_bytes, 2)[0]
    tee_type = struct.unpack_from("<I", quote_bytes, 4)[0]
    if tee_type != _TEE_TYPE_TDX:
        raise ValueError(f"Quote tee_type is 0x{tee_type:X}, expected 0x{_TEE_TYPE_TDX:X} (TDX)")
    rb = 48
    mrtd = quote_bytes[rb + 136:rb + 184].hex()
    rtmr0 = quote_bytes[rb + 328:rb + 376].hex()
    rtmr1 = quote_bytes[rb + 376:rb + 424].hex()
    td_attributes = quote_bytes[rb + 120:rb + 128]
    report_data = quote_bytes[rb + 520:rb + 584]
    return {
        "version": version, "att_key_type": att_key_type, "tee_type": tee_type,
        "mrtd": mrtd, "rtmr0": rtmr0, "rtmr1": rtmr1,
        "td_attributes": td_attributes.hex(), "report_data": report_data,
        "report_data_hex": report_data.hex(),
    }


def verify_tdx_quote_signature(quote_bytes: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    signed_data_len = 632
    if len(quote_bytes) < signed_data_len + 4 + 64 + 64:
        raise ValueError("TDX quote too short for signature verification")
    signed_data = quote_bytes[:signed_data_len]
    sig_offset = signed_data_len + 4
    enclave_sig = quote_bytes[sig_offset:sig_offset + 64]
    att_key_xy = quote_bytes[sig_offset + 64:sig_offset + 128]
    att_key_x = int.from_bytes(att_key_xy[:32], "big")
    att_key_y = int.from_bytes(att_key_xy[32:], "big")
    att_pub = ec.EllipticCurvePublicNumbers(att_key_x, att_key_y, ec.SECP256R1()).public_key()
    r = int.from_bytes(enclave_sig[:32], "big")
    s = int.from_bytes(enclave_sig[32:], "big")
    der_sig = utils.encode_dss_signature(r, s)
    try:
        att_pub.verify(der_sig, signed_data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _locate_qe_report_offset(quote_bytes: bytes):
    """Return absolute offset of the QE report (sgx_report_body_t, 384 bytes).

    TDX v4 DCAP quotes wrap ECDSA sig-data in an outer cert-data header
    (``cert_data_type`` (2) + ``cert_data_size`` (4) = 6 bytes) right after
    the attestation public key.  For ``cert_data_type == 6``
    (QE_REPORT_CERTIFICATION_DATA, which is what cloud TDX attesters such as
    GCP emit) the QE report is embedded inside that outer blob, so the true
    offset is ``sig_offset + 128 + 6`` rather than ``sig_offset + 128``.

    Legacy DCAP v3 / non-cert-wrapped layouts put the QE report directly at
    ``sig_offset + 128``.  We detect which by looking at the two bytes at
    ``+128``: a plausible ``cert_data_type`` is ``1..7``.  Anything outside
    that range is treated as the legacy layout.  Returns ``None`` when the
    quote is too short to contain a QE report at either layout (e.g. pure
    configfs-tsm quotes that omit QE certification data).

    This is a byte-for-byte port of ``_locate_qe_report_offset`` in
    tdx/gcp/client.template.py.  This platform is the only GPU-CC one with an
    Intel TDX CPU side, so it carries its own copy of the DCAP parsing code;
    it previously hardcoded ``sig_offset + 128`` and read every derived
    offset (QE report signature, QE auth data, PCK cert data) 6 bytes early.
    """
    signed_data_len = 632
    sig_offset = signed_data_len + 4
    if len(quote_bytes) < sig_offset + 128 + 6 + 384:
        if len(quote_bytes) >= sig_offset + 128 + 384:
            return sig_offset + 128
        return None
    ct = int.from_bytes(quote_bytes[sig_offset + 128:sig_offset + 130], "little")
    if 1 <= ct <= 7:
        return sig_offset + 128 + 6
    return sig_offset + 128


def verify_qe_report_binding(quote_bytes: bytes) -> bool:
    """Verify QE report's report_data contains SHA-256(attestation_key || qe_auth_data).

    A quote that carries no QE certification data is a failure, not a special
    case.  This used to return "absent" whenever a length check over the
    server-supplied blob came up short, and the caller had to remember to
    treat that as fatal.  Length checks on untrusted input can only ever tell
    you the input is unusable, never that it is acceptable, so there is no
    third state worth keeping: matches sgx/, tdx/azure/ and tdx/gcp/.
    """
    signed_data_len = 632
    sig_offset = signed_data_len + 4

    att_key_xy = quote_bytes[sig_offset + 64:sig_offset + 128]
    qe_report_offset = _locate_qe_report_offset(quote_bytes)
    if qe_report_offset is None or len(quote_bytes) < qe_report_offset + 384:
        print("  QE report binding: FAILED (quote carries no QE report)", file=sys.stderr)
        return False

    qe_report = quote_bytes[qe_report_offset:qe_report_offset + 384]
    qe_report_data = qe_report[320:384]

    qe_sig_offset = qe_report_offset + 384
    qe_auth_offset = qe_sig_offset + 64
    if len(quote_bytes) < qe_auth_offset + 2:
        print("  QE report binding: FAILED (quote too short for QE auth data)", file=sys.stderr)
        return False
    qe_auth_size = struct.unpack_from("<H", quote_bytes, qe_auth_offset)[0]
    if qe_auth_offset + 2 + qe_auth_size > len(quote_bytes):
        print("  QE report binding: FAILED (QE auth data runs past end of quote)", file=sys.stderr)
        return False
    qe_auth_data = quote_bytes[qe_auth_offset + 2:qe_auth_offset + 2 + qe_auth_size]

    expected_hash = hashlib.sha256(att_key_xy + qe_auth_data).digest()
    return qe_report_data[:32] == expected_hash


def verify_qe_report_signature(quote_bytes: bytes, pck_leaf) -> bool:
    """Verify the QE report's ECDSA signature, made by the PCK leaf's key.

    This is the link that ties the attestation key to Intel-provisioned
    hardware, and this client had no such check at all — the fourth Intel
    verifier in the tree was missed when sgx/, tdx/azure/ and tdx/gcp/ got
    theirs.  Without it every other CPU-side check is self-referential: the
    TD report is verified with an attestation key read out of the same quote,
    and ``verify_qe_report_binding`` hashes that key against a QE report read
    out of the same quote.  PCK chains are public — every genuine quote
    embeds one — so an attacker could forge a TD report with any MRTD,
    sign it with a key of their own, set the QE report's report_data to
    SHA-256(their key || qe_auth) and paste a real Intel chain back in.
    Only this signature is rooted outside the quote, in the PCK certificate
    chain that ends at Intel's root CA.

    *pck_leaf* must be the leaf ``verify_pck_cert_chain`` just walked to the
    pinned root; re-parsing the chain here would reintroduce the same
    disconnect somewhere new.

    The QE report is the 384 bytes at ``_locate_qe_report_offset`` and its
    signature (r || s, ECDSA-P256) is the 64 bytes immediately after it.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    qe_report_offset = _locate_qe_report_offset(quote_bytes)
    if qe_report_offset is None or len(quote_bytes) < qe_report_offset + 384 + 64:
        print("  QE report signature: FAILED (quote carries no QE report and "
              "signature to verify)", file=sys.stderr)
        return False

    pck_pub = pck_leaf.public_key()
    if not isinstance(pck_pub, ec.EllipticCurvePublicKey):
        print(f"  QE report signature: FAILED (PCK leaf key is "
              f"{type(pck_pub).__name__}, not ECDSA)", file=sys.stderr)
        return False

    qe_report = quote_bytes[qe_report_offset:qe_report_offset + 384]
    sig = quote_bytes[qe_report_offset + 384:qe_report_offset + 448]
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")

    try:
        pck_pub.verify(
            utils.encode_dss_signature(r, s), qe_report, ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        print("  QE report signature: FAILED (the PCK leaf key did not sign this "
              "QE report — the attestation key is not vouched for by "
              "Intel-provisioned hardware)", file=sys.stderr)
        return False


def check_ca_certificate(cert, index, remaining_intermediates):
    """Validate the CA-ness of an issuing certificate (RFC 5280 §4.2.1.9/§4.2.1.3).

    A chain walk that verifies only signatures accepts an end-entity
    certificate acting as a CA: anyone holding *any* Intel-issued leaf
    could sign a forged PCK certificate, and the walk would succeed
    because it never asks whether the signer was permitted to sign
    certificates.  basicConstraints exists to stop exactly that.

    ``remaining_intermediates`` is the number of CA certificates that
    appear *below* this one in the chain, i.e. what ``pathLenConstraint``
    bounds.  The pinned ``CN=Intel SGX Root CA`` carries
    ``basicConstraints CA:TRUE, pathlen:1`` and a critical ``keyUsage``
    with ``keyCertSign``, so a conforming Intel chain — PCK leaf ->
    PCK Platform/Processor CA -> root, one intermediate — passes; a chain
    with a second intermediate under the root would not.

    Raises ``ValueError`` on any violation.  ``verify_pck_cert_chain``
    runs inside a ``try`` that turns that into ``{"ok": False, "reason": ...}``,
    which is fatal at the call site.
    """
    from cryptography import x509

    label = f"issuer certificate [{index}]"
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise ValueError(
            f"{label} has no basicConstraints extension, so it is not a CA"
        )
    if not bc.ca:
        raise ValueError(f"{label} has basicConstraints CA:FALSE")
    if bc.path_length is not None and remaining_intermediates > bc.path_length:
        raise ValueError(
            f"{label} has pathLenConstraint={bc.path_length} but "
            f"{remaining_intermediates} intermediate(s) follow it in the chain"
        )
    # keyUsage is optional in RFC 5280.  When present it is authoritative,
    # so a CA without keyCertSign must be rejected; when absent there is
    # nothing to check and rejecting would break a conforming chain.
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not ku.key_cert_sign:
        raise ValueError(f"{label} has a keyUsage extension without keyCertSign")


def check_leaf_certificate(cert):
    """Reject a PCK leaf that claims to be a CA.

    The PCK certificate is an end entity.  If it carried CA:TRUE it could
    mint further certificates under the pinned Intel root, which is exactly
    the confusion basicConstraints exists to prevent.
    """
    from cryptography import x509

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return  # absent basicConstraints means "not a CA" (RFC 5280 §4.2.1.9)
    if bc.ca:
        raise ValueError("PCK leaf certificate asserts basicConstraints CA:TRUE")


def verify_pck_cert_chain(quote_bytes: bytes) -> dict:
    """Verify the PCK certificate chain against Intel's Root CA.

    Returns ``{"ok": True, "pck_leaf": <x509.Certificate>}`` when the chain
    validates to the pinned root, and ``{"ok": False, "reason": "..."}``
    otherwise.

    The leaf is returned because its key signs the QE report — see
    ``verify_qe_report_signature``.  This function used to return the bare
    strings "passed"/"absent"/"failed" and drop the leaf on the floor, so
    nothing downstream could check *which* platform key vouched for the
    attestation key; that was the whole vulnerability.  Handing the caller
    the leaf it just walked to the pinned root is what makes the two checks
    one statement instead of two unrelated ones.

    The "absent" tri-state is gone with it, for the reason spelled out in
    ``verify_qe_report_binding``: a quote with no cert data is a failure,
    and a length check over attacker-supplied bytes can never be a pass.
    Every former "absent" was already fatal at the call site, so this
    narrows nothing; it just removes a state that could be widened by
    mistake.  Matches sgx/, tdx/azure/ and tdx/gcp/.
    """
    from cryptography import x509 as _x509
    from cryptography.hazmat.backends import default_backend as _be
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    try:
        if not _INTEL_ROOT_CA_PEM or not _INTEL_ROOT_CA_PEM.strip():
            return {"ok": False, "reason": "no Intel Root CA PEM in client"}
        qe_report_offset = _locate_qe_report_offset(quote_bytes)
        if qe_report_offset is None:
            return {"ok": False, "reason": "quote carries no QE report"}
        qe_sig_offset = qe_report_offset + 384
        qe_auth_offset = qe_sig_offset + 64
        if len(quote_bytes) < qe_auth_offset + 2:
            return {"ok": False, "reason": "quote too short for QE auth data"}
        qe_auth_size = struct.unpack_from("<H", quote_bytes, qe_auth_offset)[0]
        cert_meta_offset = qe_auth_offset + 2 + qe_auth_size
        if len(quote_bytes) < cert_meta_offset + 6:
            return {"ok": False, "reason": "quote too short for cert meta"}
        cert_data_type = struct.unpack_from("<H", quote_bytes, cert_meta_offset)[0]
        cert_data_size = struct.unpack_from("<I", quote_bytes, cert_meta_offset + 2)[0]
        cert_data = quote_bytes[cert_meta_offset + 6:cert_meta_offset + 6 + cert_data_size]
        if cert_data_type != 5:
            return {"ok": False, "reason": f"cert_data_type {cert_data_type} != 5"}
        pem_certs = []
        remainder = cert_data
        while b"-----BEGIN CERTIFICATE-----" in remainder:
            start = remainder.index(b"-----BEGIN CERTIFICATE-----")
            end = remainder.index(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
            pem_certs.append(remainder[start:end])
            remainder = remainder[end:]
        if not pem_certs:
            return {"ok": False, "reason": "no PEM certs found"}
        chain = [_x509.load_pem_x509_certificate(p, _be()) for p in pem_certs]
        root_ca = _x509.load_pem_x509_certificate(_INTEL_ROOT_CA_PEM.strip().encode(), _be())
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        for idx, cert in enumerate([root_ca] + chain):
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                return {"ok": False,
                        "reason": f"cert [{idx}] outside validity window"}

        # basicConstraints / keyUsage.  Without these the walk below proves
        # only "the next certificate's signature verifies", never "the signer
        # was allowed to sign certificates" — so an attacker holding any
        # Intel-issued end-entity key could sign a forged PCK leaf and the
        # chain would validate.  `chain` is leaf-first, so index 0 is the end
        # entity and every later entry is used as an issuer; `i - 1` is the
        # number of CA certificates below entry `i`, which is what
        # pathLenConstraint bounds.  A violation raises ValueError, which the
        # except clause below reports as {"ok": False}.
        check_leaf_certificate(chain[0])
        for i in range(1, len(chain)):
            check_ca_certificate(chain[i], i, remaining_intermediates=i - 1)
        # The pinned anchor signs chain[-1].  Intel's cert_data ends with the
        # root itself, in which case the loop above already checked it with
        # the correct pathLen budget and re-checking it as one level higher
        # would count an intermediate that does not exist.  x509.Certificate
        # equality is over the DER encoding, so a re-encoded copy still
        # compares equal.
        if chain[-1] != root_ca:
            check_ca_certificate(root_ca, len(chain),
                                 remaining_intermediates=len(chain) - 1)

        # L-02: every certificate in an Intel DCAP PCK chain is ECDSA-signed.
        # These guards used to be `if isinstance(...)`, so a chain presenting a
        # non-EC issuer key skipped its signature check entirely and still
        # returned "passed".  A key type we do not recognise is a reason to
        # refuse, never a reason to skip.  Matches sgx/ and tdx/*/client.
        for i in range(len(chain) - 1):
            issuer_pub = chain[i + 1].public_key()
            if not isinstance(issuer_pub, _ec.EllipticCurvePublicKey):
                print(f"  PCK certificate chain: FAILED (cert [{i + 1}] public key "
                      "is not ECDSA)", file=sys.stderr)
                return {"ok": False,
                        "reason": f"cert [{i + 1}] public key is not ECDSA"}
            issuer_pub.verify(chain[i].signature, chain[i].tbs_certificate_bytes, _ec.ECDSA(chain[i].signature_hash_algorithm))
        top_cert = chain[-1]
        root_pub = root_ca.public_key()
        if not isinstance(root_pub, _ec.EllipticCurvePublicKey):
            print("  PCK certificate chain: FAILED (pinned Intel root CA public "
                  "key is not ECDSA)", file=sys.stderr)
            return {"ok": False,
                    "reason": "pinned Intel root CA public key is not ECDSA"}
        root_pub.verify(top_cert.signature, top_cert.tbs_certificate_bytes, _ec.ECDSA(top_cert.signature_hash_algorithm))
        print("  PCK certificate chain: PASSED", file=sys.stderr)
        # chain[0] is the leaf whose signature path to the pinned root was
        # just established.  verify_qe_report_signature must be given *this*
        # certificate — parsing cert_data a second time somewhere else would
        # recreate the gap this return value closes.
        # ``pck_chain`` is the whole chain, leaf-first, so the TCB evaluation
        # can check *every* certificate in it against Intel's CRLs.  Revoking a
        # PCK intermediate is how Intel withdraws trust in a whole class of
        # platform; a leaf-only revocation check would miss it.
        return {"ok": True, "pck_leaf": chain[0], "pck_chain": chain}
    except Exception as e:
        # InvalidSignature and several other cryptography exceptions
        # carry no message, so str(e) is "" — which turned the most
        # important rejection this function can make ("does not chain
        # to the pinned Intel root") into an empty reason and a bare
        # "FAILED ()" on stderr.  Fall back to the exception type.
        reason = str(e) or type(e).__name__
        print(f"  PCK certificate chain: FAILED ({reason})", file=sys.stderr)
        return {"ok": False, "reason": reason}


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
    """Verify the JWKS key's x5c certificate chain roots to our pinned NVIDIA CA.

    The JWKS key contains x5c=[leaf_cert, intermediate_cert]. We verify:
    1. leaf_cert is signed by intermediate_cert
    2. intermediate_cert matches our pinned _NVIDIA_NRAS_INTERMEDIATE_CA_PEM
    """
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
    7. F-7: if *expected_nonce_hex* is non-empty, assert it matches the
       ``eat_nonce`` claim of the overall EAT.

    Two things this does NOT do, stated because an earlier version of this
    docstring claimed otherwise:

    * The per-GPU detached JWTs are signature-checked against the same JWKS
      and their required claims are compared, but their ``eat_nonce`` is not
      compared against *expected_nonce_hex*.  Only the overall EAT is
      nonce-bound.  Adding the per-GPU check requires confirming that NRAS
      populates ``eat_nonce`` in the detached claim JWTs; until that is
      confirmed against live NRAS output, enforcing it would fail closed on
      every deployment.
    * The per-GPU ``jwt.decode`` calls do not pass ``issuer=``, so the ``iss``
      claim of a detached JWT is unchecked.  The x5c pin on the JWKS key
      still constrains who could have signed it.
    """
    result = {"verified": False}
    if not token:
        result["error"] = "No GPU attestation token provided"
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

        # F-7: enforce nonce binding.  NRAS echoes the submitted nonce in the
        # `eat_nonce` claim (RFC 9711).  A missing claim when we explicitly
        # supplied a binding indicates an old NRAS version OR a relay — we
        # refuse rather than silently accept.
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


# ---------------------------------------------------------------------------
# Platform TCB status evaluation (Intel PCS collateral)
# ---------------------------------------------------------------------------
#
# Everything above proves the quote came from Intel-provisioned hardware.  It
# says nothing about whether that hardware is current: an OUT_OF_DATE platform
# running microcode with published errata, or one whose PCK key Intel has
# REVOKED, produces a quote that passes every check above.  The evaluation
# itself lives in the shared module templates/common/tee_crafter_tcb_eval.py,
# which the build stages next to this client — one implementation for all four
# Intel clients, because four copies of a DCAP verifier drifting apart is what
# produced the last three attestation bugs in this tree (one of them a missing
# QE-report signature check, i.e. a full bypass).

_TCB_EVAL_MODULE = "tee_crafter_tcb_eval"
_TCB_EVAL_MODULE_ENV = "TEE_CRAFTER_TCB_EVAL_MODULE"


def _tcb_eval_module_candidates() -> list:
    """Filesystem locations for the shared evaluator, in resolution order."""
    paths = []
    env = os.environ.get(_TCB_EVAL_MODULE_ENV)
    if env:
        paths.append(env)
    try:
        paths.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  _TCB_EVAL_MODULE + ".py"))
    except Exception:
        pass
    paths.append("/etc/tee_crafter/" + _TCB_EVAL_MODULE + ".py")
    return paths


def load_tcb_eval_module():
    """Import the shared Intel TCB evaluator staged next to this client.

    The build writes ``tee_crafter_tcb_eval.py`` into the same directory as
    this script, and the deploy runs ``python3 <client> ...`` from there, so
    that directory is ``sys.path[0]`` and the plain import succeeds.  The
    explicit path walk covers the cases where it does not — a client imported
    rather than executed, or a baked image keeping its collateral under
    ``/etc/tee_crafter``.

    A missing module raises.  There is deliberately no "evaluator unavailable,
    carry on" branch: that is the shape of every soft-skip bug this repository
    has had.
    """
    import importlib
    import importlib.util

    try:
        return importlib.import_module(_TCB_EVAL_MODULE)
    except ImportError:
        pass
    for path in _tcb_eval_module_candidates():
        if not path or not os.path.exists(path):
            continue
        spec = importlib.util.spec_from_file_location(_TCB_EVAL_MODULE, path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[_TCB_EVAL_MODULE] = module
        spec.loader.exec_module(module)
        return module
    raise RuntimeError(
        f"{_TCB_EVAL_MODULE}.py is neither next to this client nor on "
        f"sys.path (looked at {_tcb_eval_module_candidates()}). The build "
        "stages it there; a build that did not is incomplete, and this client "
        "will not accept a quote without evaluating the platform's Intel TCB "
        "status.")


def enforce_platform_tcb_status(quote_bytes: bytes, quote_info: dict,
                                pck_result: dict) -> None:
    """Evaluate the platform's Intel TCB status.  Any failure is fatal.

    TDX v4 has no CPUSVN in the TD report body, so the platform CPUSVN comes
    from the nested QE report (an ``sgx_report_body_t``, CPUSVN at its bytes
    0..15), located with ``_locate_qe_report_offset`` rather than a hardcoded
    offset.  ``TEE_TCB_SVN`` — the 16 bytes at TD report body offset 0 — is
    what ``tdxtcbcomponents`` is compared against.
    """
    try:
        qe_off = _locate_qe_report_offset(quote_bytes)
        if qe_off is None or len(quote_bytes) < qe_off + 384:
            raise RuntimeError(
                "the quote carries no QE report, so neither the platform "
                "CPUSVN nor the QE identity can be evaluated")
        qe_report = quote_bytes[qe_off:qe_off + 384]
        tcb = load_tcb_eval_module()
        tcb.enforce(
            tee="tdx",
            pck_chain=pck_result.get("pck_chain") or [],
            qe_report=qe_report,
            report_cpusvn=qe_report[0:16],
            tee_tcb_svn=bytes.fromhex(quote_info.get("tee_tcb_svn") or ""),
            # TD report body: 584 bytes after the 48-byte quote header.
            # Carries MRSIGNERSEAM and SEAMATTRIBUTES, which is what
            # lets the evaluator check the TDX module identity against
            # Intel's tdxModuleIdentities rather than trusting the
            # module version alone.  Required: the evaluator refuses a
            # TDX evaluation without it instead of skipping the check.
            td_report_body=quote_bytes[48:632],
            pinned_root_ca_pem=_INTEL_ROOT_CA_PEM,
            check_leaf_certificate=check_leaf_certificate,
            check_ca_certificate=check_ca_certificate,
        )
    except SystemExit:
        raise
    except Exception as exc:
        print("FATAL: platform TCB status evaluation failed: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)


def verify_ratls_connection(host: str, port: int, ratls_nonce: bytes | None = None) -> tuple:
    """Connect via RA-TLS and verify dual attestation (CPU TDX + GPU NRAS)."""
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
        print("FATAL: Server did not present a certificate.", file=sys.stderr)
        sys.exit(1)

    # CPU attestation (TDX)
    try:
        quote_bytes = extract_quote_from_cert(cert_der)
    except ValueError as e:
        conn.close()
        print(f"FATAL: {e}. RA-TLS attestation required.", file=sys.stderr)
        sys.exit(1)

    quote_info = parse_tdx_quote(quote_bytes)
    print(f"  CPU TEE:            Intel TDX", file=sys.stderr)
    print(f"  MRTD:               {quote_info['mrtd']}", file=sys.stderr)
    print(f"  RTMR[0]:            {quote_info['rtmr0'][:32]}...", file=sys.stderr)

    print("Verifying TDX quote ECDSA signature...", file=sys.stderr)
    if not verify_tdx_quote_signature(quote_bytes):
        conn.close()
        print("FATAL: TDX quote ECDSA signature verification FAILED.", file=sys.stderr)
        sys.exit(1)
    print("  TDX quote signature: PASSED", file=sys.stderr)

    td_attr_bytes = bytes.fromhex(quote_info["td_attributes"])
    if len(td_attr_bytes) >= 8 and (td_attr_bytes[0] & 0x01):
        conn.close()
        print("FATAL: TD_ATTRIBUTES has DEBUG bit set — refusing production connection.", file=sys.stderr)
        sys.exit(1)
    print("  TD_ATTRIBUTES debug bit: CLEAR (production mode)", file=sys.stderr)

    print("Verifying QE report binding...", file=sys.stderr)
    if not verify_qe_report_binding(quote_bytes):
        # This covers what used to be two branches, "failed" and "absent".
        # "absent" was decided by a length check over the *quote the server
        # sent*, so an attacker who truncates the quote below the QE-data
        # offset chose that branch; both were already fatal, and collapsing
        # them removes a state that could be widened back to warn-and-continue
        # (which is what this client used to do).
        conn.close()
        print("FATAL: QE report binding verification FAILED — nothing ties the "
              "attestation key to a Quoting Enclave, so its authenticity "
              "cannot be confirmed.", file=sys.stderr)
        sys.exit(1)
    print("  QE report binding: PASSED", file=sys.stderr)

    print("Verifying PCK certificate chain...", file=sys.stderr)
    pck_result = verify_pck_cert_chain(quote_bytes)
    if not pck_result.get("ok"):
        # Same reasoning as the QE branch above, plus: without a PCK chain
        # there is no path to Intel's root, so nothing about this quote is
        # anchored in hardware.
        conn.close()
        print("FATAL: PCK certificate chain verification FAILED — cannot verify "
              f"hardware root of trust ({pck_result.get('reason', 'unknown')}).",
              file=sys.stderr)
        sys.exit(1)
    print("  PCK certificate chain: PASSED", file=sys.stderr)

    # The two checks above are self-referential on their own: the TD report is
    # verified with an attestation key read out of this same quote, and the QE
    # binding hashes that key against a QE report read out of this same quote.
    # PCK chains are public, so a forged quote can carry a genuine one.  This
    # is the step that makes the previous ones mean something: the leaf that
    # verify_pck_cert_chain just walked to the pinned Intel root must be the
    # key that signed this QE report.  It is passed through from
    # `pck_result` rather than re-parsed, so there is no way for the
    # certificate that was validated and the certificate that is used to
    # drift apart.
    print("Verifying QE report signature (PCK leaf key)...", file=sys.stderr)
    if not verify_qe_report_signature(quote_bytes, pck_result["pck_leaf"]):
        conn.close()
        print("FATAL: QE report signature verification FAILED. The attestation "
              "key is not vouched for by an Intel-provisioned platform key.",
              file=sys.stderr)
        sys.exit(1)
    print("  QE report signature: PASSED", file=sys.stderr)

    # Evaluate the platform's Intel TCB status (and QEIdentity, and the PCK
    # CRLs) against the signature-verified collateral bundle.  Everything above
    # proves the hardware; this is the step that says Intel still trusts it.
    # This client had no TCB status evaluation and no QE identity check at all,
    # which is the drift TestIntelVerifierParity called out.
    print("Evaluating platform TCB status (Intel PCS collateral)...",
          file=sys.stderr)
    enforce_platform_tcb_status(quote_bytes, quote_info, pck_result)

    # F-4: an MRTD the client learns from the server it is verifying is not
    # a pin.  This is a one-shot script, so there is no "subsequent
    # connection" to enforce it on — refuse unless the operator opts out.
    if EXPECTED_MRTD and EXPECTED_MRTD != "unknown":
        if quote_info["mrtd"] != EXPECTED_MRTD:
            conn.close()
            print(f"FATAL: MRTD mismatch! Expected {EXPECTED_MRTD}, got {quote_info['mrtd']}", file=sys.stderr)
            sys.exit(1)
        print("  MRTD verification: PASSED", file=sys.stderr)
    elif _allow_unpinned_measurement():
        print("  ***********************************************************", file=sys.stderr)
        print("  WARNING: no MRTD is pinned into this client.", file=sys.stderr)
        print(f"  {_ALLOW_UNPINNED_ENV}=1 is set, so the quote is", file=sys.stderr)
        print("  accepted on its signature alone. The identity of the software", file=sys.stderr)
        print("  inside the TD is NOT being checked.", file=sys.stderr)
        print(f"  Observed MRTD: {quote_info['mrtd']}", file=sys.stderr)
        print("  ***********************************************************", file=sys.stderr)
    else:
        conn.close()
        print(
            "FATAL: no MRTD pinned into this client. A valid TDX quote proves "
            "the hardware, not which image booted on it. Rebuild the client "
            f"with the expected MRTD, or set {_ALLOW_UNPINNED_ENV}=1 to accept "
            "any image.",
            file=sys.stderr,
        )
        sys.exit(1)

    # GPU attestation (NVIDIA NRAS) — required on GCP (full-confidential)
    gpu_token = extract_gpu_token_from_cert(cert_der)
    if not gpu_token:
        conn.close()
        print("FATAL: GPU NRAS attestation NOT PRESENT in certificate (required on GCP).", file=sys.stderr)
        sys.exit(1)

    # F-7: recover the server-computed NRAS nonce binding and recompute it
    # locally before trusting the NRAS token.  Missing binding (old server)
    # is treated as a hard failure in defence-in-depth — GCP/Azure builds
    # always populate it; AWS partial-confidential builds do too.
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

    # F-14: belt-and-braces TLS SPKI exact-equal check.
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
    # TEE's report_data: this platform has no CPU anchor for the commitment,
    # so the guarantee is 'NVIDIA attested this GPU evidence', not 'the CPU
    # TEE hardware signed this value'.  Stated in the output for that reason.
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

    # F-8: enforce measured-boot vTPM PCR extension.
    vtpm_pcrs = extract_vtpm_pcrs_from_cert(cert_der)
    if not verify_vtpm_pcrs(vtpm_pcrs):
        conn.close()
        print("FATAL: vTPM measured-boot verification failed (F-8).", file=sys.stderr)
        sys.exit(1)

    print("  Dual attestation (TDX + NVIDIA CC): COMPLETE", file=sys.stderr)
    print("  Security model: FULL-CONFIDENTIAL (encrypted PCIe)", file=sys.stderr)

    # AUD-7 / ATT-006 / ATT-007 / ATT-009 / ATT-010: structured
    # ATTESTATION_REPORT line for the deploy orchestrator.
    try:
        spki = _spki_sha256_from_der(cert_der)
    except Exception:
        spki = ""
    try:
        attestation_report = {
            "platform": "gpu-cc-gcp",
            "issuer": "intel-tdx+nvidia-nras",
            "report_kind": "tdx_dcap+nras_eat",
            "quote_signature_alg": "ECDSA_P256_SHA256",
            "mrtd": quote_info.get("mrtd", ""),
            "rtmr0": quote_info.get("rtmr0", ""),
            "rtmr1": quote_info.get("rtmr1", ""),
            "rtmr2": quote_info.get("rtmr2", ""),
            "rtmr3": quote_info.get("rtmr3", ""),
            "tcb_svn": quote_info.get("tee_tcb_svn", ""),
            "nras_token_valid": True,
            "nras_token_kid": locals().get("nras_kid", "") or "",
            "nras_eat_digest": locals().get("nras_eat_digest", "") or "",
            "nonce_binding": quote_info.get("report_data_hex", ""),
            "nonce": (ratls_nonce or b"").hex(),
            "spki_sha256": spki,
            "container_digest": server_cd or "",
            # AUD-3: the audit-log chain-key commitment NVIDIA signed into
            # eat_nonce and Intel signed into the quote's REPORT_DATA.
            "chain_key_commitment": attested_chain_commitment,
        }
        print(f"ATTESTATION_REPORT {json.dumps(attestation_report, separators=(',', ':'))}")
    except Exception as _att_err:
        print(f"WARN: failed to emit ATTESTATION_REPORT line: {type(_att_err).__name__}: {_att_err}", file=sys.stderr)

    # AUD-3: main() needs the commitment to rebuild the REPORT_DATA preimage.
    quote_info["chain_key_commitment"] = attested_chain_commitment
    return conn, quote_info


def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def send_request(conn, payload: dict) -> dict:
    _MAX_RESPONSE_SIZE = 64 * 1024 * 1024
    data = json.dumps(payload).encode("utf-8")
    conn.sendall(struct.pack("!I", len(data)))
    conn.sendall(data)
    hdr = _recv_exactly(conn, 4)
    resp_len = struct.unpack("!I", hdr)[0]
    if resp_len > _MAX_RESPONSE_SIZE:
        raise ValueError(f"Response size {resp_len} exceeds maximum")
    response = _recv_exactly(conn, resp_len)
    return json.loads(response.decode("utf-8"))


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 client_gpu_cc_gcp.py <host_ip> [port]", file=sys.stderr)
        sys.exit(1)
    host_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5005
    ratls_nonce = os.urandom(32)
    print(f"Connecting to GPU CC GCP VM at {host_ip}:{port} via RA-TLS...", file=sys.stderr)
    print("  Platform: GCP A3 (Intel TDX + NVIDIA H100 CC)", file=sys.stderr)
    try:
        conn, quote_info = verify_ratls_connection(host_ip, port, ratls_nonce=ratls_nonce)
        print("Dual RA-TLS Attestation Passed! (TDX + NVIDIA CC)", file=sys.stderr)
    except Exception as e:
        print(f"Failed to establish RA-TLS connection: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)

    # MRTD was already either matched against the build-time pin or
    # explicitly waived in verify_ratls_connection; nothing to re-derive.
    report_data_bytes = quote_info["report_data"]

    print("Requesting VM public key via attested connection...", file=sys.stderr)
    try:
        att_resp = send_request(conn, {"action": "get_attestation", "nonce": base64.b64encode(os.urandom(32)).decode()})
        enclave_pub_b64 = att_resp.get("enclave_public_key")
        if not enclave_pub_b64:
            print("FATAL: VM did not provide its public key.", file=sys.stderr)
            sys.exit(1)
        enclave_pub_bytes = base64.b64decode(enclave_pub_b64)

        gpu_info = att_resp.get("gpu_info", {})
        if gpu_info:
            print(f"  GPU: {gpu_info.get('gpu_name', 'N/A')} x{gpu_info.get('gpu_count', '?')}", file=sys.stderr)
            print(f"  CC Mode: {gpu_info.get('cc_mode', 'N/A')}", file=sys.stderr)
            print(f"  Driver: {gpu_info.get('driver_version', 'N/A')}", file=sys.stderr)
    except Exception as e:
        print(f"Failed to get VM public key: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # AUD-3: the TDX quote's REPORT_DATA covers the ECDH key, the container
    # digest and the audit-log chain-key commitment, length-prefixed.  The
    # commitment used here is the one whose NRAS nonce NVIDIA already signed
    # (checked above), so a server that publishes one commitment to NRAS and
    # a different one to Intel fails both ways.
    pub_key_hash = _attest_binding_digest(
        enclave_pub_bytes,
        EXPECTED_CONTAINER_DIGEST.encode("utf-8"),
        quote_info.get("chain_key_commitment", "").encode("ascii"),
    )
    if report_data_bytes[:32] != pub_key_hash:
        print("FATAL: TDX quote report_data does not equal the v2 binding digest "
              "over (ECDH pubkey, container digest, chain_key_commitment). The "
              "VM public key, the container digest or the audit-log chain-key "
              "commitment is not the one Intel signed.", file=sys.stderr)
        print(f"  Expected {pub_key_hash.hex()}, got {report_data_bytes[:32].hex()}",
              file=sys.stderr)
        sys.exit(1)
    print("  Public key + container + chain-commitment binding: PASSED "
          "(Intel-signed TDX report_data)", file=sys.stderr)

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
