import sys
import json
import os
import ssl
import socket
import hashlib
import struct
import base64

EXPECTED_MEASUREMENT = "{measurement}"
EXPECTED_MEASUREMENTS = {measurements_json}

def _measurement_allowlist():
    vals = []
    if isinstance(EXPECTED_MEASUREMENTS, list):
        vals.extend(EXPECTED_MEASUREMENTS)
    if EXPECTED_MEASUREMENT and EXPECTED_MEASUREMENT != "unknown":
        vals.append(EXPECTED_MEASUREMENT)
    return {v.lower() for v in vals if v and v != "unknown"}

def _measurement_allowed(meas):
    allow = _measurement_allowlist()
    if not allow:
        return None
    return (meas or "").lower() in allow

# AMD Root of Trust certificate chain(s) for VCEK verification (SNP-2).
# The build injects either a single processor-family chain or both Milan
# and Genoa chains.  At runtime the client tries each available chain and
# accepts the first that validates the endorsement cert — giving cert-
# chain-based auto-selection by CHIP_ID without having to parse CPU family
# directly.  Placeholder tokens are intentionally kept out of this comment
# block; the template renderer replaces text globally and a multi-line PEM
# would otherwise bleed into non-comment lines.
_AMD_ROOT_CA_PEM = """{amd_root_ca}"""
_AMD_ROOT_CA_MILAN_PEM = """{amd_root_ca_milan}"""
# VCEK-signing chain for Milan: [SEV-Milan (ASK), ARK-Milan].  The bundle
# above carries the VLEK intermediate (SEV-VLEK-Milan), which is what AWS
# returns; a Milan host that returns a VCEK -- GCP does -- has no issuer in
# it, so chain verification could only fail.  Same ARK in both, so this
# widens what verifies without changing the pinned root.
_AMD_ASK_CA_MILAN_PEM = """{amd_ask_ca_milan}"""
_AMD_ROOT_CA_GENOA_PEM = """{amd_root_ca_genoa}"""

SNP_QUOTE_OID = "1.3.6.1.4.1.3704.1.1.1"
CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"
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


# REPORTED_TCB bits 55:48 = SNP firmware SVN (Milan/Genoa/Bergamo; AMD ABI 56860).
# AMD-SB-3015: minimum mitigated SPL, per processor family.  The report itself
# carries no trustworthy CPU-family field, so the family comes from which AMD
# root chain validated the VCEK (AMD issues VCEKs under a family-specific ARK).
_MIN_SNP_FIRMWARE_SVN_BY_FAMILY = {"milan": 0x17, "genoa": 0x16}
# Floor applied when the validating chain does not name a family (legacy
# single-chain builds).  Strictest known value — fail safe, not open.
_MIN_SNP_FIRMWARE_SVN = max(_MIN_SNP_FIRMWARE_SVN_BY_FAMILY.values())
_PLATFORM_INFO_ALIAS_CHECK_COMPLETE = 1 << 5

# Attestation report field offsets (same as AWS — identical AMD SEV-SNP ABI)
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
_SNP_REPORT_SIZE = 1184
_SNP_SIGNED_DATA_SIZE = 0x2A0


def extract_snp_evidence_from_cert(cert_der: bytes) -> tuple:
    """Extract SNP report, endorsement cert, and optional TPM evidence from RA-TLS certificate.

    Returns (report, endorsement_cert, tpm_evidence, runtime_data) where
    tpm_evidence is
    (quote_msg, quote_sig, ak_pub_pem) or None.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(SNP_QUOTE_OID)

    for ext in cert.extensions:
        if ext.oid == target_oid:
            blob = ext.value.value
            if len(blob) < _SNP_REPORT_SIZE + 4:
                raise ValueError(f"SNP extension too short: {len(blob)} bytes")
            report = blob[:_SNP_REPORT_SIZE]
            cert_len = struct.unpack_from("<I", blob, _SNP_REPORT_SIZE)[0]
            endorsement_cert = blob[_SNP_REPORT_SIZE + 4:_SNP_REPORT_SIZE + 4 + cert_len]

            tpm_evidence = None
            runtime_data = b""
            tpm_offset = _SNP_REPORT_SIZE + 4 + cert_len
            if tpm_offset + 4 <= len(blob):
                tpm_blob_len = struct.unpack_from("<I", blob, tpm_offset)[0]
                if tpm_blob_len > 0:
                    tpm_blob = blob[tpm_offset + 4:tpm_offset + 4 + tpm_blob_len]
                    try:
                        tpm_evidence = _parse_tpm_evidence(tpm_blob)
                    except Exception as e:
                        raise ValueError(f"Failed to parse TPM evidence: {e}") from e
                # Optional trailing field: the HCL runtime data the SNP
                # REPORT_DATA commits to.  Absent from certificates minted
                # before it was added, hence optional rather than required.
                rt_offset = tpm_offset + 4 + tpm_blob_len
                if rt_offset + 4 <= len(blob):
                    rt_len = struct.unpack_from("<I", blob, rt_offset)[0]
                    if 0 < rt_len <= len(blob) - rt_offset - 4:
                        runtime_data = blob[rt_offset + 4:rt_offset + 4 + rt_len]

            return report, endorsement_cert, tpm_evidence, runtime_data

    raise ValueError("TLS certificate does not contain an SNP attestation extension")


def _parse_tpm_evidence(blob: bytes) -> tuple:
    """Parse TPM evidence blob → (quote_msg, quote_sig, ak_pub_pem)."""
    off = 0
    msg_len = struct.unpack_from("<I", blob, off)[0]; off += 4
    quote_msg = blob[off:off + msg_len]; off += msg_len
    sig_len = struct.unpack_from("<I", blob, off)[0]; off += 4
    quote_sig = blob[off:off + sig_len]; off += sig_len
    pub_len = struct.unpack_from("<I", blob, off)[0]; off += 4
    ak_pub = blob[off:off + pub_len]
    return quote_msg, quote_sig, ak_pub



def verify_hcl_ak_binding(report_data: bytes, runtime_data: bytes,
                          ak_pub: bytes) -> bool:
    """Is the TPM attestation key the one the AMD-signed report vouches for?

    This is what upgrades ``snp-azure`` from "some vTPM signed a quote" to a
    binding rooted in AMD's signature, and it is why a strict AK-binding gate
    can pass on a platform with no ``/dev/sev-guest``.

    Two checks, both necessary:

    1. ``sha256(runtime_data) == report_data[:32]``.  The SNP report is signed
       by AMD over REPORT_DATA, so this ties the runtime-data JSON to the
       hardware signature.  Verified on a live CVM on 2026-08-23: REPORT_DATA
       was ``5901fcb0925d6ff4…`` followed by 32 zero bytes, and sha256 of the
       1233-byte JSON matched exactly.
    2. The RSA modulus of ``keys[kid == "HCLAkPub"]`` is the modulus of
       *ak_pub*, the attestation key whose private half signed the quote.

       ``ak_pub`` is **PEM** here -- the app runs ``tpm2_readpublic -f pem`` --
       so this parses it and compares the modulus as an integer.  An earlier
       revision tested ``modulus in ak_pub`` as a byte substring, which is
       silently always false against PEM (base64 of DER contains none of the
       raw modulus bytes): the upgrade below would never have fired and the
       strict gate would have stayed unsatisfiable, with a full set of green
       unit tests, because the fixture supplied a raw blob rather than the PEM
       the app actually sends.  A raw TPM2B_PUBLIC is still accepted as a
       fallback, where the substring test is the right one.

    Without check 2, the quote proves only that *whoever holds the presented AK*
    signed the right nonce — and an attacker replaying a captured SNP report can
    generate their own AK and do exactly that, committing to their own key hash.
    That is the circularity this closes.

    Returns False rather than raising for any malformed input: the caller treats
    a failed upgrade as "no strong binding" and reports the weaker mode, which
    keeps a parsing quirk from being indistinguishable from an attack.
    """
    if not runtime_data or not ak_pub or len(report_data) < 32:
        return False
    if hashlib.sha256(runtime_data).digest() != report_data[:32]:
        return False
    try:
        doc = json.loads(runtime_data)
    except Exception:
        return False
    for key in (doc.get("keys") or []):
        if key.get("kid") != "HCLAkPub":
            continue
        n_b64 = key.get("n")
        if not isinstance(n_b64, str):
            return False
        try:
            modulus = base64.urlsafe_b64decode(
                n_b64 + "=" * (-len(n_b64) % 4))
        except Exception:
            return False
        if len(modulus) < 128:
            return False
        return _ak_pub_has_modulus(ak_pub, modulus)
    return False


def _ak_pub_has_modulus(ak_pub: bytes, modulus: bytes) -> bool:
    """Does *ak_pub* carry exactly this RSA modulus?

    Handles the PEM the app sends and a raw TPM2B_PUBLIC blob, in that order.
    Comparing integers rather than bytes for the parsed case is what makes a
    leading zero byte -- legal in a JWK ``n``, absent from the parsed modulus --
    a match rather than a spurious failure.
    """
    want = int.from_bytes(modulus, "big")
    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key, load_der_public_key,
        )
        for loader in (load_pem_public_key, load_der_public_key):
            try:
                pub = loader(ak_pub)
            except Exception:
                continue
            numbers = getattr(pub, "public_numbers", None)
            if numbers is None:
                continue
            got = getattr(numbers(), "n", None)
            if got is not None:
                return got == want
    except Exception:
        pass
    # Raw TPM2B_PUBLIC: the modulus appears verbatim. 256 bytes of
    # high-entropy data, so a coincidental hit is not a practical concern.
    return modulus in ak_pub


def extract_container_digest_from_cert(cert_der: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(CONTAINER_DIGEST_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            return ext.value.value.decode("utf-8")
    return None


def parse_snp_report(report: bytes) -> dict:
    """Parse key fields from an AMD SEV-SNP attestation report."""
    if len(report) < _SNP_REPORT_SIZE:
        raise ValueError(f"SNP report too short: {len(report)} bytes")

    version = struct.unpack_from("<I", report, _OFF_VERSION)[0]
    guest_svn = struct.unpack_from("<I", report, _OFF_GUEST_SVN)[0]
    policy = struct.unpack_from("<Q", report, _OFF_POLICY)[0]
    vmpl = struct.unpack_from("<I", report, _OFF_VMPL)[0]
    sig_algo = struct.unpack_from("<I", report, _OFF_SIG_ALGO)[0]
    current_tcb = struct.unpack_from("<Q", report, _OFF_CURRENT_TCB)[0]
    plat_info = struct.unpack_from("<Q", report, _OFF_PLAT_INFO)[0]
    report_data = report[_OFF_REPORT_DATA:_OFF_REPORT_DATA + 64]
    measurement = report[_OFF_MEASUREMENT:_OFF_MEASUREMENT + 48].hex()
    host_data = report[_OFF_HOST_DATA:_OFF_HOST_DATA + 32].hex()
    id_key_digest = report[_OFF_ID_KEY_DIGEST:_OFF_ID_KEY_DIGEST + 48].hex()
    author_key_digest = report[_OFF_AUTHOR_KEY_DIGEST:_OFF_AUTHOR_KEY_DIGEST + 48].hex()
    report_id = report[_OFF_REPORT_ID:_OFF_REPORT_ID + 32].hex()
    reported_tcb = struct.unpack_from("<Q", report, _OFF_REPORTED_TCB)[0]
    chip_id = report[_OFF_CHIP_ID:_OFF_CHIP_ID + 64].hex()
    committed_tcb = struct.unpack_from("<Q", report, _OFF_COMMITTED_TCB)[0]
    launch_tcb = struct.unpack_from("<Q", report, _OFF_LAUNCH_TCB)[0]

    policy_debug = bool(policy & (1 << 19))
    policy_migrate = bool(policy & (1 << 18))
    policy_smt = bool(policy & (1 << 16))
    policy_abi_major = (policy >> 8) & 0xFF
    policy_abi_minor = policy & 0xFF

    return {
        "version": version,
        "guest_svn": guest_svn,
        "policy": policy,
        "policy_debug": policy_debug,
        "policy_migrate": policy_migrate,
        "policy_smt": policy_smt,
        "policy_abi_major": policy_abi_major,
        "policy_abi_minor": policy_abi_minor,
        "vmpl": vmpl,
        "sig_algo": sig_algo,
        "current_tcb": current_tcb,
        "plat_info": plat_info,
        "report_data": report_data,
        "report_data_hex": report_data.hex(),
        "measurement": measurement,
        "host_data": host_data,
        "id_key_digest": id_key_digest,
        "author_key_digest": author_key_digest,
        "report_id": report_id,
        "reported_tcb": reported_tcb,
        "chip_id": chip_id,
        "committed_tcb": committed_tcb,
        "launch_tcb": launch_tcb,
    }


def verify_snp_report_signature(report: bytes, endorsement_pem: bytes) -> bool:
    """Verify the ECDSA-384 signature on the SNP report using the VCEK."""
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod, utils
    from cryptography.hazmat.primitives import hashes as hash_mod
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature

    if len(report) < _OFF_SIGNATURE + 512:
        raise ValueError("Report too short for signature verification")

    try:
        cert = x509.load_pem_x509_certificate(endorsement_pem, default_backend())
        pub_key = cert.public_key()
    except Exception as e:
        print(f"  Could not load endorsement certificate: {e}", file=sys.stderr)
        return False

    signed_data = report[:_SNP_SIGNED_DATA_SIZE]

    r = int.from_bytes(report[_OFF_SIGNATURE:_OFF_SIGNATURE + 48], "little")
    s = int.from_bytes(report[_OFF_SIGNATURE + 72:_OFF_SIGNATURE + 72 + 48], "little")
    der_sig = utils.encode_dss_signature(r, s)

    try:
        pub_key.verify(der_sig, signed_data, ec_mod.ECDSA(hash_mod.SHA384()))
        return True
    except InvalidSignature:
        return False


def _parse_pem_chain(pem: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    chain_certs = []
    remainder = pem
    while b"-----BEGIN CERTIFICATE-----" in remainder:
        start = remainder.index(b"-----BEGIN CERTIFICATE-----")
        end = remainder.index(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
        chain_certs.append(
            x509.load_pem_x509_certificate(remainder[start:end], default_backend())
        )
        remainder = remainder[end:]
    return chain_certs


def _verify_cert_sig(issuer_pub, cert) -> None:
    """Verify cert.signature with issuer_pub.  Raises on any failure.

    Dispatch is on the *issuer key type*, never guarded by an
    ``isinstance`` check that can silently skip the verification: an
    unrecognised key type raises, so the chain fails closed.
    """
    from cryptography.hazmat.primitives.asymmetric import (
        ec as ec_mod,
        padding as padding_mod,
        rsa as rsa_mod,
    )

    algo = cert.signature_hash_algorithm
    if isinstance(issuer_pub, rsa_mod.RSAPublicKey):
        # AMD ARK/ASK/VCEK are RSA-4096 RSASSA-PSS with MGF1 and salt
        # length == digest size (verified against the baked-in ARK
        # bundles: sha384 / MGF1-sha384 / salt 0x30).  PKCS#1 v1.5 does
        # NOT validate these certificates.
        issuer_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding_mod.PSS(mgf=padding_mod.MGF1(algo), salt_length=algo.digest_size),
            algo,
        )
    elif isinstance(issuer_pub, ec_mod.EllipticCurvePublicKey):
        issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes, ec_mod.ECDSA(algo))
    else:
        raise ValueError(f"unsupported issuer key type: {type(issuer_pub).__name__}")


def _spki_sha256_of_cert(cert) -> str:
    """SHA-256 of a certificate's SubjectPublicKeyInfo (DER)."""
    from cryptography.hazmat.primitives import serialization
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def _trusted_ark_spki_digests() -> set:
    """SPKI SHA-256 digests of the ARKs baked into this client.

    The ARK is the last certificate of each baked bundle.  We pin the
    key, not the subject name — an attacker can put "CN=ARK-Milan" on a
    self-signed certificate, but cannot reproduce AMD's public key.
    """
    digests = set()
    for pem_str in (_AMD_ROOT_CA_PEM, _AMD_ROOT_CA_MILAN_PEM,
                    _AMD_ASK_CA_MILAN_PEM, _AMD_ROOT_CA_GENOA_PEM):
        if not pem_str or not pem_str.strip():
            continue
        try:
            certs = _parse_pem_chain(pem_str.strip().encode())
        except Exception:
            continue
        if certs:
            digests.add(_spki_sha256_of_cert(certs[-1]))
    return digests


def _try_verify_against_chain(endorsement_cert, chain_certs, label: str) -> bool:
    """Verify VCEK -> ASK -> ARK against one baked chain.

    Returns True only if every link verifies, the chain's ARK is one of
    the baked-in AMD roots, and all certs are in-window.
    """
    import datetime

    if not chain_certs:
        return False

    now = datetime.datetime.now(datetime.timezone.utc)
    for cert in [endorsement_cert] + chain_certs:
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False

    try:
        _verify_cert_sig(chain_certs[0].public_key(), endorsement_cert)
        for i in range(len(chain_certs) - 1):
            _verify_cert_sig(chain_certs[i + 1].public_key(), chain_certs[i])
        ark = chain_certs[-1]
        _verify_cert_sig(ark.public_key(), ark)

        # The ARK self-signature proves only self-consistency — any
        # self-signed certificate passes it.  Anchor the walk by pinning
        # the ARK's public key to a root baked into this client.
        trusted = _trusted_ark_spki_digests()
        if not trusted or _spki_sha256_of_cert(ark) not in trusted:
            return False
    except Exception:
        return False

    print(f"  AMD certificate chain: PASSED against {label}", file=sys.stderr)
    return True


def verify_endorsement_cert_chain(endorsement_pem: bytes):
    """Verify VCEK chains to the AMD root of trust, trying each baked
    chain in turn (SNP-2 cert-chain auto-selection).

    Returns the label of the chain that validated ("Milan", "Genoa" or
    "default"), or None if none did.  The label is the client's only
    trustworthy processor-family signal, because AMD issues VCEK
    certificates under a family-specific ARK."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    try:
        endorsement_cert = x509.load_pem_x509_certificate(
            endorsement_pem, default_backend()
        )

        candidates = []
        for label, pem_str in (
            ("Milan", _AMD_ROOT_CA_MILAN_PEM),
            # Same "Milan" label on purpose: the label is the client's only
            # trustworthy processor-family signal, and a VCEK verified by the
            # Milan ASK is just as much a Milan part as one verified by the
            # Milan VLEK chain.
            ("Milan", _AMD_ASK_CA_MILAN_PEM),
            ("Genoa", _AMD_ROOT_CA_GENOA_PEM),
            ("default", _AMD_ROOT_CA_PEM),
        ):
            if pem_str and pem_str.strip():
                candidates.append((label, _parse_pem_chain(pem_str.strip().encode())))

        if not candidates:
            print("  AMD cert chain: FAILED (no AMD root CA PEM in client)",
                  file=sys.stderr)
            return None

        for label, chain_certs in candidates:
            if _try_verify_against_chain(endorsement_cert, chain_certs, label):
                return label

        print("  AMD cert chain: FAILED (endorsement not signed by any known ARK/ASK chain)",
              file=sys.stderr)
        return None

    except Exception as e:
        print(f"  AMD certificate chain verification failed: {e}", file=sys.stderr)
        return None


def verify_guest_policy(report_info: dict) -> bool:
    """Verify the guest policy flags meet security requirements."""
    passed = True

    if report_info["policy_debug"]:
        print("  FATAL: Guest policy has DEBUG enabled!", file=sys.stderr)
        passed = False
    else:
        print("  Policy debug disabled: PASSED", file=sys.stderr)

    if report_info["policy_migrate"]:
        print("  FATAL: Guest policy allows migration — refusing connection.", file=sys.stderr)
        passed = False
    else:
        print("  Policy migration disabled: PASSED", file=sys.stderr)

    if report_info["vmpl"] != 0:
        print(f"  FATAL: VMPL is {report_info['vmpl']} (expected 0)", file=sys.stderr)
        passed = False

    return passed


def verify_parsed_report_fields(report_info: dict) -> bool:
    """Check the SNP report fields that parse_snp_report() used to drop.

    Every field below was decoded and then never looked at again, which
    reads as coverage that does not exist.  Each one is now either
    enforced, pinnable on demand, or explicitly labelled informational.

    Fatal:
      * ``LAUNCH_TCB <= REPORTED_TCB`` — the TCB the guest launched under
        must not exceed the currently reported one.  Same anti-rollback
        family as the COMMITTED_TCB check already performed by the caller
        (AMD SEV-SNP ABI 56860, attestation report layout).

    Pinned when the operator supplies a value, and reported as unpinned
    otherwise:
      * ``HOST_DATA``         — ``TEE_CRAFTER_SNP_EXPECTED_HOST_DATA``
      * ``ID_KEY_DIGEST``     — ``TEE_CRAFTER_SNP_EXPECTED_ID_KEY_DIGEST``
      * ``AUTHOR_KEY_DIGEST`` — ``TEE_CRAFTER_SNP_EXPECTED_AUTHOR_KEY_DIGEST``

      All three take a lower-case hex string.  ID_KEY_DIGEST and
      AUTHOR_KEY_DIGEST are all-zero unless the guest was launched with a
      signed ID block, which none of the TEE-Crafter Terraform paths do
      today — so "no pin" is the honest default rather than a silent one.

    Warned by default, fatal on request:
      * ``POLICY`` bit 16 (SMT).  An SMT-enabled guest shares physical
        cores with sibling threads and is exposed to cross-thread
        side-channel classes.  Every major cloud runs its SEV-SNP fleet
        with SMT enabled, so refusing by default would reject essentially
        every real deployment; set
        ``TEE_CRAFTER_SNP_REQUIRE_SMT_DISABLED=1`` to make it fatal.

    Deliberately not checked, because this client has nothing to compare
    them against: GUEST_SVN (printed by the caller), CURRENT_TCB, REPORT_ID
    and the POLICY ABI major/minor fields.  Enforcing any of them needs an
    operator-supplied baseline that does not exist today; they are left in
    the parsed dict for callers that have one.
    """
    passed = True

    launch = report_info.get("launch_tcb", 0)
    reported = report_info.get("reported_tcb", 0)
    if launch > reported:
        print(f"  FATAL: LAUNCH_TCB (0x{launch:016X}) > REPORTED_TCB "
              f"(0x{reported:016X}) — TCB anti-rollback violation.", file=sys.stderr)
        passed = False
    else:
        print(f"  LAUNCH_TCB <= REPORTED_TCB: PASSED "
              f"(0x{launch:016X} <= 0x{reported:016X})", file=sys.stderr)

    for env_name, field, label in (
        ("TEE_CRAFTER_SNP_EXPECTED_HOST_DATA", "host_data", "HOST_DATA"),
        ("TEE_CRAFTER_SNP_EXPECTED_ID_KEY_DIGEST", "id_key_digest", "ID_KEY_DIGEST"),
        ("TEE_CRAFTER_SNP_EXPECTED_AUTHOR_KEY_DIGEST", "author_key_digest",
         "AUTHOR_KEY_DIGEST"),
    ):
        expected = (os.environ.get(env_name) or "").strip().lower()
        actual = (report_info.get(field) or "").lower()
        if not expected:
            print(f"  {label}: not pinned ({env_name} unset); "
                  f"observed {actual[:16]}...", file=sys.stderr)
            continue
        if expected != actual:
            print(f"  FATAL: {label} mismatch — expected {expected[:16]}..., "
                  f"got {actual[:16]}...", file=sys.stderr)
            passed = False
        else:
            print(f"  {label} pin: PASSED", file=sys.stderr)

    if report_info.get("policy_smt"):
        # Any recognised truthy spelling enables the fatal check.  An exact
        # ``== "1"`` test meant an operator writing ``=true`` to harden the
        # deployment silently got warn-only instead.
        if os.environ.get("TEE_CRAFTER_SNP_REQUIRE_SMT_DISABLED", "0"
                          ).strip().lower() in ("1", "true", "yes", "y", "on"):
            print("  FATAL: guest policy permits SMT (POLICY bit 16) and "
                  "TEE_CRAFTER_SNP_REQUIRE_SMT_DISABLED=1.", file=sys.stderr)
            passed = False
        else:
            print("  WARNING: guest policy permits SMT (POLICY bit 16). The "
                  "guest may share physical cores with sibling threads, which "
                  "exposes it to cross-thread side-channel classes. Set "
                  "TEE_CRAFTER_SNP_REQUIRE_SMT_DISABLED=1 to refuse.",
                  file=sys.stderr)
    else:
        print("  Policy SMT disabled: PASSED", file=sys.stderr)

    return passed


def _snp_firmware_svn_from_reported_tcb(reported_tcb: int) -> int:
    """SNP firmware SVN from REPORTED_TCB bits 55:48 (Milan/Genoa/Bergamo class; ABI 56860)."""
    return (reported_tcb >> 48) & 0xFF


def verify_plat_info_amd_sb_3015(report_info: dict) -> bool:
    """Require PLATFORM_INFO bit 5 (ALIAS_CHECK_COMPLETE) per AMD-SB-3015 / ABI 56860."""
    plat = report_info.get("plat_info", 0)
    if not (plat & _PLATFORM_INFO_ALIAS_CHECK_COMPLETE):
        print("  FATAL: PLATFORM_INFO ALIAS_CHECK_COMPLETE (bit 5) is clear — "
              "AMD-SB-3015 (CVE-2024-21944) mitigation not confirmed. Update host firmware.",
              file=sys.stderr)
        return False
    print("  PLATFORM_INFO ALIAS_CHECK_COMPLETE (AMD-SB-3015): PASSED", file=sys.stderr)
    return True


def _min_snp_firmware_svn(cpu_family) -> int:
    """AMD-SB-3015 SNP firmware SVN floor for the attested processor family."""
    return _MIN_SNP_FIRMWARE_SVN_BY_FAMILY.get(
        (cpu_family or "").lower(), _MIN_SNP_FIRMWARE_SVN
    )


def verify_tcb_version(report_info: dict, cpu_family=None) -> bool:
    """Verify REPORTED_TCB SNP firmware SVN meets the AMD-SB-3015 minimum for the
    attested processor family (ABI 56860 bits 55:48).

    ``cpu_family`` is "Milan"/"Genoa" as established by the AMD root chain that
    validated the VCEK, or None when the chain did not name a family — in which
    case the strictest floor applies.
    """
    reported = report_info.get("reported_tcb", 0)
    snp_svn = _snp_firmware_svn_from_reported_tcb(reported)
    floor = _min_snp_firmware_svn(cpu_family)
    family_label = cpu_family or "unidentified"
    if snp_svn < floor:
        print(f"  FATAL: SNP firmware SVN in REPORTED_TCB is 0x{snp_svn:02X} "
              f"(bits 55:48); minimum 0x{floor:02X} per AMD-SB-3015 for "
              f"{family_label}-class hosts.",
              file=sys.stderr)
        return False
    print(f"  TCB / SNP firmware SVN check: PASSED (REPORTED_TCB=0x{reported:016X}, "
          f"SNP SVN bits 55:48 = 0x{snp_svn:02X} ≥ 0x{floor:02X} for {family_label}-class)",
          file=sys.stderr)
    return True


def verify_tpm_quote(tpm_evidence: tuple | None, expected_nonce: bytes) -> bool:
    """Verify the TPM2 Quote signature and qualifying nonce.

    tpm_evidence = (quote_msg, quote_sig_blob, ak_pub_pem)
    expected_nonce = SHA256(ECDH_pubkey [+ container_digest]) from the server TPM Quote
    (must match the client's ECDH + optional digest binding input).

    Returns True if the quote is valid and the nonce matches.
    """
    if tpm_evidence is None:
        print("  TPM Quote binding: FAILED (no TPM evidence in certificate)", file=sys.stderr)
        return False

    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature

    quote_msg, quote_sig_blob, ak_pub_pem = tpm_evidence

    # --- Parse TPMS_ATTEST to extract qualifying nonce ---
    # Layout (big-endian / TPM wire format):
    #   u32  magic          (0xFF544347 = TPM_GENERATED_VALUE)
    #   u16  type           (0x8018 = TPM_ST_ATTEST_QUOTE)
    #   TPM2B_NAME qualifiedSigner  (u16 size + data)
    #   TPM2B_DATA extraData        (u16 size + data)  ← our nonce
    if len(quote_msg) < 8:
        print("  TPM Quote: message too short", file=sys.stderr)
        return False

    magic = struct.unpack_from(">I", quote_msg, 0)[0]
    if magic != 0xFF544347:
        print(f"  TPM Quote: bad magic 0x{magic:08X}", file=sys.stderr)
        return False

    attest_type = struct.unpack_from(">H", quote_msg, 4)[0]
    if attest_type != 0x8018:
        print(f"  TPM Quote: unexpected type 0x{attest_type:04X}", file=sys.stderr)
        return False

    off = 6
    signer_size = struct.unpack_from(">H", quote_msg, off)[0]; off += 2 + signer_size
    nonce_size = struct.unpack_from(">H", quote_msg, off)[0]; off += 2
    actual_nonce = quote_msg[off:off + nonce_size]

    if actual_nonce != expected_nonce:
        print(f"  TPM Quote: nonce MISMATCH (expected {expected_nonce.hex()[:16]}..., "
              f"got {actual_nonce.hex()[:16]}...)", file=sys.stderr)
        return False

    # --- Parse TPMT_SIGNATURE to get raw RSA signature ---
    # Layout: u16 algorithm, u16 hash_alg, u16 sig_size, sig_data
    if len(quote_sig_blob) < 6:
        print("  TPM Quote: signature blob too short", file=sys.stderr)
        return False

    sig_size = struct.unpack_from(">H", quote_sig_blob, 4)[0]
    raw_sig = quote_sig_blob[6:6 + sig_size]

    # --- Verify signature using AK public key ---
    try:
        ak_key = _ser.load_pem_public_key(ak_pub_pem, default_backend())
    except Exception as e:
        print(f"  TPM Quote: failed to load AK public key: {e}", file=sys.stderr)
        return False

    try:
        ak_key.verify(
            raw_sig,
            quote_msg,
            padding.PKCS1v15(),
            _hashes.SHA256(),
        )
    except InvalidSignature:
        print("  TPM Quote: SIGNATURE INVALID", file=sys.stderr)
        return False

    print("  TPM Quote binding: PASSED (nonce matches SHA256(ECDH_pubkey [+ digest]), "
          "signature valid)", file=sys.stderr)
    return True


def _spki_sha256_from_der(cert_der: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    return _spki_sha256_of_cert(
        x509.load_der_x509_certificate(cert_der, default_backend())
    )


def _spki_der_from_cert_der(cert_der: bytes) -> bytes:
    """The peer certificate's SubjectPublicKeyInfo, DER-encoded."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    return cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_live_challenge(att_resp: dict, nonce_ascii: bytes, cert_der: bytes,
                          endorsement_pem: bytes, expected_measurement: str) -> tuple:
    """M-02: verify a freshly generated, channel-bound SNP report.

    Checks that the report the server signed in reply to *our* challenge
    satisfies ``report_data[:32] == _attest_binding_digest(nonce_ascii,
    peer_tls_spki_der, chain_key_commitment_hex_ascii)``, which supplies
    freshness (a replayed report cannot match a nonce it never saw), TLS
    channel binding (a relay would need the genuine VM to sign over the
    relay's own SPKI, which it never does) and AUD-3 audit-log anchoring
    (AMD signs the commitment to the in-TEE audit log's HMAC chain key, so a
    wholesale log replacement no longer verifies).

    Azure caveat: this can only succeed when the server obtained its report
    through ``/dev/sev-guest``.  On the vTPM HCL path REPORT_DATA is fixed by
    the Hyper-V HCL and no guest-supplied challenge appears in it, so the
    caller treats a failure as fatal only when the strong report_data binding
    mode was established — see ``main()``.

    Returns ``(ok: bool, reason: str)``.
    """
    report_hex = (att_resp or {}).get("report_hex") or ""
    if not report_hex:
        return False, "server returned no 'report_hex' in the attestation response"
    try:
        live_report = bytes.fromhex(report_hex)
    except ValueError:
        return False, "'report_hex' is not valid hex"

    if not verify_snp_report_signature(live_report, endorsement_pem):
        return False, "ECDSA signature over the live report failed against the VCEK/VLEK"

    live_info = parse_snp_report(live_report)

    try:
        spki_der = _spki_der_from_cert_der(cert_der)
    except Exception as exc:
        return False, f"could not read the peer certificate SPKI: {type(exc).__name__}"

    # AUD-3: the third preimage field is the server's audit-log chain-key
    # commitment.  Resolving it here (rather than in main) keeps the
    # fail-closed policy in one testable place.
    commitment_ascii, commitment_error = resolve_chain_key_commitment(
        (att_resp or {}).get("chain_key_commitment", ""))
    if commitment_error:
        return False, commitment_error

    expected_binding = _attest_binding_digest(
        nonce_ascii, spki_der, commitment_ascii)
    if live_info["report_data"][:32] != expected_binding:
        return False, (
            "report_data does not equal the v2 attestation binding digest over "
            "(nonce, TLS SPKI, chain_key_commitment) — the report is stale, was "
            "produced for a different TLS channel, does not commit to the "
            "audit-log chain key the server declared, or was minted by the "
            "Azure vTPM HCL (which fixes REPORT_DATA)"
        )

    if expected_measurement and live_info.get("measurement") != expected_measurement:
        return False, (
            "the live report's measurement differs from the certificate-embedded "
            f"report ({live_info.get('measurement')} != {expected_measurement})"
        )

    # Machine-readable echo of the commitment *after* it has been shown to
    # match the hardware-signed report_data.  The deploy scrapes this exact
    # `key: value` shape into the provenance ledger
    # (cli/deployment/common/attestation_report.py, _HEX_FIELDS_RE), which is
    # what `verify-siem-chain --expect-chain-commitment` pins exported events
    # against.  Without it the ledger recorded nothing and that check silently
    # degraded to "internal consistency only" -- the value was attested and
    # then dropped between the client and the ledger.
    #
    # Emitted here rather than in the ATTESTATION_REPORT JSON because on these
    # platforms that JSON is assembled before this verification runs, so
    # putting it there would record a claim the hardware had not yet been
    # shown to sign.  Empty means TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1 --
    # nothing was anchored, so nothing is recorded.
    if commitment_ascii:
        print(f"chain_key_commitment: {commitment_ascii.decode('ascii')}",
              file=sys.stderr)
    return True, ""


def verify_ratls_connection(host: str, port: int, ratls_nonce: bytes | None = None) -> tuple:
    """Connect over TLS, extract and verify the SNP attestation report.

    ``ratls_nonce`` is *not* consumed here.  The certificate-embedded report
    binds report_data = SHA-256(ECDH pubkey [|| container_digest] ||
    sha256(ak_pub)) — key material, **not** the TLS SubjectPublicKeyInfo and
    not a per-connection challenge — so it cannot echo anything this
    connection supplies.  ``main()`` sends this nonce to the VM afterwards
    and checks the report signed in reply via ``verify_live_challenge``.  The
    value is also round-tripped into ``ATTESTATION_REPORT`` for audit
    correlation.
    """
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
        print("FATAL: No server certificate. Aborting.", file=sys.stderr)
        sys.exit(1)

    try:
        (report_bytes, endorsement_pem, tpm_evidence,
         hcl_runtime_data) = extract_snp_evidence_from_cert(cert_der)
    except ValueError as e:
        conn.close()
        print(f"FATAL: {e}. Aborting.", file=sys.stderr)
        sys.exit(1)

    report_info = parse_snp_report(report_bytes)
    report_info["_tpm_evidence"] = tpm_evidence
    report_info["_hcl_runtime_data"] = hcl_runtime_data

    print(f"  Report version:     {report_info['version']}", file=sys.stderr)
    print(f"  Guest SVN:          {report_info['guest_svn']}", file=sys.stderr)
    print(f"  Policy:             0x{report_info['policy']:016X}", file=sys.stderr)
    print(f"  VMPL:               {report_info['vmpl']}", file=sys.stderr)
    print(f"  Measurement:        {report_info['measurement']}", file=sys.stderr)
    print(f"  Chip ID:            {report_info['chip_id'][:32]}...", file=sys.stderr)
    print(f"  Reported TCB:       0x{report_info['reported_tcb']:016X}", file=sys.stderr)
    print(f"  PLATFORM_INFO:     0x{report_info['plat_info']:016X}", file=sys.stderr)

    if not endorsement_pem:
        conn.close()
        print("FATAL: No endorsement certificate in RA-TLS certificate — cannot verify report signature "
              "or AMD hardware root of trust.", file=sys.stderr)
        sys.exit(1)

    # 1. Validate sig_algo == 1 (ECDSA P-384 with SHA-384; AMD SEV-SNP ABI §7.3)
    if report_info.get("sig_algo") != 1:
        conn.close()
        print(f"FATAL: Unexpected sig_algo={report_info.get('sig_algo')} "
              "(expected 1 = ECDSA P-384 + SHA-384).", file=sys.stderr)
        sys.exit(1)
    print("  sig_algo: 1 (ECDSA P-384 + SHA-384)", file=sys.stderr)

    # 2. Verify ECDSA-384 signature
    print("Verifying SNP report ECDSA signature...", file=sys.stderr)
    if not verify_snp_report_signature(report_bytes, endorsement_pem):
        conn.close()
        print("FATAL: SNP report signature FAILED.", file=sys.stderr)
        sys.exit(1)
    print("  SNP report signature: PASSED", file=sys.stderr)

    # 3. Verify endorsement cert chain (VCEK -> ASK -> ARK).  The label of the
    #    chain that validated is the processor family (see step 7).
    print("Verifying AMD endorsement certificate chain...", file=sys.stderr)
    chain_label = verify_endorsement_cert_chain(endorsement_pem)
    if not chain_label:
        conn.close()
        print("FATAL: AMD endorsement certificate chain verification FAILED. "
              "The VCEK does not chain to a trusted AMD root.", file=sys.stderr)
        sys.exit(1)

    # 4. Verify launch measurement.  Without a pinned measurement the chain
    #    above proves only "some genuine SEV-SNP guest" — not which workload
    #    is running inside it — so an unpinned client fails closed.
    allow = _measurement_allowlist()
    if allow:
        if not _measurement_allowed(report_info["measurement"]):
            conn.close()
            print(f"FATAL: Measurement mismatch! Got {report_info['measurement']}, "
                  f"not in pinned allowlist ({len(allow)} variant(s)).", file=sys.stderr)
            sys.exit(1)
        print(f"  Measurement: PASSED ({len(allow)} pinned variant(s))", file=sys.stderr)
    elif os.environ.get("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT") == "1":
        print("  WARNING: no launch measurement is pinned into this client and "
              "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 is set. This connection is "
              "NOT verifying workload identity — any code running in any genuine "
              "SEV-SNP guest will be accepted. Development use only.", file=sys.stderr)
        print(f"  Unverified measurement: {report_info['measurement']}", file=sys.stderr)
    else:
        conn.close()
        print("FATAL: No launch measurement is pinned into this client, so the "
              "workload running inside the CVM cannot be identified. Rebuild the "
              "client with the expected measurement, or set "
              "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 to accept any measurement "
              "(development only).", file=sys.stderr)
        sys.exit(1)

    # 5. Verify guest policy
    print("Verifying guest policy...", file=sys.stderr)
    if not verify_guest_policy(report_info):
        conn.close()
        print("FATAL: Guest policy verification failed.", file=sys.stderr)
        sys.exit(1)

    # 6. AMD-SB-3015: PLATFORM_INFO.ALIAS_CHECK_COMPLETE (ABI 56860 bit 5)
    print("Verifying PLATFORM_INFO (AMD-SB-3015)...", file=sys.stderr)
    if not verify_plat_info_amd_sb_3015(report_info):
        conn.close()
        print("FATAL: PLATFORM_INFO verification failed.", file=sys.stderr)
        sys.exit(1)

    # 7. REPORTED_TCB SNP firmware SVN (bits 55:48; AMD-SB-3015 minima).  The
    #    legacy "default" chain carries no family signal, so only the two
    #    family-specific labels select a family-specific floor.
    cpu_family = chain_label if chain_label in ("Milan", "Genoa") else None
    print("Verifying TCB / SNP firmware SVN...", file=sys.stderr)
    if not verify_tcb_version(report_info, cpu_family):
        conn.close()
        print("FATAL: SNP firmware SVN / TCB below minimum.", file=sys.stderr)
        sys.exit(1)

    # 8. COMMITTED_TCB <= REPORTED_TCB anti-rollback (AMD SEV-SNP ABI §4.4)
    committed = report_info.get("committed_tcb", 0)
    reported = report_info.get("reported_tcb", 0)
    if committed > reported:
        conn.close()
        print(f"FATAL: COMMITTED_TCB (0x{committed:016X}) > REPORTED_TCB (0x{reported:016X}) — "
              "TCB anti-rollback violation.", file=sys.stderr)
        sys.exit(1)
    print(f"  COMMITTED_TCB <= REPORTED_TCB: PASSED "
          f"(0x{committed:016X} <= 0x{reported:016X})", file=sys.stderr)

    # Report fields that used to be parsed and then dropped: LAUNCH_TCB,
    # HOST_DATA, ID_KEY_DIGEST, AUTHOR_KEY_DIGEST and POLICY.SMT.
    print("Verifying remaining report fields...", file=sys.stderr)
    if not verify_parsed_report_fields(report_info):
        conn.close()
        print("FATAL: SNP report field verification failed.", file=sys.stderr)
        sys.exit(1)

    # 9. Container image digest binding
    server_cd = extract_container_digest_from_cert(cert_der)
    if server_cd:
        print(f"  Container digest: {server_cd}", file=sys.stderr)
        if EXPECTED_CONTAINER_DIGEST and EXPECTED_CONTAINER_DIGEST != "":
            if server_cd != EXPECTED_CONTAINER_DIGEST:
                conn.close()
                print(f"FATAL: Container digest mismatch! got={server_cd} expected={EXPECTED_CONTAINER_DIGEST}", file=sys.stderr)
                sys.exit(1)
            print("  Container binding: PASSED", file=sys.stderr)

    # AUD-7 / ATT-006 / ATT-007: structured ATTESTATION_REPORT line.
    try:
        spki = _spki_sha256_from_der(cert_der)
    except Exception:
        spki = ""
    try:
        attestation_report = {
            "platform": "snp-azure",
            "issuer": "amd-sev-snp",
            "report_kind": "amd_sev_snp_v2",
            "quote_signature_alg": "ECDSA_P384_SHA384",
            "measurement": report_info.get("measurement", ""),
            "tcb_svn": f"0x{report_info.get('reported_tcb', 0):016X}",
            "vcek_chip_id": report_info.get("chip_id", ""),
            "nonce_binding": report_info.get("report_data_hex", ""),
            "nonce": (ratls_nonce or b"").hex(),
            "spki_sha256": spki,
            "container_digest": server_cd or "",
        }
        print(f"ATTESTATION_REPORT {json.dumps(attestation_report, separators=(',', ':'))}")
    except Exception:
        pass

    # Carried out so main() can verify the live challenge report against the
    # same AMD-rooted endorsement key that was validated above.
    report_info["_endorsement_pem"] = endorsement_pem
    report_info["_peer_cert_der"] = cert_der

    return conn, report_info


def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def send_request(conn: ssl.SSLSocket, payload: dict) -> dict:
    """Send a JSON request and receive the response."""
    _MAX_RESPONSE_SIZE = 64 * 1024 * 1024
    data = json.dumps(payload).encode("utf-8")
    conn.sendall(struct.pack("!I", len(data)))
    conn.sendall(data)

    hdr = _recv_exactly(conn, 4)
    resp_len = struct.unpack("!I", hdr)[0]
    if resp_len > _MAX_RESPONSE_SIZE:
        raise ValueError(f"Response size {resp_len} exceeds maximum {_MAX_RESPONSE_SIZE}")
    response = _recv_exactly(conn, resp_len)
    return json.loads(response.decode("utf-8"))


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 client_snp_azure.py <host_ip> [port]", file=sys.stderr)
        sys.exit(1)

    host_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5005

    ratls_nonce = os.urandom(32)
    print(f"Connecting to SNP Azure VM at {host_ip}:{port} via RA-TLS...", file=sys.stderr)
    try:
        conn, report_info = verify_ratls_connection(host_ip, port, ratls_nonce=ratls_nonce)
        print("AMD SEV-SNP RA-TLS Attestation Verification Passed! (Azure)", file=sys.stderr)
    except Exception as e:
        print(f"Failed to establish RA-TLS connection: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)

    report_data_bytes = report_info["report_data"]

    # Measurement is enforced inside verify_ratls_connection(); a client with
    # no pinned measurement only reaches this point via the explicit
    # TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 opt-out.
    attested_measurement = report_info.get("measurement", "")
    allow = _measurement_allowlist()
    if allow and not _measurement_allowed(attested_measurement):
        print(f"FATAL: Measurement mismatch: {attested_measurement} not in pinned allowlist", file=sys.stderr)
        sys.exit(1)

    print("Requesting VM public key...", file=sys.stderr)
    # M-02: send the client nonce generated above (previously a second,
    # discarded random value) so the report the VM signs in reply is bound to
    # this run and to this TLS channel.
    nonce_ascii = base64.b64encode(ratls_nonce)
    try:
        att_resp = send_request(conn, {"action": "get_attestation",
                                       "nonce": nonce_ascii.decode()})
        enclave_pub_b64 = att_resp.get("enclave_public_key")
        if not enclave_pub_b64:
            print("FATAL: VM did not provide its public key.", file=sys.stderr)
            sys.exit(1)
        enclave_pub_bytes = base64.b64decode(enclave_pub_b64)
    except Exception as e:
        print(f"Failed to get VM public key: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # SNP-3: the Azure SNP template binds SHA256(ak_pub) into the SNP
    # report user_data alongside the ECDH pubkey and optional container
    # digest.  Clients verify this enriched binding first; the legacy
    # binding (no ak hash) is still accepted for backwards compatibility
    # with older images, but is logged as WEAK.
    tpm_evidence = report_info.get("_tpm_evidence")
    ak_pub_hash_bytes = b""
    if tpm_evidence is not None:
        try:
            _, _, _ak_pub_pem = tpm_evidence
            ak_pub_hash_bytes = hashlib.sha256(_ak_pub_pem).digest()
        except Exception:
            ak_pub_hash_bytes = b""

    base_binding = enclave_pub_bytes
    if EXPECTED_CONTAINER_DIGEST:
        base_binding = enclave_pub_bytes + EXPECTED_CONTAINER_DIGEST.encode()
    # Candidate bindings in order of strength:
    #   1. ECDH || [container_digest] || sha256(ak_pub)  — SNP-3 enriched
    #   2. ECDH || [container_digest]                    — legacy
    strong_binding = base_binding + ak_pub_hash_bytes if ak_pub_hash_bytes else None
    legacy_binding = base_binding

    strong_hash = hashlib.sha256(strong_binding).digest() if strong_binding else None
    legacy_hash = hashlib.sha256(legacy_binding).digest()

    binding_mode = None
    pub_key_hash = None

    if strong_hash and report_data_bytes[:32] == strong_hash:
        print("  Public key binding: PASSED (report_data matches ECDH pubkey || ak_pub_hash, SNP-3)",
              file=sys.stderr)
        binding_mode = "report_data_strong"
        pub_key_hash = strong_hash
    elif report_data_bytes[:32] == legacy_hash:
        print("  Public key binding: PASSED (report_data matches ECDH pubkey; legacy — AK not bound)",
              file=sys.stderr)
        binding_mode = "report_data_legacy"
        pub_key_hash = legacy_hash
    else:
        for candidate, label in (
            (strong_hash, "strong"),
            (legacy_hash, "legacy"),
        ):
            if candidate is None:
                continue
            if verify_tpm_quote(tpm_evidence, candidate):
                print(f"  Public key binding: PASSED via TPM Quote ({label})",
                      file=sys.stderr)
                binding_mode = f"tpm_quote_{label}"
                pub_key_hash = candidate
                break
        if binding_mode is None:
            print("FATAL: Public key binding failed — neither report_data nor TPM Quote "
                  "could verify the ECDH public key. Aborting.", file=sys.stderr)
            sys.exit(1)

    # Upgrade a TPM-quote binding to an AMD-rooted one when the HCL runtime data
    # proves the AK is the one the SNP report commits to.
    #
    # Why this exists: on Azure the Hyper-V HCL fixes REPORT_DATA, so
    # `report_data_strong` is unreachable -- there is no /dev/sev-guest on any
    # Azure SEV-SNP SKU (verified on a live Standard_DC2as_v5, 2026-08-23).  The
    # quote alone is not a substitute, because an attacker replaying a captured
    # SNP report can mint their own AK and sign a quote committing to their own
    # key hash.  What closes that is the runtime data: AMD signs REPORT_DATA,
    # REPORT_DATA is sha256 of the runtime-data JSON, and that JSON names the
    # AK.  See verify_hcl_ak_binding.
    if binding_mode in ("tpm_quote_strong", "tpm_quote_legacy"):
        _rt = report_info.get("_hcl_runtime_data") or b""
        _ak = b""
        if tpm_evidence is not None:
            try:
                _, _, _ak = tpm_evidence
            except Exception:
                _ak = b""
        if verify_hcl_ak_binding(report_data_bytes, _rt, _ak):
            print("  AK->SNP binding: PASSED (AK is named in the HCL runtime "
                  "data that AMD-signed REPORT_DATA commits to)",
                  file=sys.stderr)
            binding_mode = "hcl_runtime_data_strong"
        elif _rt:
            print("  WARNING: HCL runtime data was present but did not bind the "
                  "AK to REPORT_DATA; treating the AK as unattested.",
                  file=sys.stderr)

    # SNP-3: fail closed if only the legacy binding succeeded on an HCL
    # (vTPM) path AND the caller demands strict AK binding.  On the HCL
    # path REPORT_DATA is fixed by the Azure HCL and cannot include the
    # AK hash; operators wanting the strictest posture must deploy on
    # instances where /dev/sev-guest is directly available.
    #
    # Production default: strict ON ("1").  All DCxxads_v5 / ECxxads_v5
    # confidential VM SKUs expose /dev/sev-guest natively and therefore
    # satisfy the strong "report_data_strong" binding.  Setting this to
    # "0" silently downgrades the trust boundary on HCL-only SKUs and is
    # intended only for legacy lab environments — never for prod.
    # Only a recognised falsy spelling disables this.  An exact ``== "1"`` test
    # used to mean that writing ``=true`` -- which reads as *more* strict --
    # silently turned the check off and then reported itself as ``=0``.
    if os.environ.get("TEE_CRAFTER_STRICT_SNP_AK_BINDING", "1").strip().lower(
    ) not in ("0", "false", "no", "n", "off"):
        # `hcl_runtime_data_strong` is accepted alongside `report_data_strong`
        # because both root the AK in AMD's signature; they differ only in
        # whether the AK hash sits directly in REPORT_DATA (bare-metal SNP) or
        # in the JSON that REPORT_DATA is the digest of (Azure's HCL).  Without
        # this the gate was unsatisfiable on every Azure SEV-SNP SKU and its
        # advice -- "redeploy on an instance exposing /dev/sev-guest" -- named
        # something that does not exist there.
        if binding_mode not in ("report_data_strong",
                                "hcl_runtime_data_strong"):
            print(
                "FATAL: TEE_CRAFTER_STRICT_SNP_AK_BINDING=1 but strong AK->SNP "
                "binding was not established. The server may be on a vTPM HCL "
                "path where REPORT_DATA cannot carry sha256(ak_pub); redeploy "
                "on an instance exposing /dev/sev-guest.",
                file=sys.stderr,
            )
            sys.exit(1)
    elif binding_mode in ("report_data_legacy", "tpm_quote_legacy"):
        print(
            "  WARNING: TPM AK is not cryptographically bound to the AMD-signed "
            "SNP report (legacy binding mode). An attacker who captures a real "
            "SNP report from another CVM could in principle pair it with a "
            "quote from a foreign TPM. Set TEE_CRAFTER_STRICT_SNP_AK_BINDING=1 "
            "to fail closed on such deployments.",
            file=sys.stderr,
        )

    # M-02: freshness + TLS channel binding.  The certificate-embedded report
    # is minted once per rotation and binds key material, not this connection,
    # so on its own it is replayable for the life of the certificate.  The
    # live challenge below closes that — but only on the /dev/sev-guest path,
    # which is exactly the path that produces binding_mode ==
    # "report_data_strong".  When the server is on the vTPM HCL path the
    # Hyper-V HCL fixes REPORT_DATA, no guest challenge can appear in it, and
    # we say so instead of claiming a property we did not verify.
    print("Verifying live attestation challenge (freshness + channel binding)...",
          file=sys.stderr)
    live_ok, live_reason = verify_live_challenge(
        att_resp,
        nonce_ascii,
        report_info.get("_peer_cert_der", b""),
        report_info.get("_endorsement_pem", b""),
        report_info.get("measurement", ""),
    )
    if live_ok:
        print("  Live challenge: PASSED (report_data == v2 binding digest over "
              "(nonce, TLS SPKI, chain_key_commitment), AMD-signed, same "
              "measurement as the certificate-embedded report)", file=sys.stderr)
        # AUD-3: only reachable on the /dev/sev-guest path, where REPORT_DATA
        # is guest-controlled, so the commitment really is AMD-signed here.
        _attested_commitment = (att_resp.get("chain_key_commitment") or "").strip().lower()
        if _attested_commitment:
            print("  Audit-log chain-key commitment (AMD-signed): "
                  f"{_attested_commitment}", file=sys.stderr)
        else:
            print("  Audit-log chain-key commitment: NONE (accepted via "
                  "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1)", file=sys.stderr)
    elif binding_mode == "report_data_strong":
        print(f"FATAL: live attestation challenge failed on a guest-controlled "
              f"REPORT_DATA path: {live_reason}", file=sys.stderr)
        sys.exit(1)
    else:
        print("  Live challenge: NOT ESTABLISHED — the server's REPORT_DATA is "
              f"not guest-controlled (binding_mode={binding_mode}). Reason: "
              f"{live_reason}", file=sys.stderr)
        print("  This connection therefore has NO per-connection freshness and "
              "NO TLS channel binding: the AMD-signed evidence proves the CVM, "
              "not that the CVM is the peer on this socket. Deploy on a SKU "
              "exposing /dev/sev-guest to obtain both.", file=sys.stderr)
        # AUD-3.  The Hyper-V HCL mints the report at boot from NV index
        # 0x01400001 and the guest supplies no runtime data, so there is no
        # field in it that could carry the audit-log chain-key commitment.
        # Say so rather than printing a value we did not see AMD sign.
        print("  Audit-log chain-key commitment: NOT ESTABLISHED — REPORT_DATA "
              "is not guest-influenceable on this path, so the commitment the "
              "server publishes "
              f"({(att_resp.get('chain_key_commitment') or '(none)')[:16]}...) "
              "is SELF-REPORTED and unanchored. An exported audit log from this "
              "VM cannot be tied back to AMD-signed evidence.", file=sys.stderr)

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
