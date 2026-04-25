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

# AMD Root of Trust certificate chain(s) for VLEK/VCEK verification.
# The build injects either a single processor-family chain (ARK->ASK for
# Milan or Genoa) or both chains to enable SNP-2 style auto-selection by
# CHIP_ID / signature.  Missing chains are rendered as an empty string.
# NB: placeholder tokens like %%amd_root_ca%% must never appear in comments,
# because the template renderer performs a global textual replace and a
# multi-line PEM would otherwise bleed into non-comment lines.
_AMD_ROOT_CA_PEM = """{amd_root_ca}"""
_AMD_ROOT_CA_MILAN_PEM = """{amd_root_ca_milan}"""
# VCEK-signing chain for Milan: [SEV-Milan (ASK), ARK-Milan].  The bundle
# above carries the VLEK intermediate (SEV-VLEK-Milan), which is what AWS
# returns; a Milan host that returns a VCEK -- GCP does -- has no issuer in
# it, so chain verification could only fail.  Same ARK in both, so this
# widens what verifies without changing the pinned root.
_AMD_ASK_CA_MILAN_PEM = """{amd_ask_ca_milan}"""
_AMD_ROOT_CA_GENOA_PEM = """{amd_root_ca_genoa}"""

# OID used in the RA-TLS certificate to embed the SNP attestation report
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


# Attestation report field offsets (AMD SEV-SNP ABI spec)
_OFF_VERSION = 0x00
_OFF_GUEST_SVN = 0x04
_OFF_POLICY = 0x08
_OFF_FAMILY_ID = 0x10
_OFF_IMAGE_ID = 0x20
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
_OFF_REPORT_ID_MA = 0x160
_OFF_REPORTED_TCB = 0x180
_OFF_CHIP_ID = 0x1A0
_OFF_COMMITTED_TCB = 0x1E0
_OFF_LAUNCH_TCB = 0x1F0
_OFF_SIGNATURE = 0x2A0
_SNP_REPORT_SIZE = 1184
_SNP_SIGNED_DATA_SIZE = 0x2A0  # signature starts here; everything before is signed


def extract_snp_evidence_from_cert(cert_der: bytes) -> tuple:
    """
    Extract the SNP attestation report and endorsement cert from a TLS
    certificate's X.509 extension.

    Returns (report_bytes, endorsement_cert_pem).
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
            return report, endorsement_cert

    raise ValueError("TLS certificate does not contain an SNP attestation extension")


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
    """
    Parse key fields from an AMD SEV-SNP attestation report.

    Report layout (1184 bytes total):
      0x000: version (u32)
      0x004: guest_svn (u32)
      0x008: policy (u64 — GuestPolicy)
      0x010: family_id (16 bytes)
      0x020: image_id (16 bytes)
      0x030: vmpl (u32)
      0x034: sig_algo (u32)
      0x038: current_tcb (u64)
      0x040: plat_info (u64)
      0x050: report_data (64 bytes)
      0x090: measurement (48 bytes — SHA-384 launch digest)
      0x0C0: host_data (32 bytes)
      0x0E0: id_key_digest (48 bytes)
      0x110: author_key_digest (48 bytes)
      0x140: report_id (32 bytes)
      0x160: report_id_ma (32 bytes)
      0x180: reported_tcb (u64)
      0x1A0: chip_id (64 bytes)
      0x1E0: committed_tcb (u64)
      0x1F0: launch_tcb (u64)
      0x2A0: signature (512 bytes — ECDSA-384 r || s)
    """
    if len(report) < _SNP_REPORT_SIZE:
        raise ValueError(f"SNP report too short: {len(report)} bytes (need {_SNP_REPORT_SIZE})")

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

    # Parse guest policy bits
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
    """
    Verify the ECDSA-384 signature on the SNP attestation report using the
    endorsement key (VLEK on AWS, VCEK on Azure).

    The signature covers bytes [0, 0x2A0) of the report.
    AMD SEV-SNP ABI: ECDSA_SIG = { r[72], s[72], reserved[368] } = 512 bytes.
    P-384 values occupy the first 48 bytes of each 72-byte field, little-endian.
    """
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

    # AMD SEV-SNP ABI: ECDSA_SIG struct has r[72] then s[72].
    # P-384 values are in the first 48 bytes of each field, little-endian.
    r_bytes = report[_OFF_SIGNATURE:_OFF_SIGNATURE + 48]
    s_bytes = report[_OFF_SIGNATURE + 72:_OFF_SIGNATURE + 72 + 48]

    r = int.from_bytes(r_bytes, "little")
    s = int.from_bytes(s_bytes, "little")
    der_sig = utils.encode_dss_signature(r, s)

    try:
        pub_key.verify(der_sig, signed_data, ec_mod.ECDSA(hash_mod.SHA384()))
        return True
    except InvalidSignature:
        return False


def _parse_pem_chain(pem: bytes):
    """Parse a PEM bundle into a list of x509 certs ordered as in the file."""
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
        # AMD ARK/ASK/VLEK are RSA-4096 RSASSA-PSS with MGF1 and salt
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
    """Attempt ARK->ASK->VLEK/VCEK verification against a single chain.

    Returns True only if every link verifies, the chain's ARK is one of
    the baked-in AMD roots, and all certs are in-window.  Any failure
    returns False silently so the caller can try another chain —
    failures are not printed at this level.
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

    print(f"  AMD certificate chain verification: PASSED against {label}",
          file=sys.stderr)
    return True


def verify_endorsement_cert_chain(endorsement_pem: bytes):
    """
    Verify the endorsement certificate (VLEK/VCEK) chains to the AMD
    root of trust (ARK -> ASK -> VLEK/VCEK).

    SNP-2: the client may have been baked with a single legacy chain or
    with both Milan and Genoa chains.  We try every available chain and
    accept the endorsement if *any* one validates — this is the
    cryptographic equivalent of selecting by CHIP_ID without having to
    parse the CPUID-encoded chip family.  If no chain matches,
    verification fails closed.

    Returns the label of the chain that validated ("Milan", "Genoa" or
    "default"), or None if none did.  The label is the client's only
    trustworthy processor-family signal, because AMD issues VLEK/VCEK
    certificates under a family-specific ARK.
    """
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
            print("  AMD cert chain verification: FAILED (no AMD root CA PEM in client)",
                  file=sys.stderr)
            return None

        for label, chain_certs in candidates:
            if _try_verify_against_chain(endorsement_cert, chain_certs, label):
                return label

        print("  AMD cert chain verification: FAILED (endorsement not signed by any known ARK/ASK chain)",
              file=sys.stderr)
        return None

    except Exception as e:
        print(f"  AMD certificate chain verification failed: {e}", file=sys.stderr)
        return None


# --- TCB / platform security (AMD SEV-SNP Firmware ABI 56860; AMD-SB-3015) ---
# REPORTED_TCB (offset 0x180): for 3rd/4th Gen EPYC (Milan/Genoa/Bergamo class), the SNP
# firmware SVN is bits 55:48 (see 56860 TCB_VERSION / attestation doc).
# AMD-SB-3015 (CVE-2024-21944): minimum mitigated SPL, per processor family.  The report
# itself carries no trustworthy CPU-family field, so the family comes from which AMD root
# chain validated the endorsement cert (VLEK/VCEK are issued under a family-specific ARK).
_MIN_SNP_FIRMWARE_SVN_BY_FAMILY = {"milan": 0x17, "genoa": 0x16}
# Floor applied when the validating chain does not name a family (legacy single-chain
# builds).  Strictest known value — an unidentified family must not relax the check.
_MIN_SNP_FIRMWARE_SVN = max(_MIN_SNP_FIRMWARE_SVN_BY_FAMILY.values())

# PLATFORM_INFO (report offset 0x40): bit 5 = ALIAS_CHECK_COMPLETE (56860 + AMD-SB-3015).
_PLATFORM_INFO_ALIAS_CHECK_COMPLETE = 1 << 5


def verify_guest_policy(report_info: dict) -> bool:
    """
    Verify the guest policy flags in the SNP report meet security requirements.
    """
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
        print(f"  FATAL: VMPL is {report_info['vmpl']} (expected 0 for highest privilege)", file=sys.stderr)
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
    validated the endorsement certificate, or None when the chain did not name a
    family — in which case the strictest floor applies.
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


def _spki_sha256_from_der(cert_der: bytes) -> str:
    """SHA-256 of the leaf certificate's SubjectPublicKeyInfo (DER)."""
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

    The report embedded in the TLS certificate is generated once per
    certificate rotation and binds only the ECDH public key, so on its own
    it is replayable for the life of the certificate and says nothing about
    which TLS key is in use.  This checks the report the server produced in
    direct response to *our* challenge:

      report_data[:32] == _attest_binding_digest(
          nonce_ascii, peer_tls_spki_der, chain_key_commitment_hex_ascii)

    which gives three properties the certificate-embedded report does not:

      * freshness — an attacker replaying a captured report cannot make it
        match a nonce it never saw;
      * channel binding — a relaying man-in-the-middle would have to induce
        the genuine VM to sign over the *MITM's* SPKI, which it never does,
        because the VM hashes its own SPKI;
      * audit-log anchoring (AUD-3) — the AMD signature now covers the
        SHA-256 commitment to the in-TEE audit log's HMAC chain key, so a
        replaced log (fresh key, fresh genesis, fresh chain) no longer
        verifies against hardware-signed evidence.

    Returns ``(ok: bool, reason: str)``.  The caller treats ``False`` as fatal.
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
            "produced for a different TLS channel, or does not commit to the "
            "audit-log chain key the server declared "
            f"(got {live_info['report_data'][:32].hex()[:16]}..., expected "
            f"{expected_binding.hex()[:16]}...)"
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
    """
    Connect to the SNP VM via TLS. Extract the embedded AMD SEV-SNP
    attestation report from the certificate and verify it.

    ``ratls_nonce`` is *not* consumed here.  The certificate-embedded report
    binds report_data = SHA-256(ECDH pubkey [|| container_digest]) — the ECDH
    key, **not** the TLS SubjectPublicKeyInfo, and not a per-connection
    challenge — so it is minted at certificate-rotation time and cannot echo
    anything this connection supplies.  Freshness and TLS channel binding are
    established afterwards in ``main()`` by ``verify_live_challenge``, which
    sends this nonce to the VM and checks the report it signs in reply.  The
    value is also round-tripped into the ``ATTESTATION_REPORT`` line so the
    audit ledger can correlate this verifier run.
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
        print("FATAL: Server did not present a certificate. Aborting.", file=sys.stderr)
        sys.exit(1)

    try:
        report_bytes, endorsement_pem = extract_snp_evidence_from_cert(cert_der)
    except ValueError as e:
        conn.close()
        print(f"FATAL: {e}. RA-TLS attestation is required — aborting.", file=sys.stderr)
        sys.exit(1)

    report_info = parse_snp_report(report_bytes)

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
        print("FATAL: SNP report ECDSA signature verification FAILED.", file=sys.stderr)
        sys.exit(1)
    print("  SNP report signature: PASSED", file=sys.stderr)

    # 3. Verify endorsement cert chain (VLEK -> ASK -> ARK).  The label of the
    #    chain that validated is the processor family (see step 7).
    print("Verifying AMD endorsement certificate chain...", file=sys.stderr)
    chain_label = verify_endorsement_cert_chain(endorsement_pem)
    if not chain_label:
        conn.close()
        print("FATAL: AMD endorsement certificate chain verification FAILED. "
              "The VLEK/VCEK does not chain to a trusted AMD root.", file=sys.stderr)
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
        print(f"  Measurement verification: PASSED ({len(allow)} pinned variant(s))", file=sys.stderr)
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

    # AUD-7 / ATT-006 / ATT-007: emit a structured single-line
    # ``ATTESTATION_REPORT`` for the deploy orchestrator to record
    # into the build provenance chain.  The deploy phase's audit
    # step parses this exact prefix (see
    # cli/deployment/common/attestation_report.py).  Stdout because
    # stdout is what client_step.py captures and forwards to
    # audit.record_check().
    try:
        spki = _spki_sha256_from_der(cert_der)
    except Exception:
        spki = ""
    try:
        attestation_report = {
            "platform": "snp-aws",
            "issuer": "amd-sev-snp",
            "report_kind": "amd_sev_snp_v2",
            "quote_signature_alg": "ECDSA_P384_SHA384",
            "measurement": report_info.get("measurement", ""),
            "tcb_svn": f"0x{report_info.get('reported_tcb', 0):016X}",
            "tcb_chip_id": report_info.get("chip_id", "")[:64],
            "vlek_chip_id": report_info.get("chip_id", ""),
            # report_data of the certificate-embedded report.  This is
            # SHA-256(ECDH pubkey [|| container_digest]) — a key binding, not
            # a freshness binding, and not over the TLS SPKI.  Freshness is
            # carried by "nonce" below plus the verify_live_challenge() check.
            "nonce_binding": report_info.get("report_data_hex", ""),
            "nonce": (ratls_nonce or b"").hex(),
            "spki_sha256": spki,
            "container_digest": server_cd or "",
        }
        print(f"ATTESTATION_REPORT {json.dumps(attestation_report, separators=(',', ':'))}")
    except Exception:
        # Audit emission is best-effort — never break the data path.
        pass

    # Carried out so main() can verify the live challenge report against the
    # same AMD-rooted endorsement key that was validated above.
    report_info["_endorsement_pem"] = endorsement_pem
    report_info["_peer_cert_der"] = cert_der

    return conn, report_info


def _recv_exactly(sock, n):
    """Read exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def send_request(conn: ssl.SSLSocket, payload: dict) -> dict:
    """Send a JSON request and receive the JSON response (length-prefixed framing)."""
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
        print("Usage: python3 client_snp_aws.py <host_ip> [port]", file=sys.stderr)
        sys.exit(1)

    host_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5005

    # Phase 1: RA-TLS verification + attestation request.  Generate
    # a fresh 32-byte client nonce so the audit log can correlate
    # this verifier run with any later replay or report search.
    ratls_nonce = os.urandom(32)
    print(f"Connecting to SNP confidential VM at {host_ip}:{port} via RA-TLS...", file=sys.stderr)
    try:
        conn, report_info = verify_ratls_connection(host_ip, port, ratls_nonce=ratls_nonce)
        print("AMD SEV-SNP RA-TLS Attestation Verification Passed!", file=sys.stderr)
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
        print(f"FATAL: Attested measurement {attested_measurement} not in pinned allowlist", file=sys.stderr)
        sys.exit(1)

    print("Requesting VM public key via attested connection...", file=sys.stderr)
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
        print(f"Failed to get VM public key: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    print("Verifying live attestation challenge (freshness + channel binding)...",
          file=sys.stderr)
    ok, reason = verify_live_challenge(
        att_resp,
        nonce_ascii,
        report_info.get("_peer_cert_der", b""),
        report_info.get("_endorsement_pem", b""),
        report_info.get("measurement", ""),
    )
    if not ok:
        print(f"FATAL: live attestation challenge failed: {reason}", file=sys.stderr)
        sys.exit(1)
    print("  Live challenge: PASSED (report_data == v2 binding digest over "
          "(nonce, TLS SPKI, chain_key_commitment), AMD-signed, same "
          "measurement as the certificate-embedded report)", file=sys.stderr)
    # AUD-3: surface the anchored value.  verify_live_challenge only returns
    # True when the AMD signature covers exactly this commitment, so it is
    # safe to print it as attested rather than as self-reported.  Pin it and
    # hand it to `tee-crafter verify-siem-chain --expect-chain-commitment <hex>` to tie
    # an exported audit log back to this hardware.
    _attested_commitment = (att_resp.get("chain_key_commitment") or "").strip().lower()
    if _attested_commitment:
        print(f"  Audit-log chain-key commitment (AMD-signed): {_attested_commitment}",
              file=sys.stderr)
    else:
        print("  Audit-log chain-key commitment: NONE (accepted via "
              "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1)", file=sys.stderr)

    # C3: v2 preimage, matching ``_att_input`` in the app template.  Always two
    # fields -- an absent container digest is an empty field, not a shorter
    # field list -- so this never has to branch on whether one is expected.
    pub_key_hash = _attest_binding_digest(
        enclave_pub_bytes, EXPECTED_CONTAINER_DIGEST.encode())
    if report_data_bytes[:32] != pub_key_hash:
        print("FATAL: VM public key does not match SNP report_data binding!", file=sys.stderr)
        print(f"  Expected (from report): {report_data_bytes[:32].hex()}", file=sys.stderr)
        print(f"  Got SHA-256(pub_key):   {pub_key_hash.hex()}", file=sys.stderr)
        sys.exit(1)
    print("  Public key binding: PASSED", file=sys.stderr)

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
