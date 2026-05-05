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


def _allow_unpinned_measurement() -> bool:
    """Whether the operator has opted out of requiring a pinned measurement.

    A client with no baked-in measurement cannot tell a genuine image from
    any other image the same hardware happens to be running, so the
    default is to refuse.  Setting TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1
    downgrades that to a warning for lab / first-boot capture runs, where
    the whole point is to *learn* the measurement.
    """
    return os.environ.get("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT", "0") == "1"


# AMD root of trust for the SEV-SNP endorsement (VCEK/VLEK) chain.  The
# injected PEM bundle holds the ASK/SEV intermediate followed by the
# self-signed ARK for the processor family the build targeted (Genoa by
# default on Azure NCC H100 v5).  Placeholder tokens are intentionally
# kept out of this comment block; the template renderer replaces text
# globally and a multi-line PEM would otherwise bleed into code lines.
_AMD_ROOT_CA_PEM = """{amd_root_ca}"""
# NVIDIA NRAS JWKS signing CA.  This file is the NRAS *intermediate*
# (the leaf's issuer), not a self-signed root — the x5c check below pins
# x5c[1] to it byte-for-byte, so "intermediate" is the accurate name.
_NVIDIA_NRAS_INTERMEDIATE_CA_PEM = """{nvidia_root_ca}"""

SNP_REPORT_OID = "1.3.6.1.4.1.3704.1.3.1"
SNP_QUOTE_OID = "1.3.6.1.4.1.3704.1.1.1"
GPU_ATT_OID = "1.3.6.1.4.1.59386.1.1"
CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"
# F-7: server-provided ECDH pub + salt so we can recompute
# sha256(v2_binding_digest(ECDH-pub, chain_key_commitment) || salt) and
# match it against the NRAS-signed eat_nonce claim (AUD-3).
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


_SNP_ATTESTATION_REPORT_SIZE = 1184

# Attestation report field offsets (AMD SEV-SNP ABI 56860, same layout the
# CPU-only snp/azure client parses).
_OFF_VERSION = 0x00
_OFF_GUEST_SVN = 0x04
_OFF_POLICY = 0x08
_OFF_VMPL = 0x30
_OFF_SIG_ALGO = 0x34
_OFF_PLAT_INFO = 0x40
_OFF_REPORT_DATA = 0x50
_OFF_MEASUREMENT = 0x90
_OFF_REPORTED_TCB = 0x180
_OFF_CHIP_ID = 0x1A0
_OFF_COMMITTED_TCB = 0x1E0
_OFF_SIGNATURE = 0x2A0
# Everything before the signature block is what the VCEK signs.
_SNP_SIGNED_DATA_SIZE = 0x2A0


def extract_snp_report_from_cert(cert_der: bytes) -> tuple:
    """Extract SNP evidence from the RA-TLS certificate.

    The SNP_QUOTE_OID extension blob is laid out as:
        report (1184 bytes)
        u32 endorsement_cert_len  ||  endorsement cert chain (PEM)
        u32 tpm_blob_len          ||  TPM Quote blob
        u32 runtime_data_len      ||  HCL runtime data (JSON, optional)

    The endorsement (VCEK/VLEK) chain is mandatory: without it the report
    signature cannot be checked and the CPU TEE is unattested.  The legacy
    SNP_REPORT_OID extension carried a bare report with no endorsement, so
    it is no longer accepted.

    Returns (snp_report_bytes, endorsement_pem, tpm_evidence_or_None,
    hcl_runtime_data).  The last field is ``b\"\"`` for certificates minted
    before it was added.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    for ext in cert.extensions:
        if ext.oid == x509.ObjectIdentifier(SNP_QUOTE_OID):
            blob = ext.value.value
            if len(blob) < _SNP_ATTESTATION_REPORT_SIZE + 4:
                raise ValueError(f"SNP quote extension too short: {len(blob)} bytes")
            snp_report = blob[:_SNP_ATTESTATION_REPORT_SIZE]
            off = _SNP_ATTESTATION_REPORT_SIZE
            cert_len = struct.unpack_from("<I", blob, off)[0]
            off += 4
            if cert_len == 0 or off + cert_len > len(blob):
                raise ValueError(
                    "SNP quote extension carries no endorsement certificate — "
                    "the report signature cannot be verified (server template "
                    "is out of date)")
            endorsement_pem = blob[off:off + cert_len]
            off += cert_len
            tpm_evidence = _parse_tpm_evidence(blob[off:])
            runtime_data = _parse_hcl_runtime_data(blob[off:])
            return snp_report, endorsement_pem, tpm_evidence, runtime_data

    if any(ext.oid == x509.ObjectIdentifier(SNP_REPORT_OID) for ext in cert.extensions):
        raise ValueError(
            "TLS certificate carries a bare SNP report (OID 1.3.6.1.4.1.3704.1.3.1) "
            "with no AMD endorsement certificate — refusing to treat an unsigned "
            "report as CPU-TEE attestation")

    raise ValueError("TLS certificate does not contain an SNP report extension")


def _parse_hcl_runtime_data(data: bytes) -> bytes:
    """Read the optional HCL runtime data that follows the TPM Quote blob.

    Returns ``b""`` when absent, which is the normal case for a certificate
    minted by a server template built before this field existed.
    """
    if len(data) < 4:
        return b""
    tpm_blob_len = struct.unpack_from("<I", data, 0)[0]
    off = 4 + tpm_blob_len
    if off + 4 > len(data):
        return b""
    rt_len = struct.unpack_from("<I", data, off)[0]
    if rt_len <= 0 or off + 4 + rt_len > len(data):
        return b""
    return data[off + 4:off + 4 + rt_len]


def _ak_pub_has_modulus(ak_pub: bytes, modulus: bytes) -> bool:
    """Does *ak_pub* carry exactly this RSA modulus?

    ``ak_pub`` is PEM here -- the app runs ``tpm2_readpublic -f pem`` -- so this
    parses it and compares integers.  A byte-substring test against PEM is
    silently always false, because base64-of-DER contains none of the raw
    modulus bytes.  A raw TPM2B_PUBLIC blob is accepted as a fallback, where the
    substring test is the correct one.
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
    return modulus in ak_pub


def verify_hcl_ak_binding(report_data: bytes, runtime_data: bytes,
                          ak_pub: bytes) -> bool:
    """Is the TPM attestation key the one the AMD-signed report vouches for?

    This is what turns "the quote proves the same process built the preimage"
    into "AMD vouches for the key that signed the quote", and it is the missing
    link this client used to report honestly as *NOT ESTABLISHED*.

    Two checks, both required:

    1. ``sha256(runtime_data) == report_data[:32]`` -- AMD signs REPORT_DATA, so
       this ties the runtime-data JSON to the hardware signature.
    2. The RSA modulus of ``keys[kid == "HCLAkPub"]`` is the modulus of the AK
       that signed the quote.

    Without (2) the AK is unpinned: an attacker replaying a captured SNP report
    can generate their own key and sign a quote committing to their own key
    hash, which is internally consistent and would otherwise pass.

    Returns False on any malformed input, so a parsing quirk reads as "no strong
    binding" rather than as success.
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


def _parse_tpm_evidence(data: bytes) -> tuple | None:
    """Parse TPM Quote evidence from the certificate extension blob."""
    if len(data) < 4:
        return None
    tpm_blob_len = struct.unpack_from("<I", data, 0)[0]
    if tpm_blob_len == 0:
        return None
    tpm_blob = data[4:4 + tpm_blob_len]
    off = 0

    def _read_chunk():
        nonlocal off
        if off + 4 > len(tpm_blob):
            return b""
        sz = struct.unpack_from("<I", tpm_blob, off)[0]
        off += 4
        chunk = tpm_blob[off:off + sz]
        off += sz
        return chunk

    quote_msg = _read_chunk()
    quote_sig = _read_chunk()
    ak_pub = _read_chunk()
    if not quote_msg or not quote_sig or not ak_pub:
        return None
    return quote_msg, quote_sig, ak_pub


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
    """Return the F-7 NRAS nonce-binding payload from the RA-TLS cert, or None."""
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


_MIN_SNP_FIRMWARE_SVN = 0x16
_PLATFORM_INFO_ALIAS_CHECK_COMPLETE = 1 << 5


def parse_snp_report(report: bytes) -> dict:
    """Parse the fields of an AMD SEV-SNP attestation report we act on."""
    if len(report) < _SNP_ATTESTATION_REPORT_SIZE:
        raise ValueError(f"SNP report too short: {len(report)} bytes")
    report_data = report[_OFF_REPORT_DATA:_OFF_REPORT_DATA + 64]
    policy = struct.unpack_from("<Q", report, _OFF_POLICY)[0]
    return {
        "version": struct.unpack_from("<I", report, _OFF_VERSION)[0],
        "guest_svn": struct.unpack_from("<I", report, _OFF_GUEST_SVN)[0],
        "measurement": report[_OFF_MEASUREMENT:_OFF_MEASUREMENT + 48].hex(),
        "report_data": report_data,
        "report_data_hex": report_data.hex(),
        "policy": policy,
        "policy_debug": bool(policy & (1 << 19)),
        "policy_migrate": bool(policy & (1 << 18)),
        "vmpl": struct.unpack_from("<I", report, _OFF_VMPL)[0],
        "sig_algo": struct.unpack_from("<I", report, _OFF_SIG_ALGO)[0],
        "plat_info": struct.unpack_from("<Q", report, _OFF_PLAT_INFO)[0],
        "reported_tcb": struct.unpack_from("<Q", report, _OFF_REPORTED_TCB)[0],
        "committed_tcb": struct.unpack_from("<Q", report, _OFF_COMMITTED_TCB)[0],
        "chip_id": report[_OFF_CHIP_ID:_OFF_CHIP_ID + 64].hex(),
    }


def verify_guest_policy(report_info: dict) -> bool:
    """Verify the guest policy flags meet security requirements."""
    passed = True
    if report_info.get("policy_debug"):
        print("  FATAL: Guest policy has DEBUG enabled!", file=sys.stderr)
        passed = False
    else:
        print("  Policy debug disabled: PASSED", file=sys.stderr)
    if report_info.get("policy_migrate"):
        print("  FATAL: Guest policy allows migration — refusing connection.", file=sys.stderr)
        passed = False
    else:
        print("  Policy migration disabled: PASSED", file=sys.stderr)
    if report_info.get("vmpl", 0) != 0:
        print(f"  FATAL: VMPL is {report_info['vmpl']} (expected 0)", file=sys.stderr)
        passed = False
    else:
        print("  VMPL 0: PASSED", file=sys.stderr)
    return passed


def verify_snp_report_signature(report: bytes, endorsement_pem: bytes) -> bool:
    """Verify the ECDSA-P384/SHA-384 signature on the SNP report using the VCEK.

    The signature occupies the tail of the report; r and s are 72-byte
    little-endian fields (only the low 48 bytes are significant for
    P-384).  Everything before ``_OFF_SIGNATURE`` is the signed data.
    """
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod, utils
    from cryptography.hazmat.primitives import hashes as hash_mod
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature

    if len(report) < _OFF_SIGNATURE + 512:
        print("  SNP report signature: FAILED (report too short for signature block)",
              file=sys.stderr)
        return False

    try:
        cert = x509.load_pem_x509_certificate(
            _first_pem_cert(endorsement_pem), default_backend())
        pub_key = cert.public_key()
    except Exception as e:
        print(f"  SNP report signature: FAILED (cannot load endorsement cert: {e})",
              file=sys.stderr)
        return False

    if not isinstance(pub_key, ec_mod.EllipticCurvePublicKey):
        print(f"  SNP report signature: FAILED (endorsement key is "
              f"{type(pub_key).__name__}, expected EC P-384 VCEK/VLEK)", file=sys.stderr)
        return False

    r = int.from_bytes(report[_OFF_SIGNATURE:_OFF_SIGNATURE + 48], "little")
    s = int.from_bytes(report[_OFF_SIGNATURE + 72:_OFF_SIGNATURE + 72 + 48], "little")
    der_sig = utils.encode_dss_signature(r, s)

    try:
        pub_key.verify(der_sig, report[:_SNP_SIGNED_DATA_SIZE],
                       ec_mod.ECDSA(hash_mod.SHA384()))
        return True
    except InvalidSignature:
        print("  SNP report signature: FAILED (InvalidSignature)", file=sys.stderr)
        return False


def _first_pem_cert(pem: bytes) -> bytes:
    """Return the first PEM certificate block in *pem* (the VCEK/VLEK leaf)."""
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    start = pem.index(begin)
    stop = pem.index(end, start) + len(end)
    return pem[start:stop]


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


def _verify_cert_signature(issuer_pub, subject_cert) -> None:
    """Verify *subject_cert*'s signature with *issuer_pub*, or raise.

    Key-type dispatch mirrors the NVIDIA x5c check below, with one
    deliberate difference: AMD's ARK and ASK are RSA-4096 keys that sign
    with **RSASSA-PSS** (OID 1.2.840.113549.1.1.10), not PKCS#1 v1.5.
    The PSS parameters AMD uses — and the ones verified against the
    shipped ARK/ASK certificates — are MGF1 over the same digest as the
    signature (SHA-384) with a salt length equal to that digest (48
    bytes).  Both values are read off the certificate rather than
    hard-coded so a future family that signs with a different digest
    still verifies.

    An unrecognised key type raises so the caller fails closed instead of
    silently skipping the link (the bug this replaces).
    """
    from cryptography.hazmat.primitives.asymmetric import (
        ec as ec_mod, padding as padding_mod, rsa as rsa_mod,
    )

    halg = subject_cert.signature_hash_algorithm
    if isinstance(issuer_pub, rsa_mod.RSAPublicKey):
        issuer_pub.verify(
            subject_cert.signature,
            subject_cert.tbs_certificate_bytes,
            padding_mod.PSS(mgf=padding_mod.MGF1(halg), salt_length=halg.digest_size),
            halg,
        )
    elif isinstance(issuer_pub, ec_mod.EllipticCurvePublicKey):
        issuer_pub.verify(
            subject_cert.signature,
            subject_cert.tbs_certificate_bytes,
            ec_mod.ECDSA(halg),
        )
    else:
        raise TypeError(f"Unsupported issuer public key type: {type(issuer_pub)}")


def verify_endorsement_cert_chain(endorsement_pem: bytes) -> bool:
    """Verify the VCEK/VLEK chains to the pinned AMD root of trust.

    Walks endorsement -> ASK -> ... -> ARK, checks every validity window,
    and requires the ARK to be self-signed with the key we shipped.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    import datetime

    if not _AMD_ROOT_CA_PEM or not _AMD_ROOT_CA_PEM.strip():
        print("  AMD cert chain: FAILED (no AMD root CA PEM baked into client)",
              file=sys.stderr)
        return False

    try:
        endorsement_cert = x509.load_pem_x509_certificate(
            _first_pem_cert(endorsement_pem), default_backend())
        chain_certs = _parse_pem_chain(_AMD_ROOT_CA_PEM.strip().encode())
        if not chain_certs:
            print("  AMD cert chain: FAILED (baked AMD PEM holds no certificates)",
                  file=sys.stderr)
            return False

        now = datetime.datetime.now(datetime.timezone.utc)
        for cert in [endorsement_cert] + chain_certs:
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                print(f"  AMD cert chain: FAILED (certificate expired or not yet "
                      f"valid: {cert.subject.rfc4514_string()})", file=sys.stderr)
                return False

        # endorsement (VCEK/VLEK) <- ASK, then each intermediate <- its issuer.
        _verify_cert_signature(chain_certs[0].public_key(), endorsement_cert)
        for i in range(len(chain_certs) - 1):
            _verify_cert_signature(chain_certs[i + 1].public_key(), chain_certs[i])
        ark = chain_certs[-1]
        _verify_cert_signature(ark.public_key(), ark)

        print(f"  AMD certificate chain: PASSED (VCEK -> "
              f"{' -> '.join(c.subject.rfc4514_string().split(',')[0] for c in chain_certs)})",
              file=sys.stderr)
        return True
    except Exception as e:
        print(f"  AMD certificate chain: FAILED ({type(e).__name__}: {e})", file=sys.stderr)
        return False


def verify_tpm_quote(tpm_evidence: tuple | None, expected_nonce: bytes) -> bool:
    """Verify the TPM2 Quote signature and qualifying nonce.

    tpm_evidence = (quote_msg, quote_sig_blob, ak_pub_pem)
    expected_nonce = the v2 binding digest over (ECDH pubkey, container
    digest, audit-log chain-key commitment) — must match the server's TPM
    Quote qualifying_data.

    Returns True if the quote is valid and the nonce matches.
    """
    if not tpm_evidence:
        print("  TPM Quote: NOT PRESENT (server did not embed TPM Quote)", file=sys.stderr)
        return False
    if len(tpm_evidence) != 3:
        print("  TPM Quote: MALFORMED (expected 3 components)", file=sys.stderr)
        return False

    from cryptography.hazmat.primitives.asymmetric import padding, utils as asym_utils
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature

    quote_msg, quote_sig_blob, ak_pub_pem = tpm_evidence

    # Parse TPMS_ATTEST to extract qualifying nonce
    # Layout (big-endian / TPM wire format):
    #   u32  magic          (0xFF544347 = TPM_GENERATED_VALUE)
    #   u16  type           (0x8018 = TPM_ST_ATTEST_QUOTE)
    #   TPM2B_NAME qualifiedSigner  (u16 size + data)
    #   TPM2B_DATA extraData        (u16 size + data)  <- our nonce
    try:
        off = 4 + 2  # skip magic + type
        qs_size = struct.unpack_from(">H", quote_msg, off)[0]
        off += 2 + qs_size
        ed_size = struct.unpack_from(">H", quote_msg, off)[0]
        off += 2
        extra_data = quote_msg[off:off + ed_size]
    except Exception as e:
        print(f"  TPM Quote: FAILED to parse TPMS_ATTEST ({e})", file=sys.stderr)
        return False

    if extra_data != expected_nonce:
        print("  TPM Quote: NONCE MISMATCH", file=sys.stderr)
        return False

    # Verify RSA-SSA signature over quote_msg
    # tpm2_quote default: RSASSA-PKCS1-v1_5 with SHA256
    try:
        pub_key = load_pem_public_key(ak_pub_pem, backend=default_backend())

        # Parse TPMT_SIGNATURE blob (skip sigAlg u16 + hashAlg u16 + size u16)
        sig_off = 2 + 2 + 2  # sigAlg + hashAlg + size
        raw_sig = quote_sig_blob[sig_off:]

        pub_key.verify(
            raw_sig,
            quote_msg,
            padding.PKCS1v15(),
            _hashes.SHA256(),
        )
    except InvalidSignature:
        print("  TPM Quote: SIGNATURE INVALID", file=sys.stderr)
        return False

    print("  TPM Quote binding: PASSED (nonce matches the v2 binding digest, "
          "signature valid)", file=sys.stderr)
    return True


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
       claim must match exactly (bind to local ECDH identity).
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


def verify_snp_evidence(cert_der: bytes) -> dict:
    """Verify the AMD SEV-SNP half of the dual attestation.

    This is the check the GPU-CC Azure client used to skip entirely: the
    RA-TLS certificate's SNP report was parsed and printed but never
    verified against AMD's root of trust, so the CPU TEE holding the
    plaintext was unattested while the client reported FULL-CONFIDENTIAL.

    Every step is fail-closed.  Returns
    ``{"ok": bool, "error": str, "info": dict}``; ``info`` is the parsed
    report and is only safe to publish as evidence when ``ok`` is True.
    """
    out = {"ok": False, "error": "", "info": {}}

    try:
        (snp_report, endorsement_pem, tpm_evidence,
         hcl_runtime_data) = extract_snp_report_from_cert(cert_der)
    except ValueError as e:
        out["error"] = str(e)
        return out

    try:
        snp_info = parse_snp_report(snp_report)
    except ValueError as e:
        out["error"] = str(e)
        return out
    snp_info["_tpm_evidence"] = tpm_evidence
    snp_info["_hcl_runtime_data"] = hcl_runtime_data
    out["info"] = snp_info

    print(f"  CPU TEE:         AMD SEV-SNP", file=sys.stderr)
    print(f"  Measurement:     {snp_info['measurement']}", file=sys.stderr)
    print(f"  Chip ID:         {snp_info['chip_id'][:32]}...", file=sys.stderr)

    # 1. sig_algo == 1 (ECDSA P-384 + SHA-384; AMD SEV-SNP ABI §7.3).
    if snp_info["sig_algo"] != 1:
        out["error"] = (f"unexpected sig_algo={snp_info['sig_algo']} "
                        "(expected 1 = ECDSA P-384 + SHA-384)")
        return out
    print("  sig_algo: 1 (ECDSA P-384 + SHA-384)", file=sys.stderr)

    # 2. The report is signed by the endorsement key it shipped with.
    print("Verifying SNP report ECDSA signature...", file=sys.stderr)
    if not verify_snp_report_signature(snp_report, endorsement_pem):
        out["error"] = "SNP report signature verification failed"
        return out
    print("  SNP report signature: PASSED", file=sys.stderr)

    # 3. That endorsement key chains to AMD (VCEK/VLEK -> ASK -> ARK).
    print("Verifying AMD endorsement certificate chain...", file=sys.stderr)
    if not verify_endorsement_cert_chain(endorsement_pem):
        out["error"] = ("AMD endorsement certificate chain verification failed — "
                        "the endorsement key does not chain to a trusted AMD root")
        return out

    # 4. Launch measurement must be pinned (F-4: no trust-on-first-use).
    allow = _measurement_allowlist()
    if allow:
        if not _measurement_allowed(snp_info["measurement"]):
            out["error"] = (f"SNP measurement {snp_info['measurement']} is not in the "
                            f"pinned allowlist ({len(allow)} variant(s))")
            return out
        print(f"  SNP measurement: PASSED ({len(allow)} pinned variant(s))", file=sys.stderr)
    elif _allow_unpinned_measurement():
        print("  ***********************************************************", file=sys.stderr)
        print("  WARNING: no launch measurement is pinned into this client.", file=sys.stderr)
        print("  TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 is set, so the", file=sys.stderr)
        print("  report is accepted on its AMD signature alone. The identity", file=sys.stderr)
        print("  of the software inside the CVM is NOT being checked.", file=sys.stderr)
        print(f"  Observed measurement: {snp_info['measurement']}", file=sys.stderr)
        print("  ***********************************************************", file=sys.stderr)
    else:
        out["error"] = (
            "no launch measurement pinned into this client. A signed SNP report "
            "proves the hardware, not which image booted on it. Rebuild the "
            "client with the expected measurement, or set "
            "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 to accept any image")
        return out

    # 5. Guest policy: no debug, no migration, VMPL 0.
    print("Verifying guest policy...", file=sys.stderr)
    if not verify_guest_policy(snp_info):
        out["error"] = "guest policy verification failed"
        return out

    # 6. PLATFORM_INFO.ALIAS_CHECK_COMPLETE + REPORTED_TCB SNP firmware SVN.
    plat_info = snp_info["plat_info"]
    reported_tcb = snp_info["reported_tcb"]
    committed_tcb = snp_info["committed_tcb"]
    snp_svn = (reported_tcb >> 48) & 0xFF
    print(f"  PLATFORM_INFO:   0x{plat_info:016X}", file=sys.stderr)
    print(f"  REPORTED_TCB:    0x{reported_tcb:016X} (SNP SVN = 0x{snp_svn:02X})", file=sys.stderr)
    if not (plat_info & _PLATFORM_INFO_ALIAS_CHECK_COMPLETE):
        out["error"] = ("PLATFORM_INFO ALIAS_CHECK_COMPLETE (bit 5) is clear — "
                        "AMD-SB-3015 (CVE-2024-21944) mitigation not confirmed")
        return out
    print("  AMD-SB-3015 alias check: PASSED", file=sys.stderr)
    if snp_svn < _MIN_SNP_FIRMWARE_SVN:
        out["error"] = (f"SNP firmware SVN 0x{snp_svn:02X} < minimum "
                        f"0x{_MIN_SNP_FIRMWARE_SVN:02X} (AMD-SB-3015 / ABI 56860)")
        return out
    print(f"  SNP firmware SVN: PASSED (0x{snp_svn:02X} >= 0x{_MIN_SNP_FIRMWARE_SVN:02X})",
          file=sys.stderr)

    # 7. COMMITTED_TCB <= REPORTED_TCB anti-rollback (AMD SEV-SNP ABI §4.4).
    if committed_tcb > reported_tcb:
        out["error"] = (f"COMMITTED_TCB (0x{committed_tcb:016X}) > REPORTED_TCB "
                        f"(0x{reported_tcb:016X}) — TCB anti-rollback violation")
        return out
    print(f"  COMMITTED_TCB <= REPORTED_TCB: PASSED "
          f"(0x{committed_tcb:016X} <= 0x{reported_tcb:016X})", file=sys.stderr)

    out["ok"] = True
    return out


def verify_ratls_connection(host: str, port: int, ratls_nonce: bytes | None = None) -> tuple:
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

    # CPU attestation (AMD SEV-SNP): signature, AMD chain, measurement,
    # policy, PLATFORM_INFO and TCB.  Nothing below may report
    # dual attestation until this returns ok.
    snp_result = verify_snp_evidence(cert_der)
    if not snp_result["ok"]:
        conn.close()
        print(f"FATAL: SEV-SNP attestation failed: {snp_result['error']}", file=sys.stderr)
        sys.exit(1)
    snp_verified = True
    snp_info = snp_result["info"]
    print("  AMD SEV-SNP attestation: PASSED", file=sys.stderr)

    # GPU attestation (NVIDIA NRAS) — required on Azure NCC (full-confidential)
    gpu_token = extract_gpu_token_from_cert(cert_der)
    if not gpu_token:
        conn.close()
        print("FATAL: GPU NRAS attestation NOT PRESENT in certificate (required on Azure NCC).", file=sys.stderr)
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
    gpu_verified = True
    print("  GPU NRAS attestation: PASSED", file=sys.stderr)
    # AUD-3: NVIDIA's signature over eat_nonce now covers this commitment,
    # so the audit log this VM exports can be tied back to signed evidence.
    # Note the anchor is the NVIDIA-signed GPU attestation, not the CPU
    # TEE's report_data unless the VM exposes /dev/sev-guest.  On the vTPM/HCL
    # path the guarantee is 'NVIDIA attested this GPU evidence', not 'the CPU
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

    # Both halves are proven, so the dual-attestation claim is now earned.
    # These two lines are the operator's summary of the trust boundary; the
    # guard keeps them honest if a future edit makes either check non-fatal.
    if not (snp_verified and gpu_verified):
        conn.close()
        print("FATAL: refusing to report dual attestation — "
              f"snp_verified={snp_verified} gpu_verified={gpu_verified}", file=sys.stderr)
        sys.exit(1)
    print("  Dual attestation (SNP + NVIDIA CC): COMPLETE", file=sys.stderr)
    print("  Security model: FULL-CONFIDENTIAL (encrypted PCIe)", file=sys.stderr)

    # AUD-7 / ATT-006 / ATT-007 / ATT-009 / ATT-010: structured
    # ATTESTATION_REPORT line for the deploy orchestrator.  ``vcek_chip_id``
    # is only evidence because the VCEK signature and its chain to AMD were
    # checked above; it is omitted otherwise rather than reported unverified.
    try:
        spki = _spki_sha256_from_der(cert_der)
    except Exception:
        spki = ""
    try:
        attestation_report = {
            "platform": "gpu-cc-azure",
            "issuer": "amd-sev-snp+nvidia-nras",
            "report_kind": "amd_sev_snp_v2+nras_eat",
            "quote_signature_alg": "ECDSA_P384_SHA384",
            "measurement": snp_info.get("measurement", ""),
            "tcb_svn": f"0x{snp_info.get('reported_tcb', 0):016X}" if snp_info.get("reported_tcb") else "",
            "vcek_chip_id": snp_info.get("chip_id", "") if snp_verified else "",
            "nras_token_valid": True,
            "nras_token_kid": locals().get("nras_kid", "") or "",
            "nras_eat_digest": locals().get("nras_eat_digest", "") or "",
            "nonce_binding": snp_info.get("report_data_hex", ""),
            "nonce": (ratls_nonce or b"").hex(),
            "spki_sha256": spki,
            "container_digest": server_cd or "",
            # AUD-3: the audit-log chain-key commitment NVIDIA signed into
            # the NRAS eat_nonce claim.
            "chain_key_commitment": attested_chain_commitment,
        }
        print(f"ATTESTATION_REPORT {json.dumps(attestation_report, separators=(',', ':'))}")
    except Exception:
        pass

    # AUD-3: main() needs it to rebuild the REPORT_DATA / TPM-quote preimage.
    snp_info["chain_key_commitment"] = attested_chain_commitment
    return conn, snp_info


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
        print("Usage: python3 client_gpu_cc_azure.py <host_ip> [port]", file=sys.stderr)
        sys.exit(1)
    host_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5005
    ratls_nonce = os.urandom(32)
    print(f"Connecting to GPU CC Azure VM at {host_ip}:{port}...", file=sys.stderr)
    print("  Platform: Azure NCC H100 v5 (AMD SEV-SNP + NVIDIA CC)", file=sys.stderr)
    try:
        conn, snp_info = verify_ratls_connection(host_ip, port, ratls_nonce=ratls_nonce)
        print("Dual RA-TLS Attestation Passed! (SNP + NVIDIA CC)", file=sys.stderr)
    except Exception as e:
        print(f"Failed: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)

    print("Requesting VM public key...", file=sys.stderr)
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
    except Exception as e:
        print(f"Failed: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # AUD-3: the binding preimage is (ECDH pubkey, container digest,
    # audit-log chain-key commitment), length-prefixed.  The commitment used
    # here is the one whose NRAS nonce NVIDIA already signed, so a server
    # that publishes one commitment to NRAS and another to the CPU TEE fails.
    pub_key_hash = _attest_binding_digest(
        enclave_pub_bytes,
        EXPECTED_CONTAINER_DIGEST.encode("utf-8"),
        snp_info.get("chain_key_commitment", "").encode("ascii"),
    )
    report_data = snp_info["report_data"]
    # Which of the three bindings actually held, named so the strict gate below
    # can decide on it rather than on the shape of the printed output.  Same
    # vocabulary as the snp-azure client, because it is the same paravisor and
    # the same question.
    binding_mode = None
    if report_data[:32] == pub_key_hash:
        print("  Public key + container + chain-commitment binding: PASSED "
              "(AMD-signed REPORT_DATA)", file=sys.stderr)
        print("  Audit-log chain-key commitment: AMD-SIGNED (this VM exposed a "
              "guest-controlled REPORT_DATA path)", file=sys.stderr)
        binding_mode = "report_data_strong"
    else:
        tpm_evidence = snp_info.get("_tpm_evidence")
        if verify_tpm_quote(tpm_evidence, pub_key_hash):
            print("  Public key + container + chain-commitment binding: PASSED "
                  "via TPM Quote", file=sys.stderr)
            # The quote alone does not root the AK in AMD: the HCL fixes
            # REPORT_DATA, and an attacker replaying a captured SNP report could
            # sign a quote with a key they generated, committing to their own key
            # hash.  The HCL runtime data closes that -- AMD signs REPORT_DATA,
            # REPORT_DATA is sha256 of the runtime-data JSON, and that JSON names
            # the attestation key.  When it verifies, the commitment IS anchored
            # in AMD-signed evidence and this says so; when it does not, the
            # previous honest limitation still stands and is reported unchanged.
            _ak = b""
            try:
                _, _, _ak = tpm_evidence
            except Exception:
                _ak = b""
            if verify_hcl_ak_binding(report_data,
                                     snp_info.get("_hcl_runtime_data") or b"",
                                     _ak):
                print("  Audit-log chain-key commitment vs the CPU TEE: "
                      "ESTABLISHED — the TPM Quote's attestation key is named "
                      "in the HCL runtime data that AMD-signed REPORT_DATA "
                      "commits to, so the quote is rooted in AMD-signed "
                      "evidence.", file=sys.stderr)
                binding_mode = "hcl_runtime_data_strong"
            else:
                print("  Audit-log chain-key commitment vs the CPU TEE: NOT "
                      "ESTABLISHED — the Azure vTPM HCL fixes REPORT_DATA, and "
                      "the TPM Quote's attestation key could not be tied to it "
                      "(no usable HCL runtime data). The commitment IS anchored "
                      "in the NVIDIA-signed GPU attestation above; it is not "
                      "anchored in AMD-signed evidence.", file=sys.stderr)
                binding_mode = "tpm_quote_unrooted"
        else:
            print("FATAL: Public key binding failed — neither report_data nor TPM Quote "
                  "could verify the (ECDH pubkey, container digest, "
                  "chain_key_commitment) preimage. Aborting.", file=sys.stderr)
            sys.exit(1)

    # Fail closed when the CPU-side attestation key is not rooted in AMD's
    # signature.  This platform is the same Azure paravisor as snp-azure: there
    # is no /dev/sev-guest, the HCL fixes REPORT_DATA, and the only thing that
    # ties the quoting key to AMD-signed evidence is the HCL runtime data.  Left
    # ungated, `tpm_quote_unrooted` means an attacker who replays a captured SNP
    # report from any other Azure CVM can mint their own attestation key, sign a
    # quote committing to their own ECDH key and container digest, and this
    # client would print a warning and carry on — so the CPU half of the
    # evidence would prove nothing about this peer.
    #
    # The GPU half is unaffected: NVIDIA signs the GPU evidence and that check
    # is enforced above regardless.  What this gate protects is the CPU-side
    # claim and the container digest bound alongside it.
    #
    # Default ON, and it should stay on: the server prefers the HCL-vouched AK
    # (`_tpm_hcl_ak` in the app template), so a healthy deploy on this platform
    # reaches `hcl_runtime_data_strong`.  Setting this to "0" accepts a CPU-side
    # binding that a replayed report can forge, and is for diagnosing a
    # deployment, not for running one.
    # Only a recognised falsy spelling disables this.  An exact ``== "1"`` test
    # used to mean that writing ``=true`` -- which reads as *more* strict --
    # silently turned the check off and then reported itself as ``=0``.
    if os.environ.get("TEE_CRAFTER_STRICT_SNP_AK_BINDING", "1").strip().lower(
    ) not in ("0", "false", "no", "n", "off"):
        if binding_mode not in ("report_data_strong",
                                "hcl_runtime_data_strong"):
            print(
                "FATAL: TEE_CRAFTER_STRICT_SNP_AK_BINDING=1 but the TPM "
                "attestation key was not rooted in AMD-signed evidence "
                f"(binding_mode={binding_mode}). The server did not present "
                "usable HCL runtime data naming its quoting key, so the CPU-side "
                "attestation cannot be attributed to this VM. Aborting.",
                file=sys.stderr,
            )
            sys.exit(1)
    elif binding_mode == "tpm_quote_unrooted":
        print(
            "  WARNING: TEE_CRAFTER_STRICT_SNP_AK_BINDING=0 — accepting a TPM "
            "Quote whose attestation key is not tied to the AMD-signed report. "
            "The CPU-side evidence proves a CVM exists, not that it is this "
            "peer. Only the NVIDIA-signed GPU evidence is authenticated here.",
            file=sys.stderr,
        )

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
