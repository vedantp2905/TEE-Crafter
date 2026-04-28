import sys
import json
import os
import ssl
import socket
import hashlib
import struct
import base64

EXPECTED_MRTD = "{mrtd}"

# M-06: an MRTD this client learns from the server it is verifying is not a
# pin.  The previous version self-pinned on first sight and printed "(All
# subsequent connections will enforce this value)" — but this is a one-shot
# script, so the only "subsequent connection" was the second one made moments
# later by the same process against the same peer.  A valid TDX quote proves
# the hardware, not which image booted on it, so an unpinned client now fails
# closed.  Matches the SGX, SNP and GPU-CC clients.
_ALLOW_UNPINNED_ENV = "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT"


def _allow_unpinned_measurement() -> bool:
    return os.environ.get(_ALLOW_UNPINNED_ENV, "0") == "1"


# Intel SGX Provisioning Certification Root CA — the anchor DCAP PCK
# certificates chain to (subject CN=Intel SGX Root CA, ECDSA P-256).  TDX DCAP
# uses the same Intel provisioning infrastructure as SGX.  It is *not* the
# retired EPID/IAS "Intel SGX Attestation Report Signing CA", which is RSA-3072
# and never signs a PCK chain.  Injected at build time from
# certs/intel-sgx-dcap-root.pem.
_INTEL_ROOT_CA_PEM = """{intel_root_ca}"""

# Checked before the chain walk so a build that injected the wrong anchor
# reports the cause rather than an opaque signature failure.
_EXPECTED_ROOT_CA_CN = "Intel SGX Root CA"

# Intel SGX/TDX quote OID — shared by SGX and TDX; the tee_type field
# in the quote header distinguishes them (0x00 = SGX, 0x81 = TDX).
TDX_QUOTE_OID = "1.2.840.113741.1.13.1"
CONTAINER_DIGEST_OID = "1.3.6.1.4.1.59386.1.2"
EXPECTED_CONTAINER_DIGEST = "{container_digest}"

# TDX TEE type constant in quote header
_TEE_TYPE_TDX = 0x81

# Which evidence format this client accepts, fixed at build time.
#
# The verifier must never be chosen from the bytes the server sends: a server
# that prefixes four bytes to an arbitrary blob would otherwise pick which
# verifier runs.  So this is substituted at render time and the blob only ever
# gets to disagree with it.
#
# The two formats do not share a trust root, which is why this is a deliberate
# build-time choice and not a runtime fallback:
#
#   "dcap" — a standard Intel DCAP quote from configfs-tsm or /dev/tdx-guest
#            (tdx/azure/app.template.py, generate_tdx_quote), verified here
#            against Intel's root CA.
#   "azure-guest"
#          — an MAA /attest/AzureGuest token, minted inside the TD by
#            Microsoft's guest-attestation library and verified here
#            (_verify_azure_attestation).  The trust root is Microsoft, not
#            Intel, and the session binding is MAA-signed rather than
#            hardware-signed.  Accepting it is an explicit decision.
#
# Default stays "dcap" because it is strictly the stronger of the two.  But on
# an Azure paravisor CVM it is not merely weaker to pick "azure-guest" — it is
# the only thing that works, and the history is worth keeping because it cost
# three live runs to establish:
#
#   1. Pinned to "dcap", the VM presented an HCLA blob and the client refused.
#      Correct refusal; the conclusion drawn from it ("enable the hcla path")
#      was wrong.
#   2. The former "hcla" path POSTed the 2600-byte vTPM envelope to
#      /attest/TdxVm.  404 on the wrong api-version, then 400 on the right one.
#   3. The 400 was never a body-shaping problem.  /attest/TdxVm verifies Intel
#      DCAP quotes; offset 32 of NV 0x01400001 holds a *raw* 1024-byte TDREPORT
#      whose REPORTMACSTRUCT only the TDX module and the Quoting Enclave can
#      check.  There was nothing to reshape.
#
# The guest-attestation library exists precisely because that envelope is not a
# documented wire format, and it is also the holder of the TPM-sealed key that
# unwraps a Secure Key Release -- so it is this platform's dependency either way.
_PLATFORM = "tdx-azure"
_EXPECTED_EVIDENCE_FORMAT = "{evidence_format}"


def extract_quote_from_cert(cert_der: bytes) -> bytes:
    """
    Extract the TDX quote from a TLS certificate's X.509 extension.
    The quote is stored in an extension with the RA-TLS OID.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(TDX_QUOTE_OID)

    for ext in cert.extensions:
        if ext.oid == target_oid:
            return ext.value.value
    raise ValueError("TLS certificate does not contain a TDX quote extension")


def extract_container_digest_from_cert(cert_der: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(CONTAINER_DIGEST_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            return ext.value.value.decode("utf-8")
    return None


# NOTE: ``_qe_identity_lookup_path`` and ``_check_qe_identity_tcb_status`` used
# to live here.  They read an *unsigned* ``qe_identity.json`` off the operator's
# disk, and when it was absent they fell back to a hand-copied
# minimum-QE-SVN floor of 4, labelled "Intel PCS TD_QE isvsvn baseline as of
# 2026-04".
# Both are gone.  The floor only ever floored — it silently lost value as Intel
# shipped newer QE builds, while reading like real assurance — and a second,
# signature-free QEIdentity evaluator alongside the real one is the "four copies
# drift apart" failure mode this change exists to end.  QEIdentity is now
# checked by the shared evaluator against the signature-verified collateral
# bundle; see ``enforce_platform_tcb_status`` below.  The bundle is located with
# the same convention this function established: ``$TEE_CRAFTER_TCB_COLLATERAL``
# -> a file beside this script -> ``/etc/tee_crafter/``.


def _locate_qe_report_offset(quote_bytes: bytes):
    """Return absolute offset of the QE report (sgx_report_body_t, 384 bytes).

    TDX v4 DCAP quotes wrap ECDSA sig-data in an outer cert-data header
    (``cert_data_type`` (2) + ``cert_data_size`` (4) = 6 bytes) right after
    the attestation public key.  For ``cert_data_type == 6``
    (QE_REPORT_CERTIFICATION_DATA, which is what Azure/GCP TDX attesters
    emit) the QE report is embedded inside that outer blob, so the true
    offset is ``sig_offset + 128 + 6`` rather than ``sig_offset + 128``.

    Legacy DCAP v3 / non-cert-wrapped layouts put the QE report directly at
    ``sig_offset + 128``.  We detect which by the two bytes at ``+128``:
    a plausible ``cert_data_type`` is ``1..7``.  Returns ``None`` when the
    quote is too short to contain a QE report at either layout (e.g. pure
    configfs-tsm quotes that omit QE certification data).
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


def parse_tdx_quote(quote_bytes: bytes) -> dict:
    """
    Parse key fields from a TDX DCAP quote (version 4+).

    TDX Quote Layout:
      Header (48 bytes):
        bytes 0-1:   version (uint16 LE) — typically 4 or 5
        bytes 2-3:   att_key_type (uint16 LE) — 2 = ECDSA-P256
        bytes 4-7:   tee_type (uint32 LE) — 0x81 = TDX
        bytes 8-9:   qe_svn (uint16 LE)
        bytes 10-11: pce_svn (uint16 LE)
        bytes 12-27: qe_vendor_id (16 bytes)
        bytes 28-47: user_data (20 bytes)

      TD Report Body (584 bytes, starting at offset 48):
        0-15:     TEE_TCB_SVN (16 bytes)
        16-63:    MR_SEAM (48 bytes)
        64-111:   MR_SIGNER_SEAM (48 bytes)
        112-119:  SEAM_ATTRIBUTES (8 bytes)
        120-127:  TD_ATTRIBUTES (8 bytes)
        128-135:  XFAM (8 bytes)
        136-183:  MRTD (48 bytes) — measurement of Trust Domain
        184-231:  MRCONFIGID (48 bytes)
        232-279:  MROWNER (48 bytes)
        280-327:  MROWNERCONFIG (48 bytes)
        328-375:  RTMR[0] (48 bytes)
        376-423:  RTMR[1] (48 bytes)
        424-471:  RTMR[2] (48 bytes)
        472-519:  RTMR[3] (48 bytes)
        520-583:  REPORT_DATA (64 bytes) — user-defined, for key binding
    """
    if len(quote_bytes) < 632:
        raise ValueError(f"TDX quote too short: {len(quote_bytes)} bytes (need >= 632)")

    version = struct.unpack_from("<H", quote_bytes, 0)[0]
    att_key_type = struct.unpack_from("<H", quote_bytes, 2)[0]
    tee_type = struct.unpack_from("<I", quote_bytes, 4)[0]

    if tee_type != _TEE_TYPE_TDX:
        raise ValueError(
            f"Quote tee_type is 0x{tee_type:X}, expected 0x{_TEE_TYPE_TDX:X} (TDX). "
            "This may be an SGX quote, not a TDX quote."
        )

    rb = 48  # TD Report Body offset

    tee_tcb_svn = quote_bytes[rb:rb + 16]
    mr_seam = quote_bytes[rb + 16:rb + 64].hex()
    mr_signer_seam = quote_bytes[rb + 64:rb + 112].hex()
    td_attributes = quote_bytes[rb + 120:rb + 128]
    mrtd = quote_bytes[rb + 136:rb + 184].hex()
    mr_config_id = quote_bytes[rb + 184:rb + 232].hex()
    mr_owner = quote_bytes[rb + 232:rb + 280].hex()
    rtmr0 = quote_bytes[rb + 328:rb + 376].hex()
    rtmr1 = quote_bytes[rb + 376:rb + 424].hex()
    rtmr2 = quote_bytes[rb + 424:rb + 472].hex()
    rtmr3 = quote_bytes[rb + 472:rb + 520].hex()
    report_data = quote_bytes[rb + 520:rb + 584]

    return {
        "version": version,
        "att_key_type": att_key_type,
        "tee_type": tee_type,
        "tee_tcb_svn": tee_tcb_svn.hex(),
        "mr_seam": mr_seam,
        "mr_signer_seam": mr_signer_seam,
        "td_attributes": td_attributes.hex(),
        "mrtd": mrtd,
        "mr_config_id": mr_config_id,
        "mr_owner": mr_owner,
        "rtmr0": rtmr0,
        "rtmr1": rtmr1,
        "rtmr2": rtmr2,
        "rtmr3": rtmr3,
        "report_data": report_data,
        "report_data_hex": report_data.hex(),
    }


def verify_tdx_quote_signature(quote_bytes: bytes) -> bool:
    """
    Verify the ECDSA-P256 signature over the quote header + TD Report Body.

    TDX uses the same signature structure as SGX DCAP v4:
      Offset 632: sig_data_len (uint32)
      Offset 636: isv_enclave_report_sig (64 bytes: r || s)
      Offset 700: ecdsa_attestation_key (64 bytes: x || y)
    """
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    # Header (48) + TD Report Body (584) = 632 bytes signed
    signed_data_len = 632
    if len(quote_bytes) < signed_data_len + 4 + 64 + 64:
        raise ValueError("TDX quote too short for signature verification")

    signed_data = quote_bytes[:signed_data_len]

    sig_data_len = struct.unpack_from("<I", quote_bytes, signed_data_len)[0]
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


def verify_qe_report_binding(quote_bytes: bytes) -> bool:
    """
    Verify QE report's report_data contains SHA-256(attestation_key || qe_auth_data),
    binding the attestation key to the Quoting Enclave identity.
    """
    signed_data_len = 632
    sig_offset = signed_data_len + 4

    att_key_xy = quote_bytes[sig_offset + 64:sig_offset + 128]
    qe_report_offset = _locate_qe_report_offset(quote_bytes)
    if qe_report_offset is None or len(quote_bytes) < qe_report_offset + 384:
        return False

    qe_report = quote_bytes[qe_report_offset:qe_report_offset + 384]
    qe_report_data = qe_report[320:384]

    qe_sig_offset = qe_report_offset + 384
    qe_auth_offset = qe_sig_offset + 64
    if len(quote_bytes) < qe_auth_offset + 2:
        return False
    qe_auth_size = struct.unpack_from("<H", quote_bytes, qe_auth_offset)[0]
    qe_auth_data = quote_bytes[qe_auth_offset + 2:qe_auth_offset + 2 + qe_auth_size]

    expected_hash = hashlib.sha256(att_key_xy + qe_auth_data).digest()
    return qe_report_data[:32] == expected_hash


def verify_qe_report_signature(quote_bytes: bytes, pck_leaf) -> bool:
    """
    Verify the Quoting Enclave report's ECDSA signature, made by the private
    key of the PCK leaf certificate.

    This is the link that ties the attestation key to Intel-provisioned
    hardware.  Without it every other check is self-referential: the TD report
    is verified with an attestation key read out of the same quote, and the QE
    binding hashes that key against a QE report read out of the same quote.
    Only this signature is rooted outside the quote, in the PCK certificate
    chain that ends at Intel's root CA.

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
    runs inside a ``try`` that turns that into ``{"ok": False, ...}``.
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
    """
    Verify the PCK certificate chain embedded in the TDX DCAP quote
    against Intel's Root CA (same anchor as SGX).

    Returns ``{"ok": True, "pck_leaf": <x509.Certificate>}`` when the chain
    validates to the pinned root, and ``{"ok": False, "reason": "..."}``
    otherwise.  The leaf is returned because its key signs the QE report —
    see ``verify_qe_report_signature``.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

    try:
        if not _INTEL_ROOT_CA_PEM or not _INTEL_ROOT_CA_PEM.strip():
            print("  PCK chain verification: FAILED (no Intel Root CA PEM in client — cannot verify PCK chain)",
                  file=sys.stderr)
            return {"ok": False, "reason": "no Intel Root CA PEM in client"}

        signed_data_len = 632
        sig_offset = signed_data_len + 4
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
            print(f"  PCK chain verification: FAILED (cert data type {cert_data_type} != 5 PEM chain)",
                  file=sys.stderr)
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

        chain = [x509.load_pem_x509_certificate(p, default_backend()) for p in pem_certs]
        root_ca = x509.load_pem_x509_certificate(
            _INTEL_ROOT_CA_PEM.strip().encode(), default_backend()
        )

        root_cn = next(
            (a.value for a in root_ca.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME)),
            "",
        )
        if root_cn != _EXPECTED_ROOT_CA_CN:
            print(f"  FATAL: the pinned trust anchor is {root_cn!r}, not "
                  f"{_EXPECTED_ROOT_CA_CN!r}.  DCAP PCK certificates chain to the "
                  "Intel SGX Provisioning Certification Root CA; this build "
                  "injected the wrong certificate.", file=sys.stderr)
            return {"ok": False, "reason": f"trust anchor is {root_cn!r}"}

        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        for idx, cert in enumerate([root_ca] + chain):
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                print(f"  FATAL: Certificate [{idx}] expired or not yet valid. "
                      f"Valid: {cert.not_valid_before_utc} – {cert.not_valid_after_utc}", file=sys.stderr)
                return {"ok": False, "reason": f"cert [{idx}] outside validity window"}

        # basicConstraints / keyUsage.  Without these the walk below proves
        # only "the next certificate's signature verifies", never "the signer
        # was allowed to sign certificates" — so an attacker holding any
        # Intel-issued end-entity key could sign a forged PCK leaf and the
        # chain would validate.  `chain` is leaf-first, so index 0 is the end
        # entity and every later entry is used as an issuer; `i - 1` is the
        # number of CA certificates below entry `i`, which is what
        # pathLenConstraint bounds.
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

        # Every certificate in a DCAP PCK chain is ECDSA-signed.  A non-EC
        # issuer key means the chain is not a PCK chain, so skipping the
        # signature check for it (as this code used to) would let the whole
        # chain walk succeed without verifying anything.
        for i in range(len(chain) - 1):
            issuer_pub = chain[i + 1].public_key()
            if not isinstance(issuer_pub, ec_mod.EllipticCurvePublicKey):
                return {"ok": False,
                        "reason": f"cert [{i + 1}] public key is not ECDSA"}
            issuer_pub.verify(
                chain[i].signature,
                chain[i].tbs_certificate_bytes,
                ec_mod.ECDSA(chain[i].signature_hash_algorithm),
            )

        top_cert = chain[-1]
        root_pub = root_ca.public_key()
        if not isinstance(root_pub, ec_mod.EllipticCurvePublicKey):
            return {"ok": False,
                    "reason": "pinned Intel root CA public key is not ECDSA"}
        root_pub.verify(
            top_cert.signature,
            top_cert.tbs_certificate_bytes,
            ec_mod.ECDSA(top_cert.signature_hash_algorithm),
        )

        print("  PCK certificate chain verification: PASSED "
              "(name-free walk to the pinned root: signatures, validity "
              "windows, basicConstraints CA/pathLen, keyUsage keyCertSign)",
              file=sys.stderr)
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
        print(f"  PCK certificate chain verification failed: {reason}", file=sys.stderr)
        return {"ok": False, "reason": reason}


# ---------------------------------------------------------------------------
# AUD-3: the audit log's genesis commitment must be inside report_data
# ---------------------------------------------------------------------------
#
# The in-TD audit log is an HMAC hash chain keyed by a secret that never leaves
# guest memory, and the guest publishes SHA-256(key) as the "chain key
# commitment".  On its own that commitment is self-referential — it lives in
# the log's own genesis entry, so a host that discards the log regenerates key,
# genesis, chain and commitment together and nothing contradicts it.  The guest
# therefore hashes the commitment into the TDX quote's report_data; this client
# recomputes the preimage and refuses the connection when it does not match,
# which is what turns "the log claims a commitment" into "the TDX module signed
# this commitment".
#
# These four must stay byte-identical to tdx/azure/app.template.py.  The label
# and the encoder are shared with the SNP clients so there is exactly one
# preimage format in the tree; the purpose string is what separates this
# binding (the RA-TLS certificate's embedded quote, tdx-azure) from theirs and
# from the other TDX cloud, whose field list is otherwise identical.
_ATTEST_BINDING_LABEL = b"tee-crafter/attest-binding/v2"
_CERT_BINDING_PURPOSE = b"ratls-cert-report-data/tdx-azure"
_EXPECTED_CERT_REPORT_DATA_BINDING = (
    "sha256(lp('tee-crafter/attest-binding/v2') || uint32be(4) || "
    "lp('ratls-cert-report-data/tdx-azure') || lp(ecdh_pub) || "
    "lp(container_digest) || lp(chain_key_commitment_hex_ascii))")
_ALLOW_UNBOUND_AUDIT_CHAIN_ENV = "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN"


def _attest_binding_preimage(*fields: bytes) -> bytes:
    """Rebuild the guest's attestation-binding preimage.

    Raw concatenation of variable-length fields is ambiguous —
    ``a=b"ab", b=b"cd"`` and ``a=b"abc", b=b"d"`` produce identical bytes — so
    evidence minted against one field split could be presented as satisfying a
    different one, here specifically across the container-digest/commitment
    boundary.  Every field therefore carries its own big-endian uint32 length
    prefix, the field *count* is prefixed as well (so a short field list cannot
    be padded out into a longer one), and a version label is hashed in so a v1
    preimage — ``ecdh_pub || container_digest``, which carried no commitment —
    can never be reinterpreted as a v2 one.  This must stay byte-for-byte
    identical to ``_attest_binding_preimage`` in tdx/azure/app.template.py.
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

    *declared* is the ``chain_key_commitment`` the guest published alongside
    its attestation evidence.  Returns ``(commitment_ascii, error)``; a
    non-empty *error* is fatal for the caller.

    An absent commitment is fatal by default.  With no hardware-signed
    commitment the audit log is unanchored, and a host-level adversary who
    replaces it wholesale — fresh HMAC key, fresh genesis entry, fresh chain,
    matching published commitment — is indistinguishable from an honest run.
    ``TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1`` opts out with a loud warning,
    following the same convention as ``TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT``.
    """
    value = (declared or "").strip().lower()
    if not value:
        if os.environ.get(_ALLOW_UNBOUND_AUDIT_CHAIN_ENV) == "1":
            bar = "*" * 78
            print(bar, file=sys.stderr)
            print("WARNING: the VM declared no runtime audit-log chain-key",
                  file=sys.stderr)
            print(f"commitment and {_ALLOW_UNBOUND_AUDIT_CHAIN_ENV}=1 is set. The",
                  file=sys.stderr)
            print("audit log this deployment produces is NOT anchored to any",
                  file=sys.stderr)
            print("hardware-signed value: a host-level adversary can discard it and",
                  file=sys.stderr)
            print("publish a self-consistent replacement, and nothing here will",
                  file=sys.stderr)
            print("notice. Development use only.", file=sys.stderr)
            print(bar, file=sys.stderr)
            return b"", ""
        return b"", (
            "the VM declared no runtime audit-log chain-key commitment "
            "('chain_key_commitment' absent or empty), so its audit log has no "
            "hardware-signed anchor. Rebuild the TEE image from a commit that "
            "stages tee_crafter_audit_logger, or set "
            f"{_ALLOW_UNBOUND_AUDIT_CHAIN_ENV}=1 to accept an unanchored log "
            "(development only).")
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        return b"", (
            "'chain_key_commitment' is not a 64-character SHA-256 hex digest "
            f"(got {len(value)} character(s))")
    return value.encode("ascii"), ""


def verify_report_data_binding(report_data: bytes, att_resp: dict,
                               enclave_pub_bytes: bytes,
                               container_digest: str,
                               quote_info: dict | None = None) -> tuple:
    """Verify the session binding against the v2 preimage.  ``(ok, reason)``.

    One function for both evidence formats, on purpose.  *Where* the binding
    lives differs by platform — hardware-signed ``report_data[:32]`` on the DCAP
    path, the MAA client-payload nonce on the AzureGuest path, because an Azure
    paravisor CVM spends ``report_data`` on the paravisor's own runtime claims —
    but *what* is bound is identical, and the recomputation below is shared.
    Splitting this into two functions is how one of them ends up without the
    check; the AzureGuest path shipped in exactly that state.

    Fails closed on every unexpected shape: a guest that omits or misstates the
    binding descriptor is refused outright, and the commitment itself must be a
    64-character SHA-256 hex digest or explicitly opted out of.
    """
    binding = (att_resp or {}).get("cert_report_data_binding") or ""
    if binding != _EXPECTED_CERT_REPORT_DATA_BINDING:
        return False, (
            "the VM did not describe its certificate quote's report_data "
            f"preimage as {_EXPECTED_CERT_REPORT_DATA_BINDING!r} (got "
            f"{binding!r}). Client and guest must be built from the same "
            "commit: a pre-v2 guest binds only SHA-256(ECDH pubkey "
            "[|| container digest]) and carries no hardware-signed audit-chain "
            "commitment, which is the thing this check exists to establish."
        )

    commitment_ascii, commitment_error = resolve_chain_key_commitment(
        (att_resp or {}).get("chain_key_commitment", ""))
    if commitment_error:
        return False, commitment_error

    expected = _attest_binding_digest(
        _CERT_BINDING_PURPOSE, enclave_pub_bytes,
        container_digest.encode("utf-8"), commitment_ascii)

    fmt = (quote_info or {}).get("evidence_format", "dcap")
    if fmt == "azure-guest":
        # The nonce is a string chosen by the guest and signed over by MAA, so
        # the comparison is against the encodings AttestationClient may have
        # applied -- see expected_client_payload_nonces() for why more than one
        # is accepted and why that does not widen the check.
        nonce = str((quote_info or {}).get("client_payload_nonce", ""))
        if not nonce:
            return False, (
                "the MAA token carries no x-ms-runtime.client-payload.nonce, so "
                "nothing ties it to this session. A token without it attests "
                "that some Azure confidential VM exists — which any tenant can "
                "obtain for their own VM and replay here — not that this "
                "connection terminates inside the TD that was measured."
            )
        maa = _load_maa_module()
        if nonce not in maa.expected_client_payload_nonces(expected):
            return False, (
                "the MAA token's client-payload nonce is not this session's v2 "
                "binding (purpose, ECDH pubkey, container digest, "
                "chain_key_commitment). The token is validly signed but was "
                f"issued for a different session (token carries {nonce!r}, "
                f"recomputed {expected.hex()})"
            )
    elif report_data[:32] != expected:
        return False, (
            "report_data is not SHA-256 of the v2 preimage (purpose, ECDH "
            "pubkey, container digest, chain_key_commitment) — one of those is "
            "not the value the hardware signed (quote carries "
            f"{report_data[:32].hex()}, recomputed {expected.hex()})"
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


def _emit_attestation_report(quote_info: dict, server_cd: str | None,
                              spki: str, ratls_nonce: bytes, kind: str) -> None:
    """Emit a structured ATTESTATION_REPORT line for the deploy orchestrator."""
    try:
        _azure_guest = quote_info.get("evidence_format") == "azure-guest"
        attestation_report = {
            "platform": _PLATFORM,
            # Who actually vouched for this. On the AzureGuest path Intel never
            # signs anything we see -- MAA does, after checking the Azure CA and
            # PCK chains itself -- so recording "intel-tdx" would put a false
            # trust root into the provenance ledger.
            "issuer": (quote_info.get("maa_issuer") or "microsoft-azure-attestation")
                      if _azure_guest else "intel-tdx",
            "report_kind": kind,
            "quote_signature_alg": "RS256" if _azure_guest else "ECDSA_P256_SHA256",
            "mrtd": quote_info.get("mrtd", ""),
            "rtmr0": quote_info.get("rtmr0", ""),
            "rtmr1": quote_info.get("rtmr1", ""),
            "rtmr2": quote_info.get("rtmr2", ""),
            "rtmr3": quote_info.get("rtmr3", ""),
            "tcb_svn": quote_info.get("tee_tcb_svn", ""),
            "nonce_binding": quote_info.get("report_data_hex", ""),
            "nonce": (ratls_nonce or b"").hex(),
            "spki_sha256": spki,
            "container_digest": server_cd or "",
        }
        print(f"ATTESTATION_REPORT {json.dumps(attestation_report, separators=(',', ':'))}")
    except Exception as _att_err:
        print(f"WARN: failed to emit ATTESTATION_REPORT line: {type(_att_err).__name__}: {_att_err}", file=sys.stderr)


def verify_ratls_connection(host: str, port: int, ratls_nonce: bytes | None = None) -> tuple:
    """
    Connect to the TDX VM via TLS. Extract the embedded TDX attestation
    evidence from the RA-TLS certificate and verify it.

    The evidence format is fixed at build time by ``_EXPECTED_EVIDENCE_FORMAT``
    and never inferred from the blob, so the server cannot choose its own
    verifier.  A raw Azure vTPM HCLA report is rejected under *either* setting:
    it is unverifiable by this client and unacceptable to ``/attest/TdxVm``, so
    a guest presenting one has skipped the MAA exchange rather than found an
    alternative to it.

    ``ratls_nonce`` is round-tripped into ``ATTESTATION_REPORT`` for
    audit correlation.
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
        quote_bytes = extract_quote_from_cert(cert_der)
    except ValueError as e:
        conn.close()
        print(f"FATAL: {e}. RA-TLS attestation is required — aborting.", file=sys.stderr)
        sys.exit(1)

    # The blob only gets to say what it *claims* to be; the build-time
    # platform config decides which verifier runs.  A mismatch is fatal.
    looks_hcla = quote_bytes[:4] == b"HCLA"
    looks_jwt = quote_bytes[:3] == b"eyJ"
    if _EXPECTED_EVIDENCE_FORMAT == "dcap" and (looks_hcla or looks_jwt):
        conn.close()
        print(f"FATAL: this client was built for {_PLATFORM} DCAP evidence but the "
              "server presented "
              + ("a raw Azure vTPM HCLA report" if looks_hcla
                 else "an MAA AzureGuest token")
              + ". Refusing to proceed. An Azure paravisor CVM cannot produce a "
                "DCAP quote at all; rebuild with "
                "TEE_CRAFTER_TDX_EVIDENCE_FORMAT=azure-guest, accepting that "
                "this moves the trust root from Intel to Microsoft.",
              file=sys.stderr)
        sys.exit(1)
    if _EXPECTED_EVIDENCE_FORMAT == "azure-guest" and not looks_jwt:
        conn.close()
        print(f"FATAL: this client was built for {_PLATFORM} AzureGuest evidence "
              "but the server presented "
              + ("a raw Azure vTPM HCLA report, which nothing can verify -- the "
                 "guest did not exchange it for an MAA token. Re-bake so "
                 "AttestationClient is installed" if looks_hcla
                 else "something that is not a JWT")
              + ". Refusing to proceed.", file=sys.stderr)
        sys.exit(1)

    server_cd = extract_container_digest_from_cert(cert_der)
    if server_cd:
        print(f"  Container digest: {server_cd}", file=sys.stderr)
        if EXPECTED_CONTAINER_DIGEST and EXPECTED_CONTAINER_DIGEST != "":
            if server_cd != EXPECTED_CONTAINER_DIGEST:
                conn.close()
                print(f"FATAL: Container digest mismatch! got={server_cd} expected={EXPECTED_CONTAINER_DIGEST}", file=sys.stderr)
                sys.exit(1)
            print("  Container binding: PASSED", file=sys.stderr)

    try:
        spki = _spki_sha256_from_der(cert_der)
    except Exception:
        spki = ""

    if _EXPECTED_EVIDENCE_FORMAT == "azure-guest":
        conn_out, quote_info = _verify_azure_attestation(conn, quote_bytes)
        _emit_attestation_report(quote_info, server_cd, spki, ratls_nonce or b"",
                                 "azure_guest_maa")
        return conn_out, quote_info
    else:
        conn_out, quote_info = _verify_dcap_attestation(conn, quote_bytes)
        _emit_attestation_report(quote_info, server_cd, spki, ratls_nonce or b"", "dcap")
        return conn_out, quote_info


#: MAA instance that adjudicates HCLA evidence.  No default: an attestation
#: service the operator did not choose is not a trust anchor.
_MAA_ENDPOINT = os.environ.get("TEE_CRAFTER_MAA_ENDPOINT", "").strip()
_MAA_MODULE = "tee_crafter_maa"


def _load_maa_module():
    """Import the shared MAA verifier staged beside this client.

    Same contract as :func:`load_tcb_eval_module`, and same reason it raises
    rather than degrading: a build that did not stage the verifier must refuse
    connections, not accept them unverified.
    """
    import importlib
    import importlib.util

    try:
        return importlib.import_module(_MAA_MODULE)
    except ImportError:
        pass
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), _MAA_MODULE + ".py"),
        "/etc/tee_crafter/" + _MAA_MODULE + ".py",
    ]
    for path in candidates:
        if not os.path.exists(path):
            continue
        spec = importlib.util.spec_from_file_location(_MAA_MODULE, path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[_MAA_MODULE] = module
        spec.loader.exec_module(module)
        return module
    raise RuntimeError(
        f"{_MAA_MODULE}.py is neither beside this client nor on sys.path "
        f"(looked at {candidates}). The build stages it; a build that did not "
        "is incomplete, and this client will not accept HCLA evidence without "
        "verifying MAA's verdict on it.")


def _verify_azure_attestation(conn, quote_bytes: bytes) -> tuple:
    """Verify an MAA ``/attest/AzureGuest`` token minted inside the TD.

    On an Azure paravisor CVM the guest cannot produce a quote.  vTPM NV
    ``0x01400001`` yields a raw 1024-byte ``TDREPORT`` (Microsoft's own
    attestation-report format table: header 32 bytes, payload at offset 32,
    runtime data at 1216) whose ``REPORTMACSTRUCT`` is MAC'd with a key held only
    by the TDX module and the Quoting Enclave.  Nothing here can check it, and
    ``/attest/TdxVm`` will not accept it either — it verifies Intel DCAP quotes,
    which is why three live runs got a 404 and then a 400.

    So the TD does the exchange itself, using Microsoft's guest-attestation
    library, and hands over the resulting JWT as its RA-TLS evidence.  What is
    verified here is that token: RS256 against the published JWKS, issuer,
    expiry, then ``x-ms-isolation-tee.x-ms-attestation-type == "tdxvm"`` and
    ``…x-ms-compliance-status == "azure-compliant-cvm"``, the MRTD/RTMRs, the
    debug flags, and — the part that makes it mean anything about *this*
    connection — the client-payload nonce.

    **What this function deliberately does not do is check the binding.** That
    happens once, later, in :func:`verify_report_data_binding`, alongside the
    DCAP path's equivalent check — because the values it needs (the ECDH public
    key and the audit-chain commitment) only arrive in the ``get_attestation``
    response, and because one enforcement point for both evidence formats is the
    only way a future edit cannot quietly exempt one of them. The nonce is
    carried out of here in ``quote_info["client_payload_nonce"]`` for that check.

    Fails closed in three ways here — no configured MAA endpoint, no staged
    verifier, a token MAA will not stand behind — and a fourth there.
    """
    maa = _load_maa_module()

    if not _MAA_ENDPOINT:
        conn.close()
        print("FATAL: AzureGuest evidence needs an attestation service to "
              "adjudicate it, and TEE_CRAFTER_MAA_ENDPOINT is unset. Set it to "
              "your MAA instance (e.g. https://<name>.<region>.attest.azure.net). "
              "Refusing to proceed.", file=sys.stderr)
        sys.exit(1)

    try:
        import json as _json
        import urllib.request as _urlreq

        token = quote_bytes.decode("ascii").strip()
    except Exception as exc:
        conn.close()
        print(f"FATAL: AzureGuest evidence is not an ASCII JWT: {exc}",
              file=sys.stderr)
        sys.exit(1)

    try:
        jwks_raw = _urlreq.urlopen(maa.jwks_url_for(_MAA_ENDPOINT), timeout=15).read()
        verdict = maa.verify_maa_azure_guest_token(
            token,
            expected_issuer=_MAA_ENDPOINT,
            jwks=_json.loads(jwks_raw),
            expected_mrtd=EXPECTED_MRTD if EXPECTED_MRTD not in ("", "unknown") else "",
        )
    except Exception as exc:
        conn.close()
        print(f"FATAL: MAA could not vouch for this VM: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"    MAA issuer:        {verdict.issuer}", file=sys.stderr)
    print(f"    Attestation type:  tdxvm ({verdict.compliance_status})", file=sys.stderr)
    print(f"    MRTD:              {verdict.mrtd[:32]}…", file=sys.stderr)
    print(f"    Platform TCB:      {verdict.tcb_status}", file=sys.stderr)
    # Said out loud on every run, because it is the one place tdx-azure is
    # weaker than every other platform here and a reader of the logs should not
    # have to know the platform internals to find that out.
    print("    NOTE: trust root is Microsoft Azure Attestation, not Intel, and "
          "the session binding is MAA-signed rather than hardware-signed. An "
          "Azure paravisor CVM offers no stronger option.", file=sys.stderr)

    runtime = (verdict.claims or {}).get("x-ms-runtime") or {}
    payload = runtime.get("client-payload") if isinstance(runtime, dict) else {}
    nonce = str((payload or {}).get("nonce", ""))

    quote_info = {
        "mrtd": verdict.mrtd,
        # Deliberately empty rather than the token's `tdx_report_data`.  That
        # field is real, but it is the paravisor's hash of its own runtime
        # claims, not our session binding -- handing it onward under the name
        # the DCAP path uses would let the shared binding check compare the
        # wrong 32 bytes and call it a match.
        "report_data": b"",
        "report_data_hex": nonce,
        "rtmrs": list(verdict.rtmrs),
        "tdx_report_data": verdict.report_data,
        "tcb_status": verdict.tcb_status,
        "evidence_format": "azure-guest",
        "maa_issuer": verdict.issuer,
        "debug": verdict.debug,
        "client_payload_nonce": nonce,
    }
    return conn, quote_info


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


def _verify_dcap_attestation(conn, quote_bytes: bytes) -> tuple:
    """Verify a standard TDX DCAP quote."""
    quote_info = parse_tdx_quote(quote_bytes)

    print(f"  Quote version:      {quote_info['version']}", file=sys.stderr)
    print(f"  TEE type:           TDX (0x{quote_info['tee_type']:X})", file=sys.stderr)
    print(f"  MRTD:               {quote_info['mrtd']}", file=sys.stderr)
    print(f"  RTMR[0]:            {quote_info['rtmr0'][:32]}...", file=sys.stderr)
    print(f"  RTMR[1]:            {quote_info['rtmr1'][:32]}...", file=sys.stderr)
    print(f"  TD Attributes:      {quote_info['td_attributes']}", file=sys.stderr)
    print(f"  TEE_TCB_SVN:        {quote_info['tee_tcb_svn']}", file=sys.stderr)

    td_attr_bytes = bytes.fromhex(quote_info["td_attributes"])
    if len(td_attr_bytes) >= 8 and (td_attr_bytes[0] & 0x01):
        conn.close()
        print("FATAL: TD_ATTRIBUTES has DEBUG bit set — refusing production connection.", file=sys.stderr)
        sys.exit(1)
    print("  TD_ATTRIBUTES debug bit: CLEAR (production mode)", file=sys.stderr)

    # TDX-3 (the hand-rolled "TDX module >= 1.5" floor) has been DELETED here.
    # It read TEE_TCB_SVN[0] as the module's major SVN and [1] as the minor.
    # That is backwards.  Intel's Quote Verification Library defines
    # TDX_MODULE_MAJOR_SVN_INDEX = 1 and TDX_MODULE_MINOR_SVN_INDEX = 0
    # (Src/AttestationLibrary/src/Verifiers/Checks/EvaluateTcb.cpp), and the
    # live tdxModuleIdentities confirm it: every FMSPC Intel serves TDX TCB
    # info for publishes ids TDX_01 and TDX_03, i.e. module *major* versions
    # keyed on byte 1.
    #
    # Swapping the two bytes broke the comparison in both directions:
    #   * a real module 1.2 presents [0]=2, [1]=1 -> the check read major=2,
    #     took the `major > 1` branch and PASSED a module it existed to reject;
    #   * a real module 3.0 presents [0]=0, [1]=3 -> the check read major=0 and
    #     REFUSED a module newer than the floor.
    #
    # It is deleted rather than corrected because the module is now evaluated
    # properly against signed Intel collateral: enforce_platform_tcb_status
    # below matches MRSIGNERSEAM and SEAMATTRIBUTES against the tdxModule /
    # tdxModuleIdentities Intel signs, resolves the module's own tcbStatus from
    # its tcbLevels, and converges that with the platform status.  Intel's
    # tcbLevels already encode the CVE-driven judgement this constant was
    # trying to hardcode, and they stay current without anyone editing a
    # template.  A hardcoded floor beside real collateral is the same
    # hand-maintained pattern that produced the deleted `qe_svn >= 4` floor.

    # QE identity is checked further down, not here: it needs the PCK chain
    # (for the FMSPC and the CRLs), so it runs alongside the platform TCB
    # evaluation after the chain walk.  See enforce_platform_tcb_status.

    # 1. Verify ECDSA signature over quote body
    print("Verifying TDX quote ECDSA signature...", file=sys.stderr)
    if not verify_tdx_quote_signature(quote_bytes):
        conn.close()
        print("FATAL: TDX quote ECDSA signature verification FAILED.", file=sys.stderr)
        sys.exit(1)
    print("  TDX quote signature: PASSED", file=sys.stderr)

    # 2. Verify MRTD (measurement of trust domain).  M-06: no self-pinning —
    #    an unpinned client fails closed unless the operator opts out.
    if EXPECTED_MRTD and EXPECTED_MRTD != "unknown":
        if quote_info["mrtd"] != EXPECTED_MRTD:
            conn.close()
            print(f"FATAL: MRTD mismatch! Expected {EXPECTED_MRTD}, "
                  f"got {quote_info['mrtd']}", file=sys.stderr)
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
            "any image (development only).",
            file=sys.stderr,
        )
        sys.exit(1)

    # 3. Verify QE report binding (attestation key hash)
    print("Verifying QE report binding...", file=sys.stderr)
    if verify_qe_report_binding(quote_bytes):
        print("  QE report binding: PASSED", file=sys.stderr)
    else:
        raise RuntimeError("QE report binding verification failed — attestation key authenticity cannot be confirmed")

    # 4. Verify PCK certificate chain against Intel Root CA
    print("Verifying PCK certificate chain...", file=sys.stderr)
    pck_result = verify_pck_cert_chain(quote_bytes)
    if not pck_result.get("ok"):
        conn.close()
        print("FATAL: PCK certificate chain verification FAILED. "
              "Cannot verify hardware root of trust.", file=sys.stderr)
        sys.exit(1)

    # 5. Verify the QE report is signed by the PCK leaf key.  Steps 1 and 3
    #    both read the attestation key out of the quote, so they prove nothing
    #    on their own; this step is what makes them meaningful.
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
    print("Evaluating platform TCB status (Intel PCS collateral)...",
          file=sys.stderr)
    enforce_platform_tcb_status(quote_bytes, quote_info, pck_result)

    return conn, quote_info


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
        print("Usage: python3 client_tdx.py <host_ip> [port]", file=sys.stderr)
        sys.exit(1)

    host_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5005

    # Phase 1: RA-TLS verification + attestation request on the SAME connection.
    # The VM server is single-threaded; opening a connection without
    # sending data blocks the server in recv() and prevents subsequent
    # connections from being accepted (deadlock through Bastion tunnels).
    ratls_nonce = os.urandom(32)
    print(f"Connecting to TDX confidential VM at {host_ip}:{port} via RA-TLS...", file=sys.stderr)
    try:
        conn, quote_info = verify_ratls_connection(host_ip, port, ratls_nonce=ratls_nonce)
        print("TDX RA-TLS Attestation Verification Passed!", file=sys.stderr)
    except Exception as e:
        print(f"Failed to establish RA-TLS connection: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)

    report_data_bytes = quote_info["report_data"]

    # M-06: MRTD is enforced inside verify_ratls_connection().  A client with
    # no pinned MRTD only reaches this point via the explicit
    # TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 opt-out, so there is nothing
    # to self-pin here; re-check the pin rather than assign one.
    attested_mrtd = quote_info.get("mrtd", "")
    if EXPECTED_MRTD and EXPECTED_MRTD != "unknown" and attested_mrtd != EXPECTED_MRTD:
        print(f"FATAL: Attested MRTD {attested_mrtd} does not match pinned {EXPECTED_MRTD}", file=sys.stderr)
        sys.exit(1)

    print("Requesting VM public key via attested connection...", file=sys.stderr)
    try:
        att_resp = send_request(conn, {"action": "get_attestation", "nonce": base64.b64encode(os.urandom(32)).decode()})
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

    # Verify report_data[:32] against the v2 preimage: it binds the ECDH public
    # key (so the ECIES layer belongs to this TD), the container image digest,
    # and the runtime audit log's genesis commitment (so the log is anchored to
    # hardware).
    print("Verifying report_data binding (ECDH key + container digest + "
          "audit-chain commitment)...", file=sys.stderr)
    ok, reason = verify_report_data_binding(
        report_data_bytes, att_resp, enclave_pub_bytes,
        EXPECTED_CONTAINER_DIGEST or "", quote_info)
    if not ok:
        print(f"FATAL: report_data binding failed: {reason}", file=sys.stderr)
        sys.exit(1)
    print("  Public key binding: PASSED (SHA-256 match in report_data)", file=sys.stderr)
    _commitment = att_resp.get("chain_key_commitment") or ""
    print("  Audit-chain genesis commitment: "
          + (f"BOUND to the hardware-signed quote ({_commitment})"
             if _commitment else "ABSENT (accepted via explicit opt-out)"),
          file=sys.stderr)

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
