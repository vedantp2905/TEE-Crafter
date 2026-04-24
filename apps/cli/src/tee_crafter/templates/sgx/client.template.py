import sys
import json
import os
import ssl
import socket
import hashlib
import struct
import base64

EXPECTED_MRENCLAVE = "{mrenclave}"
EXPECTED_MRSIGNER = "{mrsigner}"

SGX_QUOTE_OID = "1.2.840.113741.1.13.1"

# Intel SGX Provisioning Certification Root CA — the anchor that DCAP PCK
# certificates chain to.  Its subject is `CN=Intel SGX Root CA` and its key is
# ECDSA P-256.  This is *not* the retired EPID/IAS "Intel SGX Attestation
# Report Signing CA": that certificate is RSA-3072 and never signs a PCK
# chain, so anchoring a DCAP quote to it can only ever fail.  Injected at
# build time from `certs/intel-sgx-dcap-root.pem` by
# `core/builder.render_sgx_client_template`.
_INTEL_SGX_ROOT_CA_PEM = """{intel_sgx_root_ca}"""

# Checked before the chain walk so that a build which injected the wrong
# anchor reports the cause rather than an opaque signature failure.
_EXPECTED_ROOT_CA_CN = "Intel SGX Root CA"


def extract_quote_from_cert(cert_der: bytes) -> bytes:
    """
    Extract the SGX DCAP quote from an RA-TLS certificate's X.509 extension.
    The quote is stored in an extension with OID 1.2.840.113741.1.13.1.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    target_oid = x509.ObjectIdentifier(SGX_QUOTE_OID)

    for ext in cert.extensions:
        if ext.oid == target_oid:
            return ext.value.value
    raise ValueError("RA-TLS certificate does not contain SGX quote extension")


def parse_sgx_quote(quote_bytes: bytes) -> dict:
    """
    Parse key fields from a DCAP SGX quote (version 3+).
    Layout (Intel SGX DCAP spec — sgx_quote3_t):
      Quote header (48 bytes):
        0-1:   version (uint16 LE)
        2-3:   att_key_type (uint16 LE)
        4-7:   tee_type (uint32 LE, 0 = SGX)
        8-9:   qe_svn (uint16 LE)
        10-11: pce_svn (uint16 LE)
        12-27: qe_vendor_id (16 bytes)
        28-47: user_data (20 bytes)
      Report body (384 bytes, sgx_report_body_t at offset 48):
        0-15:    cpusvn (16 bytes)
        16-19:   miscselect (4 bytes)
        48-63:   attributes (16 bytes) — FLAGS (8 bytes, LE) + XFRM (8 bytes)
                 FLAGS bit 0 = INIT, bit 1 = DEBUG
        64-95:   mr_enclave (32 bytes)
        128-159: mr_signer  (32 bytes)
        256-257: isv_prod_id (uint16 LE)
        258-259: isv_svn     (uint16 LE)
        320-383: report_data (64 bytes)
    """
    if len(quote_bytes) < 432:
        raise ValueError(f"Quote too short: {len(quote_bytes)} bytes (need >= 432)")

    version = struct.unpack_from("<H", quote_bytes, 0)[0]

    rb_offset = 48
    flags = struct.unpack_from("<Q", quote_bytes, rb_offset + 48)[0]
    flags_debug = bool(flags & (1 << 1))
    mrenclave = quote_bytes[rb_offset + 64 : rb_offset + 96].hex()
    mrsigner = quote_bytes[rb_offset + 128 : rb_offset + 160].hex()
    isv_prod_id = struct.unpack_from("<H", quote_bytes, rb_offset + 256)[0]
    isv_svn = struct.unpack_from("<H", quote_bytes, rb_offset + 258)[0]
    report_data = quote_bytes[rb_offset + 320 : rb_offset + 384]

    return {
        "version": version,
        "flags": flags,
        "flags_debug": flags_debug,
        "mrenclave": mrenclave,
        "mrsigner": mrsigner,
        "isv_prod_id": isv_prod_id,
        "isv_svn": isv_svn,
        "report_data": report_data,
        "report_data_hex": report_data.hex(),
    }


def verify_dcap_quote_signature(quote_bytes: bytes) -> bool:
    """
    Verify the ECDSA-P256 signature over the quote header+report_body.

    DCAP v3 quote signature layout (starting at offset 432):
      - sig_data_len:                uint32 (4 bytes)
      - isv_enclave_report_sig:      64 bytes (r||s, ECDSA-P256)
      - ecdsa_attestation_key:       64 bytes (x||y, P-256 uncompressed)
      - qe_report_body:              384 bytes
      - qe_report_sig:               64 bytes (ECDSA-P256)
      - qe_auth_data_size:           uint16
      - qe_auth_data:                variable
      - cert_data_type:              uint16
      - cert_data_size:              uint32
      - cert_data:                   variable (PCK cert chain)
    """
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    if len(quote_bytes) < 436 + 64 + 64:
        raise ValueError("Quote too short for signature verification")

    signed_data = quote_bytes[:432]

    sig_data_len = struct.unpack_from("<I", quote_bytes, 432)[0]
    enclave_sig = quote_bytes[436:500]       # 64 bytes: r || s
    att_key_xy  = quote_bytes[500:564]       # 64 bytes: x || y

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
    Verify that the QE report's report_data field contains
    SHA-256(attestation_key || qe_auth_data), binding the attestation
    key to the Quoting Enclave identity.
    """
    if len(quote_bytes) < 564 + 384:
        return False

    att_key_xy = quote_bytes[500:564]
    qe_report = quote_bytes[564:948]
    qe_report_data = qe_report[320:384]

    qe_auth_offset = 948 + 64  # after qe_report_sig
    if len(quote_bytes) < qe_auth_offset + 2:
        return False
    qe_auth_size = struct.unpack_from("<H", quote_bytes, qe_auth_offset)[0]
    qe_auth_data = quote_bytes[qe_auth_offset + 2 : qe_auth_offset + 2 + qe_auth_size]

    expected_hash = hashlib.sha256(att_key_xy + qe_auth_data).digest()
    return qe_report_data[:32] == expected_hash


def verify_qe_report_signature(quote_bytes: bytes, pck_leaf) -> bool:
    """
    Verify the Quoting Enclave report's ECDSA signature, made by the private
    key of the PCK leaf certificate.

    This is the link that ties the attestation key to Intel-provisioned
    hardware.  Without it every other check is self-referential: the enclave
    report is verified with an attestation key read out of the same quote, and
    the QE binding hashes that key against a QE report read out of the same
    quote.  Only this signature is rooted outside the quote, in the PCK
    certificate chain that ends at Intel's root CA.

    Offsets follow the DCAP v3 signature layout documented in
    ``verify_dcap_quote_signature``: the QE report body is the 384 bytes at
    564, and its signature (r || s, ECDSA-P256) is the 64 bytes at 948.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    if len(quote_bytes) < 1012:
        print(f"  QE report signature: FAILED (quote is {len(quote_bytes)} bytes, "
              "need >= 1012 for the QE report and its signature)", file=sys.stderr)
        return False

    pck_pub = pck_leaf.public_key()
    if not isinstance(pck_pub, ec.EllipticCurvePublicKey):
        print(f"  QE report signature: FAILED (PCK leaf key is "
              f"{type(pck_pub).__name__}, not ECDSA)", file=sys.stderr)
        return False

    qe_report = quote_bytes[564:948]
    sig = quote_bytes[948:1012]
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


def verify_pck_cert_chain(quote_bytes: bytes):
    """
    Verify the PCK certificate chain embedded in the DCAP quote against
    Intel's SGX Root CA.

    Returns a dict on success::
        {
            "ok": True,
            "pck_leaf": x509.Certificate,     # signs the QE report
            "pck_leaf_not_before": datetime,
            "pck_leaf_not_after":  datetime,
        }

    On any failure returns ``{"ok": False, "reason": "..."}``.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        qe_auth_offset = 948 + 64
        if len(quote_bytes) < qe_auth_offset + 2:
            return {"ok": False, "reason": "quote too short for QE auth"}
        qe_auth_size = struct.unpack_from("<H", quote_bytes, qe_auth_offset)[0]

        cert_meta_offset = qe_auth_offset + 2 + qe_auth_size
        if len(quote_bytes) < cert_meta_offset + 6:
            return {"ok": False, "reason": "quote too short for cert meta"}
        cert_data_type = struct.unpack_from("<H", quote_bytes, cert_meta_offset)[0]
        cert_data_size = struct.unpack_from("<I", quote_bytes, cert_meta_offset + 2)[0]
        cert_data = quote_bytes[cert_meta_offset + 6 : cert_meta_offset + 6 + cert_data_size]

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
            _INTEL_SGX_ROOT_CA_PEM.encode(), default_backend()
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
            if not isinstance(issuer_pub, ec.EllipticCurvePublicKey):
                return {"ok": False,
                        "reason": f"cert [{i + 1}] public key is not ECDSA"}
            issuer_pub.verify(
                chain[i].signature,
                chain[i].tbs_certificate_bytes,
                ec.ECDSA(chain[i].signature_hash_algorithm),
            )

        top_cert = chain[-1]
        root_pub = root_ca.public_key()
        if not isinstance(root_pub, ec.EllipticCurvePublicKey):
            return {"ok": False,
                    "reason": "pinned Intel root CA public key is not ECDSA"}
        root_pub.verify(
            top_cert.signature,
            top_cert.tbs_certificate_bytes,
            ec.ECDSA(top_cert.signature_hash_algorithm),
        )

        print("  PCK certificate chain verification: PASSED "
              "(name-free walk to the pinned root: signatures, validity "
              "windows, basicConstraints CA/pathLen, keyUsage keyCertSign)",
              file=sys.stderr)
        return {
            "ok": True,
            "pck_leaf": chain[0],
            # The whole chain, leaf-first, is returned so the TCB evaluation can
            # check *every* certificate in it against Intel's CRLs.  Revoking a
            # PCK intermediate is how Intel withdraws trust in a whole class of
            # platform, and a leaf-only revocation check would miss it.
            "pck_chain": chain,
            "pck_leaf_not_before": chain[0].not_valid_before_utc,
            "pck_leaf_not_after": chain[0].not_valid_after_utc,
        }

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
#
# The bundle is located the same way the TDX clients located qe_identity.json:
# $TEE_CRAFTER_TCB_COLLATERAL, else a file beside this script, else
# /etc/tee_crafter/.  See the shared module's docstring for the schema.

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
    this script, and the deploy runs ``python3 client_sgx.py ...`` from there,
    so that directory is ``sys.path[0]`` and the plain import succeeds.  The
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


def enforce_platform_tcb_status(quote_bytes: bytes, pck_result: dict) -> None:
    """Evaluate the platform's Intel TCB status.  Any failure is fatal.

    SGX v3 layout: the report body starts at 48, so CPUSVN is
    ``quote_bytes[48:64]``, and the QE report is the fixed 384 bytes at 564
    (see ``verify_dcap_quote_signature`` for the full signature layout).
    """
    try:
        tcb = load_tcb_eval_module()
        tcb.enforce(
            tee="sgx",
            pck_chain=pck_result.get("pck_chain") or [],
            qe_report=quote_bytes[564:948],
            report_cpusvn=quote_bytes[48:64],
            pinned_root_ca_pem=_INTEL_SGX_ROOT_CA_PEM,
            check_leaf_certificate=check_leaf_certificate,
            check_ca_certificate=check_ca_certificate,
        )
    except SystemExit:
        raise
    except Exception as exc:
        print("FATAL: platform TCB status evaluation failed: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)


def require_pinned_measurements() -> None:
    """Refuse to run against an enclave whose identity was never pinned.

    The build fills ``EXPECTED_MRENCLAVE``/``EXPECTED_MRSIGNER`` from
    ``gramine-sgx-sign``.  When Gramine is not installed on the build host both
    render as ``"unknown"``, and the client used to pin whatever the first
    quote happened to carry — trust on first use, which leaves the very
    connection an attacker would target unauthenticated.  Fail closed instead;
    operators who genuinely want TOFU (a throwaway dev enclave) opt in.
    """
    unresolved = [
        name for name, value in (("MRENCLAVE", EXPECTED_MRENCLAVE),
                                 ("MRSIGNER", EXPECTED_MRSIGNER))
        if not value or value == "unknown"
    ]
    if not unresolved:
        return

    names = " and ".join(unresolved)
    if os.environ.get("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT") == "1":
        bar = "*" * 78
        print(bar, file=sys.stderr)
        print(f"WARNING: {names} unresolved and "
              "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 is set.", file=sys.stderr)
        print("This client will trust the first enclave it meets and cannot tell",
              file=sys.stderr)
        print("the intended enclave from an impostor.  Never use in production.",
              file=sys.stderr)
        print(bar, file=sys.stderr)
        return

    print(f"FATAL: {names} unresolved ('unknown').  The build host could not run "
          "gramine-sgx-sign, so this client has no enclave identity to pin and "
          "would trust whatever answers on the port.  Rebuild on a host with "
          "Gramine installed, or set TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 to "
          "accept trust-on-first-use.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# AUD-3: the audit log's genesis commitment must be inside report_data
# ---------------------------------------------------------------------------
#
# The in-TEE audit log is an HMAC hash chain keyed by a secret that never
# leaves enclave memory, and the enclave publishes SHA-256(key) as the "chain
# key commitment".  On its own that commitment is self-referential — it lives
# in the log's own genesis entry, so a host that discards the log regenerates
# key, genesis, chain and commitment together and nothing contradicts it.  The
# enclave therefore hashes the commitment into the DCAP quote's report_data;
# this client recomputes the preimage and refuses the connection when it does
# not match, which is what turns "the log claims a commitment" into "the
# hardware signed this commitment".
#
# These four must stay byte-identical to sgx/app_gramine.template.py.  The
# label and the encoder are shared with the SNP clients so there is exactly one
# preimage format in the tree; the purpose string is what separates this
# binding (the RA-TLS certificate's embedded quote, sgx) from theirs.
_ATTEST_BINDING_LABEL = b"tee-crafter/attest-binding/v2"
_CERT_BINDING_PURPOSE = b"ratls-cert-report-data/sgx"
_EXPECTED_CERT_REPORT_DATA_BINDING = (
    "sha256(lp('tee-crafter/attest-binding/v2') || uint32be(3) || "
    "lp('ratls-cert-report-data/sgx') || lp(ecdh_pub) || "
    "lp(chain_key_commitment_hex_ascii))")
_ALLOW_UNBOUND_AUDIT_CHAIN_ENV = "TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN"


def _attest_binding_preimage(*fields: bytes) -> bytes:
    """Rebuild the enclave's attestation-binding preimage.

    Raw concatenation of variable-length fields is ambiguous —
    ``a=b"ab", b=b"cd"`` and ``a=b"abc", b=b"d"`` produce identical bytes — so
    evidence minted against one field split could be presented as satisfying a
    different one.  Every field therefore carries its own big-endian uint32
    length prefix, the field *count* is prefixed as well (so a short field list
    cannot be padded out into a longer one), and a version label is hashed in so
    a v1 preimage — bare ``sha256(ecdh_pub)``, which carried no commitment —
    can never be reinterpreted as a v2 one.  This must stay byte-for-byte
    identical to ``_attest_binding_preimage`` in sgx/app_gramine.template.py.
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

    *declared* is the ``chain_key_commitment`` the enclave published alongside
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
            print("WARNING: the enclave declared no runtime audit-log chain-key",
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
            "the enclave declared no runtime audit-log chain-key commitment "
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
                               enclave_pub_bytes: bytes) -> tuple:
    """Verify report_data[:32] against the v2 preimage.  Returns ``(ok, reason)``.

    Fails closed on every unexpected shape: an enclave that omits or misstates
    the binding descriptor is refused outright, and the commitment itself must
    be a 64-character SHA-256 hex digest or explicitly opted out of.
    """
    binding = (att_resp or {}).get("cert_report_data_binding") or ""
    if binding != _EXPECTED_CERT_REPORT_DATA_BINDING:
        return False, (
            "the enclave did not describe its certificate quote's report_data "
            f"preimage as {_EXPECTED_CERT_REPORT_DATA_BINDING!r} (got "
            f"{binding!r}). Client and enclave must be built from the same "
            "commit: a pre-v2 enclave binds only SHA-256(ECDH pubkey) and "
            "carries no hardware-signed audit-chain commitment, which is the "
            "thing this check exists to establish."
        )

    commitment_ascii, commitment_error = resolve_chain_key_commitment(
        (att_resp or {}).get("chain_key_commitment", ""))
    if commitment_error:
        return False, commitment_error

    expected = _attest_binding_digest(
        _CERT_BINDING_PURPOSE, enclave_pub_bytes, commitment_ascii)
    if report_data[:32] != expected:
        return False, (
            "report_data is not SHA-256 of the v2 preimage (purpose, ECDH "
            "pubkey, chain_key_commitment) — either the ECDH public key or the "
            "audit-chain commitment is not the one the hardware signed (quote "
            f"carries {report_data[:32].hex()}, recomputed {expected.hex()})"
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


def verify_ratls_connection(host: str, port: int, ratls_nonce: bytes | None = None) -> ssl.SSLSocket:
    """
    Connect to the enclave server via TLS. Extract the RA-TLS
    certificate's embedded DCAP quote and perform full verification:
      1. ECDSA signature over quote header+report (tamper detection)
      2. MRENCLAVE / MRSIGNER identity matching
      3. QE report binding (attestation key hashed into the QE report)
      4. PCK certificate chain to Intel Root CA
      5. QE report signature by the PCK leaf key — the only link that ties
         the attestation key to Intel-provisioned hardware

    Aborts on any verification failure — no fallback to unattested mode.

    ``ratls_nonce`` is round-tripped into ``ATTESTATION_REPORT`` for
    audit correlation; RA-TLS itself binds freshness via report_data
    not via an external nonce.
    """
    require_pinned_measurements()

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

    quote_info = parse_sgx_quote(quote_bytes)

    print(f"  Quote version:  {quote_info['version']}", file=sys.stderr)
    print(f"  MRENCLAVE:      {quote_info['mrenclave']}", file=sys.stderr)
    print(f"  MRSIGNER:       {quote_info['mrsigner']}", file=sys.stderr)
    print(f"  ISV_PROD_ID:    {quote_info['isv_prod_id']}", file=sys.stderr)
    print(f"  ISV_SVN:        {quote_info['isv_svn']}", file=sys.stderr)

    # 1. Reject debug enclaves
    if quote_info.get("flags_debug"):
        conn.close()
        print(f"FATAL: SGX FLAGS.DEBUG is set (flags=0x{quote_info.get('flags', 0):016X}) — "
              "refusing connection to debug enclave in production.", file=sys.stderr)
        sys.exit(1)
    print("  SGX FLAGS.DEBUG: CLEAR (production enclave)", file=sys.stderr)

    # 2. Verify ECDSA signature over quote body
    print("Verifying DCAP quote ECDSA signature...", file=sys.stderr)
    if not verify_dcap_quote_signature(quote_bytes):
        conn.close()
        print("FATAL: DCAP quote ECDSA signature verification FAILED.", file=sys.stderr)
        sys.exit(1)
    print("  DCAP quote signature: PASSED", file=sys.stderr)

    # 3. Verify MRENCLAVE
    if EXPECTED_MRENCLAVE and EXPECTED_MRENCLAVE != "unknown":
        if quote_info["mrenclave"] != EXPECTED_MRENCLAVE:
            conn.close()
            print(f"FATAL: MRENCLAVE mismatch! Expected {EXPECTED_MRENCLAVE}, "
                  f"got {quote_info['mrenclave']}", file=sys.stderr)
            sys.exit(1)
        print("  MRENCLAVE verification: PASSED", file=sys.stderr)

    # 4. Verify MRSIGNER
    if EXPECTED_MRSIGNER and EXPECTED_MRSIGNER != "unknown":
        if quote_info["mrsigner"] != EXPECTED_MRSIGNER:
            conn.close()
            print(f"FATAL: MRSIGNER mismatch! Expected {EXPECTED_MRSIGNER}, "
                  f"got {quote_info['mrsigner']}", file=sys.stderr)
            sys.exit(1)
        print("  MRSIGNER verification: PASSED", file=sys.stderr)

    # 5. Verify QE report binding (attestation key hash)
    print("Verifying QE report binding...", file=sys.stderr)
    if verify_qe_report_binding(quote_bytes):
        print("  QE report binding: PASSED", file=sys.stderr)
    else:
        raise RuntimeError("QE report binding verification failed — attestation key authenticity cannot be confirmed")

    # 6. Verify PCK certificate chain against Intel Root CA
    print("Verifying PCK certificate chain...", file=sys.stderr)
    pck_result = verify_pck_cert_chain(quote_bytes)
    if not pck_result.get("ok"):
        conn.close()
        print("FATAL: PCK certificate chain verification FAILED. "
              "Cannot verify hardware root of trust.", file=sys.stderr)
        sys.exit(1)

    # 7. Verify the QE report is signed by the PCK leaf key.  Steps 2 and 5
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

    # 8. Evaluate the platform's Intel TCB status against signed PCS
    #    collateral.  Steps 2-7 prove the hardware; this is the step that says
    #    the hardware is still trusted by Intel.  Fatal on any failure.
    print("Evaluating platform TCB status (Intel PCS collateral)...",
          file=sys.stderr)
    enforce_platform_tcb_status(quote_bytes, pck_result)

    # AUD-7 / ATT-006 / ATT-007: structured ATTESTATION_REPORT line.
    try:
        spki = _spki_sha256_from_der(cert_der)
    except Exception:
        spki = ""
    try:
        attestation_report = {
            "platform": "sgx",
            "issuer": "intel-sgx",
            "report_kind": "dcap",
            "quote_signature_alg": "ECDSA_P256_SHA256",
            "mrenclave": quote_info.get("mrenclave", ""),
            "mrsigner": quote_info.get("mrsigner", ""),
            "isvprodid": quote_info.get("isv_prod_id", 0),
            "isvsvn": quote_info.get("isv_svn", 0),
            "tcb_svn": quote_info.get("tcb_svn", ""),
            "nonce_binding": quote_info.get("report_data_hex", ""),
            "nonce": (ratls_nonce or b"").hex(),
            "spki_sha256": spki,
        }
        print(f"ATTESTATION_REPORT {json.dumps(attestation_report, separators=(',', ':'))}")
    except Exception as _att_err:
        print(f"WARN: failed to emit ATTESTATION_REPORT line: {type(_att_err).__name__}: {_att_err}", file=sys.stderr)

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
        print("Usage: python3 client_sgx.py <host_ip> [port]", file=sys.stderr)
        sys.exit(1)

    host_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5005

    # Phase 1: RA-TLS verification + attestation request on the SAME connection.
    # The enclave server is single-threaded; opening a connection without
    # sending data blocks the server in recv() and prevents subsequent
    # connections from being accepted (deadlock through Bastion tunnels).
    ratls_nonce = os.urandom(32)
    print(f"Connecting to SGX enclave at {host_ip}:{port} via RA-TLS...", file=sys.stderr)
    try:
        conn, quote_info = verify_ratls_connection(host_ip, port, ratls_nonce=ratls_nonce)
        print("RA-TLS Attestation Verification Passed!", file=sys.stderr)
    except Exception as e:
        print(f"Failed to establish RA-TLS connection: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)

    report_data_bytes = quote_info["report_data"]

    # Self-pin MRENCLAVE/MRSIGNER for the remaining phases.  Values injected by
    # the build already matched above; they can only still be "unknown" here if
    # the operator set TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 (see
    # require_pinned_measurements), in which case pinning from this attested
    # quote at least locks later connections to the same enclave binary.
    global EXPECTED_MRENCLAVE, EXPECTED_MRSIGNER
    if (not EXPECTED_MRENCLAVE or EXPECTED_MRENCLAVE == "unknown") and quote_info.get("mrenclave"):
        EXPECTED_MRENCLAVE = quote_info["mrenclave"]
        print(f"  Self-pinned MRENCLAVE from attested quote: {EXPECTED_MRENCLAVE[:16]}...", file=sys.stderr)
    if (not EXPECTED_MRSIGNER or EXPECTED_MRSIGNER == "unknown") and quote_info.get("mrsigner"):
        EXPECTED_MRSIGNER = quote_info["mrsigner"]
        print(f"  Self-pinned MRSIGNER from attested quote: {EXPECTED_MRSIGNER[:16]}...", file=sys.stderr)

    print("Requesting enclave public key via attested connection...", file=sys.stderr)
    try:
        att_resp = send_request(conn, {"action": "get_attestation", "nonce": base64.b64encode(os.urandom(32)).decode()})
        enclave_pub_b64 = att_resp.get("enclave_public_key")
        if not enclave_pub_b64:
            print("FATAL: Enclave did not provide its public key.", file=sys.stderr)
            sys.exit(1)
        enclave_pub_bytes = base64.b64decode(enclave_pub_b64)
    except Exception as e:
        print(f"Failed to get enclave public key: {type(e).__name__}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Verify report_data[:32] against the v2 preimage: it binds both the ECDH
    # public key (so the ECIES layer belongs to this enclave) and the runtime
    # audit log's genesis commitment (so the log is anchored to hardware).
    print("Verifying report_data binding (ECDH key + audit-chain commitment)...",
          file=sys.stderr)
    ok, reason = verify_report_data_binding(
        report_data_bytes, att_resp, enclave_pub_bytes)
    if not ok:
        print(f"FATAL: report_data binding failed: {reason}", file=sys.stderr)
        sys.exit(1)
    print("  Enclave public key binding: PASSED", file=sys.stderr)
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
