"""Intel DCAP quote verification, per rendered SGX / TDX client.

These tests render the real ``sgx/client.template.py`` and
``tdx/{azure,gcp}/client.template.py`` templates, import the result, and drive
the verifiers directly.

Every fixture is built from first principles here: the quote layouts are
written out from the Intel SGX/TDX DCAP structure definitions (offsets
cross-checked against the layout tables in the templates' own docstrings) and
the certificates are minted with ``cryptography`` rather than borrowed from the
module under test.  The bugs these tests cover — an unverified
``qe_report_sig``, an ``"absent"`` tri-state derived from a length check on
attacker input, and a verifier selected by the server's own first four bytes —
all survived earlier coverage that shared the code's assumptions.

The templates are rendered here rather than through
``core/builder/platforms.render_*`` so the trust anchor under test is the file
these clients are meant to pin (``certs/intel-sgx-dcap-root.pem``) regardless
of which anchor the central loader currently injects.
"""
from __future__ import annotations

import datetime
import hashlib
import importlib.util
import os
import struct
import sys
import types
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

import tee_crafter

_PKG_DIR = os.path.dirname(os.path.abspath(tee_crafter.__file__))
_TEMPLATES = os.path.join(_PKG_DIR, "templates")
_CERTS = os.path.join(_PKG_DIR, "certs")


# --------------------------------------------------------------------------
# DCAP quote layouts, written out independently of the code under test
# --------------------------------------------------------------------------
# SGX DCAP v3 (sgx_quote3_t + sgx_ql_ecdsa_sig_data_t):
#   0    quote header               48 bytes
#   48   sgx_report_body_t          384 bytes   -> signed data ends at 432
#   432  sig_data_len               uint32
#   436  isv_enclave_report_sig     64 bytes  (r || s)
#   500  ecdsa_attestation_key      64 bytes  (x || y)
#   564  qe_report_body             384 bytes
#   948  qe_report_sig              64 bytes  (r || s)
#   1012 qe_auth_data_size          uint16
#   1014 qe_auth_data               qe_auth_data_size bytes
#   ...  cert_data_type             uint16
#   ...  cert_data_size             uint32
#   ...  cert_data                  cert_data_size bytes (PEM chain when type 5)
SGX_SIGNED_LEN = 432
SGX_QE_REPORT_OFFSET = 564
SGX_QE_REPORT_SIG_OFFSET = 948

# TDX DCAP v4 (sgx_quote4_t): the TD report body is 584 bytes, and the ECDSA
# sig-data is wrapped in an outer cert-data header (type + size = 6 bytes)
# immediately after the attestation key, inside which the QE report sits.
#   0    quote header               48 bytes
#   48   TD report body             584 bytes   -> signed data ends at 632
#   632  sig_data_len               uint32
#   636  td_report_sig              64 bytes
#   700  ecdsa_attestation_key      64 bytes
#   764  outer cert_data_type       uint16 (6 = QE_REPORT_CERTIFICATION_DATA)
#   766  outer cert_data_size       uint32
#   770  qe_report_body             384 bytes
#   1154 qe_report_sig              64 bytes
#   1218 qe_auth_data_size          uint16 ...
TDX_SIGNED_LEN = 632
TDX_QE_REPORT_OFFSET = 770
TDX_QE_REPORT_SIG_OFFSET = 1154

REPORT_BODY_REPORT_DATA_OFFSET = 320  # within any 384-byte sgx_report_body_t


# --------------------------------------------------------------------------
# Rendered clients
# --------------------------------------------------------------------------

def _dcap_root_pem() -> str:
    with open(os.path.join(_CERTS, "intel-sgx-dcap-root.pem"), encoding="utf-8") as f:
        return f.read().strip()


def _epid_root_pem() -> str:
    """Synthesise a stand-in for the retired Intel EPID/IAS root.

    The real ``CN=Intel SGX Attestation Report Signing CA`` used to ship in
    ``certs/`` and was wired in as the DCAP anchor, which it can never be: DCAP
    PCK certificates chain to ``CN=Intel SGX Root CA``. It has been deleted from
    the repository so nobody re-adopts it by accident.

    The regression it guards is still worth testing, so we build an equivalent
    here rather than reading a file that must no longer exist. What matters is
    the shape that defeated the old chain walk: an **RSA** root, whose key type
    made the ``isinstance(..., EllipticCurvePublicKey)`` guard skip the
    anchoring step while the function still reported success.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
        x509.NameAttribute(
            NameOID.COMMON_NAME, "Intel SGX Attestation Report Signing CA",
        ),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()


def _nvidia_intermediate_pem() -> str:
    with open(os.path.join(_CERTS, "nvidia-nras-intermediate.pem"),
              encoding="utf-8") as f:
        return f.read().strip()


def _render(relpath: str, subs: dict) -> str:
    with open(os.path.join(_TEMPLATES, relpath), encoding="utf-8") as f:
        source = f.read()
    for token, value in subs.items():
        source = source.replace(token, value)
    left = [t for t in ("{mrenclave}", "{mrsigner}", "{mrtd}", "{intel_root_ca}",
                        "{intel_sgx_root_ca}", "{container_digest}",
                        "{nvidia_root_ca}", "{expected_vtpm_pcrs}")
            if t in source]
    assert not left, f"unsubstituted placeholders in {relpath}: {left}"
    return source


def _import_source(source: str, tmp_path, stem: str):
    path = tmp_path / f"{stem}_{uuid.uuid4().hex}.py"
    path.write_text(source, encoding="utf-8")
    mod_name = path.stem
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(mod_name, None)
    return module


def _sgx_client(tmp_path, *, mrenclave="ab" * 32, mrsigner="cd" * 32, root_pem=None):
    source = _render("sgx/client.template.py", {
        "{mrenclave}": mrenclave,
        "{mrsigner}": mrsigner,
        "{intel_sgx_root_ca}": root_pem if root_pem is not None else _dcap_root_pem(),
    })
    return _import_source(source, tmp_path, "rendered_sgx_client")


def _tdx_client(cloud: str, tmp_path, *, mrtd="ef" * 48, root_pem=None,
                evidence_format="dcap"):
    """Render a TDX client.

    ``evidence_format`` mirrors ``platforms.tdx_evidence_format()`` and only
    applies to ``tdx-azure`` -- the ``tdx/gcp`` template has no such
    placeholder, and ``str.replace`` on an absent key is a no-op.
    """
    source = _render(f"tdx/{cloud}/client.template.py", {
        "{mrtd}": mrtd,
        "{container_digest}": "",
        "{evidence_format}": evidence_format,
        "{intel_root_ca}": root_pem if root_pem is not None else _dcap_root_pem(),
    })
    # Stage the client-support modules beside the rendered client, exactly as
    # `copy_client_support_modules` does in a real build.  Without this the
    # HCLA path dies on "tee_crafter_maa.py is neither beside this client nor
    # on sys.path" before reaching any verification logic -- which is a real
    # fail-closed behaviour, but not the one these tests are about.
    from tee_crafter.core.builder.runtime_modules import copy_client_support_modules
    copy_client_support_modules(str(tmp_path))
    return _import_source(source, tmp_path, f"rendered_tdx_{cloud}_client")


@pytest.fixture(scope="module")
def sgx_client(tmp_path_factory):
    return _sgx_client(tmp_path_factory.mktemp("sgx_client"))


@pytest.fixture(scope="module")
def tdx_gcp_client(tmp_path_factory):
    return _tdx_client("gcp", tmp_path_factory.mktemp("tdx_gcp_client"))


@pytest.fixture(scope="module")
def tdx_azure_client(tmp_path_factory):
    return _tdx_client("azure", tmp_path_factory.mktemp("tdx_azure_client"))


def _gpu_cc_gcp_client(tmp_path, *, mrtd="ef" * 48, root_pem=None):
    """Render and import ``gpu_cc/gcp/client.template.py``.

    This platform's absence from this file is why a **complete CPU-side
    attestation bypass** survived two audit passes: ``gpu-cc-gcp`` runs the
    same Intel TDX DCAP quote path as ``tdx-gcp`` but had no
    ``verify_qe_report_signature`` at all, and "the DCAP tests pass" was never
    a statement about it.  The fixture takes the same shape as
    :func:`_tdx_client` so every quote-level test below can be pointed at it
    without special-casing.
    """
    source = _render("gpu_cc/gcp/client.template.py", {
        "{mrtd}": mrtd,
        "{container_digest}": "",
        "{expected_vtpm_pcrs}": "",
        "{intel_root_ca}": root_pem if root_pem is not None else _dcap_root_pem(),
        "{nvidia_root_ca}": _nvidia_intermediate_pem(),
    })
    return _import_source(source, tmp_path, "rendered_gpu_cc_gcp_client")


@pytest.fixture(scope="module")
def gpu_cc_gcp_client(tmp_path_factory):
    return _gpu_cc_gcp_client(tmp_path_factory.mktemp("gpu_cc_gcp_client"))


# --------------------------------------------------------------------------
# Attacker-built certificates and quotes
# --------------------------------------------------------------------------

#: Why every attacker cert below carries basicConstraints.
#:
#: Without it the verifiers reject the rogue chain at "issuer certificate [1]
#: has no basicConstraints extension, so it is not a CA" — a *structural*
#: complaint that never reaches the anchoring step.  The chain-rejection tests
#: then passed while asserting, in their own docstrings, that the walk to the
#: pinned Intel root was what rejected them.  It was not.  A well-formed rogue
#: chain forces the rejection to come from the pinned key, which is the claim
#: these tests exist to make.
def _self_signed(key, common_name: str, *, ca: bool = True) -> x509.Certificate:
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                       critical=True)
    )
    return builder.sign(key, hashes.SHA256())


def _issued_by(issuer_key, issuer_cert, subject_key, common_name: str,
               *, ca: bool = False) -> x509.Certificate:
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                       critical=True)
    )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _raw_sig(key, message: bytes) -> bytes:
    """ECDSA-P256 signature as the 64-byte r || s form DCAP quotes carry."""
    r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _public_xy(key) -> bytes:
    nums = key.public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _report_body(*, report_data: bytes = b"", size: int = 384) -> bytearray:
    body = bytearray(size)
    body[REPORT_BODY_REPORT_DATA_OFFSET:REPORT_BODY_REPORT_DATA_OFFSET + len(report_data)] = report_data
    return body


def _cert_chain_blob(certs) -> bytes:
    return b"".join(_pem(c) for c in certs)


def _sgx_quote(*, att_key: ec.EllipticCurvePrivateKey, pck_key, chain_pem: bytes,
               qe_auth: bytes = b"authdata", enclave_report: bytes | None = None,
               bind_attestation_key: bool = True) -> bytes:
    """Assemble an SGX DCAP v3 quote whose every internal check is consistent."""
    header = bytearray(48)
    struct.pack_into("<H", header, 0, 3)      # version
    struct.pack_into("<H", header, 2, 2)      # att_key_type = ECDSA-P256
    struct.pack_into("<I", header, 4, 0)      # tee_type = SGX

    body = bytearray(enclave_report if enclave_report is not None else _report_body())
    struct.pack_into("<Q", body, 48, 0x1)     # attributes.FLAGS: INIT set, DEBUG clear

    signed = bytes(header) + bytes(body)
    assert len(signed) == SGX_SIGNED_LEN

    att_key_xy = _public_xy(att_key)
    enclave_sig = _raw_sig(att_key, signed)

    qe_report = _report_body()
    if bind_attestation_key:
        digest = hashlib.sha256(att_key_xy + qe_auth).digest()
        qe_report[REPORT_BODY_REPORT_DATA_OFFSET:REPORT_BODY_REPORT_DATA_OFFSET + 32] = digest
    qe_report = bytes(qe_report)
    qe_sig = _raw_sig(pck_key, qe_report)

    tail = (struct.pack("<H", len(qe_auth)) + qe_auth
            + struct.pack("<H", 5) + struct.pack("<I", len(chain_pem)) + chain_pem)
    sig_data = enclave_sig + att_key_xy + qe_report + qe_sig + tail

    quote = signed + struct.pack("<I", len(sig_data)) + sig_data
    assert quote[SGX_QE_REPORT_OFFSET:SGX_QE_REPORT_OFFSET + 384] == qe_report
    assert quote[SGX_QE_REPORT_SIG_OFFSET:SGX_QE_REPORT_SIG_OFFSET + 64] == qe_sig
    return quote


def _tdx_quote(*, att_key: ec.EllipticCurvePrivateKey, pck_key, chain_pem: bytes,
               qe_auth: bytes = b"authdata", bind_attestation_key: bool = True) -> bytes:
    """Assemble a TDX DCAP v4 quote with QE_REPORT_CERTIFICATION_DATA wrapping."""
    header = bytearray(48)
    struct.pack_into("<H", header, 0, 4)         # version
    struct.pack_into("<H", header, 2, 2)         # att_key_type
    struct.pack_into("<I", header, 4, 0x81)      # tee_type = TDX

    td_body = bytearray(584)
    td_body[0] = 1                               # TEE_TCB_SVN[0] — TDX module major
    td_body[1] = 5                               # TEE_TCB_SVN[1] — TDX module minor

    signed = bytes(header) + bytes(td_body)
    assert len(signed) == TDX_SIGNED_LEN

    att_key_xy = _public_xy(att_key)
    td_sig = _raw_sig(att_key, signed)

    qe_report = _report_body()
    if bind_attestation_key:
        digest = hashlib.sha256(att_key_xy + qe_auth).digest()
        qe_report[REPORT_BODY_REPORT_DATA_OFFSET:REPORT_BODY_REPORT_DATA_OFFSET + 32] = digest
    qe_report = bytes(qe_report)
    qe_sig = _raw_sig(pck_key, qe_report)

    inner = (qe_report + qe_sig
             + struct.pack("<H", len(qe_auth)) + qe_auth
             + struct.pack("<H", 5) + struct.pack("<I", len(chain_pem)) + chain_pem)
    sig_data = (td_sig + att_key_xy
                + struct.pack("<H", 6) + struct.pack("<I", len(inner)) + inner)

    quote = signed + struct.pack("<I", len(sig_data)) + sig_data
    assert quote[TDX_QE_REPORT_OFFSET:TDX_QE_REPORT_OFFSET + 384] == qe_report
    assert quote[TDX_QE_REPORT_SIG_OFFSET:TDX_QE_REPORT_SIG_OFFSET + 64] == qe_sig
    return quote


@pytest.fixture(scope="module")
def rogue():
    """A complete attacker-controlled PCK chain, self-consistent but unrelated
    to Intel's root.  The root even borrows Intel's CN, so passing the chain
    walk has to depend on the pinned key rather than on the name."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    pck_key = ec.generate_private_key(ec.SECP256R1())
    root = _self_signed(root_key, "Intel SGX Root CA")
    inter = _issued_by(root_key, root, inter_key, "Intel SGX PCK Platform CA",
                       ca=True)
    leaf = _issued_by(inter_key, inter, pck_key, "Intel SGX PCK Certificate")
    return types.SimpleNamespace(
        root_key=root_key, pck_key=pck_key, root=root, leaf=leaf,
        chain_pem=_cert_chain_blob([leaf, inter, root]),
        # Same leaf and intermediate with the attacker's root omitted.  With
        # only two certs the verifier appends the *pinned* Intel root as the
        # anchor, so the path length is legal and every structural check
        # passes — the rejection then has to come from Intel's root key
        # failing to verify the attacker's intermediate.  The three-cert blob
        # above never reaches that step (it trips Intel's pathLenConstraint
        # first), so on its own it cannot demonstrate the signature check
        # works at all.
        unrooted_chain_pem=_cert_chain_blob([leaf, inter]),
    )


# --------------------------------------------------------------------------
# FIX 1 — qe_report_sig must be verified against the PCK leaf
# --------------------------------------------------------------------------

class TestQeReportSignature:
    def test_sgx_accepts_the_leaf_that_actually_signed_the_qe_report(self, sgx_client, rogue):
        """Positive control: proves the 564/948 offsets address the real fields."""
        quote = _sgx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        assert sgx_client.verify_qe_report_signature(quote, rogue.leaf) is True

    def test_sgx_rejects_a_leaf_that_did_not_sign_the_qe_report(self, sgx_client, rogue):
        other_key = ec.generate_private_key(ec.SECP256R1())
        other_leaf = _self_signed(other_key, "Intel SGX PCK Certificate")
        quote = _sgx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        assert sgx_client.verify_qe_report_signature(quote, other_leaf) is False

    def test_sgx_rejects_a_tampered_qe_report(self, sgx_client, rogue):
        quote = bytearray(_sgx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                                     pck_key=rogue.pck_key, chain_pem=rogue.chain_pem))
        quote[SGX_QE_REPORT_OFFSET] ^= 0xFF
        assert sgx_client.verify_qe_report_signature(bytes(quote), rogue.leaf) is False

    def test_tdx_gcp_accepts_the_leaf_that_actually_signed_the_qe_report(
            self, tdx_gcp_client, rogue):
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        assert tdx_gcp_client.verify_qe_report_signature(quote, rogue.leaf) is True

    def test_tdx_gcp_rejects_a_leaf_that_did_not_sign_the_qe_report(
            self, tdx_gcp_client, rogue):
        other_leaf = _self_signed(ec.generate_private_key(ec.SECP256R1()),
                                  "Intel SGX PCK Certificate")
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        assert tdx_gcp_client.verify_qe_report_signature(quote, other_leaf) is False

    def test_tdx_azure_rejects_a_leaf_that_did_not_sign_the_qe_report(
            self, tdx_azure_client, rogue):
        other_leaf = _self_signed(ec.generate_private_key(ec.SECP256R1()),
                                  "Intel SGX PCK Certificate")
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        assert tdx_azure_client.verify_qe_report_signature(quote, other_leaf) is False

    # gpu-cc-gcp: the platform that had no verify_qe_report_signature at all.
    # Positive control first, because the bypass was closed by adding the
    # function — a rejection test alone would also pass against a stub that
    # rejects everything.
    def test_gpu_cc_gcp_accepts_the_leaf_that_actually_signed_the_qe_report(
            self, gpu_cc_gcp_client, rogue):
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        assert gpu_cc_gcp_client.verify_qe_report_signature(quote, rogue.leaf) is True

    def test_gpu_cc_gcp_rejects_a_leaf_that_did_not_sign_the_qe_report(
            self, gpu_cc_gcp_client, rogue):
        other_leaf = _self_signed(ec.generate_private_key(ec.SECP256R1()),
                                  "Intel SGX PCK Certificate")
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        assert gpu_cc_gcp_client.verify_qe_report_signature(quote, other_leaf) is False

    def test_gpu_cc_gcp_rejects_a_tampered_qe_report(self, gpu_cc_gcp_client, rogue):
        quote = bytearray(_tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                                     pck_key=rogue.pck_key,
                                     chain_pem=rogue.chain_pem))
        quote[TDX_QE_REPORT_OFFSET] ^= 0xFF
        assert gpu_cc_gcp_client.verify_qe_report_signature(
            bytes(quote), rogue.leaf) is False


class TestFabricatedQuoteIsRejected:
    """A wholly attacker-built quote: fabricated attestation key, matching QE
    binding, and a valid-but-unrelated PCK chain.  Every self-referential check
    passes; the chain walk to the pinned Intel root is what must reject it."""

    def test_sgx_self_referential_checks_pass_but_the_chain_does_not(
            self, sgx_client, rogue):
        quote = _sgx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)

        assert sgx_client.verify_dcap_quote_signature(quote) is True
        assert sgx_client.verify_qe_report_binding(quote) is True

        result = sgx_client.verify_pck_cert_chain(quote)
        assert result["ok"] is False, (
            "an attacker-minted chain, even one whose root borrows Intel's CN, "
            "must not validate against the pinned Intel SGX Root CA"
        )
        assert "pck_leaf" not in result

    def test_tdx_gcp_self_referential_checks_pass_but_the_chain_does_not(
            self, tdx_gcp_client, rogue):
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)

        assert tdx_gcp_client.verify_tdx_quote_signature(quote) is True
        assert tdx_gcp_client.verify_qe_report_binding(quote) is True
        assert tdx_gcp_client.verify_pck_cert_chain(quote)["ok"] is False

    def test_tdx_azure_self_referential_checks_pass_but_the_chain_does_not(
            self, tdx_azure_client, rogue):
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)

        assert tdx_azure_client.verify_tdx_quote_signature(quote) is True
        assert tdx_azure_client.verify_qe_report_binding(quote) is True
        assert tdx_azure_client.verify_pck_cert_chain(quote)["ok"] is False

    def test_gpu_cc_gcp_self_referential_checks_pass_but_the_chain_does_not(
            self, gpu_cc_gcp_client, rogue):
        """The exact shape of the bypass this platform used to have.

        ``verify_tdx_quote_signature`` and ``verify_qe_report_binding`` both
        read from the same attacker-supplied quote, so both pass on a wholly
        fabricated one.  With no QE-report signature check and a chain walk
        that discarded the leaf, nothing tied that quote to Intel silicon.
        """
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)

        assert gpu_cc_gcp_client.verify_tdx_quote_signature(quote) is True
        assert gpu_cc_gcp_client.verify_qe_report_binding(quote) is True

        result = gpu_cc_gcp_client.verify_pck_cert_chain(quote)
        assert result["ok"] is False
        # The leaf must not leak out of a failed walk: returning it was what
        # let a caller "verify" the QE report against an attacker's own leaf.
        assert "pck_leaf" not in result


class TestRejectionReachesThePinnedRoot:
    """Pin *why* a rogue chain is refused, not just that it is.

    Every ``verify_pck_cert_chain`` rejection test in this file used to assert
    only ``ok is False``, while the docstrings claimed the walk to the pinned
    Intel root was what rejected the chain.  It was not: the attacker certs
    carried no ``basicConstraints``, so the walk stopped at "not a CA" long
    before any Intel key was used.  Fixing the fixture then exposed a second
    early exit (Intel's ``pathLenConstraint``).  Neither of those depends on
    the pinned *key*, so neither would notice if the anchoring signature check
    were removed — the exact defect class this file exists to catch.

    Two certs (leaf + intermediate, attacker root omitted) is the shape that
    forces the decisive step to be Intel's root key verifying the attacker's
    intermediate.
    """

    @staticmethod
    def _chain_result(client, rogue, *, sgx: bool):
        builder = _sgx_quote if sgx else _tdx_quote
        quote = builder(att_key=ec.generate_private_key(ec.SECP256R1()),
                        pck_key=rogue.pck_key,
                        chain_pem=rogue.unrooted_chain_pem)
        return client.verify_pck_cert_chain(quote)

    def test_sgx_rejects_at_the_pinned_root_signature(self, sgx_client, rogue):
        result = self._chain_result(sgx_client, rogue, sgx=True)
        assert result["ok"] is False
        assert result["reason"] == "InvalidSignature", (
            "expected the pinned Intel root's signature check to be the step "
            f"that refused the chain, got {result['reason']!r}")

    def test_tdx_gcp_rejects_at_the_pinned_root_signature(self, tdx_gcp_client, rogue):
        result = self._chain_result(tdx_gcp_client, rogue, sgx=False)
        assert result["ok"] is False
        assert result["reason"] == "InvalidSignature", result["reason"]

    def test_tdx_azure_rejects_at_the_pinned_root_signature(self, tdx_azure_client, rogue):
        result = self._chain_result(tdx_azure_client, rogue, sgx=False)
        assert result["ok"] is False
        assert result["reason"] == "InvalidSignature", result["reason"]

    def test_gpu_cc_gcp_rejects_at_the_pinned_root_signature(self, gpu_cc_gcp_client, rogue):
        result = self._chain_result(gpu_cc_gcp_client, rogue, sgx=False)
        assert result["ok"] is False
        assert result["reason"] == "InvalidSignature", result["reason"]

    @pytest.mark.parametrize("client_fixture,sgx", [
        ("sgx_client", True),
        ("tdx_gcp_client", False),
        ("tdx_azure_client", False),
        ("gpu_cc_gcp_client", False),
    ])
    def test_no_rejection_has_an_empty_reason(self, request, client_fixture, sgx, rogue):
        """``str(InvalidSignature())`` is ``""``.

        The anchoring failure therefore reported no reason at all and printed
        ``FAILED ()`` — the operator was told the chain was refused but not
        that it failed to chain to Intel.  A rejection an operator cannot act
        on is most of the way to no rejection at all.
        """
        client = request.getfixturevalue(client_fixture)
        builder = _sgx_quote if sgx else _tdx_quote
        good = builder(att_key=ec.generate_private_key(ec.SECP256R1()),
                       pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        unrooted = builder(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key,
                           chain_pem=rogue.unrooted_chain_pem)
        for label, blob in (("rogue", good), ("unrooted", unrooted),
                            ("empty", b""), ("zeros", b"\x00" * 900)):
            result = client.verify_pck_cert_chain(blob)
            assert result["ok"] is False, label
            assert result.get("reason"), (
                f"{client_fixture}/{label}: chain refused with no reason")


# --------------------------------------------------------------------------
# FIX 2 — the pinned anchor must be the DCAP root, not the EPID/IAS root
# --------------------------------------------------------------------------

class TestTrustAnchor:
    def test_shipped_dcap_root_is_the_intel_sgx_root_ca(self):
        cert = x509.load_pem_x509_certificate(_dcap_root_pem().encode())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "Intel SGX Root CA"
        assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
        assert cert.issuer == cert.subject  # self-signed root, not an intermediate

    def test_epid_root_is_refused_as_the_dcap_anchor(self, tmp_path, rogue):
        """The retired EPID/IAS root used to be accepted silently: it is
        RSA-3072, so the chain walk's `isinstance(..., EC)` guard skipped the
        anchoring step entirely and the function still reported success."""
        client = _sgx_client(tmp_path, root_pem=_epid_root_pem())
        quote = _sgx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        result = client.verify_pck_cert_chain(quote)
        assert result["ok"] is False
        assert "Attestation Report Signing CA" in result["reason"]


# --------------------------------------------------------------------------
# FIX 4 — truncated / "absent" quotes are failures, not free passes
# --------------------------------------------------------------------------

class TestTruncatedQuoteIsRejected:
    # 632 signed bytes + 4-byte length + 64-byte signature + 64-byte key: a
    # quote with no QE certification data at all.  This is exactly the shape
    # that used to be waved through as "absent".
    MINIMAL_TDX_LEN = TDX_SIGNED_LEN + 4 + 64 + 64

    def test_tdx_gcp_quote_without_qe_data_fails_both_checks(self, tdx_gcp_client):
        att_key = ec.generate_private_key(ec.SECP256R1())
        header = bytearray(48)
        struct.pack_into("<H", header, 0, 4)
        struct.pack_into("<H", header, 2, 2)
        struct.pack_into("<I", header, 4, 0x81)
        signed = bytes(header) + bytes(584)
        quote = (signed + struct.pack("<I", 128)
                 + _raw_sig(att_key, signed) + _public_xy(att_key))
        assert len(quote) == self.MINIMAL_TDX_LEN == 764

        # The attacker's own key signs the body, so this check passes.
        assert tdx_gcp_client.verify_tdx_quote_signature(quote) is True
        # These two must not.
        assert tdx_gcp_client.verify_qe_report_binding(quote) is False
        assert tdx_gcp_client.verify_pck_cert_chain(quote)["ok"] is False

    def test_tdx_gcp_verifiers_are_no_longer_tri_state(self, tdx_gcp_client, rogue):
        """No code path may return the string "absent" for either verifier."""
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        for blob in (b"", b"\x00" * 764, quote, quote[:1000]):
            assert isinstance(tdx_gcp_client.verify_qe_report_binding(blob), bool)
            assert isinstance(tdx_gcp_client.verify_pck_cert_chain(blob), dict)

    def test_sgx_truncated_quote_has_no_qe_report_signature(self, sgx_client, rogue):
        assert sgx_client.verify_qe_report_signature(b"\x00" * 800, rogue.leaf) is False
        assert sgx_client.verify_pck_cert_chain(b"\x00" * 800)["ok"] is False

    def test_gpu_cc_gcp_quote_without_qe_data_fails_both_checks(self, gpu_cc_gcp_client):
        att_key = ec.generate_private_key(ec.SECP256R1())
        header = bytearray(48)
        struct.pack_into("<H", header, 0, 4)
        struct.pack_into("<H", header, 2, 2)
        struct.pack_into("<I", header, 4, 0x81)
        signed = bytes(header) + bytes(584)
        quote = (signed + struct.pack("<I", 128)
                 + _raw_sig(att_key, signed) + _public_xy(att_key))
        assert len(quote) == self.MINIMAL_TDX_LEN == 764

        assert gpu_cc_gcp_client.verify_tdx_quote_signature(quote) is True
        assert gpu_cc_gcp_client.verify_qe_report_binding(quote) is False
        assert gpu_cc_gcp_client.verify_pck_cert_chain(quote)["ok"] is False

    def test_gpu_cc_gcp_verifiers_are_no_longer_tri_state(self, gpu_cc_gcp_client, rogue):
        """``bool("absent") is True``, so a tri-state return read as a bool is a
        worse fail-open than no check at all.  Pin the types."""
        quote = _tdx_quote(att_key=ec.generate_private_key(ec.SECP256R1()),
                           pck_key=rogue.pck_key, chain_pem=rogue.chain_pem)
        for blob in (b"", b"\x00" * 764, quote, quote[:1000]):
            assert isinstance(gpu_cc_gcp_client.verify_qe_report_binding(blob), bool)
            assert isinstance(gpu_cc_gcp_client.verify_pck_cert_chain(blob), dict)
            assert isinstance(
                gpu_cc_gcp_client.verify_qe_report_signature(blob, rogue.leaf), bool)


# --------------------------------------------------------------------------
# FIX 3 — the verifier is chosen at build time, and HCLA fails closed
# --------------------------------------------------------------------------

class _FakeSock:
    def settimeout(self, _timeout):
        pass


class _FakeConn:
    def __init__(self):
        self.closed = False

    def connect(self, _addr):
        pass

    def getpeercert(self, binary_form=False):
        return b"not-a-real-der-certificate"

    def close(self):
        self.closed = True


class _FakeSSLContext:
    def __init__(self, _protocol):
        self.conn = _FakeConn()

    def wrap_socket(self, _sock, server_hostname=None):
        return self.conn


def _patch_transport(monkeypatch, client, quote_bytes):
    """Replace the client's socket/TLS layer so verify_ratls_connection runs
    against a canned quote without a network."""
    conns = []

    class _TrackingContext(_FakeSSLContext):
        def __init__(self, protocol):
            super().__init__(protocol)
            conns.append(self.conn)

    fake_ssl = types.SimpleNamespace(
        SSLContext=_TrackingContext,
        PROTOCOL_TLS_CLIENT=object(),
        CERT_NONE=object(),
        TLSVersion=types.SimpleNamespace(TLSv1_3=object()),
    )
    fake_socket = types.SimpleNamespace(
        socket=lambda *_a, **_k: _FakeSock(), AF_INET=2, SOCK_STREAM=1,
    )
    monkeypatch.setattr(client, "ssl", fake_ssl)
    monkeypatch.setattr(client, "socket", fake_socket)
    monkeypatch.setattr(client, "extract_quote_from_cert", lambda _der: quote_bytes)
    monkeypatch.setattr(client, "extract_container_digest_from_cert", lambda _der: None)
    return conns


class TestAzureHclaFailsClosed:
    HCLA_BLOB = b"HCLA" + struct.pack("<I", 2) + struct.pack("<I", 1024) + b"\x00" * 2600

    def test_build_time_format_defaults_to_dcap(self, tdx_azure_client, monkeypatch):
        """`dcap` and `azure-guest` do not share a trust root -- Intel's CA
        versus Microsoft Azure Attestation -- so the Microsoft-rooted one has to
        be asked for, never inherited.

        The env is cleared explicitly. This assertion is about the *default*, and
        reading it off the ambient environment made it pass or fail depending on
        whether the developer's `.env` happened to set the knob -- which is
        exactly the class of test that reports the wrong thing later.
        """
        from tee_crafter.core.builder.platforms import (
            TDX_EVIDENCE_FORMAT_ENV, tdx_evidence_format,
        )
        monkeypatch.delenv(TDX_EVIDENCE_FORMAT_ENV, raising=False)
        assert tdx_azure_client._PLATFORM == "tdx-azure"
        assert tdx_azure_client._EXPECTED_EVIDENCE_FORMAT == "dcap"
        assert tdx_evidence_format() == "dcap"

    def test_hcla_blob_never_reaches_a_verifier(self, tdx_azure_client, monkeypatch):
        """Four bytes of server-supplied prefix must not select the verifier."""
        def _must_not_run(*_a, **_k):
            raise AssertionError("an HCLA blob reached a verification path")

        conns = _patch_transport(monkeypatch, tdx_azure_client, self.HCLA_BLOB)
        monkeypatch.setattr(tdx_azure_client, "_verify_dcap_attestation", _must_not_run)
        monkeypatch.setattr(tdx_azure_client, "_verify_azure_attestation", _must_not_run)

        with pytest.raises(SystemExit) as exc:
            tdx_azure_client.verify_ratls_connection("10.0.0.1", 5005)
        assert exc.value.code == 1
        assert conns and conns[0].closed, "the connection must be closed on rejection"

    def test_the_azure_verifier_itself_refuses_a_raw_hcla_blob(
            self, tdx_azure_client):
        """Even called directly, a raw vTPM blob never returns success.

        It is not a JWT and it is not verifiable by anyone reachable from here,
        so there is no branch that could accept it -- the previous code's
        forwarding of it to `/attest/TdxVm` was the bug, not a feature to keep.
        """
        conn = _FakeConn()
        with pytest.raises(SystemExit) as exc:
            tdx_azure_client._verify_azure_attestation(conn, self.HCLA_BLOB)
        assert exc.value.code == 1
        assert conn.closed

    def test_no_hcla_parser_remains(self, tdx_azure_client):
        """The parser only ever fed the bypass; leaving it invites its return."""
        assert not hasattr(tdx_azure_client, "parse_azure_attestation_report")


# --------------------------------------------------------------------------
# FIX 6 — an unresolved MRENCLAVE is fatal unless explicitly opted out of
# --------------------------------------------------------------------------

class TestUnpinnedMeasurement:
    def test_unknown_mrenclave_aborts(self, tmp_path, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT", raising=False)
        client = _sgx_client(tmp_path, mrenclave="unknown", mrsigner="unknown")
        with pytest.raises(SystemExit) as exc:
            client.require_pinned_measurements()
        assert exc.value.code == 1

    def test_explicit_opt_out_allows_tofu(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT", "1")
        client = _sgx_client(tmp_path, mrenclave="unknown", mrsigner="unknown")
        assert client.require_pinned_measurements() is None

    def test_pinned_build_needs_no_opt_out(self, sgx_client, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT", raising=False)
        assert sgx_client.require_pinned_measurements() is None


# --------------------------------------------------------------------------
# FIX 5 — the never-configured SGX TCB floors are gone rather than permissive
# --------------------------------------------------------------------------

def test_sgx_client_has_no_permissive_tcb_floors(sgx_client):
    for name in ("EXPECTED_MIN_ISV_SVN", "EXPECTED_MIN_TCB_EVAL_DATE",
                 "verify_isv_svn", "verify_tcb_evaluation_date"):
        assert not hasattr(sgx_client, name), (
            f"{name} was never passed by any caller and always defaulted "
            "permissive; it should not have come back without real wiring"
        )


class TestAzureGuestIsTheEvidenceAndHclaIsNever:
    """What three live `tdx-azure` runs actually established.

    The first attempt pinned "dcap", the VM presented an HCLA blob, and the
    client refused. The conclusion drawn -- "so enable an hcla path" -- was
    wrong, and the next two runs paid for it: the hcla path POSTed the 2600-byte
    vTPM envelope to `/attest/TdxVm` and got a 404 (wrong api-version) and then
    a 400. The 400 was never a body-shaping problem. Per Microsoft's attestation
    report format table, offset 32 of NV 0x01400001 holds a **raw 1024-byte
    TDREPORT** whose REPORTMACSTRUCT only the TDX module and the Quoting Enclave
    can verify, and `/attest/TdxVm` verifies Intel DCAP *quotes*.

    So the corrected property, pinned here from both sides: a raw HCLA blob is
    evidence of nothing and is refused under **either** format, and the evidence
    that does reach the verifier is an MAA token.
    """

    HCLA_BLOB = b"HCLA" + struct.pack("<I", 2) + struct.pack("<I", 1024) + b"\x00" * 2600
    # Header of a real AzureGuest JWT: `{"alg":...` base64url-encodes to `eyJ`.
    JWT_BLOB = b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln"

    @pytest.fixture(scope="class")
    def ag_client(self, tmp_path_factory):
        return _tdx_client("azure", tmp_path_factory.mktemp("tdx_ag_client"),
                           evidence_format="azure-guest")

    def test_the_format_is_what_was_asked_for(self, ag_client):
        assert ag_client._EXPECTED_EVIDENCE_FORMAT == "azure-guest"

    def test_a_maa_token_reaches_the_verifier(self, ag_client, monkeypatch):
        reached = {}

        def _spy(conn, blob, *a, **k):
            reached["blob"] = blob
            raise SystemExit(0)

        _patch_transport(monkeypatch, ag_client, self.JWT_BLOB)
        monkeypatch.setattr(ag_client, "_verify_azure_attestation", _spy)
        with pytest.raises(SystemExit):
            ag_client.verify_ratls_connection("10.0.0.1", 5005)
        assert reached.get("blob") == self.JWT_BLOB

    def test_a_raw_hcla_blob_is_refused_by_an_azure_guest_build(
            self, ag_client, monkeypatch):
        """The exact blob the old code forwarded to MAA.

        A guest presenting this has skipped the MAA exchange, not found an
        alternative to it -- there is nothing here anyone can verify.
        """
        called = []
        monkeypatch.setattr(ag_client, "_verify_azure_attestation",
                            lambda *a, **k: called.append(1))
        conns = _patch_transport(monkeypatch, ag_client, self.HCLA_BLOB)
        with pytest.raises(SystemExit) as exc:
            ag_client.verify_ratls_connection("10.0.0.1", 5005)
        assert exc.value.code == 1
        assert conns and conns[0].closed
        assert not called, "an unverifiable HCLA blob reached the verifier"

    def test_a_dcap_quote_is_refused_by_an_azure_guest_build(
            self, ag_client, monkeypatch):
        """The gate still runs in the other direction — the server does not
        get to pick the verifier just because the build chose MAA."""
        conns = _patch_transport(monkeypatch, ag_client, b"\x04\x00" + b"\x00" * 2600)
        with pytest.raises(SystemExit) as exc:
            ag_client.verify_ratls_connection("10.0.0.1", 5005)
        assert exc.value.code == 1
        assert conns and conns[0].closed

    def test_a_dcap_build_refuses_both_azure_shapes(self, tdx_azure_client,
                                                    monkeypatch):
        """A DCAP-pinned client must not quietly accept either Azure form."""
        for blob in (self.HCLA_BLOB, self.JWT_BLOB):
            conns = _patch_transport(monkeypatch, tdx_azure_client, blob)
            with pytest.raises(SystemExit) as exc:
                tdx_azure_client.verify_ratls_connection("10.0.0.1", 5005)
            assert exc.value.code == 1
            assert conns and conns[0].closed


class TestTheEvidenceFormatKnob:
    def test_default(self, monkeypatch):
        from tee_crafter.core.builder import platforms
        monkeypatch.delenv(platforms.TDX_EVIDENCE_FORMAT_ENV, raising=False)
        assert platforms.tdx_evidence_format() == "dcap"

    @pytest.mark.parametrize(
        "value", ["azure-guest", "AZURE-GUEST", " dcap ", "DCAP"])
    def test_accepted_values(self, monkeypatch, value):
        from tee_crafter.core.builder import platforms
        monkeypatch.setenv(platforms.TDX_EVIDENCE_FORMAT_ENV, value)
        assert platforms.tdx_evidence_format() == value.strip().lower()

    def test_a_typo_raises_rather_than_silently_defaulting(self, monkeypatch):
        """Reverting to `dcap` on a typo is indistinguishable from the
        operator's choice having been applied — and on Azure that reversion
        produces a VM that cannot attest at all."""
        from tee_crafter.core.builder import platforms
        monkeypatch.setenv(platforms.TDX_EVIDENCE_FORMAT_ENV, "azureguest")
        with pytest.raises(ValueError, match="not one of"):
            platforms.tdx_evidence_format()

    def test_the_retired_hcla_spelling_explains_itself(self, monkeypatch):
        """`hcla` named the blob, and the code behind that name POSTed the raw
        Azure envelope to /attest/TdxVm — a combination that cannot succeed.

        Anyone carrying it in a `.env` deserves the reason, not "not one of".
        """
        from tee_crafter.core.builder import platforms
        monkeypatch.setenv(platforms.TDX_EVIDENCE_FORMAT_ENV, "hcla")
        with pytest.raises(ValueError, match="renamed to 'azure-guest'"):
            platforms.tdx_evidence_format()

    def test_the_rendered_client_carries_the_choice(self, monkeypatch):
        from tee_crafter.core.builder import platforms
        monkeypatch.setenv(platforms.TDX_EVIDENCE_FORMAT_ENV, "azure-guest")
        src = platforms.render_tdx_client_template()
        assert '_EXPECTED_EVIDENCE_FORMAT = "azure-guest"' in src
        assert "{evidence_format}" not in src
