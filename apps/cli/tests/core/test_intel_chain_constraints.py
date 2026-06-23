"""basicConstraints / keyUsage on the Intel PCK chains, and the audit-chain
genesis commitment inside the hardware-signed ``report_data``.

Covers the three Intel-anchored platforms with a DCAP quote parser of their
own: ``sgx``, ``tdx-azure`` and ``tdx-gcp``.  (``gpu-cc-gcp`` is the fourth and
has its own file, ``test_gpu_cc_gcp_intel_chain.py`` — it was missed by the
first pass at these checks, which is why the parity test exists.)

Everything here is built from first principles rather than borrowed from the
code under test:

* the DCAP quote layouts are written out below from the Intel SGX/TDX
  structure definitions (SGX v3: QE report at 564, its signature at 948;
  TDX v4: TD report body at 48 so MRTD lands at 184, QE report at 770, its
  signature at 1154);
* the certificates are minted here with ``cryptography``, with
  basicConstraints and keyUsage set explicitly per case;
* the ``report_data`` preimage is re-implemented in ``_lp`` /
  ``_independent_binding_digest`` from its documented shape, and pinned by a
  golden vector, so a test never asks the module under test what the answer
  should be.  A shared helper would pass whenever both sides were wrong
  together, which is the failure mode this whole file exists to rule out.

There is no live Intel PCK chain and no TEE hardware on the machine these
tests run on.  The positive path for the CA checks is therefore anchored two
ways: the *real* pinned ``certs/intel-sgx-dcap-root.pem`` is asserted to
satisfy ``check_ca_certificate`` with its real ``pathlen:1`` budget, and a
synthetic root standing in for it (same CN, same constraints) carries the
full end-to-end chain walk.  The negative cases are entirely synthetic,
which is the point: an attacker's chain is synthetic too.
"""
from __future__ import annotations

import datetime
import hashlib
import importlib.util
import os
import struct
import sys
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

_INTEL_ROOT_CN = "Intel SGX Root CA"

# --------------------------------------------------------------------------
# Quote layouts, written out independently of the code under test
# --------------------------------------------------------------------------
SGX_SIGNED_LEN = 432          # 48-byte header + 384-byte sgx_report_body_t
SGX_QE_REPORT_OFFSET = 564
SGX_QE_REPORT_SIG_OFFSET = 948

TDX_SIGNED_LEN = 632          # 48-byte header + 584-byte TD report body
TDX_MRTD_OFFSET = 184         # 48 (body) + 136 (MRTD within the body)
TDX_QE_REPORT_OFFSET = 770    # after the 6-byte outer cert-data header at 764
TDX_QE_REPORT_SIG_OFFSET = 1154

REPORT_BODY_REPORT_DATA_OFFSET = 320   # within any 384-byte sgx_report_body_t

#: Expected ``cert_report_data_binding`` descriptor per platform.  Hardcoded
#: here on purpose: if either side of a platform pair drifts, the literal
#: catches it, whereas reading the constant out of one module and comparing it
#: to the other only catches half the drift.
EXPECTED_BINDING_DESC = {
    "sgx": (
        "sha256(lp('tee-crafter/attest-binding/v2') || uint32be(3) || "
        "lp('ratls-cert-report-data/sgx') || lp(ecdh_pub) || "
        "lp(chain_key_commitment_hex_ascii))"),
    "tdx-azure": (
        "sha256(lp('tee-crafter/attest-binding/v2') || uint32be(4) || "
        "lp('ratls-cert-report-data/tdx-azure') || lp(ecdh_pub) || "
        "lp(container_digest) || lp(chain_key_commitment_hex_ascii))"),
    "tdx-gcp": (
        "sha256(lp('tee-crafter/attest-binding/v2') || uint32be(4) || "
        "lp('ratls-cert-report-data/tdx-gcp') || lp(ecdh_pub) || "
        "lp(container_digest) || lp(chain_key_commitment_hex_ascii))"),
}

BINDING_PURPOSE = {
    "sgx": b"ratls-cert-report-data/sgx",
    "tdx-azure": b"ratls-cert-report-data/tdx-azure",
    "tdx-gcp": b"ratls-cert-report-data/tdx-gcp",
}

_BINDING_LABEL = b"tee-crafter/attest-binding/v2"


# --------------------------------------------------------------------------
# The report_data preimage, re-implemented from its documented shape
# --------------------------------------------------------------------------

def _lp(blob: bytes) -> bytes:
    """``uint32be(len(x)) || x`` — the "lp(...)" of the binding descriptor."""
    return struct.pack("!I", len(blob)) + blob


def _independent_binding_preimage(*fields: bytes) -> bytes:
    """``lp(label) || uint32be(nfields) || lp(f) for f in fields``."""
    out = _lp(_BINDING_LABEL) + struct.pack("!I", len(fields))
    for field in fields:
        out += _lp(field)
    return out


def _independent_binding_digest(*fields: bytes) -> bytes:
    return hashlib.sha256(_independent_binding_preimage(*fields)).digest()


# --------------------------------------------------------------------------
# Rendered templates
# --------------------------------------------------------------------------

def _dcap_root_pem() -> str:
    with open(os.path.join(_CERTS, "intel-sgx-dcap-root.pem"), encoding="utf-8") as fh:
        return fh.read().strip()


def _import_source(source: str, tmp_path, stem: str):
    path = tmp_path / f"{stem}_{uuid.uuid4().hex}.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def _render(relpath: str, subs: dict) -> str:
    with open(os.path.join(_TEMPLATES, relpath), encoding="utf-8") as fh:
        source = fh.read()
    for token, value in subs.items():
        source = source.replace(token, value)
    left = [t for t in ("{mrenclave}", "{mrsigner}", "{mrtd}", "{intel_root_ca}",
                        "{intel_sgx_root_ca}", "{container_digest}",
                        "{user_imports}", "{user_logic}") if t in source]
    assert not left, f"unsubstituted placeholders in {relpath}: {left}"
    return source


_CLIENT_TEMPLATE = {
    "sgx": "sgx/client.template.py",
    "tdx-azure": "tdx/azure/client.template.py",
    "tdx-gcp": "tdx/gcp/client.template.py",
}
_APP_TEMPLATE = {
    "sgx": "sgx/app_gramine.template.py",
    "tdx-azure": "tdx/azure/app.template.py",
    "tdx-gcp": "tdx/gcp/app.template.py",
}


def _client(platform: str, tmp_path, *, root_pem: str | None = None,
            container_digest: str = ""):
    root = root_pem if root_pem is not None else _dcap_root_pem()
    if platform == "sgx":
        subs = {"{mrenclave}": "ab" * 32, "{mrsigner}": "cd" * 32,
                "{intel_sgx_root_ca}": root}
    else:
        subs = {"{mrtd}": "ef" * 48, "{container_digest}": container_digest,
                "{intel_root_ca}": root}
    source = _render(_CLIENT_TEMPLATE[platform], subs)
    return _import_source(source, tmp_path, f"client_{platform.replace('-', '_')}")


def _app(platform: str, tmp_path):
    source = _render(_APP_TEMPLATE[platform],
                     {"{user_imports}": "", "{user_logic}": "    return data"})
    return _import_source(source, tmp_path, f"app_{platform.replace('-', '_')}")


PLATFORMS = ("sgx", "tdx-azure", "tdx-gcp")


@pytest.fixture(scope="module", params=PLATFORMS)
def platform(request):
    return request.param


@pytest.fixture(scope="module")
def client(platform, tmp_path_factory):
    return _client(platform, tmp_path_factory.mktemp("clients"))


# --------------------------------------------------------------------------
# Certificate minting, one knob per RFC 5280 constraint under test
# --------------------------------------------------------------------------

def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _mint(common_name: str, subject_key, *, issuer_key=None, issuer_name=None,
          basic_constraints="ca", path_length=None, key_cert_sign=True,
          omit_key_usage=False) -> x509.Certificate:
    """Mint one ECDSA-P256 certificate.

    ``basic_constraints`` is ``"ca"`` (CA:TRUE), ``"end-entity"`` (CA:FALSE)
    or ``"omit"`` (no basicConstraints extension at all).
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = _name(common_name)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name if issuer_name is not None else subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if basic_constraints == "ca":
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
    elif basic_constraints == "end-entity":
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True)
    elif basic_constraints != "omit":
        raise AssertionError(f"bad basic_constraints={basic_constraints!r}")

    if not omit_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=not key_cert_sign,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(issuer_key if issuer_key is not None else subject_key,
                        hashes.SHA256())


class _Chain:
    """A synthetic PCK chain plus the anchor PEM the client should be built with."""

    def __init__(self, *, intermediate_bc="ca", intermediate_path_len=0,
                 intermediate_key_cert_sign=True, intermediate_omit_ku=False,
                 root_path_len=1, leaf_bc="end-entity"):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())

        # Stands in for CN=Intel SGX Root CA.  The real anchor's own
        # constraints (CA:TRUE, pathlen:1, keyCertSign) are asserted directly
        # against certs/intel-sgx-dcap-root.pem in TestRealPinnedRoot.
        self.root = _mint(_INTEL_ROOT_CN, self.root_key,
                          basic_constraints="ca", path_length=root_path_len)
        self.intermediate = _mint(
            "Intel SGX PCK Platform CA", self.inter_key,
            issuer_key=self.root_key, issuer_name=self.root.subject,
            basic_constraints=intermediate_bc,
            path_length=intermediate_path_len,
            key_cert_sign=intermediate_key_cert_sign,
            omit_key_usage=intermediate_omit_ku)
        self.leaf = _mint(
            "Intel SGX PCK Certificate", self.leaf_key,
            issuer_key=self.inter_key, issuer_name=self.intermediate.subject,
            basic_constraints=leaf_bc, key_cert_sign=False)

    @property
    def root_pem(self) -> str:
        return self.root.public_bytes(serialization.Encoding.PEM).decode().strip()

    @property
    def chain_pem(self) -> bytes:
        """Leaf-first, root last — the order Intel's cert_data uses."""
        return b"".join(
            c.public_bytes(serialization.Encoding.PEM)
            for c in (self.leaf, self.intermediate, self.root))


# --------------------------------------------------------------------------
# Quote assembly
# --------------------------------------------------------------------------

def _raw_sig(key, message: bytes) -> bytes:
    r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _public_xy(key) -> bytes:
    nums = key.public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _report_body(report_data: bytes = b"") -> bytes:
    body = bytearray(384)
    body[REPORT_BODY_REPORT_DATA_OFFSET:
         REPORT_BODY_REPORT_DATA_OFFSET + len(report_data)] = report_data
    return bytes(body)


def _sgx_quote(*, chain_pem: bytes, pck_key, report_data: bytes = b"",
               qe_auth: bytes = b"authdata") -> bytes:
    header = bytearray(48)
    struct.pack_into("<H", header, 0, 3)     # version
    struct.pack_into("<H", header, 2, 2)     # att_key_type = ECDSA-P256
    struct.pack_into("<I", header, 4, 0)     # tee_type = SGX
    body = bytearray(_report_body(report_data))
    struct.pack_into("<Q", body, 48, 0x1)    # attributes.FLAGS: INIT, DEBUG clear
    signed = bytes(header) + bytes(body)
    assert len(signed) == SGX_SIGNED_LEN

    att_key = ec.generate_private_key(ec.SECP256R1())
    att_key_xy = _public_xy(att_key)
    enclave_sig = _raw_sig(att_key, signed)

    qe_report = bytearray(_report_body())
    digest = hashlib.sha256(att_key_xy + qe_auth).digest()
    qe_report[REPORT_BODY_REPORT_DATA_OFFSET:
              REPORT_BODY_REPORT_DATA_OFFSET + 32] = digest
    qe_report = bytes(qe_report)
    qe_sig = _raw_sig(pck_key, qe_report)

    tail = (struct.pack("<H", len(qe_auth)) + qe_auth
            + struct.pack("<H", 5) + struct.pack("<I", len(chain_pem)) + chain_pem)
    sig_data = enclave_sig + att_key_xy + qe_report + qe_sig + tail
    quote = signed + struct.pack("<I", len(sig_data)) + sig_data

    assert quote[SGX_QE_REPORT_OFFSET:SGX_QE_REPORT_OFFSET + 384] == qe_report
    assert quote[SGX_QE_REPORT_SIG_OFFSET:SGX_QE_REPORT_SIG_OFFSET + 64] == qe_sig
    return quote


def _tdx_quote(*, chain_pem: bytes, pck_key, report_data: bytes = b"",
               qe_auth: bytes = b"authdata", mrtd: bytes = b"\xef" * 48) -> bytes:
    header = bytearray(48)
    struct.pack_into("<H", header, 0, 4)        # version
    struct.pack_into("<H", header, 2, 2)        # att_key_type
    struct.pack_into("<I", header, 4, 0x81)     # tee_type = TDX

    td_body = bytearray(584)
    td_body[0] = 1                              # TEE_TCB_SVN[0] — module major
    td_body[1] = 5                              # TEE_TCB_SVN[1] — module minor
    td_body[136:136 + 48] = mrtd                # MRTD -> absolute offset 184
    td_body[520:520 + len(report_data)] = report_data
    signed = bytes(header) + bytes(td_body)
    assert len(signed) == TDX_SIGNED_LEN
    assert signed[TDX_MRTD_OFFSET:TDX_MRTD_OFFSET + 48] == mrtd

    att_key = ec.generate_private_key(ec.SECP256R1())
    att_key_xy = _public_xy(att_key)
    td_sig = _raw_sig(att_key, signed)

    qe_report = bytearray(_report_body())
    digest = hashlib.sha256(att_key_xy + qe_auth).digest()
    qe_report[REPORT_BODY_REPORT_DATA_OFFSET:
              REPORT_BODY_REPORT_DATA_OFFSET + 32] = digest
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


def _quote_for(platform: str, chain: _Chain, **kwargs) -> bytes:
    if platform == "sgx":
        return _sgx_quote(chain_pem=chain.chain_pem, pck_key=chain.leaf_key,
                          **kwargs)
    return _tdx_quote(chain_pem=chain.chain_pem, pck_key=chain.leaf_key, **kwargs)


def _walk(platform: str, chain: _Chain, tmp_path) -> dict:
    """Run the platform's PCK chain walk over *chain*, anchored to its own root."""
    client = _client(platform, tmp_path, root_pem=chain.root_pem)
    return client.verify_pck_cert_chain(_quote_for(platform, chain))


# ==========================================================================
# ITEM 14 — basicConstraints / keyUsage on the Intel PCK chain
# ==========================================================================

class TestPckChainCaConstraints:
    """Accept a conforming chain; reject every way of using a non-CA as issuer.

    Every case below differs from ``test_conforming_chain_is_accepted`` in
    exactly one certificate extension, and every signature in every case is
    valid.  So the only thing that can decide them is the constraint check —
    which is what makes these tests evidence rather than decoration.
    """

    def test_conforming_chain_is_accepted(self, platform, tmp_path):
        result = _walk(platform, _Chain(), tmp_path)
        assert result["ok"] is True, result.get("reason")
        assert result["pck_leaf"] is not None

    def test_end_entity_used_as_issuer_is_rejected(self, platform, tmp_path):
        """The item-14 attack: a CA:FALSE certificate signing the PCK leaf.

        An attacker holding any Intel-issued end-entity certificate signs a
        forged leaf with it.  Names chain, signatures verify, the anchor is
        reached — only the CA bit says no.
        """
        result = _walk(platform, _Chain(intermediate_bc="end-entity"), tmp_path)
        assert result["ok"] is False
        assert "CA:FALSE" in result["reason"]

    def test_issuer_without_basic_constraints_is_rejected(self, platform, tmp_path):
        result = _walk(platform, _Chain(intermediate_bc="omit"), tmp_path)
        assert result["ok"] is False
        assert "no basicConstraints" in result["reason"]

    def test_issuer_key_usage_without_key_cert_sign_is_rejected(
            self, platform, tmp_path):
        result = _walk(
            platform, _Chain(intermediate_key_cert_sign=False), tmp_path)
        assert result["ok"] is False
        assert "keyCertSign" in result["reason"]

    def test_issuer_without_key_usage_at_all_is_accepted(self, platform, tmp_path):
        """keyUsage is optional in RFC 5280 §4.2.1.3; absent is not a violation.

        Recorded so the permissiveness is a decision rather than an oversight:
        rejecting here would break any conforming chain that omits the
        extension.
        """
        result = _walk(platform, _Chain(intermediate_omit_ku=True), tmp_path)
        assert result["ok"] is True, result.get("reason")

    def test_path_len_constraint_is_enforced(self, platform, tmp_path):
        """A root with pathlen:0 cannot have an intermediate beneath it."""
        result = _walk(platform, _Chain(root_path_len=0), tmp_path)
        assert result["ok"] is False
        assert "pathLenConstraint" in result["reason"]

    def test_path_len_constraint_of_one_admits_one_intermediate(
            self, platform, tmp_path):
        """The budget the real Intel root actually publishes."""
        result = _walk(platform, _Chain(root_path_len=1), tmp_path)
        assert result["ok"] is True, result.get("reason")

    def test_leaf_asserting_ca_true_is_rejected(self, platform, tmp_path):
        """A leaf with CA:TRUE could mint further certs under the pinned root."""
        result = _walk(platform, _Chain(leaf_bc="ca"), tmp_path)
        assert result["ok"] is False
        assert "leaf certificate asserts basicConstraints CA:TRUE" in result["reason"]

    def test_leaf_without_basic_constraints_is_accepted(self, platform, tmp_path):
        """Absent basicConstraints means "not a CA" (RFC 5280 §4.2.1.9)."""
        result = _walk(platform, _Chain(leaf_bc="omit"), tmp_path)
        assert result["ok"] is True, result.get("reason")


class TestRealPinnedRoot:
    """Anchor the positive path in the certificate actually shipped.

    The synthetic root in ``_Chain`` only proves the walk works on *some*
    conforming chain.  These assert that the constraints the checks rely on
    are the ones ``certs/intel-sgx-dcap-root.pem`` really carries, read
    straight off the file rather than through the client.
    """

    def _root(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(_dcap_root_pem().encode())

    def test_shipped_root_constraints_are_what_the_checks_assume(self):
        root = self._root()
        assert root.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME)[0].value == _INTEL_ROOT_CN
        bc = root.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True
        assert bc.path_length == 1
        ku = root.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_cert_sign is True

    def test_shipped_root_passes_the_ca_check_with_its_real_budget(
            self, client):
        """One intermediate under a pathlen:1 root is exactly in budget."""
        assert client.check_ca_certificate(
            self._root(), 2, remaining_intermediates=1) is None

    def test_shipped_root_rejects_two_intermediates(self, client):
        root = self._root()
        with pytest.raises(ValueError, match="pathLenConstraint=1"):
            client.check_ca_certificate(root, 3, remaining_intermediates=2)

    def test_shipped_root_is_not_treated_as_a_leaf(self, client):
        """check_leaf_certificate must reject it — it is CA:TRUE."""
        with pytest.raises(ValueError, match="CA:TRUE"):
            client.check_leaf_certificate(self._root())


class TestCaCheckUnitCases:
    """The two helpers on their own, so each rule has a named failing case."""

    def test_missing_basic_constraints_raises_value_error(self, client):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _mint("no-bc", key, basic_constraints="omit")
        with pytest.raises(ValueError, match="no basicConstraints"):
            client.check_ca_certificate(cert, 1, remaining_intermediates=0)

    def test_ca_false_raises_value_error(self, client):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _mint("ee", key, basic_constraints="end-entity")
        with pytest.raises(ValueError, match="CA:FALSE"):
            client.check_ca_certificate(cert, 1, remaining_intermediates=0)

    def test_key_usage_without_key_cert_sign_raises_value_error(self, client):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _mint("ca-no-kcs", key, basic_constraints="ca",
                     key_cert_sign=False)
        with pytest.raises(ValueError, match="keyCertSign"):
            client.check_ca_certificate(cert, 1, remaining_intermediates=0)

    def test_path_len_zero_with_one_intermediate_raises_value_error(self, client):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _mint("ca-pl0", key, basic_constraints="ca", path_length=0)
        with pytest.raises(ValueError, match="pathLenConstraint=0"):
            client.check_ca_certificate(cert, 1, remaining_intermediates=1)

    def test_path_len_zero_with_no_intermediate_is_accepted(self, client):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _mint("ca-pl0", key, basic_constraints="ca", path_length=0)
        assert client.check_ca_certificate(
            cert, 1, remaining_intermediates=0) is None

    def test_unconstrained_path_len_accepts_any_depth(self, client):
        """``path_length=None`` means no pathLenConstraint was asserted."""
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _mint("ca-any", key, basic_constraints="ca", path_length=None)
        assert client.check_ca_certificate(
            cert, 9, remaining_intermediates=8) is None


# ==========================================================================
# ITEM 11 — the audit-chain genesis commitment inside report_data
# ==========================================================================

COMMITMENT_A = "a" * 64
COMMITMENT_B = "b" * 64


def _ecdh_pub() -> bytes:
    """An uncompressed P-256 point, the shape the apps put in report_data."""
    return ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)


def _bound_report_data(platform: str, pub: bytes, commitment: str,
                       container_digest: str = "") -> bytes:
    """The 64-byte report_data an honest TEE would produce, computed here."""
    if platform == "sgx":
        fields = (BINDING_PURPOSE[platform], pub, commitment.encode("ascii"))
    else:
        fields = (BINDING_PURPOSE[platform], pub,
                  container_digest.encode("utf-8"), commitment.encode("ascii"))
    return _independent_binding_digest(*fields).ljust(64, b"\x00")


def _att_resp(platform: str, commitment: str, *, binding=None) -> dict:
    return {
        "enclave_public_key": "unused-by-the-function-under-test",
        "cert_report_data_binding": (
            EXPECTED_BINDING_DESC[platform] if binding is None else binding),
        "chain_key_commitment": commitment,
    }


def _verify(client, platform: str, report_data: bytes, att_resp: dict,
            pub: bytes, container_digest: str = ""):
    if platform == "sgx":
        return client.verify_report_data_binding(report_data, att_resp, pub)
    return client.verify_report_data_binding(
        report_data, att_resp, pub, container_digest)


class TestPreimageEncoding:
    """The preimage must be injective, and must not drift between the pair."""

    def test_golden_vector_pins_the_encoding(self):
        """A hardcoded digest, so app and client cannot drift together.

        Fields: purpose=b"p", ecdh_pub=b"k", commitment=b"c".  The preimage is
        ``uint32be(29) || b"tee-crafter/attest-binding/v2" || uint32be(3) ||
        uint32be(1) || b"p" || uint32be(1) || b"k" || uint32be(1) || b"c"``.
        """
        preimage = _independent_binding_preimage(b"p", b"k", b"c")
        assert preimage == (
            b"\x00\x00\x00\x1dtee-crafter/attest-binding/v2"
            b"\x00\x00\x00\x03"
            b"\x00\x00\x00\x01p\x00\x00\x00\x01k\x00\x00\x00\x01c")
        assert hashlib.sha256(preimage).hexdigest() == (
            "beb8885e08aec1a5319671d9691b572b3b9187c40fb3c928d8fc71a34fcbbe6c")

    def test_length_prefixes_defeat_field_splicing(self):
        """``pub=b"abc", cd=b"d"`` and ``pub=b"ab", cd=b"cd"`` must differ.

        Their raw concatenations are byte-identical (``b"abcd"``), which is
        exactly the collision that made the v1 preimage
        ``ecdh_pub || container_digest`` unsafe to extend with a third field.
        """
        purpose = BINDING_PURPOSE["tdx-gcp"]
        commitment = COMMITMENT_A.encode("ascii")
        left = _independent_binding_digest(purpose, b"abc", b"d", commitment)
        right = _independent_binding_digest(purpose, b"ab", b"cd", commitment)
        assert left != right
        # ...and the raw concatenation the prefixes replaced does collide.
        assert b"abc" + b"d" == b"ab" + b"cd"

    def test_field_count_is_hashed_so_a_short_list_cannot_be_padded(self):
        two = _independent_binding_digest(b"a", b"b")
        three = _independent_binding_digest(b"a", b"b", b"")
        assert two != three

    def test_version_label_separates_v2_from_a_bare_concatenation(self):
        """A v1 digest can never be reinterpreted as a v2 one."""
        pub = _ecdh_pub()
        v1 = hashlib.sha256(pub).digest()
        v2 = _independent_binding_digest(BINDING_PURPOSE["sgx"], pub,
                                        COMMITMENT_A.encode("ascii"))
        assert v1 != v2

    @pytest.mark.parametrize("plat", PLATFORMS)
    def test_app_and_client_publish_the_same_descriptor(self, plat, tmp_path):
        """Both halves must equal the literal in this file, not just each other."""
        app = _app(plat, tmp_path)
        client = _client(plat, tmp_path)
        assert app._CERT_REPORT_DATA_BINDING_DESC == EXPECTED_BINDING_DESC[plat]
        assert client._EXPECTED_CERT_REPORT_DATA_BINDING == EXPECTED_BINDING_DESC[plat]
        assert app._CERT_BINDING_PURPOSE == BINDING_PURPOSE[plat]
        assert client._CERT_BINDING_PURPOSE == BINDING_PURPOSE[plat]

    @pytest.mark.parametrize("plat", PLATFORMS)
    def test_app_encoder_matches_the_independent_implementation(self, plat, tmp_path):
        app = _app(plat, tmp_path)
        fields = (b"purpose", b"\x01\x02", b"", b"zzz")
        assert app._attest_binding_preimage(*fields) == \
            _independent_binding_preimage(*fields)


class TestReportDataCommitmentBinding:
    def test_correctly_bound_commitment_is_accepted(self, client, platform):
        pub = _ecdh_pub()
        rd = _bound_report_data(platform, pub, COMMITMENT_A)
        ok, reason = _verify(client, platform, rd,
                             _att_resp(platform, COMMITMENT_A), pub)
        assert ok, reason

    def test_tampered_commitment_is_rejected(self, client, platform):
        """The quote signs commitment A; the host claims B."""
        pub = _ecdh_pub()
        rd = _bound_report_data(platform, pub, COMMITMENT_A)
        ok, reason = _verify(client, platform, rd,
                             _att_resp(platform, COMMITMENT_B), pub)
        assert ok is False
        assert "not SHA-256 of the v2 preimage" in reason

    def test_substituted_ecdh_key_is_rejected(self, client, platform):
        """Regression guard: the key binding must survive the new third field."""
        rd = _bound_report_data(platform, _ecdh_pub(), COMMITMENT_A)
        ok, reason = _verify(client, platform, rd,
                             _att_resp(platform, COMMITMENT_A), _ecdh_pub())
        assert ok is False
        assert "not SHA-256 of the v2 preimage" in reason

    def test_absent_commitment_is_fatal_by_default(self, client, platform,
                                                  monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", raising=False)
        pub = _ecdh_pub()
        rd = _bound_report_data(platform, pub, "")
        ok, reason = _verify(client, platform, rd, _att_resp(platform, ""), pub)
        assert ok is False
        assert "no runtime audit-log chain-key commitment" in reason

    def test_missing_commitment_field_is_fatal_by_default(self, client, platform,
                                                         monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", raising=False)
        pub = _ecdh_pub()
        resp = _att_resp(platform, "")
        del resp["chain_key_commitment"]
        ok, reason = _verify(client, platform,
                             _bound_report_data(platform, pub, ""), resp, pub)
        assert ok is False
        assert "no runtime audit-log chain-key commitment" in reason

    def test_absent_commitment_accepted_only_with_explicit_opt_out(
            self, client, platform, monkeypatch, capsys):
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", "1")
        pub = _ecdh_pub()
        rd = _bound_report_data(platform, pub, "")
        ok, reason = _verify(client, platform, rd, _att_resp(platform, ""), pub)
        assert ok, reason
        banner = capsys.readouterr().err
        assert "WARNING" in banner
        assert "NOT anchored" in banner
        assert "Development use only" in banner

    def test_opt_out_does_not_excuse_a_tampered_commitment(
            self, client, platform, monkeypatch):
        """The hatch covers an *empty* commitment, never a wrong one."""
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", "1")
        pub = _ecdh_pub()
        rd = _bound_report_data(platform, pub, COMMITMENT_A)
        ok, reason = _verify(client, platform, rd,
                             _att_resp(platform, COMMITMENT_B), pub)
        assert ok is False
        assert "not SHA-256 of the v2 preimage" in reason

    def test_short_commitment_is_rejected(self, client, platform):
        pub = _ecdh_pub()
        short = "ab" * 20
        rd = _bound_report_data(platform, pub, short)
        ok, reason = _verify(client, platform, rd,
                             _att_resp(platform, short), pub)
        assert ok is False
        assert "64-character SHA-256 hex digest" in reason

    def test_non_hex_commitment_is_rejected(self, client, platform):
        pub = _ecdh_pub()
        bogus = "z" * 64
        rd = _bound_report_data(platform, pub, bogus)
        ok, reason = _verify(client, platform, rd,
                             _att_resp(platform, bogus), pub)
        assert ok is False
        assert "64-character SHA-256 hex digest" in reason

    def test_v1_report_data_is_rejected(self, client, platform):
        """The breaking change is detected rather than silently downgraded.

        A pre-v2 TEE binds ``SHA-256(ecdh_pub [|| container_digest])`` and
        publishes no descriptor at all.
        """
        pub = _ecdh_pub()
        rd = hashlib.sha256(pub).digest().ljust(64, b"\x00")
        resp = {"enclave_public_key": "x"}
        ok, reason = _verify(client, platform, rd, resp, pub)
        assert ok is False
        assert "did not describe its certificate quote's report_data" in reason

    def test_missing_binding_descriptor_is_fatal(self, client, platform):
        pub = _ecdh_pub()
        rd = _bound_report_data(platform, pub, COMMITMENT_A)
        resp = _att_resp(platform, COMMITMENT_A, binding="")
        ok, reason = _verify(client, platform, rd, resp, pub)
        assert ok is False
        assert "did not describe its certificate quote's report_data" in reason

    def test_another_platforms_descriptor_is_rejected(self, client, platform):
        """A quote minted for one platform must not validate on another."""
        other = next(p for p in PLATFORMS if p != platform)
        pub = _ecdh_pub()
        rd = _bound_report_data(platform, pub, COMMITMENT_A)
        resp = _att_resp(platform, COMMITMENT_A,
                         binding=EXPECTED_BINDING_DESC[other])
        ok, reason = _verify(client, platform, rd, resp, pub)
        assert ok is False
        assert "did not describe its certificate quote's report_data" in reason


class TestContainerDigestIsStillBound:
    """TDX only: the container digest keeps its place in the preimage."""

    @pytest.mark.parametrize("plat", ("tdx-azure", "tdx-gcp"))
    def test_matching_container_digest_is_accepted(self, plat, tmp_path):
        digest = "sha256:" + "1" * 64
        client = _client(plat, tmp_path, container_digest=digest)
        pub = _ecdh_pub()
        rd = _bound_report_data(plat, pub, COMMITMENT_A, container_digest=digest)
        ok, reason = client.verify_report_data_binding(
            rd, _att_resp(plat, COMMITMENT_A), pub, digest)
        assert ok, reason

    @pytest.mark.parametrize("plat", ("tdx-azure", "tdx-gcp"))
    def test_swapped_container_digest_is_rejected(self, plat, tmp_path):
        client = _client(plat, tmp_path)
        pub = _ecdh_pub()
        rd = _bound_report_data(plat, pub, COMMITMENT_A,
                                container_digest="sha256:" + "1" * 64)
        ok, reason = client.verify_report_data_binding(
            rd, _att_resp(plat, COMMITMENT_A), pub, "sha256:" + "2" * 64)
        assert ok is False
        assert "not SHA-256 of the v2 preimage" in reason


class TestQuoteCarriesTheBoundReportData:
    """End-to-end over a real quote blob: parse report_data back out and verify.

    The tests above hand ``verify_report_data_binding`` a bare 64-byte string.
    This one puts the same bytes at the platform's real ``report_data`` offset,
    runs the platform's own parser, and feeds the parser's output to the
    verifier — so a wrong offset cannot hide behind a passing unit test.
    """

    def test_report_data_survives_the_parser(self, platform, tmp_path):
        pub = _ecdh_pub()
        rd = _bound_report_data(platform, pub, COMMITMENT_A)
        chain = _Chain()
        anchored = _client(platform, tmp_path, root_pem=chain.root_pem)
        quote = _quote_for(platform, chain, report_data=rd)

        if platform == "sgx":
            info = anchored.parse_sgx_quote(quote)
        else:
            info = anchored.parse_tdx_quote(quote)
        assert info["report_data"] == rd

        ok, reason = _verify(anchored, platform, info["report_data"],
                             _att_resp(platform, COMMITMENT_A), pub)
        assert ok, reason
        # ...and the same quote's PCK chain walk is the one item 14 hardened,
        # so both fixes are exercised against a single blob.
        assert anchored.verify_pck_cert_chain(quote)["ok"] is True
