"""The Intel TDX half of the ``gpu-cc-gcp`` client: QE report offset, PCK
chain constraints, and the QE report signature that anchors both.

``gpu-cc-gcp`` is the only GPU-CC platform with an Intel TDX CPU side, so it
carries its own copy of the DCAP quote-parsing and PCK-chain code rather than
sharing ``sgx/`` or ``tdx/*/``.  That copy had drifted from the other three
Intel verifiers in three ways, and this file pins all three:

1. **QE report offset.**  A TDX v4 quote wraps its ECDSA signature data in an
   outer cert-data header (``cert_data_type`` u16 + ``cert_data_size`` u32 =
   6 bytes) immediately after the attestation public key.  For
   ``cert_data_type == 6`` (QE_REPORT_CERTIFICATION_DATA — what cloud TDX
   attesters including GCP emit) the QE report therefore starts at 770, not
   764.  The client used to hardcode 764, so the QE report, its signature,
   the QE auth data and the PCK cert data were all read 6 bytes early.
2. **basicConstraints / keyUsage on the PCK chain.**  The chain walk verified
   signatures only, so any Intel-issued end-entity certificate could be used
   to sign a forged PCK leaf.
3. **No QE report signature check at all.**  ``sgx/``, ``tdx/azure/`` and
   ``tdx/gcp/`` each verify that the PCK leaf's key signed the QE report;
   this client had no such function, and ``verify_pck_cert_chain`` threw the
   chain-verified leaf away.  Everything else on the CPU side is
   self-referential — the TD report is checked with an attestation key read
   out of the quote, and the QE binding hashes that key against a QE report
   read out of the same quote — and PCK chains are public, so a wholly
   forged quote carrying a genuine chain passed.  See
   ``TestQeReportSignatureBindsTheAttestationKey``, which builds exactly that
   forgery.

Everything below is built from first principles rather than borrowed from the
code under test:

* the quote layout is written out from the Intel TDX v4 structure definitions
  — 48-byte header + 584-byte TD report body = 632 signed bytes, a 4-byte
  ``sig_data_len``, then ``ecdsa_sig(64) || att_pub_key(64)`` putting the
  outer cert-data header at 764 and the QE report at 770, its signature at
  1154.  Those numbers are literals here, never asked of the module;
* certificates are minted in this file with one explicit knob per RFC 5280
  constraint under test;
* the QE binding digest is recomputed here from its documented shape
  (``SHA-256(att_pub_key || qe_auth_data)``) rather than through the client.

There is no TEE hardware and no live Intel collateral on the machine these
tests run on, so every chain here is synthetic — which is the point, since an
attacker's chain is synthetic too.  The one thing anchored in shipped bytes is
``TestRealPinnedRoot``, which reads ``certs/intel-sgx-dcap-root.pem`` off disk
and asserts the constraints the checks depend on are really the ones Intel
publishes.
"""
from __future__ import annotations

import ast
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
_TEMPLATE = os.path.join(_PKG_DIR, "templates", "gpu_cc", "gcp",
                         "client.template.py")
_CERTS = os.path.join(_PKG_DIR, "certs")

_INTEL_ROOT_CN = "Intel SGX Root CA"

# --------------------------------------------------------------------------
# TDX v4 quote layout, written out independently of the code under test
# --------------------------------------------------------------------------
TDX_SIGNED_LEN = 632         # 48-byte header + 584-byte TD report body
SIG_OFFSET = 636             # + the 4-byte sig_data_len field
ATT_PUB_KEY_OFFSET = 700     # SIG_OFFSET + 64-byte ECDSA signature

#: Where the outer cert-data header (type u16 + size u32) sits in a v4 quote,
#: and — for a legacy/non-wrapped layout — where the QE report itself sits.
LEGACY_QE_REPORT_OFFSET = 764
#: 764 + 6: the QE report inside a ``cert_data_type == 6`` wrapper.
V4_QE_REPORT_OFFSET = 770
V4_QE_REPORT_SIG_OFFSET = 1154        # 770 + 384
V4_QE_AUTH_SIZE_OFFSET = 1218         # 1154 + 64

REPORT_BODY_REPORT_DATA_OFFSET = 320  # within any 384-byte sgx_report_body_t

CERT_DATA_TYPE_QE_REPORT = 6          # QE_REPORT_CERTIFICATION_DATA
CERT_DATA_TYPE_PCK_CHAIN = 5          # PCK_CERT_CHAIN (PEM)

QE_AUTH_DATA = b"qe-auth-data"

#: The MRTD baked into the client under test.  A real deployment's pin is a
#: public value: it is printed at build time and shipped inside the client
#: script the operator distributes.  The forgery in
#: ``TestQeReportSignatureBindsTheAttestationKey`` therefore uses it, because
#: an attacker would.
PINNED_MRTD_HEX = "ef" * 48


# --------------------------------------------------------------------------
# Rendering the template as an importable module
# --------------------------------------------------------------------------

def _dcap_root_pem() -> str:
    with open(os.path.join(_CERTS, "intel-sgx-dcap-root.pem"),
              encoding="utf-8") as fh:
        return fh.read().strip()


def _client(tmp_path, *, root_pem: str | None = None,
            container_digest: str = "") -> object:
    """Render ``gpu_cc/gcp/client.template.py`` and import it as a module.

    ``root_pem`` is injected as the pinned trust anchor, so a synthetic chain
    can be walked to a synthetic root without touching the shipped one.
    """
    with open(_TEMPLATE, encoding="utf-8") as fh:
        source = fh.read()
    subs = {
        "{mrtd}": PINNED_MRTD_HEX,
        "{container_digest}": container_digest,
        "{expected_vtpm_pcrs}": "",
        "{intel_root_ca}": root_pem if root_pem is not None else _dcap_root_pem(),
        # Never exercised here: nothing in these tests reaches the NRAS path.
        "{nvidia_root_ca}": "",
    }
    for token, value in subs.items():
        source = source.replace(token, value)
    left = [t for t in subs if t in source]
    assert not left, f"unsubstituted placeholders: {left}"

    path = tmp_path / f"client_gpu_cc_gcp_{uuid.uuid4().hex}.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """A client pinned to the real shipped Intel root (no chain walked)."""
    return _client(tmp_path_factory.mktemp("gpu_cc_gcp_client"))


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
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True)
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
    """A synthetic PCK chain plus the anchor PEM the client is built with.

    Every signature is real in every configuration — the root signs the
    intermediate, the intermediate signs the leaf — so the only thing that
    can decide a case is the constraint under test.
    """

    def __init__(self, *, intermediate_bc="ca", intermediate_path_len=0,
                 intermediate_key_cert_sign=True, intermediate_omit_ku=False,
                 root_path_len=1, leaf_bc="end-entity"):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())

        # Stands in for CN=Intel SGX Root CA.  The real anchor's own
        # constraints are asserted against the shipped PEM in
        # TestRealPinnedRoot.
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
        return self.root.public_bytes(
            serialization.Encoding.PEM).decode().strip()

    @property
    def chain_pem(self) -> bytes:
        """Leaf-first, root last — the order Intel's ``cert_data`` uses."""
        return b"".join(
            c.public_bytes(serialization.Encoding.PEM)
            for c in (self.leaf, self.intermediate, self.root))


# --------------------------------------------------------------------------
# Quote assembly, byte by byte
# --------------------------------------------------------------------------

def _raw_sig(key, message: bytes) -> bytes:
    r, s = utils.decode_dss_signature(
        key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _public_xy(key) -> bytes:
    nums = key.public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _signed_body(report_data: bytes = b"",
                 mrtd: bytes = bytes.fromhex(PINNED_MRTD_HEX)) -> bytes:
    """The 632 bytes the TDX module signs: 48-byte header + TD report body."""
    header = bytearray(48)
    struct.pack_into("<H", header, 0, 4)       # version 4
    struct.pack_into("<H", header, 2, 2)      # att_key_type = ECDSA-P256
    struct.pack_into("<I", header, 4, 0x81)   # tee_type = TDX
    td_body = bytearray(584)
    td_body[0] = 1                             # TEE_TCB_SVN[0] — module major
    td_body[1] = 5                             # TEE_TCB_SVN[1] — module minor
    td_body[136:136 + 48] = mrtd               # MRTD
    td_body[520:520 + len(report_data)] = report_data
    signed = bytes(header) + bytes(td_body)
    assert len(signed) == TDX_SIGNED_LEN
    return signed


def _qe_report(att_key_xy: bytes, qe_auth: bytes, *,
               cpu_svn: bytes = b"\x00\x00") -> bytes:
    """A 384-byte ``sgx_report_body_t`` bound to *att_key_xy* and *qe_auth*.

    ``report_data[:32] = SHA-256(att_pub_key || qe_auth_data)``, recomputed
    here from the documented shape of the binding.  ``cpu_svn`` is the first
    two bytes of the body and matters only to the legacy-layout probe.
    """
    body = bytearray(384)
    body[0:2] = cpu_svn
    body[REPORT_BODY_REPORT_DATA_OFFSET:REPORT_BODY_REPORT_DATA_OFFSET + 32] = \
        hashlib.sha256(att_key_xy + qe_auth).digest()
    return bytes(body)


def _v4_quote(*, chain_pem: bytes, qe_sig_key, report_data: bytes = b"",
              qe_auth: bytes = QE_AUTH_DATA, qe_sig: bytes | None = None,
              cert_data_type: int = CERT_DATA_TYPE_QE_REPORT,
              mrtd: bytes = bytes.fromhex(PINNED_MRTD_HEX)) -> bytes:
    """A TDX v4 quote with the QE report inside an outer cert-data wrapper.

    Layout, from the Intel TDX v4 definitions::

        [0:632]      header + TD report body        (signed)
        [632:636]    sig_data_len
        [636:700]    ECDSA signature over [0:632]
        [700:764]    attestation public key (x || y)
        [764:770]    cert_data_type u16 || cert_data_size u32   <- the wrapper
        [770:1154]   QE report (sgx_report_body_t)
        [1154:1218]  QE report signature
        [1218:...]   qe_auth_size u16 || qe_auth || PCK cert-data header+chain

    ``qe_sig_key`` is whichever key signs the QE report.  Passing
    ``chain.leaf_key`` models a genuine quote; passing a key that is *not* in
    ``chain_pem`` models the forgery in
    ``TestQeReportSignatureBindsTheAttestationKey``.  The attestation keypair
    is always generated here and always really signs the TD report, so the
    quote is internally consistent whichever key is used.
    """
    signed = _signed_body(report_data, mrtd)
    att_key = ec.generate_private_key(ec.SECP256R1())
    att_key_xy = _public_xy(att_key)
    td_sig = _raw_sig(att_key, signed)

    qe_report = _qe_report(att_key_xy, qe_auth)
    if qe_sig is None:
        qe_sig = _raw_sig(qe_sig_key, qe_report)
    assert len(qe_sig) == 64

    inner = (qe_report + qe_sig
             + struct.pack("<H", len(qe_auth)) + qe_auth
             + struct.pack("<H", CERT_DATA_TYPE_PCK_CHAIN)
             + struct.pack("<I", len(chain_pem)) + chain_pem)
    sig_data = (td_sig + att_key_xy
                + struct.pack("<H", cert_data_type)
                + struct.pack("<I", len(inner)) + inner)
    quote = signed + struct.pack("<I", len(sig_data)) + sig_data

    # The layout literals above, asserted against the bytes just written.
    assert quote[ATT_PUB_KEY_OFFSET:ATT_PUB_KEY_OFFSET + 64] == att_key_xy
    assert quote[LEGACY_QE_REPORT_OFFSET:V4_QE_REPORT_OFFSET] == (
        struct.pack("<H", cert_data_type) + struct.pack("<I", len(inner)))
    assert quote[V4_QE_REPORT_OFFSET:V4_QE_REPORT_OFFSET + 384] == qe_report
    assert quote[V4_QE_REPORT_SIG_OFFSET:
                 V4_QE_REPORT_SIG_OFFSET + 64] == qe_sig
    assert quote[V4_QE_AUTH_SIZE_OFFSET:V4_QE_AUTH_SIZE_OFFSET + 2] == \
        struct.pack("<H", len(qe_auth))
    return quote


def _legacy_quote(*, chain_pem: bytes, qe_sig_key, report_data: bytes = b"",
                  qe_auth: bytes = QE_AUTH_DATA) -> bytes:
    """A quote with the QE report directly at 764 — no outer cert wrapper.

    The QE report's first two bytes are CPUSVN.  ``0x000b`` (11) is used
    here because the layout probe reads those two bytes as a candidate
    ``cert_data_type`` and only ``1..7`` are defined DCAP values, so anything
    outside that range means "no wrapper".
    """
    signed = _signed_body(report_data)
    att_key = ec.generate_private_key(ec.SECP256R1())
    att_key_xy = _public_xy(att_key)
    td_sig = _raw_sig(att_key, signed)

    qe_report = _qe_report(att_key_xy, qe_auth, cpu_svn=b"\x0b\x00")
    qe_sig = _raw_sig(qe_sig_key, qe_report)

    sig_data = (td_sig + att_key_xy + qe_report + qe_sig
                + struct.pack("<H", len(qe_auth)) + qe_auth
                + struct.pack("<H", CERT_DATA_TYPE_PCK_CHAIN)
                + struct.pack("<I", len(chain_pem)) + chain_pem)
    quote = signed + struct.pack("<I", len(sig_data)) + sig_data

    assert quote[LEGACY_QE_REPORT_OFFSET:
                 LEGACY_QE_REPORT_OFFSET + 384] == qe_report
    return quote


def _walk(chain: _Chain, tmp_path, **quote_kwargs) -> dict:
    """Run the PCK chain walk over *chain*, anchored to *chain*'s own root.

    Returns the client's ``{"ok": ..., "pck_leaf"/"reason": ...}`` verdict.
    """
    client = _client(tmp_path, root_pem=chain.root_pem)
    quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key,
                      **quote_kwargs)
    return client.verify_pck_cert_chain(quote)


# ==========================================================================
# BUG 1 — the QE report offset must be detected, not assumed
# ==========================================================================

class TestQeReportOffsetDetection:
    """770 for a ``cert_data_type == 6`` v4 quote, 764 for a legacy one."""

    def test_v4_cert_wrapped_quote_puts_the_qe_report_at_770(self, tmp_path):
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key)
        assert client._locate_qe_report_offset(quote) == V4_QE_REPORT_OFFSET

    def test_legacy_quote_puts_the_qe_report_at_764(self, tmp_path):
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _legacy_quote(chain_pem=chain.chain_pem,
                              qe_sig_key=chain.leaf_key)
        assert client._locate_qe_report_offset(quote) == LEGACY_QE_REPORT_OFFSET

    @pytest.mark.parametrize("cert_data_type", (1, 2, 3, 4, 5, 6, 7))
    def test_every_defined_cert_data_type_is_recognised_as_a_wrapper(
            self, cert_data_type, tmp_path):
        """The wrapper is a wrapper whatever type it declares.

        Only type 6 carries a QE report, and ``verify_pck_cert_chain``
        rejects a non-5 *inner* type separately; the offset probe's job is
        just to spot the 6-byte header.
        """
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key,
                          cert_data_type=cert_data_type)
        assert client._locate_qe_report_offset(quote) == V4_QE_REPORT_OFFSET

    def test_quote_long_enough_for_only_the_legacy_layout_reports_764(
            self, client):
        """1148 == 764 + 384: room for a QE report at 764 but not at 770."""
        assert client._locate_qe_report_offset(b"\x00" * 1148) == \
            LEGACY_QE_REPORT_OFFSET

    def test_quote_too_short_for_either_layout_returns_none(self, client):
        assert client._locate_qe_report_offset(b"\x00" * 1147) is None
        assert client._locate_qe_report_offset(b"") is None


class TestQeReportOffsetIsUsedByBothCallers:
    """Both call sites that used to hardcode 764 now agree with the probe."""

    def test_qe_report_binding_passes_on_a_v4_quote(self, tmp_path):
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key)
        assert client.verify_qe_report_binding(quote) is True

    def test_qe_report_binding_passes_on_a_legacy_quote(self, tmp_path):
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _legacy_quote(chain_pem=chain.chain_pem,
                              qe_sig_key=chain.leaf_key)
        assert client.verify_qe_report_binding(quote) is True

    def test_pck_chain_verifies_on_a_v4_quote(self, tmp_path):
        assert _walk(_Chain(), tmp_path)["ok"] is True

    def test_pck_chain_verifies_on_a_legacy_quote(self, tmp_path):
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _legacy_quote(chain_pem=chain.chain_pem,
                              qe_sig_key=chain.leaf_key)
        assert client.verify_pck_cert_chain(quote)["ok"] is True

    def test_truncated_quote_is_a_failure_not_a_pass(self, tmp_path):
        """No QE report at either layout: fail closed, with a reason.

        This used to return the string "absent".  Both verifiers are now
        two-state (see ``TestNoSoftStateRemains``).
        """
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        result = client.verify_pck_cert_chain(b"\x00" * 1000)
        assert result["ok"] is False
        assert result["reason"] == "quote carries no QE report"
        assert "pck_leaf" not in result

    def test_the_old_hardcoded_offset_read_the_outer_cert_header(
            self, tmp_path):
        """What 764 actually points at in a v4 quote, byte for byte.

        The first 6 bytes the old code treated as the head of the QE report
        are the wrapper's ``cert_data_type`` (6) and ``cert_data_size``, and
        the 384 bytes it hashed were the QE report shifted 6 early.
        """
        chain = _Chain()
        quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key)
        qe_report = quote[V4_QE_REPORT_OFFSET:V4_QE_REPORT_OFFSET + 384]

        assert struct.unpack_from("<H", quote, LEGACY_QE_REPORT_OFFSET)[0] == \
            CERT_DATA_TYPE_QE_REPORT
        assert quote[LEGACY_QE_REPORT_OFFSET:
                     LEGACY_QE_REPORT_OFFSET + 384] != qe_report
        # ...and the 2 bytes the old code read as qe_auth_size (764+384+64 =
        # 1212) fall strictly inside the real QE report signature.
        assert V4_QE_REPORT_SIG_OFFSET <= 1212 < V4_QE_AUTH_SIZE_OFFSET

    def test_the_old_hardcoded_offset_would_not_have_found_the_pck_chain(
            self, tmp_path, monkeypatch):
        """BUG 1, behaviourally: pin the offset back to 764 and the walk fails.

        The QE report signature is fixed to 64 zero bytes in this one case so
        the misaligned read is deterministic: with them zeroed, the old offset
        reads ``qe_auth_size = 0`` out of the signature field and then a
        ``cert_data_type`` of 0 instead of 5.  Nothing in
        ``verify_pck_cert_chain`` looks at those 64 bytes — the QE report
        signature is checked by ``verify_qe_report_signature``, which this
        case does not call — so zeroing them cannot make the chain walk
        succeed or fail on its own.
        """
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key,
                          qe_sig=b"\x00" * 64)

        assert client.verify_pck_cert_chain(quote)["ok"] is True

        monkeypatch.setattr(client, "_locate_qe_report_offset",
                            lambda _quote: LEGACY_QE_REPORT_OFFSET)
        result = client.verify_pck_cert_chain(quote)
        assert result["ok"] is False
        assert result["reason"] == "cert_data_type 0 != 5"


# ==========================================================================
# BUG 2 — basicConstraints / keyUsage on the PCK chain
# ==========================================================================

class TestPckChainCaConstraints:
    """Accept a conforming chain; reject every way of using a non-CA as issuer.

    Each case differs from ``test_conforming_chain_is_accepted`` in exactly
    one certificate extension, and every signature in every case is valid, so
    the constraint check is the only thing that can decide the outcome.
    """

    def test_conforming_chain_is_accepted(self, tmp_path):
        """leaf CA:FALSE -> intermediate CA:TRUE pathlen:0 -> root pathlen:1."""
        result = _walk(_Chain(), tmp_path)
        assert result["ok"] is True, result.get("reason")
        assert result["pck_leaf"] is not None

    def test_end_entity_used_as_issuer_is_rejected(self, tmp_path):
        """The attack: a CA:FALSE certificate signing the PCK leaf.

        An attacker holding any Intel-issued end-entity certificate signs a
        forged leaf with it.  Names chain, signatures verify, the pinned
        anchor is reached — only the CA bit says no.
        """
        result = _walk(_Chain(intermediate_bc="end-entity"), tmp_path)
        assert result["ok"] is False
        assert "CA:FALSE" in result["reason"]

    def test_issuer_without_basic_constraints_is_rejected(self, tmp_path):
        result = _walk(_Chain(intermediate_bc="omit"), tmp_path)
        assert result["ok"] is False
        assert "no basicConstraints" in result["reason"]

    def test_issuer_key_usage_without_key_cert_sign_is_rejected(self, tmp_path):
        result = _walk(_Chain(intermediate_key_cert_sign=False), tmp_path)
        assert result["ok"] is False
        assert "keyCertSign" in result["reason"]

    def test_leaf_asserting_ca_true_is_rejected(self, tmp_path):
        """A leaf with CA:TRUE could mint further certs under the anchor."""
        result = _walk(_Chain(leaf_bc="ca"), tmp_path)
        assert result["ok"] is False
        assert "leaf certificate asserts basicConstraints CA:TRUE" in result["reason"]

    def test_path_len_constraint_is_enforced(self, tmp_path):
        """A pathlen:0 root cannot have an intermediate beneath it."""
        result = _walk(_Chain(root_path_len=0), tmp_path)
        assert result["ok"] is False
        assert "pathLenConstraint=0" in result["reason"]

    def test_issuer_without_key_usage_at_all_is_accepted(self, tmp_path):
        """keyUsage is optional in RFC 5280 §4.2.1.3; absent is no violation.

        Recorded so the permissiveness is a decision rather than an
        oversight: rejecting here would break any conforming chain that omits
        the extension.
        """
        result = _walk(_Chain(intermediate_omit_ku=True), tmp_path)
        assert result["ok"] is True, result.get("reason")

    def test_leaf_without_basic_constraints_is_accepted(self, tmp_path):
        """Absent basicConstraints means "not a CA" (RFC 5280 §4.2.1.9)."""
        result = _walk(_Chain(leaf_bc="omit"), tmp_path)
        assert result["ok"] is True, result.get("reason")

    def test_path_len_of_one_admits_the_single_real_intermediate(self, tmp_path):
        """The budget the real Intel root publishes: PCK leaf -> PCK CA -> root."""
        result = _walk(_Chain(root_path_len=1), tmp_path)
        assert result["ok"] is True, result.get("reason")

    def test_root_included_in_cert_data_is_not_double_counted(self, tmp_path):
        """Intel's ``cert_data`` ends with the root itself.

        Re-checking that root as one level higher than the chain position it
        already occupies would count an intermediate that does not exist and
        reject a genuine ``pathlen:1`` chain.  ``_Chain.chain_pem`` includes
        the root, so ``test_conforming_chain_is_accepted`` passing at all is
        the evidence; this asserts the boundary directly by shrinking the
        budget to 0 and watching it start failing.
        """
        chain = _Chain()
        assert chain.chain_pem.count(b"BEGIN CERTIFICATE") == 3
        assert _walk(chain, tmp_path)["ok"] is True
        assert _walk(_Chain(root_path_len=0), tmp_path)["ok"] is False


class TestNoSoftStateRemains:
    """Both verifiers are two-state: a verdict is a pass or a failure.

    This platform has twice been bitten by the ``"absent"`` tri-state, which
    was decided by a length check over the *server-supplied* quote and so was
    attacker-selectable.  Both former "absent" branches at the call site were
    already fatal, so removing the state narrowed nothing — but it removes
    something that could be widened back by mistake, and it stops a
    constraint violation ever being reported as a softer kind of outcome.

    A failed verdict must therefore be indistinguishable *in kind* from any
    other failed verdict: ``ok`` is ``False``, no ``pck_leaf`` is handed out,
    and the string states are gone from both functions' vocabulary.
    """

    _VIOLATIONS = [
        {"intermediate_bc": "end-entity"},
        {"intermediate_bc": "omit"},
        {"intermediate_key_cert_sign": False},
        {"leaf_bc": "ca"},
        {"root_path_len": 0},
    ]

    @pytest.mark.parametrize("kwargs", _VIOLATIONS)
    def test_violation_is_a_hard_failure_with_no_leaf(self, kwargs, tmp_path):
        result = _walk(_Chain(**kwargs), tmp_path)
        assert result["ok"] is False
        assert "pck_leaf" not in result
        assert isinstance(result["reason"], str) and result["reason"]

    @pytest.mark.parametrize("kwargs", _VIOLATIONS)
    def test_violation_is_never_reported_as_a_string_state(self, kwargs,
                                                           tmp_path):
        """No caller can mistake a violation for the old soft "absent"."""
        result = _walk(_Chain(**kwargs), tmp_path)
        assert not isinstance(result, str)
        assert result.get("reason") != "absent"

    def test_qe_report_binding_is_a_bool_on_every_input(self, client):
        """A truncated quote used to yield "absent" here; now it is False."""
        for blob in (b"", b"\x00" * 700, b"\x00" * 1148, b"\x00" * 4000):
            assert client.verify_qe_report_binding(blob) is False


class TestConstraintHelpers:
    """The two helpers on their own, so each rule has a named failing case."""

    def test_missing_basic_constraints_raises_value_error(self, client):
        cert = _mint("no-bc", ec.generate_private_key(ec.SECP256R1()),
                     basic_constraints="omit")
        with pytest.raises(ValueError, match="no basicConstraints"):
            client.check_ca_certificate(cert, 1, remaining_intermediates=0)

    def test_ca_false_raises_value_error(self, client):
        cert = _mint("ee", ec.generate_private_key(ec.SECP256R1()),
                     basic_constraints="end-entity")
        with pytest.raises(ValueError, match="CA:FALSE"):
            client.check_ca_certificate(cert, 1, remaining_intermediates=0)

    def test_key_usage_without_key_cert_sign_raises_value_error(self, client):
        cert = _mint("ca-no-kcs", ec.generate_private_key(ec.SECP256R1()),
                     basic_constraints="ca", key_cert_sign=False)
        with pytest.raises(ValueError, match="keyCertSign"):
            client.check_ca_certificate(cert, 1, remaining_intermediates=0)

    def test_path_len_zero_with_one_intermediate_raises_value_error(self, client):
        cert = _mint("ca-pl0", ec.generate_private_key(ec.SECP256R1()),
                     basic_constraints="ca", path_length=0)
        with pytest.raises(ValueError, match="pathLenConstraint=0"):
            client.check_ca_certificate(cert, 1, remaining_intermediates=1)

    def test_path_len_zero_with_no_intermediate_is_accepted(self, client):
        cert = _mint("ca-pl0", ec.generate_private_key(ec.SECP256R1()),
                     basic_constraints="ca", path_length=0)
        assert client.check_ca_certificate(
            cert, 1, remaining_intermediates=0) is None

    def test_unconstrained_path_len_accepts_any_depth(self, client):
        """``path_length=None`` means no pathLenConstraint was asserted."""
        cert = _mint("ca-any", ec.generate_private_key(ec.SECP256R1()),
                     basic_constraints="ca", path_length=None)
        assert client.check_ca_certificate(
            cert, 9, remaining_intermediates=8) is None

    def test_leaf_asserting_ca_true_raises_value_error(self, client):
        cert = _mint("bad-leaf", ec.generate_private_key(ec.SECP256R1()),
                     basic_constraints="ca")
        with pytest.raises(ValueError, match="CA:TRUE"):
            client.check_leaf_certificate(cert)

    def test_end_entity_leaf_is_accepted(self, client):
        cert = _mint("good-leaf", ec.generate_private_key(ec.SECP256R1()),
                     basic_constraints="end-entity")
        assert client.check_leaf_certificate(cert) is None


class TestRealPinnedRoot:
    """Anchor the positive path in the certificate actually shipped.

    The synthetic root only proves the walk works on *some* conforming chain.
    These read ``certs/intel-sgx-dcap-root.pem`` straight off disk and assert
    the constraints the checks rely on are the ones Intel really publishes.
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

    def test_shipped_root_passes_the_ca_check_with_its_real_budget(self, client):
        """One intermediate under a pathlen:1 root is exactly in budget."""
        assert client.check_ca_certificate(
            self._root(), 2, remaining_intermediates=1) is None

    def test_shipped_root_rejects_two_intermediates(self, client):
        with pytest.raises(ValueError, match="pathLenConstraint=1"):
            client.check_ca_certificate(self._root(), 3,
                                        remaining_intermediates=2)

    def test_shipped_root_is_not_treated_as_a_leaf(self, client):
        with pytest.raises(ValueError, match="CA:TRUE"):
            client.check_leaf_certificate(self._root())


# ==========================================================================
# BUG 3 — the QE report signature, which is what anchors everything above
# ==========================================================================

class TestQeReportSignatureBindsTheAttestationKey:
    """The full-bypass forgery, and the check that stops it.

    ``_forged_quote`` below is what a host-level adversary can actually
    build.  It needs no Intel key and no hardware:

    * generate a P-256 keypair — this becomes the "attestation key";
    * write any MRTD into the TD report body and sign the 632 signed bytes
      with that key, so ``verify_tdx_quote_signature`` passes;
    * set the QE report's ``report_data`` to
      ``SHA-256(att_pub || qe_auth)``, so ``verify_qe_report_binding``
      passes;
    * paste in a PCK chain that validates to the pinned Intel root — these
      are public, every genuine quote carries one — so
      ``verify_pck_cert_chain`` passes;
    * sign the QE report with a key of their own, because nothing checked
      that signature.

    The first three assertions in ``test_forged_attestation_key_...`` are
    there to prove the forgery really does satisfy every *other* check, so
    the last assertion is the only thing standing between this quote and an
    accepted attestation with an arbitrary MRTD.
    """

    @staticmethod
    def _forged_quote(chain: _Chain) -> bytes:
        """A quote with a genuine chain whose leaf did NOT sign the QE report.

        The MRTD is the client's own pinned value — an attacker knows it,
        it is shipped in the client script — so even the MRTD pin does not
        catch this quote.  Nothing here requires an Intel key: the QE report
        is signed by a keypair generated on the spot.
        """
        rogue_qe_key = ec.generate_private_key(ec.SECP256R1())
        return _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=rogue_qe_key,
                         mrtd=bytes.fromhex(PINNED_MRTD_HEX))

    def test_conforming_quote_is_accepted(self, tmp_path):
        """The PCK leaf really signed the QE report: accepted."""
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key)
        assert client.verify_qe_report_signature(quote, chain.leaf) is True

    def test_forged_attestation_key_with_a_genuine_pck_chain_is_rejected(
            self, tmp_path):
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = self._forged_quote(chain)

        # Every pre-existing CPU-side check is satisfied by the forgery...
        assert client.verify_tdx_quote_signature(quote) is True
        assert client.verify_qe_report_binding(quote) is True
        pck = client.verify_pck_cert_chain(quote)
        assert pck["ok"] is True, pck.get("reason")
        # ...including the MRTD pin, because the pinned value is public.
        assert client.EXPECTED_MRTD == PINNED_MRTD_HEX
        assert client.parse_tdx_quote(quote)["mrtd"] == client.EXPECTED_MRTD

        # ...and this is the one check that refuses it.
        assert client.verify_qe_report_signature(quote, pck["pck_leaf"]) is False

    def test_the_forgery_is_rejected_using_the_chain_verified_leaf(self, tmp_path):
        """The leaf fed to the signature check comes from the chain walk.

        Structural: ``verify_pck_cert_chain`` hands back the certificate it
        validated, and that exact object is what refuses the forgery.  A
        second, independent parse of ``cert_data`` would recreate the gap the
        return value closes.
        """
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = self._forged_quote(chain)
        leaf = client.verify_pck_cert_chain(quote)["pck_leaf"]

        assert leaf.public_bytes(serialization.Encoding.DER) == \
            chain.leaf.public_bytes(serialization.Encoding.DER)
        assert client.verify_qe_report_signature(quote, leaf) is False

    def test_returned_leaf_is_the_chain_leaf_not_an_issuer(self, tmp_path):
        """Leaf-first ordering: ``pck_leaf`` must be the end entity."""
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key)
        leaf = client.verify_pck_cert_chain(quote)["pck_leaf"]

        der = leaf.public_bytes(serialization.Encoding.DER)
        assert der == chain.leaf.public_bytes(serialization.Encoding.DER)
        assert der != chain.intermediate.public_bytes(serialization.Encoding.DER)
        assert der != chain.root.public_bytes(serialization.Encoding.DER)
        assert client.verify_qe_report_signature(quote, leaf) is True

    def test_a_leaf_from_a_different_chain_does_not_verify(self, tmp_path):
        """Two genuine platforms: A's QE report is not signed by B's leaf."""
        chain_a, chain_b = _Chain(), _Chain()
        client = _client(tmp_path, root_pem=chain_a.root_pem)
        quote = _v4_quote(chain_pem=chain_a.chain_pem,
                          qe_sig_key=chain_a.leaf_key)
        assert client.verify_qe_report_signature(quote, chain_a.leaf) is True
        assert client.verify_qe_report_signature(quote, chain_b.leaf) is False

    def test_tampered_qe_report_is_rejected(self, tmp_path):
        """One flipped byte inside the signed 384 bytes breaks the signature."""
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = bytearray(_v4_quote(chain_pem=chain.chain_pem,
                                    qe_sig_key=chain.leaf_key))
        quote[V4_QE_REPORT_OFFSET + 8] ^= 0xFF
        assert client.verify_qe_report_signature(bytes(quote),
                                                 chain.leaf) is False

    def test_legacy_layout_quote_verifies_at_764(self, tmp_path):
        """The signature check uses the detected offset, not a hardcoded one."""
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _legacy_quote(chain_pem=chain.chain_pem,
                              qe_sig_key=chain.leaf_key)
        assert client.verify_qe_report_signature(quote, chain.leaf) is True

    def test_wrong_offset_would_verify_nothing(self, tmp_path, monkeypatch):
        """BUG 1 and BUG 3 interact: at 764 the signed bytes are the wrong 384."""
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key)
        assert client.verify_qe_report_signature(quote, chain.leaf) is True

        monkeypatch.setattr(client, "_locate_qe_report_offset",
                            lambda _quote: LEGACY_QE_REPORT_OFFSET)
        assert client.verify_qe_report_signature(quote, chain.leaf) is False

    def test_truncated_quote_has_no_signature_to_verify(self, tmp_path):
        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        for blob in (b"", b"\x00" * 1148, b"\x00" * 1217):
            assert client.verify_qe_report_signature(blob, chain.leaf) is False

    def test_non_ecdsa_pck_leaf_is_refused_not_skipped(self, tmp_path, capsys):
        """An RSA "PCK leaf" is a reason to refuse, never a reason to skip."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        chain = _Chain()
        client = _client(tmp_path, root_pem=chain.root_pem)
        quote = _v4_quote(chain_pem=chain.chain_pem, qe_sig_key=chain.leaf_key)
        rsa_leaf = _mint("rsa-leaf", rsa.generate_private_key(
            public_exponent=65537, key_size=2048),
            basic_constraints="end-entity", key_cert_sign=False)

        assert client.verify_qe_report_signature(quote, rsa_leaf) is False
        assert "not ECDSA" in capsys.readouterr().err


class TestCallSiteWiring:
    """The fix has to be reached, not merely defined.

    These read the template source: a unit-level ``verify_qe_report_signature``
    that no code path calls would leave the vulnerability wide open, and the
    leaf has to travel from the chain walk to the signature check without a
    second parse in between.  A live end-to-end run is not available here —
    it would need a TDX host and an NVIDIA NRAS token — so the wiring is
    pinned statically.
    """

    def _source(self) -> str:
        with open(_TEMPLATE, encoding="utf-8") as fh:
            return fh.read()

    def test_signature_check_is_called_with_the_chain_walk_result(self):
        src = self._source()
        assert 'verify_qe_report_signature(quote_bytes, pck_result["pck_leaf"])' \
            in src

    def test_signature_failure_is_fatal(self):
        src = self._source()
        idx = src.index("if not verify_qe_report_signature(")
        tail = src[idx:idx + 500]
        assert "conn.close()" in tail
        assert "sys.exit(1)" in tail
        assert "FATAL" in tail

    def test_the_signature_check_runs_after_the_chain_walk(self):
        """Order matters: the leaf does not exist before the walk."""
        src = self._source()
        assert src.index("pck_result = verify_pck_cert_chain(quote_bytes)") < \
            src.index("if not verify_qe_report_signature(")

    def test_cert_data_is_parsed_in_exactly_one_place(self):
        """No second parse to drift away from the one that was verified.

        Counts PEM-scanning loops, not occurrences of the PEM marker — the
        single loop mentions it twice (``in remainder`` and ``.index``).
        """
        src = self._source()
        assert src.count('while b"-----BEGIN CERTIFICATE-----" in remainder') == 1

    @pytest.mark.parametrize("func,expected", [
        ("verify_qe_report_binding", bool),
        ("verify_qe_report_signature", bool),
        ("verify_pck_cert_chain", dict),
    ])
    def test_no_string_tri_state_survives_in_either_verifier(self, func,
                                                             expected):
        """The old "absent"/"passed"/"failed" returns are gone from the code.

        Walked with ``ast`` rather than grepped, so the docstrings that
        *describe* the removed states cannot satisfy or break this.
        """
        tree = ast.parse(self._source())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == func)
        returns = [n.value for n in ast.walk(fn)
                   if isinstance(n, ast.Return) and n.value is not None]
        assert returns, f"{func} has no value-returning statement"
        for value in returns:
            assert not (isinstance(value, ast.Constant)
                        and isinstance(value.value, str)), (
                f"{func} still returns the string literal "
                f"{getattr(value, 'value', None)!r}")
        # ...and at least one return really is of the declared shape.
        literal_kinds = {
            dict: ast.Dict,
            bool: (ast.Constant, ast.Compare, ast.BoolOp),
        }[expected]
        assert any(isinstance(v, literal_kinds) for v in returns)


class TestIntelVerifierParity:
    """All four Intel-anchored clients must define the same verifiers.

    This bug family — a wrong offset, a missing constraint check, a missing
    signature check — happened because four copies of the same DCAP verifier
    drifted and nothing compared them.  Reading each template's ``def``s and
    requiring the security-relevant set is cheap and would have caught the
    missing ``verify_qe_report_signature`` here the moment the other three
    got theirs.

    The QE-identity drift this docstring used to describe is gone:
    ``_check_qe_identity_tcb_status`` and the unsigned ``_qe_identity_lookup_path``
    reader were deleted from all four clients rather than copied into
    ``gpu_cc/gcp``, and replaced by the shared signed-collateral evaluator in
    ``templates/common/tee_crafter_tcb_eval.py``.
    """

    #: Every Intel DCAP client must verify all of these.
    REQUIRED = (
        "verify_qe_report_binding",
        "verify_qe_report_signature",
        "verify_pck_cert_chain",
        "check_ca_certificate",
        "check_leaf_certificate",
    )
    INTEL_CLIENTS = (
        "sgx/client.template.py",
        "tdx/azure/client.template.py",
        "tdx/gcp/client.template.py",
        "gpu_cc/gcp/client.template.py",
    )
    #: SGX v3 puts the QE report at a fixed 564, so only the TDX v4 clients
    #: need the layout probe.
    TDX_CLIENTS = INTEL_CLIENTS[1:]

    @staticmethod
    def _defs(relpath: str) -> set:
        path = os.path.join(_PKG_DIR, "templates", *relpath.split("/"))
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        return {n.name for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef)}

    @pytest.mark.parametrize("relpath", INTEL_CLIENTS)
    def test_every_intel_client_defines_every_verifier(self, relpath):
        missing = sorted(set(self.REQUIRED) - self._defs(relpath))
        assert missing == [], f"{relpath} is missing {missing}"

    @pytest.mark.parametrize("relpath", TDX_CLIENTS)
    def test_every_tdx_client_detects_the_qe_report_offset(self, relpath):
        assert "_locate_qe_report_offset" in self._defs(relpath), relpath

    @staticmethod
    def _enforce_call_keywords(relpath: str) -> set:
        """Keyword argument names passed to the shared evaluator's ``enforce``."""
        path = os.path.join(_PKG_DIR, "templates", *relpath.split("/"))
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        names = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Matches ``tcb.enforce(...)`` regardless of the import alias.
            if isinstance(func, ast.Attribute) and func.attr == "enforce":
                names |= {kw.arg for kw in node.keywords if kw.arg}
        return names

    @pytest.mark.parametrize("relpath", TDX_CLIENTS)
    def test_every_tdx_client_passes_the_td_report_body(self, relpath):
        """The TDX-module check needs MRSIGNERSEAM, which lives in the TD report.

        ``tee_crafter_tcb_eval.evaluate()`` refuses a TDX evaluation without
        ``td_report_body`` rather than skipping the module check — the right
        choice, but it means a client that forgets to pass it fails **every**
        TDX verification at runtime. Nothing else in the suite exercises this
        wiring: the evaluator's own tests call it directly, and no test renders
        a client and drives a real quote through it. So the wiring is asserted
        here, at the one place that already knows all four clients must agree.
        """
        keywords = self._enforce_call_keywords(relpath)
        assert "td_report_body" in keywords, (
            f"{relpath} calls tcb.enforce() without td_report_body — every "
            f"TDX verification on this platform will refuse. Pass "
            f"td_report_body=quote_bytes[48:632]. Got: {sorted(keywords)}")

    def test_sgx_client_does_not_pass_the_td_report_body(self):
        """SGX has no TD report; passing one would be a copy-paste artefact."""
        keywords = self._enforce_call_keywords("sgx/client.template.py")
        assert "td_report_body" not in keywords
        # Guard against the assertion above passing vacuously because the
        # call shape changed and no keywords were found at all.
        assert "tee" in keywords, keywords
