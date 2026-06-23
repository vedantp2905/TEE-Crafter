"""Builder-side Intel PCS TCB collateral: fetch, verify, bundle.

Every fixture here is minted locally with ``cryptography`` -- own root CA, own
"TCB Signing" leaf, own PCK CA, own documents signed by hand with
``private_key.sign(...)``.  Nothing is produced by the code under test, so a
passing signature check means the verifier agrees with an independent signer
rather than agreeing with itself.

No test touches the network: ``http_get`` is injected everywhere, and the
pinned trust anchor is injected via ``root_ca=`` so the suite never depends on
the repo PEM being current.

The load-bearing test is ``test_reserialized_document_is_rejected``.  Intel
signs the *verbatim response bytes* of the ``tcbInfo`` / ``enclaveIdentity``
value; a ``json.loads`` -> ``json.dumps`` round-trip changes them and must
fail.  Measured against live PCS output on 2026-08-20: Intel's real signature
verified against the raw substring, and *also* against
``json.dumps(..., separators=(",", ":"))`` purely because Intel currently
emits whitespace-free JSON in document order.  It failed with
``sort_keys=True`` and with default spacing.  So the round-trip looks correct
today and silently breaks the moment formatting shifts -- hence the fixture
below is deliberately built so that *no* ``json.dumps`` setting can reproduce
its on-wire bytes.
"""

import base64
import datetime
import json
import os
import urllib.parse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.x509.oid import NameOID

from tee_crafter.core.attestation.tcb_collateral import (
    FMSPC_ITEMS,
    REQUIRED_ITEMS,
    SCHEMA_VERSION,
    ChainVerificationError,
    CollateralError,
    CollateralFetchError,
    CollateralFormatError,
    HttpResponse,
    SignatureVerificationError,
    build_collateral_bundle,
    decode_issuer_chain,
    extract_signed_value,
    stage_tcb_collateral,
    verify_collateral_bundle,
    verify_issuer_chain,
    verify_pck_crl,
    verify_root_ca_crl,
    verify_signed_json,
)

#: Every item name the builder can emit.  The client's reader has a *closed*
#: whitelist of names and rejects the whole bundle on an unknown one, so this
#: tuple is half of a two-sided contract; see
#: ``TestBuilderClientContract`` at the bottom of this file.
ALL_ITEM_NAMES = (
    "sgx_tcb_info", "tdx_tcb_info", "sgx_qe_identity", "tdx_qe_identity",
    "sgx_pck_crl_platform", "sgx_pck_crl_processor", "sgx_root_ca_crl",
)

NOW = datetime.datetime(2026, 8, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
_NOT_BEFORE = NOW - datetime.timedelta(days=30)
_NOT_AFTER = NOW + datetime.timedelta(days=365)
FMSPC = "00806F050000"


# ---------------------------------------------------------------------------
# Local PKI
# ---------------------------------------------------------------------------


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _mint(common_name, *, issuer_name=None, issuer_key=None, ca=False,
          path_length=None, key_usage=None, not_before=_NOT_BEFORE,
          not_after=_NOT_AFTER, omit_basic_constraints=False):
    """Mint one certificate.  Self-signed when no issuer key is given."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(common_name)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name if issuer_name is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if not omit_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    cert = builder.sign(issuer_key if issuer_key is not None else key,
                        hashes.SHA256())
    return cert, key


def _ca_key_usage(crl_sign=True):
    return x509.KeyUsage(
        digital_signature=False, content_commitment=False,
        key_encipherment=False, data_encipherment=False, key_agreement=False,
        key_cert_sign=True, crl_sign=crl_sign, encipher_only=False,
        decipher_only=False)


def _signing_key_usage(digital_signature=True):
    return x509.KeyUsage(
        digital_signature=digital_signature, content_commitment=True,
        key_encipherment=False, data_encipherment=False, key_agreement=False,
        key_cert_sign=False, crl_sign=False, encipher_only=False,
        decipher_only=False)


def _pem(*certs) -> str:
    return "".join(
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        for cert in certs
    )


class Pki:
    """A stand-in for Intel's DCAP PKI, mirroring the real shape.

    Real chains observed on 2026-08-20:
      * TCBInfo / QEIdentity: ``CN=Intel SGX TCB Signing`` (CA:FALSE,
        keyUsage digitalSignature+contentCommitment) then ``CN=Intel SGX
        Root CA`` (CA:TRUE pathlen:1, keyCertSign+cRLSign).
      * PCK CRL: ``CN=Intel SGX PCK Platform CA`` (CA:TRUE pathlen:0,
        keyCertSign+cRLSign) then the same root.
    """

    def __init__(self):
        self.root, self.root_key = _mint(
            "Test SGX Root CA", ca=True, path_length=1,
            key_usage=_ca_key_usage())
        self.tcb_signing, self.tcb_signing_key = _mint(
            "Test SGX TCB Signing", issuer_name=self.root.subject,
            issuer_key=self.root_key, ca=False,
            key_usage=_signing_key_usage())
        self.pck_ca, self.pck_ca_key = _mint(
            "Test SGX PCK Platform CA", issuer_name=self.root.subject,
            issuer_key=self.root_key, ca=True, path_length=0,
            key_usage=_ca_key_usage())

    @property
    def tcb_chain_pem(self) -> str:
        return _pem(self.tcb_signing, self.root)

    @property
    def pck_crl_chain_pem(self) -> str:
        return _pem(self.pck_ca, self.root)


@pytest.fixture
def pki():
    return Pki()


# ---------------------------------------------------------------------------
# Hand-signed documents
# ---------------------------------------------------------------------------


def _sign_raw(private_key, payload: bytes) -> str:
    """Sign ``payload`` the way Intel does: ECDSA P-256/SHA-256, hex r||s."""
    der = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def make_signed_body(private_key, value_key: str, value_json: str) -> bytes:
    """Wrap a *literal* value string and its signature into a response body.

    ``value_json`` is inserted verbatim, so a caller can hand-craft on-wire
    formatting (whitespace, escaped solidus, exponent numbers) that no
    ``json.dumps`` setting reproduces.
    """
    signature = _sign_raw(private_key, value_json.encode("utf-8"))
    return (
        '{"' + value_key + '":' + value_json
        + ',"signature":"' + signature + '"}'
    ).encode("utf-8")


#: Formatting no ``json.dumps`` call can reproduce, so a round-trip provably
#: changes the bytes:
#:   * spaces and a newline between tokens   -> compact dumps differs
#:   * keys not in sorted order              -> sort_keys=True differs
#:   * ``1.50`` and ``2e1``                  -> float repr becomes 1.5 / 20.0
#:   * ``"a\/b"``                            -> dumps emits an unescaped "/"
_AWKWARD_TCB_INFO = (
    '{ "id": "TDX",\n'
    '  "version": 3,\n'
    '  "fmspc": "' + FMSPC + '",\n'
    '  "advisoryURL": "https:\\/\\/security-center.intel.com",\n'
    '  "tcbEvaluationDataNumber": 2e1,\n'
    '  "someRatio": 1.50,\n'
    '  "tcbLevels": [ { "tcbStatus": "UpToDate" } ] }'
)

_COMPACT_ENCLAVE_IDENTITY = json.dumps(
    {
        "id": "TD_QE",
        "version": 2,
        "tcbEvaluationDataNumber": 20,
        "miscselect": "00000000",
        "miscselectMask": "FFFFFFFF",
        "isvprodid": 2,
        "tcbLevels": [{"tcb": {"isvsvn": 4}, "tcbStatus": "UpToDate"}],
    },
    separators=(",", ":"),
)


@pytest.fixture
def tcb_info_body(pki):
    return make_signed_body(pki.tcb_signing_key, "tcbInfo", _AWKWARD_TCB_INFO)


@pytest.fixture
def qe_identity_body(pki):
    return make_signed_body(pki.tcb_signing_key, "enclaveIdentity",
                            _COMPACT_ENCLAVE_IDENTITY)


def make_crl(pki, *, issuer_cert=None, issuer_key=None) -> bytes:
    issuer_cert = issuer_cert if issuer_cert is not None else pki.pck_ca
    issuer_key = issuer_key if issuer_key is not None else pki.pck_ca_key
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(_NOT_BEFORE)
        .next_update(_NOT_AFTER)
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(1234)
            .revocation_date(_NOT_BEFORE)
            .build()
        )
    )
    crl = builder.sign(issuer_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def crl_der(pki):
    return make_crl(pki)


@pytest.fixture
def root_crl_der(pki):
    """The Root-CA-issued CRL: the only thing that can revoke a PCK CA."""
    return make_crl(pki, issuer_cert=pki.root, issuer_key=pki.root_key)


# ---------------------------------------------------------------------------
# Injected HTTP
# ---------------------------------------------------------------------------


def _url_encoded(pem: str) -> str:
    """Reproduce Intel's percent-encoded issuer-chain header value."""
    return urllib.parse.quote(pem, safe="")


class FakePcs:
    """Injectable ``http_get``.  Records calls; never opens a socket."""

    def __init__(self, pki, tcb_info_body, qe_identity_body, crl_der,
                 root_crl_der=None, *, fail_paths=(), status_overrides=None,
                 drop_chain_paths=(), root_crl_chain_header=None):
        self.pki = pki
        self.tcb_info_body = tcb_info_body
        self.qe_identity_body = qe_identity_body
        self.crl_der = crl_der
        self.root_crl_der = (root_crl_der if root_crl_der is not None
                             else make_crl(pki, issuer_cert=pki.root,
                                           issuer_key=pki.root_key))
        self.fail_paths = tuple(fail_paths)
        self.status_overrides = dict(status_overrides or {})
        self.drop_chain_paths = tuple(drop_chain_paths)
        #: Lets a test prove that a chain *offered* for the root CA CRL is
        #: ignored rather than consulted.
        self.root_crl_chain_header = root_crl_chain_header
        self.calls: list[str] = []

    def __call__(self, url: str, timeout: float) -> HttpResponse:
        self.calls.append(url)
        for fragment in self.fail_paths:
            if fragment in url:
                raise CollateralFetchError(f"injected failure for {fragment}")
        for fragment, status in self.status_overrides.items():
            if fragment in url:
                return HttpResponse(status=status, headers={}, body=b"nope")

        if "IntelSGXRootCA.der" in url:
            # Intel serves this as a bare S3 object: DER body, no issuer-chain
            # header of any kind (observed 2026-08-20).
            headers = {"Content-Type": "binary/octet-stream"}
            if self.root_crl_chain_header is not None:
                headers["SGX-PCK-CRL-Issuer-Chain"] = _url_encoded(
                    self.root_crl_chain_header)
            return HttpResponse(status=200, headers=headers,
                                body=self.root_crl_der)

        if "/tcb?" in url:
            header = "TCB-Info-Issuer-Chain"
            chain = self.pki.tcb_chain_pem
            body = self.tcb_info_body
        elif "/qe/identity" in url:
            header = "SGX-Enclave-Identity-Issuer-Chain"
            chain = self.pki.tcb_chain_pem
            body = self.qe_identity_body
        elif "/pckcrl" in url:
            header = "SGX-PCK-CRL-Issuer-Chain"
            chain = self.pki.pck_crl_chain_pem
            body = self.crl_der
        else:
            return HttpResponse(status=404, headers={}, body=b"")

        headers = {"Content-Type": "application/json"}
        if not any(fragment in url for fragment in self.drop_chain_paths):
            headers[header] = _url_encoded(chain)
        return HttpResponse(status=200, headers=headers, body=body)


@pytest.fixture
def fake_pcs(pki, tcb_info_body, qe_identity_body, crl_der, root_crl_der):
    return FakePcs(pki, tcb_info_body, qe_identity_body, crl_der, root_crl_der)


def _bundle(pki, fake_pcs, fmspc=FMSPC, **kwargs):
    """Build a bundle against the fake PCS with both hosts redirected."""
    kwargs.setdefault("base_url", "https://pcs.test")
    kwargs.setdefault("certificates_base_url", "https://certs.test")
    return build_collateral_bundle(fmspc, http_get=fake_pcs, root_ca=pki.root,
                                   now=NOW, **kwargs)


# ===========================================================================
# extract_signed_value: the raw-bytes slice
# ===========================================================================


def test_extract_signed_value_returns_verbatim_bytes(tcb_info_body):
    raw = extract_signed_value(tcb_info_body, "tcbInfo")
    assert raw == _AWKWARD_TCB_INFO.encode("utf-8")
    # The slice must be a genuine substring of the wire body, not a rebuild.
    assert raw in tcb_info_body


def test_extract_signed_value_handles_nested_braces_and_escapes():
    body = (
        b'{"tcbInfo":{"a":{"b":"}}not-the-end{{"},"c":"quote\\"brace}"},'
        b'"signature":"00"}'
    )
    assert extract_signed_value(body, "tcbInfo") == (
        b'{"a":{"b":"}}not-the-end{{"},"c":"quote\\"brace}"}'
    )


def test_extract_signed_value_tolerates_whitespace_before_colon():
    body = b'{"enclaveIdentity"  :  {"id":"TD_QE"},"signature":"00"}'
    assert extract_signed_value(body, "enclaveIdentity") == b'{"id":"TD_QE"}'


def test_extract_signed_value_missing_key_raises_format_error():
    with pytest.raises(CollateralFormatError, match="no 'tcbInfo' member"):
        extract_signed_value(b'{"other":{}}', "tcbInfo")


def test_extract_signed_value_unterminated_object_raises_format_error():
    with pytest.raises(CollateralFormatError, match="not terminated"):
        extract_signed_value(b'{"tcbInfo":{"a":1', "tcbInfo")


def test_extract_signed_value_non_object_raises_format_error():
    with pytest.raises(CollateralFormatError, match="not a JSON object"):
        extract_signed_value(b'{"tcbInfo":"a string"}', "tcbInfo")


# ===========================================================================
# Document signature verification
# ===========================================================================


def test_valid_tcb_info_is_accepted(pki, tcb_info_body):
    signed = verify_signed_json(tcb_info_body, "tcbInfo", pki.tcb_chain_pem,
                                root_ca=pki.root, now=NOW)
    assert signed == _AWKWARD_TCB_INFO.encode("utf-8")


def test_valid_qe_identity_is_accepted(pki, qe_identity_body):
    signed = verify_signed_json(qe_identity_body, "enclaveIdentity",
                                pki.tcb_chain_pem, root_ca=pki.root, now=NOW)
    assert signed == _COMPACT_ENCLAVE_IDENTITY.encode("utf-8")


@pytest.mark.parametrize("dumps_kwargs", [
    {},                                            # default spacing
    {"separators": (",", ":")},                    # compact
    {"separators": (",", ":"), "sort_keys": True},  # compact + sorted
    {"indent": 2},                                 # pretty-printed
])
def test_reserialized_document_is_rejected(pki, dumps_kwargs):
    """LOAD-BEARING: verification must use the verbatim bytes, both ways.

    Two halves, deliberately in one test so neither can be deleted without the
    other noticing:

    * the *original*, awkwardly-formatted document must be ACCEPTED.  This is
      the half that kills the "simplification" -- swap
      ``extract_signed_value`` for ``json.loads`` -> ``json.dumps`` and this
      assertion fails, because no ``json.dumps`` setting reproduces the wire
      bytes Intel signed.
    * the *re-serialized* document must be REJECTED.  This is the half that
      kills a verifier which canonicalizes its input before checking, or which
      skips the signature check altogether.
    """
    original = make_signed_body(pki.tcb_signing_key, "tcbInfo",
                               _AWKWARD_TCB_INFO)
    assert verify_signed_json(original, "tcbInfo", pki.tcb_chain_pem,
                              root_ca=pki.root, now=NOW) == \
        _AWKWARD_TCB_INFO.encode("utf-8")

    parsed = json.loads(original)
    round_tripped = json.dumps(parsed["tcbInfo"], **dumps_kwargs)
    assert round_tripped != _AWKWARD_TCB_INFO, (
        "fixture no longer differs from this json.dumps setting; the test "
        "would pass for the wrong reason"
    )
    reserialized = (
        '{"tcbInfo":' + round_tripped
        + ',"signature":"' + parsed["signature"] + '"}'
    ).encode("utf-8")

    with pytest.raises(SignatureVerificationError, match="did not verify"):
        verify_signed_json(reserialized, "tcbInfo", pki.tcb_chain_pem,
                           root_ca=pki.root, now=NOW)


def test_tampered_field_is_rejected(pki, tcb_info_body):
    tampered = tcb_info_body.replace(b'"UpToDate"', b'"OutOfDate"')
    assert tampered != tcb_info_body
    with pytest.raises(SignatureVerificationError):
        verify_signed_json(tampered, "tcbInfo", pki.tcb_chain_pem,
                           root_ca=pki.root, now=NOW)


def test_whitespace_only_change_is_rejected(pki, tcb_info_body):
    """Even semantically-null reformatting breaks the signature, by design."""
    tampered = tcb_info_body.replace(b'"id": "TDX"', b'"id":"TDX"')
    assert tampered != tcb_info_body
    with pytest.raises(SignatureVerificationError):
        verify_signed_json(tampered, "tcbInfo", pki.tcb_chain_pem,
                           root_ca=pki.root, now=NOW)


def test_signature_from_a_different_key_is_rejected(pki, tcb_info_body):
    _, other_key = _mint("Impostor Signing", issuer_name=pki.root.subject,
                         issuer_key=pki.root_key, ca=False,
                         key_usage=_signing_key_usage())
    forged = make_signed_body(other_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(SignatureVerificationError):
        verify_signed_json(forged, "tcbInfo", pki.tcb_chain_pem,
                           root_ca=pki.root, now=NOW)


def test_missing_signature_field_raises_format_error(pki):
    body = ('{"tcbInfo":' + _AWKWARD_TCB_INFO + '}').encode("utf-8")
    with pytest.raises(CollateralFormatError, match="no 'signature' string"):
        verify_signed_json(body, "tcbInfo", pki.tcb_chain_pem,
                           root_ca=pki.root, now=NOW)


def test_wrong_length_signature_raises_format_error(pki):
    body = ('{"tcbInfo":' + _AWKWARD_TCB_INFO + ',"signature":"aabb"}').encode()
    with pytest.raises(CollateralFormatError, match="expected 64"):
        verify_signed_json(body, "tcbInfo", pki.tcb_chain_pem,
                           root_ca=pki.root, now=NOW)


def test_non_hex_signature_raises_format_error(pki):
    body = ('{"tcbInfo":' + _AWKWARD_TCB_INFO
            + ',"signature":"' + "z" * 128 + '"}').encode()
    with pytest.raises(CollateralFormatError, match="not hex"):
        verify_signed_json(body, "tcbInfo", pki.tcb_chain_pem,
                           root_ca=pki.root, now=NOW)


def test_non_json_body_raises_format_error(pki):
    with pytest.raises(CollateralFormatError, match="not valid JSON"):
        verify_signed_json(b"<html>proxy error</html>", "tcbInfo",
                           pki.tcb_chain_pem, root_ca=pki.root, now=NOW)


# ===========================================================================
# Issuer chain / anchoring
# ===========================================================================


def test_chain_terminating_at_a_foreign_root_is_rejected(pki, tcb_info_body):
    """A chain anchored on some *other* real root must not validate."""
    other_root, other_root_key = _mint("Other Root CA", ca=True, path_length=1,
                                       key_usage=_ca_key_usage())
    leaf, leaf_key = _mint("Other TCB Signing", issuer_name=other_root.subject,
                           issuer_key=other_root_key, ca=False,
                           key_usage=_signing_key_usage())
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError):
        verify_signed_json(body, "tcbInfo", _pem(leaf, other_root),
                           root_ca=pki.root, now=NOW)


def test_foreign_leaf_with_the_root_omitted_is_rejected(pki):
    """The pinned root must actually be made to *verify* the chain's top.

    ``test_chain_terminating_at_a_foreign_root_is_rejected`` is caught by the
    "top is self-signed and is not the pinned root" guard alone.  This case
    strips the foreign root from the header, so the only thing standing between
    an attacker chain and acceptance is the final signature check against the
    pinned anchor.  (Found by mutation testing: deleting that check left every
    other chain test green.)
    """
    other_root, other_root_key = _mint("Other Root CA", ca=True, path_length=1,
                                       key_usage=_ca_key_usage())
    leaf, leaf_key = _mint("Other TCB Signing", issuer_name=other_root.subject,
                           issuer_key=other_root_key, ca=False,
                           key_usage=_signing_key_usage())
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="did not sign"):
        verify_signed_json(body, "tcbInfo", _pem(leaf), root_ca=pki.root,
                           now=NOW)


def test_foreign_crl_issuer_with_the_root_omitted_is_rejected(pki):
    """Same gap, CRL path: a lone foreign PCK CA must not be accepted."""
    rogue = Pki()
    with pytest.raises(ChainVerificationError, match="did not sign"):
        verify_pck_crl(make_crl(rogue), _pem(rogue.pck_ca), root_ca=pki.root,
                       now=NOW)


def test_intermediate_that_did_not_sign_the_leaf_is_rejected(pki):
    """The mid-chain signature walk must run, not just the endpoints.

    ``inter`` is a genuine CA under the pinned root, but it did not sign
    ``leaf`` -- ``leaf`` merely *names* it as issuer.  Only the
    ``chain[i]``/``chain[i+1]`` walk catches that.
    """
    inter, _inter_key = _mint("Real Intermediate", issuer_name=pki.root.subject,
                              issuer_key=pki.root_key, ca=True, path_length=0,
                              key_usage=_ca_key_usage())
    _impostor, impostor_key = _mint("Impostor Intermediate", ca=True,
                                    path_length=0, key_usage=_ca_key_usage())
    leaf, leaf_key = _mint("Forged TCB Signing", issuer_name=inter.subject,
                           issuer_key=impostor_key, ca=False,
                           key_usage=_signing_key_usage())
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="did not sign"):
        verify_signed_json(body, "tcbInfo", _pem(leaf, inter, pki.root),
                           root_ca=pki.root, now=NOW)


def test_self_minted_chain_carrying_its_own_root_is_rejected(pki):
    """The circular-anchor trap.

    Intel ships a copy of the root CA inside the issuer-chain header.  A
    verifier that trusts "the root that arrived with the response" is trivially
    satisfied by an attacker who supplies both.  Here the whole PKI is
    attacker-minted and internally consistent -- signature valid, chain valid,
    root self-signed and present in the header -- and it must still be
    rejected, because the only anchor is the pinned certificate.
    """
    rogue = Pki()
    body = make_signed_body(rogue.tcb_signing_key, "tcbInfo",
                           _AWKWARD_TCB_INFO)
    # Self-consistency check: the rogue bundle validates against its own root.
    assert verify_signed_json(body, "tcbInfo", rogue.tcb_chain_pem,
                              root_ca=rogue.root, now=NOW)

    with pytest.raises(ChainVerificationError,
                       match="terminates at a self-signed certificate"):
        verify_signed_json(body, "tcbInfo", rogue.tcb_chain_pem,
                           root_ca=pki.root, now=NOW)


def test_ca_false_certificate_used_as_issuer_is_rejected(pki):
    """An end-entity certificate must not be usable as an issuer.

    Without basicConstraints enforcement, anyone holding *any* Intel-issued
    leaf could mint a signing certificate and the walk would succeed.
    """
    ee_cert, ee_key = _mint("End Entity Not A CA",
                            issuer_name=pki.root.subject,
                            issuer_key=pki.root_key, ca=False,
                            key_usage=_signing_key_usage())
    leaf, leaf_key = _mint("Forged TCB Signing", issuer_name=ee_cert.subject,
                           issuer_key=ee_key, ca=False,
                           key_usage=_signing_key_usage())
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="CA:FALSE"):
        verify_signed_json(body, "tcbInfo", _pem(leaf, ee_cert, pki.root),
                           root_ca=pki.root, now=NOW)


def test_issuer_without_basic_constraints_is_rejected(pki):
    ee_cert, ee_key = _mint("No BasicConstraints",
                            issuer_name=pki.root.subject,
                            issuer_key=pki.root_key,
                            omit_basic_constraints=True)
    leaf, leaf_key = _mint("Forged TCB Signing", issuer_name=ee_cert.subject,
                           issuer_key=ee_key, ca=False,
                           key_usage=_signing_key_usage())
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="no basicConstraints"):
        verify_signed_json(body, "tcbInfo", _pem(leaf, ee_cert, pki.root),
                           root_ca=pki.root, now=NOW)


def test_issuer_without_key_cert_sign_is_rejected(pki):
    sub_ca, sub_ca_key = _mint(
        "CA Without keyCertSign", issuer_name=pki.root.subject,
        issuer_key=pki.root_key, ca=True, path_length=0,
        key_usage=x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False))
    leaf, leaf_key = _mint("Forged TCB Signing", issuer_name=sub_ca.subject,
                           issuer_key=sub_ca_key, ca=False,
                           key_usage=_signing_key_usage())
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="without keyCertSign"):
        verify_signed_json(body, "tcbInfo", _pem(leaf, sub_ca, pki.root),
                           root_ca=pki.root, now=NOW)


def test_path_length_constraint_is_enforced(pki):
    """root has pathlen:1, so two stacked CAs under it must be refused."""
    inter_a, inter_a_key = _mint("Intermediate A", issuer_name=pki.root.subject,
                                 issuer_key=pki.root_key, ca=True,
                                 path_length=1, key_usage=_ca_key_usage())
    inter_b, inter_b_key = _mint("Intermediate B",
                                 issuer_name=inter_a.subject,
                                 issuer_key=inter_a_key, ca=True,
                                 path_length=0, key_usage=_ca_key_usage())
    leaf, leaf_key = _mint("Deep TCB Signing", issuer_name=inter_b.subject,
                           issuer_key=inter_b_key, ca=False,
                           key_usage=_signing_key_usage())
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="pathLenConstraint"):
        verify_signed_json(body, "tcbInfo",
                           _pem(leaf, inter_b, inter_a, pki.root),
                           root_ca=pki.root, now=NOW)


def test_signing_leaf_asserting_ca_true_is_rejected(pki):
    leaf, leaf_key = _mint("CA:TRUE Signing", issuer_name=pki.root.subject,
                           issuer_key=pki.root_key, ca=True, path_length=0,
                           key_usage=_ca_key_usage())
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="CA:TRUE"):
        verify_signed_json(body, "tcbInfo", _pem(leaf, pki.root),
                           root_ca=pki.root, now=NOW)


def test_signing_leaf_without_digital_signature_is_rejected(pki):
    leaf, leaf_key = _mint(
        "Signing Without digitalSignature", issuer_name=pki.root.subject,
        issuer_key=pki.root_key, ca=False,
        key_usage=_signing_key_usage(digital_signature=False))
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="without digitalSignature"):
        verify_signed_json(body, "tcbInfo", _pem(leaf, pki.root),
                           root_ca=pki.root, now=NOW)


def test_expired_signing_certificate_is_rejected(pki):
    leaf, leaf_key = _mint(
        "Expired TCB Signing", issuer_name=pki.root.subject,
        issuer_key=pki.root_key, ca=False, key_usage=_signing_key_usage(),
        not_before=NOW - datetime.timedelta(days=400),
        not_after=NOW - datetime.timedelta(days=1))
    body = make_signed_body(leaf_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="validity window"):
        verify_signed_json(body, "tcbInfo", _pem(leaf, pki.root),
                           root_ca=pki.root, now=NOW)


def test_chain_with_root_omitted_from_header_still_verifies(pki, tcb_info_body):
    """The header's root copy is redundant; the pinned anchor is what counts."""
    assert verify_signed_json(tcb_info_body, "tcbInfo",
                              _pem(pki.tcb_signing), root_ca=pki.root, now=NOW)


def test_root_ca_alone_cannot_be_the_document_signer(pki):
    body = make_signed_body(pki.root_key, "tcbInfo", _AWKWARD_TCB_INFO)
    with pytest.raises(ChainVerificationError, match="CA:TRUE"):
        verify_signed_json(body, "tcbInfo", _pem(pki.root),
                           root_ca=pki.root, now=NOW)


def test_verify_issuer_chain_returns_the_signer(pki):
    signer = verify_issuer_chain(pki.tcb_chain_pem, root_ca=pki.root, now=NOW)
    assert signer.subject == pki.tcb_signing.subject


def test_empty_chain_header_raises_format_error():
    with pytest.raises(CollateralFormatError, match="empty"):
        decode_issuer_chain("")


def test_non_pem_chain_header_raises_format_error():
    with pytest.raises(CollateralFormatError, match="does not decode to PEM"):
        decode_issuer_chain("%7B%22not%22%3A%22pem%22%7D")


def test_decode_issuer_chain_round_trips_intel_style_encoding(pki):
    assert decode_issuer_chain(_url_encoded(pki.tcb_chain_pem)) == \
        pki.tcb_chain_pem


# ===========================================================================
# PCK CRL
# ===========================================================================


def test_valid_pck_crl_is_accepted(pki, crl_der):
    crl = verify_pck_crl(crl_der, pki.pck_crl_chain_pem, root_ca=pki.root,
                         now=NOW)
    assert crl.issuer == pki.pck_ca.subject
    assert [rev.serial_number for rev in crl] == [1234]


def test_tampered_pck_crl_is_rejected(pki, crl_der):
    tampered = bytearray(crl_der)
    tampered[-1] ^= 0xFF
    with pytest.raises((SignatureVerificationError, CollateralFormatError)):
        verify_pck_crl(bytes(tampered), pki.pck_crl_chain_pem,
                       root_ca=pki.root, now=NOW)


def test_pck_crl_signed_by_a_foreign_ca_is_rejected(pki):
    rogue = Pki()
    rogue_crl = make_crl(rogue)
    with pytest.raises(ChainVerificationError):
        verify_pck_crl(rogue_crl, rogue.pck_crl_chain_pem, root_ca=pki.root,
                       now=NOW)


def test_pck_crl_issuer_without_crl_sign_is_rejected(pki):
    no_crl_sign, no_crl_sign_key = _mint(
        "PCK CA Without cRLSign", issuer_name=pki.root.subject,
        issuer_key=pki.root_key, ca=True, path_length=0,
        key_usage=_ca_key_usage(crl_sign=False))
    crl = make_crl(pki, issuer_cert=no_crl_sign, issuer_key=no_crl_sign_key)
    with pytest.raises(ChainVerificationError, match="without cRLSign"):
        verify_pck_crl(crl, _pem(no_crl_sign, pki.root), root_ca=pki.root,
                       now=NOW)


def test_pck_crl_issuer_name_mismatch_is_rejected(pki):
    """A CRL issued by a different name than the chain's signer is refused."""
    other_ca, other_ca_key = _mint("Some Other PCK CA",
                                   issuer_name=pki.root.subject,
                                   issuer_key=pki.root_key, ca=True,
                                   path_length=0, key_usage=_ca_key_usage())
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(other_ca.subject)
        .last_update(_NOT_BEFORE)
        .next_update(_NOT_AFTER)
    )
    # Signed by pki.pck_ca's key but naming other_ca as issuer.
    crl = builder.sign(pki.pck_ca_key, hashes.SHA256())
    with pytest.raises(ChainVerificationError, match="does not match"):
        verify_pck_crl(crl.public_bytes(serialization.Encoding.DER),
                       pki.pck_crl_chain_pem, root_ca=pki.root, now=NOW)


def test_pem_crl_body_is_rejected_as_not_der(pki, crl_der):
    """The builder asks for encoding=der; a PEM body means the wrong request."""
    pem_crl = x509.load_der_x509_crl(crl_der).public_bytes(
        serialization.Encoding.PEM)
    with pytest.raises(CollateralFormatError, match="not a DER X.509 CRL"):
        verify_pck_crl(pem_crl, pki.pck_crl_chain_pem, root_ca=pki.root,
                       now=NOW)


# ===========================================================================
# Root CA CRL: signed directly by the pinned root, no chain
# ===========================================================================
#
# This is the item that closes the client's "PCK revocation: NOT COVERED" gap.
# The platform/processor CRLs above are issued *by* a PCK CA, so they can
# revoke a PCK leaf but never the PCK CA itself; only the root's own CRL can.


def test_valid_root_ca_crl_is_accepted(pki, root_crl_der):
    crl = verify_root_ca_crl(root_crl_der, root_ca=pki.root, now=NOW)
    assert crl.issuer == pki.root.subject
    assert [rev.serial_number for rev in crl] == [1234]


def test_root_ca_crl_takes_no_chain_argument(pki, root_crl_der):
    """The circular-anchor trap is closed by the signature, not by a check.

    ``verify_root_ca_crl`` has no parameter through which an alternative issuer
    could be supplied, so there is nothing to reorder or forget.  A caller that
    tries to pass one gets a ``TypeError`` at the call site.
    """
    with pytest.raises(TypeError):
        verify_root_ca_crl(root_crl_der, pki.pck_crl_chain_pem,  # type: ignore[misc]
                           root_ca=pki.root, now=NOW)


def test_tampered_root_ca_crl_is_rejected(pki, root_crl_der):
    tampered = bytearray(root_crl_der)
    tampered[-1] ^= 0xFF
    with pytest.raises((SignatureVerificationError, CollateralFormatError)):
        verify_root_ca_crl(bytes(tampered), root_ca=pki.root, now=NOW)


def test_root_ca_crl_signed_by_a_rogue_root_is_rejected(pki):
    """A whole self-consistent rogue PKI must not be able to supply this CRL.

    ``Pki`` mints every root with the same distinguished name, so the rogue root
    here is a *name twin* of the pinned one: ``crl.issuer == root_ca.subject``
    passes and only the signature check separates them.  That makes this the
    stronger version of the test -- rejection cannot be coming from a name
    comparison.
    """
    rogue = Pki()
    rogue_crl = make_crl(rogue, issuer_cert=rogue.root,
                         issuer_key=rogue.root_key)
    assert rogue.root.subject == pki.root.subject
    assert rogue.root != pki.root
    # Self-consistency control: it verifies against its own root.
    assert verify_root_ca_crl(rogue_crl, root_ca=rogue.root, now=NOW)
    with pytest.raises(SignatureVerificationError, match="did not verify"):
        verify_root_ca_crl(rogue_crl, root_ca=pki.root, now=NOW)


def test_root_ca_crl_signed_by_a_subordinate_ca_is_rejected(pki):
    """Only the root may issue it -- not a CA the root happens to have issued.

    The PCK CA is legitimately trusted for its *own* CRLs.  Accepting a
    PCK-CA-issued CRL here would let it declare itself unrevoked.
    """
    crl = make_crl(pki)  # issued by pki.pck_ca
    with pytest.raises(ChainVerificationError, match="is not the pinned"):
        verify_root_ca_crl(crl, root_ca=pki.root, now=NOW)


def test_root_ca_crl_with_matching_issuer_name_but_foreign_key_is_rejected(pki):
    """Name collision must not substitute for a signature check.

    ``impostor`` carries the *same subject name* as the pinned root but a
    different key, so ``crl.issuer == root_ca.subject`` passes and only the
    signature check rejects it.  (This is the test that dies if
    ``_verify_crl_signature`` is removed from ``verify_root_ca_crl``.)
    """
    impostor_key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki.root.subject)
        .last_update(_NOT_BEFORE)
        .next_update(_NOT_AFTER)
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(pki.pck_ca.serial_number)
            .revocation_date(_NOT_BEFORE)
            .build())
    )
    forged = builder.sign(impostor_key, hashes.SHA256())
    der = forged.public_bytes(serialization.Encoding.DER)
    assert x509.load_der_x509_crl(der).issuer == pki.root.subject
    with pytest.raises(SignatureVerificationError, match="did not verify"):
        verify_root_ca_crl(der, root_ca=pki.root, now=NOW)


def test_root_ca_crl_rejected_when_the_pinned_root_cannot_sign_crls(pki):
    """An anchor without cRLSign is not permitted to issue this CRL."""
    no_crl_sign, no_crl_sign_key = _mint(
        "Root Without cRLSign", ca=True, path_length=1,
        key_usage=_ca_key_usage(crl_sign=False))
    crl = make_crl(pki, issuer_cert=no_crl_sign, issuer_key=no_crl_sign_key)
    with pytest.raises(ChainVerificationError, match="without cRLSign"):
        verify_root_ca_crl(crl, root_ca=no_crl_sign, now=NOW)


def test_expired_pinned_root_rejects_the_root_ca_crl(pki):
    expired, expired_key = _mint(
        "Expired Root CA", ca=True, path_length=1,
        key_usage=_ca_key_usage(),
        not_before=NOW - datetime.timedelta(days=800),
        not_after=NOW - datetime.timedelta(days=1))
    crl = make_crl(pki, issuer_cert=expired, issuer_key=expired_key)
    with pytest.raises(ChainVerificationError, match="validity window"):
        verify_root_ca_crl(crl, root_ca=expired, now=NOW)


def test_pem_root_ca_crl_body_is_rejected_as_not_der(pki, root_crl_der):
    pem_crl = x509.load_der_x509_crl(root_crl_der).public_bytes(
        serialization.Encoding.PEM)
    with pytest.raises(CollateralFormatError, match="not a DER X.509 CRL"):
        verify_root_ca_crl(pem_crl, root_ca=pki.root, now=NOW)


def test_a_chain_header_on_the_root_ca_crl_is_ignored(pki, tcb_info_body,
                                                      qe_identity_body,
                                                      crl_der):
    """A chain offered for a root-signed item must not be consulted.

    The spec declares ``root_signed``, so the route is fixed before any
    response is seen.  Here the fake serves a *rogue* chain alongside a
    genuine root-signed CRL: if the header were honoured the rogue chain would
    be walked (and rejected), and if it were used to pick the verifier the item
    would take the chained path.  Neither happens -- the item verifies.
    """
    rogue = Pki()
    pcs = FakePcs(pki, tcb_info_body, qe_identity_body, crl_der,
                  make_crl(pki, issuer_cert=pki.root, issuer_key=pki.root_key),
                  root_crl_chain_header=rogue.pck_crl_chain_pem)
    bundle = _bundle(pki, pcs)
    item = bundle["items"]["sgx_root_ca_crl"]
    assert item["issuer_chain_header"] is None
    assert item["issuer_chain_pem"] == _pem(pki.root)
    assert rogue.pck_crl_chain_pem not in item["issuer_chain_pem"]


def test_root_ca_crl_fetch_failure_blocks_the_whole_bundle(pki, tcb_info_body,
                                                           qe_identity_body,
                                                           crl_der):
    """Consistent with every other item: no revocation data, no bundle.

    Justification for making this blocking rather than best-effort: the client
    treats a missing CRL for a non-root-issued certificate as a hard failure
    because an uncovered certificate is indistinguishable from a revoked one.
    Letting this item drop out silently would reintroduce exactly the
    "partial bundle that lacks revocation data" failure mode the bundle exists
    to eliminate -- and unlike the FMSPC case there is no legitimate reason for
    it to be absent, so there is nothing to declare in ``missing``.
    """
    failing = FakePcs(pki, tcb_info_body, qe_identity_body, crl_der,
                      fail_paths=("IntelSGXRootCA.der",))
    with pytest.raises(CollateralFetchError, match="injected failure"):
        _bundle(pki, failing)


def test_root_ca_crl_is_required_even_without_an_fmspc(pki, fake_pcs):
    """It is not FMSPC-dependent, so it is in every bundle the builder writes."""
    assert "sgx_root_ca_crl" in REQUIRED_ITEMS
    assert "sgx_root_ca_crl" not in FMSPC_ITEMS
    bundle = _bundle(pki, fake_pcs, None)
    assert "sgx_root_ca_crl" in bundle["items"]
    assert "sgx_root_ca_crl" not in bundle["missing"]


def test_bundle_root_ca_crl_reverifies_from_the_pinned_root_only(pki,
                                                                 fake_pcs):
    """Rewriting the stored chain cannot change how this item is verified."""
    bundle = _bundle(pki, fake_pcs)
    rogue = Pki()
    bundle["items"]["sgx_root_ca_crl"]["issuer_chain_pem"] = \
        rogue.pck_crl_chain_pem
    # Still verifies: the stored chain is not an input.
    assert "sgx_root_ca_crl" in verify_collateral_bundle(
        bundle, root_ca=pki.root, now=NOW)
    # And swapping the body for a rogue-root-signed CRL is rejected.  The rogue
    # root is a name twin of the pinned one (see Pki), so this is caught by the
    # signature, not by an issuer-name comparison.
    bundle["items"]["sgx_root_ca_crl"]["body"] = base64.b64encode(
        make_crl(rogue, issuer_cert=rogue.root,
                 issuer_key=rogue.root_key)).decode("ascii")
    with pytest.raises(SignatureVerificationError):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


# ===========================================================================
# Signature algorithm assumptions fail closed
# ===========================================================================


def test_non_p256_signing_key_is_rejected_not_skipped(pki):
    """P-256/SHA-256 is inferred, not documented -- so anything else must fail.

    A 64-byte raw r||s signature is only unambiguous on a 256-bit curve.  On
    P-384 the split would produce garbage, so the verifier must refuse rather
    than take an "algorithm I do not recognise -> skip" branch.
    """
    key = ec.generate_private_key(ec.SECP384R1())
    subject = _name("P-384 TCB Signing")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(pki.root.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(_signing_key_usage(), critical=True)
        .sign(pki.root_key, hashes.SHA256())
    )
    der = key.sign(_AWKWARD_TCB_INFO.encode("utf-8"), ec.ECDSA(hashes.SHA384()))
    r, s = asym_utils.decode_dss_signature(der)
    body = (
        '{"tcbInfo":' + _AWKWARD_TCB_INFO + ',"signature":"'
        + (r.to_bytes(48, "big") + s.to_bytes(48, "big")).hex() + '"}'
    ).encode("utf-8")
    # Caught on signature length before the curve check even runs; both are
    # hard rejects, neither is a skip.
    with pytest.raises(CollateralFormatError, match="expected 64"):
        verify_signed_json(body, "tcbInfo", _pem(cert, pki.root),
                           root_ca=pki.root, now=NOW)


def test_an_rsa_signed_crl_is_rejected(pki):
    """A CRL whose algorithm does not match the issuer key must not pass.

    ``cryptography`` reports this as ``False`` rather than raising (measured
    2026-08-20), so it lands on the ordinary "did not verify" path -- but the
    outcome that matters is that it is rejected, not skipped.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki.root.subject)
        .last_update(_NOT_BEFORE)
        .next_update(_NOT_AFTER)
        .sign(rsa_key, hashes.SHA256())
    )
    with pytest.raises(SignatureVerificationError, match="did not verify"):
        verify_root_ca_crl(crl.public_bytes(serialization.Encoding.DER),
                           root_ca=pki.root, now=NOW)


def test_an_unevaluable_crl_signature_is_rejected_not_skipped(pki):
    """Fault injection on the "cannot evaluate this signature" branch.

    No real input reaches it on the pinned ``cryptography`` version -- mismatched
    algorithms return ``False`` instead of raising (see
    ``test_an_rsa_signed_crl_is_rejected``).  It is reachable only if a future
    version starts raising, which is precisely when a fail-open regression would
    be easiest to introduce, so the branch is pinned here by stubbing the raise.

    Calls the private ``_verify_crl_signature`` on purpose: it is the only entry
    point to the branch, and going through ``verify_root_ca_crl`` would need a
    CRL that cannot currently be constructed.
    """
    from cryptography.exceptions import UnsupportedAlgorithm

    from tee_crafter.core.attestation.tcb_collateral import (
        _verify_crl_signature,
    )

    class ExplodingCrl:
        def is_signature_valid(self, _public_key):
            raise UnsupportedAlgorithm("no backend for this signature")

    with pytest.raises(SignatureVerificationError,
                       match="could not be evaluated"):
        _verify_crl_signature(ExplodingCrl(), pki.root, "root CA CRL")


def test_p384_signer_with_a_64_byte_signature_is_rejected_on_the_curve(pki):
    """The curve check is what catches a length-coincidence, so exercise it."""
    key = ec.generate_private_key(ec.SECP384R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("P-384 TCB Signing"))
        .issuer_name(pki.root.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(_signing_key_usage(), critical=True)
        .sign(pki.root_key, hashes.SHA256())
    )
    body = ('{"tcbInfo":' + _AWKWARD_TCB_INFO + ',"signature":"'
            + "ab" * 64 + '"}').encode("utf-8")
    with pytest.raises(ChainVerificationError, match="only understands"):
        verify_signed_json(body, "tcbInfo", _pem(cert, pki.root),
                           root_ca=pki.root, now=NOW)


# ===========================================================================
# Bundle assembly
# ===========================================================================


def test_complete_bundle_has_the_documented_schema(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs)
    assert bundle["schema_version"] == SCHEMA_VERSION
    assert bundle["fetched_at"] == "2026-08-20T12:00:00Z"
    assert bundle["source"] == "https://pcs.test"
    assert bundle["certificates_source"] == "https://certs.test"
    assert bundle["fmspc"] == FMSPC
    assert bundle["complete"] is True
    assert bundle["missing"] == []
    assert bundle["root_ca_sha256"] == pki.root.fingerprint(
        hashes.SHA256()).hex()
    assert set(bundle["items"]) == set(ALL_ITEM_NAMES)

    tdx_tcb = bundle["items"]["tdx_tcb_info"]
    assert tdx_tcb["kind"] == "tcb_info"
    assert tdx_tcb["signed_value_key"] == "tcbInfo"
    assert tdx_tcb["body_encoding"] == "utf-8"
    assert tdx_tcb["issuer_chain_header"] == "TCB-Info-Issuer-Chain"
    assert tdx_tcb["fmspc"] == FMSPC
    assert tdx_tcb["endpoint"] == f"/tdx/certification/v4/tcb?fmspc={FMSPC}"
    assert tdx_tcb["url"] == f"https://pcs.test/tdx/certification/v4/tcb?fmspc={FMSPC}"

    qe = bundle["items"]["tdx_qe_identity"]
    assert qe["kind"] == "enclave_identity"
    assert qe["signed_value_key"] == "enclaveIdentity"
    assert qe["issuer_chain_header"] == "SGX-Enclave-Identity-Issuer-Chain"
    assert "fmspc" not in qe
    assert qe["endpoint"] == "/tdx/certification/v4/qe/identity"

    crl = bundle["items"]["sgx_pck_crl_platform"]
    assert crl["kind"] == "pck_crl"
    assert crl["signed_value_key"] is None
    assert crl["body_encoding"] == "base64"
    assert crl["ca"] == "platform"
    assert crl["issuer_chain_header"] == "SGX-PCK-CRL-Issuer-Chain"
    assert "encoding=der" in crl["url"]

    # The root CA CRL keeps the existing item contract exactly -- same kind,
    # same body_encoding, null signed_value_key -- so the client needs no new
    # kind handling.  What differs is the host and the absent chain header.
    root_crl = bundle["items"]["sgx_root_ca_crl"]
    assert root_crl["kind"] == "pck_crl"
    assert root_crl["signed_value_key"] is None
    assert root_crl["body_encoding"] == "base64"
    assert root_crl["issuer_chain_header"] is None
    assert root_crl["endpoint"] == "/IntelSGXRootCA.der"
    assert root_crl["url"] == "https://certs.test/IntelSGXRootCA.der"
    assert "ca" not in root_crl
    assert "fmspc" not in root_crl
    # Its chain field is the pinned root itself, generated locally, so the
    # client's uniform "every CRL item has a chain" reader works unchanged.
    assert root_crl["issuer_chain_pem"] == _pem(pki.root)


def test_bundle_stores_response_bodies_verbatim(pki, fake_pcs, tcb_info_body,
                                                crl_der):
    bundle = _bundle(pki, fake_pcs)
    # Byte-for-byte identical to what the fake PCS returned -- not a
    # re-serialization of a parsed dict.
    stored = bundle["items"]["tdx_tcb_info"]["body"].encode("utf-8")
    assert stored == tcb_info_body
    assert base64.b64decode(
        bundle["items"]["sgx_pck_crl_platform"]["body"]) == crl_der
    assert bundle["items"]["tdx_tcb_info"]["issuer_chain_pem"] == \
        pki.tcb_chain_pem


def test_bundle_without_fmspc_declares_the_missing_tcb_info(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs, None)
    assert bundle["complete"] is False
    assert sorted(bundle["missing"]) == sorted(FMSPC_ITEMS)
    assert bundle["fmspc"] is None
    assert set(bundle["items"]) == set(REQUIRED_ITEMS)
    assert not any("/tcb?" in url for url in fake_pcs.calls)


def test_malformed_fmspc_raises_collateral_error(pki, fake_pcs):
    with pytest.raises(CollateralError, match="12 hex characters"):
        _bundle(pki, fake_pcs, "nothex")
    assert fake_pcs.calls == []


def test_fmspc_is_normalised_to_upper_case(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs, "00806f050000")
    assert bundle["fmspc"] == FMSPC


def test_fetch_failure_aborts_the_whole_bundle(pki, tcb_info_body,
                                               qe_identity_body, crl_der):
    failing = FakePcs(pki, tcb_info_body, qe_identity_body, crl_der,
                      fail_paths=("/pckcrl",))
    with pytest.raises(CollateralFetchError, match="injected failure"):
        _bundle(pki, failing)


def test_non_200_status_aborts_the_whole_bundle(pki, tcb_info_body,
                                                qe_identity_body, crl_der):
    failing = FakePcs(pki, tcb_info_body, qe_identity_body, crl_der,
                      status_overrides={"/qe/identity": 503})
    with pytest.raises(CollateralFetchError, match="HTTP 503"):
        _bundle(pki, failing)


def test_missing_issuer_chain_header_aborts_the_whole_bundle(
        pki, tcb_info_body, qe_identity_body, crl_der):
    failing = FakePcs(pki, tcb_info_body, qe_identity_body, crl_der,
                      drop_chain_paths=("/tcb?",))
    with pytest.raises(CollateralFormatError, match="issuer-chain headers"):
        _bundle(pki, failing)


def test_verification_failure_aborts_the_whole_bundle(pki, tcb_info_body,
                                                      qe_identity_body,
                                                      crl_der):
    # Same length, so the failure is unambiguously a content change rather
    # than a framing/length artefact.
    tampered = tcb_info_body.replace(b'"UpToDate"', b'"Revoked!"')
    assert len(tampered) == len(tcb_info_body)
    assert tampered != tcb_info_body
    failing = FakePcs(pki, tampered, qe_identity_body, crl_der)
    with pytest.raises(SignatureVerificationError):
        _bundle(pki, failing)


def test_issuer_chain_header_lookup_is_case_insensitive(pki, tcb_info_body):
    response = HttpResponse(status=200,
                            headers={"tcb-info-issuer-chain": "x"},
                            body=tcb_info_body)
    assert response.header("TCB-Info-Issuer-Chain") == "x"
    assert response.header("SGX-Enclave-Identity-Issuer-Chain") is None


# ===========================================================================
# Offline re-verification (the client's read path)
# ===========================================================================


def test_round_trip_bundle_reverifies_offline(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs)
    # Through a real JSON file's worth of serialization, as the client sees it.
    reloaded = json.loads(json.dumps(bundle))
    verified = verify_collateral_bundle(reloaded, root_ca=pki.root, now=NOW)
    assert sorted(verified) == sorted(REQUIRED_ITEMS + FMSPC_ITEMS)


def test_incomplete_bundle_is_rejected_when_completeness_required(pki,
                                                                  fake_pcs):
    bundle = _bundle(pki, fake_pcs, None)
    with pytest.raises(CollateralFormatError, match="declares itself incomplete"):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)
    # ...but it is usable for the checks it does cover, when asked explicitly.
    assert sorted(verify_collateral_bundle(
        bundle, root_ca=pki.root, now=NOW,
        require_complete=False)) == sorted(REQUIRED_ITEMS)


def test_bundle_lying_about_completeness_is_rejected(pki, fake_pcs):
    """A stripped bundle must not read as complete."""
    bundle = _bundle(pki, fake_pcs)
    del bundle["items"]["tdx_tcb_info"]
    with pytest.raises(CollateralFormatError,
                       match="claims to be complete but omits"):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


def test_bundle_missing_a_required_item_is_rejected(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs)
    del bundle["items"]["tdx_qe_identity"]
    with pytest.raises(CollateralFormatError,
                       match="missing always-required item"):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


def test_bundle_self_inconsistent_missing_list_is_rejected(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs)
    bundle["missing"] = ["tdx_tcb_info"]
    with pytest.raises(CollateralFormatError,
                       match="lists 'tdx_tcb_info' as missing"):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


def test_bundle_with_tampered_body_fails_reverification(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs)
    item = bundle["items"]["sgx_tcb_info"]
    item["body"] = item["body"].replace('"UpToDate"', '"OutOfDate"')
    with pytest.raises(SignatureVerificationError):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


def test_bundle_with_swapped_issuer_chain_fails_reverification(pki, fake_pcs):
    """Substituting an attacker chain does not help: the anchor is pinned."""
    bundle = _bundle(pki, fake_pcs)
    rogue = Pki()
    item = bundle["items"]["sgx_tcb_info"]
    item["body"] = make_signed_body(rogue.tcb_signing_key, "tcbInfo",
                                    _AWKWARD_TCB_INFO).decode("utf-8")
    item["issuer_chain_pem"] = rogue.tcb_chain_pem
    with pytest.raises(ChainVerificationError):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


def test_bundle_with_wrong_schema_version_is_rejected(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs)
    bundle["schema_version"] = SCHEMA_VERSION + 1
    with pytest.raises(CollateralFormatError, match="schema_version"):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


def test_bundle_without_fetched_at_is_rejected(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs)
    del bundle["fetched_at"]
    with pytest.raises(CollateralFormatError, match="no 'fetched_at'"):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


def test_bundle_with_unknown_item_is_rejected(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs)
    bundle["items"]["surprise"] = dict(bundle["items"]["sgx_tcb_info"])
    with pytest.raises(CollateralFormatError, match="unknown item"):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


def test_bundle_with_bad_base64_crl_is_rejected(pki, fake_pcs):
    bundle = _bundle(pki, fake_pcs)
    bundle["items"]["sgx_pck_crl_processor"]["body"] = "!!!not base64!!!"
    with pytest.raises(CollateralFormatError, match="not valid base64"):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


# ===========================================================================
# stage_tcb_collateral: build wiring
# ===========================================================================


def test_stage_writes_bundle_and_qe_identity_compat_file(tmp_path, pki,
                                                         fake_pcs,
                                                         qe_identity_body,
                                                         monkeypatch):
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    ok, detail = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                      base_url="https://pcs.test",
                                      certificates_base_url="https://certs.test",
                                      http_get=fake_pcs)
    assert ok is True, detail
    assert "complete=yes" in detail
    assert f"fmspc={FMSPC}" in detail

    bundle = json.loads((tmp_path / "tcb_collateral.json").read_text())
    assert bundle["complete"] is True
    assert verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)

    # The already-shipped TDX clients read this filename; the bytes must be the
    # verbatim, now-signature-checked QEIdentity response.
    assert (tmp_path / "qe_identity.json").read_bytes() == qe_identity_body


def test_stage_writes_nothing_when_an_item_fails(tmp_path, pki, tcb_info_body,
                                                 qe_identity_body, crl_der,
                                                 monkeypatch):
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    failing = FakePcs(pki, tcb_info_body, qe_identity_body, crl_der,
                      fail_paths=("/pckcrl",))
    ok, detail = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                      base_url="https://pcs.test",
                                      certificates_base_url="https://certs.test",
                                      http_get=failing)
    assert ok is False
    assert "CollateralFetchError" in detail
    # No partial bundle, and no stale-looking compat file either.
    assert list(tmp_path.iterdir()) == []


def test_stage_reads_fmspc_from_the_environment(tmp_path, pki, fake_pcs,
                                                monkeypatch):
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.setenv("TEE_CRAFTER_FMSPC", FMSPC)
    ok, _ = stage_tcb_collateral(str(tmp_path), base_url="https://pcs.test",
                                 certificates_base_url="https://certs.test",
                                 http_get=fake_pcs)
    assert ok is True
    bundle = json.loads((tmp_path / "tcb_collateral.json").read_text())
    assert bundle["fmspc"] == FMSPC
    assert bundle["complete"] is True


def test_stage_without_fmspc_writes_an_explicitly_incomplete_bundle(
        tmp_path, pki, fake_pcs, monkeypatch):
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.delenv("TEE_CRAFTER_FMSPC", raising=False)
    ok, detail = stage_tcb_collateral(str(tmp_path), base_url="https://pcs.test",
                                      certificates_base_url="https://certs.test",
                                      http_get=fake_pcs)
    assert ok is True
    assert "complete=no" in detail
    assert "missing=sgx_tcb_info,tdx_tcb_info" in detail
    bundle = json.loads((tmp_path / "tcb_collateral.json").read_text())
    assert bundle["complete"] is False
    with pytest.raises(CollateralFormatError):
        verify_collateral_bundle(bundle, root_ca=pki.root, now=NOW)


def test_stage_honours_the_pcs_base_url_override(tmp_path, pki, fake_pcs,
                                                 monkeypatch):
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.setenv("TEE_CRAFTER_PCS_BASE_URL", "https://mirror.internal/")
    monkeypatch.setenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL",
                       "https://certmirror.internal")
    ok, _ = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                 http_get=fake_pcs)
    assert ok is True
    assert all(url.startswith(("https://mirror.internal/",
                               "https://certmirror.internal/"))
               for url in fake_pcs.calls), fake_pcs.calls
    bundle = json.loads((tmp_path / "tcb_collateral.json").read_text())
    assert bundle["source"] == "https://mirror.internal"
    assert bundle["certificates_source"] == "https://certmirror.internal"


def test_the_two_hosts_have_independent_mirror_overrides(tmp_path, pki,
                                                         fake_pcs,
                                                         monkeypatch):
    """The overrides really are independent: different hosts, both honoured.

    The Root CA CRL lives on a different host from the rest of the collateral,
    so one override cannot cover both.  What is asserted here is that setting
    both sends each item to its own mirror -- not that either may be left out;
    that case is refused, see the tests below.
    """
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.setenv("TEE_CRAFTER_PCS_BASE_URL", "https://mirror.internal")
    monkeypatch.setenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL",
                       "https://certmirror.internal")
    ok, _ = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                 http_get=fake_pcs)
    assert ok is True
    api_calls = [u for u in fake_pcs.calls if "IntelSGXRootCA" not in u]
    cert_calls = [u for u in fake_pcs.calls if "IntelSGXRootCA" in u]
    assert api_calls and all(u.startswith("https://mirror.internal/")
                             for u in api_calls)
    assert cert_calls == ["https://certmirror.internal/IntelSGXRootCA.der"]


# ---------------------------------------------------------------------------
# C18: mirroring one Intel host and not the other
# ---------------------------------------------------------------------------
#
# Collateral is fetched from two hosts with one override each, so there are
# four configurations.  Both-default and both-overridden are legitimate; the
# two mixed ones mean half the collateral silently comes from Intel's public
# infrastructure while the operator believes it is mirrored.  On an air-gapped
# build host that is an egress attempt nobody asked for.


def test_mirroring_only_the_api_host_is_refused(tmp_path, pki, fake_pcs,
                                                monkeypatch):
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.setenv("TEE_CRAFTER_PCS_BASE_URL", "https://mirror.internal")
    monkeypatch.delenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL", raising=False)

    ok, detail = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                      http_get=fake_pcs)

    assert ok is False
    # The message must name the *other* variable, which is the whole point:
    # an operator who has never heard of the second host cannot guess it.
    assert "TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL" in detail
    assert "certificates.trustedservices.intel.com" in detail
    # Refused before any request, so an air-gapped host does not even try.
    assert fake_pcs.calls == []
    assert list(tmp_path.iterdir()) == []


def test_mirroring_only_the_certificates_host_is_refused(tmp_path, pki,
                                                         fake_pcs,
                                                         monkeypatch):
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.delenv("TEE_CRAFTER_PCS_BASE_URL", raising=False)
    monkeypatch.setenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL",
                       "https://certmirror.internal")

    ok, detail = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                      http_get=fake_pcs)

    assert ok is False
    assert "TEE_CRAFTER_PCS_BASE_URL" in detail
    assert "api.trustedservices.intel.com" in detail
    assert fake_pcs.calls == []
    assert list(tmp_path.iterdir()) == []


def test_mixing_an_argument_with_a_default_host_is_refused(tmp_path, pki,
                                                           fake_pcs,
                                                           monkeypatch):
    """The keyword arguments count as overrides too, not just the env vars."""
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.delenv("TEE_CRAFTER_PCS_BASE_URL", raising=False)
    monkeypatch.delenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL", raising=False)

    ok, detail = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                      base_url="https://mirror.internal",
                                      http_get=fake_pcs)

    assert ok is False
    assert "TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL" in detail


def test_an_argument_satisfies_the_other_hosts_env_override(tmp_path, pki,
                                                            fake_pcs,
                                                            monkeypatch):
    """A mirror given by argument and one given by env is not "mixed"."""
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.setenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL",
                       "https://certmirror.internal")

    ok, detail = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                      base_url="https://mirror.internal",
                                      http_get=fake_pcs)

    assert ok is True, detail


def test_all_default_hosts_still_work(tmp_path, pki, fake_pcs, monkeypatch):
    """The ordinary networked build must not be caught by the mixing check."""
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.delenv("TEE_CRAFTER_PCS_BASE_URL", raising=False)
    monkeypatch.delenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL", raising=False)

    ok, detail = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                      http_get=fake_pcs)

    assert ok is True, detail
    assert sorted(fake_pcs.calls) == sorted([
        u for u in fake_pcs.calls
        if u.startswith(("https://api.trustedservices.intel.com/",
                         "https://certificates.trustedservices.intel.com/"))
    ]), fake_pcs.calls
    bundle = json.loads((tmp_path / "tcb_collateral.json").read_text())
    assert bundle["source"] == "https://api.trustedservices.intel.com"
    assert bundle["certificates_source"] == \
        "https://certificates.trustedservices.intel.com"


def test_naming_the_public_host_explicitly_is_the_documented_escape_hatch(
        tmp_path, pki, fake_pcs, monkeypatch):
    """A mirrored API plus a *deliberately* public certificate host is allowed.

    This is why the refusal needs no separate bypass flag: stating the public
    URL in the same place the mirror is configured records the intent where a
    reviewer will see it, and a URL cannot be mistaken for anything else the
    way a stray boolean can.
    """
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.setenv("TEE_CRAFTER_PCS_BASE_URL", "https://mirror.internal")
    monkeypatch.setenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL",
                       "https://certificates.trustedservices.intel.com")

    ok, detail = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                      http_get=fake_pcs)

    assert ok is True, detail
    cert_calls = [u for u in fake_pcs.calls if "IntelSGXRootCA" in u]
    assert cert_calls == [
        "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"]


def test_build_collateral_bundle_refuses_mixed_hosts_too(pki, fake_pcs,
                                                         monkeypatch):
    """The check sits in _resolve_bases, so it covers the lower entry point.

    Putting it in stage_tcb_collateral alone would leave
    build_collateral_bundle -- the function any future caller reaches for --
    silently mixing hosts.
    """
    monkeypatch.delenv("TEE_CRAFTER_PCS_BASE_URL", raising=False)
    monkeypatch.delenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL", raising=False)
    with pytest.raises(CollateralError) as exc:
        build_collateral_bundle(FMSPC, base_url="https://mirror.internal",
                                http_get=fake_pcs, root_ca=pki.root, now=NOW)
    assert "TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL" in str(exc.value)
    assert fake_pcs.calls == []


def test_certificates_base_url_argument_beats_the_environment(tmp_path, pki,
                                                              fake_pcs,
                                                              monkeypatch):
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.setenv("TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL",
                       "https://ignored.internal")
    ok, _ = stage_tcb_collateral(
        str(tmp_path), fmspc=FMSPC, base_url="https://pcs.test",
        certificates_base_url="https://explicit.test", http_get=fake_pcs)
    assert ok is True
    bundle = json.loads((tmp_path / "tcb_collateral.json").read_text())
    assert bundle["certificates_source"] == "https://explicit.test"
    assert bundle["items"]["sgx_root_ca_crl"]["url"] == \
        "https://explicit.test/IntelSGXRootCA.der"


def test_stage_refuses_the_retired_single_endpoint_override(tmp_path, pki,
                                                            fake_pcs,
                                                            monkeypatch):
    """A stale air-gap variable must not silently reach the public Intel PCS."""
    monkeypatch.setattr(
        "tee_crafter.core.attestation.tcb_collateral.load_pinned_intel_root",
        lambda: pki.root)
    monkeypatch.delenv("TEE_CRAFTER_PCS_BASE_URL", raising=False)
    monkeypatch.setenv("TEE_CRAFTER_TDX_QE_IDENTITY_URL",
                       "https://mirror.internal/tdx/certification/v4/qe/identity")
    ok, detail = stage_tcb_collateral(str(tmp_path), fmspc=FMSPC,
                                      http_get=fake_pcs)
    assert ok is False
    assert "TEE_CRAFTER_PCS_BASE_URL" in detail
    assert fake_pcs.calls == []
    assert list(tmp_path.iterdir()) == []



# ---------------------------------------------------------------------------
# Build-side wiring: which platforms actually get a bundle staged
# ---------------------------------------------------------------------------

class TestCollateralIsStagedForEveryIntelPlatform:
    """The staging gate must cover all four Intel-DCAP platforms.

    It originally read ``("tdx-azure", "tdx-gcp")`` -- exactly the pair that
    already had a QE-identity check. So the two platforms that were *missing*
    one, ``sgx-azure`` and ``gpu-cc-gcp``, also got no collateral staged. Making
    the client-side evaluation mandatory without widening this gate would have
    left them failing closed on a bundle that was never going to arrive.

    Asserted against the source rather than by running a deploy: the call sits
    inside a Rich progress block in a function that provisions cloud
    infrastructure.
    """

    INTEL_DCAP_PLATFORMS = ("tdx-azure", "tdx-gcp", "sgx-azure", "gpu-cc-gcp")

    def _gate_source(self) -> str:
        import inspect
        from tee_crafter.cli.commands.deploy import deploy_container
        return inspect.getsource(deploy_container)

    def test_gate_names_every_intel_dcap_platform(self):
        src = self._gate_source()
        i = src.index("stage_tcb_collateral")
        # The platform tuple is the guard immediately above the import.
        window = src[max(0, i - 1200):i]
        for platform in self.INTEL_DCAP_PLATFORMS:
            assert f'"{platform}"' in window, (
                f"{platform} has an Intel DCAP quote but is not in the "
                "collateral staging gate")

    def test_non_intel_platforms_are_not_in_the_gate(self):
        """Staging Intel collateral for an AMD or Nitro platform is nonsense."""
        src = self._gate_source()
        i = src.index("stage_tcb_collateral")
        window = src[max(0, i - 1200):i]
        for platform in ("snp-aws", "snp-gcp", "snp-azure", "nitro-aws",
                         "gpu-cc-aws", "gpu-cc-azure"):
            assert f'"{platform}"' not in window, platform

    def test_the_retired_unverified_fetcher_is_gone(self):
        """One implementation, not two.

        ``fetch_tdx_qe_identity`` downloaded QEIdentity over TLS and never
        checked Intel's signature, so anyone able to answer for
        api.trustedservices.intel.com could dictate the QE identity the client
        then enforced. It must not come back as a second path.
        """
        from tee_crafter.core.builder import platforms
        assert not hasattr(platforms, "fetch_tdx_qe_identity")
        import inspect
        assert "fetch_tdx_qe_identity" not in inspect.getsource(platforms)

    def test_staging_failure_is_recorded_as_a_failed_audit_row(self):
        """A missing bundle must be visible in the provenance, not just stderr.

        Bounded by the end of the staging block rather than a character count —
        a fixed window silently stops covering the thing it was checking as
        soon as anything is inserted above it, which is exactly what happened
        the first time this was written.
        """
        src = self._gate_source()
        start = src.index("ok, detail = stage_tcb_collateral")
        # Phase 3 begins the next block; stop there.
        end = src.index("Phase 3", start)
        block = src[start:end]
        assert '"fail"' in block, "no failed audit row in the staging block"
        assert "fails closed" in block, "operator is not told what failure means"


class TestSharedEvaluatorIsStagedBesideTheClient:
    """The client imports a shared module; the build must actually ship it.

    `tee_crafter_tcb_eval.py` is ~76 KB in `templates/common/` and all four
    Intel clients import it, exiting 1 when it is absent. It is NOT in
    `RUNTIME_MODULES` -- and could not be, because those land in
    `build_dir/app/` for the in-TEE workload, while the verifier client runs on
    the operator's host. Without dedicated staging, every Intel deploy fails
    closed on a file that was never copied.
    """

    def test_the_module_exists_in_the_installation(self):
        import os
        from tee_crafter.core.builder.runtime_modules import (
            CLIENT_SUPPORT_MODULES, common_templates_dir,
        )
        assert "tee_crafter_tcb_eval.py" in CLIENT_SUPPORT_MODULES
        for name in CLIENT_SUPPORT_MODULES:
            assert os.path.isfile(os.path.join(common_templates_dir(), name)), name

    def test_staging_copies_it(self, tmp_path):
        from tee_crafter.core.builder.runtime_modules import (
            CLIENT_SUPPORT_MODULES, copy_client_support_modules,
        )
        copy_client_support_modules(str(tmp_path))
        for name in CLIENT_SUPPORT_MODULES:
            staged = tmp_path / name
            assert staged.is_file(), name
            # Importable, not just present.
            compile(staged.read_text(encoding="utf-8"), name, "exec")

    def test_a_missing_module_is_fatal_not_skipped(self, tmp_path, monkeypatch):
        """A silent skip ships a build that refuses every connection."""
        import pytest as _pytest
        from tee_crafter.core.builder import runtime_modules as rm
        monkeypatch.setattr(rm, "common_templates_dir",
                            lambda: str(tmp_path / "empty"))
        (tmp_path / "empty").mkdir()
        with _pytest.raises(rm.MissingRuntimeModule, match="fail closed"):
            rm.copy_client_support_modules(str(tmp_path))

    def test_deploy_stages_it_for_every_intel_platform(self):
        """Same gate as the collateral bundle, or the two drift apart."""
        import inspect
        from tee_crafter.cli.commands.deploy import deploy_container
        src = inspect.getsource(deploy_container)
        assert "copy_client_support_modules(cvm_build_dir)" in src
        gate = src.index("copy_client_support_modules")
        window = src[max(0, gate - 1500):gate]
        for platform in ("tdx-azure", "tdx-gcp", "sgx-azure", "gpu-cc-gcp"):
            assert f'"{platform}"' in window, platform

    def test_it_is_not_in_the_in_tee_runtime_set(self):
        """Those go to build_dir/app/, which the client never reads."""
        from tee_crafter.core.builder.runtime_modules import RUNTIME_MODULES
        assert "tee_crafter_tcb_eval.py" not in RUNTIME_MODULES


# ---------------------------------------------------------------------------
# The builder/client item-name contract
# ---------------------------------------------------------------------------

class TestBuilderClientContract:
    """The bundle's item names are a two-sided contract; keep both sides honest.

    ``templates/common/tee_crafter_tcb_eval.py`` validates item names against a
    **closed** whitelist (``_ITEM_KINDS``) and raises ``CollateralMalformed`` on
    anything it does not recognise -- rejecting the *whole* bundle, not just the
    unknown item.  So a builder-only addition is not backward compatible: adding
    an item the client has never heard of turns every deploy into a hard failure,
    which is strictly worse than the gap being closed.

    These tests exist so that mismatch is a red test on the build host instead of
    a broken deploy in production.  They read the client module directly rather
    than restating its tables, because a restated copy would drift.
    """

    @staticmethod
    def _client_module():
        import importlib.util
        from tee_crafter.core.builder.runtime_modules import common_templates_dir
        path = os.path.join(common_templates_dir(), "tee_crafter_tcb_eval.py")
        spec = importlib.util.spec_from_file_location(
            "tee_crafter_tcb_eval_contract_probe", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_client_recognises_every_item_the_builder_emits(self):
        client = self._client_module()
        unknown = [name for name in ALL_ITEM_NAMES
                   if name not in client._ITEM_KINDS]
        assert not unknown, (
            f"the client's _ITEM_KINDS whitelist does not contain {unknown}. "
            "Its bundle reader rejects the entire bundle on an unrecognised "
            "item name, so shipping these from the builder breaks every "
            "deploy. Add them to _ITEM_KINDS (all map to kind 'pck_crl' "
            "unless stated otherwise) in "
            "templates/common/tee_crafter_tcb_eval.py.")

    def test_builder_and_client_agree_on_every_kind(self):
        client = self._client_module()
        from tee_crafter.core.attestation import tcb_collateral as builder
        mismatched = {
            spec.name: (spec.kind, client._ITEM_KINDS.get(spec.name))
            for spec in builder._ITEM_SPECS
            if client._ITEM_KINDS.get(spec.name) != spec.kind
        }
        assert not mismatched, (
            f"builder kind != client kind for {mismatched}; the client refuses "
            "an item whose declared kind does not match its table")

    def test_builder_and_client_agree_on_the_signed_value_key_per_kind(self):
        client = self._client_module()
        from tee_crafter.core.attestation import tcb_collateral as builder
        for spec in builder._ITEM_SPECS:
            assert client._KIND_SIGNED_KEY[spec.kind] == spec.signed_value_key, (
                f"{spec.name}: builder emits signed_value_key "
                f"{spec.signed_value_key!r} but the client expects "
                f"{client._KIND_SIGNED_KEY[spec.kind]!r}")

    def test_every_crl_item_the_builder_emits_is_one_the_client_checks(self):
        """A CRL the client never loads cannot revoke anything.

        The client collects CRLs from a fixed ``_CRL_ITEMS`` tuple. An item that
        is whitelisted but not listed there is carried, verified and then
        ignored -- so the PCK CA would still report NOT COVERED.
        """
        client = self._client_module()
        from tee_crafter.core.attestation import tcb_collateral as builder
        emitted = {spec.name for spec in builder._ITEM_SPECS
                   if spec.kind == "pck_crl"}
        missing = sorted(emitted - set(client._CRL_ITEMS))
        assert not missing, (
            f"the client's _CRL_ITEMS does not include {missing}, so those CRLs "
            "are never loaded and the certificates they cover stay unchecked. "
            "Add them to _CRL_ITEMS in "
            "templates/common/tee_crafter_tcb_eval.py.")

    def test_a_real_builder_bundle_is_readable_by_the_client(self, tmp_path,
                                                             pki, fake_pcs,
                                                             monkeypatch):
        """End-to-end: the client's own reader must accept a staged bundle.

        This is the test that would have caught the item-name whitelist without
        anyone having to notice ``_ITEM_KINDS`` by eye.
        """
        client = self._client_module()
        monkeypatch.setattr(
            "tee_crafter.core.attestation.tcb_collateral."
            "load_pinned_intel_root", lambda: pki.root)
        ok, detail = stage_tcb_collateral(
            str(tmp_path), fmspc=FMSPC, base_url="https://pcs.test",
            certificates_base_url="https://certs.test", http_get=fake_pcs)
        assert ok is True, detail
        doc = json.loads((tmp_path / "tcb_collateral.json").read_text())
        bundle = client.CollateralBundle(doc, "staged")
        for name in ALL_ITEM_NAMES:
            assert bundle.has(name), name
        assert {item.name for item in bundle.pck_crls()} == {
            spec.name for spec in
            __import__("tee_crafter.core.attestation.tcb_collateral",
                       fromlist=["_ITEM_SPECS"])._ITEM_SPECS
            if spec.kind == "pck_crl"}
