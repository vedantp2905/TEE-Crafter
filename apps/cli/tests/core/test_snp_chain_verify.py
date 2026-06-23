"""AMD SEV-SNP endorsement-chain verification, per rendered SNP client.

These tests render the real ``snp/{aws,azure,gcp}/client.template.py``
templates, import the result, and drive the chain verifier directly.

All fixtures are built from first principles here — key types, curve,
report layout and signature encoding are written out from the AMD SEV-SNP
ABI (offsets cross-checked against ``docs/snp_flow.md``) rather than
imported from the module under test.  The previous silent-no-op bug
survived because the only coverage shared the code's own assumptions.
"""
from __future__ import annotations

import datetime
import importlib.util
import struct
import sys
import uuid

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.x509.oid import NameOID

from tee_crafter.core.builder import platforms

# --- AMD SEV-SNP attestation report layout, written out independently ---
# (ABI 56860; see docs/snp_flow.md "Attestation report layout".)
REPORT_LEN = 1184           # total report size
SIG_OFFSET = 0x2A0          # 672 — start of ECDSA_SIG; everything before is signed
SIG_FIELD_LEN = 72          # ECDSA_SIG.r and .s are 72-byte fields
P384_SCALAR_LEN = 48        # P-384 r/s occupy the low 48 bytes, little-endian
MEASUREMENT_OFFSET = 0x90   # 48-byte SHA-384 launch digest

RENDERERS = {
    "aws": platforms.render_snp_aws_client_template,
    "azure": platforms.render_snp_azure_client_template,
    "gcp": platforms.render_snp_gcp_client_template,
}


# --------------------------------------------------------------------------
# Fixtures: rendered clients
# --------------------------------------------------------------------------

def _load_rendered_client(cloud: str, tmp_path):
    """Render an SNP client template and import it as a module."""
    source = RENDERERS[cloud](measurement="", measurements=[], container_digest="")
    assert "{amd_root_ca" not in source, "AMD root CA placeholders were not substituted"
    path = tmp_path / f"rendered_snp_{cloud}_client.py"
    path.write_text(source, encoding="utf-8")

    mod_name = f"_snp_client_{cloud}_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(mod_name, None)
    return module


@pytest.fixture(scope="module", params=sorted(RENDERERS))
def client(request, tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("snp_clients")
    return _load_rendered_client(request.param, tmp_path)


# --------------------------------------------------------------------------
# Fixtures: attacker-built certificates and reports
# --------------------------------------------------------------------------

def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _self_signed(key, common_name: str, **sign_kwargs) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = _name(common_name)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, **sign_kwargs)
    )


def _issued_by(issuer_key, issuer_cert, subject_key, common_name: str,
               **sign_kwargs) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(issuer_key, **sign_kwargs)
    )


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _fabricated_report(signing_key) -> bytes:
    """A 1184-byte SNP report whose ECDSA_SIG is made by ``signing_key``.

    Encoded here directly from the ABI: SHA-384 over bytes [0, 0x2A0),
    r and s written little-endian into the low 48 bytes of two adjacent
    72-byte fields.
    """
    body = bytearray(SIG_OFFSET)
    struct.pack_into("<I", body, 0x00, 2)          # version
    struct.pack_into("<I", body, 0x30, 0)          # vmpl = 0
    struct.pack_into("<I", body, 0x34, 1)          # sig_algo = ECDSA P-384 + SHA-384
    struct.pack_into("<Q", body, 0x40, 1 << 5)     # plat_info: ALIAS_CHECK_COMPLETE
    struct.pack_into("<Q", body, 0x180, 0xFF << 48)  # reported_tcb: SNP SVN 0xFF
    body[MEASUREMENT_OFFSET:MEASUREMENT_OFFSET + 48] = bytes(range(48))

    der = signing_key.sign(bytes(body), ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(der)

    report = bytearray(REPORT_LEN)
    report[:SIG_OFFSET] = body
    report[SIG_OFFSET:SIG_OFFSET + P384_SCALAR_LEN] = r.to_bytes(P384_SCALAR_LEN, "little")
    off = SIG_OFFSET + SIG_FIELD_LEN
    report[off:off + P384_SCALAR_LEN] = s.to_bytes(P384_SCALAR_LEN, "little")
    assert len(report) == REPORT_LEN
    return bytes(report)


@pytest.fixture(scope="module")
def rogue_ec():
    """A self-signed EC P-384 "VCEK" plus a matching fabricated report."""
    key = ec.generate_private_key(ec.SECP384R1())
    cert = _self_signed(key, "TOTALLY-NOT-AMD-VCEK", algorithm=hashes.SHA384())
    return {"key": key, "cert": cert, "pem": _pem(cert),
            "report": _fabricated_report(key)}


@pytest.fixture(scope="module")
def rogue_ec_chain():
    """A fully self-consistent EC root + leaf: every signature really verifies."""
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = _self_signed(root_key, "TOTALLY-NOT-AMD-ARK", algorithm=hashes.SHA384())
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    leaf = _issued_by(root_key, root, leaf_key, "TOTALLY-NOT-AMD-VCEK",
                      algorithm=hashes.SHA384())
    return {"root": root, "leaf": leaf}


@pytest.fixture(scope="module")
def rogue_rsa_pss_chain():
    """The same, but RSA + RSASSA-PSS — i.e. AMD's own signature scheme."""
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _self_signed(root_key, "ARK-Milan",
                        algorithm=hashes.SHA384(), rsa_padding=pss)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _issued_by(root_key, root, leaf_key, "SEV-VLEK-Milan",
                      algorithm=hashes.SHA384(), rsa_padding=pss)
    return {"root": root, "leaf": leaf}


def _real_amd_bundle(family: str):
    """[ASK/VLEK, ARK] straight off disk, parsed without the client's helper."""
    from tee_crafter.core.builder.platforms import _load_amd_root_ca
    pem = _load_amd_root_ca(family).encode()
    certs = x509.load_pem_x509_certificates(pem)
    assert len(certs) == 2, f"expected ASK+ARK in amd-ark-{family}.pem"
    return certs


# --------------------------------------------------------------------------
# FIX 1 — signatures are actually verified; rogue endorsement is rejected
# --------------------------------------------------------------------------

class TestRogueEndorsementRejected:
    def test_fabricated_report_verifies_against_the_rogue_cert(self, client, rogue_ec):
        """The attack payload is realistic: the report signature does check out."""
        assert client.verify_snp_report_signature(rogue_ec["report"], rogue_ec["pem"]) is True

    def test_rogue_self_signed_ec_cert_is_rejected(self, client, rogue_ec):
        assert not client.verify_endorsement_cert_chain(rogue_ec["pem"])

    def test_rogue_ec_chain_is_rejected_despite_valid_signatures(self, client, rogue_ec_chain):
        """Every link verifies, but the root is not an AMD ARK (FIX 2)."""
        assert client._try_verify_against_chain(
            rogue_ec_chain["leaf"], [rogue_ec_chain["root"]], "rogue-ec") is False

    def test_rogue_rsa_pss_chain_is_rejected_despite_valid_signatures(
            self, client, rogue_rsa_pss_chain):
        """Same scheme AMD uses, same subject names — still rejected on SPKI."""
        assert client._try_verify_against_chain(
            rogue_rsa_pss_chain["leaf"], [rogue_rsa_pss_chain["root"]], "rogue-rsa") is False

    def test_rogue_root_signature_really_does_verify(self, client, rogue_rsa_pss_chain):
        """Guards against the chain being rejected for the wrong reason."""
        root = rogue_rsa_pss_chain["root"]
        client._verify_cert_sig(root.public_key(), rogue_rsa_pss_chain["leaf"])
        client._verify_cert_sig(root.public_key(), root)


# --------------------------------------------------------------------------
# FIX 1/2 — the genuine AMD chain is accepted
# --------------------------------------------------------------------------

class TestGenuineAmdChainAccepted:
    @pytest.mark.parametrize("family", ["milan", "genoa"])
    def test_real_ask_under_real_ark_is_accepted(self, client, family):
        """ASK signed by ARK + ARK self-signature, both real AMD RSASSA-PSS."""
        ask, ark = _real_amd_bundle(family)
        assert client._try_verify_against_chain(ask, [ark], family.capitalize()) is True

    @pytest.mark.parametrize("family", ["milan", "genoa"])
    def test_real_amd_signatures_verify_through_verify_cert_sig(self, client, family):
        ask, ark = _real_amd_bundle(family)
        client._verify_cert_sig(ark.public_key(), ask)   # ASK <- ARK
        client._verify_cert_sig(ark.public_key(), ark)   # ARK self-signature

    @pytest.mark.parametrize("family", ["milan", "genoa"])
    def test_real_ark_is_in_the_pinned_anchor_set(self, client, family):
        _, ark = _real_amd_bundle(family)
        spki = ark.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        import hashlib
        assert hashlib.sha256(spki).hexdigest() in client._trusted_ark_spki_digests()

    def test_amd_certs_are_rsa_pss_not_pkcs1(self, client):
        """PKCS#1 v1.5 must not be what verifies these — regression guard."""
        _, ark = _real_amd_bundle("milan")
        assert isinstance(ark.public_key(), rsa.RSAPublicKey)
        # Assert the *specific* exception.  A bare `Exception` would also be
        # satisfied by a TypeError from mis-calling verify(), so the test would
        # pass while proving nothing about the padding — which is precisely the
        # bug this guards (AMD signs RSASSA-PSS, and the original code checked
        # nothing at all).
        with pytest.raises(InvalidSignature):
            ark.public_key().verify(
                ark.signature, ark.tbs_certificate_bytes,
                padding.PKCS1v15(), ark.signature_hash_algorithm,
            )


# --------------------------------------------------------------------------
# FIX 1 — unsupported issuer key types fail closed
# --------------------------------------------------------------------------

class TestUnsupportedKeyTypeRaises:
    def test_ed25519_issuer_raises(self, client, rogue_ec):
        ed_pub = ed25519.Ed25519PrivateKey.generate().public_key()
        with pytest.raises(ValueError, match="unsupported issuer key type"):
            client._verify_cert_sig(ed_pub, rogue_ec["cert"])

    def test_non_key_object_raises(self, client, rogue_ec):
        with pytest.raises(ValueError, match="unsupported issuer key type"):
            client._verify_cert_sig(object(), rogue_ec["cert"])

    def test_chain_with_unsupported_root_key_is_rejected(self, client, rogue_ec):
        """The raise must be caught by the chain walk, not propagate as a pass."""
        class _FakeCert:
            not_valid_before_utc = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
            not_valid_after_utc = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
            signature = b"\x00" * 64
            tbs_certificate_bytes = b"tbs"
            signature_hash_algorithm = hashes.SHA512()

            @staticmethod
            def public_key():
                return ed25519.Ed25519PrivateKey.generate().public_key()

        assert client._try_verify_against_chain(
            rogue_ec["cert"], [_FakeCert()], "ed25519-root") is False


# --------------------------------------------------------------------------
# FIX 5 — family-aware AMD-SB-3015 SNP firmware SVN floor
# --------------------------------------------------------------------------

class TestFamilyAwareSvnFloor:
    @pytest.mark.parametrize("family,floor", [("Milan", 0x17), ("Genoa", 0x16)])
    def test_floor_matches_family(self, client, family, floor):
        assert client._min_snp_firmware_svn(family) == floor

    def test_unidentified_family_gets_the_strictest_floor(self, client):
        assert client._min_snp_firmware_svn(None) == 0x17
        assert client._min_snp_firmware_svn("default") == 0x17

    def test_milan_host_at_genoa_floor_is_rejected(self, client):
        report_info = {"reported_tcb": 0x16 << 48}
        assert client.verify_tcb_version(report_info, "Genoa") is True
        assert client.verify_tcb_version(report_info, "Milan") is False
