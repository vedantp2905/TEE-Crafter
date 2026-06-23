"""Coverage for the Medium/Low attestation fixes in the client templates.

Each test class maps to one audit finding:

* ``TestSnpLiveChallenge`` — M-02.  The SNP report embedded in the TLS
  certificate binds the ECDH key, not the TLS key, and is minted once per
  certificate rotation.  The clients now send their nonce to the VM and
  verify the report it signs in reply, which must equal the v2
  attestation-binding digest over ``(nonce, peer TLS SPKI, audit-log
  chain-key commitment)``.  AUD-3 added the third field and made the
  encoding length-prefixed; the wire format is not compatible with the
  previous ``SHA-256(nonce || spki)``, so these fixtures were updated
  rather than added to.  The AUD-3 behaviour itself is covered in
  ``test_chain_commitment_binding.py``.
* ``TestSnpParsedReportFields`` — the report fields that used to be parsed
  and dropped (LAUNCH_TCB, HOST_DATA, ID/AUTHOR key digests, POLICY.SMT).
* ``TestTdxNoSelfPinning`` — M-06.  ``tdx/azure`` and ``tdx/gcp`` no longer
  trust-on-first-use an MRTD they learned from the peer.
* ``TestNitroChainConstraints`` — the Nitro COSE/PCR path now enforces
  basicConstraints, pathLenConstraint and keyUsage on issuing certificates.

Report bytes are assembled from the AMD SEV-SNP ABI layout directly rather
than by calling the parser under test, so a change to the offsets in the
template does not silently change what these tests assert.
"""
from __future__ import annotations

import datetime
import hashlib
import importlib.util
import struct
import sys
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

from tee_crafter.core.builder import platforms

# --- AMD SEV-SNP attestation report layout (ABI 56860), written out here ---
REPORT_LEN = 1184
SIG_OFFSET = 0x2A0
SIG_FIELD_LEN = 72
P384_SCALAR_LEN = 48
OFF_POLICY = 0x08
OFF_VMPL = 0x30
OFF_SIG_ALGO = 0x34
OFF_REPORT_DATA = 0x50
OFF_MEASUREMENT = 0x90
OFF_HOST_DATA = 0xC0
OFF_REPORTED_TCB = 0x180
OFF_LAUNCH_TCB = 0x1F0

SNP_RENDERERS = {
    "aws": platforms.render_snp_aws_client_template,
    "azure": platforms.render_snp_azure_client_template,
    "gcp": platforms.render_snp_gcp_client_template,
}


def _load_module(source: str, tmp_path, stem: str):
    path = tmp_path / f"{stem}.py"
    path.write_text(source, encoding="utf-8")
    mod_name = f"_{stem}_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(mod_name, None)
    return module


@pytest.fixture(scope="module", params=sorted(SNP_RENDERERS))
def snp_client(request, tmp_path_factory):
    source = SNP_RENDERERS[request.param](
        measurement="", measurements=[], container_digest="")
    tmp_path = tmp_path_factory.mktemp("snp_ml_clients")
    return _load_module(source, tmp_path, f"rendered_snp_{request.param}_client")


# ---------------------------------------------------------------------------
# Helpers: a self-consistent "VCEK" plus reports signed by it
# ---------------------------------------------------------------------------

def _endorsement_cert(key) -> bytes:
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-vcek")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA384())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _signed_report(signing_key, *, report_data: bytes = b"",
                   measurement: bytes = b"", reported_tcb: int = 0,
                   launch_tcb: int = 0, host_data: bytes = b"",
                   policy: int = 0) -> bytes:
    """Assemble a 1184-byte report and sign bytes [0, 0x2A0) with ECDSA-P384."""
    body = bytearray(SIG_OFFSET)
    struct.pack_into("<I", body, 0x00, 2)              # version
    struct.pack_into("<I", body, OFF_VMPL, 0)
    struct.pack_into("<I", body, OFF_SIG_ALGO, 1)      # ECDSA P-384 + SHA-384
    struct.pack_into("<Q", body, OFF_POLICY, policy)
    struct.pack_into("<Q", body, OFF_REPORTED_TCB, reported_tcb)
    struct.pack_into("<Q", body, OFF_LAUNCH_TCB, launch_tcb)
    body[OFF_REPORT_DATA:OFF_REPORT_DATA + len(report_data)] = report_data
    body[OFF_MEASUREMENT:OFF_MEASUREMENT + len(measurement)] = measurement
    body[OFF_HOST_DATA:OFF_HOST_DATA + len(host_data)] = host_data

    der = signing_key.sign(bytes(body), ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(der)

    report = bytearray(REPORT_LEN)
    report[:SIG_OFFSET] = body
    report[SIG_OFFSET:SIG_OFFSET + P384_SCALAR_LEN] = r.to_bytes(P384_SCALAR_LEN, "little")
    off = SIG_OFFSET + SIG_FIELD_LEN
    report[off:off + P384_SCALAR_LEN] = s.to_bytes(P384_SCALAR_LEN, "little")
    return bytes(report)


def _peer_cert_der(tls_key) -> bytes:
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vm.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(tls_key, hashes.SHA384())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _spki_der(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --- v2 attestation-binding encoding, written out from the wire spec ---
# The server publishes this shape in its `challenge_binding` field:
#   sha256(lp(label) || uint32be(field_count) || lp(field)...)
# where lp(x) == uint32be(len(x)) || x.  Encoded here with int.to_bytes so
# it does not share an implementation with the template under test.
_V2_LABEL = b"tee-crafter/attest-binding/v2"
CHAIN_COMMITMENT = "3f" * 32


def _lp(field: bytes) -> bytes:
    return len(field).to_bytes(4, "big") + field


def _v2_digest(*fields: bytes) -> bytes:
    body = _lp(_V2_LABEL) + len(fields).to_bytes(4, "big")
    for field in fields:
        body += _lp(field)
    return hashlib.sha256(body).digest()


@pytest.fixture
def challenge_setup():
    """A VM identity: endorsement key, TLS key, nonce and matching report."""
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    tls_key = ec.generate_private_key(ec.SECP384R1())
    nonce_ascii = b"Zm9vYmFyLW5vbmNlLXZhbHVlLTAxMjM0NTY3ODk="
    measurement = bytes(range(48))
    binding = _v2_digest(nonce_ascii, _spki_der(tls_key),
                         CHAIN_COMMITMENT.encode("ascii"))
    return {
        "vcek_key": vcek_key,
        "endorsement_pem": _endorsement_cert(vcek_key),
        "tls_key": tls_key,
        "cert_der": _peer_cert_der(tls_key),
        "nonce_ascii": nonce_ascii,
        "measurement_hex": measurement.hex(),
        "report": _signed_report(vcek_key, report_data=binding,
                                 measurement=measurement),
    }


# ---------------------------------------------------------------------------
# M-02
# ---------------------------------------------------------------------------

class TestSnpLiveChallenge:
    def test_correctly_bound_report_is_accepted(self, snp_client, challenge_setup):
        ok, reason = snp_client.verify_live_challenge(
            {"report_hex": challenge_setup["report"].hex(),
             "chain_key_commitment": CHAIN_COMMITMENT},
            challenge_setup["nonce_ascii"],
            challenge_setup["cert_der"],
            challenge_setup["endorsement_pem"],
            challenge_setup["measurement_hex"],
        )
        assert ok, reason

    def test_replayed_report_from_another_nonce_is_rejected(self, snp_client,
                                                            challenge_setup):
        """Freshness: the same VM, the same TLS key, a different challenge."""
        ok, reason = snp_client.verify_live_challenge(
            {"report_hex": challenge_setup["report"].hex(),
             "chain_key_commitment": CHAIN_COMMITMENT},
            b"a-completely-different-nonce",
            challenge_setup["cert_der"],
            challenge_setup["endorsement_pem"],
            challenge_setup["measurement_hex"],
        )
        assert not ok
        assert "v2 attestation binding digest" in reason

    def test_relayed_report_on_a_foreign_tls_key_is_rejected(self, snp_client,
                                                             challenge_setup):
        """Channel binding: a relay presents its own certificate.

        The relay forwards our nonce to the real VM and returns the VM's
        genuine, AMD-signed report.  It cannot make that report cover the
        relay's own SubjectPublicKeyInfo, so the check must fail.
        """
        mitm_cert_der = _peer_cert_der(ec.generate_private_key(ec.SECP384R1()))
        ok, reason = snp_client.verify_live_challenge(
            {"report_hex": challenge_setup["report"].hex(),
             "chain_key_commitment": CHAIN_COMMITMENT},
            challenge_setup["nonce_ascii"],
            mitm_cert_der,
            challenge_setup["endorsement_pem"],
            challenge_setup["measurement_hex"],
        )
        assert not ok
        assert "v2 attestation binding digest" in reason

    def test_report_signed_by_a_foreign_key_is_rejected(self, snp_client,
                                                        challenge_setup):
        rogue_key = ec.generate_private_key(ec.SECP384R1())
        binding = _v2_digest(
            challenge_setup["nonce_ascii"], _spki_der(challenge_setup["tls_key"]),
            CHAIN_COMMITMENT.encode("ascii"))
        rogue_report = _signed_report(
            rogue_key, report_data=binding,
            measurement=bytes.fromhex(challenge_setup["measurement_hex"]))
        ok, reason = snp_client.verify_live_challenge(
            {"report_hex": rogue_report.hex(),
             "chain_key_commitment": CHAIN_COMMITMENT},
            challenge_setup["nonce_ascii"],
            challenge_setup["cert_der"],
            challenge_setup["endorsement_pem"],
            challenge_setup["measurement_hex"],
        )
        assert not ok
        assert "signature" in reason

    def test_measurement_swap_is_rejected(self, snp_client, challenge_setup):
        """The live report must describe the same workload as the cert report."""
        ok, reason = snp_client.verify_live_challenge(
            {"report_hex": challenge_setup["report"].hex(),
             "chain_key_commitment": CHAIN_COMMITMENT},
            challenge_setup["nonce_ascii"],
            challenge_setup["cert_der"],
            challenge_setup["endorsement_pem"],
            "aa" * 48,
        )
        assert not ok
        assert "measurement" in reason

    @pytest.mark.parametrize("response", [
        {},
        None,
        {"report_hex": "", "chain_key_commitment": CHAIN_COMMITMENT},
        {"report_hex": "not-hex", "chain_key_commitment": CHAIN_COMMITMENT},
    ])
    def test_missing_or_malformed_report_is_rejected(self, snp_client,
                                                     challenge_setup, response):
        ok, _ = snp_client.verify_live_challenge(
            response,
            challenge_setup["nonce_ascii"],
            challenge_setup["cert_der"],
            challenge_setup["endorsement_pem"],
            challenge_setup["measurement_hex"],
        )
        assert not ok

    def test_client_sends_the_nonce_it_generated(self):
        """The nonce must reach the server, not be generated and discarded."""
        for cloud, render in SNP_RENDERERS.items():
            src = render(measurement="", measurements=[], container_digest="")
            assert 'base64.b64encode(ratls_nonce)' in src, cloud
            assert '"nonce": base64.b64encode(os.urandom(32)).decode()' not in src, (
                f"{cloud} still sends a throwaway nonce instead of ratls_nonce")


# ---------------------------------------------------------------------------
# Parsed-but-ignored report fields
# ---------------------------------------------------------------------------

class TestSnpParsedReportFields:
    def _info(self, snp_client, **overrides):
        key = ec.generate_private_key(ec.SECP384R1())
        report = _signed_report(key, **overrides)
        return snp_client.parse_snp_report(report)

    def test_launch_tcb_above_reported_tcb_is_fatal(self, snp_client):
        info = self._info(snp_client, reported_tcb=0x10, launch_tcb=0x20)
        assert snp_client.verify_parsed_report_fields(info) is False

    def test_launch_tcb_at_or_below_reported_tcb_passes(self, snp_client):
        info = self._info(snp_client, reported_tcb=0x20, launch_tcb=0x20)
        assert snp_client.verify_parsed_report_fields(info) is True

    def test_host_data_pin_mismatch_is_fatal(self, snp_client, monkeypatch):
        info = self._info(snp_client, host_data=b"\x01" * 32)
        monkeypatch.setenv("TEE_CRAFTER_SNP_EXPECTED_HOST_DATA", "02" * 32)
        assert snp_client.verify_parsed_report_fields(info) is False

    def test_host_data_pin_match_passes(self, snp_client, monkeypatch):
        info = self._info(snp_client, host_data=b"\x01" * 32)
        monkeypatch.setenv("TEE_CRAFTER_SNP_EXPECTED_HOST_DATA", "01" * 32)
        assert snp_client.verify_parsed_report_fields(info) is True

    def test_smt_warns_by_default_and_refuses_on_request(self, snp_client,
                                                         monkeypatch):
        info = self._info(snp_client, policy=1 << 16)
        monkeypatch.delenv("TEE_CRAFTER_SNP_REQUIRE_SMT_DISABLED", raising=False)
        assert snp_client.verify_parsed_report_fields(info) is True
        monkeypatch.setenv("TEE_CRAFTER_SNP_REQUIRE_SMT_DISABLED", "1")
        assert snp_client.verify_parsed_report_fields(info) is False


# ---------------------------------------------------------------------------
# M-06
# ---------------------------------------------------------------------------

TDX_RENDERERS = {
    "azure": platforms.render_tdx_client_template,
    "gcp": platforms.render_tdx_gcp_client_template,
}


class TestTdxNoSelfPinning:
    @pytest.mark.parametrize("cloud", sorted(TDX_RENDERERS))
    def test_unpinned_mrtd_is_not_learned_from_the_peer(self, cloud):
        src = TDX_RENDERERS[cloud](mrtd="", container_digest="")
        assert "MRTD self-pinned from verified quote" not in src
        assert "Self-pinning MRTD from attested connection" not in src
        assert "EXPECTED_MRTD = quote_info" not in src

    @pytest.mark.parametrize("cloud", sorted(TDX_RENDERERS))
    def test_env_opt_out_matches_the_other_platforms(self, cloud, tmp_path):
        src = TDX_RENDERERS[cloud](mrtd="", container_digest="")
        module = _load_module(src, tmp_path, f"rendered_tdx_{cloud}_client")
        assert module._ALLOW_UNPINNED_ENV == "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT"
        assert module._allow_unpinned_measurement() is False

    @pytest.mark.parametrize("cloud", sorted(TDX_RENDERERS))
    def test_env_opt_out_is_honoured(self, cloud, tmp_path, monkeypatch):
        src = TDX_RENDERERS[cloud](mrtd="", container_digest="")
        module = _load_module(src, tmp_path, f"rendered_tdx_{cloud}_optout")
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT", "1")
        assert module._allow_unpinned_measurement() is True


# ---------------------------------------------------------------------------
# Nitro chain constraints
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def nitro_client(tmp_path_factory):
    from tee_crafter.core.builder import builder
    root_pem = (
        __import__("pathlib").Path(platforms.__file__).parents[2]
        / "certs" / "nitro-root.pem"
    ).read_text(encoding="utf-8")
    src = builder.render_client_template(pcr_hashes={}, root_ca=root_pem)
    tmp_path = tmp_path_factory.mktemp("nitro_client")
    return _load_module(src, tmp_path, "rendered_nitro_client")


def _cert(key, *, ca: bool, path_length=None, key_cert_sign=True,
          with_key_usage=True) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length),
                       critical=True)
    )
    if with_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=key_cert_sign,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(key, hashes.SHA384())


class TestNitroChainConstraints:
    @pytest.fixture(scope="class")
    def key(self):
        return ec.generate_private_key(ec.SECP384R1())

    def test_real_pinned_root_satisfies_the_ca_checks(self, nitro_client):
        """Guard against a check that would reject AWS's own root."""
        root_pem = (
            __import__("pathlib").Path(platforms.__file__).parents[2]
            / "certs" / "nitro-root.pem"
        ).read_bytes()
        root = x509.load_pem_x509_certificate(root_pem)
        nitro_client.check_ca_certificate(root, 1, remaining_intermediates=3)

    def test_end_entity_acting_as_issuer_is_rejected(self, nitro_client, key):
        leaf = _cert(key, ca=False)
        with pytest.raises(ValueError, match="CA:FALSE"):
            nitro_client.check_ca_certificate(leaf, 1, remaining_intermediates=0)

    def test_missing_basic_constraints_on_an_issuer_is_rejected(self, nitro_client, key):
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-bc")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA384())
        )
        with pytest.raises(ValueError, match="no basicConstraints"):
            nitro_client.check_ca_certificate(cert, 1, remaining_intermediates=0)

    def test_path_length_constraint_is_enforced(self, nitro_client, key):
        ca = _cert(key, ca=True, path_length=0)
        nitro_client.check_ca_certificate(ca, 1, remaining_intermediates=0)
        with pytest.raises(ValueError, match="pathLenConstraint"):
            nitro_client.check_ca_certificate(ca, 1, remaining_intermediates=1)

    def test_ca_without_key_cert_sign_is_rejected(self, nitro_client, key):
        ca = _cert(key, ca=True, key_cert_sign=False)
        with pytest.raises(ValueError, match="keyCertSign"):
            nitro_client.check_ca_certificate(ca, 1, remaining_intermediates=0)

    def test_absent_key_usage_is_permitted(self, nitro_client, key):
        """RFC 5280 makes keyUsage optional; absence must not fail closed."""
        ca = _cert(key, ca=True, with_key_usage=False)
        nitro_client.check_ca_certificate(ca, 1, remaining_intermediates=0)

    def test_leaf_claiming_ca_true_is_rejected(self, nitro_client, key):
        with pytest.raises(ValueError, match="CA:TRUE"):
            nitro_client.check_leaf_certificate(_cert(key, ca=True))

    def test_ordinary_leaf_is_accepted(self, nitro_client, key):
        nitro_client.check_leaf_certificate(_cert(key, ca=False))
