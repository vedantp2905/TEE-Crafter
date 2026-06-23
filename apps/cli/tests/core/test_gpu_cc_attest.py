"""GPU-CC client attestation tests.

These exercise the rendered client templates as real modules.  Every
fixture (SNP report bytes, endorsement certificate, RA-TLS certificate) is
built here from ``struct`` and ``cryptography`` primitives so a bug in the
template's own parser or verifier cannot make a fabricated report look
genuine.

The central case: a self-signed EC certificate paired with a fabricated
SEV-SNP report must be rejected by ``gpu-cc-azure``, and the
FULL-CONFIDENTIAL banner must never reach the operator when it is.
"""
import contextlib
import io
import os
import socket
import ssl
import struct
import tempfile
import threading
import types

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tee_crafter.core.builder import platforms


# --- fixture builders (independent of the code under test) -----------------

SNP_QUOTE_OID = "1.3.6.1.4.1.3704.1.1.1"
GPU_ATT_OID = "1.3.6.1.4.1.59386.1.1"
NITROTPM_OID = "1.3.6.1.4.1.59386.2.1"

_REPORT_SIZE = 1184
_PINNED_MEASUREMENT = "ab" * 48


def _fabricate_snp_report(measurement_hex: str = _PINNED_MEASUREMENT) -> bytes:
    """Build a 1184-byte SEV-SNP report that is well-formed but unsigned.

    Field values are chosen so every *policy* check would pass — debug and
    migration clear, VMPL 0, ALIAS_CHECK_COMPLETE set, SNP SVN 0x16.  The
    only thing wrong with it is that AMD never signed it, which is exactly
    the property a verifier has to catch.
    """
    report = bytearray(_REPORT_SIZE)
    struct.pack_into("<I", report, 0x00, 2)            # version
    struct.pack_into("<Q", report, 0x08, 0x0030000)    # policy: no debug/migrate
    struct.pack_into("<I", report, 0x30, 0)            # vmpl
    struct.pack_into("<I", report, 0x34, 1)            # sig_algo = ECDSA P-384
    struct.pack_into("<Q", report, 0x40, 1 << 5)       # PLATFORM_INFO alias check
    report[0x50:0x50 + 64] = b"\x11" * 64              # report_data
    report[0x90:0x90 + 48] = bytes.fromhex(measurement_hex)
    struct.pack_into("<Q", report, 0x180, 0x16 << 48)  # REPORTED_TCB, SNP SVN 0x16
    report[0x1A0:0x1A0 + 64] = b"\x22" * 64            # chip_id
    struct.pack_into("<Q", report, 0x1E0, 0x16 << 48)  # COMMITTED_TCB
    report[0x2A0:0x2A0 + 512] = b"\x33" * 512          # signature (garbage)
    return bytes(report)


def _self_signed_ec_cert(common_name: str = "rogue-vcek"):
    """An EC P-384 self-signed certificate posing as an AMD VCEK."""
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    import datetime as dt

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(key, hashes.SHA384())
    )
    return key, cert


def _snp_extension_blob(report: bytes, endorsement_pem: bytes) -> bytes:
    """report || u32 cert_len || cert PEM || u32 tpm_len (empty)."""
    return (report
            + struct.pack("<I", len(endorsement_pem)) + endorsement_pem
            + struct.pack("<I", 0))


def _ratls_cert(extensions):
    """Build a self-signed RA-TLS cert carrying *extensions* [(oid, bytes)]."""
    import datetime as dt

    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gpu-cc-test.local")])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
    )
    for oid, payload in extensions:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), payload),
            critical=False,
        )
    return key, builder.sign(key, hashes.SHA384())


@contextlib.contextmanager
def _ratls_server(key, cert):
    """Serve *cert* over TLS 1.3 on localhost for exactly one connection."""
    tmpdir = tempfile.mkdtemp(prefix="gpu_cc_test_")
    cert_path = os.path.join(tmpdir, "cert.pem")
    key_path = os.path.join(tmpdir, "key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(20)
    port = srv.getsockname()[1]

    def _serve():
        try:
            raw, _ = srv.accept()
            raw.settimeout(10)
            try:
                ctx.wrap_socket(raw, server_side=True).close()
            except OSError:
                raw.close()
        except OSError:
            pass

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        srv.close()
        thread.join(timeout=5)
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)


def _load_client(source: str) -> types.ModuleType:
    """Exec a rendered client template as a module without running main()."""
    module = types.ModuleType("gpu_cc_client_under_test")
    exec(compile(source, "client_under_test.py", "exec"), module.__dict__)
    return module


@pytest.fixture()
def azure_client():
    return _load_client(platforms.render_gpu_cc_azure_client_template(
        measurement=_PINNED_MEASUREMENT))


@pytest.fixture()
def azure_client_unpinned():
    return _load_client(platforms.render_gpu_cc_azure_client_template())


@pytest.fixture()
def gcp_client_unpinned():
    return _load_client(platforms.render_gpu_cc_gcp_client_template())


@pytest.fixture()
def aws_client():
    return _load_client(platforms.render_gpu_cc_aws_client_template())


@pytest.fixture()
def forged_azure_cert():
    """RA-TLS cert with a fabricated SNP report + self-signed EC endorsement."""
    _, rogue_cert = _self_signed_ec_cert()
    blob = _snp_extension_blob(
        _fabricate_snp_report(),
        rogue_cert.public_bytes(serialization.Encoding.PEM),
    )
    return _ratls_cert([(SNP_QUOTE_OID, blob), (GPU_ATT_OID, b"not-a-real-token")])


# --- FIX 1: gpu-cc-azure must verify the SEV-SNP report --------------------

def test_azure_rejects_self_signed_endorsement_certificate(azure_client, forged_azure_cert):
    _, cert = forged_azure_cert
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        result = azure_client.verify_snp_evidence(cert_der)

    assert result["ok"] is False
    # The forged report fails at the signature step, before the chain walk.
    assert "signature" in result["error"].lower()


def test_azure_rejects_endorsement_not_chaining_to_amd(azure_client, monkeypatch):
    """With the report signature stubbed out, the AMD chain walk still refuses."""
    _, rogue_cert = _self_signed_ec_cert()
    rogue_pem = rogue_cert.public_bytes(serialization.Encoding.PEM)
    monkeypatch.setitem(azure_client.__dict__, "verify_snp_report_signature",
                        lambda report, pem: True)
    _, cert = _ratls_cert([
        (SNP_QUOTE_OID, _snp_extension_blob(_fabricate_snp_report(), rogue_pem)),
    ])

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        result = azure_client.verify_snp_evidence(
            cert.public_bytes(serialization.Encoding.DER))

    assert result["ok"] is False
    assert "chain" in result["error"].lower()


def test_azure_rejects_report_with_no_endorsement_certificate(azure_client):
    """A bare report with no endorsement chain is unverifiable, so refused."""
    _, cert = _ratls_cert([
        (SNP_QUOTE_OID, _fabricate_snp_report() + struct.pack("<I", 0)),
    ])

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        result = azure_client.verify_snp_evidence(
            cert.public_bytes(serialization.Encoding.DER))

    assert result["ok"] is False
    assert "endorsement" in result["error"].lower()


def test_azure_does_not_print_full_confidential_when_snp_fails(
    azure_client, forged_azure_cert,
):
    """End-to-end: the operator must not see a dual-attestation claim."""
    key, cert = forged_azure_cert
    stderr = io.StringIO()
    with _ratls_server(key, cert) as port:
        with contextlib.redirect_stderr(stderr):
            with pytest.raises(SystemExit) as exc:
                azure_client.verify_ratls_connection("127.0.0.1", port)

    assert exc.value.code == 1
    output = stderr.getvalue()
    assert "FULL-CONFIDENTIAL" not in output
    assert "Dual attestation" not in output
    assert "SEV-SNP attestation failed" in output
    # SNP verification gates everything after it: we never even reach the
    # GPU token, so a forged CPU report cannot ride in on a valid GPU one.
    assert "Verifying GPU NRAS attestation token" not in output


def test_azure_amd_pss_chain_verifies_against_shipped_certs(azure_client):
    """The PSS parameters must actually validate AMD's real ARK/ASK pair.

    AMD signs with RSASSA-PSS (MGF1-SHA384, 48-byte salt), not PKCS#1 v1.5;
    getting this wrong would make every genuine chain fail closed.
    """
    chain = azure_client._parse_pem_chain(azure_client._AMD_ROOT_CA_PEM.strip().encode())
    assert len(chain) == 2, "expected ASK/SEV + ARK in the baked AMD bundle"
    ask, ark = chain
    azure_client._verify_cert_signature(ark.public_key(), ask)
    azure_client._verify_cert_signature(ark.public_key(), ark)


def test_azure_unknown_issuer_key_type_raises(azure_client):
    """Fail closed rather than silently skipping an unrecognised key type."""
    chain = azure_client._parse_pem_chain(azure_client._AMD_ROOT_CA_PEM.strip().encode())

    class NotAKey:
        pass

    with pytest.raises(TypeError):
        azure_client._verify_cert_signature(NotAKey(), chain[0])


def test_azure_reads_the_injected_amd_root_ca(azure_client):
    """FIX 5: {amd_root_ca} is injected *and* actually consulted."""
    assert "BEGIN CERTIFICATE" in azure_client._AMD_ROOT_CA_PEM

    calls = []
    original = azure_client._parse_pem_chain

    def _spy(pem):
        calls.append(pem)
        return original(pem)

    azure_client.__dict__["_parse_pem_chain"] = _spy
    try:
        _, rogue_cert = _self_signed_ec_cert()
        with contextlib.redirect_stderr(io.StringIO()):
            azure_client.verify_endorsement_cert_chain(
                rogue_cert.public_bytes(serialization.Encoding.PEM))
    finally:
        azure_client.__dict__["_parse_pem_chain"] = original

    assert any(azure_client._AMD_ROOT_CA_PEM.strip().encode() == c for c in calls)


# --- FIX 4: an unpinned measurement is a hard failure ----------------------

def _stub_snp_crypto(module):
    """Let the measurement check be reached without AMD's signing key."""
    module.__dict__["verify_snp_report_signature"] = lambda report, pem: True
    module.__dict__["verify_endorsement_cert_chain"] = lambda pem: True


def test_azure_unpinned_measurement_fails_without_optout(
    azure_client_unpinned, monkeypatch,
):
    monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT", raising=False)
    _stub_snp_crypto(azure_client_unpinned)
    _, rogue_cert = _self_signed_ec_cert()
    _, cert = _ratls_cert([(SNP_QUOTE_OID, _snp_extension_blob(
        _fabricate_snp_report(), rogue_cert.public_bytes(serialization.Encoding.PEM)))])

    with contextlib.redirect_stderr(io.StringIO()):
        result = azure_client_unpinned.verify_snp_evidence(
            cert.public_bytes(serialization.Encoding.DER))

    assert result["ok"] is False
    assert "no launch measurement pinned" in result["error"]


def test_azure_unpinned_measurement_allowed_with_explicit_optout(
    azure_client_unpinned, monkeypatch,
):
    monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT", "1")
    _stub_snp_crypto(azure_client_unpinned)
    _, rogue_cert = _self_signed_ec_cert()
    _, cert = _ratls_cert([(SNP_QUOTE_OID, _snp_extension_blob(
        _fabricate_snp_report(), rogue_cert.public_bytes(serialization.Encoding.PEM)))])

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        result = azure_client_unpinned.verify_snp_evidence(
            cert.public_bytes(serialization.Encoding.DER))

    assert result["ok"] is True
    assert "WARNING" in stderr.getvalue()


def test_azure_client_has_no_trust_on_first_use_comment():
    source = platforms.render_gpu_cc_azure_client_template()
    assert "All subsequent connections will enforce this value" not in source


def test_gcp_client_has_no_trust_on_first_use_comment():
    source = platforms.render_gpu_cc_gcp_client_template()
    assert "All subsequent connections will enforce this value" not in source


def test_aws_client_has_no_trust_on_first_use_comment():
    source = platforms.render_gpu_cc_aws_client_template()
    assert "All subsequent connections will enforce this value" not in source


# --- FIX 3: gcp vTPM PCRs are mandatory, and unsigned ---------------------

def test_gcp_vtpm_pcrs_fail_closed_when_unpinned(gcp_client_unpinned, monkeypatch):
    monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT", raising=False)
    monkeypatch.delenv("TEE_CRAFTER_EXPECTED_VTPM_PCRS", raising=False)

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        assert gcp_client_unpinned.verify_vtpm_pcrs({"0": "aa" * 32}) is False
    assert "no expected PCR set is pinned" in stderr.getvalue()


def test_gcp_vtpm_pcrs_warn_loudly_under_optout(gcp_client_unpinned, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT", "1")
    monkeypatch.delenv("TEE_CRAFTER_EXPECTED_VTPM_PCRS", raising=False)

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        assert gcp_client_unpinned.verify_vtpm_pcrs({"0": "aa" * 32}) is True
    output = stderr.getvalue()
    assert "NOT being checked" in output
    assert "PASSED" not in output


def test_gcp_vtpm_pcrs_enforced_when_pinned(gcp_client_unpinned, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_EXPECTED_VTPM_PCRS", "0:" + "aa" * 32)

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        assert gcp_client_unpinned.verify_vtpm_pcrs({"0": "aa" * 32}) is True
        assert gcp_client_unpinned.verify_vtpm_pcrs({"0": "bb" * 32}) is False
    assert "mismatch" in stderr.getvalue()


# --- FIX 2: gpu-cc-aws CPU attestation fails closed ----------------------

def test_aws_cpu_attestation_fails_closed_without_a_document(aws_client, monkeypatch):
    """A certificate carrying only the self-reported PCR blob is refused.

    This assertion changed shape on 2026-08-24 but not intent. It used to
    require the message "UNVERIFIABLE", because the client refused *all*
    CPU-side attestation on the belief that no AWS NitroTPM root was pinned. It
    is: a NitroTPM document chains to CN=aws.nitro-enclaves, which is
    certs/nitro-root.pem. So the client now verifies a document when one is
    present -- and must still fail closed when one is absent, which is what this
    checks. The unsigned NITROTPM_OID blob is not a substitute.
    """
    monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNVERIFIED_AWS_CPU_ATTESTATION", raising=False)
    key, cert = _ratls_cert([(NITROTPM_OID, b'{"pcrs": {"0": "aa"}}')])

    stderr = io.StringIO()
    with _ratls_server(key, cert) as port:
        with contextlib.redirect_stderr(stderr):
            with pytest.raises(SystemExit) as exc:
                aws_client.verify_ratls_connection("127.0.0.1", port)

    assert exc.value.code == 1
    output = stderr.getvalue()
    assert "no NitroTPM attestation document" in output
    # Never claim a check that did not run.
    assert "NitroTPM attestation document: VERIFIED" not in output
    assert "NitroTPM measurement: PASSED" not in output


def test_aws_client_never_claims_nitrotpm_was_verified():
    source = platforms.render_gpu_cc_aws_client_template()
    assert "NitroTPM attestation: PRESENT" not in source
    assert "NitroTPM measurement: PASSED" not in source
    assert "NitroTPM measurement self-pinned" not in source


# --- Template hygiene: placeholders must survive editing ------------------

@pytest.mark.parametrize(
    "render, kwargs, expected",
    [
        (platforms.render_gpu_cc_azure_client_template,
         {"measurement": "de" * 48, "container_digest": "sha256:azure"},
         ["de" * 48, "sha256:azure"]),
        # gpu-cc-aws takes ``measurement`` and deliberately drops it: the
        # platform has no CPU-side attestation, so there is nothing to compare
        # it against (tracker C5/C12).  Only the container digest is expected
        # in the rendered client.
        (platforms.render_gpu_cc_aws_client_template,
         {"measurement": "de" * 32, "container_digest": "sha256:aws"},
         ["sha256:aws"]),
        (platforms.render_gpu_cc_gcp_client_template,
         {"mrtd": "de" * 48, "container_digest": "sha256:gcp",
          "expected_vtpm_pcrs": "0:" + "ff" * 32},
         ["de" * 48, "sha256:gcp", "0:" + "ff" * 32]),
    ],
)
def test_client_placeholders_are_substituted(render, kwargs, expected):
    source = render(**kwargs)
    for value in expected:
        assert value in source
    assert "BEGIN CERTIFICATE" in source
    compile(source, "rendered.py", "exec")
