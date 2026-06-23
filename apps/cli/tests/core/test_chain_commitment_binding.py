"""AUD-3: the audit-log genesis commitment must be inside hardware-signed evidence.

The in-TEE runtime audit log (``templates/common/tee_crafter_audit_logger.py``)
is an HMAC hash chain whose key exists only in encrypted guest memory.  The
logger writes a SHA-256 commitment to that key into the log's genesis entry —
but compared only against the same log, the commitment proves nothing: a
host-level adversary who discards the log can mint a fresh key, write a fresh
genesis entry and a fresh chain, and publish the matching commitment.

These tests cover the fix: the commitment is folded into the preimage of the
hardware-signed attestation value, and the platform clients recompute that
preimage and fail closed when it does not match.

Two deliberate choices, both learned the hard way on this repo:

* The expected bytes are built by ``_v2_digest`` below, an independent
  re-implementation of the wire format written from the ``challenge_binding``
  description the servers publish.  It uses ``int.to_bytes`` where the
  templates use ``struct.pack``, so it cannot silently track a change made to
  both sides at once.
* Failures are asserted on the specific reason string or the specific exit
  code, never on a bare exception.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import textwrap
import uuid

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

from tee_crafter.core.builder import builder, platforms

REPO_TEMPLATES = os.path.join(
    os.path.dirname(os.path.abspath(platforms.__file__)), "..", "..", "templates")
REPO_TEMPLATES = os.path.normpath(REPO_TEMPLATES)


# ---------------------------------------------------------------------------
# The v2 attestation-binding encoding, re-implemented from the wire spec
# ---------------------------------------------------------------------------
# Every server publishes this shape in a self-describing field
# (``challenge_binding`` / ``nonce_binding`` / ``binding``):
#
#   sha256( lp(label) || uint32be(field_count) || lp(field_0) || lp(field_1) ...)
#
# where lp(x) == uint32be(len(x)) || x.
_V2_LABEL = b"tee-crafter/attest-binding/v2"


def _lp(field: bytes) -> bytes:
    return len(field).to_bytes(4, "big") + field


def _v2_preimage(*fields: bytes) -> bytes:
    body = _lp(_V2_LABEL) + len(fields).to_bytes(4, "big")
    for field in fields:
        body += _lp(field)
    return body


def _v2_digest(*fields: bytes) -> bytes:
    return hashlib.sha256(_v2_preimage(*fields)).digest()


#: A syntactically valid commitment (64 lowercase hex characters).
COMMITMENT_A = "a1" * 32
#: A second one, for tamper tests.
COMMITMENT_B = "b2" * 32


# ---------------------------------------------------------------------------
# AMD SEV-SNP report assembly (ABI 56860 offsets, written out here)
# ---------------------------------------------------------------------------
SNP_REPORT_LEN = 1184
SNP_SIG_OFFSET = 0x2A0
SNP_SIG_FIELD_LEN = 72
SNP_P384_SCALAR_LEN = 48
SNP_OFF_VMPL = 0x30
SNP_OFF_SIG_ALGO = 0x34
SNP_OFF_REPORT_DATA = 0x50
SNP_OFF_MEASUREMENT = 0x90


def _snp_signed_report(signing_key, report_data: bytes, measurement: bytes) -> bytes:
    body = bytearray(SNP_SIG_OFFSET)
    struct.pack_into("<I", body, 0x00, 2)
    struct.pack_into("<I", body, SNP_OFF_VMPL, 0)
    struct.pack_into("<I", body, SNP_OFF_SIG_ALGO, 1)
    body[SNP_OFF_REPORT_DATA:SNP_OFF_REPORT_DATA + len(report_data)] = report_data
    body[SNP_OFF_MEASUREMENT:SNP_OFF_MEASUREMENT + len(measurement)] = measurement
    der = signing_key.sign(bytes(body), ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(der)
    report = bytearray(SNP_REPORT_LEN)
    report[:SNP_SIG_OFFSET] = body
    report[SNP_SIG_OFFSET:SNP_SIG_OFFSET + SNP_P384_SCALAR_LEN] = \
        r.to_bytes(SNP_P384_SCALAR_LEN, "little")
    off = SNP_SIG_OFFSET + SNP_SIG_FIELD_LEN
    report[off:off + SNP_P384_SCALAR_LEN] = s.to_bytes(SNP_P384_SCALAR_LEN, "little")
    return bytes(report)


def _self_signed_cert(key, common_name: str) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA384())
    )


def _spki_der(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# Rendered-template loading
# ---------------------------------------------------------------------------
SNP_CLIENT_RENDERERS = {
    "snp-aws": lambda: platforms.render_snp_aws_client_template(
        measurement="", measurements=[], container_digest=""),
    "snp-azure": lambda: platforms.render_snp_azure_client_template(
        measurement="", measurements=[], container_digest=""),
    "snp-gcp": lambda: platforms.render_snp_gcp_client_template(
        measurement="", measurements=[], container_digest=""),
}

GPU_CLIENT_RENDERERS = {
    "gpu-cc-aws": platforms.render_gpu_cc_aws_client_template,
    "gpu-cc-azure": platforms.render_gpu_cc_azure_client_template,
    "gpu-cc-gcp": platforms.render_gpu_cc_gcp_client_template,
}

#: The seven platform app templates this change covers, and the tag used in
#: their log lines.
#: Every app template, so "all apps agree" is a statement about all of them.
#:
#: ``sgx``, ``tdx-azure`` and ``tdx-gcp`` were missing from this map. They
#: import cleanly and always did — they were simply never listed, so the whole
#: producer-side class silently covered 6 platforms while reading as though it
#: covered all of them. SGX in particular is the platform whose commitment
#: publication *always* fails (no ``/run`` mount in the Gramine manifest), so
#: the one platform that depends entirely on the fallback was the one not being
#: exercised.
APP_TEMPLATES = {
    "nitro": "nitro/app_vsock.template.py",
    "snp-aws": "snp/aws/app.template.py",
    "snp-azure": "snp/azure/app.template.py",
    "snp-gcp": "snp/gcp/app.template.py",
    "gpu-cc-aws": "gpu_cc/aws/app.template.py",
    "gpu-cc-azure": "gpu_cc/azure/app.template.py",
    "gpu-cc-gcp": "gpu_cc/gcp/app.template.py",
    "sgx": "sgx/app_gramine.template.py",
    "tdx-azure": "tdx/azure/app.template.py",
    "tdx-gcp": "tdx/gcp/app.template.py",
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


@pytest.fixture(scope="module", params=sorted(SNP_CLIENT_RENDERERS))
def snp_client(request, tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("aud3_snp_clients")
    return _load_module(SNP_CLIENT_RENDERERS[request.param](), tmp_path,
                        f"client_{request.param.replace('-', '_')}")


@pytest.fixture(scope="module", params=sorted(GPU_CLIENT_RENDERERS))
def gpu_client(request, tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("aud3_gpu_clients")
    return _load_module(GPU_CLIENT_RENDERERS[request.param](), tmp_path,
                        f"client_{request.param.replace('-', '_')}")


@pytest.fixture(scope="module")
def nitro_client(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("aud3_nitro_client")
    source = builder.render_client_template(pcr_hashes={"0": "aa" * 48}, root_ca="")
    return _load_module(source, tmp_path, "client_nitro")


# ---------------------------------------------------------------------------
# Producer side: the app templates really pick the commitment up
# ---------------------------------------------------------------------------
# Run in a subprocess: importing an app template puts templates/common on
# sys.path and instantiates a process-wide audit-log HMAC key, and we do not
# want either leaking into the rest of the session.
_PROBE = r'''
import importlib.util, json, os, sys, uuid

common, tpl_root, workdir, out_path = sys.argv[1:5]
sys.path.insert(0, common)
# argv[6], when given, overrides where the commitment is published.  Used to
# simulate a platform on which publication cannot succeed (see the SGX case).
os.environ["TEE_CRAFTER_CHAIN_COMMITMENT_PATH"] = (
    sys.argv[6] if len(sys.argv) > 6
    else os.path.join(workdir, "run", "chain_key_commitment"))
os.environ["TEE_AUDIT_LOG_DIR"] = os.path.join(workdir, "log")

apps = json.loads(sys.argv[5])
results = {}
for label, rel in apps.items():
    src = open(os.path.join(tpl_root, rel)).read()
    src = src.replace("{user_imports}", "").replace("{user_logic}", "    return data")
    mod_path = os.path.join(workdir, "app_%s.py" % label.replace("-", "_"))
    with open(mod_path, "w") as fh:
        fh.write(src)
    name = "_probe_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, mod_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    entry = {}
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        entry["import_error"] = "%s: %s" % (type(exc).__name__, exc)
        results[label] = entry
        continue
    # Two shapes in the tree: the SNP / GPU-CC templates resolve the
    # commitment at import into a module-level _CHAIN_KEY_COMMITMENT, while
    # sgx / tdx-* resolve it lazily in _chain_key_commitment().  Reading only
    # the constant silently reported None for the lazy ones, which is why they
    # were absent from APP_TEMPLATES and never covered.
    commitment = getattr(mod, "_CHAIN_KEY_COMMITMENT", None)
    if not commitment and hasattr(mod, "_chain_key_commitment"):
        try:
            commitment = mod._chain_key_commitment()
        except Exception as exc:
            entry["commitment_error"] = "%s: %s" % (type(exc).__name__, exc)
    entry["commitment"] = commitment
    entry["preimage_ab_cd"] = mod._attest_binding_preimage(b"ab", b"cd").hex()
    entry["preimage_abc_d"] = mod._attest_binding_preimage(b"abc", b"d").hex()
    entry["preimage_one_field"] = mod._attest_binding_preimage(b"abcd").hex()
    entry["digest_ab_cd"] = mod._attest_binding_digest(b"ab", b"cd").hex()
    results[label] = entry

published = os.environ["TEE_CRAFTER_CHAIN_COMMITMENT_PATH"]
payload = {"apps": results,
           "published": open(published).read().strip() if os.path.isfile(published) else None}
with open(out_path, "w") as fh:
    json.dump(payload, fh)
'''


@pytest.fixture(scope="module")
def app_probe(tmp_path_factory):
    """Import every app template in a subprocess and report what it produced."""
    workdir = tmp_path_factory.mktemp("aud3_app_probe")
    script = workdir / "probe.py"
    script.write_text(textwrap.dedent(_PROBE), encoding="utf-8")
    out = workdir / "probe.json"
    # nitro/app_vsock.template.py pulls in asn1crypto/boto3, which are not
    # installed in the test environment; drop it from the import probe and
    # cover it by source inspection instead (see TestSourceWiring).
    apps = {k: v for k, v in APP_TEMPLATES.items() if k != "nitro"}
    proc = subprocess.run(
        [sys.executable, str(script),
         os.path.join(REPO_TEMPLATES, "common"), REPO_TEMPLATES, str(workdir),
         str(out), json.dumps(apps)],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"probe failed:\n{proc.stdout}\n{proc.stderr}"
    return json.loads(out.read_text())


@pytest.fixture(scope="module")
def app_probe_unpublishable(tmp_path_factory):
    """Same probe, but with publication guaranteed to fail.

    This is the SGX case made testable without an SGX host.
    ``templates/sgx/manifest.template.toml`` declares no ``/run`` mount and
    Gramine's tmpfs is enclave memory, so inside the enclave
    ``publish_chain_key_commitment()`` always fails and
    ``bootstrap_chain_commitment()`` returns ``""``. Every app template then has
    to fall back to the in-process ``get_chain_key_commitment()`` — otherwise
    the quote carries an empty commitment and **every client refuses the
    connection**.

    That fallback was the highest-risk untested path in the previous round
    (tracker B4), on the grounds that it needed real hardware. It does not: the
    failure being simulated is an unwritable publication path, and pointing the
    path *underneath a regular file* makes ``os.makedirs`` raise
    ``NotADirectoryError`` on both macOS and Linux. What still needs an SGX host
    is confirming that Gramine fails this write in exactly this way — not
    whether the fallback works when it does.
    """
    workdir = tmp_path_factory.mktemp("aud3_app_probe_nopub")
    script = workdir / "probe.py"
    script.write_text(textwrap.dedent(_PROBE), encoding="utf-8")
    out = workdir / "probe.json"

    blocker = workdir / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    unwritable = str(blocker / "run" / "chain_key_commitment")

    apps = {k: v for k, v in APP_TEMPLATES.items() if k != "nitro"}
    proc = subprocess.run(
        [sys.executable, str(script),
         os.path.join(REPO_TEMPLATES, "common"), REPO_TEMPLATES, str(workdir),
         str(out), json.dumps(apps), unwritable],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"probe failed:\n{proc.stdout}\n{proc.stderr}"
    payload = json.loads(out.read_text())
    payload["published_path"] = unwritable
    return payload


class TestCommitmentSurvivesFailedPublication:
    """B4: publication failing must not cost the hardware binding."""

    def test_publication_really_did_fail(self, app_probe_unpublishable):
        """Guard the negative control.

        If publication quietly succeeded, the tests below would be re-testing
        the happy path while claiming to cover the fallback.
        """
        assert app_probe_unpublishable["published"] is None
        assert not os.path.exists(app_probe_unpublishable["published_path"])

    @pytest.mark.parametrize("label",
                             sorted(k for k in APP_TEMPLATES if k != "nitro"))
    def test_app_still_binds_a_real_commitment(self, app_probe_unpublishable,
                                               label):
        entry = app_probe_unpublishable["apps"][label]
        assert "import_error" not in entry, entry.get("import_error")
        commitment = entry["commitment"]
        assert re.fullmatch(r"[0-9a-f]{64}", commitment or ""), (
            f"{label} lost its chain-key commitment because publication "
            f"failed; a client would refuse this quote. Got {commitment!r}")

    def test_all_apps_still_agree(self, app_probe_unpublishable):
        values = {label: entry["commitment"]
                  for label, entry in app_probe_unpublishable["apps"].items()}
        assert len(set(values.values())) == 1, values


class TestBothOutcomesOfPublicationAreLogged:
    """The assertions above are written from the code, not from a run.

    Whether Gramine's emulated tmpfs lets this write succeed is a property of
    the runtime, and it has never been watched on a real ``sgx-azure --batch``
    run. Only the failure used to log anything, which left two states that
    matter indistinguishable in an enclave log: a call that never happened, and
    a write that went wrong without raising. One line per outcome means a single
    run answers it.
    """

    @staticmethod
    def _logger_module(tmp_path, monkeypatch):
        import importlib.util

        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "src", "tee_crafter", "templates", "common",
            "tee_crafter_audit_logger.py")
        monkeypatch.setenv("TEE_CRAFTER_AUDIT_LOG_DIR", str(tmp_path / "log"))
        spec = importlib.util.spec_from_file_location(
            "_probe_audit_logger", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_success_is_logged_with_the_path(self, tmp_path, monkeypatch, caplog):
        mod = self._logger_module(tmp_path, monkeypatch)
        target = tmp_path / "published" / "chain_key_commitment"
        with caplog.at_level("INFO"):
            result = mod.publish_chain_key_commitment(str(target))
        assert result, "publication should have succeeded here"
        assert str(target) in caplog.text
        assert "published" in caplog.text

    def test_failure_is_logged_and_says_the_binding_survives(self, tmp_path,
                                                             monkeypatch,
                                                             caplog):
        """The warning has to say what was *not* lost, or an operator reads it
        as 'attestation is broken' and tears down a working deploy."""
        mod = self._logger_module(tmp_path, monkeypatch)
        blocked = tmp_path / "blocked"
        blocked.write_text("not a directory", encoding="utf-8")
        with caplog.at_level("WARNING"):
            result = mod.publish_chain_key_commitment(
                str(blocked / "chain_key_commitment"))
        assert result == ""
        assert "NOT published" in caplog.text
        assert "report_data" in caplog.text


class TestAppTemplatesBindTheLiveCommitment:
    """The wiring item 11 was actually about: one call per app template."""

    @pytest.mark.parametrize("label", sorted(k for k in APP_TEMPLATES if k != "nitro"))
    def test_app_resolves_a_real_commitment(self, app_probe, label):
        entry = app_probe["apps"][label]
        assert "import_error" not in entry, entry.get("import_error")
        commitment = entry["commitment"]
        assert isinstance(commitment, str)
        assert re.fullmatch(r"[0-9a-f]{64}", commitment), commitment

    def test_all_apps_agree_and_match_the_published_file(self, app_probe):
        """Same process, same audit logger, so one commitment for all of them.

        The tmpfs file is written by ``publish_chain_key_commitment`` and read
        by the SIEM sidecar; if the app bound a different value to hardware
        than the sidecar exports, ``verify-siem-chain`` would compare two
        unrelated things.
        """
        values = {label: entry["commitment"]
                  for label, entry in app_probe["apps"].items()}
        assert len(set(values.values())) == 1, values
        assert app_probe["published"] == next(iter(values.values()))

    @pytest.mark.parametrize("label", sorted(k for k in APP_TEMPLATES if k != "nitro"))
    def test_preimage_matches_the_published_wire_format(self, app_probe, label):
        entry = app_probe["apps"][label]
        assert entry["preimage_ab_cd"] == _v2_preimage(b"ab", b"cd").hex()
        assert entry["digest_ab_cd"] == _v2_digest(b"ab", b"cd").hex()

    @pytest.mark.parametrize("label", sorted(k for k in APP_TEMPLATES if k != "nitro"))
    def test_field_boundaries_cannot_be_spliced(self, app_probe, label):
        """The whole point of length-prefixing.

        Raw concatenation cannot tell ``("ab", "cd")`` from ``("abc", "d")``:
        both are the bytes ``abcd``.  Under v2 they must differ, and neither
        may collide with a single field holding all four bytes.
        """
        entry = app_probe["apps"][label]
        assert b"ab" + b"cd" == b"abc" + b"d"          # the hazard, stated
        assert entry["preimage_ab_cd"] != entry["preimage_abc_d"]
        assert entry["preimage_ab_cd"] != entry["preimage_one_field"]
        assert entry["preimage_abc_d"] != entry["preimage_one_field"]

    def test_label_is_inside_the_hashed_bytes(self, app_probe):
        """A v1 or v3 preimage must never be reinterpretable as a v2 one."""
        entry = next(iter(app_probe["apps"].values()))
        other_label = b"tee-crafter/attest-binding/v3"
        forged = _lp(other_label) + (2).to_bytes(4, "big") + _lp(b"ab") + _lp(b"cd")
        assert entry["digest_ab_cd"] != hashlib.sha256(forged).hexdigest()


class TestSourceWiring:
    """Source-level guards for the call sites the probe cannot reach.

    ``get_attestation`` handlers need a live socket and real TEE hardware to
    invoke, and ``nitro/app_vsock.template.py`` cannot even be imported here
    (boto3/asn1crypto are not test dependencies).  These assertions at least
    fail loudly if a future edit drops the commitment from a preimage.
    """

    #: The tree has two shapes for reaching the commitment, and an assertion
    #: written against one of them silently skips the other. The SNP and
    #: GPU-CC templates resolve it at import into ``_CHAIN_KEY_COMMITMENT``;
    #: ``sgx`` and ``tdx-*`` resolve it lazily via ``_chain_key_commitment()``.
    #: Both are legitimate — what matters is that the value reaches the client
    #: and the preimage.
    _DECLARE_FORMS = (
        '"chain_key_commitment": _CHAIN_KEY_COMMITMENT',
        '"chain_key_commitment": _chain_key_commitment()',
    )
    _PREIMAGE_FORMS = (
        '_CHAIN_KEY_COMMITMENT.encode("ascii")',
        '_commitment.encode("ascii")',
    )

    @pytest.mark.parametrize("label,rel", sorted(APP_TEMPLATES.items()))
    def test_app_declares_the_commitment_to_clients(self, label, rel):
        src = open(os.path.join(REPO_TEMPLATES, rel), encoding="utf-8").read()
        assert any(form in src for form in self._DECLARE_FORMS), (
            f"{rel} does not publish the commitment to its client in any "
            f"recognised form: {self._DECLARE_FORMS}")

    @pytest.mark.parametrize("label,rel", sorted(APP_TEMPLATES.items()))
    def test_app_feeds_the_commitment_into_a_binding_preimage(self, label, rel):
        src = open(os.path.join(REPO_TEMPLATES, rel), encoding="utf-8").read()
        assert any(form in src for form in self._PREIMAGE_FORMS), (
            f"{rel} does not fold the commitment into a binding preimage in "
            f"any recognised form: {self._PREIMAGE_FORMS}")
        # ... and the naive v1 concatenation is gone.
        assert "challenge = nonce + _TLS_SPKI_DER" not in src, rel

    def test_nitro_app_no_longer_forwards_the_raw_client_nonce(self):
        src = open(os.path.join(REPO_TEMPLATES, APP_TEMPLATES["nitro"]),
                   encoding="utf-8").read()
        assert 'nonce=data.get("nonce", "")' not in src
        assert "_attest_binding_digest(" in src


# ---------------------------------------------------------------------------
# Consumer side: SNP live challenge
# ---------------------------------------------------------------------------
@pytest.fixture
def snp_setup():
    """A VM identity plus a correctly bound live report."""
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    tls_key = ec.generate_private_key(ec.SECP384R1())
    nonce_ascii = base64.b64encode(bytes(range(32)))
    measurement = bytes(range(48))
    endorsement_pem = _self_signed_cert(vcek_key, "test-vcek").public_bytes(
        serialization.Encoding.PEM)
    cert_der = _self_signed_cert(tls_key, "vm.local").public_bytes(
        serialization.Encoding.DER)

    def report_for(commitment_ascii: bytes) -> bytes:
        return _snp_signed_report(
            vcek_key,
            _v2_digest(nonce_ascii, _spki_der(tls_key), commitment_ascii),
            measurement)

    return {
        "nonce_ascii": nonce_ascii,
        "cert_der": cert_der,
        "endorsement_pem": endorsement_pem,
        "measurement_hex": measurement.hex(),
        "tls_key": tls_key,
        "vcek_key": vcek_key,
        "report_for": report_for,
    }


def _call_snp(client, snp_setup, att_resp):
    return client.verify_live_challenge(
        att_resp,
        snp_setup["nonce_ascii"],
        snp_setup["cert_der"],
        snp_setup["endorsement_pem"],
        snp_setup["measurement_hex"],
    )


class TestSnpChainCommitmentBinding:
    def test_bound_commitment_is_accepted(self, snp_client, snp_setup):
        ok, reason = _call_snp(snp_client, snp_setup, {
            "report_hex": snp_setup["report_for"](COMMITMENT_A.encode()).hex(),
            "chain_key_commitment": COMMITMENT_A,
        })
        assert ok, reason

    def test_tampered_commitment_is_rejected(self, snp_client, snp_setup):
        """AMD signed COMMITMENT_A; the server claims COMMITMENT_B."""
        ok, reason = _call_snp(snp_client, snp_setup, {
            "report_hex": snp_setup["report_for"](COMMITMENT_A.encode()).hex(),
            "chain_key_commitment": COMMITMENT_B,
        })
        assert not ok
        assert "v2 attestation binding digest" in reason

    def test_absent_commitment_is_rejected(self, snp_client, snp_setup,
                                           monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", raising=False)
        ok, reason = _call_snp(snp_client, snp_setup, {
            "report_hex": snp_setup["report_for"](COMMITMENT_A.encode()).hex(),
        })
        assert not ok
        assert "no runtime audit-log chain-key commitment" in reason

    def test_absent_commitment_rejected_even_when_report_binds_nothing(
            self, snp_client, snp_setup, monkeypatch):
        """A server that simply never had a commitment is still refused.

        This is the fail-closed half: an empty binding is internally
        consistent, so only the explicit opt-out may accept it.
        """
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", raising=False)
        ok, reason = _call_snp(snp_client, snp_setup, {
            "report_hex": snp_setup["report_for"](b"").hex(),
            "chain_key_commitment": "",
        })
        assert not ok
        assert "no runtime audit-log chain-key commitment" in reason

    def test_escape_hatch_accepts_an_unbound_chain_with_a_warning(
            self, snp_client, snp_setup, monkeypatch, capsys):
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", "1")
        ok, reason = _call_snp(snp_client, snp_setup, {
            "report_hex": snp_setup["report_for"](b"").hex(),
        })
        assert ok, reason
        assert "WARNING" in capsys.readouterr().err

    def test_escape_hatch_does_not_excuse_a_mismatched_binding(
            self, snp_client, snp_setup, monkeypatch):
        """The opt-out waives the *requirement*, not the arithmetic.

        The report commits to COMMITMENT_A but nothing is declared, so the
        recomputed preimage uses an empty commitment and cannot match.
        """
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", "1")
        ok, reason = _call_snp(snp_client, snp_setup, {
            "report_hex": snp_setup["report_for"](COMMITMENT_A.encode()).hex(),
        })
        assert not ok
        assert "v2 attestation binding digest" in reason

    @pytest.mark.parametrize("bad", ["a1" * 31, "a1" * 33, "zz" * 32,
                                     "not-a-digest"])
    def test_malformed_commitment_is_rejected(self, snp_client, snp_setup,
                                              monkeypatch, bad):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", raising=False)
        ok, reason = _call_snp(snp_client, snp_setup, {
            "report_hex": snp_setup["report_for"](bad.encode()).hex(),
            "chain_key_commitment": bad,
        })
        assert not ok
        assert "not a 64-character SHA-256 hex digest" in reason

    def test_uppercase_commitment_is_normalised_not_rejected(
            self, snp_client, snp_setup):
        """Hex case is not semantic; the preimage uses the lowercase form."""
        ok, reason = _call_snp(snp_client, snp_setup, {
            "report_hex": snp_setup["report_for"](COMMITMENT_A.encode()).hex(),
            "chain_key_commitment": COMMITMENT_A.upper(),
        })
        assert ok, reason

    def test_legacy_v1_concatenated_report_is_rejected(self, snp_client,
                                                       snp_setup):
        """The pre-AUD-3 wire format: sha256(nonce || spki), no length prefixes.

        A server built before this change is refused rather than silently
        downgraded — client and server must be rebuilt from the same commit.
        """
        legacy = _snp_signed_report(
            snp_setup["vcek_key"],
            hashlib.sha256(snp_setup["nonce_ascii"]
                           + _spki_der(snp_setup["tls_key"])).digest(),
            bytes.fromhex(snp_setup["measurement_hex"]))
        ok, reason = _call_snp(snp_client, snp_setup, {
            "report_hex": legacy.hex(),
            "chain_key_commitment": COMMITMENT_A,
        })
        assert not ok
        assert "v2 attestation binding digest" in reason


# ---------------------------------------------------------------------------
# Consumer side: GPU-CC NRAS nonce binding
# ---------------------------------------------------------------------------
GPU_SALT = bytes(range(32))
GPU_ECDH_PUB = b"\x04" + bytes(range(64))


def _nras_binding(commitment_ascii: bytes, *, declared_commitment=None,
                  nonce_hex=None) -> dict:
    """Build the certificate extension payload a GPU-CC server publishes."""
    computed = hashlib.sha256(
        _v2_digest(GPU_ECDH_PUB, commitment_ascii) + GPU_SALT).hexdigest()
    payload = {
        "ecdh_pub_b64": base64.b64encode(GPU_ECDH_PUB).decode(),
        "nonce_salt_hex": GPU_SALT.hex(),
        "nonce_hex": nonce_hex if nonce_hex is not None else computed,
        "tls_spki_sha256": "cc" * 32,
    }
    declared = (commitment_ascii.decode() if declared_commitment is None
                else declared_commitment)
    if declared is not None:
        payload["chain_key_commitment"] = declared
    return payload


class TestGpuCcNrasCommitmentBinding:
    """On GPU-CC the anchor is the NVIDIA-signed ``eat_nonce``.

    ``_verify_nras_nonce_binding`` recomputes the nonce the server submitted
    to NRAS; ``verify_gpu_nras_token`` then requires NVIDIA's token to echo
    exactly that value.  Folding the commitment into the nonce preimage is
    therefore what puts it under a signature.
    """

    def test_bound_commitment_is_accepted(self, gpu_client):
        out = gpu_client._verify_nras_nonce_binding(
            _nras_binding(COMMITMENT_A.encode()))
        assert out["ok"], out["error"]
        assert out["chain_key_commitment"] == COMMITMENT_A

    def test_tampered_commitment_is_rejected(self, gpu_client):
        binding = _nras_binding(COMMITMENT_A.encode(),
                               declared_commitment=COMMITMENT_B)
        out = gpu_client._verify_nras_nonce_binding(binding)
        assert not out["ok"]
        assert "binding mismatch" in out["error"]

    def test_absent_commitment_is_rejected(self, gpu_client, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", raising=False)
        binding = _nras_binding(COMMITMENT_A.encode(), declared_commitment=None)
        binding.pop("chain_key_commitment")
        out = gpu_client._verify_nras_nonce_binding(binding)
        assert not out["ok"]
        assert "no runtime audit-log chain-key commitment" in out["error"]

    def test_escape_hatch_accepts_an_unbound_chain(self, gpu_client, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", "1")
        binding = _nras_binding(b"", declared_commitment="")
        out = gpu_client._verify_nras_nonce_binding(binding)
        assert out["ok"], out["error"]
        assert out["chain_key_commitment"] == ""

    def test_legacy_v1_nonce_is_rejected(self, gpu_client):
        """Pre-AUD-3 servers computed sha256(ecdh_pub || salt) directly."""
        legacy_nonce = hashlib.sha256(GPU_ECDH_PUB + GPU_SALT).hexdigest()
        binding = _nras_binding(COMMITMENT_A.encode(), nonce_hex=legacy_nonce)
        out = gpu_client._verify_nras_nonce_binding(binding)
        assert not out["ok"]
        assert "binding mismatch" in out["error"]

    def test_malformed_commitment_is_rejected(self, gpu_client, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", raising=False)
        binding = _nras_binding(b"deadbeef", declared_commitment="deadbeef")
        out = gpu_client._verify_nras_nonce_binding(binding)
        assert not out["ok"]
        assert "not a 64-character SHA-256 hex digest" in out["error"]


# ---------------------------------------------------------------------------
# Consumer side: Nitro attestation-document nonce
# ---------------------------------------------------------------------------
def _cose_doc(nonce: bytes) -> str:
    """A COSE_Sign1 envelope whose payload carries only the nonce.

    ``verify_attestation`` checks the nonce before anything else, so this is
    enough to exercise that gate without a real NSM document.
    """
    payload = cbor2.dumps({"nonce": nonce})
    return base64.b64encode(cbor2.dumps([b"", {}, payload, b""])).decode()


class TestNitroDocNonceCommitmentBinding:
    """nsm-cli cannot set ``user_data``, so the commitment rides the nonce.

    ``templates/common/nsm_main.rs`` hardcodes ``user_data: None`` and offers
    no flag for it, and ``public_key`` must stay the raw ECDH key the client
    extracts.  The nonce field is the only remaining guest-supplied input the
    Nitro Hypervisor signs.
    """

    def test_expected_nonce_matches_the_published_wire_format(self, nitro_client):
        client_nonce = bytes(range(32))
        assert nitro_client.expected_doc_nonce(
            client_nonce, COMMITMENT_A.encode()) == _v2_digest(
                client_nonce, COMMITMENT_A.encode())

    def test_bound_nonce_passes_the_nonce_gate(self, nitro_client, capsys):
        """A correct document gets past the nonce check and dies on timestamp.

        Asserting on the *next* failure is how we know the nonce comparison
        itself succeeded, without having to forge a whole signed NSM document
        (which would need AWS's Nitro attestation key).
        """
        client_nonce = bytes(range(32))
        doc = _cose_doc(_v2_digest(client_nonce, COMMITMENT_A.encode()))
        with pytest.raises(SystemExit) as exc:
            nitro_client.verify_attestation(doc, client_nonce,
                                            COMMITMENT_A.encode())
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "nonce does not equal" not in err
        assert "timestamp" in err

    def test_tampered_commitment_is_rejected(self, nitro_client, capsys):
        client_nonce = bytes(range(32))
        doc = _cose_doc(_v2_digest(client_nonce, COMMITMENT_A.encode()))
        with pytest.raises(SystemExit) as exc:
            nitro_client.verify_attestation(doc, client_nonce,
                                            COMMITMENT_B.encode())
        assert exc.value.code == 1
        assert "nonce does not equal the v2 binding digest" in capsys.readouterr().err

    def test_legacy_raw_nonce_document_is_rejected(self, nitro_client, capsys):
        """Pre-AUD-3 enclaves echoed the client's raw 32 bytes."""
        client_nonce = bytes(range(32))
        with pytest.raises(SystemExit) as exc:
            nitro_client.verify_attestation(_cose_doc(client_nonce), client_nonce,
                                            COMMITMENT_A.encode())
        assert exc.value.code == 1
        assert "nonce does not equal the v2 binding digest" in capsys.readouterr().err

    def test_absent_commitment_is_rejected(self, nitro_client, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", raising=False)
        commitment, error = nitro_client.resolve_chain_key_commitment("")
        assert commitment == b""
        assert "no runtime audit-log chain-key commitment" in error

    def test_escape_hatch_accepts_an_unbound_chain(self, nitro_client,
                                                   monkeypatch, capsys):
        monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", "1")
        commitment, error = nitro_client.resolve_chain_key_commitment("")
        assert (commitment, error) == (b"", "")
        assert "WARNING" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The resolver's policy, once per client family
# ---------------------------------------------------------------------------
ALL_CLIENT_RENDERERS = {**SNP_CLIENT_RENDERERS, **{
    k: v for k, v in GPU_CLIENT_RENDERERS.items()}}


@pytest.fixture(scope="module", params=sorted(ALL_CLIENT_RENDERERS))
def any_client(request, tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("aud3_any_clients")
    return _load_module(ALL_CLIENT_RENDERERS[request.param](), tmp_path,
                        f"any_{request.param.replace('-', '_')}")


class TestResolverPolicyIsUniform:
    """All six RA-TLS clients must agree on the fail-closed policy."""

    def test_valid_commitment_round_trips(self, any_client):
        assert any_client.resolve_chain_key_commitment(COMMITMENT_A) == (
            COMMITMENT_A.encode("ascii"), "")

    def test_absent_is_fatal(self, any_client, monkeypatch):
        monkeypatch.delenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", raising=False)
        commitment, error = any_client.resolve_chain_key_commitment(None)
        assert commitment == b""
        assert "no runtime audit-log chain-key commitment" in error

    def test_env_hatch_must_be_exactly_one(self, any_client, monkeypatch):
        """"true"/"yes"/"0" must not open the hatch — only "1"."""
        for value in ("0", "true", "yes", "", "01"):
            monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN", value)
            _, error = any_client.resolve_chain_key_commitment("")
            assert error, f"{value!r} should not open the escape hatch"
