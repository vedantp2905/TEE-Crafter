"""Drive a **rendered** verifier client's TCB enforcement with a real quote.

The gap this closes
-------------------
Nothing else in the suite renders a client template and runs a quote through
its own call site. The evaluator's tests call ``tcb.enforce(...)`` directly with
hand-built keyword arguments; the client tests parse the template's source and
assert on structure. Between those two sits the actual call, and it was
untested.

That is not hypothetical. ``td_report_body`` was added as a *required* argument
to ``evaluate()`` — correctly fail-closed, so the new TDX-module check cannot
silently no-op — while the three TDX clients still did not pass it. The full
suite stayed green and every TDX deploy would have refused at verify time. It
was caught because the agent that made the change said so in prose, not because
anything failed.

So these tests go through ``enforce_platform_tcb_status(quote_bytes,
quote_info, pck_result)`` — the function the client actually calls — with a
quote assembled byte by byte and a fully signed collateral bundle, and assert
the platform is accepted. A missing or misrouted argument shows up as a
refusal, which is exactly what an operator would have seen.

The Intel PKI here is fabricated (``IntelWorld``) and the client is rendered
with that fake root as its pinned anchor, so the whole chain is exercised
without touching the network or needing real silicon.
"""
from __future__ import annotations

import importlib.util
import os
import struct
import sys
import types
import uuid

import pytest

import tee_crafter

# Reuse the Intel-collateral fabrication harness rather than reimplementing
# SGX X.509 extensions and signed PCS documents.  Importing across test modules
# is deliberate: a second copy of that machinery would drift, which is the
# failure mode this whole area keeps producing.
from tests.core.test_tcb_status_eval import (  # noqa: E402
    IntelWorld,
    _PLATFORM_CPUSVN,
    _TEE_TCB_SVN,
    build_qe_report,
    build_td_report_body,
)

_PKG_DIR = os.path.dirname(os.path.abspath(tee_crafter.__file__))
_TEMPLATES = os.path.join(_PKG_DIR, "templates")
_COMMON = os.path.join(_TEMPLATES, "common")

#: TDX v4 quote geometry.  Header 48 + TD report body 584 = 632 signed bytes.
_HEADER_LEN = 48
_TD_BODY_LEN = 584
_SIGNED_LEN = _HEADER_LEN + _TD_BODY_LEN


def _render(relpath: str, root_pem: str) -> str:
    with open(os.path.join(_TEMPLATES, relpath), encoding="utf-8") as fh:
        source = fh.read()
    for token, value in (
        ("{mrtd}", "ef" * 48),
        ("{container_digest}", ""),
        ("{expected_vtpm_pcrs}", ""),
        ("{intel_root_ca}", root_pem.strip()),
        ("{nvidia_root_ca}", _nvidia_pem()),
    ):
        source = source.replace(token, value)
    left = [t for t in ("{mrtd}", "{intel_root_ca}", "{container_digest}",
                        "{nvidia_root_ca}", "{expected_vtpm_pcrs}")
            if t in source]
    assert not left, f"unsubstituted placeholders in {relpath}: {left}"
    return source


def _nvidia_pem() -> str:
    with open(os.path.join(_PKG_DIR, "certs", "nvidia-nras-intermediate.pem"),
              encoding="utf-8") as fh:
        return fh.read().strip()


def _import_client(source: str, stem: str, tmp_path) -> types.ModuleType:
    path = tmp_path / f"{stem}_{uuid.uuid4().hex}.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(path.stem, None)
    return module


def _tdx_quote(*, pck_chain_pem: bytes, td_body: bytes, qe_report: bytes) -> bytes:
    """Assemble a TDX DCAP v4 quote wrapping *pck_chain_pem* as cert_data 5.

    Signatures over the quote body are not what these tests exercise — the
    chain walk and TCB evaluation are — so the attestation key is generated
    here and its signature is well-formed but otherwise uninteresting.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    att_key = ec.generate_private_key(ec.SECP256R1())

    header = bytearray(_HEADER_LEN)
    struct.pack_into("<H", header, 0, 4)        # version 4
    struct.pack_into("<H", header, 2, 2)        # ECDSA-P256 attestation key
    struct.pack_into("<I", header, 4, 0x81)     # tee_type = TDX

    assert len(td_body) == _TD_BODY_LEN, len(td_body)
    signed = bytes(header) + bytes(td_body)

    def _raw(key, payload):
        r, s = utils.decode_dss_signature(
            key.sign(payload, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    numbers = att_key.public_key().public_numbers()
    att_key_xy = (numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big"))
    td_sig = _raw(att_key, signed)

    qe_auth = b"authdata"
    qe_sig = _raw(att_key, qe_report)

    inner = (qe_report + qe_sig
             + struct.pack("<H", len(qe_auth)) + qe_auth
             + struct.pack("<H", 5)
             + struct.pack("<I", len(pck_chain_pem)) + pck_chain_pem)
    sig_data = (td_sig + att_key_xy
                + struct.pack("<H", 6) + struct.pack("<I", len(inner)) + inner)
    return signed + struct.pack("<I", len(sig_data)) + sig_data


@pytest.fixture()
def world():
    return IntelWorld()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    # The client caches the evaluator into sys.modules by design; drop it so a
    # test cannot inherit another test's successful load.
    monkeypatch.delitem(sys.modules, "tee_crafter_tcb_eval", raising=False)
    for name in ("TEE_CRAFTER_TCB_COLLATERAL",
                 "TEE_CRAFTER_TCB_COLLATERAL_MAX_AGE_HOURS",
                 "TEE_CRAFTER_TCB_ALLOW_STATUS",
                 "TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS",
                 "TEE_CRAFTER_TCB_EVAL_MODULE"):
        monkeypatch.delenv(name, raising=False)


TDX_CLIENTS = [
    "tdx/azure/client.template.py",
    "tdx/gcp/client.template.py",
    "gpu_cc/gcp/client.template.py",
]


class _Harness:
    """A rendered client plus everything its TCB call site needs."""

    def __init__(self, relpath, world, tmp_path, monkeypatch):
        self.world = world
        self.pem = _pem_chain(world)
        self.td_body = build_td_report_body(tee_tcb_svn=_TEE_TCB_SVN)
        self.qe_report = build_qe_report(cpusvn=_PLATFORM_CPUSVN) \
            if _qe_takes_cpusvn() else build_qe_report()
        self.quote = _tdx_quote(pck_chain_pem=self.pem,
                                td_body=self.td_body,
                                qe_report=self.qe_report)
        self.client = _import_client(
            _render(relpath, world.root_pem),
            "rendered_" + relpath.replace("/", "_").replace(".py", ""),
            tmp_path)
        # The evaluator must be importable from beside the client, exactly as
        # copy_client_support_modules stages it at build time.
        monkeypatch.setenv(
            "TEE_CRAFTER_TCB_EVAL_MODULE",
            os.path.join(_COMMON, "tee_crafter_tcb_eval.py"))
        monkeypatch.setenv(
            "TEE_CRAFTER_TCB_COLLATERAL",
            world.write_bundle(tmp_path, tee="tdx"))
        self.quote_info = {"tee_tcb_svn": _TEE_TCB_SVN.hex()}
        self.pck_result = {"pck_chain": world.pck_chain()}

    def enforce(self):
        return self.client.enforce_platform_tcb_status(
            self.quote, self.quote_info, self.pck_result)


def _pem_chain(world) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return b"".join(
        c.public_bytes(serialization.Encoding.PEM) for c in world.pck_chain())


def _qe_takes_cpusvn() -> bool:
    import inspect
    return "cpusvn" in inspect.signature(build_qe_report).parameters


@pytest.mark.parametrize("relpath", TDX_CLIENTS)
def test_rendered_client_accepts_an_up_to_date_platform(
        relpath, world, tmp_path, monkeypatch, capsys):
    """The end-to-end path the deploy actually runs.

    If any argument the evaluator requires is missing from this client's
    ``tcb.enforce`` call — ``td_report_body`` was, on all three — the call
    raises, the client prints FATAL and exits 1. So a clean return is the
    assertion that the wiring is complete, not just present in the source.
    """
    harness = _Harness(relpath, world, tmp_path, monkeypatch)
    # enforce_platform_tcb_status turns any failure into SystemExit(1).
    harness.enforce()
    err = capsys.readouterr().err
    assert "FATAL" not in err, err
    assert "UpToDate" in err, err


@pytest.mark.parametrize("relpath", TDX_CLIENTS)
def test_rendered_client_refuses_a_revoked_platform(
        relpath, world, tmp_path, monkeypatch, capsys):
    """A positive-only test would pass against a call that evaluates nothing."""
    harness = _Harness(relpath, world, tmp_path, monkeypatch)
    # Mark every level Revoked so whichever one the platform's SVNs match is
    # the one that refuses.  Rewriting the default set rather than building a
    # bespoke one keeps the SVN/PCESVN geometry that the platform actually
    # matches against.
    revoked_levels = []
    for level in world.default_levels("tdx"):
        level = dict(level)
        level["tcbStatus"] = "Revoked"
        revoked_levels.append(level)
    monkeypatch.setenv(
        "TEE_CRAFTER_TCB_COLLATERAL",
        world.write_bundle(
            tmp_path, name="revoked.json", tee="tdx",
            tcb_info_body=world.tcb_info_body(tee="tdx", levels=revoked_levels)))
    with pytest.raises(SystemExit) as exc:
        harness.enforce()
    assert exc.value.code == 1
    assert "FATAL" in capsys.readouterr().err


@pytest.mark.parametrize("relpath", TDX_CLIENTS)
def test_rendered_client_refuses_when_collateral_is_absent(
        relpath, world, tmp_path, monkeypatch, capsys):
    """No bundle staged must be fatal, never a skip.

    A build that forgets to stage collateral is the case where "verified"
    silently means "not checked", so it has to fail the same way a bad status
    does.
    """
    harness = _Harness(relpath, world, tmp_path, monkeypatch)
    monkeypatch.setenv("TEE_CRAFTER_TCB_COLLATERAL",
                       str(tmp_path / "does-not-exist.json"))
    with pytest.raises(SystemExit) as exc:
        harness.enforce()
    assert exc.value.code == 1
    assert "FATAL" in capsys.readouterr().err
