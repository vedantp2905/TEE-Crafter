"""The snp-azure app must quote with the AK the HCL vouches for.

The verifier half of this (``verify_hcl_ak_binding``) is covered by
test_snp_azure_hcl_ak_binding.  It was correct and still failed on hardware,
because the *server* was quoting with a key nothing vouches for: the app minted
a fresh primary with ``tpm2_createprimary`` while the runtime data names the
paravisor's own AK.  Two keys, so the modulus comparison could never match, and
the strict gate stayed unsatisfiable.

Measured on tee-crafter-snp-vm-3515abcc, 2026-08-23:

    HCLAkPub modulus         8CB54C6000007485B8D0563451E077DEEAD9AC6A4B24...
    tpm2_readpublic 0x81000003  8CB54C6000007485B8D0563451E077DEEAD9AC6A4B24...
    REPORT_DATA[:32] == sha256(runtime_data)          True

and, after the app switched to that handle, the client reported
``AK->SNP binding: PASSED`` with ``binding_mode=hcl_runtime_data_strong``.

The handle is verified rather than trusted: ``0x81000003`` is tried first but
only used if its modulus equals HCLAkPub, so an Azure change in handle layout
degrades to the ephemeral AK (which the verifier then refuses) instead of
quoting with an unvouched key.
"""
from __future__ import annotations

import ast
import base64
import json
import logging
import os
import types

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def _template(*parts: str) -> str:
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "src", "tee_crafter", "templates", *parts,
        "app.template.py")


_APP = _template("snp", "azure")

#: ``gpu-cc-azure`` is the same paravisor and carries the same helper, ported
#: rather than reimplemented.  It is exercised here because the client-side
#: check was ported to that platform first, and a verifier upgrade whose server
#: half is missing is exactly the inert fix this project has now hit twice.
#: The platform itself remains unverified on hardware -- no ``NCCads``
#: capacity (B6) -- so these are parity tests, not evidence.
_APPS = {
    "snp-azure": _APP,
    "gpu-cc-azure": _template("gpu_cc", "azure"),
}

DEFAULT_HANDLE = "0x81000003"
OTHER_HANDLES = ("0x81000001", "0x81000004")


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def _n_b64(key, pad: int = 0) -> str:
    n = key.public_key().public_numbers().n
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b"\x00" * pad + raw).decode().rstrip("=")


def _runtime_data(*, ak_n: str | None) -> bytes:
    keys = []
    if ak_n is not None:
        keys.append({"kid": "HCLAkPub", "kty": "RSA", "e": "AQAB", "n": ak_n})
    keys.append({"kid": "HCLEkPub", "kty": "RSA", "e": "AQAB",
                 "n": _n_b64(_key())})
    return json.dumps({"keys": keys, "vm-configuration": {}}).encode()


class _Proc:
    def __init__(self, stdout: bytes = b""):
        self.returncode = 0
        self.stdout = stdout
        self.stderr = b""


def _load(runtime_data: bytes, handle_pems: dict, app: str = _APP):
    """Build the module with ``subprocess`` and the TPM stubbed out."""
    src = open(app, encoding="utf-8").read()
    mod = types.ModuleType("extracted_app")
    calls = []

    def _run(argv, **kw):
        calls.append(list(argv))
        if argv[0] == "tpm2_getcap":
            listed = "".join(f"- {h}\n" for h in handle_pems)
            return _Proc(listed.encode())
        if argv[0] == "tpm2_readpublic":
            handle = argv[argv.index("-c") + 1]
            if handle not in handle_pems:
                raise RuntimeError(f"no such handle {handle}")
            out = argv[argv.index("-o") + 1]
            with open(out, "wb") as f:
                f.write(handle_pems[handle])
            return _Proc()
        raise AssertionError(f"unexpected argv {argv}")

    mod.__dict__.update(
        json=json, base64=base64, os=os, logging=logging,
        serialization=serialization,
        subprocess=types.SimpleNamespace(run=_run),
        _get_hcl_runtime_data=lambda: runtime_data,
    )
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "_tpm_hcl_ak":
            exec(compile(ast.Module([node], []), app, "exec"), mod.__dict__)
        elif isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "_TPM_HCL_AK_HANDLE"
                for t in node.targets):
            exec(compile(ast.Module([node], []), app, "exec"), mod.__dict__)
    assert hasattr(mod, "_tpm_hcl_ak"), f"_tpm_hcl_ak not found in {app}"
    assert mod._TPM_HCL_AK_HANDLE == DEFAULT_HANDLE
    return mod, calls


@pytest.mark.parametrize("app", list(_APPS.values()),
                         ids=list(_APPS))
class TestItFindsTheAttestedAk:

    def test_it_returns_the_handle_whose_modulus_is_hclakpub(self, app):
        ak = _key()
        pems = {DEFAULT_HANDLE: _pem(ak),
                OTHER_HANDLES[0]: _pem(_key())}
        mod, _ = _load(_runtime_data(ak_n=_n_b64(ak)), pems)
        got = mod._tpm_hcl_ak()
        assert got is not None
        pem, handle = got
        assert handle == DEFAULT_HANDLE
        assert pem == _pem(ak)

    def test_it_tries_the_known_handle_first(self, app):
        """Saves enumerating the whole persistent range on the common path."""
        ak = _key()
        mod, calls = _load(_runtime_data(ak_n=_n_b64(ak)),
                           {DEFAULT_HANDLE: _pem(ak)})
        assert mod._tpm_hcl_ak() is not None
        readpublic = [c for c in calls if c[0] == "tpm2_readpublic"]
        assert readpublic[0][readpublic[0].index("-c") + 1] == DEFAULT_HANDLE

    def test_it_scans_when_the_known_handle_is_the_wrong_key(self, app):
        """An Azure layout change must not silently fall back to ephemeral."""
        ak = _key()
        pems = {DEFAULT_HANDLE: _pem(_key()),
                OTHER_HANDLES[0]: _pem(ak),
                OTHER_HANDLES[1]: _pem(_key())}
        mod, _ = _load(_runtime_data(ak_n=_n_b64(ak)), pems)
        got = mod._tpm_hcl_ak()
        assert got is not None and got[1] == OTHER_HANDLES[0]

    def test_a_leading_zero_in_the_jwk_modulus_still_matches(self, app):
        """A JWK ``n`` may carry a leading zero byte; the parsed key never does.

        Comparing bytes rather than integers here would reject the real key.
        """
        ak = _key()
        mod, _ = _load(_runtime_data(ak_n=_n_b64(ak, pad=1)),
                       {DEFAULT_HANDLE: _pem(ak)})
        assert mod._tpm_hcl_ak() is not None


@pytest.mark.parametrize("app", list(_APPS.values()),
                         ids=list(_APPS))
class TestItRefusesRatherThanGuessing:
    """Every negative path must return None so the caller uses the ephemeral
    AK and the verifier's strict gate does the refusing."""

    def test_no_handle_matches(self, app):
        mod, _ = _load(_runtime_data(ak_n=_n_b64(_key())),
                       {DEFAULT_HANDLE: _pem(_key()),
                        OTHER_HANDLES[0]: _pem(_key())})
        assert mod._tpm_hcl_ak() is None

    def test_no_runtime_data_at_all(self, app):
        mod, _ = _load(b"", {DEFAULT_HANDLE: _pem(_key())})
        assert mod._tpm_hcl_ak() is None

    def test_runtime_data_without_an_hclakpub_key(self, app):
        mod, _ = _load(_runtime_data(ak_n=None),
                       {DEFAULT_HANDLE: _pem(_key())})
        assert mod._tpm_hcl_ak() is None

    def test_unparseable_runtime_data(self, app):
        mod, _ = _load(b"{not json", {DEFAULT_HANDLE: _pem(_key())})
        assert mod._tpm_hcl_ak() is None

    def test_no_persistent_handles_readable(self, app):
        mod, _ = _load(_runtime_data(ak_n=_n_b64(_key())), {})
        assert mod._tpm_hcl_ak() is None


class TestTheCallSiteUsesIt:
    """A correct helper nobody calls is what the first attempt at this was."""

    @pytest.fixture(scope="class")
    def src(self):
        return open(_APP, encoding="utf-8").read()

    def test_the_ratls_path_prefers_the_hcl_ak(self, src):
        assert "_hcl_ak = _tpm_hcl_ak()" in src

    def test_the_ephemeral_path_is_still_reachable(self, src):
        """Kept so an unexpected TPM layout is a verifier refusal, not a crash."""
        body = src[src.index("_hcl_ak = _tpm_hcl_ak()"):]
        assert "_tpm_create_ak()" in body[:600]

    def test_it_does_not_rmtree_a_persistent_handle(self, src):
        """The HCL AK has no context directory; the old cleanup assumed one.

        ``shutil.rmtree(None)`` raises, and it sits in a ``finally`` -- so this
        would have masked the real result with a TypeError on the happy path.
        """
        body = src[src.index("_hcl_ak = _tpm_hcl_ak()"):]
        cleanup = body[body.index("finally:"):body.index("finally:") + 300]
        assert "if _ak_ctx_dir:" in cleanup


class TestTheGpuCcCallSiteUsesItToo:
    """The client-side check was ported to gpu-cc-azure before the server side.

    That is the inert-fix shape: a verifier that can only report the upgrade if
    the server happens to present the right key, against a server that never
    does.  gpu-cc-azure builds its quote in one shot inside
    ``_generate_tpm_quote`` rather than the two-phase flow snp-azure uses, so
    the call site is different and needs its own assertion.
    """

    @pytest.fixture(scope="class")
    def src(self):
        return open(_APPS["gpu-cc-azure"], encoding="utf-8").read()

    def test_the_quote_prefers_the_hcl_ak(self, src):
        quote_fn = src[src.index("def _generate_tpm_quote("):]
        assert "hcl_ak = _tpm_hcl_ak()" in quote_fn[:4000]

    def test_the_ephemeral_primary_is_only_the_else_branch(self, src):
        quote_fn = src[src.index("def _generate_tpm_quote("):]
        head = quote_fn[:5000]
        assert head.index("hcl_ak = _tpm_hcl_ak()") < head.index(
            "tpm2_createprimary")

    def test_the_hcl_ak_pem_is_what_gets_returned(self, src):
        """The returned ak_pub must be the HCL AK, not a stale ephemeral read.

        The function returns the bytes at ``ak_pub_path``, so the HCL branch has
        to write the PEM there rather than leaving the file untouched.
        """
        quote_fn = src[src.index("def _generate_tpm_quote("):]
        branch = quote_fn[quote_fn.index("if hcl_ak:"):]
        assert "f.write(ak_pub_pem)" in branch[:400]
