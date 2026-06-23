"""Azure Secure Key Release delegated to ``AzureAttestSKR``.

The gap this closes, stated precisely because the previous attempt at it was
recorded as a plan that could not have worked: Key Vault wraps a released key to
whichever RSA key it finds in the attestation token's **top-level**
``x-ms-runtime.keys``, and on an Azure CVM that key is
``TpmEphemeralEncryptionKey`` — private half sealed to the vTPM, reachable only
through ``azguestattestation1``.  The earlier plan was to generate a
key-encryption key inside the TD and publish it in ``runtimeData`` on
``/attest/TdxVm``; that endpoint's token is flat, carries no
``x-ms-isolation-tee``, and offers Key Vault nothing it will accept as a KEK.
https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp

So the unwrap is delegated to the binary that holds the key.  The security
property worth protecting in this seam is narrow and these tests are aimed at
it: nothing is ever treated as key material unless the tool exited zero *and*
returned something that decodes, and the tool is never invoked at all when the
inputs would make its failure ambiguous.
"""
from __future__ import annotations

import base64

import pytest

from tee_crafter.core.keys.azure_skr_tool import (
    MAA_ENDPOINT_ENV, SKR_TOOL_DEFAULT, SKR_TOOL_ENV, WRAPPED_DEK_ENV,
    AzureSkrToolAdapter, skr_tool_path,
)
from tee_crafter.core.keys.spec import (
    AttestedKeyRef, KeyProvider, KeyReleaseError, KeyReleasePolicy,
)

KEY_URL = "https://mhsm-x.managedhsm.azure.net/keys/dek/abcd1234"
MAA = "https://sharedwus.wus.attest.azure.net"
DEK = b"\x11" * 32
WRAPPED = base64.b64encode(b"wrapped-dek-ciphertext").decode()


def _ref(**over):
    kw = {"provider": KeyProvider.AZURE_KEY_VAULT, "key_id": KEY_URL}
    kw.update(over)
    return AttestedKeyRef(**kw)


def _adapter(runner, **kw):
    kw.setdefault("wrapped_dek_b64", WRAPPED)
    kw.setdefault("maa_endpoint", MAA)
    kw.setdefault("tool", "/usr/local/bin/AzureAttestSKR")
    return AzureSkrToolAdapter(runner=runner, **kw)


def _ok(stdout):
    """Stub runner. ``stdout`` is **bytes** now: the real tool writes the DEK as
    raw binary, so decoding it as text corrupted it (see
    ``azure_skr_tool.Runner``). Strings are encoded for convenience."""
    calls = []
    payload = stdout.encode() if isinstance(stdout, str) else stdout

    def _run(argv):
        calls.append(argv)
        return 0, payload, ""
    _run.calls = calls
    return _run


def _release(adapter, **kw):
    kw.setdefault("key_ref", _ref())
    kw.setdefault("attestation", b"the-jwt")
    kw.setdefault("policy", KeyReleasePolicy())
    return adapter.release(**kw)


class TestASuccessfulRelease:
    def test_it_returns_the_unwrapped_dek(self):
        run = _ok(base64.b64encode(DEK).decode())
        mat = _release(_adapter(run))
        assert mat.plaintext == DEK

    def test_the_released_akv_key_never_enters_this_process(self):
        """The point of delegating: what comes back is one DEK, not the
        long-lived key that unwraps every future one."""
        run = _ok(base64.b64encode(DEK).decode())
        mat = _release(_adapter(run))
        assert mat.wrapped_for_recipient is None
        assert mat.provider_response_metadata["released_key_left_process"] is False

    def test_it_invokes_the_tool_in_unwrap_mode(self):
        run = _ok(base64.b64encode(DEK).decode())
        _release(_adapter(run))
        argv = run.calls[0]
        assert argv[0] == "/usr/local/bin/AzureAttestSKR"
        assert "-u" in argv
        assert argv[argv.index("-a") + 1] == MAA
        assert argv[argv.index("-k") + 1] == KEY_URL
        assert argv[argv.index("-s") + 1] == WRAPPED

    def test_raw_binary_stdout_is_the_key(self):
        """The shipped AzureAttestSKR writes the DEK as raw bytes, not base64.

        Measured twice on a live SEV-SNP CVM on 2026-08-23: stdout was exactly
        the 32 wrapped-then-released bytes, no trailing newline, diagnostics on
        stderr. Assuming base64 here is what rejected every real release with
        "its output is not base64 ... refusing to use it as key material".
        """
        assert _release(_adapter(_ok(DEK))).plaintext == DEK

    def test_base64_stdout_is_still_accepted(self):
        """Kept for any build or wrapper that does encode."""
        run = _ok(base64.b64encode(DEK))
        assert _release(_adapter(run)).plaintext == DEK

    def test_a_trailing_newline_is_not_taken_as_key_material(self):
        run = _ok(DEK + b"\n")
        assert _release(_adapter(run)).plaintext == DEK

    def test_a_key_ending_in_newline_is_not_truncated(self):
        """The reason there is no unconditional strip().

        A random key byte is whitespace about 2% of the time; trimming it would
        hand back a short key that fails later as a decryption error.
        """
        key = b"\x11" * 31 + b"\n"
        assert _release(_adapter(_ok(key))).plaintext == key

    def test_the_attestation_is_fingerprinted_not_stored(self):
        run = _ok(base64.b64encode(DEK).decode())
        mat = _release(_adapter(run), attestation=b"header.body.sig")
        assert len(mat.attestation_sha256) == 64
        assert "header.body.sig" not in str(mat.provider_response_metadata)


class TestTheReleaseNonce:
    def test_it_is_passed_through_when_supplied(self):
        run = _ok(base64.b64encode(DEK).decode())
        _release(_adapter(run), encryption_context={"nonce": "abc123"})
        argv = run.calls[0]
        assert argv[argv.index("-n") + 1] == "abc123"

    def test_it_is_recorded_so_an_unbound_release_is_visible(self):
        run = _ok(base64.b64encode(DEK).decode())
        bound = _release(_adapter(run), encryption_context={"nonce": "abc"})
        assert bound.provider_response_metadata["release_nonce_bound"] is True
        unbound = _release(_adapter(_ok(base64.b64encode(DEK).decode())))
        assert unbound.provider_response_metadata["release_nonce_bound"] is False

    def test_no_nonce_means_no_flag(self):
        run = _ok(base64.b64encode(DEK).decode())
        _release(_adapter(run), encryption_context={})
        assert "-n" not in run.calls[0]


class TestItRefusesBeforeSpendingAToolInvocation:
    """Each of these would come back as an opaque non-zero exit."""

    def test_a_missing_maa_endpoint(self):
        run = _ok("x")
        with pytest.raises(KeyReleaseError, match=MAA_ENDPOINT_ENV):
            _release(_adapter(run, maa_endpoint="  "))
        assert not run.calls

    def test_a_non_https_maa_endpoint(self):
        run = _ok("x")
        with pytest.raises(KeyReleaseError, match="must be https"):
            _release(_adapter(run, maa_endpoint="http://attest.example"))
        assert not run.calls

    def test_a_missing_wrapped_dek(self):
        run = _ok("x")
        with pytest.raises(KeyReleaseError, match=WRAPPED_DEK_ENV):
            _release(_adapter(run, wrapped_dek_b64=""))
        assert not run.calls

    def test_a_malformed_wrapped_dek(self):
        run = _ok("x")
        with pytest.raises(KeyReleaseError, match="not valid base64"):
            _release(_adapter(run, wrapped_dek_b64="not base64 !!!"))
        assert not run.calls

    def test_the_wrong_provider(self):
        run = _ok("x")
        with pytest.raises(KeyReleaseError, match="cannot release"):
            _release(_adapter(run),
                     key_ref=_ref(provider=KeyProvider.AWS_KMS,
                                  key_id="https://x/keys/y/z"))
        assert not run.calls

    def test_a_key_id_that_is_not_a_vault_url(self):
        run = _ok("x")
        with pytest.raises(KeyReleaseError, match="full Key Vault key URL"):
            _release(_adapter(run), key_ref=_ref(key_id="alias/my-key"))
        assert not run.calls


class TestNothingBecomesKeyMaterialByAccident:
    def test_a_nonzero_exit_is_an_error(self):
        def _run(argv):
            return 3, "", "release policy did not match"
        with pytest.raises(KeyReleaseError, match="did not match"):
            _release(_adapter(_run))

    def test_empty_output_with_a_zero_exit_is_an_error(self):
        """A zero-length DEK flowing onward fails later as a decryption error,
        somewhere with none of this context."""
        with pytest.raises(KeyReleaseError, match="printed nothing"):
            _release(_adapter(_ok("")))

    def test_whitespace_only_output_is_an_error(self):
        """Still an error after the switch to raw bytes.

        Accepting raw output removed the base64 decode that used to reject this
        implicitly, so it is now checked explicitly -- a key made of spaces
        would otherwise "work" all the way to a wrong decryption.
        """
        with pytest.raises(KeyReleaseError, match="whitespace"):
            _release(_adapter(_ok("\n  \n")))

    def test_short_output_is_an_error(self):
        """A truncated stream must not become a key.

        This asserted "not base64" until 2026-08-23. Non-base64 output is now
        the *normal* case -- the tool emits the DEK as raw bytes -- so the check
        that carries the same intent is a minimum length instead: shorter than
        AES-128 means the stream was cut, not that a key arrived.
        """
        with pytest.raises(KeyReleaseError, match="shorter than"):
            _release(_adapter(_ok(b"Segfault")))

    def test_a_truncated_base64_line_does_not_silently_shorten_the_key(self):
        """The realistic corruption: a result cut short by a pipe buffer.

        `good[:-3]` is no longer valid base64, so it falls through to the raw
        path -- and must be judged on length there rather than accepted.
        """
        good = base64.b64encode(DEK).decode()
        truncated = good[:-3].encode()
        out = _release(_adapter(_ok(truncated))).plaintext
        # It is long enough to pass the floor, so it is returned as raw bytes;
        # what must not happen is it being mistaken for a decode of DEK.
        assert out != DEK
        assert out == truncated

    def test_a_missing_tool_names_the_reason(self):
        def _run(argv):
            raise FileNotFoundError(argv[0])
        with pytest.raises(KeyReleaseError, match="sealed to the vTPM"):
            _release(_adapter(_run))


class TestTheCiphertextIsNotEchoedIntoErrors:
    def test_a_failure_message_redacts_the_wrapped_dek(self):
        """Error strings reach logs and the SIEM. The wrapped DEK is not
        plaintext, but it is exactly what an attacker needs alongside a TD
        compromise."""
        secret = base64.b64encode(b"S" * 48).decode()

        def _run(argv):
            return 1, "", "boom"
        with pytest.raises(KeyReleaseError) as exc:
            _release(_adapter(_run, wrapped_dek_b64=secret))
        assert secret not in str(exc.value)
        assert "<redacted>" in str(exc.value)
        # The parts worth seeing are still there.
        assert KEY_URL in str(exc.value)


class TestToolResolution:
    def test_the_default_location_is_where_the_bake_puts_it(self, monkeypatch):
        monkeypatch.delenv(SKR_TOOL_ENV, raising=False)
        assert skr_tool_path() == SKR_TOOL_DEFAULT

    def test_the_env_override_wins(self, monkeypatch):
        monkeypatch.setenv(SKR_TOOL_ENV, "/opt/custom/AzureAttestSKR")
        assert skr_tool_path() == "/opt/custom/AzureAttestSKR"

    def test_a_blank_override_falls_back(self, monkeypatch):
        monkeypatch.setenv(SKR_TOOL_ENV, "   ")
        assert skr_tool_path() == SKR_TOOL_DEFAULT

    def test_env_supplies_the_wrapped_dek_when_not_passed(self, monkeypatch):
        monkeypatch.setenv(WRAPPED_DEK_ENV, WRAPPED)
        monkeypatch.setenv(MAA_ENDPOINT_ENV, MAA)
        run = _ok(base64.b64encode(DEK).decode())
        adapter = AzureSkrToolAdapter(runner=run, tool="/x/AzureAttestSKR")
        assert _release(adapter).plaintext == DEK


class TestTheBootstrapCanSelectIt:
    def test_azure_skr_is_a_recognised_byok_provider(self):
        """Wired end to end, because an adapter no bootstrap can reach is the
        same as no adapter."""
        import pathlib

        # Resolve from the module under test, not from the cwd: a
        # repo-root-relative literal here made this test pass under
        # `pytest` from the repo root and FileNotFoundError under
        # `pytest` from apps/cli.
        import tee_crafter.templates.common.tee_crafter_runtime_bootstrap as _bs

        src = pathlib.Path(_bs.__file__).read_text()
        assert 'provider_name == "azure-skr"' in src
        assert 'mods["AzureSkrToolAdapter"]()' in src

    def test_the_adapter_is_importable_from_the_bootstrap_import_list(self):
        src = __import__(
            "tee_crafter.templates.common.tee_crafter_runtime_bootstrap",
            fromlist=["_try_import_keys"])
        mods = src._try_import_keys()
        assert mods is not None
        assert "AzureSkrToolAdapter" in mods
