"""Offline tests for the TLS trust-store fallback in ``_urllib_get``.

The live counterpart is ``tests/integration/test_pcs_live_fetch.py``; these run
with no network so the *logic* is covered on every push.

Why this code exists: the first live fetch of Intel collateral failed with
``CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`` on a host
where ``curl`` against the same URL returned 200 and ``certifi`` was installed
in the same virtualenv. Read as a network fault it sends an operator to their
firewall; it is a missing trust store.

Two things are pinned here that a naive implementation gets wrong:

* the retry must trigger on the **actual** verification failure, not on
  inspecting the default store first — on the host that motivated this,
  ``ssl.create_default_context().get_ca_certs()`` reported 128 certificates and
  still could not verify, so that proxy signal was simply wrong;
* a non-TLS failure (DNS, timeout, refused) must **not** be retried, or every
  genuinely offline build pays two timeouts and gets a misleading TLS hint.
"""
from __future__ import annotations

import ssl
import urllib.error

import pytest

from tee_crafter.core.attestation import tcb_collateral as tc


def _verify_error() -> urllib.error.URLError:
    """A URLError wrapping a certificate-verification failure, as urllib raises."""
    return urllib.error.URLError(
        ssl.SSLCertVerificationError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "unable to get local issuer certificate"))


class TestIsTlsVerificationError:
    def test_recognises_the_wrapped_form_urllib_actually_raises(self):
        """``URLError.reason`` holds the SSLError; the outer type is not one."""
        exc = _verify_error()
        assert not isinstance(exc, ssl.SSLError)
        assert tc._is_tls_verification_error(exc) is True

    def test_recognises_a_bare_ssl_error(self):
        assert tc._is_tls_verification_error(ssl.SSLError("boom")) is True

    @pytest.mark.parametrize("exc", [
        urllib.error.URLError("[Errno 8] nodename nor servname provided"),
        TimeoutError("timed out"),
        OSError("connection refused"),
    ])
    def test_rejects_non_tls_failures(self, exc):
        assert tc._is_tls_verification_error(exc) is False


class TestUrllibGetFallback:
    def test_retries_through_certifi_after_a_verification_failure(self, monkeypatch):
        contexts = []

        def fake_urlopen(request, timeout=None, context=None):
            contexts.append(context)
            if context is None:
                raise _verify_error()
            return _FakeResponse()

        sentinel = ssl.create_default_context()
        monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(tc, "_certifi_context", lambda: sentinel)

        response = tc._urllib_get("https://example.invalid/tcb", 5.0)
        assert response.status == 200
        # First attempt on the default store, second with the fallback.
        assert contexts == [None, sentinel]

    def test_does_not_retry_a_non_tls_failure(self, monkeypatch):
        """A DNS or timeout error must fail once, not twice.

        Retrying would double the wait on every genuinely air-gapped build and
        attach a TLS hint that points at the wrong problem.
        """
        calls = []

        def fake_urlopen(request, timeout=None, context=None):
            calls.append(context)
            raise urllib.error.URLError("[Errno 8] nodename nor servname provided")

        monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(tc, "_certifi_context",
                            lambda: pytest.fail("certifi must not be consulted"))

        with pytest.raises(tc.CollateralFetchError) as exc:
            tc._urllib_get("https://example.invalid/tcb", 5.0)
        assert len(calls) == 1
        assert "nodename nor servname" in str(exc.value)
        assert "trust-store" not in str(exc.value)

    def test_reports_the_original_error_when_the_retry_also_fails(self, monkeypatch):
        """certifi not being the missing piece must not hide the real cause."""
        def fake_urlopen(request, timeout=None, context=None):
            raise _verify_error()

        monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(tc, "_certifi_context",
                            lambda: ssl.create_default_context())

        with pytest.raises(tc.CollateralFetchError) as exc:
            tc._urllib_get("https://example.invalid/tcb", 5.0)
        message = str(exc.value)
        assert "CERTIFICATE_VERIFY_FAILED" in message
        # And the hint names the fix rather than leaving the operator guessing.
        assert "certifi" in message
        assert "SSL_CERT_FILE" in message

    def test_missing_certifi_still_reports_the_tls_hint(self, monkeypatch):
        def fake_urlopen(request, timeout=None, context=None):
            raise _verify_error()

        monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(tc, "_certifi_context", lambda: None)

        with pytest.raises(tc.CollateralFetchError) as exc:
            tc._urllib_get("https://example.invalid/tcb", 5.0)
        assert "pinned Intel SGX Root CA" in str(exc.value)

    def test_verification_is_never_disabled(self, monkeypatch):
        """The fallback swaps CA bundles; it must not turn checking off.

        A fallback that reached for ``CERT_NONE`` would make this error go away
        just as effectively and is the tempting wrong fix.
        """
        captured = []

        def fake_urlopen(request, timeout=None, context=None):
            captured.append(context)
            if context is None:
                raise _verify_error()
            return _FakeResponse()

        monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
        tc._urllib_get("https://example.invalid/tcb", 5.0)

        fallback = captured[-1]
        assert fallback is not None
        assert fallback.verify_mode == ssl.CERT_REQUIRED
        assert fallback.check_hostname is True
        assert fallback.get_ca_certs(), "fallback context loaded no CA certs"


class _FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def read(self):
        return b"{}"
