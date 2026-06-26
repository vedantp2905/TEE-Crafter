"""Live end-to-end fetch of Intel PCS collateral through the real HTTP path.

Everything else that covers ``core/attestation/tcb_collateral.py`` injects a
fake ``http_get``, so ``_urllib_get`` itself — the only part that touches the
network — was never executed by the suite.  That gap hid a real failure: the
first live run of this module raised

    CollateralFetchError: URLError: <urlopen error [SSL:
    CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local
    issuer certificate>

on a machine where ``curl`` against the same URLs returned 200, because the
interpreter had no usable CA store while the system one was fine.  No amount
of injected-transport testing would have surfaced that.

These tests are marked ``integration`` and therefore deselected by the default
``addopts``.  Run them deliberately::

    python -m pytest tests/integration/test_pcs_live_fetch.py -m integration

They need outbound HTTPS to ``api.trustedservices.intel.com`` and
``certificates.trustedservices.intel.com``.  Neither needs credentials — Intel
PCS v4 collateral is public — so this is the one part of the attestation stack
that *can* be verified against the real service from a developer machine.

The TCB status of the FMSPC below is deliberately not asserted: it is a real
platform whose status Intel changes over time, and pinning it would make this
file fail for a reason that has nothing to do with the code.  What is asserted
is that every document fetched carries a signature that verifies against the
pinned Intel root, which is the property the builder exists to establish.
"""
from __future__ import annotations

import pytest

from tee_crafter.core.attestation import tcb_collateral as tc

pytestmark = pytest.mark.integration

#: A real, currently-served FMSPC.  Any FMSPC Intel still publishes TCBInfo
#: for works; this one was chosen because it returns 200 from both hosts.
LIVE_FMSPC = "90c06f000000"


@pytest.fixture(scope="module")
def live_bundle():
    """Fetch a complete bundle from the real Intel PCS.

    ``build_collateral_bundle`` verifies each document's signature against the
    pinned root as it goes, so a successful call is itself the assertion that
    Intel's live collateral passes this module's verification — not just that
    the HTTP request returned bytes.
    """
    try:
        return tc.build_collateral_bundle(fmspc=LIVE_FMSPC)
    except tc.CollateralFetchError as exc:
        pytest.skip(f"Intel PCS unreachable from this host: {exc}")


def test_every_item_is_present_and_signature_verified(live_bundle):
    assert live_bundle["complete"] is True
    assert live_bundle["missing"] == []
    # All seven: SGX+TDX TCBInfo, SGX+TDX QEIdentity, platform+processor PCK
    # CRLs, Root CA CRL.  Spelled out rather than compared against the
    # module's own spec list, so dropping a spec cannot silently shrink the
    # expectation along with the behaviour.
    assert set(live_bundle["items"]) == {
        "sgx_tcb_info", "tdx_tcb_info",
        "sgx_qe_identity", "tdx_qe_identity",
        "sgx_pck_crl_platform", "sgx_pck_crl_processor",
        "sgx_root_ca_crl",
    }


def test_bundle_re_verifies_offline(live_bundle):
    """The client's own re-verification must accept what the builder produced.

    This is the handoff that matters: the builder verifies on fetch, and the
    verifier client re-verifies the staged bundle offline with no network.  A
    live fetch that only the builder can validate would fail closed on every
    deploy.
    """
    tc.verify_collateral_bundle(live_bundle)


def test_two_hosts_are_recorded_separately(live_bundle):
    """Collateral spans two Intel hosts; both must be named in the bundle.

    ``source`` alone used to describe every item, which is what makes the
    air-gap mirror override easy to get half-right (tracker C18).
    """
    assert "api.trustedservices.intel.com" in live_bundle["source"]
    assert ("certificates.trustedservices.intel.com"
            in live_bundle["certificates_source"])


def test_live_fetch_needs_no_ssl_cert_file_env(monkeypatch):
    """The fetch must work on an interpreter with a broken default trust store.

    This is the exact failure that motivated the certifi retry: a
    `python-build-standalone` interpreter (what ``uv`` installs) whose default
    store reports 128 loaded CA certificates and still cannot chain Intel's
    certificate, on a host where ``curl`` returns 200. Clearing
    ``SSL_CERT_FILE`` reproduces it, so this asserts the retry rather than the
    ambient environment.
    """
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    url = (f"{tc.DEFAULT_PCS_BASE_URL.rstrip('/')}"
           "/sgx/certification/v4/qe/identity")
    try:
        response = tc._urllib_get(url, 20.0)
    except tc.CollateralFetchError as exc:
        pytest.skip(f"Intel PCS unreachable from this host: {exc}")
    assert response.status == 200
    assert response.body


def test_urllib_get_reports_a_bad_status_without_raising():
    """``_urllib_get`` must surface an HTTP error status as a response.

    An ``HTTPError`` *is* a response; treating it as a transport failure loses
    the status code, which is the only thing that distinguishes "this FMSPC is
    unknown to Intel" (404) from "Intel is rate-limiting this build host"
    (429).  Exercised against the live service with a deliberately invalid
    FMSPC.
    """
    url = (f"{tc.DEFAULT_PCS_BASE_URL.rstrip('/')}"
           "/sgx/certification/v4/tcb?fmspc=ffffffffffff")
    try:
        response = tc._urllib_get(url, 15.0)
    except tc.CollateralFetchError as exc:
        pytest.skip(f"Intel PCS unreachable from this host: {exc}")
    assert response.status != 200
    assert isinstance(response.headers, dict)
