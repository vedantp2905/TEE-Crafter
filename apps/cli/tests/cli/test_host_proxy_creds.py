"""SEC-CREDS-2: host_proxy.template.py credential-scoping contract.

The host_proxy is a Python template that is read verbatim and shipped
to deployed instances.  These tests confirm static invariants:

* The proxy only attaches ``__aws_credentials`` to requests that
  actually trigger AWS calls (``ciphertext_b64`` / ``encrypted_payload``).
  Pure attestation handshakes — and any future no-cred paths — never
  receive credential material.
* The proxy strips any inbound ``__aws_credentials`` field before
  resolving its own credentials, so a malicious caller cannot inject
  their own creds and have them passed to the enclave.
* IMDSv2 availability is required before forwarding creds (refusal
  is explicit, not silent).
* ``TEE_CRAFTER_PROXY_NO_CREDS=1`` is honoured.

We test the template file source directly: importing it fails because
of its FastAPI dependencies, but its credential-scoping policy lives
in plain string predicates and a dispatch function we can ``exec`` in
a stripped context.
"""
from __future__ import annotations

import os
import sys
import types

import pytest


TEMPLATE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "src", "tee_crafter", "templates", "nitro", "host_proxy.template.py",
)


def _load_predicates() -> dict:
    """Execute just the credential-policy helpers from the template.

    The template imports FastAPI / boto3 / uvicorn at module top, so we
    cannot do a plain ``import``.  Instead we slice out the helpers
    (``_request_needs_aws_creds`` and ``_imdsv2_available`` reset
    plumbing) and exec them in an isolated namespace.
    """
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        text = f.read()
    # Stub fastapi + boto3 so the module imports cleanly.
    fake_fastapi = types.ModuleType("fastapi")
    fake_fastapi.FastAPI = lambda *a, **k: types.SimpleNamespace(
        post=lambda *a, **k: (lambda f: f),
    )
    fake_fastapi.Request = type("Request", (), {})
    fake_fastapi.HTTPException = type("HTTPException", (Exception,), {})
    fake_responses = types.ModuleType("fastapi.responses")
    fake_responses.JSONResponse = lambda *a, **k: (a, k)
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.Session = lambda *a, **k: types.SimpleNamespace(
        get_credentials=lambda: None, region_name=None,
        client=lambda *a, **k: None,
    )
    fake_boto3.client = lambda *a, **k: None
    sys.modules.setdefault("fastapi", fake_fastapi)
    sys.modules.setdefault("fastapi.responses", fake_responses)
    sys.modules.setdefault("boto3", fake_boto3)
    ns: dict = {"__name__": "host_proxy_for_tests"}
    exec(compile(text, TEMPLATE_PATH, "exec"), ns)
    return ns


@pytest.fixture(scope="module")
def template_ns():
    return _load_predicates()


# ---------------------------------------------------------------------------
# _request_needs_aws_creds
# ---------------------------------------------------------------------------

class TestRequestNeedsAwsCreds:
    @pytest.mark.parametrize("body", [
        {"action": "get_attestation"},
        {"action": "get_attestation", "nonce": "abc"},
        {"action": "get_attestation", "public_key_b64": "..."},
        # Bare body without any KMS markers.
        {"random_field": "value"},
        # Empty / non-dict bodies should never trigger cred forwarding.
        {},
        [],
        "string-body",
        42,
    ])
    def test_non_kms_paths_never_get_creds(self, template_ns, body):
        assert template_ns["_request_needs_aws_creds"](body) is False

    @pytest.mark.parametrize("body", [
        {"ciphertext_b64": "AAAA="},
        {"encrypted_payload": "BBBB=", "client_public_key": "C", "nonce": "N"},
        {"ciphertext_b64": "A", "extra_metadata": True},
    ])
    def test_kms_paths_get_creds(self, template_ns, body):
        assert template_ns["_request_needs_aws_creds"](body) is True

    def test_empty_string_markers_do_not_trigger(self, template_ns):
        # A KMS field that's empty is "falsy" — we must NOT forward
        # creds in that case (no useful KMS call possible).
        assert template_ns["_request_needs_aws_creds"](
            {"ciphertext_b64": ""}) is False
        assert template_ns["_request_needs_aws_creds"](
            {"encrypted_payload": ""}) is False


# ---------------------------------------------------------------------------
# Inbound credential stripping
# ---------------------------------------------------------------------------

class TestInboundCredentialStripping:
    """The template strips inbound __aws_credentials before resolving
    its own.  Test the predicate set the handler relies on."""

    def test_template_source_strips_inbound_creds(self):
        with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
            text = f.read()
        # The strip-on-entry pattern.  If this string drifts, update
        # the test, but make sure the new pattern is equivalent.
        assert "body_json.pop(\"__aws_credentials\"" in text


# ---------------------------------------------------------------------------
# Static invariants in the template source
# ---------------------------------------------------------------------------

class TestStaticInvariants:
    """Catch regressions by reading the template as source."""

    @pytest.fixture(scope="class")
    def src(self) -> str:
        with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
            return f.read()

    def test_imdsv2_probe_is_PUT_with_token_header(self, src):
        assert "X-aws-ec2-metadata-token-ttl-seconds" in src
        assert "169.254.169.254" in src
        # IMDSv2 uses PUT for the token endpoint.
        assert 'method="PUT"' in src

    def test_no_cred_envvar_honoured(self, src):
        assert "TEE_CRAFTER_PROXY_NO_CREDS" in src

    def test_never_forwards_caller_supplied_creds(self, src):
        # The pop() of inbound creds must happen BEFORE the resolve
        # call (`_fetch_short_lived_creds(...)`) inside the request
        # handler — otherwise a caller could inject ``__aws_credentials``
        # in their body and the proxy would forward those instead of
        # resolving its own.
        #
        # The function DEFINITION ``def _fetch_short_lived_creds`` lives
        # earlier in the file (module-level), so we slice the request
        # handler body and check the order there.
        handler_start = src.find("async def handle_enclave_request")
        assert handler_start >= 0
        handler_body = src[handler_start:]
        strip_idx = handler_body.find("body_json.pop(\"__aws_credentials\"")
        call_idx = handler_body.find("_fetch_short_lived_creds(")
        assert strip_idx >= 0, "inbound-creds strip is missing"
        assert call_idx >= 0, "credential resolver invocation is missing"
        assert strip_idx < call_idx, (
            "host_proxy resolves creds before stripping inbound; "
            "potential credential-injection vector.")

    def test_never_logs_secret_material(self, src):
        # LOG-1 (hardened): the template must NEVER emit secret_key,
        # session token, OR the access-key tail.  Earlier versions
        # logged ``AK=...XXXX`` for operator correlation; that's now
        # forbidden because the tail + timestamp identifies the IAM
        # principal in CloudTrail.
        forbidden = [
            'creds["secret_key"]',
            'creds.get("secret_key")',
            'aws_creds["secret_key"]',
            'aws_creds.get("secret_key")',
            'logging.info("[PROXY] %s", creds["secret_key"]',
            # Access-key tail must not appear in any log call.
            'creds["access_key"][-4:]',
            'creds.get("access_key", "")[-4:]',
            'aws_creds.get("access_key", "")[-4:]',
        ]
        for f in forbidden:
            assert f not in src, f"host_proxy may log secret/identifying material: {f}"

    def test_strict_imds_is_default(self, src):
        # SEC-CREDS-2: production default is STRICT IMDSv2 — the env
        # read defaults to "1".  Setting TEE_CRAFTER_PROXY_STRICT_IMDS=0
        # is a dev hatch that re-enables the env-cred fallback.
        assert 'TEE_CRAFTER_PROXY_STRICT_IMDS", "1"' in src, (
            "host_proxy must default STRICT_IMDS to 1 (production)"
        )
        assert "STRICT" in src

    def test_strict_imds_only_fires_when_env_creds_present(self, src):
        # Earlier code 503'd unconditionally on missing IMDS, which broke
        # every ECIES request (the entropy seed is best-effort; no env
        # fallback exists on a baked AMI).  The strict gate now only
        # fires when there is something to fall back TO — i.e.,
        # AWS_ACCESS_KEY_ID is present.  Otherwise the proxy forwards
        # without creds and the enclave handles missing creds for ECIES.
        assert "_STRICT_IMDS and not imdsv2_ok and has_env_creds" in src, (
            "strict-IMDS 503 must require has_env_creds; otherwise "
            "ECIES traffic with an unreachable IMDS becomes a hard 503."
        )

    def test_http_exception_is_preserved(self, src):
        # The outer ``except Exception`` must re-raise HTTPException
        # untouched.  Otherwise intentional 4xx/5xx responses (including
        # the strict-IMDS 503) get silently converted to a generic 500.
        handler_start = src.find("async def handle_enclave_request")
        assert handler_start >= 0
        handler_body = src[handler_start:]
        http_re_raise = handler_body.find("except HTTPException:")
        broad_catch = handler_body.find("except Exception")
        assert 0 <= http_re_raise < broad_catch, (
            "Handler must re-raise HTTPException before the broad "
            "Exception catch; otherwise 4xx/5xx codes leak as 500."
        )
