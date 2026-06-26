"""SEC-CREDS-1: enclave must NEVER set AWS_* env vars.

Static-source-level invariants on
``src/tee_crafter/templates/nitro/app_vsock.template.py``.

The whole point of the refactor is that per-request creds are
threaded as boto3 client kwargs, scoped to one client object, and
GC'd at the end of the request — they never become global state via
``os.environ``.  These tests pin that contract so a future edit can't
silently regress to "just set env vars, it works on my deploy".
"""
from __future__ import annotations

import os
import re

import pytest


APP_VSOCK_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "src", "tee_crafter", "templates", "nitro", "app_vsock.template.py",
)


@pytest.fixture(scope="module")
def src() -> str:
    with open(APP_VSOCK_PATH, "r", encoding="utf-8") as f:
        return f.read()


class TestNoOsEnvironPollution:
    @pytest.mark.parametrize("forbidden", [
        # Direct env-var pollution patterns we are explicitly removing.
        "os.environ['AWS_ACCESS_KEY_ID']",
        'os.environ["AWS_ACCESS_KEY_ID"]',
        "os.environ['AWS_SECRET_ACCESS_KEY']",
        'os.environ["AWS_SECRET_ACCESS_KEY"]',
        "os.environ['AWS_SESSION_TOKEN']",
        'os.environ["AWS_SESSION_TOKEN"]',
    ])
    def test_no_aws_env_assignments(self, src, forbidden):
        # The string can only appear inside a `pop()` (cleanup of old
        # env vars set by earlier code).  We've removed that block,
        # so the string must not appear at all.
        assert forbidden + " =" not in src, (
            f"app_vsock template assigns {forbidden} — "
            "creds leak into global process env.")

    def test_kms_helpers_take_explicit_creds(self, src):
        # Both KMS callers must accept aws_creds explicitly.
        assert re.search(
            r"def\s+kms_decrypt_with_attestation\("
            r"[^)]*aws_creds", src,
        ), "kms_decrypt_with_attestation must take aws_creds kwarg"
        assert re.search(
            r"def\s+seed_entropy_from_kms\("
            r"[^)]*aws_creds", src,
        ), "seed_entropy_from_kms must take aws_creds kwarg"

    def test_request_handler_passes_creds_explicitly(self, src):
        # Inside the request dispatch the helpers are called with the
        # local ``aws_creds`` dict, not via env-var fallback.
        assert "kms_decrypt_with_attestation(" in src
        assert "aws_creds=aws_creds" in src
        # And seed_entropy_from_kms is called with the explicit creds.
        assert "seed_entropy_from_kms(aws_creds=aws_creds)" in src

    def test_creds_scrubbed_in_finally(self, src):
        # The ``finally:`` block at the bottom of the per-request
        # try/except must drop the local creds variable so it can't
        # outlive the request (Python frame GC will free it shortly
        # after either way, but the explicit ``del`` makes the
        # contract obvious to humans reading the code).
        assert "del aws_creds" in src

    def test_no_aws_credentials_in_log_keys(self, src):
        # When logging parsed JSON keys, the template MUST redact the
        # __aws_credentials field so it doesn't show up in journald.
        assert "__aws_credentials(redacted)" in src


class TestStructuredCredsAuditLogs:
    """The single audit log line for the per-request creds attachment
    must NOT contain the access-key, secret-key, or session token —
    nor even the access-key TAIL (which combined with a timestamp
    identifies the IAM principal in CloudTrail)."""

    def test_audit_log_line_omits_secrets(self, src):
        idx = src.find("[VSOCK] Per-request AWS creds attached")
        assert idx > 0, "audit log line missing"
        snippet = src[idx:idx + 600]
        # Allowed: region + expiration.
        assert "expires=%s" in snippet or "expiration" in snippet.lower()
        # Forbidden: full access key, secret key, session token, OR
        # the access-key tail (now redacted as of LOG-1 hardening).
        for forbidden in ('"secret_key"', "'secret_key'",
                            '"token"', "'token'",
                            'aws_creds["secret_key"]',
                            'aws_creds.get("secret_key")',
                            'aws_creds.get("access_key", "")[-4:]',
                            'aws_creds["access_key"][-4:]'):
            assert forbidden not in snippet, (
                f"per-request creds log line contains {forbidden!r}; "
                "secrets/identifiers may end up in journald.")

    def test_no_access_key_tail_anywhere_in_template(self, src):
        """Stricter posture: no slice of access_key[-4:] anywhere in
        the enclave template.  Operators have region + expiry, that's
        the right level of correlation for in-TEE logs."""
        # Any of these patterns indicate someone took the last 4 chars
        # of the access key for "operator correlation" — disallowed.
        for forbidden in (
            'access_key", "")[-4:]',
            'access_key"][-4:]',
            "access_key', '')[-4:]",
            "access_key'][-4:]",
        ):
            assert forbidden not in src, (
                f"enclave template may log access-key tail: {forbidden!r}")
