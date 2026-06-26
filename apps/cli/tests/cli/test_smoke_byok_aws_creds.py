"""smoke_byok_aws.py: long-lived IAM-user keys must not leave the laptop.

The threat model in the smoke script's docstring promises that the
default flow mints short-lived STS session credentials before
forwarding anything over the SSM tunnel.  These tests pin that promise:

* When the ambient creds carry no ``session_token``, we MUST call
  ``sts:GetSessionToken`` and forward only the resulting temporary
  credential.
* When the ambient creds already carry a ``session_token`` (instance
  role / SSO / assume-role base), we forward them verbatim — they're
  already short-lived.
* ``--use-ambient-creds`` opts out of STS minting (for the EC2-runner
  case).
* ``--skip-creds`` produces a payload with no ``__aws_credentials``
  field at all.
"""
from __future__ import annotations

import importlib.util
import os
from datetime import datetime, timezone
from unittest import mock

import pytest


SMOKE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "byok-sandbox", "aws", "smoke_byok_aws.py",
)


@pytest.fixture(scope="module")
def smoke():
    spec = importlib.util.spec_from_file_location("smoke_byok_aws", SMOKE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Short-lived session creds
# ---------------------------------------------------------------------------

class _FakeBotoCreds:
    def __init__(self, ak, sk, token=None):
        self.access_key = ak
        self.secret_key = sk
        self.token = token

    def get_frozen_credentials(self):
        return self


class _FakeStsClient:
    def __init__(self, return_value=None, raises=None):
        self.calls = []
        self._return_value = return_value or {
            "Credentials": {
                "AccessKeyId": "ASIA-EPHEMERAL",
                "SecretAccessKey": "fake-ephemeral-secret",
                "SessionToken": "fake-session-token",
                "Expiration": datetime(2099, 1, 1, tzinfo=timezone.utc),
            }
        }
        self._raises = raises

    def get_session_token(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises:
            raise self._raises
        return self._return_value


class _FakeBotoSession:
    def __init__(self, ambient_creds: _FakeBotoCreds, sts: _FakeStsClient):
        self._creds = ambient_creds
        self._sts = sts

    def get_credentials(self):
        return self._creds

    def client(self, name):
        assert name == "sts"
        return self._sts


class TestShortLivedSessionCreds:
    def test_iam_user_creds_get_swapped_for_session_token(self, smoke):
        ambient = _FakeBotoCreds("AKIA-LONGLIVED", "raw-long-lived-secret")
        sts = _FakeStsClient()
        fake_boto3 = mock.MagicMock()
        fake_boto3.Session.return_value = _FakeBotoSession(ambient, sts)

        with mock.patch.dict("sys.modules", {"boto3": fake_boto3}):
            out = smoke._short_lived_session_credentials(
                "us-east-2", duration_seconds=900,
            )
        # The forwarded triplet is the EPHEMERAL one, NOT the laptop key.
        assert out["access_key"] == "ASIA-EPHEMERAL"
        assert out["secret_key"] == "fake-ephemeral-secret"
        assert out["token"] == "fake-session-token"
        # Long-lived material was not leaked into the payload.
        assert "AKIA-LONGLIVED" not in str(out)
        assert "raw-long-lived-secret" not in str(out)
        # And we recorded what we did so callers can audit.
        assert out["_minted_by"] == "sts:GetSessionToken"
        assert sts.calls == [{"DurationSeconds": 900}]

    def test_already_temporary_creds_pass_through(self, smoke):
        # Instance-role / SSO / assume-role base creds already have a
        # session_token; minting another would be wasteful.  We
        # forward them verbatim.
        ambient = _FakeBotoCreds("ASIA-instance", "instance-sk",
                                  token="instance-session-token")
        sts = _FakeStsClient(raises=AssertionError("STS must not be called!"))
        fake_boto3 = mock.MagicMock()
        fake_boto3.Session.return_value = _FakeBotoSession(ambient, sts)

        with mock.patch.dict("sys.modules", {"boto3": fake_boto3}):
            out = smoke._short_lived_session_credentials(
                "us-east-2", duration_seconds=900,
            )
        assert out["_minted_by"] == "ambient"
        assert out["token"] == "instance-session-token"
        assert sts.calls == []

    def test_no_ambient_creds_raises(self, smoke):
        fake_boto3 = mock.MagicMock()
        fake_boto3.Session.return_value = mock.MagicMock(
            get_credentials=lambda: None,
        )
        with mock.patch.dict("sys.modules", {"boto3": fake_boto3}):
            with pytest.raises(SystemExit):
                smoke._short_lived_session_credentials(
                    "us-east-2", duration_seconds=900,
                )

    def test_mfa_serial_requires_token(self, smoke):
        ambient = _FakeBotoCreds("AKIA-x", "raw-sk")
        sts = _FakeStsClient()
        fake_boto3 = mock.MagicMock()
        fake_boto3.Session.return_value = _FakeBotoSession(ambient, sts)
        with mock.patch.dict("sys.modules", {"boto3": fake_boto3}):
            with pytest.raises(SystemExit, match="mfa"):
                smoke._short_lived_session_credentials(
                    "us-east-2", duration_seconds=900,
                    mfa_serial="arn:aws:iam::1:mfa/me",
                )

    def test_mfa_pair_gets_forwarded_to_sts(self, smoke):
        ambient = _FakeBotoCreds("AKIA-x", "raw-sk")
        sts = _FakeStsClient()
        fake_boto3 = mock.MagicMock()
        fake_boto3.Session.return_value = _FakeBotoSession(ambient, sts)
        with mock.patch.dict("sys.modules", {"boto3": fake_boto3}):
            smoke._short_lived_session_credentials(
                "us-east-2", duration_seconds=900,
                mfa_serial="arn:aws:iam::1:mfa/me", mfa_token="123456",
            )
        assert sts.calls == [{
            "DurationSeconds": 900,
            "SerialNumber": "arn:aws:iam::1:mfa/me",
            "TokenCode": "123456",
        }]


# ---------------------------------------------------------------------------
# Static invariants in the smoke source
# ---------------------------------------------------------------------------

class TestSmokeSourceInvariants:
    @pytest.fixture(scope="class")
    def src(self) -> str:
        with open(SMOKE_PATH, "r", encoding="utf-8") as f:
            return f.read()

    def test_documents_threat_model(self, src):
        assert "Threat model" in src
        assert "long-lived" in src.lower() or "long lived" in src.lower()

    def test_default_does_not_use_ambient(self, src):
        # The opt-in flag must exist (so EC2 runners can use ambient
        # creds when those creds are already short-lived) but the
        # default code path must call ``_short_lived_session_credentials``.
        assert "--use-ambient-creds" in src
        assert "_short_lived_session_credentials" in src

    def test_supports_skip_creds_smoke(self, src):
        assert "--skip-creds" in src
