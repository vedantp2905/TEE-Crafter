"""Both in-TEE release paths must default the audit sink, not just BYOK's.

Found on real GCP hardware (`snp-gcp` and `tdx-gcp`) 2026-08-21.  Every deploy
combining ``--byok gcp-kms`` with ``--secrets-env`` produced an attested,
verified VM whose workload container never ran::

    [tee-crafter-secrets] BYOK DEK released for the app
    sealed .env orchestrator construction failed: ValueError(
      'KeyReleasePolicy.require_signed_audit is set but no audit sink was
       passed to KeyReleaseOrchestrator(audit=...)')
    [tee-crafter-secrets] FATAL sealed .env attested release failed
    [tee-crafter-secrets] refusing to start the workload (fail-closed).

Two call sites onto one orchestrator.  ``bootstrap_byok_release`` defaults
``audit`` to the in-TEE HMAC-chained sink -- with a comment explaining that
without it "every ``--byok`` deployment would fail closed at boot".
``bootstrap_secret_env_release`` passed ``audit=None`` straight through, so
with the shipped policy (``require_signed_audit`` defaults True) it could
never construct.

Everything around it worked, which is why it took hardware to find: the
attestation verified, the DEK was released, the SIEM chain flowed.  Only the
payload was missing.
"""

import inspect
import re

import pytest

from tee_crafter.templates.common import tee_crafter_runtime_bootstrap as boot

RELEASE_FNS = ["bootstrap_byok_release", "bootstrap_secret_env_release"]


def _body(name):
    return inspect.getsource(getattr(boot, name))


class TestBothPathsDefaultTheSink:
    @pytest.mark.parametrize("fn", RELEASE_FNS)
    def test_defaults_audit_when_none(self, fn):
        src = _body(fn)
        assert "if audit is None:" in src, (
            f"{fn} does not default the audit sink, so the orchestrator "
            f"refuses to construct under require_signed_audit")
        assert "_InTeeAuditSink()" in src, f"{fn} defaults to something else"

    @pytest.mark.parametrize("fn", RELEASE_FNS)
    def test_default_precedes_orchestrator_construction(self, fn):
        """Defaulting after the call would be dead code."""
        src = _body(fn)
        assert src.index("if audit is None:") < src.index("_build_orchestrator(")

    @pytest.mark.parametrize("fn", RELEASE_FNS)
    def test_sink_is_passed_through(self, fn):
        """It must reach the orchestrator, not just be assigned."""
        src = _body(fn)
        m = re.search(r"_build_orchestrator\(\s*mods,\s*attestation_provider,\s*audit\s*\)", src)
        assert m, f"{fn} does not hand `audit` to _build_orchestrator"


class TestPolicyStaysStrict:
    """The fix must not be "turn the requirement off".

    ``require_signed_audit`` is the control that makes a release a verifiable
    event.  Defaulting the *sink* keeps it; defaulting the *policy* to False
    would silently drop the audit obligation instead.
    """

    def test_require_signed_audit_still_defaults_true(self):
        from tee_crafter.core.keys.release import KeyReleasePolicy

        assert KeyReleasePolicy().require_signed_audit is True

    def test_orchestrator_still_refuses_without_a_sink(self):
        """The guard that caught this must remain a hard failure."""
        from tee_crafter.core.keys.release import (
            KeyReleaseOrchestrator,
            KeyReleasePolicy,
        )

        class _Adapter:
            pass

        class _Provider:
            def fresh(self, *, purpose, nonce=b""):
                return b"", 0.0, ""

        # The policy has to be otherwise valid, or the measurement-gate check
        # fires first and this asserts nothing about the audit sink.
        policy = KeyReleasePolicy(
            allowed_measurement_sha256=["a" * 64],
            require_signed_audit=True,
        )
        with pytest.raises(ValueError, match="require_signed_audit"):
            KeyReleaseOrchestrator(
                attestation_provider=_Provider(),
                adapters={"x": _Adapter()},
                policy=policy,
                audit=None,
            )

    def test_env_override_is_still_the_documented_escape(self):
        """The knob named in the error message must actually exist."""
        src = inspect.getsource(boot._build_orchestrator)
        assert "TEE_CRAFTER_BYOK_REQUIRE_SIGNED_AUDIT" in src


class TestInTeeSinkShape:
    def test_sink_exposes_record(self):
        """`_record_audit` calls `.record(...)`; a wrong shape fails closed."""
        sink = boot._InTeeAuditSink()
        assert callable(getattr(sink, "record", None))

    def test_sink_failure_propagates(self):
        """A swallowed sink error would make the audit obligation cosmetic."""
        src = inspect.getsource(boot._InTeeAuditSink)
        assert "except" not in src or "raise" in src, (
            "the in-TEE sink must not silently swallow logging failures")
