"""The verifier's reasoning has to survive the run that produced it.

Every generated client prints its verification chain to stderr and its result to
stdout. Six deploy paths saved stdout and dropped stderr -- after parsing it in
memory for the attestation report, so the information existed and was discarded.
That made a *passing* run harder to audit than a failing one.
"""
from __future__ import annotations

import json

from tee_crafter.cli.deployment.common.client_evidence import (
    STDERR_FILENAME, record_client_evidence_paths, save_client_evidence,
)

REASONING = (
    "binding_mode=hcl_runtime_data_strong\n"
    "nras_nonce_echo=match\n"
    "ak_rooted_in_amd_signed_evidence=true\n"
)


class _Console:
    def __init__(self):
        self.lines = []

    def print(self, text=""):
        self.lines.append(str(text))

    @property
    def text(self):
        return "\n".join(self.lines)


class _Audit:
    def __init__(self):
        self.records = []

    def record(self, phase, step, status, **fields):
        self.records.append({"phase": phase, "step": step,
                             "status": status, **fields})


def test_stderr_is_written_on_success(tmp_path):
    paths = save_client_evidence(
        str(tmp_path), json.dumps({"ok": True}), REASONING)
    assert (tmp_path / STDERR_FILENAME).read_text() == REASONING
    assert paths["stderr"].endswith(STDERR_FILENAME)


def test_stderr_is_written_on_failure_too(tmp_path):
    """A failed verification is when the reasoning matters most, and the console
    panel showing it scrolls away behind journalctl dumps."""
    save_client_evidence(str(tmp_path), "", "measurement mismatch: expected ab…",
                         success=False)
    assert "mismatch" in (tmp_path / STDERR_FILENAME).read_text()


def test_json_stdout_is_pretty_printed_to_client_output_json(tmp_path):
    save_client_evidence(str(tmp_path), '{"a":1}', "")
    body = (tmp_path / "client_output.json").read_text()
    assert json.loads(body) == {"a": 1}
    assert "\n" in body  # indented, not the original one-liner


def test_non_json_stdout_goes_to_the_txt_fallback(tmp_path):
    save_client_evidence(str(tmp_path), "plain text result", "")
    assert (tmp_path / "client_output.txt").read_text() == "plain text result"
    assert not (tmp_path / "client_output.json").exists()


def test_empty_streams_write_nothing(tmp_path):
    paths = save_client_evidence(str(tmp_path), "", "")
    assert list(tmp_path.iterdir()) == []
    assert paths == {"stdout": "", "stderr": ""}


def test_silence_from_the_verifier_is_called_out(tmp_path):
    """No stderr means either the client logged nothing or it was not the client
    this project generates. Either way the operator should hear about it."""
    console = _Console()
    save_client_evidence(str(tmp_path), '{"ok":1}', "", console=console)
    assert "no verification reasoning" in console.text


def test_an_unwritable_build_dir_does_not_raise(tmp_path):
    """This runs after the deploy has already succeeded or failed; it must not
    be the thing that changes the outcome."""
    missing = tmp_path / "does" / "not" / "exist"
    paths = save_client_evidence(str(missing), '{"a":1}', REASONING,
                                 console=_Console())
    assert paths == {"stdout": "", "stderr": ""}


def test_paths_are_bound_into_the_audit_chain(tmp_path):
    audit = _Audit()
    paths = save_client_evidence(str(tmp_path), '{"a":1}', REASONING)
    record_client_evidence_paths(audit, paths)
    assert len(audit.records) == 1
    entry = audit.records[0]
    assert entry["client_stderr"] == STDERR_FILENAME
    assert entry["client_output"] == "client_output.json"


def test_nothing_is_recorded_when_nothing_was_saved():
    audit = _Audit()
    record_client_evidence_paths(audit, {"stdout": "", "stderr": ""})
    assert audit.records == []


def test_no_audit_trail_is_tolerated(tmp_path):
    record_client_evidence_paths(None, {"stdout": "x", "stderr": "y"})


# --------------------------------------------------------------------------
# Every client call site must use the helper
# --------------------------------------------------------------------------

def test_all_client_call_sites_persist_stderr():
    """Guards against the sixth site drifting back to stdout-only.

    The failure this prevents is silent: a path that writes client_output.json
    by hand looks completely correct in review.
    """
    import inspect

    from tee_crafter.cli.deployment.common import (
        azure_bastion_client, client_step, gcp_phase_client,
    )
    from tee_crafter.cli.deployment.sgx import enclave
    from tee_crafter.cli.deployment.snp import aws_service

    for module in (client_step, azure_bastion_client, gcp_phase_client,
                   aws_service, enclave):
        src = inspect.getsource(module)
        if "client_output.json" not in src and "save_client_evidence" not in src:
            continue
        assert "save_client_evidence" in src, (
            f"{module.__name__} writes client output without going through "
            "save_client_evidence, so its stderr is dropped")
        assert 'open(os.path.join(build_dir, "client_output.json")' not in src, (
            f"{module.__name__} still hand-writes client_output.json")
