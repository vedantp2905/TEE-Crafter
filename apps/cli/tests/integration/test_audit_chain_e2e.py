"""Integration test: full audit trail record -> save -> verify cycle."""

import json
import os


from tee_crafter.core.audit import BuildAuditTrail, ENCLAVE_TCB_SUBSTEPS, sha256_hex


class TestAuditChainEndToEnd:
    def test_full_pipeline_cycle(self, tmp_path):
        trail = BuildAuditTrail()
        trail.set_metadata("0.1.0", str(tmp_path))

        trail.record("Ingestion", "Collect files", "pass", file_count=5)
        trail.record("Ingestion", "Parse entrypoint", "pass", entrypoint="app.py:process")

        trail.record("LLM Generation", "Generate vsock wrapper", "pass",
                      model="gpt-4", attempt=1)
        trail.record("Verification", "Python compile check", "pass")
        trail.record("Verification", "Confinement check", "pass",
                      blockers=0, warnings=0)

        fake_file = tmp_path / "app_vsock.py"
        fake_file.write_text("# generated code")
        trail.record_file_hash("Build", "app_vsock.py hash", str(fake_file))

        trail.record("Build", "Docker image built", "pass")

        trail.record_enclave_tcb_substeps(sha256_hex("template_content"))

        trail.record("Deploy", "Terraform apply", "pass",
                      instance_id="i-abc123", region="us-east-1")
        trail.record("Deploy", "Enclave started", "pass",
                      enclave_cid=16)

        console_output = json.dumps({
            "audit": "enclave_startup",
            "steps": ["rsa_key_generated", "vsock_server_listening"],
        })
        steps = BuildAuditTrail.parse_enclave_startup_report(console_output)
        assert steps is not None
        trail.record_enclave_runtime_startup(steps)

        json_path = trail.save(str(tmp_path))
        txt_path = trail.save_summary(str(tmp_path))

        assert os.path.isfile(json_path)
        assert os.path.isfile(txt_path)

        with open(json_path) as f:
            doc = json.load(f)
        assert doc["pipeline_version"] == "0.1.0"
        assert doc["total_entries"] > 10

        ok, msg = BuildAuditTrail.verify_chain(json_path)
        assert ok is True, f"Chain verification failed: {msg}"

        summary = open(txt_path).read()
        assert "PROVENANCE REPORT" in summary
        assert "passed" in summary

    def test_tamper_detection(self, tmp_path):
        trail = BuildAuditTrail()
        for i in range(5):
            trail.record("Build", f"step_{i}", "pass", index=i)

        path = trail.save(str(tmp_path))
        ok, _ = BuildAuditTrail.verify_chain(path)
        assert ok is True

        with open(path) as f:
            doc = json.load(f)
        doc["entries"][2]["details"]["index"] = 999
        with open(path, "w") as f:
            json.dump(doc, f)

        ok, msg = BuildAuditTrail.verify_chain(path)
        assert ok is False

    def test_secret_never_persisted(self, tmp_path):
        trail = BuildAuditTrail()
        trail.record("Build", "inject creds", "pass",
                      aws_key="AKIAIOSFODNN7EXAMPLE",
                      session_token="AQo" + "x" * 300,
                      private_key="-----BEGIN RSA PRIVATE KEY-----\ndata",
                      safe_value="us-east-1")

        path = trail.save(str(tmp_path))
        content = open(path).read()
        assert "AKIAIOSFODNN7EXAMPLE" not in content
        assert "-----BEGIN RSA PRIVATE KEY-----" not in content
        assert "us-east-1" in content

    def test_enclave_tcb_all_substeps_recorded(self, tmp_path):
        trail = BuildAuditTrail()
        trail.record_enclave_tcb_substeps("hash123")
        path = trail.save(str(tmp_path))
        with open(path) as f:
            doc = json.load(f)
        entry_ids = {e["details"]["substep_id"] for e in doc["entries"]}
        expected_ids = {sub["id"] for sub in ENCLAVE_TCB_SUBSTEPS}
        assert expected_ids == entry_ids

    def test_record_check_round_trips_to_ledger(self, tmp_path):
        """End-to-end: record_check should populate the ledger and
        ledger.save should produce a usable audit_evidence.json."""
        trail = BuildAuditTrail()
        trail.set_metadata("0.1.0", str(tmp_path))
        trail.record_check(
            "Phase 0", "BYOK provider resolved", "BYOK-001",
            observed="aws-kms",
        )
        trail.record_check(
            "Phase 0", "SIEM signing on", "SIEM-006",
            observed=True,
        )
        ledger_paths = trail.ledger.save(str(tmp_path))
        assert os.path.isfile(ledger_paths["json"])
        with open(ledger_paths["json"], "r", encoding="utf-8") as f:
            doc = json.load(f)
        ids = {r["check_id"] for r in doc["rows"]}
        assert "BYOK-001" in ids
        assert "SIEM-006" in ids
        assert doc["totals"].get("pass", 0) >= 2
