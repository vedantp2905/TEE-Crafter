"""Tests for core/audit.py: hash chain, secret redaction, verify, save/load, TCB substeps."""

import json
import os


from tee_crafter.core.audit import (
    AuditEntry,
    BuildAuditTrail,
    ENCLAVE_TCB_SUBSTEPS,
    _looks_like_secret,
    _sanitize_details,
    sha256_file,
    sha256_hex,
)


class TestSha256:
    def test_hex_string(self):
        digest = sha256_hex("hello")
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_hex_bytes(self):
        digest = sha256_hex(b"hello")
        assert digest == sha256_hex("hello")

    def test_hex_empty(self):
        digest = sha256_hex("")
        assert len(digest) == 64

    def test_hex_deterministic(self):
        assert sha256_hex("test") == sha256_hex("test")

    def test_hex_different_inputs_differ(self):
        assert sha256_hex("a") != sha256_hex("b")

    def test_file_existing(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        digest = sha256_file(str(f))
        assert len(digest) == 64
        assert digest == sha256_hex("hello world")

    def test_file_missing(self):
        assert sha256_file("/nonexistent/path/file.txt") == ""

    def test_file_large(self, tmp_path):
        f = tmp_path / "large.bin"
        data = b"x" * (1 << 17)
        f.write_bytes(data)
        digest = sha256_file(str(f))
        assert len(digest) == 64

    def test_file_empty(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        digest = sha256_file(str(f))
        assert len(digest) == 64


class TestLooksLikeSecret:
    def test_aws_access_key(self):
        assert _looks_like_secret("AKIAIOSFODNN7EXAMPLE") is True

    def test_short_string(self):
        assert _looks_like_secret("abc") is False

    def test_pem_private_key(self):
        assert _looks_like_secret("-----BEGIN RSA PRIVATE KEY-----\ndata") is True

    def test_long_base64_token(self):
        token = "AQo" + "A" * 200
        assert _looks_like_secret(token) is True

    def test_normal_string(self):
        assert _looks_like_secret("us-east-1") is False

    def test_non_string(self):
        assert _looks_like_secret(12345) is False

    def test_empty(self):
        assert _looks_like_secret("") is False

    def test_hash_value_ok(self):
        assert _looks_like_secret("a" * 64) is False


class TestSanitizeDetails:
    def test_redacts_aws_key(self):
        details = {"key": "AKIAIOSFODNN7EXAMPLE"}
        result = _sanitize_details(details)
        assert result["key"] == "[REDACTED]"

    def test_preserves_normal(self):
        details = {"region": "us-east-1", "count": 5}
        result = _sanitize_details(details)
        assert result == details

    def test_nested_dict(self):
        details = {"outer": {"secret": "AKIAIOSFODNN7EXAMPLE"}}
        result = _sanitize_details(details)
        assert result["outer"]["secret"] == "[REDACTED]"

    def test_list_with_secrets(self):
        details = {"tokens": ["safe", "AKIAIOSFODNN7EXAMPLE"]}
        result = _sanitize_details(details)
        assert result["tokens"][0] == "safe"
        assert result["tokens"][1] == "[REDACTED]"


class TestAuditEntry:
    def test_digest_deterministic(self):
        e = AuditEntry(seq=0, timestamp="t", phase="p", step="s", status="pass")
        assert e.digest() == e.digest()

    def test_digest_changes_with_content(self):
        e1 = AuditEntry(seq=0, timestamp="t", phase="p", step="s1", status="pass")
        e2 = AuditEntry(seq=0, timestamp="t", phase="p", step="s2", status="pass")
        assert e1.digest() != e2.digest()

    def test_digest_includes_prev_hash(self):
        e1 = AuditEntry(seq=0, timestamp="t", phase="p", step="s", status="pass", prev_hash="aaa")
        e2 = AuditEntry(seq=0, timestamp="t", phase="p", step="s", status="pass", prev_hash="bbb")
        assert e1.digest() != e2.digest()

    def test_digest_hex_format(self):
        e = AuditEntry(seq=0, timestamp="t", phase="p", step="s", status="pass")
        d = e.digest()
        assert len(d) == 64
        assert all(c in "0123456789abcdef" for c in d)


class TestBuildAuditTrail:
    def test_record_creates_entry(self):
        trail = BuildAuditTrail()
        entry = trail.record("Build", "step1", "pass", key="value")
        assert entry.phase == "Build"
        assert entry.step == "step1"
        assert entry.status == "pass"
        assert entry.details["key"] == "value"

    def test_record_check_emits_ledger_row(self):
        """record_check should atomically write to both trail and ledger."""
        trail = BuildAuditTrail()
        trail.record_check(
            "Phase 1", "BYOK provider resolved", "BYOK-001",
            observed="aws-kms",
        )
        assert trail.ledger.has("BYOK-001")
        row = trail.ledger.get("BYOK-001")
        assert row is not None
        assert row.category == "BYOK"
        # The corresponding trail entry must also exist.
        steps = [e.step for e in trail._entries]
        assert any("BYOK provider resolved" in s for s in steps)

    def test_hash_chain_integrity(self):
        trail = BuildAuditTrail()
        e1 = trail.record("Build", "step1", "pass")
        e2 = trail.record("Build", "step2", "pass")
        assert e2.prev_hash == e1.digest()

    def test_genesis_sentinel(self):
        trail = BuildAuditTrail()
        e = trail.record("Build", "step1", "pass")
        assert e.prev_hash == "0" * 64

    def test_sequential_numbering(self):
        trail = BuildAuditTrail()
        e0 = trail.record("Build", "step1", "pass")
        e1 = trail.record("Build", "step2", "pass")
        e2 = trail.record("Build", "step3", "pass")
        assert e0.seq == 0
        assert e1.seq == 1
        assert e2.seq == 2

    def test_record_file_hash_existing(self, tmp_path):
        trail = BuildAuditTrail()
        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        entry = trail.record_file_hash("Build", "hash_step", str(f))
        assert entry.status == "pass"
        assert entry.details["sha256"] != ""

    def test_record_file_hash_missing(self):
        trail = BuildAuditTrail()
        entry = trail.record_file_hash("Build", "hash_step", "/nonexistent.py")
        assert entry.status == "fail"
        assert entry.details["sha256"] == ""

    def test_record_hash_value(self):
        trail = BuildAuditTrail()
        entry = trail.record_hash_value("Build", "content", "my code", label="app.py")
        assert entry.status == "pass"
        assert entry.details["sha256"] == sha256_hex("my code")

    def test_record_enclave_tcb_substeps(self):
        trail = BuildAuditTrail()
        trail.record_enclave_tcb_substeps("abc123")
        assert len(trail._entries) == len(ENCLAVE_TCB_SUBSTEPS)
        for entry in trail._entries:
            assert entry.details["template_sha256"] == "abc123"
            assert entry.status == "pass"

    def test_record_enclave_runtime_startup(self):
        trail = BuildAuditTrail()
        steps = ["rsa_key_generated", "vsock_server_listening"]
        entry = trail.record_enclave_runtime_startup(steps)
        assert entry.details["step_count"] == 2
        assert entry.details["reported_steps"] == steps

    def test_set_metadata(self):
        trail = BuildAuditTrail()
        trail.set_metadata("0.1.0", "/builds/test")
        assert trail._pipeline_version == "0.1.0"
        assert trail._build_dir == "/builds/test"

    def test_save_json(self, tmp_path):
        trail = BuildAuditTrail()
        trail.set_metadata("0.1.0", str(tmp_path))
        trail.record("Build", "step1", "pass")
        trail.record("Build", "step2", "pass")
        path = trail.save(str(tmp_path))
        assert os.path.isfile(path)
        with open(path) as f:
            doc = json.load(f)
        assert doc["audit_trail_version"] == "1.0"
        # ``set_metadata`` records PC-003 (build_dir writable) and
        # PC-004 (cli version), so a freshly initialised trail
        # already carries 2 audit rows before the test adds its
        # own.  We assert against the body the test produced
        # explicitly so future PC additions don't churn this row.
        assert doc["total_entries"] >= 4
        own_entries = [e for e in doc["entries"] if e["phase"] == "Build"]
        assert len(own_entries) == 2

    def test_save_summary(self, tmp_path):
        trail = BuildAuditTrail()
        trail.record("Build", "step1", "pass")
        trail.record("Deploy", "step2", "fail")
        trail.record("Deploy", "step3", "skip")
        path = trail.save_summary(str(tmp_path))
        assert os.path.isfile(path)
        content = open(path).read()
        assert "PROVENANCE REPORT" in content
        assert "1 passed" in content
        assert "1 failed" in content

    def test_sanitizes_secrets_in_record(self):
        trail = BuildAuditTrail()
        entry = trail.record("Build", "step", "pass", api_key="AKIAIOSFODNN7EXAMPLE")
        assert entry.details["api_key"] == "[REDACTED]"


class TestParseEnclaveStartupReport:
    def test_valid_report(self):
        console = '{"audit": "enclave_startup", "steps": ["rsa_key_generated", "vsock_server_listening"]}'
        result = BuildAuditTrail.parse_enclave_startup_report(console)
        assert result == ["rsa_key_generated", "vsock_server_listening"]

    def test_report_with_noise(self):
        console = "some log output\n" + '{"audit": "enclave_startup", "steps": ["step1"]}' + "\nmore noise"
        result = BuildAuditTrail.parse_enclave_startup_report(console)
        assert result == ["step1"]

    def test_no_report(self):
        assert BuildAuditTrail.parse_enclave_startup_report("just logs") is None

    def test_empty_input(self):
        assert BuildAuditTrail.parse_enclave_startup_report("") is None

    def test_none_input(self):
        assert BuildAuditTrail.parse_enclave_startup_report(None) is None

    def test_invalid_json(self):
        assert BuildAuditTrail.parse_enclave_startup_report("{bad json}") is None

    def test_wrong_audit_type(self):
        assert BuildAuditTrail.parse_enclave_startup_report('{"audit": "other", "steps": []}') is None


class TestVerifyChain:
    def test_valid_chain(self, tmp_path):
        trail = BuildAuditTrail()
        trail.record("Build", "step1", "pass")
        trail.record("Build", "step2", "pass")
        trail.record("Deploy", "step3", "pass")
        path = trail.save(str(tmp_path))
        ok, msg = BuildAuditTrail.verify_chain(path)
        assert ok is True
        assert msg == ""

    def test_tampered_entry(self, tmp_path):
        trail = BuildAuditTrail()
        trail.record("Build", "step1", "pass")
        trail.record("Build", "step2", "pass")
        path = trail.save(str(tmp_path))
        with open(path) as f:
            doc = json.load(f)
        doc["entries"][1]["step"] = "TAMPERED"
        with open(path, "w") as f:
            json.dump(doc, f)
        ok, msg = BuildAuditTrail.verify_chain(path)
        assert ok is False
        assert "Chain broken" in msg or "chain_head_hash mismatch" in msg

    def test_empty_trail(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text(json.dumps({"entries": []}))
        ok, msg = BuildAuditTrail.verify_chain(str(path))
        assert ok is False
        assert "empty" in msg.lower()

    def test_tampered_head_hash(self, tmp_path):
        trail = BuildAuditTrail()
        trail.record("Build", "step1", "pass")
        path = trail.save(str(tmp_path))
        with open(path) as f:
            doc = json.load(f)
        doc["chain_head_hash"] = "0" * 64
        with open(path, "w") as f:
            json.dump(doc, f)
        ok, msg = BuildAuditTrail.verify_chain(path)
        assert ok is False
        assert "mismatch" in msg


class TestEnclaveTCBSubsteps:
    def test_all_substeps_have_required_fields(self):
        for sub in ENCLAVE_TCB_SUBSTEPS:
            assert "id" in sub
            assert "name" in sub
            assert "category" in sub

    def test_categories_valid(self):
        valid = {"startup", "request_attestation", "request_data"}
        for sub in ENCLAVE_TCB_SUBSTEPS:
            assert sub["category"] in valid

    def test_unique_ids(self):
        ids = [sub["id"] for sub in ENCLAVE_TCB_SUBSTEPS]
        assert len(ids) == len(set(ids))

    def test_substep_count(self):
        assert len(ENCLAVE_TCB_SUBSTEPS) >= 10
