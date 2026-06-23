"""Tests for the compliance report generator: registry, evidence, engine, frameworks, renderers."""

import json
import os
import re

import pytest

from tee_crafter.core.compliance.registry import (
    ComplianceControl, ControlVerdict, EvidenceItem, FrameworkDefinition,
    FrameworkRegistry, Responsibility, Strength, VerdictStatus,
    build_default_registry,
)
from tee_crafter.core.compliance.frameworks import ALL_FRAMEWORKS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_provenance(tmp_path, *, platform="nitro-aws", flow="container",
                     extra_entries=None):
    """Create a minimal but valid build_provenance.json for testing."""
    from tee_crafter.core.audit import BuildAuditTrail, sha256_hex

    trail = BuildAuditTrail()
    trail.set_metadata("0.1.0-test", str(tmp_path))

    trail.record("Phase 1: Container", "Docker image built", "pass",
                 image_tag="test:latest", image_digest="sha256:abc",
                 container_port=8080, platform=platform)
    trail.record("Phase 2: Packaging", "Nitro multi-stage Dockerfile", "pass",
                 dockerfile_sha256=sha256_hex("FROM test"),
                 entrypoint_sha256=sha256_hex("#!/bin/bash"))
    trail.record("Phase 2: Packaging", "EIF build (nitro-cli build-enclave)", "pass",
                 eif_sha256="eif123", PCR0="pcr0val", PCR1="pcr1val",
                 PCR2="pcr2val", platform=platform)
    trail.record("Phase 2: Packaging", "Client script rendered with PCRs", "pass",
                 client_py_sha256=sha256_hex("client"), root_ca_sha256="",
                 pcr_values_injected=True)
    trail.record("Phase 3: IaC Generation", "Terraform config generated", "pass",
                 main_tf_sha256=sha256_hex("terraform"),
                 kms_policy_pcr_bound=True,
                 security_group_https_only=True,
                 vpc_endpoint_for_kms=True,
                 no_ssh_ingress=True)
    trail.record("Phase 3: IaC Generation", "Terraform validate", "pass")

    if extra_entries:
        for e in extra_entries:
            trail.record(**e)

    path = trail.save(str(tmp_path))
    return path


def _write_ledger(tmp_path, *, verdict="pass", check_ids=None):
    """Write an ``audit_evidence.json`` next to the provenance file.

    Evidence only counts towards control coverage when an audit check proves
    it, so tests that want a non-empty verdict need a ledger to point at.
    """
    from tee_crafter.core.audit import build_layout as layout
    from tee_crafter.core.compliance.evidence import _EVIDENCE_CHECK_BACKING

    if check_ids is None:
        check_ids = sorted({
            cid for cids in _EVIDENCE_CHECK_BACKING.values() for cid in cids
        })
    doc = {
        "ledger_version": "1.0",
        "rows": [{"check_id": cid, "verdict": verdict} for cid in check_ids],
    }
    ledger_path = os.path.join(layout.audit_dir(str(tmp_path)),
                               "audit_evidence.json")
    os.makedirs(os.path.dirname(ledger_path), exist_ok=True)
    with open(ledger_path, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return ledger_path


# Identifier shapes taken from each standard.  An invented identifier almost
# always breaks the shape of the scheme it claims to belong to, so this is the
# cheapest guard against shipping one.
_CONTROL_ID_PATTERNS = {
    # 45 CFR 164.310 / 164.312, e.g. 164.312(a)(2)(iv)
    "hipaa": r"^164\.31[02]\([a-e]\)(\(\d\))?(\((?:i|ii|iii|iv|v)\))?$",
    # AICPA TSC, e.g. CC6.1 / PI1.1
    "soc2": r"^(CC|PI|A|C|P)\d\.\d$",
    "pci_dss": r"^Req \d{1,2}\.\d{1,2}$",
    "gdpr": r"^Art \d{1,2}(\(\d\))?(\([a-z]\))?$",
    "ccpa": r"^1798\.\d{3}(\([a-z]\))?(\(\d{1,2}\))?(\([A-Z]\))?$",
    # NIST 800-53 Rev 5, e.g. SC-8 / AC-2(1)
    "nist_800_53": r"^[A-Z]{2}-\d+(\(\d+\))?$",
    # NIST CSF 2.0 subcategories, e.g. PR.AA-01
    "nist_csf": r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$",
    # ISO/IEC 27001:2022 Annex A, e.g. A.8.24
    "iso_27001": r"^A\.\d+\.\d+$",
    "iso_27701": r"^\d+\.\d+\.\d+$",
    "hitrust": r"^\d{2}\.[a-z]{1,2}$",
    # CSA CCM v4.0, e.g. CEK-03
    "csa_ccm": r"^[A-Z&]{3}-\d{2}$",
    # 16 CFR 314.4, e.g. 314.4(c)(3)
    "glba": r"^314\.4\([a-j]\)(\(\d\))?$",
    "nis2": r"^Art \d{1,2}(\(\d\))?(\([a-j]\))?$",
    "eu_ai_act": r"^Art \d{1,2}(\.\d)?$",
}

# CSF 2.0 category identifiers (NIST CSF 2.0 Core, Table 1).  CSF 1.1
# categories such as PR.AC and PR.IP were withdrawn and must not appear.
_CSF_2_0_CATEGORIES = {
    "GV.OC", "GV.RM", "GV.RR", "GV.PO", "GV.OV", "GV.SC",
    "ID.AM", "ID.RA", "ID.IM",
    "PR.AA", "PR.AT", "PR.DS", "PR.PS", "PR.IR",
    "DE.CM", "DE.AE",
    "RS.MA", "RS.AN", "RS.CO", "RS.MI",
    "RC.RP", "RC.CO",
}

# CSA CCM v4.0 domain identifiers.
_CCM_V4_DOMAINS = {
    "A&A", "AIS", "BCR", "CCC", "CEK", "DCS", "DSP", "GRC", "HRS", "IAM",
    "IPY", "IVS", "LOG", "SEF", "STA", "TVM", "UEM",
}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestFrameworkRegistry:
    def test_build_default_has_14_frameworks(self):
        reg = build_default_registry()
        assert len(reg) == 14

    def test_all_framework_ids_unique(self):
        ids = [fw.framework_id for fw in ALL_FRAMEWORKS]
        assert len(ids) == len(set(ids))

    def test_register_and_get(self):
        reg = FrameworkRegistry()
        fw = FrameworkDefinition(
            framework_id="test", name="Test", version="1.0",
            tier="test", description="test", controls=[],
        )
        reg.register(fw)
        assert reg.get("test") is fw
        assert reg.get("nonexistent") is None

    def test_ids_and_all(self):
        reg = build_default_registry()
        assert set(reg.ids()) == {fw.framework_id for fw in ALL_FRAMEWORKS}
        assert len(reg.all()) == 14


# ---------------------------------------------------------------------------
# Framework Definitions (all 14)
# ---------------------------------------------------------------------------

class TestFrameworkDefinitions:
    @pytest.mark.parametrize("fw", ALL_FRAMEWORKS, ids=lambda f: f.framework_id)
    def test_framework_has_controls(self, fw):
        assert len(fw.controls) >= 3, f"{fw.framework_id} has too few controls"

    @pytest.mark.parametrize("fw", ALL_FRAMEWORKS, ids=lambda f: f.framework_id)
    def test_controls_have_required_fields(self, fw):
        for c in fw.controls:
            assert c.control_id, f"Missing control_id in {fw.framework_id}"
            assert c.title, f"Missing title for {c.control_id}"
            assert c.description, f"Missing description for {c.control_id}"
            assert c.section, f"Missing section for {c.control_id}"
            assert isinstance(c.responsibility, Responsibility)

    @pytest.mark.parametrize("fw", ALL_FRAMEWORKS, ids=lambda f: f.framework_id)
    def test_control_ids_match_their_standards_identifier_scheme(self, fw):
        """Every control_id must look like an identifier from its standard.

        This is the guard that would have caught the invented identifiers
        (``FedRAMP SC-8``, ``AC.L2-b.1.D``, ``ICT-RM-1``): each of them breaks
        the shape of the scheme it claims to belong to.
        """
        pattern = _CONTROL_ID_PATTERNS.get(fw.framework_id)
        assert pattern, (
            f"{fw.framework_id} has no control_id pattern. Add one before "
            f"shipping the framework -- an unpatterned framework is how "
            f"invented identifiers get in."
        )
        for c in fw.controls:
            assert re.match(pattern, c.control_id), (
                f"{fw.framework_id}/{c.control_id} does not match the "
                f"{fw.framework_id} identifier pattern {pattern}"
            )

    def test_nist_csf_uses_only_csf_2_0_categories(self):
        """CSF 1.1 categories (PR.AC, PR.IP, ...) were withdrawn in CSF 2.0."""
        fw = next(f for f in ALL_FRAMEWORKS if f.framework_id == "nist_csf")
        for c in fw.controls:
            category = c.control_id.split("-")[0]
            assert category in _CSF_2_0_CATEGORIES, (
                f"{c.control_id} uses {category}, which is not a CSF 2.0 "
                f"category (CSF 1.1 categories were withdrawn)"
            )

    def test_csa_ccm_uses_only_v4_domains(self):
        fw = next(f for f in ALL_FRAMEWORKS if f.framework_id == "csa_ccm")
        assert fw.version == "v4.0"
        for c in fw.controls:
            domain = c.control_id.split("-")[0]
            assert domain in _CCM_V4_DOMAINS, (
                f"{c.control_id} uses domain {domain}, which is not a CCM "
                f"v4.0 domain"
            )

    def test_deleted_frameworks_stay_deleted(self):
        """The four frameworks whose identifiers were fabricated are gone.

        Reinstating any of them needs the real control catalogue, not a
        reconstruction -- so failing here is a prompt to check the source, not
        to edit the expected set.
        """
        ids = {fw.framework_id for fw in ALL_FRAMEWORKS}
        assert ids.isdisjoint({"fedramp", "dora", "cmmc_2", "iso_42001"})

    @pytest.mark.parametrize("fw", ALL_FRAMEWORKS, ids=lambda f: f.framework_id)
    def test_control_ids_unique_within_framework(self, fw):
        ids = [c.control_id for c in fw.controls]
        assert len(ids) == len(set(ids)), f"Duplicate IDs in {fw.framework_id}"

    @pytest.mark.parametrize("fw", ALL_FRAMEWORKS, ids=lambda f: f.framework_id)
    def test_product_controls_have_evidence_keys(self, fw):
        for c in fw.controls:
            if c.responsibility == Responsibility.PRODUCT:
                assert c.evidence_keys, (
                    f"{fw.framework_id}/{c.control_id} is product_evidence "
                    f"but has no evidence_keys"
                )

    @pytest.mark.parametrize("fw", ALL_FRAMEWORKS, ids=lambda f: f.framework_id)
    def test_customer_controls_have_no_evidence_keys(self, fw):
        for c in fw.controls:
            if c.responsibility == Responsibility.CUSTOMER:
                assert not c.evidence_keys, (
                    f"{fw.framework_id}/{c.control_id} is customer_responsibility "
                    f"but has evidence_keys"
                )

    @pytest.mark.parametrize("fw", ALL_FRAMEWORKS, ids=lambda f: f.framework_id)
    def test_framework_metadata(self, fw):
        assert fw.name
        assert fw.version
        assert fw.tier in ("core_regulated", "security_framework", "industry_specific")

    def test_total_framework_count(self):
        assert len(ALL_FRAMEWORKS) == 14

    @pytest.mark.parametrize("fw", ALL_FRAMEWORKS, ids=lambda f: f.framework_id)
    def test_to_dict(self, fw):
        d = fw.to_dict()
        assert d["framework_id"] == fw.framework_id
        assert d["control_count"] == len(fw.controls)


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

class TestDataModel:
    def test_evidence_item_to_dict(self):
        e = EvidenceItem(
            key="test", title="Test", description="d", source="s",
            artifacts={"a": 1}, strength=Strength.STRONG,
        )
        d = e.to_dict()
        assert d["key"] == "test"
        assert d["strength"] == "strong"
        assert d["artifacts"] == {"a": 1}

    def test_control_verdict_to_dict(self):
        ctrl = ComplianceControl(
            control_id="C1", title="T", description="D",
            evidence_keys=["k1"], section="S",
            responsibility=Responsibility.PRODUCT,
        )
        v = ControlVerdict(
            control=ctrl, status=VerdictStatus.SATISFIED,
            responsibility=Responsibility.PRODUCT,
            evidence=[], notes="ok",
        )
        d = v.to_dict()
        assert d["status"] == "satisfied"
        assert d["control_id"] == "C1"

    def test_responsibility_values(self):
        assert Responsibility.PRODUCT.value == "product_evidence"
        assert Responsibility.CUSTOMER.value == "customer_responsibility"
        assert Responsibility.SHARED.value == "shared"

    def test_verdict_status_values(self):
        assert VerdictStatus.SATISFIED.value == "satisfied"
        assert VerdictStatus.PARTIAL.value == "partial"
        assert VerdictStatus.GAP.value == "gap"
        assert VerdictStatus.CUSTOMER_RESPONSIBILITY.value == "customer_responsibility"


# ---------------------------------------------------------------------------
# Evidence Collector
# ---------------------------------------------------------------------------

class TestEvidenceCollector:
    def test_collects_all_15_categories(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        keys = {e.key for e in items}
        expected_always = {
            "tee_hardware_isolation", "ratls_attestation",
            "encryption_in_transit", "encryption_at_rest",
            "zero_ingress_network", "systemd_sandboxing",
            "hash_chain_integrity", "ed25519_signature",
            "supply_chain_controls", "ephemeral_keys",
            "build_reproducibility", "access_control",
        }
        assert expected_always.issubset(keys), f"Missing: {expected_always - keys}"

    def test_detects_platform(self, tmp_path):
        path = _make_provenance(tmp_path, platform="snp-azure")
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        assert collector.platform == "snp-azure"
        assert collector.cloud == "azure"

    def test_detects_flow(self, tmp_path):
        path = _make_provenance(tmp_path, flow="container")
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        assert collector.flow == "container"

    def test_non_container_provenance_is_unknown_flow(self, tmp_path):
        """The product is container-only; provenance without a container
        packaging entry is reported as ``unknown`` (no legacy LLM flow)."""
        from tee_crafter.core.audit import BuildAuditTrail

        trail = BuildAuditTrail()
        trail.set_metadata("0.1.0-test", str(tmp_path))
        trail.record("Phase 3: IaC Generation", "Terraform config generated", "pass")
        path = trail.save(str(tmp_path))

        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        assert collector.flow == "unknown"

    def test_docker_hardening_for_container_flow(self, tmp_path):
        path = _make_provenance(tmp_path, platform="snp-aws")
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        docker = [e for e in items if e.key == "docker_hardening"]
        assert len(docker) == 1
        assert docker[0].artifacts.get("cap_drop") == "ALL"

    def test_no_docker_hardening_without_container_packaging(self, tmp_path):
        """Provenance with no container packaging entry yields no
        docker_hardening evidence (flow is unknown, not container)."""
        from tee_crafter.core.audit import BuildAuditTrail

        trail = BuildAuditTrail()
        trail.set_metadata("0.1.0-test", str(tmp_path))
        trail.record("Phase 3: IaC Generation", "Terraform config generated", "pass")
        path = trail.save(str(tmp_path))

        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        assert collector.flow == "unknown"
        items = collector.collect_all()
        docker = [e for e in items if e.key == "docker_hardening"]
        assert len(docker) == 0

    def test_hash_chain_valid(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        chain = next(e for e in items if e.key == "hash_chain_integrity")
        assert chain.artifacts["chain_valid"] is True
        # The chain verifies, but with no audit ledger PC-008/PROV-005 never
        # ran, so the claim is capped and does not count as coverage.
        assert chain.strength == Strength.MODERATE
        assert chain.verified is False
        assert chain.artifacts["unproven_checks"] == ["PC-008", "PROV-005"]

    def test_seccomp_claim_follows_the_staged_profile(self, tmp_path, monkeypatch):
        """The ``seccomp`` claim must track the profile file, not a constant.

        The profile was missing from the tree entirely while this collector
        still reported ``"seccomp": "custom"``.
        """
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        path = _make_provenance(tmp_path, platform="snp-aws")

        docker = next(e for e in EvidenceCollector(path).collect_all()
                      if e.key == "docker_hardening")
        assert docker.artifacts["seccomp"] == "custom"
        assert docker.artifacts["seccomp_profile_staged"] is True
        assert docker.artifacts["seccomp_default_deny"] is True
        # ``syscalls`` is a list of rule groups; the reported count must be
        # the number of allowlisted syscall *names*, not the group count,
        # or an auditor reads "6 syscalls" for a ~300-syscall allowlist.
        assert docker.artifacts["seccomp_syscall_rules"] > (
            docker.artifacts["seccomp_rule_groups"])
        assert "custom seccomp profile" in docker.description

        collector = EvidenceCollector(path)
        monkeypatch.setattr(
            collector, "_seccomp_profile",
            lambda: {"seccomp": "docker-default", "seccomp_profile_staged": False},
        )
        docker = next(e for e in collector.collect_all()
                      if e.key == "docker_hardening")
        assert docker.artifacts["seccomp"] == "docker-default"
        assert "no custom profile is staged" in docker.description
        assert docker.strength == Strength.INFORMATIONAL

    def test_batch_output_bundle_is_not_claimed_encrypted_or_signed(self, tmp_path):
        """The capture script tars, sha256sums and chmod 0644s -- nothing more.

        Every field here is read out of
        ``scripts/common/tee_crafter_capture_container.sh`` by
        ``_batch_bundle_facts``, so this test is really asserting that the
        evidence still matches the script that produces the bundle.
        """
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        path = _make_provenance(tmp_path)
        ev = next(e for e in EvidenceCollector(path).collect_all()
                  if e.key == "output_schema_validation")
        assert ev.artifacts["capture_script_staged"] is True
        assert ev.artifacts["capture"] == "plain_tar_gz"
        assert ev.artifacts["integrity"] == "sha256_sidecar"
        assert ev.artifacts["bundle_encrypted"] is False
        assert ev.artifacts["bundle_signed"] is False
        assert ev.artifacts["bundle_size_capped"] is False
        assert ev.artifacts["bundle_mode"] == "0644"
        assert "NOT encrypted, NOT signed, NOT size-capped" in ev.description
        assert "sha-256" in ev.description.lower()
        assert "encrypted_signed_bundle" not in ev.artifacts.values()

    def test_batch_bundle_claims_track_the_capture_script(self, tmp_path,
                                                          monkeypatch):
        """If the script gains encryption/signing, the claim must follow it.

        The point of deriving these from the script is that the evidence
        cannot silently go stale.  Feed the collector a script that DOES
        encrypt and sign and check the prose and artifacts both flip.
        """
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        fake = tmp_path / "capture.sh"
        fake.write_text(
            'tar czf "$bundle" .\n'
            'sha256sum "$bundle"\n'
            'openssl enc -aes-256-gcm -in "$bundle"\n'
            'cosign sign --key k "$bundle"\n'
            'chmod 0600 "$bundle"\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(
            EvidenceCollector, "_capture_script_path", lambda self: str(fake),
        )
        path = _make_provenance(tmp_path)
        ev = next(e for e in EvidenceCollector(path).collect_all()
                  if e.key == "output_schema_validation")
        assert ev.artifacts["bundle_encrypted"] is True
        assert ev.artifacts["bundle_signed"] is True
        assert ev.artifacts["bundle_mode"] == "0600"
        assert "encrypted, signed" in ev.description
        assert "NOT size-capped" in ev.description

    def test_batch_bundle_claims_nothing_when_script_is_missing(
            self, tmp_path, monkeypatch):
        """No producer to read -> no claim about the bundle at all."""
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        monkeypatch.setattr(
            EvidenceCollector, "_capture_script_path",
            lambda self: str(tmp_path / "does-not-exist.sh"),
        )
        path = _make_provenance(tmp_path)
        ev = next(e for e in EvidenceCollector(path).collect_all()
                  if e.key == "output_schema_validation")
        assert ev.artifacts["capture_script_staged"] is False
        assert "bundle_encrypted" not in ev.artifacts
        assert "not present in this installation" in ev.description

    def test_evidence_item_fields(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        for item in items:
            assert item.key
            assert item.title
            assert item.description
            assert item.source
            assert isinstance(item.strength, Strength)


# ---------------------------------------------------------------------------
# Compliance Engine
# ---------------------------------------------------------------------------

class TestComplianceEngine:
    def test_evaluate_all_produces_all_frameworks(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        results = engine.evaluate_all()
        assert len(results) == 14

    def test_evaluate_selected_frameworks(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path,
                                  framework_ids=["hipaa", "soc2"])
        results = engine.evaluate_all()
        assert set(results.keys()) == {"hipaa", "soc2"}

    def test_customer_controls_get_customer_status(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        results = engine.evaluate_all()
        for fw_id, verdicts in results.items():
            for v in verdicts:
                if v.control.responsibility == Responsibility.CUSTOMER:
                    assert v.status == VerdictStatus.CUSTOMER_RESPONSIBILITY

    def test_product_controls_have_evidence(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        results = engine.evaluate_all()
        for fw_id, verdicts in results.items():
            for v in verdicts:
                if v.status == VerdictStatus.SATISFIED:
                    assert len(v.evidence) > 0

    def test_hipaa_product_controls_are_not_satisfied_without_a_ledger(self, tmp_path):
        """Staged artifacts alone must not satisfy a HIPAA safeguard.

        This test used to assert the opposite, which is what let a provenance
        file with no audit ledger certify five 45 CFR 164.312 safeguards.
        Nothing here has been checked by an audit check, so nothing is proven.
        """
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path,
                                  framework_ids=["hipaa"])
        results = engine.evaluate_all()
        hipaa = results["hipaa"]
        for v in hipaa:
            if v.control.responsibility == Responsibility.PRODUCT:
                assert v.status != VerdictStatus.SATISFIED, (
                    f"HIPAA {v.control.control_id} claims satisfied with no "
                    f"audit ledger backing it: {v.notes}"
                )

    def test_hipaa_controls_satisfied_once_the_ledger_proves_them(self, tmp_path):
        """SATISFIED is reachable, but only via passing audit checks."""
        path = _make_provenance(tmp_path)
        _write_ledger(tmp_path, verdict="pass")

        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path,
                                  framework_ids=["hipaa"])
        results = engine.evaluate_all()
        satisfied = [v for v in results["hipaa"]
                     if v.status == VerdictStatus.SATISFIED]
        assert satisfied, "no HIPAA control satisfied even with an all-pass ledger"
        for v in satisfied:
            assert v.evidence
            assert all(e.verified for e in v.evidence)
            assert all(e.strength == Strength.STRONG for e in v.evidence)

    def test_failing_ledger_check_blocks_satisfied(self, tmp_path):
        path = _make_provenance(tmp_path)
        _write_ledger(tmp_path, verdict="fail")

        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        results = engine.evaluate_all()
        for fw_id, verdicts in results.items():
            for v in verdicts:
                assert v.status != VerdictStatus.SATISFIED, (
                    f"{fw_id}/{v.control.control_id} satisfied despite every "
                    f"backing audit check failing"
                )

    def test_not_evaluated_ledger_check_does_not_count_as_coverage(self, tmp_path):
        """A ``not_evaluated`` row is absence of evidence, not evidence."""
        path = _make_provenance(tmp_path)
        _write_ledger(tmp_path, verdict="not_evaluated")

        from tee_crafter.core.compliance.evidence import EvidenceCollector
        items = EvidenceCollector(path).collect_all()
        assert items
        assert not any(e.verified for e in items)

        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        data = engine._build_report_data(engine.evaluate_all())
        assert data["summary"]["by_status"]["satisfied"] == 0

    def test_one_entry_provenance_satisfies_nothing(self, tmp_path):
        """Acceptance test for the 50%-coverage bug.

        A provenance file with a single "Docker image built" entry used to
        yield 68 satisfied controls, 0 gaps and 86.2% overall coverage,
        including five HIPAA 164.312 safeguards.
        """
        from tee_crafter.core.audit import BuildAuditTrail
        trail = BuildAuditTrail()
        trail.set_metadata("0.1.0-test", str(tmp_path))
        trail.record("Phase 1: Container", "Docker image built", "pass")
        path = trail.save(str(tmp_path))

        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        data = engine._build_report_data(engine.evaluate_all())

        assert data["summary"]["by_status"]["satisfied"] == 0
        assert data["summary"]["by_status"]["gap"] > 0
        assert data["summary"]["product_coverage_pct"] == 0.0

        hipaa = engine.evaluate_framework(engine._registry.get("hipaa"))
        assert not [v for v in hipaa if v.status == VerdictStatus.SATISFIED]

    def test_report_data_structure(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        results = engine.evaluate_all()
        data = engine._build_report_data(results)
        assert data["schema_version"] == "1.0"
        assert "report_id" in data
        assert "generated_at" in data
        assert "provenance" in data
        assert "deployment" in data
        assert "summary" in data
        assert "frameworks" in data
        assert "evidence_inventory" in data
        assert data["summary"]["frameworks_evaluated"] == 14
        assert data["summary"]["total_controls"] == 110

    def test_report_control_counts_match_the_framework_modules(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        data = engine._build_report_data(engine.evaluate_all())

        by_id = {fw.framework_id: fw for fw in ALL_FRAMEWORKS}
        for fw_id, fw_data in data["frameworks"].items():
            expected = len(by_id[fw_id].controls)
            assert fw_data["controls_evaluated"] == expected
            assert len(fw_data["controls"]) == expected
            tally = (fw_data["satisfied"] + fw_data["partial"] + fw_data["gap"]
                     + fw_data["not_applicable"] + fw_data["customer_responsibility"])
            assert tally == expected, f"{fw_id} status tally {tally} != {expected}"
        assert data["summary"]["total_controls"] == sum(
            len(fw.controls) for fw in ALL_FRAMEWORKS)

    def test_verdict_notes_not_empty(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        results = engine.evaluate_all()
        for fw_id, verdicts in results.items():
            for v in verdicts:
                assert v.notes, f"{fw_id}/{v.control.control_id} has empty notes"


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

class TestRenderers:
    def test_json_renderer(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        compliance_dir = engine.generate_report(str(tmp_path), formats=["json"])

        assert os.path.isdir(compliance_dir)
        agg = os.path.join(compliance_dir, "compliance_report.json")
        assert os.path.isfile(agg)
        with open(agg) as f:
            data = json.load(f)
        assert data["schema_version"] == "1.0"
        assert len(data["frameworks"]) == 14

        fw_dir = os.path.join(compliance_dir, "frameworks")
        assert os.path.isdir(fw_dir)
        for fw_id in data["frameworks"]:
            fw_path = os.path.join(fw_dir, f"{fw_id}.json")
            assert os.path.isfile(fw_path), f"Missing {fw_path}"

    def test_markdown_renderer(self, tmp_path):
        path = _make_provenance(tmp_path)
        _write_ledger(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        compliance_dir = engine.generate_report(str(tmp_path), formats=["md"])

        md_path = os.path.join(compliance_dir, "compliance_report.md")
        assert os.path.isfile(md_path)
        content = open(md_path).read()
        assert "TEE-Crafter Compliance Report" in content
        assert "HIPAA" in content
        assert "PASS" in content or "PARTIAL" in content

    def test_html_renderer(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        compliance_dir = engine.generate_report(str(tmp_path), formats=["html"])

        html_path = os.path.join(compliance_dir, "compliance_report.html")
        assert os.path.isfile(html_path)
        content = open(html_path).read()
        assert "<!DOCTYPE html>" in content
        assert "TEE-Crafter" in content

    def test_all_formats(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        compliance_dir = engine.generate_report(str(tmp_path))

        assert os.path.isfile(os.path.join(compliance_dir, "compliance_report.json"))
        assert os.path.isfile(os.path.join(compliance_dir, "compliance_report.md"))
        assert os.path.isfile(os.path.join(compliance_dir, "compliance_report.html"))


# ---------------------------------------------------------------------------
# Integration: full pipeline
# ---------------------------------------------------------------------------

class TestComplianceIntegration:
    def test_full_pipeline_cycle(self, tmp_path):
        """Build audit trail -> save -> compliance reports -> verify."""
        from tee_crafter.core.audit import BuildAuditTrail

        trail = BuildAuditTrail()
        trail.set_metadata("0.1.0", str(tmp_path))
        trail.record("Phase 1: Container", "Docker image built", "pass",
                     image_tag="app:latest", platform="nitro-aws")
        trail.record("Phase 2: Packaging", "EIF build (nitro-cli build-enclave)", "pass",
                     eif_sha256="abc", PCR0="pcr0", PCR1="pcr1", PCR2="pcr2",
                     platform="nitro-aws")
        trail.record("Phase 3: IaC Generation", "Terraform config generated", "pass",
                     main_tf_sha256="tf123", kms_policy_pcr_bound=True,
                     security_group_https_only=True, vpc_endpoint_for_kms=True,
                     no_ssh_ingress=True)

        json_path = trail.save(str(tmp_path))
        assert os.path.isfile(json_path)

        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=json_path)
        compliance_dir = engine.generate_report(str(tmp_path))

        assert os.path.isdir(compliance_dir)
        assert os.path.isdir(os.path.join(compliance_dir, "frameworks"))

        with open(os.path.join(compliance_dir, "compliance_report.json")) as f:
            report = json.load(f)

        assert report["schema_version"] == "1.0"
        assert report["summary"]["frameworks_evaluated"] == 14
        assert report["summary"]["total_controls"] == 110
        assert report["provenance"]["chain_valid"] is True
        assert report["deployment"]["tee_platform"] == "nitro-aws"

        fw_dir = os.path.join(compliance_dir, "frameworks")
        for fw_id in report["frameworks"]:
            assert os.path.isfile(os.path.join(fw_dir, f"{fw_id}.json"))

    def test_compliance_dir_structure(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        compliance_dir = engine.generate_report(str(tmp_path))

        expected_files = [
            "compliance_report.json",
            "compliance_report.md",
            "compliance_report.html",
        ]
        for f in expected_files:
            assert os.path.isfile(os.path.join(compliance_dir, f))

        expected_fw_files = [
            "hipaa.json", "soc2.json", "pci_dss.json", "gdpr.json",
            "ccpa.json", "nist_800_53.json", "nist_csf.json",
            "iso_27001.json", "iso_27701.json", "hitrust.json",
            "csa_ccm.json", "glba.json", "nis2.json", "eu_ai_act.json",
        ]
        fw_dir = os.path.join(compliance_dir, "frameworks")
        for f in expected_fw_files:
            assert os.path.isfile(os.path.join(fw_dir, f)), f"Missing {f}"

    def test_json_schema_stable_fields(self, tmp_path):
        """Verify the JSON schema has all fields needed for dashboard upload."""
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        compliance_dir = engine.generate_report(str(tmp_path), formats=["json"])

        with open(os.path.join(compliance_dir, "compliance_report.json")) as f:
            data = json.load(f)

        assert isinstance(data["report_id"], str)
        assert len(data["report_id"]) == 64
        assert "T" in data["generated_at"]
        assert data["generator_version"]

        prov = data["provenance"]
        assert "chain_head_hash" in prov
        assert "chain_valid" in prov
        assert "signature_valid" in prov
        assert "total_entries" in prov

        dep = data["deployment"]
        assert "tee_platform" in dep
        assert "flow" in dep
        assert "cloud" in dep

        summ = data["summary"]
        assert "by_status" in summ
        assert "product_coverage_pct" in summ
        assert "overall_coverage_pct" in summ

        assert isinstance(data["evidence_inventory"], list)
        for ei in data["evidence_inventory"]:
            assert "key" in ei
            assert "collected" in ei
            assert "strength" in ei



# ---------------------------------------------------------------------------
# Merged from test_near_term_features.py
# ---------------------------------------------------------------------------

"""Tests for near-term compliance features: audit logger, attestation monitor, vuln scanner."""

import sys
import time

import pytest

# Ensure templates/common is importable for the runtime modules
_COMMON_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "tee_crafter", "templates", "common"
)
sys.path.insert(0, os.path.abspath(_COMMON_DIR))


# ---------------------------------------------------------------------------
# Runtime Audit Logger
# ---------------------------------------------------------------------------

class TestAuditLogger:

    def _reset_audit_state(self, aud, tmp_path, monkeypatch):
        """AUD-3: reset module-level state so each test starts from a fresh
        chain.  The module now emits a genesis entry lazily on first write,
        keyed by an in-memory HMAC key.  Tests need to reset ``_GENESIS_WRITTEN``
        alongside the hash/seq so a new genesis is emitted for the new log file.
        """
        monkeypatch.setattr(aud, "_LOG_DIR", str(tmp_path))
        monkeypatch.setattr(aud, "_LOG_FILE", str(tmp_path / "runtime_audit.jsonl"))
        monkeypatch.setattr(aud, "_prev_hash", "0" * 64)
        monkeypatch.setattr(aud, "_entry_seq", 0)
        monkeypatch.setattr(aud, "_GENESIS_WRITTEN", False)

    def test_log_request_creates_file(self, tmp_path, monkeypatch):
        import tee_crafter_audit_logger as aud
        self._reset_audit_state(aud, tmp_path, monkeypatch)

        aud.log_request(
            request_bytes=b'{"hello":"world"}',
            response_bytes=b'{"result":42}',
            action="data",
            status="ok",
            latency_ms=12.5,
        )

        log_file = tmp_path / "runtime_audit.jsonl"
        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        # AUD-3: first line is the genesis entry, second is the actual event
        assert len(lines) == 2
        genesis = json.loads(lines[0])
        assert genesis["action"] == "_genesis"
        assert genesis["chain_key_commitment"] == aud.get_chain_key_commitment()
        entry = json.loads(lines[1])
        assert entry["seq"] == 1
        assert entry["action"] == "data"
        assert entry["status"] == "ok"
        assert entry["request_size"] == len(b'{"hello":"world"}')
        assert entry["response_size"] == len(b'{"result":42}')
        assert entry["latency_ms"] == 12.5
        assert "request_hash" in entry
        assert "response_hash" in entry
        assert "entry_hash" in entry
        assert "prev_hash" in entry
        assert entry["prev_hash"] == genesis["entry_hash"]

    def test_hash_chain_integrity(self, tmp_path, monkeypatch):
        import tee_crafter_audit_logger as aud
        self._reset_audit_state(aud, tmp_path, monkeypatch)
        log_path = str(tmp_path / "runtime_audit.jsonl")

        for i in range(5):
            aud.log_request(
                request_bytes=f"req-{i}".encode(),
                response_bytes=f"resp-{i}".encode(),
                latency_ms=float(i),
            )

        ok, msg = aud.verify_chain(log_path, chain_key=aud._CHAIN_KEY)
        assert ok, msg
        # 5 events + 1 genesis
        assert "6 entries" in msg

    def test_chain_tamper_detection(self, tmp_path, monkeypatch):
        import tee_crafter_audit_logger as aud
        self._reset_audit_state(aud, tmp_path, monkeypatch)
        log_path = str(tmp_path / "runtime_audit.jsonl")

        for i in range(3):
            aud.log_request(
                request_bytes=f"req-{i}".encode(),
                response_bytes=f"resp-{i}".encode(),
            )

        lines = (tmp_path / "runtime_audit.jsonl").read_text().strip().splitlines()
        # lines[0] = genesis, lines[1..3] = user events; tamper with
        # lines[2] (the second user event) to verify the HMAC catches it.
        tampered = json.loads(lines[2])
        tampered["status"] = "tampered"
        lines[2] = json.dumps(tampered, separators=(",", ":"), sort_keys=True)
        (tmp_path / "runtime_audit.jsonl").write_text("\n".join(lines) + "\n")

        ok, msg = aud.verify_chain(log_path, chain_key=aud._CHAIN_KEY)
        assert not ok
        assert "line 3" in msg.lower() or "mismatch" in msg.lower() or "break" in msg.lower()

    def test_wrap_process_request(self, tmp_path, monkeypatch):
        import tee_crafter_audit_logger as aud
        self._reset_audit_state(aud, tmp_path, monkeypatch)

        def my_process_request(data):
            return {"doubled": data.get("x", 0) * 2}

        wrapped = aud.wrap_process_request(my_process_request)
        result = wrapped({"x": 21})
        assert result == {"doubled": 42}

        lines = (tmp_path / "runtime_audit.jsonl").read_text().strip().splitlines()
        # genesis + the wrapped call
        assert len(lines) == 2
        entry = json.loads(lines[1])
        assert entry["status"] == "ok"
        assert entry["latency_ms"] >= 0

    def test_wrap_process_request_error(self, tmp_path, monkeypatch):
        import tee_crafter_audit_logger as aud
        self._reset_audit_state(aud, tmp_path, monkeypatch)

        def failing_fn(data):
            raise ValueError("boom")

        wrapped = aud.wrap_process_request(failing_fn)
        with pytest.raises(ValueError, match="boom"):
            wrapped({"x": 1})

        lines = (tmp_path / "runtime_audit.jsonl").read_text().strip().splitlines()
        # genesis + error entry
        assert len(lines) == 2
        entry = json.loads(lines[1])
        assert entry["status"] == "error"
        assert "boom" in entry.get("extra", {}).get("error", "")

    def test_get_stats(self, tmp_path, monkeypatch):
        import tee_crafter_audit_logger as aud
        self._reset_audit_state(aud, tmp_path, monkeypatch)

        aud.log_request(request_bytes=b"a", response_bytes=b"b")
        stats = aud.get_stats()
        # AUD-3: stats include the genesis entry in total_entries
        assert stats["total_entries"] == 2
        assert stats["log_exists"] is True
        assert stats["log_size_bytes"] > 0
        assert stats["chain_key_commitment"] == aud.get_chain_key_commitment()

    def test_log_rotation(self, tmp_path, monkeypatch):
        import tee_crafter_audit_logger as aud
        self._reset_audit_state(aud, tmp_path, monkeypatch)
        log_path = str(tmp_path / "runtime_audit.jsonl")
        monkeypatch.setattr(aud, "_MAX_LOG_SIZE", 100)

        for i in range(5):
            aud.log_request(
                request_bytes=b"x" * 50,
                response_bytes=b"y" * 50,
            )

        assert os.path.exists(log_path)
        prev_path = log_path + ".prev"
        assert os.path.exists(prev_path)


# ---------------------------------------------------------------------------
# Continuous Attestation Monitor
# ---------------------------------------------------------------------------

class TestAttestationMonitor:

    def test_configure_and_start(self, tmp_path, monkeypatch):
        import tee_crafter_attestation_monitor as mon
        monkeypatch.setattr(mon, "_LOG_DIR", str(tmp_path))
        monkeypatch.setattr(mon, "_LOG_FILE", str(tmp_path / "attestation_monitor.jsonl"))
        monkeypatch.setattr(mon, "_running", False)
        monkeypatch.setattr(mon, "_thread", None)
        monkeypatch.setattr(mon, "_baseline", None)
        monkeypatch.setattr(mon, "_results", [])
        monkeypatch.setattr(mon, "_attest_fn", None)

        call_count = 0

        def mock_attest():
            nonlocal call_count
            call_count += 1
            return {"measurement": "abc123"}

        mon.configure(mock_attest, interval_secs=1)
        mon.start()
        time.sleep(2.5)
        mon.stop()

        assert call_count >= 1
        status = mon.get_status()
        assert status["baseline_measurement"] == "abc123"
        assert status["total_checks"] >= 1
        assert not status["drift_detected"]

    def test_drift_detection(self, tmp_path, monkeypatch):
        import tee_crafter_attestation_monitor as mon
        monkeypatch.setattr(mon, "_LOG_DIR", str(tmp_path))
        monkeypatch.setattr(mon, "_LOG_FILE", str(tmp_path / "attestation_monitor.jsonl"))
        monkeypatch.setattr(mon, "_running", False)
        monkeypatch.setattr(mon, "_thread", None)
        monkeypatch.setattr(mon, "_baseline", None)
        monkeypatch.setattr(mon, "_results", [])
        monkeypatch.setattr(mon, "_attest_fn", None)

        call_count = 0

        def drifting_attest():
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return {"measurement": "original"}
            return {"measurement": "drifted"}

        mon.configure(drifting_attest, interval_secs=1)
        mon.start(baseline_measurement="original")
        time.sleep(2.5)
        mon.stop()

        status = mon.get_status()
        assert status["baseline_measurement"] == "original"
        has_drift = any(r.get("drift") for r in mon._results)
        if call_count > 1:
            assert has_drift

    def test_error_handling(self, tmp_path, monkeypatch):
        import tee_crafter_attestation_monitor as mon
        monkeypatch.setattr(mon, "_LOG_DIR", str(tmp_path))
        monkeypatch.setattr(mon, "_LOG_FILE", str(tmp_path / "attestation_monitor.jsonl"))
        monkeypatch.setattr(mon, "_running", False)
        monkeypatch.setattr(mon, "_thread", None)
        monkeypatch.setattr(mon, "_baseline", None)
        monkeypatch.setattr(mon, "_results", [])
        monkeypatch.setattr(mon, "_attest_fn", None)

        def failing_attest():
            raise RuntimeError("hardware failure")

        mon.configure(failing_attest, interval_secs=1)
        mon.start()
        time.sleep(1.5)
        mon.stop()

        status = mon.get_status()
        assert status["total_checks"] >= 1
        assert mon._results[0]["status"] == "error"
        assert "hardware failure" in mon._results[0]["error"]

    def test_get_status_not_started(self, monkeypatch):
        import tee_crafter_attestation_monitor as mon
        monkeypatch.setattr(mon, "_running", False)
        monkeypatch.setattr(mon, "_baseline", None)
        monkeypatch.setattr(mon, "_results", [])
        monkeypatch.setattr(mon, "_attest_fn", None)

        status = mon.get_status()
        assert status["running"] is False
        assert status["total_checks"] == 0
        assert status["last_check"] is None

    def test_log_file_created(self, tmp_path, monkeypatch):
        import tee_crafter_attestation_monitor as mon
        monkeypatch.setattr(mon, "_LOG_DIR", str(tmp_path))
        log_path = str(tmp_path / "attestation_monitor.jsonl")
        monkeypatch.setattr(mon, "_LOG_FILE", log_path)
        monkeypatch.setattr(mon, "_running", False)
        monkeypatch.setattr(mon, "_thread", None)
        monkeypatch.setattr(mon, "_baseline", None)
        monkeypatch.setattr(mon, "_results", [])
        monkeypatch.setattr(mon, "_attest_fn", None)

        def mock_attest():
            return {"measurement": "test"}

        mon.configure(mock_attest, interval_secs=1)
        mon.start()
        time.sleep(1.5)
        mon.stop()

        assert os.path.exists(log_path)
        with open(log_path) as f:
            entries = [json.loads(line) for line in f if line.strip()]
        assert len(entries) >= 1
        assert "measurement" in entries[0]
        assert "ts_iso" in entries[0]


# ---------------------------------------------------------------------------
# Vulnerability Scanner
# ---------------------------------------------------------------------------

class TestVulnScan:

    def test_scan_result_dataclass(self):
        from tee_crafter.core.security.vuln_scan import VulnScanResult
        r = VulnScanResult(scanner="trivy", image="test:latest", success=True,
                           critical=0, high=0, medium=5, low=10, total=15)
        assert r.passed is True
        d = r.to_dict()
        assert d["scanner"] == "trivy"
        assert d["passed"] is True
        assert d["total"] == 15

    def test_scan_result_not_passed(self):
        """Fixable CRITICAL/HIGH block the gate.

        Updated 2026-08: the gate now blocks on findings that have an upstream
        fix rather than on any CRITICAL/HIGH at all, so the counts alone no
        longer decide this — ``fixable_*`` does.  See
        ``tests/core/test_vuln_gate_blocks_on_fixable.py`` for why (an
        unsatisfiable gate is worse than a narrower one).
        """
        from tee_crafter.core.security.vuln_scan import VulnScanResult
        r = VulnScanResult(scanner="trivy", image="test:latest", success=True,
                           critical=1, high=3, medium=5, low=10, total=19,
                           fixable_critical=1, fixable_high=3)
        assert r.passed is False

    def test_scan_result_unfixed_only_passes(self):
        """The same counts with no upstream fix available do not block."""
        from tee_crafter.core.security.vuln_scan import VulnScanResult
        r = VulnScanResult(scanner="trivy", image="test:latest", success=True,
                           critical=1, high=3, medium=5, low=10, total=19)
        assert r.passed is True
        assert (r.unfixed_critical, r.unfixed_high) == (1, 3)

    def test_scan_result_failed(self):
        from tee_crafter.core.security.vuln_scan import VulnScanResult
        r = VulnScanResult(scanner="none", image="test", success=False,
                           error="No scanner")
        assert r.passed is False
        assert r.to_dict()["success"] is False

    def test_parse_trivy_report(self, tmp_path):
        from tee_crafter.core.security.vuln_scan import _parse_trivy_report
        report = {
            "Results": [
                {
                    "Target": "test:latest",
                    "Vulnerabilities": [
                        # ``Status: fixed`` makes the CRITICAL/HIGH actionable,
                        # which is what the gate blocks on since 2026-08.
                        {"VulnerabilityID": "CVE-2024-001", "Severity": "CRITICAL",
                         "Status": "fixed", "FixedVersion": "2.0"},
                        {"VulnerabilityID": "CVE-2024-002", "Severity": "HIGH",
                         "Status": "fixed", "FixedVersion": "2.0"},
                        {"VulnerabilityID": "CVE-2024-003", "Severity": "MEDIUM"},
                        {"VulnerabilityID": "CVE-2024-004", "Severity": "LOW"},
                        {"VulnerabilityID": "CVE-2024-005", "Severity": "UNKNOWN"},
                    ],
                }
            ]
        }
        report_path = str(tmp_path / "trivy_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f)

        result = _parse_trivy_report("test:latest", report_path)
        assert result.success is True
        assert result.critical == 1
        assert result.high == 1
        assert result.medium == 1
        assert result.low == 1
        assert result.unknown == 1
        assert result.total == 5
        assert result.passed is False

    def test_parse_trivy_report_clean(self, tmp_path):
        from tee_crafter.core.security.vuln_scan import _parse_trivy_report
        report = {"Results": [{"Target": "clean:latest", "Vulnerabilities": []}]}
        report_path = str(tmp_path / "trivy_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f)

        result = _parse_trivy_report("clean:latest", report_path)
        assert result.success is True
        assert result.total == 0
        assert result.passed is True

    def test_parse_trivy_report_missing_file(self, tmp_path):
        from tee_crafter.core.security.vuln_scan import _parse_trivy_report
        result = _parse_trivy_report("test", str(tmp_path / "nonexistent.json"))
        assert result.success is False

    def test_parse_grype_report(self, tmp_path):
        from tee_crafter.core.security.vuln_scan import _parse_grype_report
        report = {
            "matches": [
                {"vulnerability": {"id": "CVE-1", "severity": "Critical"}},
                {"vulnerability": {"id": "CVE-2", "severity": "High"}},
                {"vulnerability": {"id": "CVE-3", "severity": "Medium"}},
            ]
        }
        report_path = str(tmp_path / "grype_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f)

        result = _parse_grype_report("test:latest", report_path)
        assert result.success is True
        assert result.critical == 1
        assert result.high == 1
        assert result.medium == 1
        assert result.total == 3

    def test_scan_image_no_tools(self, monkeypatch):
        from tee_crafter.core.security import vuln_scan
        monkeypatch.setattr(vuln_scan, "_has_tool", lambda name: False)
        result = vuln_scan.scan_image("test:latest", "/tmp/scan")
        assert result.success is False
        assert result.scanner == "none"
        assert "No vulnerability scanner" in result.error


# ---------------------------------------------------------------------------
# Evidence Collector: New Evidence Types
# ---------------------------------------------------------------------------

class TestNewEvidenceTypes:

    def _make_provenance(self, tmp_path, *, platform="nitro-aws", flow="container",
                         extra_entries=None):
        from tee_crafter.core.audit import BuildAuditTrail, sha256_hex
        trail = BuildAuditTrail()
        trail.set_metadata("0.2.0-test", str(tmp_path))
        trail.record("Phase 1: Container", "Docker image built", "pass",
                     image_tag="test:latest", image_digest="sha256:abc",
                     container_port=8080, platform=platform)
        trail.record("Phase 2: Packaging", "Nitro multi-stage Dockerfile", "pass",
                     dockerfile_sha256=sha256_hex("FROM test"),
                     entrypoint_sha256=sha256_hex("#!/bin/bash"))
        trail.record("Phase 2: Packaging", "EIF build (nitro-cli build-enclave)", "pass",
                     eif_sha256="eif123", PCR0="pcr0val", PCR1="pcr1val",
                     PCR2="pcr2val", platform=platform)
        trail.record("Phase 2: Packaging", "Client script rendered with PCRs", "pass",
                     client_py_sha256=sha256_hex("client"), root_ca_sha256="",
                     pcr_values_injected=True)
        trail.record("Phase 3: IaC Generation", "Terraform config generated", "pass",
                     main_tf_sha256=sha256_hex("terraform"),
                     kms_policy_pcr_bound=True,
                     security_group_https_only=True,
                     vpc_endpoint_for_kms=True,
                     no_ssh_ingress=True)
        if extra_entries:
            for e in extra_entries:
                trail.record(**e)
        return trail.save(str(tmp_path))

    def test_runtime_audit_logging_evidence(self, tmp_path):
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        path = self._make_provenance(tmp_path)
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        keys = [e.key for e in items]
        assert "runtime_audit_logging" in keys
        ev = next(e for e in items if e.key == "runtime_audit_logging")
        # Nothing about the deployed logger is observable from a build
        # provenance file; SIEM-001/SIEM-006 are what can prove it.
        assert ev.strength.value == "informational"
        assert ev.verified is False
        assert ev.artifacts["hash_chain"] is True
        assert ev.artifacts["plaintext_logged"] is False

    def test_continuous_attestation_evidence(self, tmp_path):
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        path = self._make_provenance(tmp_path)
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        keys = [e.key for e in items]
        assert "continuous_attestation" in keys
        ev = next(e for e in items if e.key == "continuous_attestation")
        assert ev.strength.value == "informational"
        assert ev.verified is False
        assert ev.artifacts["drift_detection"] is True

    def test_vulnerability_scan_evidence_with_scan(self, tmp_path):
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        path = self._make_provenance(
            tmp_path,
            extra_entries=[{
                "phase": "Phase 1: Container",
                "step": "Vulnerability scan",
                "status": "pass",
                "scanner": "trivy",
                "critical": 0,
                "high": 0,
                "medium": 3,
                "low": 10,
                "total": 13,
                "passed": True,
                "report_path": "/tmp/trivy_report.json",
            }],
        )
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        keys = [e.key for e in items]
        assert "vulnerability_scan" in keys
        ev = next(e for e in items if e.key == "vulnerability_scan")
        assert ev.artifacts["scanner"] == "trivy"
        assert ev.artifacts["total"] == 13
        assert ev.artifacts["passed"] is True
        # The scan passed, but VLN-001/002/003 were never recorded, so the
        # STRONG claim is capped until the ledger backs it.
        assert ev.strength.value == "moderate"
        assert ev.verified is False

    def test_vulnerability_scan_evidence_not_passed(self, tmp_path):
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        path = self._make_provenance(
            tmp_path,
            extra_entries=[{
                "phase": "Phase 1: Container",
                "step": "Vulnerability scan",
                "status": "pass",
                "scanner": "trivy",
                "critical": 2,
                "high": 5,
                "medium": 10,
                "low": 20,
                "total": 37,
                "passed": False,
            }],
        )
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        ev = next(e for e in items if e.key == "vulnerability_scan")
        assert ev.strength.value == "moderate"

    def test_vulnerability_scan_absent_without_scan_entries(self, tmp_path):
        """No vulnerability-scan evidence is emitted when the provenance has
        no image-scan entries."""
        from tee_crafter.core.audit import BuildAuditTrail, sha256_hex
        trail = BuildAuditTrail()
        trail.set_metadata("0.2.0-test", str(tmp_path))
        trail.record("Phase 1: Container", "Docker image built", "pass",
                     image_tag="test:latest", image_digest="sha256:abc",
                     platform="nitro-aws")
        trail.record("Phase 2: Packaging", "Nitro multi-stage Dockerfile", "pass",
                     dockerfile_sha256=sha256_hex("FROM test"), platform="nitro-aws")
        path = trail.save(str(tmp_path))

        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        keys = [e.key for e in items]
        assert "vulnerability_scan" not in keys


# ---------------------------------------------------------------------------
# Framework Updates: Verify new evidence keys present
# ---------------------------------------------------------------------------

class TestFrameworkNewEvidenceKeys:

    def test_hipaa_includes_runtime_audit_logging(self):
        from tee_crafter.core.compliance.frameworks.hipaa import FRAMEWORK
        audit_control = next(c for c in FRAMEWORK.controls if c.control_id == "164.312(b)")
        assert "runtime_audit_logging" in audit_control.evidence_keys

    def test_hipaa_includes_continuous_attestation(self):
        from tee_crafter.core.compliance.frameworks.hipaa import FRAMEWORK
        integrity = next(c for c in FRAMEWORK.controls if c.control_id == "164.312(c)(1)")
        assert "continuous_attestation" in integrity.evidence_keys

    def test_soc2_monitoring_includes_new_evidence(self):
        from tee_crafter.core.compliance.frameworks.soc2 import FRAMEWORK
        cc71 = next(c for c in FRAMEWORK.controls if c.control_id == "CC7.1")
        assert "runtime_audit_logging" in cc71.evidence_keys
        assert "continuous_attestation" in cc71.evidence_keys

    def test_soc2_change_mgmt_includes_vuln_scan(self):
        from tee_crafter.core.compliance.frameworks.soc2 import FRAMEWORK
        cc81 = next(c for c in FRAMEWORK.controls if c.control_id == "CC8.1")
        assert "vulnerability_scan" in cc81.evidence_keys

    def test_pci_dss_includes_vuln_scan(self):
        from tee_crafter.core.compliance.frameworks.pci_dss import FRAMEWORK
        req63 = next(c for c in FRAMEWORK.controls if c.control_id == "Req 6.3")
        assert "vulnerability_scan" in req63.evidence_keys
        req113 = next(c for c in FRAMEWORK.controls if c.control_id == "Req 11.3")
        assert "vulnerability_scan" in req113.evidence_keys

    def test_pci_dss_audit_trail_includes_runtime_logging(self):
        from tee_crafter.core.compliance.frameworks.pci_dss import FRAMEWORK
        req102 = next(c for c in FRAMEWORK.controls if c.control_id == "Req 10.2")
        assert "runtime_audit_logging" in req102.evidence_keys

    def test_nist_800_53_audit_includes_runtime_logging(self):
        from tee_crafter.core.compliance.frameworks.nist_800_53 import FRAMEWORK
        au2 = next(c for c in FRAMEWORK.controls if c.control_id == "AU-2")
        assert "runtime_audit_logging" in au2.evidence_keys

    def test_nist_800_53_has_si7_and_ra5(self):
        from tee_crafter.core.compliance.frameworks.nist_800_53 import FRAMEWORK
        ids = [c.control_id for c in FRAMEWORK.controls]
        assert "SI-7" in ids
        assert "RA-5" in ids
        si7 = next(c for c in FRAMEWORK.controls if c.control_id == "SI-7")
        assert "continuous_attestation" in si7.evidence_keys
        ra5 = next(c for c in FRAMEWORK.controls if c.control_id == "RA-5")
        assert "vulnerability_scan" in ra5.evidence_keys

    def test_nist_csf_detect_includes_new_evidence(self):
        from tee_crafter.core.compliance.frameworks.nist_csf import FRAMEWORK
        de = next(c for c in FRAMEWORK.controls if c.control_id == "DE.CM-01")
        assert "runtime_audit_logging" in de.evidence_keys
        assert "continuous_attestation" in de.evidence_keys

    def test_iso_27001_logging_includes_runtime_audit(self):
        from tee_crafter.core.compliance.frameworks.iso_27001 import FRAMEWORK
        a815 = next(c for c in FRAMEWORK.controls if c.control_id == "A.8.15")
        assert "runtime_audit_logging" in a815.evidence_keys

    def test_iso_27001_sdlc_includes_vuln_scan(self):
        from tee_crafter.core.compliance.frameworks.iso_27001 import FRAMEWORK
        a825 = next(c for c in FRAMEWORK.controls if c.control_id == "A.8.25")
        assert "vulnerability_scan" in a825.evidence_keys

    def test_glba_audit_trail_includes_runtime_logging(self):
        from tee_crafter.core.compliance.frameworks.glba import FRAMEWORK
        c8 = next(c for c in FRAMEWORK.controls if c.control_id == "314.4(c)(8)")
        assert "runtime_audit_logging" in c8.evidence_keys

    def test_hitrust_monitoring_includes_new_evidence(self):
        from tee_crafter.core.compliance.frameworks.hitrust import FRAMEWORK
        ab = next(c for c in FRAMEWORK.controls if c.control_id == "09.ab")
        assert "runtime_audit_logging" in ab.evidence_keys
        assert "continuous_attestation" in ab.evidence_keys

    def test_csa_ccm_change_mgmt_includes_vuln_scan(self):
        from tee_crafter.core.compliance.frameworks.csa_ccm import FRAMEWORK
        ccc = next(c for c in FRAMEWORK.controls if c.control_id == "CCC-01")
        assert "vulnerability_scan" in ccc.evidence_keys

    def test_iso_27701_records_include_runtime_audit(self):
        from tee_crafter.core.compliance.frameworks.iso_27701 import FRAMEWORK
        r = next(c for c in FRAMEWORK.controls if c.control_id == "7.2.8")
        assert "runtime_audit_logging" in r.evidence_keys


# ---------------------------------------------------------------------------
# Builder: Runtime module copy
# ---------------------------------------------------------------------------

class TestBuilderRuntimeModules:

    def test_copy_runtime_modules(self, tmp_path):
        from tee_crafter.core.builder.builder import _copy_runtime_modules
        _copy_runtime_modules(str(tmp_path))
        assert (tmp_path / "tee_crafter_audit_logger.py").exists()
        assert (tmp_path / "tee_crafter_attestation_monitor.py").exists()

    def test_platforms_copy_runtime_modules(self, tmp_path):
        from tee_crafter.core.builder.platforms import _copy_runtime_modules
        _copy_runtime_modules(str(tmp_path))
        assert (tmp_path / "tee_crafter_audit_logger.py").exists()
        assert (tmp_path / "tee_crafter_attestation_monitor.py").exists()


# ---------------------------------------------------------------------------
# Integration: evidence count increased
# ---------------------------------------------------------------------------

class TestIntegration:

    def _make_provenance(self, tmp_path):
        from tee_crafter.core.audit import BuildAuditTrail, sha256_hex
        trail = BuildAuditTrail()
        trail.set_metadata("0.2.0-test", str(tmp_path))
        trail.record("Phase 1: Container", "Docker image built", "pass",
                     image_tag="test:latest", image_digest="sha256:abc",
                     container_port=8080, platform="nitro-aws")
        trail.record("Phase 1: Container", "Vulnerability scan", "pass",
                     scanner="trivy", critical=0, high=0, medium=2,
                     low=5, total=7, passed=True)
        trail.record("Phase 2: Packaging", "Nitro multi-stage Dockerfile", "pass",
                     dockerfile_sha256=sha256_hex("FROM test"))
        trail.record("Phase 2: Packaging", "EIF build (nitro-cli build-enclave)", "pass",
                     eif_sha256="eif123", PCR0="pcr0val", PCR1="pcr1val",
                     PCR2="pcr2val", platform="nitro-aws")
        trail.record("Phase 2: Packaging", "Client script rendered with PCRs", "pass",
                     client_py_sha256=sha256_hex("client"),
                     pcr_values_injected=True)
        trail.record("Phase 3: IaC Generation", "Terraform config generated", "pass",
                     main_tf_sha256=sha256_hex("tf"),
                     kms_policy_pcr_bound=True,
                     security_group_https_only=True)
        return trail.save(str(tmp_path))

    def test_evidence_inventory_includes_new_types(self, tmp_path):
        """With vuln scan entry, we should collect all 3 new evidence types."""
        from tee_crafter.core.compliance.evidence import EvidenceCollector
        path = self._make_provenance(tmp_path)
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        keys = [e.key for e in items]
        assert "runtime_audit_logging" in keys
        assert "continuous_attestation" in keys
        assert "vulnerability_scan" in keys
        assert len(items) >= 29

    def test_full_pipeline_with_new_evidence(self, tmp_path):
        from tee_crafter.core.compliance.engine import ComplianceEngine
        path = self._make_provenance(tmp_path)
        engine = ComplianceEngine(provenance_path=path)
        compliance_dir = engine.generate_report(str(tmp_path))

        with open(os.path.join(compliance_dir, "compliance_report.json")) as f:
            data = json.load(f)

        inv_keys = [e["key"] for e in data["evidence_inventory"]]
        assert "runtime_audit_logging" in inv_keys
        assert "continuous_attestation" in inv_keys
        assert "vulnerability_scan" in inv_keys
        assert data["summary"]["total_controls"] > 0

    def test_existing_tests_still_pass_count(self, tmp_path):
        """Existing provenance (without vuln scan entry) still works."""
        from tee_crafter.core.audit import BuildAuditTrail, sha256_hex
        trail = BuildAuditTrail()
        trail.set_metadata("0.2.0-test", str(tmp_path))
        trail.record("Phase 1: Container", "Docker image built", "pass",
                     image_tag="test:latest", image_digest="sha256:abc",
                     container_port=8080, platform="nitro-aws")
        trail.record("Phase 2: Packaging", "EIF build", "pass",
                     eif_sha256="eif123", PCR0="pcr0val", platform="nitro-aws")
        trail.record("Phase 2: Packaging", "Client script rendered with PCRs", "pass",
                     client_py_sha256=sha256_hex("client"), pcr_values_injected=True)
        trail.record("Phase 3: IaC Generation", "Terraform config generated", "pass",
                     main_tf_sha256=sha256_hex("tf"))
        path = trail.save(str(tmp_path))

        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        keys = [e.key for e in items]
        assert "runtime_audit_logging" in keys
        assert "continuous_attestation" in keys
        assert "vulnerability_scan" not in keys


# ---------------------------------------------------------------------------
# Key Rotation Manager
# ---------------------------------------------------------------------------

class TestKeyRotation:

    def _fresh_module(self, monkeypatch, tmp_path):
        import importlib
        import tee_crafter_key_rotation as kr
        importlib.reload(kr)
        monkeypatch.setattr(kr, "_LOG_DIR", str(tmp_path))
        monkeypatch.setattr(kr, "_LOG_FILE", str(tmp_path / "key_rotation.jsonl"))
        monkeypatch.setattr(kr, "_prev_hash", "0" * 64)
        monkeypatch.setattr(kr, "_entry_seq", 0)
        monkeypatch.setattr(kr, "_total_rotations", 0)
        monkeypatch.setattr(kr, "_rotation_history", [])
        monkeypatch.setattr(kr, "_key_created_at", 0.0)
        monkeypatch.setattr(kr, "_key_request_count", 0)
        monkeypatch.setattr(kr, "_current_key_id", "")
        monkeypatch.setattr(kr, "_current_key_fingerprint", "")
        return kr

    def test_record_key_birth(self, tmp_path, monkeypatch):
        kr = self._fresh_module(monkeypatch, tmp_path)
        kr.record_key_birth("boot-key-0", b"fakepubbytes", key_type="ECDH-P256")
        assert kr._current_key_id == "boot-key-0"
        assert kr._current_key_fingerprint
        log = tmp_path / "key_rotation.jsonl"
        assert log.exists()
        entry = json.loads(log.read_text().strip())
        assert entry["event"] == "key_birth"
        assert entry["key_type"] == "ECDH-P256"

    def test_record_rotation(self, tmp_path, monkeypatch):
        kr = self._fresh_module(monkeypatch, tmp_path)
        kr.record_key_birth("key-0", b"pub0", key_type="ECDH-P256")
        kr._key_request_count = 42
        record = kr.record_rotation(
            "key-1", b"pub1-new", new_key_type="ECDH-P256",
            reason="time_based", rotation_latency_ms=1.5,
        )
        assert record["event"] == "key_rotation"
        assert record["retired_key"]["requests_served"] == 42
        assert record["new_key"]["key_id"] == "key-1"
        assert kr._total_rotations == 1
        assert kr._key_request_count == 0

    def test_should_rotate_time_based(self, tmp_path, monkeypatch):
        kr = self._fresh_module(monkeypatch, tmp_path)
        kr.configure(rotation_interval_secs=1)
        kr.record_key_birth("key-0", b"pub0")
        time.sleep(1.1)
        should, reason = kr.should_rotate()
        assert should is True
        assert reason == "time_based"

    def test_should_rotate_max_requests(self, tmp_path, monkeypatch):
        kr = self._fresh_module(monkeypatch, tmp_path)
        kr.configure(rotation_interval_secs=9999, max_requests_per_key=5)
        kr.record_key_birth("key-0", b"pub0")
        for _ in range(5):
            kr.tick_request()
        should, reason = kr.should_rotate()
        assert should is True
        assert reason == "max_requests"

    def test_attestation_bound_rotation(self, tmp_path, monkeypatch):
        kr = self._fresh_module(monkeypatch, tmp_path)
        attest_called = []
        def mock_attest():
            attest_called.append(True)
            return {"measurement": "abc123"}
        kr.configure(attest_fn=mock_attest)
        kr.record_key_birth("key-0", b"pub0")
        record = kr.record_rotation("key-1", b"pub1", reason="test")
        assert len(attest_called) == 1
        assert "attestation_at_rotation" in record
        assert record["attestation_at_rotation"]["measurement"] == "abc123"

    def test_hash_chain_integrity(self, tmp_path, monkeypatch):
        kr = self._fresh_module(monkeypatch, tmp_path)
        kr.record_key_birth("key-0", b"pub0")
        kr.record_rotation("key-1", b"pub1", reason="time_based")
        kr.record_rotation("key-2", b"pub2", reason="event")
        ok, msg = kr.verify_chain(str(tmp_path / "key_rotation.jsonl"))
        assert ok, msg

    def test_get_status(self, tmp_path, monkeypatch):
        kr = self._fresh_module(monkeypatch, tmp_path)
        kr.configure(rotation_interval_secs=3600)
        kr.record_key_birth("key-0", b"pub0")
        for _ in range(10):
            kr.tick_request()
        status = kr.get_status()
        assert status["configured"] is True
        assert status["current_key"]["requests_served"] == 10
        assert status["total_rotations"] == 0

    def test_trigger_rotation_with_callback(self, tmp_path, monkeypatch):
        kr = self._fresh_module(monkeypatch, tmp_path)
        def do_rotate():
            return {"key_id": "new-key", "pub_bytes": b"rotated", "key_type": "ECDH-P384"}
        kr.configure(rotate_callback=do_rotate)
        kr.record_key_birth("key-0", b"pub0")
        record = kr.trigger_rotation(reason="drift")
        assert record is not None
        assert record["reason"] == "drift"
        assert kr._total_rotations == 1


class TestKeyRotationEvidence:

    def test_key_rotation_evidence_collected(self, tmp_path):
        from tee_crafter.core.audit import BuildAuditTrail
        trail = BuildAuditTrail()
        trail.set_metadata("0.2.0-test", str(tmp_path))
        trail.record("Phase 1: Ingestion", "LLM code generation + confinement", "pass",
                     platform="nitro-aws")
        trail.record("Phase 2: AI Translation", "Confinement verification", "pass",
                     blockers=0, warnings=0, passed=True, total_violations=0, categories={})
        trail.record("Phase 2: Packaging", "Staged app_vsock.py", "pass",
                     sha256="abc", platform="nitro-aws")
        path = trail.save(str(tmp_path))

        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        keys = [e.key for e in items]
        assert "key_rotation_evidence" in keys
        kr_item = next(e for e in items if e.key == "key_rotation_evidence")
        assert kr_item.strength.value == "informational"
        assert kr_item.artifacts["hash_chained_log"] is True
        assert kr_item.artifacts["attestation_bound"] is True

    def test_key_rotation_in_framework_mappings(self):
        from tee_crafter.core.compliance.registry import build_default_registry
        registry = build_default_registry()
        found = set()
        for fw in registry.all():
            for ctrl in fw.controls:
                if "key_rotation_evidence" in ctrl.evidence_keys:
                    found.add(f"{fw.framework_id}:{ctrl.control_id}")
        assert len(found) >= 8, f"Expected key_rotation_evidence in >=8 controls, found {found}"


class TestVPCIsolationEvidence:

    def test_vpc_isolation_evidence_collected(self, tmp_path):
        from tee_crafter.core.audit import BuildAuditTrail
        trail = BuildAuditTrail()
        trail.set_metadata("0.2.0-test", str(tmp_path))
        trail.record("Phase 1: Ingestion", "LLM code generation", "pass",
                     platform="nitro-aws")
        trail.record("Phase 2: Packaging", "Staged app", "pass",
                     sha256="abc", platform="nitro-aws")
        path = trail.save(str(tmp_path))

        from tee_crafter.core.compliance.evidence import EvidenceCollector
        collector = EvidenceCollector(path)
        items = collector.collect_all()
        keys = [e.key for e in items]
        assert "vpc_isolation" in keys
        vpc_item = next(e for e in items if e.key == "vpc_isolation")
        assert vpc_item.strength.value == "moderate"
        assert vpc_item.artifacts["dedicated_vpc"] is True
        assert vpc_item.artifacts["flow_logging_enabled"] is True

    def test_vpc_isolation_cloud_specific_details(self, tmp_path):
        from tee_crafter.core.audit import BuildAuditTrail
        for platform, cloud, mechanism_substr in [
            ("nitro-aws", "aws", "CloudWatch"),
            ("snp-gcp", "gcp", "Subnet Flow Logs"),
            ("tdx-azure", "azure", "Virtual network flow logs"),
        ]:
            trail = BuildAuditTrail()
            trail.set_metadata("0.2.0-test", str(tmp_path))
            trail.record("Phase 1", "Step", "pass", platform=platform)
            trail.record("Phase 2", "Packaging", "pass", sha256="x",
                         platform=platform)
            path = trail.save(str(tmp_path))

            from tee_crafter.core.compliance.evidence import EvidenceCollector
            collector = EvidenceCollector(path)
            items = collector.collect_all()
            vpc_item = next(e for e in items if e.key == "vpc_isolation")
            assert vpc_item.artifacts["cloud"] == cloud, (
                f"Expected cloud={cloud} for {platform}")
            assert mechanism_substr in vpc_item.artifacts.get("mechanism", ""), (
                f"Expected {mechanism_substr} in mechanism for {platform}, "
                f"got {vpc_item.artifacts}")

    def test_vpc_isolation_in_framework_mappings(self):
        from tee_crafter.core.compliance.registry import build_default_registry
        registry = build_default_registry()
        found = set()
        for fw in registry.all():
            for ctrl in fw.controls:
                if "vpc_isolation" in ctrl.evidence_keys:
                    found.add(f"{fw.framework_id}:{ctrl.control_id}")
        expected_frameworks = {"nist_800_53", "pci_dss", "soc2",
                               "hipaa", "iso_27001", "hitrust", "glba",
                               "csa_ccm"}
        found_fws = {fid.split(":")[0] for fid in found}
        assert found_fws >= expected_frameworks, (
            f"vpc_isolation missing from frameworks: "
            f"{expected_frameworks - found_fws}. Found in: {found}"
        )


class TestSourceProvenance:
    """Provenance of every control identifier must be legible in the artefact.

    A control ID in a compliance report reads as a citation. Four frameworks
    were deleted during remediation because every identifier in them was
    invented and the standard was paywalled, so nothing could be checked. These
    tests keep the surviving judgement calls visible in the output rather than
    in a reviewer's memory.
    """

    def test_every_framework_declares_its_source_authority(self):
        from tee_crafter.core.compliance.registry import build_default_registry
        reg = build_default_registry()
        for fw in reg.all():
            assert fw.source_authority in ("primary", "secondary"), (
                f"{fw.framework_id} declares {fw.source_authority!r}")

    def test_secondary_source_frameworks_say_where_to_recheck(self):
        from tee_crafter.core.compliance.registry import build_default_registry
        reg = build_default_registry()
        secondary = [f for f in reg.all()
                     if f.source_authority == "secondary"]
        # CSA gates the CCM behind registration; that is the known case.
        assert any(f.framework_id == "csa_ccm" for f in secondary)
        for fw in secondary:
            assert fw.source_url, (
                f"{fw.framework_id} is secondary-sourced but gives no URL to "
                "re-check it against")

    def test_interpreted_mapping_is_labelled(self):
        """RS.AN-03 is a substitution containing interpretation."""
        from tee_crafter.core.compliance.registry import build_default_registry
        reg = build_default_registry()
        csf = reg.get("nist_csf")
        rs = next(c for c in csf.controls if c.control_id == "RS.AN-03")
        assert rs.source_note, "the one interpreted mapping must say so"
        # It must name the literal alternative, so a reader can disagree.
        assert "RS.MA-02" in rs.source_note
        assert "interpretation" in rs.source_note.lower()

    def test_source_note_reaches_the_serialised_control(self):
        from tee_crafter.core.compliance.registry import build_default_registry
        reg = build_default_registry()
        csf = reg.get("nist_csf")
        rs = next(c for c in csf.controls if c.control_id == "RS.AN-03")
        assert "source_note" in rs.to_dict()

    def test_clean_controls_stay_clean_in_json(self):
        """Presence of source_note must be a signal, not boilerplate."""
        from tee_crafter.core.compliance.registry import build_default_registry
        reg = build_default_registry()
        csf = reg.get("nist_csf")
        plain = [c for c in csf.controls if not c.source_note]
        assert plain, "expected most controls to be direct transcriptions"
        assert "source_note" not in plain[0].to_dict()

    def test_framework_dict_surfaces_provenance(self):
        from tee_crafter.core.compliance.registry import build_default_registry
        reg = build_default_registry()
        d = reg.get("nist_csf").to_dict()
        assert d["source_authority"] in ("primary", "secondary")
        assert d["controls_with_source_notes"] >= 1

    def test_ccm_is_not_silently_presented_as_authoritative(self):
        from tee_crafter.core.compliance.registry import build_default_registry
        d = build_default_registry().get("csa_ccm").to_dict()
        assert d["source_authority"] == "secondary"
        assert "cloudsecurityalliance.org" in d["source_url"]


class TestMethodologyIsInTheArtefact:
    """A reader who receives only the JSON must be able to see the grading rule.

    The promote-on-proof ladder reports worse numbers than a downgrade-only one
    would, so the reason it produces those numbers has to travel with them. The
    pre-remediation report showed 86.2% coverage and zero gaps from a
    single-entry provenance file; nothing in that artefact explained why.
    """

    def test_report_declares_its_grading_rule(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        data = engine._build_report_data(engine.evaluate_all())
        m = data["methodology"]
        for key in ("satisfied_requires", "promotion_policy",
                    "unevaluated_is_not_passing", "source_authority"):
            assert key in m and m[key], key
        assert "promote-on-proof" in m["promotion_policy"].lower()
        assert "not_evaluated" in m["unevaluated_is_not_passing"]

    def test_every_framework_in_the_report_carries_provenance(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        data = engine._build_report_data(engine.evaluate_all())
        # `frameworks` is keyed by framework_id, not a list.
        assert data["frameworks"], "no frameworks in the report"
        for fw_id, fw in data["frameworks"].items():
            assert fw.get("source_authority") in ("primary", "secondary"), fw_id

    def test_secondary_sourced_framework_is_visible_in_the_report(self, tmp_path):
        path = _make_provenance(tmp_path)
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=path)
        data = engine._build_report_data(engine.evaluate_all())
        ccm = data["frameworks"]["csa_ccm"]
        assert ccm["source_authority"] == "secondary"
        assert "cloudsecurityalliance.org" in ccm["source_url"]
