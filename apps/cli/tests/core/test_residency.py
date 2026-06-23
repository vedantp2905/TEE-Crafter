"""Unit tests for data-residency policy + signed evidence."""
from __future__ import annotations

import ast
import json

import pytest

from tee_crafter.core.compliance.residency import (
    ResidencyPolicy, emit_residency_evidence, lookup_region, scan_terraform_for_regions,
    validate_deployment, verify_residency_evidence,
)


class TestLookup:
    def test_known_aws_region(self):
        info = lookup_region("aws", "eu-west-1")
        assert info.country_iso2 == "IE"
        assert info.regime == "GDPR"

    def test_known_azure_region(self):
        info = lookup_region("azure", "westeurope")
        assert info.regime == "GDPR"

    def test_known_gcp_region(self):
        info = lookup_region("gcp", "us-central1")
        assert info.country_iso2 == "US"

    def test_unknown_cloud(self):
        with pytest.raises(KeyError, match="cloud"):
            lookup_region("ibm", "us-east-1")

    def test_unknown_region(self):
        with pytest.raises(KeyError, match="region"):
            lookup_region("aws", "us-mars-1")


class TestPolicy:
    def test_validate_rejects_bad_country(self):
        pol = ResidencyPolicy(allowed_countries=["DEU"])
        errs = pol.validate()
        assert any("ISO" in e for e in errs)

    def test_validate_rejects_bad_region(self):
        pol = ResidencyPolicy(allowed_regions=[("aws", "us-mars-1")])
        errs = pol.validate()
        assert errs

    def test_is_allowed_via_region_list(self):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1")])
        ok, _ = pol.is_allowed(lookup_region("aws", "eu-west-1"))
        assert ok
        ok, reason = pol.is_allowed(lookup_region("aws", "us-east-1"))
        assert not ok and "not in allowed_regions" in reason

    def test_is_allowed_via_country(self):
        pol = ResidencyPolicy(allowed_countries=["DE", "IE"])
        ok, _ = pol.is_allowed(lookup_region("aws", "eu-central-1"))
        assert ok
        ok, _ = pol.is_allowed(lookup_region("aws", "us-east-1"))
        assert not ok

    def test_is_allowed_via_jurisdiction(self):
        pol = ResidencyPolicy(allowed_jurisdictions=["Germany", "France"])
        ok, _ = pol.is_allowed(lookup_region("aws", "eu-central-1"))
        assert ok

    def test_is_allowed_via_regime(self):
        pol = ResidencyPolicy(allowed_regimes=["GDPR"])
        ok, _ = pol.is_allowed(lookup_region("aws", "eu-west-1"))
        assert ok
        ok, _ = pol.is_allowed(lookup_region("aws", "us-east-1"))
        assert not ok


class TestTerraformScan:
    def test_scan_plan_resources(self):
        plan = {
            "planned_values": {
                "root_module": {
                    "resources": [
                        {"address": "aws_s3_bucket.x", "type": "aws_s3_bucket",
                         "values": {"region": "eu-west-1"}},
                    ],
                    "child_modules": [{
                        "resources": [
                            {"address": "module.k.aws_kms_key.k",
                             "type": "aws_kms_key",
                             "values": {"region": "us-east-1"}}
                        ]
                    }]
                }
            }
        }
        rows = scan_terraform_for_regions(plan)
        regions = sorted(r["region"] for r in rows)
        assert regions == ["eu-west-1", "us-east-1"]

    def test_scan_state_values(self):
        state = {
            "values": {"root_module": {"resources": [
                {"address": "azurerm_storage_account.s",
                 "type": "azurerm_storage_account",
                 "values": {"location": "westeurope"}},
            ]}}
        }
        rows = scan_terraform_for_regions(state)
        assert rows[0]["region"] == "westeurope"

    def test_scan_resource_changes(self):
        plan = {"resource_changes": [
            {"address": "google_compute_instance.x",
             "type": "google_compute_instance",
             "change": {"after": {"region": "europe-west3"}}}
        ]}
        rows = scan_terraform_for_regions(plan)
        assert rows[0]["region"] == "europe-west3"


class TestValidate:
    def test_passes_with_clean_plan(self):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1")])
        plan = {"planned_values": {"root_module": {"resources": [
            {"address": "aws_s3_bucket.x", "type": "aws_s3_bucket",
             "values": {"region": "eu-west-1"}},
        ]}}}
        v = validate_deployment(cloud="aws", primary_region="eu-west-1",
                                  policy=pol, terraform_plan=plan)
        assert v.passed
        assert not v.cross_region_findings

    def test_detects_cross_region(self):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1"),
                                                ("aws", "eu-central-1")])
        plan = {"planned_values": {"root_module": {"resources": [
            {"address": "aws_s3_bucket.x", "type": "aws_s3_bucket",
             "values": {"region": "eu-central-1"}},
        ]}}}
        v = validate_deployment(cloud="aws", primary_region="eu-west-1",
                                  policy=pol, terraform_plan=plan)
        assert v.primary_allowed
        assert len(v.cross_region_findings) == 1
        # Allowed regions list permits both, so passed is still True; but
        # the no_cross_region claim in evidence will be False.

    def test_rejects_out_of_policy_resource(self):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1")])
        plan = {"planned_values": {"root_module": {"resources": [
            {"address": "aws_s3_bucket.x", "type": "aws_s3_bucket",
             "values": {"region": "us-east-1"}},
        ]}}}
        v = validate_deployment(cloud="aws", primary_region="eu-west-1",
                                  policy=pol, terraform_plan=plan)
        assert not v.passed
        assert v.out_of_policy_resources

    def test_unknown_resource_region(self):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1")])
        plan = {"planned_values": {"root_module": {"resources": [
            {"address": "x", "type": "aws_x", "values": {"region": "eu-west-99"}},
        ]}}}
        v = validate_deployment(cloud="aws", primary_region="eu-west-1",
                                  policy=pol, terraform_plan=plan)
        assert v.out_of_policy_resources[0]["reason"] == "unknown region"

    def test_primary_blocked_means_failed(self):
        pol = ResidencyPolicy(allowed_countries=["DE"])
        v = validate_deployment(cloud="aws", primary_region="us-east-1", policy=pol)
        assert not v.passed
        assert "country" in v.primary_reason


class TestEvidence:
    def test_emit_and_verify(self, tmp_path):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1")])
        ev = emit_residency_evidence(cloud="aws", primary_region="eu-west-1",
                                       policy=pol)
        ok, reason = verify_residency_evidence(
            ev.document, ev.signature_hex, ev.public_key_pem)
        assert ok, reason

    def test_tampered_doc_fails(self, tmp_path):
        pol = ResidencyPolicy(allowed_countries=["IE"])
        ev = emit_residency_evidence(cloud="aws", primary_region="eu-west-1",
                                       policy=pol)
        tampered = dict(ev.document)
        tampered["claims"] = {**tampered["claims"], "data_residency_country": "RU"}
        ok, _ = verify_residency_evidence(tampered, ev.signature_hex, ev.public_key_pem)
        assert not ok

    def test_write(self, tmp_path):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1")])
        ev = emit_residency_evidence(cloud="aws", primary_region="eu-west-1",
                                       policy=pol)
        out = tmp_path / "ev.json"
        ev.write(str(out))
        assert out.exists()
        assert (tmp_path / "ev.json.sig").exists()
        assert (tmp_path / "ev.json.pub").exists()
        loaded = json.loads(out.read_text())
        assert loaded["claims"]["data_residency_country"] == "IE"
        assert loaded["claims"]["data_residency_jurisdiction"] == "Ireland"

    def test_evidence_contains_no_cross_region_claim(self):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1")])
        ev = emit_residency_evidence(cloud="aws", primary_region="eu-west-1",
                                       policy=pol)
        assert ev.document["claims"]["no_cross_region"] is True

    def test_evidence_no_cross_region_false_when_findings(self):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1"),
                                                ("aws", "eu-central-1")])
        plan = {"planned_values": {"root_module": {"resources": [
            {"address": "aws_s3_bucket.x", "type": "aws_s3_bucket",
             "values": {"region": "eu-central-1"}},
        ]}}}
        ev = emit_residency_evidence(cloud="aws", primary_region="eu-west-1",
                                       policy=pol, terraform_plan=plan)
        assert ev.document["claims"]["no_cross_region"] is False

    def test_signature_changes_per_emit(self):
        pol = ResidencyPolicy(allowed_regions=[("aws", "eu-west-1")])
        ev1 = emit_residency_evidence(cloud="aws", primary_region="eu-west-1",
                                        policy=pol)
        ev2 = emit_residency_evidence(cloud="aws", primary_region="eu-west-1",
                                        policy=pol)
        assert ev1.signature_hex != ev2.signature_hex


class TestRegionTableIntegrity:
    """Guard the region tables themselves.

    A duplicate key in a dict literal is silently swallowed by Python — the
    last one wins — so this cannot be caught at runtime.  It has to be read
    off the source.  ``us-west-2`` was typed as a second ``us-east-2`` and
    overwrote Ohio's coordinates with Portland's, which both corrupted
    ``us-east-2`` and dropped ``us-west-2`` from the map entirely.
    """

    def _region_dicts(self):
        import inspect
        from tee_crafter.core.compliance import residency

        tree = ast.parse(inspect.getsource(residency))
        for node in ast.walk(tree):
            if not isinstance(node, ast.AnnAssign) or not isinstance(node.value, ast.Dict):
                continue
            if not isinstance(node.target, ast.Name):
                continue
            if not node.target.id.endswith("_REGIONS") and \
                    not node.target.id.endswith("_LOCATIONS"):
                continue
            yield node.target.id, node.value

    def test_region_tables_were_found(self):
        assert list(self._region_dicts()), "AST scan matched no region tables"

    def test_no_duplicate_region_keys(self):
        for name, dict_node in self._region_dicts():
            keys = [k.value for k in dict_node.keys
                    if isinstance(k, ast.Constant)]
            dupes = {k for k in keys if keys.count(k) > 1}
            assert not dupes, f"{name} has duplicate keys: {sorted(dupes)}"

    def test_common_aws_regions_present(self):
        for region in ("us-east-1", "us-east-2", "us-west-1", "us-west-2"):
            info = lookup_region("aws", region)
            assert info.region == region
