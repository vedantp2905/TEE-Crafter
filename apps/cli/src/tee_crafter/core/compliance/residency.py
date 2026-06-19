"""Data-residency / region-pinning enforcement + signed compliance evidence.

Frameworks that buyers ask about (GDPR, DORA, EU AI Act, US state
privacy laws, sectoral rules like HIPAA / GLBA / FFIEC) all want
provable answers to two questions:

1. Where does my data physically live, in what jurisdiction?
2. Can you prove no resource crossed that boundary, even briefly?

Today TEE-Crafter lets users pick a cloud region but does not
*evidence* the choice in the audit pack.  This module:

* Maps every supported cloud region to a (cloud, country, jurisdiction,
  data_protection_regime) tuple.
* Defines :class:`ResidencyPolicy`, declarative allowlists for regions,
  countries, jurisdictions, and cross-region replication.
* Validates a resolved deployment description against the policy and
  emits a signed JSON evidence artifact suitable for a compliance pack.
* Optionally inspects a Terraform plan / state JSON for resources whose
  region or location attribute falls outside the policy.

The signing uses the same Ed25519 pattern as
:class:`tee_crafter.core.audit.BuildAuditTrail`, so an existing
verifier-style script can be re-used.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("tee_crafter.compliance.residency")


# ---- region map ----------------------------------------------------------

# Each entry: cloud -> {region -> (country_iso2, jurisdiction, regime, geo)}
# ``regime`` summarises the dominant data-protection regime: GDPR / UK-GDPR
# / CCPA / Australia-Privacy-Act / Brazil-LGPD / Switzerland-FADP / "other".
# The list is intentionally curated to the regions that customers actually
# pin in residency policies.  Adding a region only requires a new row.

_AWS_REGIONS: Dict[str, Tuple[str, str, str, Tuple[float, float]]] = {
    "us-east-1": ("US", "USA", "US-Federal", (38.9, -77.0)),
    "us-east-2": ("US", "USA", "US-Federal", (40.0, -82.9)),
    "us-west-1": ("US", "USA", "US-Federal", (37.4, -122.1)),
    "us-west-2": ("US", "USA", "US-Federal", (45.5, -122.7)),
    "ca-central-1": ("CA", "Canada", "PIPEDA", (45.5, -73.6)),
    "eu-west-1": ("IE", "Ireland", "GDPR", (53.3, -6.3)),
    "eu-west-2": ("GB", "United Kingdom", "UK-GDPR", (51.5, -0.1)),
    "eu-west-3": ("FR", "France", "GDPR", (48.8, 2.3)),
    "eu-central-1": ("DE", "Germany", "GDPR", (50.1, 8.7)),
    "eu-north-1": ("SE", "Sweden", "GDPR", (59.3, 18.0)),
    "eu-south-1": ("IT", "Italy", "GDPR", (45.5, 9.2)),
    "ap-northeast-1": ("JP", "Japan", "APPI", (35.7, 139.7)),
    "ap-northeast-2": ("KR", "South Korea", "PIPA", (37.6, 126.9)),
    "ap-southeast-1": ("SG", "Singapore", "PDPA-SG", (1.3, 103.8)),
    "ap-southeast-2": ("AU", "Australia", "Australia-Privacy-Act", (-33.9, 151.2)),
    "ap-south-1": ("IN", "India", "DPDPA", (19.1, 72.9)),
    "sa-east-1": ("BR", "Brazil", "LGPD", (-23.5, -46.6)),
}

_AZURE_LOCATIONS: Dict[str, Tuple[str, str, str, Tuple[float, float]]] = {
    "eastus": ("US", "USA", "US-Federal", (37.4, -78.7)),
    "eastus2": ("US", "USA", "US-Federal", (37.4, -78.7)),
    "westus": ("US", "USA", "US-Federal", (37.8, -122.4)),
    "westus2": ("US", "USA", "US-Federal", (47.6, -122.3)),
    "westus3": ("US", "USA", "US-Federal", (33.4, -112.1)),
    "centralus": ("US", "USA", "US-Federal", (41.6, -93.6)),
    "northeurope": ("IE", "Ireland", "GDPR", (53.3, -6.3)),
    "westeurope": ("NL", "Netherlands", "GDPR", (52.4, 4.9)),
    "uksouth": ("GB", "United Kingdom", "UK-GDPR", (51.5, -0.1)),
    "ukwest": ("GB", "United Kingdom", "UK-GDPR", (53.4, -3.0)),
    "francecentral": ("FR", "France", "GDPR", (48.8, 2.3)),
    "germanywestcentral": ("DE", "Germany", "GDPR", (50.1, 8.7)),
    "switzerlandnorth": ("CH", "Switzerland", "Switzerland-FADP", (47.4, 8.5)),
    "swedencentral": ("SE", "Sweden", "GDPR", (60.7, 17.1)),
    "japaneast": ("JP", "Japan", "APPI", (35.7, 139.7)),
    "australiaeast": ("AU", "Australia", "Australia-Privacy-Act", (-33.9, 151.2)),
    "brazilsouth": ("BR", "Brazil", "LGPD", (-23.5, -46.6)),
    "canadacentral": ("CA", "Canada", "PIPEDA", (45.5, -73.6)),
    "southeastasia": ("SG", "Singapore", "PDPA-SG", (1.3, 103.8)),
    "centralindia": ("IN", "India", "DPDPA", (18.5, 73.9)),
}

_GCP_REGIONS: Dict[str, Tuple[str, str, str, Tuple[float, float]]] = {
    "us-central1": ("US", "USA", "US-Federal", (41.3, -95.9)),
    "us-east1": ("US", "USA", "US-Federal", (33.2, -80.0)),
    "us-east4": ("US", "USA", "US-Federal", (39.0, -77.5)),
    "us-west1": ("US", "USA", "US-Federal", (45.6, -121.2)),
    "us-west2": ("US", "USA", "US-Federal", (34.0, -118.4)),
    "us-west3": ("US", "USA", "US-Federal", (40.8, -111.9)),
    "europe-west1": ("BE", "Belgium", "GDPR", (50.4, 4.4)),
    "europe-west2": ("GB", "United Kingdom", "UK-GDPR", (51.5, -0.1)),
    "europe-west3": ("DE", "Germany", "GDPR", (50.1, 8.7)),
    "europe-west4": ("NL", "Netherlands", "GDPR", (52.4, 4.9)),
    "europe-west9": ("FR", "France", "GDPR", (48.8, 2.3)),
    "europe-north1": ("FI", "Finland", "GDPR", (60.6, 27.2)),
    "asia-east1": ("TW", "Taiwan", "PDPA-TW", (24.1, 120.7)),
    "asia-northeast1": ("JP", "Japan", "APPI", (35.7, 139.7)),
    "asia-southeast1": ("SG", "Singapore", "PDPA-SG", (1.3, 103.8)),
    "australia-southeast1": ("AU", "Australia", "Australia-Privacy-Act",
                              (-33.9, 151.2)),
    "southamerica-east1": ("BR", "Brazil", "LGPD", (-23.5, -46.6)),
    "northamerica-northeast1": ("CA", "Canada", "PIPEDA", (45.5, -73.6)),
}

_REGION_TABLES: Dict[str, Dict[str, Tuple[str, str, str, Tuple[float, float]]]] = {
    "aws": _AWS_REGIONS,
    "azure": _AZURE_LOCATIONS,
    "gcp": _GCP_REGIONS,
}


@dataclass(frozen=True)
class RegionInfo:
    cloud: str
    region: str
    country_iso2: str
    jurisdiction: str
    regime: str
    geo: Tuple[float, float]


def lookup_region(cloud: str, region: str) -> RegionInfo:
    """Return canonical metadata for *cloud*/*region*.

    Raises :class:`KeyError` if the pair is unknown — callers must handle
    that explicitly so adding a brand-new region requires an explicit
    decision rather than a silent allow.
    """
    cloud = cloud.lower()
    if cloud not in _REGION_TABLES:
        raise KeyError(f"unknown cloud: {cloud!r}")
    table = _REGION_TABLES[cloud]
    if region not in table:
        raise KeyError(f"unknown region {region!r} for cloud {cloud!r}")
    iso, juris, regime, geo = table[region]
    return RegionInfo(cloud=cloud, region=region, country_iso2=iso,
                       jurisdiction=juris, regime=regime, geo=geo)


def known_regions() -> List[Tuple[str, str]]:
    return [(c, r) for c, t in _REGION_TABLES.items() for r in t]


# ---- policy --------------------------------------------------------------

@dataclass
class ResidencyPolicy:
    allowed_regions: List[Tuple[str, str]] = field(default_factory=list)
    """Whitelist of (cloud, region) tuples.  Empty list means *any region*
    that matches the country / jurisdiction allowlists below."""

    allowed_countries: List[str] = field(default_factory=list)
    """ISO 3166-1 alpha-2 country codes (e.g. ``DE``)."""

    allowed_jurisdictions: List[str] = field(default_factory=list)
    """Free-text jurisdictional names (``Germany``, ``EU``, ``USA``)."""

    allowed_regimes: List[str] = field(default_factory=list)
    """Data-protection regime tokens (``GDPR``, ``UK-GDPR``, ...)."""

    forbid_cross_region_replication: bool = True
    """If True, the evidence emitter records a ``no_cross_region`` claim
    and the validator rejects any resource that pins a different region
    than the deployment's primary region."""

    forbid_offshore_storage: bool = True
    """If True, the evidence emitter records a ``no_offshore_storage``
    claim.  Requires the caller to feed in resource locations."""

    require_signed_evidence: bool = True

    note: str = ""

    def validate(self) -> List[str]:
        errs: List[str] = []
        for c, r in self.allowed_regions:
            try:
                lookup_region(c, r)
            except KeyError as exc:
                errs.append(str(exc))
        for cc in self.allowed_countries:
            if not re.fullmatch(r"[A-Z]{2}", cc):
                errs.append(f"country {cc!r} must be ISO-3166-1 alpha-2")
        return errs

    def is_allowed(self, info: RegionInfo) -> Tuple[bool, str]:
        if self.allowed_regions:
            if (info.cloud, info.region) in self.allowed_regions:
                return True, ""
            # If a regions list is given, that's the authoritative gate.
            return False, (f"region {info.cloud}/{info.region} not in allowed_regions "
                            f"(have {len(self.allowed_regions)} entries)")
        if self.allowed_countries and info.country_iso2 not in self.allowed_countries:
            return False, (f"country {info.country_iso2} not in allowed_countries "
                            f"{self.allowed_countries}")
        if self.allowed_jurisdictions and \
                info.jurisdiction not in self.allowed_jurisdictions:
            return False, (f"jurisdiction {info.jurisdiction!r} not in "
                            f"allowed_jurisdictions {self.allowed_jurisdictions}")
        if self.allowed_regimes and info.regime not in self.allowed_regimes:
            return False, (f"regime {info.regime!r} not in allowed_regimes "
                            f"{self.allowed_regimes}")
        return True, ""


# ---- terraform plan / state inspection -----------------------------------

# Resource attributes that hold a region/location for the major providers.
_REGION_ATTRS = ("region", "location", "availability_zone", "aws_region")


def scan_terraform_for_regions(
    plan_or_state: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Walk a Terraform plan / state JSON and return every resource that
    pins a region/location attribute.

    Output rows::

        {"address": "module.x.aws_s3_bucket.b",
         "type": "aws_s3_bucket",
         "region": "eu-west-1",
         "attribute": "region"}
    """
    rows: List[Dict[str, Any]] = []

    def _walk_resources(resources: Iterable[Dict[str, Any]]):
        for r in resources or []:
            addr = r.get("address") or r.get("name") or r.get("type", "")
            type_ = r.get("type", "")
            values = (r.get("values") or
                      (r.get("change") or {}).get("after") or
                      r.get("attributes") or {})
            for attr in _REGION_ATTRS:
                v = values.get(attr) if isinstance(values, dict) else None
                if isinstance(v, str) and v:
                    rows.append({"address": addr, "type": type_,
                                  "region": v, "attribute": attr})
                    break
            # Recurse into modules.
            for child in r.get("child_modules", []) or []:
                _walk_resources(child.get("resources", []) or [])
                for grandchild in child.get("child_modules", []) or []:
                    _walk_resources(grandchild.get("resources", []) or [])

    if "values" in plan_or_state and isinstance(plan_or_state["values"], dict):
        root = plan_or_state["values"].get("root_module") or {}
        _walk_resources(root.get("resources", []))
        for child in root.get("child_modules", []) or []:
            _walk_resources(child.get("resources", []))
    if "planned_values" in plan_or_state and \
            isinstance(plan_or_state["planned_values"], dict):
        root = plan_or_state["planned_values"].get("root_module") or {}
        _walk_resources(root.get("resources", []))
        for child in root.get("child_modules", []) or []:
            _walk_resources(child.get("resources", []))
    if "resource_changes" in plan_or_state:
        _walk_resources(plan_or_state["resource_changes"])

    return rows


def _infer_cloud_for_region(region: str) -> Optional[str]:
    if region in _AWS_REGIONS:
        return "aws"
    if region in _AZURE_LOCATIONS:
        return "azure"
    if region in _GCP_REGIONS:
        return "gcp"
    return None


# ---- validator + evidence emitter ---------------------------------------

@dataclass
class ResidencyValidation:
    primary: RegionInfo
    primary_allowed: bool
    primary_reason: str
    cross_region_findings: List[Dict[str, Any]]
    out_of_policy_resources: List[Dict[str, Any]]

    @property
    def passed(self) -> bool:
        if not self.primary_allowed:
            return False
        return not self.out_of_policy_resources

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary": asdict(self.primary),
            "primary_allowed": self.primary_allowed,
            "primary_reason": self.primary_reason,
            "cross_region_findings": list(self.cross_region_findings),
            "out_of_policy_resources": list(self.out_of_policy_resources),
            "passed": self.passed,
        }


def validate_deployment(
    *,
    cloud: str, primary_region: str,
    policy: ResidencyPolicy,
    terraform_plan: Optional[Dict[str, Any]] = None,
) -> ResidencyValidation:
    info = lookup_region(cloud, primary_region)
    primary_ok, primary_reason = policy.is_allowed(info)

    cross: List[Dict[str, Any]] = []
    out_of_policy: List[Dict[str, Any]] = []

    if terraform_plan:
        rows = scan_terraform_for_regions(terraform_plan)
        for row in rows:
            r_region = row["region"]
            r_cloud = _infer_cloud_for_region(r_region) or cloud
            try:
                r_info = lookup_region(r_cloud, r_region)
            except KeyError:
                out_of_policy.append({**row, "reason": "unknown region"})
                continue
            allowed, reason = policy.is_allowed(r_info)
            if not allowed:
                out_of_policy.append({**row, "reason": reason})
            if r_region != primary_region and policy.forbid_cross_region_replication:
                cross.append(row)

    return ResidencyValidation(
        primary=info, primary_allowed=primary_ok, primary_reason=primary_reason,
        cross_region_findings=cross, out_of_policy_resources=out_of_policy,
    )


@dataclass
class ResidencyEvidence:
    document: Dict[str, Any]
    canonical_json: bytes
    document_sha256: str
    signature_hex: str
    public_key_pem: str

    def write(self, dest_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)) or ".",
                     exist_ok=True)
        with open(dest_path, "w", encoding="utf-8") as f:
            json.dump(self.document, f, indent=2)
            f.write("\n")
        sig_path = dest_path + ".sig"
        pub_path = dest_path + ".pub"
        with open(sig_path, "w", encoding="utf-8") as f:
            f.write(self.signature_hex)
        with open(pub_path, "w", encoding="utf-8") as f:
            f.write(self.public_key_pem)


def emit_residency_evidence(
    *,
    cloud: str,
    primary_region: str,
    policy: ResidencyPolicy,
    terraform_plan: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
    signing_key=None,
) -> ResidencyEvidence:
    """Run the validator and produce a signed evidence document."""
    validation = validate_deployment(
        cloud=cloud, primary_region=primary_region, policy=policy,
        terraform_plan=terraform_plan,
    )
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    doc = {
        "v": 1, "kind": "tee_crafter.residency_evidence",
        "generated_at": now,
        "policy": {
            "allowed_regions": list(policy.allowed_regions),
            "allowed_countries": list(policy.allowed_countries),
            "allowed_jurisdictions": list(policy.allowed_jurisdictions),
            "allowed_regimes": list(policy.allowed_regimes),
            "forbid_cross_region_replication": policy.forbid_cross_region_replication,
            "forbid_offshore_storage": policy.forbid_offshore_storage,
            "note": policy.note,
        },
        "validation": validation.to_dict(),
        "claims": {
            "data_residency_country": validation.primary.country_iso2,
            "data_residency_jurisdiction": validation.primary.jurisdiction,
            "data_protection_regime": validation.primary.regime,
            "no_cross_region": (
                policy.forbid_cross_region_replication
                and not validation.cross_region_findings
            ),
            "no_offshore_storage": (
                policy.forbid_offshore_storage and validation.passed
            ),
        },
        "extra": dict(extra or {}),
    }
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest_hex = hashlib.sha256(canonical).hexdigest()

    signer = signing_key or _Ed25519Signer()
    signature = signer.sign(canonical).hex()
    pub_pem = signer.public_key_pem()

    return ResidencyEvidence(
        document=doc, canonical_json=canonical,
        document_sha256=digest_hex, signature_hex=signature,
        public_key_pem=pub_pem,
    )


def verify_residency_evidence(
    document: Dict[str, Any], signature_hex: str, public_key_pem: str,
) -> Tuple[bool, str]:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pk = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(pk, Ed25519PublicKey):
            return False, "expected Ed25519 public key"
        pk.verify(bytes.fromhex(signature_hex), canonical)
        return True, ""
    except Exception as exc:
        return False, repr(exc)


class _Ed25519Signer:
    def __init__(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self._sk = Ed25519PrivateKey.generate()
        self._pem = self._sk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign(self, m: bytes) -> bytes:
        return self._sk.sign(m)

    def public_key_pem(self) -> str:
        return self._pem
