# TEE-Crafter Compliance Coverage

This document is the canonical reference for what TEE-Crafter's compliance
reports can and cannot evidence. It is intended for sales conversations,
auditor discussions, and internal planning.

## How Compliance Reports Work

Every `tee-crafter deploy` (`--batch` or `--persistent`) automatically
generates a `compliance/` directory alongside the build provenance. Reports
map **cryptographic and configuration evidence** from the build to controls
across 14 compliance frameworks.

For **non–GPU-CC** CPU-only TEE deployments, the engine does **not** require
GPU-only evidence keys (`gpu_confidential_computing`, `gpu_attestation`,
`dual_attestation_cpu_gpu`) when evaluating controls, so Nitro / SGX / SNP / TDX
workloads are not penalized for missing NRAS or dual-attestation artifacts.

Every control verdict is tagged with a responsibility scope:

- **product_evidence** -- TEE-Crafter can prove this from build/deploy/runtime artifacts.
- **customer_responsibility** -- Requires organizational policies and processes outside the product.
- **shared** -- Partially evidenced by the product; customer organizational controls also needed.

### What "satisfied" actually requires

"We never claim satisfied without proof" is only worth anything if the rule
behind it is written down, so here it is, from
`core/compliance/engine.py::evaluate_control`:

1. **Evidence must be *verified*, not merely collected.** A collector reports
 what it saw in the build provenance; whether an independent audit check
 confirmed it is the ledger's job. An evidence item counts as verified only
 when *every* backing `check_id` mapped to it has a row in
 `audit_evidence.json` with verdict `pass` (or `not_applicable`, which is
 neutral). A backing check that `fail`ed, `warn`ed, emitted `info`, was swept
 in as `not_evaluated`, or is simply absent leaves the item **unverified** and
 caps its strength at MODERATE (`evidence.py::_reconcile_with_ledger`).
2. **Coverage counts verified evidence only.** `coverage = verified / applicable`.
3. **`SATISFIED` requires `coverage == 1.0` *and* every matched item at STRONG
 strength.** Anything less is `PARTIAL` at best.
4. **Shared-responsibility controls never reach `SATISFIED`** — the best
 available verdict is `PARTIAL`, because the customer's organizational
 controls are outside what the product can evidence.
5. **A build with no ledger certifies nothing.** With no `audit_evidence.json`
 to reconcile against, nothing is verified, so no control can be satisfied.

`SATISFIED` requires actual proof, not partial coverage. A one-entry provenance
file with no ledger reports **0 satisfied / 93 gaps / 0.0% coverage** — an
engine that promoted a control at 50% coverage would report **68 satisfied / 0
gaps / 86.2%** for the same input, which is worse than no report. `SATISFIED` is
reachable: an all-passing ledger promotes 50 controls.

### A report with no audit ledger will show gaps. That is correct.

This is the single most likely thing to be reported as a bug, so it is worth
stating plainly: **a compliance report generated without a
`audit/audit_evidence.json` alongside the provenance will show `PARTIAL` and
`GAP` verdicts and 0% coverage.** Nothing is broken. Promotion to `SATISFIED`
requires the ledger to prove the backing checks passed, and with no ledger there
is nothing to reconcile against — so the engine reports what it can actually
substantiate, which is nothing.

If you are seeing unexpected gaps, check that you are pointing
`--file` at a provenance file whose sibling `audit/` directory came from the
same build.



---

## Frameworks Supported

### Tier 1: Core Regulated

| Framework | Version | Controls |
|-----------|---------|----------|
| HIPAA Technical Safeguards | 45 CFR 164.312 | 7 |
| SOC 2 Type II | TSC 2017 | 10 |
| PCI DSS | v4.0 | 9 |
| GDPR | Reg. (EU) 2016/679 | 8 |
| CCPA / CPRA | Cal. Civ. Code 1798 | 4 |

### Tier 2: Security Frameworks

| Framework | Version | Controls |
|-----------|---------|----------|
| NIST 800-53 Rev 5 | Rev 5 (2020) | 15 |
| NIST Cybersecurity Framework | CSF 2.0 (2024) | 8 |
| ISO/IEC 27001:2022 | Annex A | 9 |
| ISO/IEC 27701 | 2019 | 5 |
| HITRUST CSF | v11 | 8 |
| CSA Cloud Controls Matrix | v4.0 | 7 |
| EU NIS2 Directive | 2022/2555 | 6 |
| EU AI Act | Reg. 2024/1689 | 6 |

### Tier 3: Industry-Specific

| Framework | Version | Controls |
|-----------|---------|----------|
| GLBA Safeguards Rule | 16 CFR 314 | 8 |

**Total: 14 frameworks, 110 controls**, derived by enumerating
`build_default_registry.all`. Each framework module under
`apps/cli/src/tee_crafter/core/compliance/frameworks/` is the authoritative
control list.

### Four frameworks are deliberately not offered

CMMC 2.0, EU DORA, ISO/IEC 42001 and FedRAMP Moderate are **not** available as
report targets. Mapping them properly requires real control identifiers, and
placeholder IDs in a compliance report are worse than an absent framework —
an auditor cannot tell the difference until they check:

| Removed | Why |
|---|---|
| CMMC 2.0 Level 2 | Every ID was a `*.L2-b.1.D` placeholder, not a real practice identifier. |
| EU DORA | IDs were invented; none corresponded to an article number in Regulation 2022/2554. |
| ISO/IEC 42001 | Cited `A.11.2`; ISO/IEC 42001 Annex A ends at A.10. |
| FedRAMP Moderate | Used an invented `FedRAMP SC-8` prefix and duplicated NIST 800-53 incorrectly. |

The underlying standards are paywalled and could not be reconstructed offline,
so they were removed rather than shipped wrong. A mapping that cites control IDs
which do not exist is worse than no mapping — it fails the moment an auditor
looks one up. If you need any of these, map them yourself from the licensed text
against the evidence keys below.

The two counts most likely to be quoted at you — **18 frameworks / 138
controls** — are stale. Use 14 / 110.

---

## What TEE-Crafter Evidences Today (38 Categories)

These are extracted from `build_provenance.json` and deployment configuration:

| # | Evidence Key | Source | Strength |
|---|-------------|--------|----------|
| 1 | `tee_hardware_isolation` | TEE platform + measurement values (PCR, MRTD, etc.) | Strong |
| 2 | `ratls_attestation` | RA-TLS certificate binding to hardware attestation | Strong |
| 3 | `encryption_in_transit` | RA-TLS / ECIES end-to-end encryption | Strong |
| 4 | `encryption_at_rest` | Hardware TEE memory encryption | Strong |
| 5 | `zero_ingress_network` | Terraform security group / NSG / firewall analysis | Strong |
| 6 | `systemd_sandboxing` | Systemd unit hardening directives | Strong |
| 7 | `docker_hardening` | Seccomp, AppArmor, cap-drop, read-only rootfs | Strong |
| 8 | `hash_chain_integrity` | Provenance hash chain verification | Strong |
| 9 | `ed25519_signature` | Provenance Ed25519 signature verification | Strong |
| 10 | `ast_confinement` | **Legacy key id — no AST analysis happens.** OS-level workload confinement of the user container: `--cap-drop ALL`, custom seccomp profile, AppArmor MAC, no-new-privileges (`evidence.py::_ast_confinement`) | Moderate |
| 11 | `output_schema_validation` | Output handling: batch capture bundle + SIEM log redaction (legacy key id) | Moderate |
| 12 | `supply_chain_controls` | Pinned versions, offline install | Moderate |
| 13 | `ephemeral_keys` | No persistent TLS key storage | Strong |
| 14 | `build_reproducibility` | SHA-256 hashes of all build artifacts | Strong |
| 15 | `access_control` | SSM/Bastion/IAP-only access, tee_enclave user | Strong |
| 16 | `runtime_audit_logging` | Hash-chained request/response metadata log inside TEE | Strong |
| 17 | `continuous_attestation` | Periodic re-attestation with drift detection (300s default) | Strong |
| 18 | `vulnerability_scan` | Trivy/Grype CVE scan at build time (all flows: images + dependency lockfiles) | Moderate-Strong |
| 19 | `data_retention_controls` | Ephemeral TEE processing, no persistent plaintext, key destruction on shutdown | Strong |
| 20 | `key_rotation_evidence` | Attestation-bound ECDH key rotation with hash-chained log (default 3600s) | Strong |
| 21 | `vpc_isolation` | Per-deployment VPC/VNet with network flow logging (AWS VPC Flow Logs, GCP Subnet Flow Logs, Azure VNet flow logs + Traffic Analytics) | Strong |
| 22 | `gpu_confidential_computing` | NVIDIA GPU CC mode enabled; GPU memory hardware-encrypted; PCIe link status (encrypted on GCP/Azure, unencrypted on AWS) | Strong (GCP/Azure) / Moderate (AWS) |
| 23 | `gpu_attestation` | NVIDIA NRAS EAT JWT verifying GPU firmware, driver, and CC mode integrity | Strong |
| 24 | `dual_attestation_cpu_gpu` | Independent CPU-TEE and GPU-TEE attestation; client verifies both before data transmission | Strong (GCP/Azure) / Moderate (AWS) |
| 25 | `attestation_tls_binding` | RA-TLS hardening: SPKI / issuer checks, vTPM PCR extensions (GCP GPU CC), SNP AK binding | Strong |
| 26 | `tcb_freshness` | TCB / firmware-relevant version enforcement (SGX ISV SVN, TDX module, AMD Milan/Genoa chains, GCP `min_cpu_platform`) | Strong–Moderate |
| 27 | `attestation_issuer_allowlist` | Allowlisted attestation endpoints (MAA JWKS, Intel PCS, NRAS URL pins) | Strong–Moderate |
| 28 | `egress_lockdown_mode` | Terraform `setup_egress_mode` / NET-1: `locked-down` by default (mandatory pre-baked AMI). `open-for-setup` only when SIEM (`egress_mode=auto/public`) or the internal bake-ami pipeline explicitly needs public egress | Strong–Moderate |
| 29 | `kms_egress_scoping` | Nitro vsock-proxy / SG scoped toward KMS and attestation endpoints (Nitro-1) | Strong (Nitro) / Moderate (other) |
| 30 | `deployer_least_privilege` | AWS IAM scopes SSM SendCommand to explicit documents (RMT-2) | Strong (AWS) / Moderate (other clouds) |
| 31 | `audit_log_tamper_evidence` | Runtime audit log HMAC chain with genesis commitment (AUD-3) | Strong |
| 32 | `log_redaction` | Host proxy / server redaction of Authorization headers and sensitive payloads (LOG-1) | Strong |
| 33 | `dependency_hash_pinning` | `requirements.lock` + `pip --require-hashes` when used (F-15 / SUP-1) | Strong–Moderate |
| 34 | `script_hash_pinning` | SHA-256 verification of bootstrap script payloads (SUP-2) | Strong–Moderate |
| 35 | `container_digest_pinning` | Builder/base images referenced by digest (e.g. nitro-cli image, `FROM …@sha256:`) | Strong–Moderate |
| 36 | `measured_boot_vtpm` | vTPM PCR verification embedded in RA-TLS cert (F-8, GCP GPU CC only) | Strong–Moderate |
| 37 | `canonical_measurements_published` | Canonical `pcrs.json` (or equivalent) with EIF (Nitro-7, Nitro only) | Strong–Moderate |
| 38 | `workload_egress_allowlist` | Workload egress restricted to the `--egress-allow` destinations; backed by `EGR-005` / `EGR-006` | Strong–Moderate |

---

## What Requires Customer Organizational Controls

The following areas are **outside the scope** of TEE-Crafter product evidence.
Reports mark these as `customer_responsibility` with guidance on what is needed.

### Governance and Risk
- Information security policies (ISO 27001 A.5.1, SOC 2 CC1.1)
- Risk assessment and risk treatment (SOC 2 CC3.1, GLBA 314.4(b), NIST CSF GV.RM-01)
- Board/management oversight and commitment to integrity

### Human Resources
- Personnel screening and background checks (ISO 27001 A.6.1)
- Security awareness training and education
- Employee onboarding/offboarding access management

### Legal and Privacy
- Lawful basis for processing (GDPR Art 6)
- Data processing agreements (GDPR Art 28)
- Consumer deletion request intake and verification (CCPA 1798.105, GDPR Art 17).
 *Note: TEE-Crafter provides `data_retention_controls` evidence (ephemeral
 processing, key destruction) — customer handles request intake.*
- Privacy notices and consent mechanisms
- Cross-border data transfer documentation (ISO 27701 7.5.1)

### Incident Response
- Security incident reporting channels (HITRUST 12.a)
- Incident response and forensic investigation procedures (NIST CSF RS.AN-01)
- Breach notification processes

### Physical Security
- Physical access controls for data environments (PCI DSS Req 9.4)
- Data center physical security

### Vendor and Third-Party
- Vendor security assessment programs
- Third-party risk management
- Independent third-party assessment (e.g. a FedRAMP 3PAO, a SOC 2 auditor)

### Audit and Compliance Process
- SOC 2 Type II continuous evidence collection (beyond build pipeline)
- Continuous-monitoring programs required by your framework
- PCI DSS quarterly scanning and annual assessment
- Internal audit schedules

---

## Product Evidence (shipped)

The following evidence categories are produced by every build and
moved into `product_evidence` (i.e. no longer
`customer_responsibility` or `shared`):

- **Runtime audit logging** -- Hash-chained metadata-only logging of all
 request/response activity inside the TEE (`tee_crafter_audit_logger.py`).
- **Continuous attestation monitoring** -- Background daemon that periodically
 re-attests and detects measurement drift
 (`tee_crafter_attestation_monitor.py`).
- **Automated vulnerability scanning** -- Trivy/Grype integration scans the
 user's built container image at build time; because the scan runs against the
 assembled image it covers OS packages and every transitive dependency layer,
 not just the app's direct requirements. Results are recorded in the audit
 trail and compliance reports, and CRITICAL/HIGH findings gate the deploy
 (`VLN-*`). Closes the PCI DSS Req 6.3/11.3 vulnerability-management gap.
- **Data retention & destruction evidence** -- A `data_retention_controls`
 evidence type proving ephemeral TEE processing, no persistent plaintext,
 and key destruction on shutdown. Mapped to GDPR Art 17, CCPA 1798.105,
 HIPAA 164.310(d), ISO 27001 A.8.10, GLBA 314.4(c)(7).
- **Shared Responsibility Matrix (SRM)** -- Every build generates
 `shared_responsibility_matrix.html` + `.pdf` for auditor handoff. Covers
 all 110 controls across 14 frameworks with TEE-Crafter vs Customer scope
 columns. HTML and PDF matrices include the full report ID and provenance
 chain head hash in the footer for traceability.
- **Key rotation evidence** -- Attestation-bound ECDH key rotation with
 hash-chained tamper-evident log. Every rotation records key fingerprints,
 reason, lifetime, requests served, and fresh attestation measurement.
 Deployed to all 10 platform templates (`tee_crafter_key_rotation.py`).
- **Per-deployment VPC isolation with flow logging** -- Each AWS deployment
 creates a dedicated VPC (not the default VPC) with its own private subnet,
 security group, VPC endpoints, and CloudWatch VPC Flow Logs (60s
 aggregation, 30-day retention). GCP deployments enable subnet flow logs
 (5s aggregation, 100% sampling, full metadata). Azure deployments use VNet
 flow logs with Traffic Analytics to a per-deployment Log Analytics
 workspace (10-minute aggregation, 30-day retention).

## Future work

Evidence categories on the roadmap (planned, not yet shipped):

- **Backup and disaster recovery evidence** -- Automated DR testing with
 provenance of recovery procedures.
- **Hosted compliance dashboard** -- Upload compliance reports, track trends,
 alert on regressions. JSON schema is dashboard-ready from the start.
- **Continuous compliance monitoring** -- Real-time control status via an
 agent deployed alongside TEE workloads.
- **Automated questionnaire filling** -- Pre-fill SIG Lite, CAIQ, and vendor
 security questionnaires from compliance report data.

---

## Per-Framework Responsibility Matrix

### HIPAA

| Control | Responsibility | Notes |
|---------|---------------|-------|
| 164.312(a)(1) Access Control | Product | TEE isolation + zero-ingress |
| 164.312(a)(2)(iv) Encryption | Product | TEE memory encryption |
| 164.312(b) Audit Controls | Product | Hash chain + Ed25519 + runtime audit logs |
| 164.312(c)(1) Integrity | Product | Hash chain + continuous attestation |
| 164.310(d)(2)(i) Disposal | Shared | Ephemeral keys + no persistent plaintext; org disposal policies needed |
| 164.312(d) Authentication | Shared | Hardware attestation; org access review needed |
| 164.312(e)(1) Transmission Security | Product | RA-TLS / ECIES |

### SOC 2

| Control | Responsibility | Notes |
|---------|---------------|-------|
| CC6.1 Logical Access | Product | TEE + systemd sandboxing |
| CC6.6 System Boundaries | Product | Zero-ingress + Docker hardening |
| CC6.7 Data Transmission | Product | RA-TLS encryption |
| CC7.1 Monitoring | Product | Hash chain integrity |
| CC7.2 Anomaly Detection | Shared | Partial: continuous re-attestation + SIEM export; org detection rules needed |
| CC8.1 Change Management | Product | Build reproducibility |
| CC1.1 Integrity Values | Customer | Organizational policy |
| CC2.1 Communication | Customer | Organizational policy |
| CC3.1 Risk Assessment | Customer | Organizational policy |
| PI1.1 Processing Integrity | Product | Batch output bundle (encrypted / signed / size-capped) + container confinement |

### NIST 800-53

| Control | Responsibility | Notes |
|---------|---------------|-------|
| SC-8 Transmission Security | Product | RA-TLS |
| SC-12 Key Management | Product | Ephemeral keys + attestation |
| SC-28 Data at Rest | Product | TEE memory encryption |
| SC-13 Crypto Protection | Product | Full crypto stack |
| AU-2 Event Logging | Product | Provenance hash chain + runtime audit logs |
| AU-6 Audit Review | Shared | Chain verification + runtime logs; org review needed |
| AU-10 Non-repudiation | Product | Ed25519 signature |
| CM-3 Change Control | Product | Build reproducibility |
| CM-6 Configuration | Product | Systemd + Docker hardening |
| SA-11 Developer Testing | Shared | Trivy/Grype image + dependency scanning; org testing needed |
| SI-7 Integrity Verification | Product | Continuous attestation + hash chain |
| RA-5 Vulnerability Scanning | Shared | Trivy/Grype scan (images + deps); org remediation needed |
| AC-3 Access Enforcement | Product | TEE + zero-ingress |
| AC-4 Information Flow | Product | TEE + schema validation |
| SC-7 Boundary Protection | Product | Per-deployment VPC + flow logs + zero-ingress |

---

## Using the Reports

### Automatic (every build)
```
tee-crafter deploy --source./my-app --tee-platform nitro-aws
# -> builds/my-app_nitro_build_TIMESTAMP_DEPLOYID/compliance/
```

### Standalone (from existing provenance)
```
tee-crafter compliance report --file builds/.../build_provenance.json
tee-crafter compliance report --file builds/.../build_provenance.json --frameworks hipaa,soc2
```

### List frameworks
```
tee-crafter compliance list
```

### Shared Responsibility Matrix (for auditors)
Every build automatically generates `compliance/shared_responsibility_matrix.html`
and `compliance/shared_responsibility_matrix.pdf`. These list every control across
all 14 frameworks with columns for **TEE-Crafter scope** and **Customer scope**,
with **Report ID** and **chain head (SHA-256)** in the footer for cryptographic
traceability to `build_provenance.json`.
