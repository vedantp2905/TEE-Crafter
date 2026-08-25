# Audit evidence matrix

Every TEE-Crafter build produces a structured evidence ledger
(`audit/audit_evidence.json`) alongside the hash-chained
`provenance/build_provenance.json`. Each row in the ledger corresponds
to one `check_id` drawn from this catalogue. Rows are emitted by:

## On-disk build layout

The build directory is split into kind-specific subfolders so an
operator can see at a glance what was emitted by which subsystem:

```
builds/<id>/
├── audit/ audit evidence ledger (json/txt/md/html + sig)
├── provenance/ hash-chained build provenance (json/txt + sig + pubkey)
├── slsa/ SLSA in-toto statement + DSSE envelope + pubkey
├── siem/ SIEM config (json + sanitised env + egress allowlist)
├── byok/ BYOK config (json + sanitised env)
├── compliance/ rendered compliance reports
├── probes/ post-deploy probe stdout/stderr
├── client_output.json the verifier client's verdict (or.txt if not JSON)
├── client_stderr.log the verifier client's *reasoning* — see below
└──... runtime + terraform staging stay at the top level
```

`client_stderr.log` is kept deliberately, and on failing runs too. The client
writes its verdict to stdout but its *reasoning* to stderr: which binding mode
held, which certificate chain it walked, which TCB fields it compared, which
PCRs matched. Retaining only the verdict meant an auditor could see that
attestation passed but not what was checked — and on a failure, the one artefact
that explains why was the one being discarded. `record_client_evidence_paths`
binds both filenames into the audit chain, so the evidence is named in the
signed ledger rather than merely present on disk.

`tee-crafter verify-provenance --file <build_dir>/provenance/build_provenance.json`
auto-resolves the sibling ledger and signature artefacts. Older builds
that were emitted with a flat layout also verify — every reader
resolves the canonical subdir path first and falls back to the
top-level filename when the subdir copy isn't there.

- **Pipeline** — collected at build time: dev-hatch flags, dependency
 vulnerability scan results, packaging hygiene, IaC static checks,
 Terraform apply outcomes, BYOK / SIEM sidecar wiring.
- **Probe** — collected after the instance comes up via SSM
 RunCommand (AWS), bastion SSH (Azure), or IAP-tunnelled SSH (GCP).
- **Cloud audit** — collected post-deploy by querying AWS CloudTrail,
 Azure Activity Log, or GCP Audit Logs.

The `tee-crafter verify-provenance --ledger <path>` command renders the
matrix and can gate CI exit codes on a required-check list.

## Verdict semantics

| Verdict | Meaning |
| ----------------- | ------------------------------------------------------------------------------------------------------- |
| `pass` | Observed value matched the expected value. |
| `fail` | Observed value did NOT match the expected value. CI must fail closed. |
| `warn` | Evidence couldn't be collected (e.g. missing IAM permission, probe couldn't reach the instance). |
| `not_applicable` | The check does not apply to this `tee_platform` or this configuration (e.g. BYOK env relocation on Nitro). |
| `info` | Informational row recorded for posterity; no gate. |

## Severities

- `critical` — Failing the check means the deployment cannot be trusted (e.g. BYOK unwrap mode wrong, attestation issuer not in the allowlist).
- `high` — Production posture violation (e.g. SIEM signing off, SSH ingress allowed in the security group).
- `moderate` — Operational hardening gap (e.g. probe couldn't run a particular sub-check).
- `informational` — Defaults captured for the audit trail.

## Categories

The catalogue is organised into 16 categories. Counts shown reflect the
catalogue as shipped; the catalogue is the source of truth — refer to
`apps/cli/src/tee_crafter/core/audit/checks.py` for any additions.

| Category | Theme | Count |
| -------- | -------------------------------------------------------- | ----- |
| PC | Pipeline configuration & build runtime | 9 |
| DH | Configurable env knobs (production posture) | 17 |
| PKG | Packaging / Docker image hygiene | 8 |
| VLN | Vulnerability scan thresholds + supply-chain pinning | 6 |
| IAC | Terraform static checks | 9 |
| IAM | Caller identity, policy simulation, instance role | 5 |
| DEP | Terraform apply outcome | 5 |
| PDR | Post-deploy runtime probes (SSM / Bastion / IAP) | 11 |
| ATT | Runtime attestation (every row driven by `client.py`) | 10 |
| SIEM | SIEM provider, sidecar, egress posture | 7 |
| BYOK | Customer-managed key release + sealed `.env` | 14 |
| EGR | Egress lockdown + workload allowlist | 6 |
| RES | Data residency (deploy-region policy gate) | 1 |
| CT | Cloud-audit log lookups | 7 |
| TEAR | Teardown / post-destroy hygiene | 6 |
| PROV | Provenance artefact integrity | 7 |

### Absence is not evidence: `not_evaluated` rows

Not every catalogued `check_id` produces a verdict on every build, and some
produce one on no build at all. As of this writing, **12 of the 128 catalogued
ids have no emitter anywhere in `apps/cli/src/tee_crafter/`**:

`BYOK-006`, `BYOK-008`, `BYOK-009`, `CT-004`, `DEP-003`, `EGR-003`, `PC-005`,
`PKG-004`, `PKG-007`, `PKG-008`, `SIEM-004`, `VLN-005`

Do not wait for those rows to show a `pass`; nothing produces one today.

To keep that visible rather than silent, `AuditEvidenceLedger.save` runs
`sweep_not_evaluated` before writing (`core/audit/ledger.py`, lines 210–243).
It adds an explicit `not_evaluated` row — carrying the catalogue's remediation
hint and the expected `source_kind` — for every catalogue check that applies to
this build's platform and was never recorded. So every row you read in this
document has a matching row in `audit_evidence.json`, and a check the pipeline
simply never ran is distinguishable from one that ran and passed.

A `not_evaluated` row fails a `--required-checks` gate exactly as a missing row
would; it just tells you why. Checks that are platform-filtered out of this
build are skipped by the sweep — their absence is correct, not a gap.

This also covers the ordinary case where a check *has* an emitter but did not
get to run: the runtime probe (`PDR-*` / `SIEM-003`) could not reach the host,
or the cloud-audit reader (`CT-*`) lacked the IAM permission.

The 12-id list is a mechanical count: catalogue ids from `CHECKS` in
`core/audit/checks.py` that appear nowhere else under
`apps/cli/src/tee_crafter/`. Re-derive it with:

```bash
python3 - <<'PY'
import sys, os
sys.path.insert(0, "apps/cli/src")
from tee_crafter.core.audit.checks import CHECKS
src = "apps/cli/src/tee_crafter"
blob = {}
for dp, dns, fns in os.walk(src):
    dns[:] = [d for d in dns if d != "__pycache__"]
    for f in fns:
        p = os.path.join(dp, f)
        try:
 blob[p] = open(p, encoding="utf-8", errors="ignore").read
        except OSError:
            pass
missing = [i for i in sorted(CHECKS)
 if not any(i in c for p, c in blob.items
                      if not p.endswith("checks.py"))]
print(len(CHECKS), "catalogued;", len(missing), "with no emitter:", ", ".join(missing))
PY
```

Last run: `128 catalogued; 12 with no emitter`, matching the list above and the
per-category counts in the table. If you see a different number, this document
is the thing that is stale, not the catalogue.

> **Ignore the figure in the code here.** `sweep_not_evaluated`'s own docstring
> (`core/audit/ledger.py:216`) still says "15 of the 128 catalogued ids had no
> emitter at all". That was the count from an earlier pass; three of those ids
> have since gained emitters. The command above is authoritative. Correcting the
> docstring is a code change.


## Production defaults (the DH-* dev-hatch surface)

Every `TEE_CRAFTER_*` and `TF_VAR_*` knob that gates security-relevant
behaviour is **production-safe when left unset**. The catalogue's
`default_expected` value is the production-correct observation, the
audit emits a `DH-*` row recording the actual observed value, and the
`verify-provenance --required-checks auto` gate fails closed when any
of the high-severity rows below is flipped to a development posture.

| ID | Env / TF var | Production default | Dev posture (FAIL) | Effect when flipped |
|----|--------------|--------------------|--------------------|---------------------|
| `DH-001` | `TEE_CRAFTER_PROXY_STRICT_IMDS` | `1` (refuse env-cred fallback) | `0` | Nitro host-proxy may source AWS creds from laptop env vars. AWS only. |
| `DH-002` | `TEE_CRAFTER_PROXY_NO_CREDS` | `0` (forward creds to enclave) | `1` | Nitro enclave cannot reach AWS — test-only knob. |
| `DH-003` | `TEE_CRAFTER_NRAS_STRICT` | `1` (no broad-internet fallback) | `0` | GPU-CC attestation may egress to any HTTPS endpoint. |
| `DH-004` | `TEE_CRAFTER_STRICT_TSM` | `1` (configfs-TSM only) | `0` | TDX-GCP / GPU-CC-GCP silently fall back to `/dev/tdx-guest` ioctl. |
| `DH-005` | `TEE_CRAFTER_SIEM_FAIL_OPEN` | `0` (fail-closed) | `1` | In-TEE gate keeps serving even when SIEM channel is dark. Only bites on the 8 CVM platforms; on `nitro-aws` / `sgx-azure` the gate is inert either way (host-side sidecar — see security.md §17.6). |
| `DH-006` | `TEE_CRAFTER_ALLOW_VULNERABLE` | unset (block on *fixable* CRITICAL/HIGH CVE) | any truthy value | Trivy/Grype gate is bypassed entirely; recorded as `gate_allowed=true`. Prefer a checked-in `.trivyignore` for specific accepted IDs — it leaves every other finding blocking. |
| `DH-007` | `TEE_CRAFTER_ACCEPT_PARTIAL_CC` | unset | any truthy value | `gpu-cc-aws` partial-confidential acknowledgement. |
| `DH-008` | `TEE_CRAFTER_STRICT_SNP_AK_BINDING` | `1` (AK bound via REPORT_DATA, or via HCL runtime data on Azure) | `0` | Accepts a TPM quote whose AK nothing vouches for. |
| `DH-009` | `TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS` | unset | `1` | Skips Intel TCB status evaluation entirely on all four Intel DCAP platforms — accepts an out-of-date or revoked platform TCB. Replaces the retired `TEE_CRAFTER_TDX_ALLOW_MISSING_QE_IDENTITY`, whose hand-copied QE-SVN floor was deleted in favour of signed collateral. |
| `DH-010` | `TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL` | unset | `1` | Per-build ephemeral Ed25519 keypair — verifiers cannot pin pubkey across builds. |
| `DH-011` | `TEE_CRAFTER_SKIP_POST_DESTROY_SHRED` | unset | `1` | Keys + sensitive tfstate retained after teardown. |
| `DH-012` | `TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE` | unset | `1` | Pipeline Docker image kept after destroy. |
| `DH-018` | `TEE_CRAFTER_TCB_ALLOW_STATUS` | unset (accept `UpToDate` only) | `SWHardeningNeeded` / `ConfigurationNeeded` / `ConfigurationAndSWHardeningNeeded` | Widens the accepted `tcbStatus` set. `OutOfDate` and `Revoked` are refused under every policy; naming one here fails the run. |
| `DH-013` | `TF_VAR_allow_nras_broad_internet` | `false` | `true` | GPU-CC firewall opens 443/tcp to the world (NRAS egress). |
| `DH-014` | `TF_VAR_allow_setup_egress` | `false` | `true` | Setup-time SG/NSG/firewall keeps a broad egress open instead of closing post-bootstrap. |
| `DH-015` | `TF_VAR_enable_secure_boot` | `true` | `false` | AWS instance launches without UEFI Secure Boot enrolled. |
| `DH-016` | `TF_VAR_byok_aws_kms_arn` | auto-exported from `--byok-config` | unset when BYOK is on | snp-aws / gpu-cc-aws instance role never gets `kms:Decrypt` on the customer key. |
| `DH-017` | `TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI` | unset | `1` | Deploy runs on a stock public AMI instead of a baked image. |

> `DH-017`'s check title in the code reads `--allow-unbaked-ami not used`
> (`core/audit/checks.py:285`), but **there is no such CLI flag**. `deploy`
> passes `allow_unbaked_ami=False` unconditionally
> (`cli/commands/deploy/deploy_container.py:329`), so the environment variable
> is the only way to trip this row. Renaming the check title is a code change.

`SIEM-002` is recorded with `expected=False` against the resolved
`fail_open` value: when the JSON config (or the env override) sets
`fail_open=true`, the row lands as `fail` and the note records whether
the env var pushed it there.

### Auto-exported BYOK Terraform vars

When `--byok aws-kms` is paired with `--byok-config` on `snp-aws` or
`gpu-cc-aws`, the CLI copies the policy `key_id` into
`TF_VAR_byok_aws_kms_arn` before `terraform apply` so the instance
role IAM block actually gains `kms:Decrypt` on the customer key.
The same helper also sets the **in-TEE reachability** flags for the
other clouds so the boot-time release can reach the key endpoint under
deny-all egress: `--byok gcp-kms` on `snp/tdx/gpu-cc -gcp` sets
`TF_VAR_byok_gcp_kms=true` (private `googleapis.com` DNS zone → restricted
VIP), and `--byok azure-kv` **or** `--byok azure-skr` on
`snp/tdx/gpu-cc -azure` sets `TF_VAR_byok_azure_kv=true`
(`Microsoft.KeyVault` service endpoint + NSG allow to the `AzureKeyVault`
service tag). Both providers set the same flag because both need the same
network path; they differ only in who performs the unwrap.

That one flag now opens two destinations on the Azure CVMs, because Secure Key
Release attests before it releases: the same `byok_azure_kv` gate also emits an
`AllowMaaEgressForSkr` rule to the `AzureAttestation` service tag, or to
`TF_VAR_maa_endpoint_cidr` when a Private Endpoint is configured. It also
attaches a system-assigned managed identity to the VM, without which the
`release` call has no principal to authenticate as; `vm_identity_principal_id`
is the Terraform output the operator grants `release` to.

Separately, on `tdx-azure` with `azure-guest` evidence, the deploy sets
`TF_VAR_attest_maa_egress=true` so the TD can reach MAA for *attestation* —
independent of BYOK, since there MAA is the trust root rather than a key-release
step.
Operator-supplied env values are never overwritten. `DH-016` records
the outcome. See [`docs/byok.md`](byok.md) for the wiring details
and [`apps/cli/src/tee_crafter/cli/commands/deploy/byok_mode.py`](../apps/cli/src/tee_crafter/cli/commands/deploy/byok_mode.py)
(`export_byok_tf_vars`) for the implementation.

### Fail-closed gates wired end-to-end

| Subsystem | Code anchor | Behaviour |
|-----------|-------------|-----------|
| SIEM in-TEE refusal | [`siem_health.assert_siem_healthy`](../apps/cli/src/tee_crafter/templates/common/siem_health.py) | Every attested request routes through `fail_closed_wrap` on the platform RA-TLS server (`app.template.py` per platform). When the SIEM health file is stale, missing, or carries a non-`pass` last export, the gate returns `{"error":"siem_blackout"}` instead of touching user code. **Armed on the 9 platforms that serve requests** — the 8 CVMs plus `nitro-aws`, which joined in 2026-08 when its exporter moved inside the enclave. `sgx-azure` is the sole exception: it is batch-only, so there is no request path for the wrapper to guard, `is_fail_closed` is `False` in-TEE, and request-time export is detective rather than preventive. Its preventive control is the withheld output bundle (`batch._withhold_output_if_unaudited`) instead. Enforced as `siem_sidecar.PREVENTIVE_GATE_PLATFORMS` / `DETECTIVE_ONLY_GATE_PLATFORMS`. |
| BYOK orchestrator | [`KeyReleaseOrchestrator.release`](../apps/cli/src/tee_crafter/core/keys/release.py) | Raises `KeyReleaseError` on stale attestation (`age > max_attestation_age_seconds`), measurement-not-in-allowlist, missing encryption-context keys, mismatched required provider, or any adapter `preflight` failure. Every failure is captured as a signed `key_release_decision` audit row before the call returns. |
| Provenance signing | [`core/audit/signing.py`](../apps/cli/src/tee_crafter/core/audit/signing.py) | When no long-lived key is configured and `TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL` is unset, the signer refuses to run — the build directory keeps `build_provenance.json` but emits a `signing_error.txt` breadcrumb and `PROV-002`/`PROV-007` fail closed. |
| Vulnerability scan | [`flow_container._emit_container_vln_verdicts`](../apps/cli/src/tee_crafter/cli/commands/deploy/flow_container.py) | When Trivy/Grype reports CRITICAL/HIGH count above threshold and `TEE_CRAFTER_ALLOW_VULNERABLE` is unset, the deploy aborts before `terraform apply`. |

## Remediation playbook

The full per-row remediation hint is encoded in
`apps/cli/src/tee_crafter/core/audit/checks.py` (`CheckSpec.remediation`). For
the high-traffic failure modes:

- **ATT-002 / ATT-003 fail** — The runtime verifier rejected the
 attestation report's signature or measurement. Re-run; if persistent,
 audit `trusted_roots/` (vendor root CA bundle) and
 `measurements.json` (expected PCR / MRENCLAVE / MRTD / RTMR) against
 the TEE family you deployed.
- **ATT-004 warn** — The runtime client did not emit an ``issuer``
 field. Either the deploy pipeline never reached `Phase 5: Post-
 Deploy` (probe / connectivity issue), or the per-platform client
 template is on an older revision that did not surface the issuer.
- **ATT-009 / ATT-010 fail (GPU-CC only)** — NVIDIA NRAS rejected the
 GPU attestation JWT, or the CPU TEE quote and the NRAS token are
 not bound to the same nonce. Check `NVIDIA_NRAS_API_KEY` and the
 GPU client.py revision.
- **BYOK-002 fail** — The wrap mode in `byok-config.json` does not match
 what this `tee_platform` requires. For Nitro / Azure SNP / GCP CC the
 wrap mode must be `dek_then_kek` (DEK encrypted in the TEE, KEK
 released via attestation). Regenerate the BYOK config with the
 unified `tools/generate_byok_config.py` script.
- **SIEM-002 fail** — `TEE_CRAFTER_SIEM_FAIL_OPEN=1` was set. This is
 a configurable knob only; unset it (or set it explicitly to `0`)
 for any deploy intended for production. Failure-mode is also
 surfaced as `DH-005`.
- **IAC-002 / IAC-003 fail** — The Terraform template would have
 permitted `0.0.0.0/0` SSH or HTTPS ingress. Tighten
 `tf_var.ingress_cidrs` and re-render the build dir.
- **EGR-002 fail** — An ``egress {... }`` block in `main.tf` still
 permits `0.0.0.0/0`. Tighten the egress CIDRs to the SIEM and KMS
 endpoint set, or move the broad block behind `allow_setup_egress`
 (which is auto-closed once cloud-init completes).
- **EGR-005 / EGR-006** — Workload egress for databases and 3rd-party
 APIs. `EGR-005` confirms egress is deny-by-default or constrained to
 an explicit `--egress-allow host:port` allowlist; `EGR-006` confirms
 that allowlist contains no `0.0.0.0/0`. The resolved destinations are
 recorded in `workload_egress.json`. Use `--egress-mode vpc` for a
 private database inside the VPC (no NAT) or `--egress-mode nat` for a
 public endpoint (NAT route, but the SG stays locked to the resolved
 CIDRs).
- **PDR-004 fail** — IMDSv1 is reachable on the deployed AWS instance.
 Run `aws ec2 modify-instance-metadata-options --http-tokens required`
 on the instance (or wipe + re-deploy with
 `TF_VAR_enable_imdsv2_only=true`).
- **PROV-002 fail / PROV-003 fail** — The build provenance signature
 isn't valid against the pinned public key. Verify
 `build_provenance.pub.sha256` matches your CI's pinned audit key. If
 this is a one-off build with the ephemeral keypair, run with
 `--require-longlived` set false (audit-only mode).
- **CT-001 / CT-002 warn** — The caller running `tee-crafter` lacks
 `cloudtrail:LookupEvents`, **or** CloudTrail returned zero events in
 the lookback window (common right after teardown — events can lag
 several minutes). Attach the `TeeCrafterDataOps` policy (which already
 includes `cloudtrail:LookupEvents`) and re-check with a wider window
 if BYOK sidecar logs show a successful unwrap (`BYOK-007` pass).
- **CT-003 warn (nitro-aws only)** — Data-plane KMS activity on the
 customer key was seen but no event carried a Nitro `Recipient` block.
 Expected when the smoke workload never calls `kmstool-enclave-cli`
 inside the enclave during the short deploy window.
- **CT-006 warn (GCP)** — No `cloudkms` decrypt events in the audit log
 filter. Enable **Cloud KMS → Data Access** audit logs (Admin Read +
 Data Read + Data Write) on the project, or confirm
 `roles/logging.viewer` on the deployer principal. See
 [docs/gcp_setup.md](gcp_setup.md).
- **TEAR-002 fail** — `TEE_CRAFTER_SKIP_POST_DESTROY_SHRED=1` was set
 during teardown. Re-run teardown without that flag, or manually
 shred the artefacts under `<build_dir>/post_destroy_shred/`.

## CI gate example

```bash
tee-crafter verify-provenance \
  --file builds/.../build_provenance.json \
  --ledger builds/.../audit_evidence.json \
  --required-checks "auto" \
  --pinned-pubkey-sha256 <YOUR_PUBKEY_FINGERPRINT> \
  --require-longlived
```

The `--required-checks auto` flag uses the per-platform list returned
by `tee_crafter.core.audit.checks.required_checks_for(tee_platform)`.
The catalogue-defined default required gate is:

- **PC** — `PC-001`, `PC-006`, `PC-007`, `PC-008`, `PC-009`
- **DH** — `DH-001` (AWS only), `DH-005`, `DH-006`, `DH-010`, `DH-011`
- **VLN** — `VLN-002`
- **IAC** — `IAC-001`, `IAC-002`, `IAC-003`
- **DEP** — `DEP-001`, `DEP-002`
- **ATT** — `ATT-001`, `ATT-002`, `ATT-003`, `ATT-004`, `ATT-005`,
 `ATT-006` (the full runtime gate: receive → chain valid → measurement
 match → issuer allowlist → TCB freshness → nonce binding)
- **TEAR** — `TEAR-001`
- **PROV** — `PROV-002`, `PROV-006`, `PROV-007`

After per-platform filtering, the resolved list shipped with each
build is:

| Platform | Required check IDs |
|----------|--------------------|
| `nitro-aws` / `snp-aws` / `gpu-cc-aws` | `PC-001`, `PC-006`, `PC-007`, `PC-008`, `PC-009`, `PROV-002`, `PROV-006`, `PROV-007`, `DH-001`, `DH-005`, `DH-006`, `DH-010`, `DH-011`, `VLN-002`, `IAC-001`, `IAC-002`, `IAC-003`, `DEP-001`, `DEP-002`, `ATT-001`–`ATT-006`, `TEAR-001` |
| `snp-azure` / `tdx-azure` / `sgx-azure` / `gpu-cc-azure` / `snp-gcp` / `tdx-gcp` / `gpu-cc-gcp` | same as above minus `DH-001` (`TEE_CRAFTER_PROXY_STRICT_IMDS` is AWS-only) |

`tee_platform` is persisted into `build_provenance.json` itself, so
`--required-checks auto` resolves the per-platform list even without
an explicit `--ledger`. Add more rows by passing an explicit
comma-separated list to `--required-checks`.

### ATT / SIEM under the unified execution model (plan 00)

The ATT and SIEM evidence still applies to the Dockerfile model, but the
*source* of the runtime evidence depends on the run mode:

| Run mode | ATT evidence | SIEM / continuous attestation |
|----------|--------------|-------------------------------|
| **`--persistent`** (VM-class TEEs: nitro/snp/tdx/gpu-cc) | boot attestation **+** the attested ingress proxy's live RA-TLS re-attestation (`ATT-008` pulses) | streamed from the proxy / host re-attest loop |
| **`--batch`** (all platforms, incl. **`sgx-azure` via GSC**) | deploy-time attestation document + signed audit bundle only (no live client channel) | deploy-time SIEM gate only |

`sgx-azure` is **batch-only** for v1, so its ATT assurance is always the
deploy-time attestation + bundle path; there is no attested proxy or live
re-attest loop for SGX. `ATT-001`–`ATT-006` remain the deploy-time verifier
gate on every platform; `ATT-008` (continuous-attestation pulses) is only
expected for `--persistent` VM-class runs.

## How the matrix is rendered

`save_audit_trail` writes four sibling files under `audit/`:

| File | Purpose |
|------|---------|
| `audit_evidence.json` | Signed (Ed25519 over canonical JSON) machine-readable ledger. CI / SIEM ingest. |
| `audit_evidence.txt` | Human-readable matrix grouped by category, with per-row `expected`/`observed`/`evidence_pointer`/`note`. |
| `audit_evidence.md` | Same content as `.txt` in Markdown; renders cleanly in PR comments. |
| `audit_evidence.html` | Same content as `.md` plus CSS for compliance bundles. |

The four files share an identical row order and the JSON ledger is
the single source of truth — re-rendering the others from the JSON
is deterministic.

### Verifying the ledger signature

```bash
tee-crafter verify-provenance \
 --file <build_dir>/provenance/build_provenance.json \
  --ledger <build_dir>/audit/audit_evidence.json \
  --pinned-pubkey-sha256 <your-long-lived-key-fingerprint> \
  --require-longlived
```

The signature is computed over the **canonical JSON** of the ledger document
(sorted keys, no whitespace) and stored hex-encoded in the sibling
`audit_evidence.sig`; it is verified with `core/audit/ledger.py::verify_ledger_signature`.
A failure exits **5** and should be treated as fatal: `audit_evidence.json` is
the evidence matrix this document tells you to rely on, so an unverifiable
signature means the rows below it prove nothing.

> Use the command above rather than comparing raw file bytes against raw
> signature bytes. The signature is over **canonical JSON**, so a raw-bytes
> comparison can never succeed and will report INVALID on a perfectly good
> ledger.

The round trip — sign on `AuditEvidenceLedger.save`, verify with
`verify_ledger_signature`, and exit 5 on a tampered ledger — is covered by
`apps/cli/tests/core/test_audit_ledger.py`, specifically
`test_ledger_signature_round_trips`, `test_ledger_signature_detects_tampering`
and `test_verify_provenance_exits_nonzero_on_bad_ledger_signature`
(21 tests, all passing). A good build exits 0.

## See also

- [docs/security.md](security.md) — broader hardening posture
- [docs/byok.md](byok.md) — BYOK setup and BYOK-* checks
- [docs/cli_reference.md](cli_reference.md) — `verify-provenance`
 command-line surface
