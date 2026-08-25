# `tee-crafter` CLI reference

The CLI surface is intentionally small. Most security-critical
behaviour (provenance signing, attestation verification, residency
evidence, vuln scanning, input sealing,
AMI pinning) is **mandatory and internalised** — there are no public
opt-out flags. What the operator chooses is *what* to deploy and
*where*; the platform decides *how*.

Run `tee-crafter <command> --help` for the authoritative flag list.

## Top-level commands

| Command | Purpose |
|--------------------------------------|----------------------------------------------------------------------|
| `tee-crafter deploy` | Build your Dockerfile / image and run it in a TEE — **requires** exactly one of `--batch` (one-shot) or `--persistent` (attested-proxy service). See [docs/execution_model.md](execution_model.md). |
| `tee-crafter deploy-from-build` | **All ten platforms.** Finish or re-deploy an already-staged build directory (`--build-dir <path>`). Dispatches on the platform recorded in `deploy_manifest.json` and restores the `TF_VAR_*` environment from it, so a resumed apply plans what the original apply planned; a directory that records no platform is refused rather than assumed. Verifies the directory's provenance hash chain and Ed25519 signature first; `--skip-integrity-check` (or `TEE_CRAFTER_SKIP_BUILD_INTEGRITY_CHECK=1`) redeploys anyway — **not for production**, since the build dir is read straight off local disk and its artifacts are what get measured into the TEE. See [resuming a partially-applied deploy](#resuming-a-partially-applied-deploy). |
| `tee-crafter destroy` | Tear down the infrastructure created by a deployment (`--build-dir <path>`). |
| `tee-crafter compliance report` | Emit a SOC 2 / HIPAA / PCI / EU-AI-Act report from build provenance (`--file`, `--frameworks`, `--format`, `--output-dir`; defaults to the provenance file's own directory). A report generated without a sibling `audit/audit_evidence.json` will show gaps by design — see [compliance.md](compliance.md). |
| `tee-crafter compliance list` | List every available compliance framework template. |
| `tee-crafter verify-provenance` | Verify the integrity of a build provenance audit trail. Supports `--pinned-pubkey-sha256 <hex>`, `--require-longlived`, and `--skip-signature` (audit-only, never used in production) for CI verifiers. Accepts `--ledger <audit_evidence.json>`, `--required-checks <list-or-auto>`, and `--allow-warn` to gate CI on a per-platform required-check list. See [docs/audit_matrix.md](audit_matrix.md). |
| `tee-crafter verify-siem-chain` | Verify a SIEM-exported AttestationEvent chain. Checks the hash chain, seq contiguity, per-boot Ed25519 signatures, optional `--expect-measurement` / `--expect-platform` / `--expect-instance-id` pinning. **Pin the signing key** with `--pinned-pubkey-sha256 <hex>`, `--pubkey <pem>` or `--pubkey-file <pem>` — the command **refuses to run** without one, because verifying against the key embedded in each event proves internal consistency, not authorship. `--expect-first-seq 0` defeats silent head-truncation. `--expect-chain-commitment <sha256>` binds the stream to the runtime audit log's HMAC key commitment — **when omitted it is read automatically** from a `build_provenance.json` found next to the events file or in the working directory, whose hash chain and Ed25519 signature must both verify (a ledger that records a commitment but fails verification is refused outright rather than silently ignored, and two ledgers that disagree are refused rather than guessed between). `--no-auto-chain-commitment` disables that lookup; `--no-require-chain-commitment` drops the commitment requirement entirely for older exports. The success panel states which value was compared and where it came from, so "pinned to an attested value" is distinguishable from "the events agreed with themselves". Exit code 2 on failure — wire into a Splunk saved-search / Datadog monitor / cron. |
| `tee-crafter siem-stage` | Re-stage SIEM env on a running TEE for token rotation or post-reboot recovery. Pushes the secret half to `/run/tee-crafter-{platform}/siem.env` (tmpfs); supports `--instance-id` (SSM), `--ssh-host` / `--ssh-key` / `--ssh-port` / `--ssh-user` (Azure / GCP), `--dry-run`. |
| `tee-crafter byok-stage` | Sister command to `siem-stage`: push a rotated BYOK config (wrapped DEK / HSM bearer) to a running TEE, or re-stage `byok.env` after a reboot, without redeploying. `--no-restart` defers the workload cutover. Rejects `nitro-aws` / `sgx-azure`, where BYOK ships inside the build artifact. See [byok.md](byok.md#key-rotation--post-reboot-re-staging--byok-stage). |
| `tee-crafter audit-gen-signing-key` | Generate the long-lived Ed25519 key that signs every build's provenance (and the parallel SLSA Provenance v1 DSSE envelope emitted alongside `build_provenance.json`). `--out-dir <path>` to write somewhere other than `~/.tee-crafter/`; `--print-private` echoes the private key to stdout (avoid — it lands in your shell history). |
| `tee-crafter seal-input` | Seal an input directory to a target enclave's public key. |
| `tee-crafter residency-check` | Validate region pinning + emit signed compliance evidence. `--strict` / `--no-strict` selects whether an unresolved region is a failure or a warning. |
| `tee-crafter fleet-preflight` | Compute desired-state, cost, and quota preflight for a fleet. |
| `tee-crafter list-instances` | List selectable instance types per TEE+cloud with their vCPU / RAM / GPU (the catalog the web UI uses). `--tee-platform <p>` to filter. |

### Hidden / internal commands

| Command | Purpose |
|--------------------------------------|----------------------------------------------------------------------|
| `tee-crafter internal bake-ami` | Build a hardened AMI / VM image with all TEE deps pre-installed. Auto-captures the CVM launch measurement (SNP/TDX) on AWS/Azure/GCP and pins it (see [measurements.md](measurements.md)). `--enable-secure-boot` / `--no-enable-secure-boot` sets the UEFI Secure Boot posture baked into the image (see [security.md](security.md#151-uefi-secure-boot-defaults-to-off-on-gpu-cc-azure--gpu-cc-gcp-operational-configurable)); `--subnet-id <id>` pins the bake VM into an existing subnet instead of letting the bake create its own. |
| `tee-crafter internal pin-measurement` | Portable fallback to record a launch measurement into the registry for any cloud/TEE (`--tee-platform`, `--image-id`, `--measurement <hex>`). Pass `--instance-type` to record an SNP vCPU tier (parsed and added so deploy accepts that size). `--field <name>` selects which measurement field to write (defaults to the platform's own, e.g. `pcr0` on Nitro, `mrenclave` on SGX). Pins **merge** into the existing allowlist by default (`--merge`, implicit); `--replace` overwrites instead. Use when auto-capture could not run. |
| `tee-crafter internal compare-measurements` | Compare every recorded bake of one platform against the others, shape for shape (`--tee-platform`, `--json`). Answers whether a re-bake changes that platform's launch digest — the SEV-SNP claim that it does not was established on `snp-azure` and has to be re-established per platform, since the firmware path differs by cloud. Reads only the existing registry, so it costs nothing and needs no hardware. Only compares the same CPU generation and vCPU tier, and only when the generation was *observed* on a booted VM rather than inferred from the instance type. See [measurements.md](measurements.md). |
| `tee-crafter deploy-container` | Back-compat alias for `tee-crafter deploy` (identical command body). Hidden from `--help`; retained so existing scripts keep working — prefer `deploy`. |

`tee-crafter internal …` is hidden from the public `--help` output.
Call it directly when you want to bake your own image — re-bake on a
CVE-driven cadence so deploys keep landing on a patched base. See [`docs/aws_setup.md`](aws_setup.md),
[`docs/azure_setup.md`](azure_setup.md), and
[`docs/gcp_setup.md`](gcp_setup.md) for per-cloud baking instructions.

## Platforms

`--tee-platform` accepts:

| Value | Cloud / hypervisor | TEE primitive |
|----------------|--------------------|--------------------------------------------|
| `nitro-aws` | AWS | AWS Nitro Enclaves |
| `sgx-azure` | Azure | Intel SGX (Gramine) |
| `tdx-azure` | Azure | Intel TDX (Confidential VMs) |
| `tdx-gcp` | GCP | Intel TDX (C3 Confidential VM) |
| `snp-aws` | AWS | AMD SEV-SNP |
| `snp-azure` | Azure | AMD SEV-SNP |
| `snp-gcp` | GCP | AMD SEV-SNP |
| `gpu-cc-aws` | AWS | NVIDIA H100/H200/B200 Confidential Compute on P5/P5en/P6 (no CPU TEE; PCIe link not encrypted by a hardware TEE) |
| `gpu-cc-azure` | Azure | NVIDIA H100 Confidential Compute + SEV-SNP |
| `gpu-cc-gcp` | GCP | NVIDIA H100 Confidential Compute + TDX |

All cross-cutting flags below work on **every platform**.

## Instance selection

There are no compute presets. Pick a shape with **`--instance-type`**; when
omitted, `deploy` uses the platform's catalog default. The instance type fully
determines vCPU / RAM / GPU on the CVM and GPU platforms (it selects the host
EC2 type on Nitro). Discover the options — with their vCPU / RAM / GPU — from
the same catalog the web UI uses:

```bash
tee-crafter list-instances # all platforms
tee-crafter list-instances --tee-platform snp-aws # one platform
```

| Flag | Meaning |
|------|---------|
| `--instance-type <type>` | Shape to deploy (e.g. `m6a.2xlarge`, `Standard_DC8as_v5`, `n2d-standard-16`). Default: platform catalog default. |
| `--spot` | Request a spot / low-priority / preemptible instance. |

The supported families are the full cloud-allowed set: `m6a`/`c6a`/`r6a`
(Milan) and `m7a`/`c7a`/`r7a` (Genoa) on AWS; `DCas`/`ECas` v5 (Milan) + v6
(Genoa) on Azure; `n2d-*` on GCP; the TDX `DCes`/`ECes` v6 (Azure) and `c3-*`
(GCP) families; and the GPU `a3-*` / NCC H100 / P5/P6 shapes.

Advanced overrides (environment variables) replace individual dimensions of
the resolved shape. Each one that is set is recorded in the build provenance as
a `DH-*` dev-hatch row, so a reviewer can see it was used:
`TEE_CRAFTER_COMPUTE_OVERRIDE_CPU`,
`TEE_CRAFTER_COMPUTE_OVERRIDE_RAM_MB`,
`TEE_CRAFTER_COMPUTE_OVERRIDE_INSTANCE_TYPE` (same as `--instance-type`),
`TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_MODEL`,
`TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_COUNT`,
`TEE_CRAFTER_COMPUTE_OVERRIDE_SPOT`.

The only constraint on SNP is that the chosen **(CPU generation, vCPU tier)**
has a bake-time measurement; `bake-ami` captures Milan + Genoa across the vCPU
tiers in `TEE_CRAFTER_SNP_CAPTURE_VCPUS` (default `2,4,8,16,32,48,64,96`) and
auto-detects vCPU-independent images. See [measurements.md](measurements.md).

## Build provenance signing

Every build signs its `provenance/build_provenance.json` with an Ed25519 key.
TEE-Crafter resolves the signing key in this order:

1. `TEE_CRAFTER_PROVENANCE_SIGNING_KEY` (PEM text, e.g. from a CI secret).
2. `TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE` (PEM path).
3. OS keyring entry `tee-crafter` / `provenance-signing-key`.
4. `~/.tee-crafter/provenance-signing-key.pem` (mode `0600`).

If none of those are configured the signer refuses to run. The knob
`TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL=1` generates a per-build
ephemeral keypair (development / one-shot eval workloads only —
verifiers cannot pin a stable pubkey across builds, so production
deployments never set it).

Bootstrap a long-lived audit key with:

```bash
tee-crafter audit-gen-signing-key
# → ~/.tee-crafter/provenance-signing-key.pem (0600)
# SHA-256 fingerprint: <fpr>
```

Every build emits four sidecars next to the JSON under the same
`provenance/` subdir: `build_provenance.sig`, `build_provenance.pub`,
`build_provenance.pub.sha256` (the SPKI-SHA256 fingerprint), and
`build_provenance.key_kind.txt` (`longlived` or `ephemeral` + source).

Verifiers pin the fingerprint in audit policy:

```bash
tee-crafter verify-provenance \
  --file build/provenance/build_provenance.json \
  --pinned-pubkey-sha256 <fpr> \
  --require-longlived
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Everything checked passed |
| `1` | Hash chain tampered |
| `2` | Signature invalid / fingerprint mismatch / key kind disallowed |
| `3` | Incompatible flag combination (`--skip-signature` with `--pinned-pubkey-sha256` or `--require-longlived`) |
| `4` | `--required-checks` gate failed — missing or non-passing rows in `audit/audit_evidence.json`, or that file was not found |
| `5` | The audit ledger's own Ed25519 signature failed to verify |

To gate CI on the audit-evidence matrix:

```bash
tee-crafter verify-provenance \
  --file build/provenance/build_provenance.json \
  --ledger build/audit/audit_evidence.json \
  --required-checks auto \
  --pinned-pubkey-sha256 <fpr> \
  --require-longlived
```

> Build directories that keep all artifacts flat at the top level
> also verify — every reader resolves the canonical subdir path first
> and falls back to a top-level path when the subdir copy isn't
> present.

## Vulnerability gate (production default — override `--allow-vulnerable`)

`deploy` invokes Trivy (or Grype as a fallback) against the built Docker image.
If the scanner ran and reports a CRITICAL or HIGH finding **that has an upstream
fixed version**, the deploy is aborted before any cloud resource is provisioned
(the production posture). Findings the distro has marked `affected`,
`fix_deferred` or `will_not_fix` are counted, printed and recorded in the
provenance, but do not block — there is nothing an operator could do about them,
and a gate that cannot be satisfied only teaches people to pass
`--allow-vulnerable`. See [container_build.md](container_build.md) for the
measurements that led to that split.

Knobs:

| Setting | Effect |
|---------|--------|
| `TEE_CRAFTER_VULN_STRICT=1` | Restore zero-tolerance: every CRITICAL/HIGH blocks, fix or no fix. The failure panel says which mode it is in. |
| `TEE_CRAFTER_VULN_HIGH_THRESHOLD` | Max *fixable* HIGH tolerated by ledger check `VLN-003`. Default `0`. |
| `TEE_CRAFTER_VULN_MEDIUM_THRESHOLD` | Max *fixable* MEDIUM tolerated by `VLN-004`. Default `25`. |
| `<source>/.trivyignore` | Accepted-risk list of CVE IDs. Reviewable in a PR, names specific IDs, leaves everything else blocking — prefer it to `--allow-vulnerable`. Recorded in the provenance as `accepted_findings` / `accepted_findings_file`. Trivy only; the Grype fallback leaves all findings blocking rather than silently ignoring the file. |
| `TEE_CRAFTER_ALLOW_VULNERABLE=1` / `--allow-vulnerable` | Proceed regardless. Recorded as `gate_allowed=True` so compliance reports surface the exception. |

Ledger checks `VLN-002`/`003`/`004` read the same `blocking_*` counts as the
gate, so `verify-provenance --required-checks auto` cannot fail a build the
deploy approved. Skipped scans (neither Trivy nor Grype installed) are
non-blocking, and record `VLN-001`–`VLN-004` as `WARN` rather than pass — a gate
that did not run is not a gate that passed.

## Post-destroy secret shred

After a successful `tee-crafter destroy` (or `--teardown`), the
build directory's ephemeral secret files are overwritten with zeros
and unlinked: `*_ssh_key.pem` (the per-deploy RSA-4096 key used for
SCP transport on Azure / GCP / GPU-CC), `terraform.tfstate.backup`
(the last copy of values flagged `sensitive = true`),
`*_authori[sz]ed_keys.tmp` stage files, **`siem/siem.env`** plus
the top-level / **`app/siem.env`** mirrors (flattened SIEM secrets),
and **`byok/byok.env`** plus the top-level / **`app/byok.env`**
mirrors (BYOK unwrap env). A **`post_destroy_shred_manifest.txt`**
is appended (listing relative paths and UTC timestamps only — never
secret bytes). The knob `TEE_CRAFTER_SKIP_POST_DESTROY_SHRED=1`
preserves them for forensic archival (off by default).
**Failed destroys** skip shredding so you can retry teardown with
the same keys. **Failed deploys** also keep local `siem.env` until
you fix configuration; use the console output and
`build_provenance.*` for diagnostics (no tokens embedded).

### Sweeping flow-log groups left by earlier versions

Versions before this one leaked the deployment's VPC Flow Log CloudWatch group
on every AWS teardown. Terraform did delete the group; the flow-log delivery
service then re-created it seconds later, because the delivery role granted
`logs:CreateLogGroup` on `Resource = "*"` and nothing forced that role to be
destroyed before the group. `destroy` reported success either way, and the
replacement carries no retention policy, so it never expires. The fix — the
role no longer gets `CreateLogGroup`, and `depends_on` inverts the destroy
order — is documented in the comment above `aws_iam_role_policy.flow_log_policy`
in each AWS template, along with the measurement it came from.

Current versions no longer leak, but groups from earlier deploys are still
sitting in the account. Find them, then delete the ones whose deployment is
gone:

```bash
aws logs describe-log-groups --log-group-name-prefix /tee-crafter \
  --query 'logGroups[?retentionInDays==null].logGroupName' --output text
```

Filtering on a null `retentionInDays` is what distinguishes an orphan from a
live deployment's group: Terraform always creates the real one with 30-day
retention, and only the service-created replacement lacks it. The deployer
policy in [`aws_setup.md`](aws_setup.md) already grants `logs:DeleteLogGroup`
on `arn:aws:logs:*:<ACCOUNT_ID>:log-group:/tee-crafter/*`, so no extra
permission is needed for the sweep.

## SLSA Provenance v1

Every build that successfully writes **and signs**
`provenance/build_provenance.json` also emits
`slsa/slsa_provenance.intoto.json` (Statement) and
`slsa/slsa_provenance.dsse.json` (DSSE envelope) via
`core/audit/slsa.py`, signed with the same Ed25519 provenance key.
Verify with `slsa-verifier` / `cosign attest --type slsaprovenance`
policy engines. The SLSA emission is **gated on a successful native
signing pass** — emitting an unsigned SLSA statement would mislead
downstream verifiers, so when `load_signing_key` fails neither
artifact is produced.

### What happens if no signing key is configured

If you see only `provenance/build_provenance.json` / `.txt` in the
build directory and **no** `provenance/build_provenance.sig`, `.pub`,
`.pub.sha256`, `.key_kind.txt`, or any `slsa/slsa_provenance.*.json`,
the build hit the no-key path. The deploy surfaces this explicitly:

1. A red `Provenance signing FAILED` line is printed in the
 `Build Provenance Audit Trail` panel.
2. A `provenance/build_provenance.signing_error.txt` breadcrumb is
 written next to the JSON, listing the three supported remediations.
3. `save_audit_trail` annotates the panel with
 `Signing: UNSIGNED provenance — signing FAILED`.

Remediation (pick one):

```bash
tee-crafter audit-gen-signing-key # bootstrap default key
# OR
export TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE=/path/to/key.pem
# OR (dev / CI smoke only)
export TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL=1
```

### Docker re-exec persistence

Because `tee-crafter` re-execs itself inside Docker for every CLI
invocation, the host directory `~/.tee-crafter/` is bind-mounted
into the container at `/root/.tee-crafter/` so the long-lived signing
key **persists across runs**. Run `tee-crafter audit-gen-signing-key`
once to bootstrap; pin the fingerprint with `--pinned-pubkey-sha256`
on every verifier.

## Resuming a partially-applied deploy

When a `terraform apply` dies partway, the resources it already created are
sound and the build directory holds a valid `terraform.tfstate`. Re-applying
converges that state rather than abandoning it:

```bash
tee-crafter deploy-from-build --build-dir builds/<id> --auto-approve
```

This works for all ten platforms. It reads `deploy_manifest.json`, which the
original `deploy` writes into the build directory before anything that can fail
— on both the `--deploy` and the `--no-deploy` path.

**Why the manifest exists rather than inferring from the directory.** Two things
live only in the process that ran `deploy`:

- **The platform**, which selects one of ten deployment phases. The directory
 *name* is not a substitute: a Nitro build directory is
 `..._container_nitro_build_...` while the platform is `nitro-aws`.
- **The `TF_VAR_*` environment.** Terraform reads these from the process
 environment; nothing writes a `.tfvars` file. This is the dangerous one,
 because a missing variable is not an error to Terraform — it falls back to the
 variable's `default`. A resume that lost `TF_VAR_attest_maa_egress` would
 quietly *delete* the NSG rule the original apply created.

So the resume makes the `TF_VAR_*` environment exactly what was recorded:
restores what is missing, prefers the recorded value where the current shell
disagrees, and **unsets** variables that were not set at apply time. Each of the
three is printed. An explicit CLI flag still wins over the recording — the
precedence is flag, then manifest, then environment — but if you want a
different plan, run `tee-crafter deploy`, not a resume.

**What it refuses.** A directory with no recorded platform (it will not guess),
a platform with no deployment phase, and a non-Nitro platform whose manifest is
missing — the launch measurements live there, and `sgx-azure` uploads them to
the VM while `snp-gcp` and `gpu-cc-azure` hand them to the client runner, so an
empty set would weaken the check instead of failing it. `nitro-aws` is exempt
because its PCRs are recomputed from `app.eif`, which is strictly better than
trusting a recorded copy.

Build directories created before `deploy_manifest.json` existed cannot be
resumed. Re-run `tee-crafter deploy`.

## Pinned image (`--ami-id`)

Every `deploy*` command requires `--ami-id <baked-id>` (or
`TEE_CRAFTER_AMI_ID` in `.env`) when `--deploy` is set. There is no
on-the-fly auto-bake and no public-base-AMI fallback in the public
CLI. Bake once with `tee-crafter internal bake-ami --tee-platform
<platform>` and re-use the resulting image ID across deploys.

Resolution order, highest first:

1. `--ami-id`
2. `TEE_CRAFTER_AMI_ID` (legacy global pin)
3. the architecture-specific variable, where the platform has one
4. the per-platform variable (`AWS_SNP_AMI`, `AZURE_TDX_IMAGE`, …)

### `nitro-aws` takes two AMIs

Nitro runs on x86_64 (`c6a.*`) **and** on Graviton (`c`/`m`/`r` `6g`–`9g`), and
an AMI serves exactly one architecture. There is deliberately no combined
`AWS_NITRO_AMI` — an arm64 instance cannot boot an x86_64 image, so a single
value would be the wrong image whenever you picked the other architecture. Set
the one(s) you use and the CLI selects by the architecture of the instance type,
so `--ami-id` is not needed per run:

```bash
AWS_NITRO_AMI_X86_64=ami-… # c6a.* hosts
AWS_NITRO_AMI_ARM64=ami-… # Graviton hosts
```

These are not two builds of one image. **UEFI Secure Boot enrolment is
x86_64-only** — AL2023's `amazon-linux-sb-keys` package ships pre-signed
PK/KEK/db for x86_64 — so the arm64 AMI is always tagged
`tee-crafter-secure-boot=disabled`, and deploying it additionally requires
`TEE_CRAFTER_ALLOW_NO_SECURE_BOOT=1`. Bake them separately:

```bash
tee-crafter internal bake-ami --tee-platform nitro-aws \
 --instance-type c6a.xlarge # x86_64, Secure Boot on
tee-crafter internal bake-ami --tee-platform nitro-aws \
 --instance-type c7g.xlarge --no-enable-secure-boot # arm64
```

Passing `--enable-secure-boot` with a Graviton `--instance-type` is refused up
front, before any instance is launched.

`snp-aws` has no arm64 counterpart: AMD SEV-SNP is an AMD CPU feature, so one
pin covers the platform.

## Persistent RA-TLS service profile

`--service-profile <preset>` is the single knob that controls the
eight RA-TLS service parameters (`cert-ttl`, `cert-grace`,
`reattest-*`, `keepalive`, `streaming`, `max-concurrent-connections`,
`on-attestation-failure`). Mutually exclusive with `--batch` (when
not `default`).

| Profile | Cert TTL | Re-attest | Streaming | Max conns | Default `on_failure` |
|----------------|----------|-----------|-----------|-----------|----------------------|
| `default` | (n/a) | (n/a) | — | — | one-shot (no service mode) — **but see below** |
| `long-lived` | 24 h | 1 h | no | 1 024 | drain |
| `short-lived` | 1 h | 10 min | no | 256 | drain |
| `streaming` | 1 h | 10 min | yes | 4 096 | drain |

> **`default` does not mean "one-shot" under `--persistent`.** When you pass
> `--persistent` and leave `--service-profile` at `default`, the CLI silently
> promotes it to `long-lived` — you get a 24 h cert TTL and hourly re-attest,
> not the "(n/a)" row above (`deploy_helpers.py::validate_run_mode`, the
> `if persistent_mode and profile == "default": profile = "long-lived"` branch
> at lines 289–291). The `default` row describes `--batch`. If you want
> `short-lived` freshness on a persistent service, you have to ask for it
> explicitly; leaving the flag off gets you the loosest of the three profiles.

See [`docs/security.md`](security.md) for the threat model.

## SIEM / continuous-attestation export

The public surface is `--siem <provider>` plus a single JSON file
`--siem-config <path>`.

```
--siem {none|syslog-cef|splunk-hec|datadog}
--siem-config FILE (required when --siem != none)
```

The JSON document carries every provider-specific field
(`endpoint`, `token`, `host`, `port`, `egress_mode`,
`egress_allowlist_cidrs`, `egress_ports`, …). See
[`docs/siem.md`](siem.md) for the schema and per-provider examples.

## Customer-managed keys (BYOK)

```
--byok {none|aws-kms|azure-kv|gcp-kms|external-hsm}
--byok-config FILE (required when --byok != none)
```

The JSON policy carries `key_id`, `region`, `unwrap`,
`encryption_context`, `policy.allowed_measurement_sha256`,
`policy.require_encryption_context_keys`, `dek_path`, … See
[`docs/byok.md`](byok.md).

**Bind release to a vetted measurement.** Pin
`policy.allowed_measurement_sha256` so in-guest key release is gated on the
attested measurement. If it is empty on a non-Nitro platform (no server-side
KMS PCR backstop) the deploy records **BYOK-011** as a warning; set
`TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT=1` to turn that into a hard failure in
CI.

## Application secrets / config (`--secrets-env`)

```
--secrets-env FILE (plaintext dotenv: DB passwords, API tokens, config)
```

Hands the CLI a dotenv file at deploy time. **BYOK is optional**, and the
two modes differ in where the cleartext lives:

- **With `--byok aws-kms`/`gcp-kms` (sealed):** the `.env` is
 envelope-sealed at build time (random 256-bit DEK, AES-256-GCM payload;
 the DEK is KMS-wrapped with your BYOK key). The cleartext never touches
 the build host, the image, or Terraform. Records **BYOK-012**.
- **Without `--byok` (baked):** the `.env` is written to `app.env` and
 baked into the **measured** image — fine for non-secret config, since
 the value becomes part of the image measurement. Use BYOK for real
 secrets.

`--secrets-env`/`TEE_CRAFTER_SECRETS_ENV` is validated up front (a
malformed dotenv fails before any build work).

> **Runtime delivery.** The dotenv is surfaced to the workload as
> environment variables at `/run/tee_crafter/app.env` (the container is
> started with `--env-file`). On **CVM platforms (SNP/TDX/GPU)** the
> `tee-crafter-secrets.service` oneshot runs **before** the container and
> either copies the baked `app.env` or, for sealed mode, performs the
> attestation-gated unseal — **fail-closed**: if the unseal/BYOK release
> fails the container `Requires=` keeps the workload stopped (dev hatch
> `TEE_CRAFTER_SECRETS_FAIL_OPEN=1`). On **Nitro baked** mode the EIF
> entrypoint sources `/tee-crafter-runtime/app.env`. The two paths that do
> **not** deliver are **Nitro sealed** (needs NSM recipient-unwrap) and
> **SGX**; the CLI prints a warning at deploy time for those, and records
> **BYOK-014** with the per-platform delivery verdict. Sealed/BYOK release
> on CVM is bound to the image's bake-time measurement (auto-pinned — see
> [measurements.md](measurements.md)); a CVM image with no pinned
> measurement is refused unless `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1`.

## Workload network egress (databases, 3rd-party APIs)

```
--egress-mode {deny|vpc|nat} (default: deny)
--egress-allow host:port (or cidr:port; repeatable)
```

In the container-orchestrated model the user's image owns its data, so
egress is the primary confidentiality boundary. Egress is
**deny-by-default**; reach is declared explicitly:

- **`deny`** (default) — nothing beyond VPC-local 443 (KMS/attestation).
- **`vpc`** — reach intra-VPC destinations (e.g. a peered private DB) on
 the `--egress-allow` ports, with **no NAT**.
- **`nat`** — reach a **public** managed-DB endpoint / SaaS API via a NAT
 gateway whose security group is locked to the resolved `/32` CIDRs
 (`0.0.0.0/0` is never opened).

Hostnames resolve at deploy time and persist to
`workload_egress.json` (a SLSA-provenance subject). Recorded as
**EGR-005** (deny-by-default or explicitly allowlisted) and **EGR-006**
(no `0.0.0.0/0` in the allowlist).

## Sealed input bundles

```bash
tee-crafter seal-input \
 --input-dir./customer_data \
 --target-pub <build_dir>/seal_pub.pem \
 --out sealed.bin \
 --build-id <sha256> \
 --aad tenant=acme
```

`seal-input` is the **only** path that encrypts an input directory to the
enclave. `--input-dir` on `deploy` does **not** seal: it builds a plain
`tar.gz`, uploads it over the deploy channel, and the host extracts it in the
clear to `/var/lib/tee_crafter/input` before bind-mounting it read-only at
`/input` (`cli/commands/deploy/batch.py`, lines 531–560). The transport is
encrypted; the copy sitting on the host disk is not.

> **`seal-input` currently has no in-TEE consumer. Do not rely on it to get
> confidential input into a batch job.** Earlier revisions of this section said
> the sealed bundle was unsealed by
> `templates/common/batch_runner.py::_maybe_unseal_input` and selected with a
> `BATCH_SEALED_INPUT` environment variable. Neither exists in this tree:
> `batch_runner.py` is not present, and `grep -r BATCH_SEALED_INPUT apps/`
> returns nothing. `seal_pub.pem` likewise appears in `apps/cli/src` only as
> help text on `seal-input --target-pub` (`cli/commands/seal_input.py:22`) —
> nothing in the deploy flow writes one, so there is no enclave public key to
> seal against either.
>
> What the command does is real and self-contained: `core/sealing/seal.py`
> produces an AES-256-GCM bundle and a manifest wrapped to the RSA public key
> you pass, with `--build-id` and any `--aad` pairs bound by the GCM tag, and
> `core/sealing/unseal.py` reverses it offline if you hold the private key.
> Treat it as a sealing primitive waiting on the runner half, not as a
> completed feature.


## Data residency / region pinning

```bash
tee-crafter residency-check \
  --cloud aws \
  --region us-east-2 \
  --policy us-only.json \
  --terraform-plan build/<deployment>/tfplan.json \
  --out build/<deployment>/residency_evidence.json
```

Validates that the chosen cloud + primary region (and every region
referenced in an optional `terraform show -json` output) matches the
JSON policy. Emits a signed `residency_evidence.json` (plus `.sig` /
`.pub` sidecars) at `--out`. Use `--no-strict` to write evidence even
on failure; the default `--strict` exits non-zero on policy mismatch.
See [`docs/compliance.md`](compliance.md).

`residency-check` is the standalone/out-of-band tool. To enforce residency
**inline during `deploy`**, point `TEE_CRAFTER_RESIDENCY_POLICY` at the
policy JSON: the chosen cloud/region is validated *before* any cloud
resource is created and the deploy aborts (recording **RES-001**) on a
violation. Unset → no-op (default behaviour preserved).

## Mixed on-demand + spot fleets

```bash
tee-crafter fleet-preflight \
  --spec my-fleet.json \
  --prices prices.json \
  [--out plan.json] [--format table|json]
```

Both `--spec` and `--prices` are JSON files (see
`tee_crafter.core.fleet.spec` for the spec schema and
`StaticPriceFeed` for the price-table format). Calculates desired
count, per-pool cost, schedule-aware monthly burn, and failover
candidates before any deploy.

## Bringing another language

There is no language scaffold and no polyglot sidecar. Any runtime your
workload needs ships inside your own `Dockerfile` / OCI image; TEE-Crafter
builds and runs it as-is. See [docs/execution_model.md](execution_model.md).

## Configuration via `.env`

Every `--flag` listed below also has a `TEE_CRAFTER_*` environment
variable; pin once in `.env` and skip retyping it on the command
line. CLI flags always win over `.env`.

| CLI flag | `.env` key | Notes |
|----------------------|----------------------------------|---------------------------------------------|
| `--instance-type` | `TEE_CRAFTER_INSTANCE_TYPE` | default: platform catalog default; `list-instances` to discover |
| `--spot` | `TEE_CRAFTER_SPOT=true` | spot / low-priority / preemptible |
| `--ami-id` | `TEE_CRAFTER_AMI_ID` | |
| `--service-profile` | `TEE_CRAFTER_SERVICE_PROFILE` | |
| `--siem` | `TEE_CRAFTER_SIEM` | |
| `--siem-config` | `TEE_CRAFTER_SIEM_CONFIG` | path to JSON |
| `--byok` | `TEE_CRAFTER_BYOK` | |
| `--byok-config` | `TEE_CRAFTER_BYOK_CONFIG` | path to JSON |
| `--secrets-env` | `TEE_CRAFTER_SECRETS_ENV` | dotenv: envelope-sealed with `--byok aws-kms`/`gcp-kms`, else baked into the measured image. **Sealing does not work with `azure-kv`** (that adapter returns no plaintext DEK). Whether release is attestation-gated depends on provider × platform — see [byok.md](byok.md#per-provider-gating). Delivered at `/run/tee_crafter/app.env` on CVM (fail-closed secrets oneshot) and Nitro baked; not delivered on Nitro sealed / SGX |
| `--egress-mode` | `TEE_CRAFTER_EGRESS_MODE` | `deny` (default) / `vpc` / `nat` |
| `--egress-allow` | `TEE_CRAFTER_EGRESS_ALLOW` | `host:port` or `cidr:port`; repeatable |
| `--batch` | `TEE_CRAFTER_BATCH=true` | one required; mutually exclusive with `--persistent` |
| `--persistent` | `TEE_CRAFTER_PERSISTENT=true` | one required; mutually exclusive with `--batch` |
| `--batch-timeout` | `TEE_CRAFTER_BATCH_TIMEOUT` | |
| `--input-dir` | `TEE_CRAFTER_INPUT_DIR` | plain `tar.gz`, extracted in the clear on the host; **not** sealed to the TEE |
| `--allow-vulnerable` | `TEE_CRAFTER_ALLOW_VULNERABLE=1` | override Trivy/Grype gate; recorded in provenance with `gate_allowed=true`. NOT for production. |
| `--keep-on-failure` | `TEE_CRAFTER_KEEP_ON_FAILURE` | Leave provisioned infrastructure running when a deploy fails, for debugging. Default is to tear it down — a failed run otherwise leaves the instance (and any NAT gateway) billing until someone runs `tee-crafter destroy`. |
| _(implicit)_ | `TEE_CRAFTER_SSH_RETRIES` | retries on transient SSH/SCP errors over Azure Bastion / GCP IAP tunnels (default `4`). |
| _(implicit)_ | `TEE_CRAFTER_SSH_RETRY_BACKOFF` | exponential-backoff base between SSH retries (default `2.0`). |

See [`.env.example`](../.env.example) for the full set of keys with
inline documentation.

## End-to-end: a maximal example

```bash
# 1) Bake once (per cloud / TEE backend). Secure Boot is enrolled by default
# on nitro-aws / snp-aws (see docs/security.md §15.1A).
# Already on for sgx-azure, tdx-azure, snp-azure, snp-gcp, tdx-gcp via
# their respective Terraform templates. Intentionally OFF for the three
# gpu-cc-* platforms (unsigned NVIDIA DKMS driver). Pass
# --no-enable-secure-boot to bake an unhardened dev AMI on AWS.
tee-crafter internal bake-ami --tee-platform snp-aws

# 2) Deploy with persistent service mode + Splunk SIEM + AWS-KMS BYOK.
tee-crafter deploy \
 --source examples/docker_flask_api \
 --tee-platform snp-aws \
 --instance-type m6a.xlarge \
 --ami-id <baked-id> \
 --persistent \
 --service-profile long-lived \
 --siem splunk-hec --siem-config configs/splunk.json \
 --byok aws-kms --byok-config configs/aws-kms.json \
 --deploy --auto-approve
```

This single command builds the image, attests it, pins the AMD SEV-SNP
measurement, releases a customer-managed KMS key into the enclave,
runs a long-lived RA-TLS service on it, and streams continuous
attestation events into Splunk — all without changing the Docker
image or the application code.

---

## Appendix: every `TEE_CRAFTER_*` variable the code reads

Generated from the tree by locating actual reads —
`os.environ.get`, `os.environ[...]`, Click `envvar=`, shell `${VAR:-default}`,
and the `NAME_ENV = "TEE_CRAFTER_..."` constant-indirection pattern — with
comment lines excluded. That last exclusion matters: `TEE_CRAFTER_ALLOW_MIXED_PCS_HOSTS`
appears only inside a comment in `core/attestation/tcb_collateral.py` explaining
why such a flag was deliberately *not* added, so it is not a variable and is not
listed here.

126 variables have a real read site. Names that appear elsewhere in the tree
but are **not** in this table are prose mentions or on-instance transcript
markers rather than inputs — `TEE_CRAFTER_MEASUREMENT=<hex>`,
`TEE_CRAFTER_PCR4=<hex>`, `TEE_CRAFTER_CPU_MODEL=<str>` and `TEE_CRAFTER_RC` are
lines a capture snippet *prints* for the bake to parse, not settings you can
override.

Prose for the security-relevant subset — everything that weakens a production
default, and the opt-in hardening knobs — is in
[security.md §19](security.md#19-every-escape-hatch-that-weakens-a-default).
This table is the index; that section is the explanation. A blank default means
the read supplies none (absent behaves as unset/false) or the default is
computed rather than literal.

| Variable | Default | Read at |
|---|---|---|
| `TEE_CRAFTER_ACCEPT_PARTIAL_CC` | — | `tee_crafter/cli/deployment/gpu_cc/aws_phase.py:97` |
| `TEE_CRAFTER_ALLOW_NON_ENCLAVE_SGX` | — | `tee_crafter/cli/deployment/sgx/gsc.py:51` |
| `TEE_CRAFTER_ALLOW_NO_SECURE_BOOT` | — | `tee_crafter/cli/commands/deploy/validators.py:36` |
| `TEE_CRAFTER_ALLOW_SETUP_EGRESS_NAT` | — | `tee_crafter/cli/commands/deploy/workload_egress.py:75` |
| `TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI` | — | `tee_crafter/cli/commands/deploy/deploy_helpers.py:153` |
| `TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN` | — | `tee_crafter/templates/gpu_cc/aws/client.template.py:59` (+9 more) |
| `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT` | `0` | `tee_crafter/cli/commands/deploy/measurement_pin.py:38` (+9 more) |
| `TEE_CRAFTER_ALLOW_UNVERIFIED_AWS_CPU_ATTESTATION` | — | `tee_crafter/templates/gpu_cc/aws/client.template.py:167` |
| `TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS` | — | `tee_crafter/templates/common/tee_crafter_tcb_eval.py:160` |
| `TEE_CRAFTER_ALLOW_VULNERABLE` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:333` (+2 more) |
| `TEE_CRAFTER_AMI_ID` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:237` (+2 more) |
| `TEE_CRAFTER_ARK_GENOA_SHA256` | `$AMD_ARK_GENOA_SHA256` | `tee_crafter/scripts/snp_aws/setup_snp_aws.sh:230` (+2 more) |
| `TEE_CRAFTER_ARK_MILAN_SHA256` | `$AMD_ARK_MILAN_SHA256` | `tee_crafter/scripts/snp_aws/setup_snp_aws.sh:229` (+2 more) |
| `TEE_CRAFTER_ATTESTATION_CLIENT` | — | `tee_crafter/templates/common/tee_crafter_maa.py:479` |
| `TEE_CRAFTER_AZURE_SKR_TOOL` | — | `tee_crafter/core/keys/azure_skr_tool.py:66` |
| `TEE_CRAFTER_AZ_CLI_INSTALLER_SHA256` | — | `tee_crafter/scripts/sgx_azure/setup_sgx.sh:80` |
| `TEE_CRAFTER_BAKE_SUFFIX` | — | `tee_crafter/cli/commands/baking/common/helpers.py:33` |
| `TEE_CRAFTER_BATCH` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:244` |
| `TEE_CRAFTER_BATCH_TIMEOUT` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:254` |
| `TEE_CRAFTER_BYOK` | `none` | `tee_crafter/cli/commands/deploy/deploy_container.py:315` (+2 more) |
| `TEE_CRAFTER_BYOK_ALLOW_ANY_MEASUREMENT` | — | `tee_crafter/core/keys/spec.py:118` |
| `TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK` | — | `tee_crafter/core/keys/azure_skr_tool.py:78` |
| `TEE_CRAFTER_BYOK_CONFIG` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:320` |
| `TEE_CRAFTER_BYOK_DEK_PATH` | `_DEFAULT_DEK_PATH` | `tee_crafter/templates/common/byok_health.py:68` (+1 more) |
| `TEE_CRAFTER_BYOK_ENABLED` | `0` | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:326` (+1 more) |
| `TEE_CRAFTER_BYOK_GRACE_SECONDS` | `30` | `tee_crafter/templates/common/byok_health.py:72` |
| `TEE_CRAFTER_BYOK_HSM_BEARER` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:255` |
| `TEE_CRAFTER_BYOK_HSM_ENDPOINT` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:254` |
| `TEE_CRAFTER_BYOK_KEY_ID` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:367` (+1 more) |
| `TEE_CRAFTER_BYOK_LABEL` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:370` |
| `TEE_CRAFTER_BYOK_MAX_AGE` | `300` | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:263` |
| `TEE_CRAFTER_BYOK_REGION` | `us-east-2` | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:235` (+2 more) |
| `TEE_CRAFTER_BYOK_UNWRAP` | `direct_bytes` | `tee_crafter/core/keys/attestation_providers.py:363` (+1 more) |
| `TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:465` (+1 more) |
| `TEE_CRAFTER_COMPUTE_OVERRIDE_CPU` | — | `tee_crafter/cli/commands/deploy/compute.py:119` |
| `TEE_CRAFTER_COMPUTE_OVERRIDE_RAM_MB` | — | `tee_crafter/cli/commands/deploy/compute.py:121` |
| `TEE_CRAFTER_DESTROY_TIMEOUT` | — | `tee_crafter/core/iac/platforms.py:25` |
| `TEE_CRAFTER_DOCKER_IMAGE` | `tee-crafter` | `tee_crafter/cli/main.py:77` |
| `TEE_CRAFTER_EGRESS_ALLOW` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:276` |
| `TEE_CRAFTER_EGRESS_MODE` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:269` |
| `TEE_CRAFTER_EXPECTED_VTPM_PCRS` | `EXPECTED_VTPM_PCRS` | `tee_crafter/templates/gpu_cc/gcp/client.template.py:221` |
| `TEE_CRAFTER_EXTRA_DOCKER_MOUNTS` | — | `tee_crafter/cli/main.py:429` |
| `TEE_CRAFTER_FMSPC` | — | `tee_crafter/core/attestation/tcb_collateral.py:155` |
| `TEE_CRAFTER_FORCE_UNLOCK` | — | `tee_crafter/cli/commands/deploy/from_build.py:265` |
| `TEE_CRAFTER_GPU_CC_MODE` | `PROTECT` | `tee_crafter/core/gpu/nvidia_attestation.py:113` |
| `TEE_CRAFTER_INPUT_DIR` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:258` |
| `TEE_CRAFTER_INSTANCE_TYPE` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:199` (+1 more) |
| `TEE_CRAFTER_IN_DOCKER` | — | `tee_crafter/cli/cloud_auth.py:27` (+2 more) |
| `TEE_CRAFTER_KEEP_ON_FAILURE` | — | `tee_crafter/cli/constants.py:18` |
| `TEE_CRAFTER_MAA_ENDPOINT` | — | `tee_crafter/cli/commands/deploy/byok_mode.py:71` (+5 more) |
| `TEE_CRAFTER_MEASUREMENTS_DIR` | — | `tee_crafter/core/measurements/registry.py:52` |
| `TEE_CRAFTER_NITRO_BUILDER_BASE` | — | `tee_crafter/core/enclave/enclave.py:115` |
| `TEE_CRAFTER_NRAS_CIDRS` | — | `tee_crafter/cli/deployment/common/nras_egress.py:76` (+1 more) |
| `TEE_CRAFTER_NRAS_HOSTS` | — | `tee_crafter/cli/deployment/common/nras_egress.py:82` |
| `TEE_CRAFTER_NRAS_RESOLVE` | `1` | `tee_crafter/cli/deployment/common/nras_egress.py:162` |
| `TEE_CRAFTER_NRAS_STRICT` | `1` | `tee_crafter/cli/deployment/common/nras_egress.py:147` (+1 more) |
| `TEE_CRAFTER_PCS_BASE_URL` | — | `tee_crafter/core/attestation/tcb_collateral.py:143` |
| `TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL` | — | `tee_crafter/core/attestation/tcb_collateral.py:152` |
| `TEE_CRAFTER_PERSISTENT` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:249` |
| `TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL` | — | `tee_crafter/core/audit/signing.py:40` |
| `TEE_CRAFTER_PROVENANCE_SIGNING_KEY` | — | `tee_crafter/core/audit/signing.py:38` |
| `TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE` | — | `tee_crafter/core/audit/signing.py:39` |
| `TEE_CRAFTER_PROXY_NO_CREDS` | `0` | `tee_crafter/templates/nitro/host_proxy.template.py:118` |
| `TEE_CRAFTER_PROXY_STRICT_IMDS` | `1` | `tee_crafter/templates/nitro/host_proxy.template.py:141` |
| `TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS` | `1` | `tee_crafter/scripts/gpu_cc_aws/setup_gpu_cc_aws.sh:332` (+1 more) |
| `TEE_CRAFTER_REQUIRE_PINNED_MEASUREMENT` | — | `tee_crafter/cli/deployment/common/attestation_report.py:40` |
| `TEE_CRAFTER_RESIDENCY_POLICY` | — | `tee_crafter/cli/commands/deploy/deploy_helpers.py:45` |
| `TEE_CRAFTER_RUSTUP_SHA256` | — | `tee_crafter/scripts/gpu_cc_azure/setup_gpu_cc_azure.sh:208` (+3 more) |
| `TEE_CRAFTER_SECRETS_ENV` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:326` |
| `TEE_CRAFTER_SECRETS_FAIL_OPEN` | — | `tee_crafter/templates/common/tee_crafter_secret_bootstrap.py:42` |
| `TEE_CRAFTER_SERVICE_MODE` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:428` |
| `TEE_CRAFTER_SERVICE_PROFILE` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:285` |
| `TEE_CRAFTER_SGX_ENCLAVE_SIZE` | — | `tee_crafter/cli/deployment/sgx/gsc.py:44` |
| `TEE_CRAFTER_SGX_MAX_THREADS` | — | `tee_crafter/cli/deployment/sgx/gsc.py:45` |
| `TEE_CRAFTER_SIEM` | `none` | `tee_crafter/cli/commands/deploy/deploy_container.py:294` (+2 more) |
| `TEE_CRAFTER_SIEM_API_KEY` | — | `tee_crafter/templates/common/siem_export.py:539` (+1 more) |
| `TEE_CRAFTER_SIEM_BEARER` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:132` |
| `TEE_CRAFTER_SIEM_COLLECTOR_HOST` | — | `tee_crafter/templates/nitro/app_vsock.template.py:317` |
| `TEE_CRAFTER_SIEM_COLLECTOR_PORT` | — | `tee_crafter/templates/nitro/app_vsock.template.py:318` |
| `TEE_CRAFTER_SIEM_CONFIG` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:299` |
| `TEE_CRAFTER_SIEM_DCE_URL` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:148` |
| `TEE_CRAFTER_SIEM_DCR_IMMUTABLE_ID` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:149` |
| `TEE_CRAFTER_SIEM_DDSOURCE` | `tee-crafter` | `tee_crafter/templates/common/siem_export.py:542` (+1 more) |
| `TEE_CRAFTER_SIEM_ENABLED` | `0` | `tee_crafter/templates/common/siem_export.py:1067` (+2 more) |
| `TEE_CRAFTER_SIEM_ENDPOINT` | — | `tee_crafter/templates/common/siem_export.py:527` (+2 more) |
| `TEE_CRAFTER_SIEM_ENV` | `prod` | `tee_crafter/templates/common/siem_export.py:543` (+1 more) |
| `TEE_CRAFTER_SIEM_ENV_FILE` | — | `tee_crafter/templates/common/siem_export.py:1051` |
| `TEE_CRAFTER_SIEM_FACILITY` | `13` | `tee_crafter/templates/common/siem_export.py:552` (+1 more) |
| `TEE_CRAFTER_SIEM_FAIL_OPEN` | — | `tee_crafter/cli/commands/deploy/siem_mode.py:355` (+1 more) |
| `TEE_CRAFTER_SIEM_GRACE_SECONDS` | `60` | `tee_crafter/templates/common/siem_health.py:115` |
| `TEE_CRAFTER_SIEM_HOST` | `localhost` | `tee_crafter/templates/common/siem_export.py:548` (+1 more) |
| `TEE_CRAFTER_SIEM_HOSTNAME` | — | `tee_crafter/templates/common/siem_export.py:554` (+1 more) |
| `TEE_CRAFTER_SIEM_INDEX` | `main` | `tee_crafter/templates/common/siem_export.py:529` (+1 more) |
| `TEE_CRAFTER_SIEM_INTERVAL_SECONDS` | `60` | `tee_crafter/templates/common/siem_export.py:1112` (+2 more) |
| `TEE_CRAFTER_SIEM_LOG_GROUP` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:156` |
| `TEE_CRAFTER_SIEM_LOG_STREAM` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:157` |
| `TEE_CRAFTER_SIEM_MAX_LAG_SECONDS` | — | `tee_crafter/templates/common/siem_health.py:107` |
| `TEE_CRAFTER_SIEM_PORT` | `514` | `tee_crafter/templates/common/siem_export.py:549` (+1 more) |
| `TEE_CRAFTER_SIEM_PROTOCOL` | `tcp` | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:100` |
| `TEE_CRAFTER_SIEM_REGION` | `us-east-2` | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:158` |
| `TEE_CRAFTER_SIEM_SERVICE` | `tee-crafter` | `tee_crafter/templates/common/siem_export.py:541` (+1 more) |
| `TEE_CRAFTER_SIEM_SEVERITY` | `5` | `tee_crafter/templates/common/siem_export.py:553` |
| `TEE_CRAFTER_SIEM_SITE` | `datadoghq.com` | `tee_crafter/templates/common/siem_export.py:540` (+1 more) |
| `TEE_CRAFTER_SIEM_SOURCE` | `tee-crafter` | `tee_crafter/templates/common/siem_export.py:532` (+1 more) |
| `TEE_CRAFTER_SIEM_STREAM_NAME` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:150` |
| `TEE_CRAFTER_SIEM_TOKEN` | — | `tee_crafter/templates/common/siem_export.py:528` (+1 more) |
| `TEE_CRAFTER_SIEM_X_VERIFY_SSL` | — | `tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py:110` |
| `TEE_CRAFTER_SKIP_BUILD_INTEGRITY_CHECK` | — | `tee_crafter/cli/commands/deploy/from_build.py:258` |
| `TEE_CRAFTER_SKIP_IMAGE_STALENESS_CHECK` | — | `tee_crafter/cli/main.py:116` |
| `TEE_CRAFTER_SKIP_LOCAL_DOCKER_PRUNE` | — | `tee_crafter/cli/deployment/common/local_docker_prune.py:42` |
| `TEE_CRAFTER_SKIP_STALE_IMAGE_CHECK` | — | `tee_crafter/cli/stale_image_check.py:47` |
| `TEE_CRAFTER_SNP_CAPTURE_VCPUS` | — | `tee_crafter/core/measurements/shapes.py:185` |
| `TEE_CRAFTER_SNP_REQUIRE_SMT_DISABLED` | `0` | `tee_crafter/templates/snp/aws/client.template.py:604` (+2 more) |
| `TEE_CRAFTER_SPOT` | — | `tee_crafter/cli/commands/deploy/deploy_container.py:204` (+1 more) |
| `TEE_CRAFTER_SSH_MUX` | `1` | `tee_crafter/core/remote/ssh_mux.py:74` |
| `TEE_CRAFTER_SSH_MUX_PERSIST` | `5m` | `tee_crafter/core/remote/ssh_mux.py:103` |
| `TEE_CRAFTER_STRICT_SNP_AK_BINDING` | `1` | `tee_crafter/templates/gpu_cc/azure/client.template.py:1403` (+1 more) |
| `TEE_CRAFTER_STRICT_TSM` | `1` | `tee_crafter/templates/gpu_cc/gcp/app.template.py:354` (+1 more) |
| `TEE_CRAFTER_TCB_ALLOW_STATUS` | — | `tee_crafter/templates/common/tee_crafter_tcb_eval.py:157` |
| `TEE_CRAFTER_TCB_COLLATERAL` | — | `tee_crafter/templates/common/tee_crafter_tcb_eval.py:149` |
| `TEE_CRAFTER_TCB_COLLATERAL_MAX_AGE_HOURS` | — | `tee_crafter/templates/common/tee_crafter_tcb_eval.py:152` |
| `TEE_CRAFTER_TCB_EVAL_MODULE` | — | `tee_crafter/templates/gpu_cc/gcp/client.template.py:1035` (+3 more) |
| `TEE_CRAFTER_TDX_EVIDENCE_FORMAT` | — | `tee_crafter/core/builder/platforms.py:239` |
| `TEE_CRAFTER_TDX_QE_IDENTITY_URL` | — | `tee_crafter/core/attestation/tcb_collateral.py:160` |
| `TEE_CRAFTER_TEE_PLATFORM` | — | `tee_crafter/templates/common/siem_export.py:1072` (+3 more) |
| `TEE_CRAFTER_VULN_STRICT` | — | `tee_crafter/core/security/vuln_scan.py:23` |
