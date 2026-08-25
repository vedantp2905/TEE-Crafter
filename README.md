# TEE-Crafter

TEE-Crafter turns an existing workload into a **verifiable confidential service**.
You give it a build-context directory containing a `Dockerfile`; it deploys that
image into hardware Trusted Execution Environments across AWS, Azure and GCP and
produces the **attestation and compliance evidence** — build provenance, audit
trail, signed output bounds — that a CISO or auditor will ask for.

Two run modes:

- **`--persistent`** — a long-lived service behind the platform-owned attested
  ingress proxy (RA-TLS). Your container runs as-is; attestation is the
  platform's job.
- **`--batch`** — one-shot run to completion, with outputs captured as a signed
  `output.tar.gz`.

Ten TEE backends are supported:

| Platform flag | Backend |
|---------------|---------|
| `nitro-aws` (default) | AWS Nitro Enclaves |
| `snp-aws` | AWS AMD SEV-SNP Confidential VM |
| `snp-azure` | Azure AMD SEV-SNP Confidential VM |
| `snp-gcp` | GCP AMD SEV-SNP Confidential VM |
| `sgx-azure` | Azure Intel SGX / Gramine (`--batch` only) |
| `tdx-azure` | Azure Intel TDX |
| `tdx-gcp` | GCP Intel TDX Confidential VM |
| `gpu-cc-azure` | Azure NVIDIA Confidential GPU (AMD SNP + H100) |
| `gpu-cc-gcp` | GCP NVIDIA Confidential GPU (Intel TDX + H100) |
| `gpu-cc-aws` | AWS NVIDIA Confidential GPU (NitroTPM + H100/H200/B200, GPU attestation only) |

**Zero-trust by default.** Every deployment gets a dedicated VPC/VNet with flow
logging — never a shared default network — and a unique suffix, so parallel
deployments coexist. **No workload NIC has a public IP.** Access runs over AWS
SSM, Azure Bastion or GCP IAP; the only public addresses in a deployment belong
to the Bastion host and, where egress is enabled, the NAT gateway.

---

## Quickstart

**Prereqs:** Docker running · Docker Buildx (`brew install docker-buildx` on
macOS) · Python 3.12 · a `.env` with cloud credentials.

```bash
git clone <this-repo> && cd tee-crafter
cp .env.example .env          # add AWS / Azure / GCP creds
make install                  # creates the venv, installs tee-crafter
source venv/bin/activate      # puts tee-crafter on your PATH
make docker-build-cli         # builds the CLI image for your host arch
tee-crafter --help            # confirms the install
```

`make install` installs into `./venv` and does not touch your PATH, so without
the `activate` line `tee-crafter` is not found — use `./venv/bin/tee-crafter`
instead if you would rather not activate. Every `tee-crafter …` command below
assumes one or the other.

Timings on an M-series Mac: `make install` about 6 s, `tee-crafter --help` under
a second and it builds nothing. `make docker-build-cli` took 101 s cold and
about 7 s warm — if a cold build looks stuck it is downloading base layers.

The CLI runs inside Docker — every `tee-crafter …` command shells into the image,
which bundles Python, Terraform, the AWS/Azure/gcloud CLIs, Gramine/GSC and the
Docker CLI. **No manual installs.** Whatever language your workload needs ships
in your own Dockerfile.

Because the image carries its own copy of the source, **editing the code does
nothing until you re-run `make docker-build-cli`** — including templates and
Terraform files, which are read at run time and so look like they should not
need a rebuild. Only relevant if you are changing TEE-Crafter itself; your own
workload is mounted, not baked in.

---

## Deploy

Two steps: bake an image once, then deploy it as often as you like.

```bash
# 1. Bake once. Prints an image / AMI id, and on the CVM platforms auto-pins
#    the launch measurement.
tee-crafter internal bake-ami --tee-platform snp-aws --region us-east-2

# 2a. Persistent service behind the attested RA-TLS proxy
tee-crafter deploy \
  --source ./examples/docker_flask_api \
  --tee-platform snp-aws --ami-id <AMI_ID> \
  --persistent --service-profile long-lived \
  --deploy --auto-approve

# 2b. Batch, one-shot — output captured to a signed output.tar.gz
tee-crafter deploy \
  --source ./examples/fintech_fraud_detection \
  --tee-platform snp-aws --ami-id <AMI_ID> \
  --batch --input-dir ./examples/fintech_fraud_detection/input \
  --deploy --auto-approve
```

Both commands omit `--teardown` on purpose: a live service, or a batch run whose
output you want to collect, has to outlive the deploy. Add `--teardown` only for
a smoke test that destroys itself. `--auto-approve` keeps the Terraform apply
non-interactive; drop it to review the plan by hand.

There are no compute presets. Pick a shape with `--instance-type` — vCPU, RAM and
GPU all come from it — or omit it for the platform default. List the options with
`tee-crafter list-instances [--tee-platform <p>]`, and add `--spot` for
spot/preemptible capacity.

### Per platform

Only `--tee-platform`, the bake `--region` and the image you pass to `--ami-id`
change.

| `--tee-platform` | Bake `--region` | `.env` image var | Notes |
|---|---|---|---|
| `nitro-aws` | `us-east-2` | `AWS_NITRO_AMI_X86_64` / `_ARM64` | One AMI per architecture. Measurement is PCR0/1/2 from the EIF |
| `snp-aws` | `us-east-2` | `AWS_SNP_AMI` | One bake covers the whole `m6a/c6a/r6a` family across both CPU generations |
| `snp-azure` | `westus` | `AZURE_SNP_IMAGE` | |
| `snp-gcp` | `us-central1-a` | `GCP_SNP_IMAGE` | |
| `sgx-azure` | `westus` | `AZURE_SGX_IMAGE` | **`--batch` only**; `--persistent` is rejected at parse time. Identity is MRENCLAVE, produced by the signing step |
| `tdx-azure` | `westus` | `AZURE_TDX_IMAGE` | Needs `TEE_CRAFTER_TDX_EVIDENCE_FORMAT=azure-guest` and `TEE_CRAFTER_MAA_ENDPOINT`. The guest cannot produce a DCAP quote, so a Microsoft Azure Attestation token is the attestation ([why](docs/tdx_flow.md)) |
| `tdx-gcp` | `us-central1-a` | `GCP_TDX_IMAGE` | |
| `gpu-cc-azure` | `eastus2` | `AZURE_GPU_CC_IMAGE` | `eastus2` only — that is where the `NCCads2023` quota lives |
| `gpu-cc-gcp` | `us-central1-a` | `GCP_GPU_CC_IMAGE` | Full dual attestation (TDX + NRAS) |
| `gpu-cc-aws` | `us-east-1` | `AWS_GPU_CC_AMI` | No CPU TEE; CPU-side attestation refuses. GPU attestation only |

**GPU prereq:** set a non-empty `NVIDIA_NRAS_API_KEY` in `.env`. Prefer
`gpu-cc-gcp` or `gpu-cc-azure` for full dual attestation. See
[docs/gpu_flow.md](docs/gpu_flow.md).

Per-platform detail: [nitro](docs/nitro_flow.md) · [snp](docs/snp_flow.md) ·
[sgx](docs/sgx_flow.md) · [tdx](docs/tdx_flow.md) · [gpu](docs/gpu_flow.md).

### What the measurement pin covers

On a confidential VM the launch measurement covers the *initial guest memory* —
firmware/OVMF, boot configuration, vCPU count — **not** the contents of the OS
image you baked, which is attached after launch and anchored by
confidential-disk encryption instead. Two bakes with materially different disk
software can measure identically.

What binds your *workload* is the **container image digest**, which the app
hashes into the attestation report alongside its key and the client re-checks.
Read the pin as "a genuine CVM on the firmware I expect" and the digest as
"running the code I expect". Full scope: [docs/measurements.md](docs/measurements.md).

### Commands

| Command | Purpose |
|---------|---------|
| `tee-crafter deploy` | Build your Dockerfile and deploy to a TEE |
| `tee-crafter deploy-from-build` | Finish or re-deploy an existing `builds/<id>/` directory |
| `tee-crafter destroy` | Tear down a deployment ([what survives](docs/teardown.md)) |
| `tee-crafter list-instances` | The instance catalog, per platform |
| `tee-crafter verify-provenance` | Verify the hash chain and Ed25519 signature on a build's provenance |
| `tee-crafter compliance report` / `list` | Generate or list compliance evidence (HIPAA, SOC 2, …) |
| `tee-crafter seal-input` | Seal an input directory to a target enclave's public key |
| `tee-crafter residency-check` | Validate region pinning and emit signed evidence |
| `tee-crafter fleet-preflight` | Desired-state, cost and quota preflight for a fleet |
| `tee-crafter internal bake-ami` | Bake a TEE image for any platform |

Common flags: `--instance-type`, `--spot`, `--service-profile`, `--input-dir`,
`--allow-vulnerable`. Full surface and every `TEE_CRAFTER_*` environment
equivalent: [docs/cli_reference.md](docs/cli_reference.md).

---

## Advanced: keys, secrets and continuous attestation

These three flags are optional, independent, and **fail-closed once enabled** —
skip them until the basic deploy works. Each has its own doc; the commands below
are the short version.

| Flag | What it does |
|------|--------------|
| `--secrets-env <path>` | Delivers an `.env` to the workload at `/run/tee_crafter/app.env`. **Paired with `--byok`** it is envelope-sealed at build time and the cleartext never touches the build host, the image or Terraform; **on its own** it is baked into the measured image, which is fine for config but not for secrets. See [docs/cli_reference.md](docs/cli_reference.md#application-secrets--config---secrets-env) |
| `--byok <provider> --byok-config <json>` | Releases a customer-managed key that is unwrapped inside the TEE. **Release is not attestation-gated by default** — every provider × platform pair starts `iam-scoped`, where the key custodian checks identity rather than a hardware measurement. [docs/byok.md](docs/byok.md#per-provider-gating) names the combinations that upgrade to `kms-enforced` and the policy conditions each needs. Providers: `aws-kms`, `gcp-kms`, `azure-skr`, `external-hsm` |
| `--siem <provider> --siem-config <json>` | Streams continuous-attestation events to `syslog-cef`, `splunk-hec` or `datadog`. See [docs/siem.md](docs/siem.md) |

The SIEM gate is **preventive on the nine platforms that serve requests** — the
eight CVMs and, since 2026-08, `nitro-aws`, whose exporter now runs inside the
enclave: if the channel goes dark the TEE refuses requests and the deploy exits
non-zero. `sgx-azure` is batch-only, so it has no request path to guard; there
the preventive control is the withheld output bundle instead, and request-time
export is **detective** only. The authoritative split is
`siem_sidecar.PREVENTIVE_GATE_PLATFORMS` / `DETECTIVE_ONLY_GATE_PLATFORMS`
([docs/siem.md](docs/siem.md#which-control-you-actually-get-per-platform-and-per-run-mode)).

A full production deploy with all three:

```bash
tee-crafter deploy \
  --source ./examples/docker_flask_api \
  --tee-platform snp-aws --ami-id <AMI_ID> \
  --persistent --service-profile long-lived \
  --secrets-env ./examples/docker_flask_api/.env \
  --siem syslog-cef --siem-config ./siem.json \
  --byok aws-kms    --byok-config ./byok.json \
  --deploy --auto-approve
```

The SIEM and BYOK config files are generated by the sandbox helpers in
[`apps/cli/siem-sandbox/scripts/`](apps/cli/siem-sandbox/scripts) and
[`apps/cli/byok-sandbox/`](apps/cli/byok-sandbox); one ready-made example is
checked in at
[`apps/cli/siem-sandbox/configs/splunk-local.json`](apps/cli/siem-sandbox/configs/splunk-local.json).

**BYOK on Azure uses `azure-skr`, never `azure-kv`.** Key Vault wraps the
released key to a vTPM-sealed key that no Python process can unwrap, so
`azure-kv` refuses on an Azure CVM rather than making a doomed call. `azure-skr`
delegates both release and unwrap to Microsoft's `AzureAttestSKR`, and needs a
hand-provisioned vault plus `TEE_CRAFTER_MAA_ENDPOINT` — see
[docs/byok.md](docs/byok.md) and [docs/azure_setup.md](docs/azure_setup.md).

Two verification commands pair with these:

| Command | Purpose |
|---------|---------|
| `tee-crafter verify-siem-chain` | Verify an exported `AttestationEvent` chain. Exit code 2 on failure, so it wires into a saved search, monitor or cron |
| `tee-crafter siem-stage` | Re-stage SIEM env on a running TEE, for token rotation or post-reboot recovery |

---

## Repository layout

```
tee-crafter/
├── apps/cli/                 # the tee-crafter CLI + core
│   ├── src/tee_crafter/      # commands, deployment phases, platform templates, trust anchors
│   ├── tests/                # pytest suite (-m "not integration" runs offline)
│   ├── byok-sandbox/         # helpers: create a CMK, wrap a DEK, smoke-test release
│   ├── siem-sandbox/         # local Splunk / syslog-ng receivers
│   └── Dockerfile            # the image the CLI re-execs itself into
├── docs/                     # per-platform flows, security, compliance, CLI reference
├── examples/                 # hello_http, docker_flask_api, fintech_fraud_detection, gpu_confidential_inference
├── builds/                   # generated CLI output, per deploy (untracked)
└── Makefile                  # install / test / lint / docker targets
```

`.github/workflows/ci.yml` runs on every push and PR: unit tests, a fresh-clone
integrity check (that every path the code opens is actually tracked), a wheel
contents check (that the trust anchors and seccomp profile are inside it),
`terraform validate` across all ten platform templates, and `ruff`.

---

## Documentation

- [project.md](docs/project.md) — high-level tour
- [execution_model.md](docs/execution_model.md) — the `--batch` / `--persistent` model
- [attested_proxy.md](docs/attested_proxy.md) — how a client verifies a persistent endpoint
- [cli_reference.md](docs/cli_reference.md) — full CLI surface, config schemas, service profiles
- [security.md](docs/security.md) — security architecture, per platform
- [measurements.md](docs/measurements.md) — what each platform measures, and what a pin covers
- [compliance.md](docs/compliance.md) — provenance and evidence packs
- [audit_matrix.md](docs/audit_matrix.md) — the audit-ledger catalogue and production defaults
- [byok.md](docs/byok.md) · [siem.md](docs/siem.md) — attestation-gated keys, continuous attestation
- [batch_mode.md](docs/batch_mode.md) · [container_build.md](docs/container_build.md) · [instance_sizing.md](docs/instance_sizing.md) · [examples.md](docs/examples.md)
- [teardown.md](docs/teardown.md) — what `destroy` removes, and what outlives it
- [pending.md](docs/pending.md) — the two platforms blocked on accelerator capacity
- [watchlist.md](docs/watchlist.md) — provider capabilities to re-check before relying on them
- [trust_anchor_rotation.md](docs/trust_anchor_rotation.md) — pinned certificates and their expiry
- Flows: [nitro](docs/nitro_flow.md) · [snp](docs/snp_flow.md) · [sgx](docs/sgx_flow.md) · [tdx](docs/tdx_flow.md) · [gpu](docs/gpu_flow.md)
- Cloud setup: [aws](docs/aws_setup.md) · [azure](docs/azure_setup.md) · [gcp](docs/gcp_setup.md)

---

## Troubleshooting

- **`nitro-cli: command not found`, or SNP/SGX/TDX setup errors** — bake an image
  first (`tee-crafter internal bake-ami …`) and pass it with `--ami-id`.
- **AWS SSM access** — check IAM permissions in [aws_setup.md](docs/aws_setup.md).
- **Azure Bastion or quota** — see [azure_setup.md](docs/azure_setup.md)
  (DCsv3 / DCesv6 / DCasv5 / NCC H100 v5).
- **GCP IAP tunnel timeout** — enable `iap.googleapis.com` and allow
  `35.235.240.0/20` in the firewall.
- **GPU CC** — set `NVIDIA_NRAS_API_KEY` in `.env`.
- **Buildx missing on macOS** — `brew install docker-buildx`.
- **Logs** — on failure the CLI streams host-proxy, vsock-proxy and enclave logs
  into `builds/<id>/logs/`.
- **Resources left after a teardown** — expected for three specific things; see
  [teardown.md](docs/teardown.md).

---

## Status

This is a personal project, published so others can read and build on it. It is
not a supported product and there is no release or support commitment.

```bash
pytest apps/cli/tests -m "not integration"
```

### What has and has not been verified

Read this before relying on any security property here.

**8 of the 10 platforms have been verified on real TEE hardware**, end to end:
deploy, attest, and a client that checks the evidence. The two that have not are
`gpu-cc-aws` and `gpu-cc-gcp`, both blocked on accelerator capacity rather than
on code. [docs/pending.md](docs/pending.md) says what would close them, and is
also the complete account of the narrower gaps on the eight platforms that *have*
run — which branch, which piece of data, which negative case.

Beyond hardware: 4,944 tests, offline verification against the real vendor CA
certificates, a live fetch against Intel's production Provisioning Certification
Service, `terraform validate` across all ten platform templates, and a real Linux
kernel for the seccomp filter.

One caveat on that test count, because a number like it invites more confidence
than it earns. Several tests in this suite were found to pass for the wrong
reason — asserting on a rejection thrown by a different check than the one under
test, or on a constant no code reads. A sharper class: a verifier can hold a full
set of green tests while the property it checks is unreachable, because the
fixture supplies something the real server never sends. Treat a green suite as a
regression signal, not as evidence that a given property holds.

Several paths **deliberately fail closed rather than pretend to verify**, and say
so in their output instead of printing a pass:

- `gpu-cc-aws` refuses CPU-side attestation and is labelled GPU-attestation-only.
  Its NitroTPM extension carries self-asserted PCR JSON with no quote, no
  attestation key and no signature, and there is no AWS NitroTPM root to anchor it
  to. See [docs/security.md](docs/security.md) §15.5.
- `snp-azure` reports RA-TLS **channel binding** as `NOT ESTABLISHED`. Its
  attestation key is AMD-rooted and its public-key binding passes, but the
  HCL-minted report's `REPORT_DATA` is fixed by the paravisor, so no per-connection
  freshness value can be placed under the hardware signature. A SKU exposing
  `/dev/sev-guest` gets the stronger binding.
- `--byok azure-kv` refuses on an Azure CVM rather than making a doomed call.
  Use `azure-skr`.
- `tdx-azure` refuses a raw vTPM/HCL blob under either evidence format — nothing
  can verify one. Its supported path exchanges that evidence for an MAA token.

Known gaps that are open rather than fail-closed:

- Measurement pinning is mandatory by default on all ten platforms, but
  `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1` disables it. Do not set it in
  production: an unpinned client accepts any genuine enclave, which proves the
  hardware is real but not which image runs on it.
- `TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS=1` skips Intel TCB evaluation
  entirely. Same warning, same reason.
- The NVIDIA attestation certificate is pinned by exact bytes and expires
  **2029-12-08** (`certs/nvidia-nras-intermediate.pem`). When NVIDIA rotates it,
  every deployed GPU-CC client stops verifying GPU attestation at once. See
  [docs/trust_anchor_rotation.md](docs/trust_anchor_rotation.md).
- On `sgx-azure --batch`, the enclave measures all of its own code but does not
  verify `/input` or `/output`; Gramine prints an `insecure configurations`
  banner for them on every run. Input integrity rests on the input digest in the
  signed audit trail. See [docs/sgx_flow.md](docs/sgx_flow.md).

Every security-relevant environment knob is **production-safe when left unset**.
The full list of dev hatches, with defaults and effects when flipped, is in
[docs/audit_matrix.md](docs/audit_matrix.md#production-defaults-the-dh--dev-hatch-surface).
`verify-provenance --required-checks auto` fails closed when any high-severity
knob has been flipped.

## License

TEE-Crafter is licensed under the **Apache License 2.0**; see
[LICENSE](LICENSE).

[NOTICE](NOTICE) records third-party material redistributed here — principally
the vendor attestation trust anchors under `apps/cli/src/tee_crafter/certs/`,
which are public CA certificates published by AMD, Intel, AWS and NVIDIA. They
are redistributed unmodified so attestation verification has a pinned trust
anchor available offline; they remain the property of their issuers and are
**not** covered by this project's licence. NOTICE also lists the external tools
TEE-Crafter shells out to (Terraform, Gramine, the cloud CLIs), which are neither
bundled nor linked.
