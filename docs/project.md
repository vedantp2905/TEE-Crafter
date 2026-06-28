# TEE-Crafter: Verifiable Confidential Workloads

## Overview

**TEE-Crafter** deploys your workloads into hardware **Trusted Execution
Environments (TEEs)** and produces **attestation + compliance evidence**
(build provenance, output bounds, audit trails).

You bring **one input**: a build context with a `Dockerfile` (or a prebuilt
OCI image). You pick **one run mode**:

- **`--persistent`** — long-lived service behind the platform-owned attested
 ingress proxy (RA-TLS terminator). Your container listens on
 `127.0.0.1:<port>`; attestation is the platform's job.
- **`--batch`** — one-shot job. Your container runs to completion; every file
 it wrote is captured into a signed `output.tar.gz`.

Any language, any Linux container runtime — ship it in your image. See
[execution_model.md](execution_model.md) for the full model and platform
matrix (`sgx-azure` is batch-only via Gramine Shielded Containers).

The CLI (`tee-crafter`) runs inside a Docker container (built from
`apps/cli/Dockerfile`) with Terraform, cloud CLIs, Gramine, and Docker. The
host only needs Docker and cloud credentials.

---

## Supported TEE Platforms

| Platform | Cloud | Hardware | Attestation | Documentation |
|----------|-------|----------|-------------|---------------|
| **AWS Nitro Enclaves** | AWS EC2 | Nitro Security Module | PCR-bound KMS + COSE_Sign1 | [nitro_flow.md](nitro_flow.md) |
| **Intel SGX via Gramine** | Azure DCsv3/DCdsv3 | SGX Enclave Page Cache | DCAP quote (MRENCLAVE/MRSIGNER) | [sgx_flow.md](sgx_flow.md) |
| **Intel TDX (Azure)** | Azure DCesv6/ECesv6 | TDX Trust Domain | RA-TLS + **MAA `/attest/AzureGuest` token**. The *guest* cannot produce a DCAP quote — no Quoting Enclave is reachable under the paravisor, and the vTPM yields a raw MAC'd `TDREPORT` — so the host brokers one via IMDS `/acc/tdquote` and MAA consumes it. The quote never reaches our client, so the trust root here is Microsoft, not Intel ([why](tdx_flow.md)) | [tdx_flow.md](tdx_flow.md) |
| **AMD SEV-SNP (AWS)** | AWS M6a/C6a/R6a | AMD Secure Processor | RA-TLS + SNP report | [snp_flow.md](snp_flow.md) |
| **AMD SEV-SNP (Azure)** | Azure DCasv5/ECasv5/v6 | AMD Secure Processor | RA-TLS + SNP report | [snp_flow.md](snp_flow.md) |
| **AMD SEV-SNP (GCP)** | GCP N2D | AMD Secure Processor | RA-TLS + SNP report | [snp_flow.md](snp_flow.md) |
| **Intel TDX (GCP)** | GCP C3 | Intel TDX | RA-TLS + TDX DCAP quote | [tdx_flow.md](tdx_flow.md) |
| **NVIDIA GPU CC (GCP)** | GCP A3 (H100) | Intel TDX + NVIDIA CC | Dual: TDX quote + NRAS EAT JWT | [gpu_flow.md](gpu_flow.md) · [pending.md](pending.md) |
| **NVIDIA GPU CC (Azure)** | Azure NCC H100 v5 | AMD SEV-SNP + NVIDIA CC | Dual: SNP + NRAS EAT JWT | [gpu_flow.md](gpu_flow.md) |
| **NVIDIA GPU CC (AWS)** | AWS P5/P5en/P6 | NitroTPM + NVIDIA CC | Dual: NRAS EAT JWT for the GPU, plus a NitroTPM attestation document for the host's measured boot — chain-validated to the pinned `certs/nitro-root.pem`, which is the same root a NitroTPM document actually uses (Measured). Verifies PCR4/PCR7 against bake-time values and binds the document to the session key. **CPU memory is still not encrypted** — measured boot is weaker than a CPU-TEE | [gpu_flow.md](gpu_flow.md) · [pending.md](pending.md) |

The two rows linking to [pending.md](pending.md) — **GPU CC (GCP)** and **GPU CC
(AWS)** — are the platforms blocked on accelerator capacity. `tdx-azure` *has*
completed attestation on hardware, through Microsoft Azure Attestation rather than
Intel DCAP; see note ¹ below for why that distinction is explicit rather than
inferred.

---

## Shared Architecture

Every deployment follows the same five-phase pipeline:

```
Phase 1 Phase 2 Phase 3 Phase 4 Phase 5
┌──────────┐ ┌──────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────────┐
│ Container│ │ Platform │ │ IaC │ │ Deploy │ │ Post-Deploy │
│ Build │───►│ Packaging │───►│ Generate │──►│ Terraform │──►│ Verification │
│ + Scan │ │ + Measure │ │ │ │ Apply │ │ + Audit bundle │
└──────────┘ └──────────────┘ └────────────┘ └────────────┘ └─────────────────┘
```

### Phase 1 — Container build

- Build the user's Docker image from their `Dockerfile`.
- Run Trivy/Grype vulnerability gate (override with `--allow-vulnerable`).
- Record image digest and layer measurements for attestation baseline.

See [container_build.md](container_build.md) for the full build-and-measure
pipeline.

### Phase 2 — Platform packaging

- **Persistent (VM-class):** stage the attested ingress proxy and user
 container tarball; wire RA-TLS cert rotation and re-attestation policy.
- **Batch:** stage the batch collector, input mount, and (for `sgx-azure`)
 GSC graminize/sign hooks.
- **Nitro:** build the Enclave Image File (EIF) when required by the platform
 path.

### Phase 3 — IaC generation

Deterministic Terraform from per-platform templates: VPC/VNet, least-privilege
IAM, KMS/Key Vault, logging, hardened compute.

### Phase 4 — Deploy

Terraform apply on a pinned, pre-baked AMI/image. No on-the-fly cloud-init
bake in production.

### Phase 5 — Post-deploy verification

- **Persistent:** client verifies RA-TLS attestation, sends a test request,
 collects `client_output.json`, `client_stderr.log` and signed provenance.
 `client_stderr.log` is the verifier's own reasoning — which binding mode held,
 whether the nonce echo matched, whether the attestation key was rooted in
 hardware-signed evidence — and is written on failure as well as success, since
 that is when it matters most.
- **Batch:** waits for container exit, downloads `output.tar.gz`, verifies
 attestation document + audit bundle.

---

## Deployment Matrix

**19 supported paths**: 10 platforms × 2 run modes, minus `sgx-azure`
`--persistent`, which is rejected at CLI parse time.

| Platform | `--batch` | `--persistent` |
|----------|-----------|----------------|
| `nitro-aws` | ✅ | ✅ |
| `snp-aws` / `snp-azure` / `snp-gcp` | ✅ | ✅ |
| `tdx-gcp` | ✅ | ✅ |
| `tdx-azure` | ✅ ¹ | ✅ ¹ |
| `gpu-cc-gcp` / `gpu-cc-azure` / `gpu-cc-aws` | ✅ | ✅ |
| `sgx-azure` | ✅ (GSC) | ❌ |

¹ **`tdx-azure` attests through Microsoft Azure Attestation, not Intel DCAP.** An
Azure paravisor CVM cannot generate a DCAP quote — there is no Quoting Enclave,
and the vTPM yields a raw `TDREPORT` that only the TDX module and a QE can
verify. So this platform requires
`TEE_CRAFTER_TDX_EVIDENCE_FORMAT=azure-guest` and a `TEE_CRAFTER_MAA_ENDPOINT`:
the guest's evidence is exchanged for an MAA token, and the token's verdict is
the attestation. The trust root is therefore Microsoft rather than Intel, which
is a real difference from `tdx-gcp` and is why the flag is explicit rather than
inferred. See [tdx_flow.md](tdx_flow.md) item 9.

See [security.md](security.md) for the full control matrix.

---

## Security Model (Shared)

| Defense | Description |
|---------|-------------|
| **Hardware isolation** | CPU (and GPU CC) memory encryption across all ten backends |
| **Attested ingress proxy** | Persistent VM-class runs terminate RA-TLS in a platform-owned gateway; user containers stay unmodified |
| **Zero-trust host** | Hosts never see plaintext application data on the attested channel |
| **Docker hardening** | `--cap-drop ALL`, `--read-only`, seccomp, AppArmor, `--pids-limit` on user containers |
| **Network isolation** | No public IP on any workload NIC; operator access via SSM / Bastion / IAP only. Public IPs exist solely on the Azure Bastion host and, where egress is enabled, the NAT gateway — never on the VM itself |
| **Build provenance** | Hash-chained, Ed25519-signed audit trail; `tee-crafter verify-provenance` |
| **Continuous attestation** | Proxy/host re-attest loop exported to SIEM on persistent runs |

---

## Public deploy command

```bash
tee-crafter deploy <path|image> \
--tee-platform <platform> \
[--batch | --persistent] \
[--service-profile long-lived|short-lived|streaming] \
[--byok-config <json>] [--siem-config <json>] \
[--instance-type <type>] [--spot] [--ami-id <id>] \
[--deploy] [--auto-approve] [--teardown]
```


---

## Documentation index

| Document | Description |
|----------|-------------|
| [execution_model.md](execution_model.md) | Unified Dockerfile model (`--batch` / `--persistent`) |
| [attested_proxy.md](attested_proxy.md) | Attested ingress proxy for persistent services |
| [batch_mode.md](batch_mode.md) | Batch capture, output bundles, security delta |
| [security.md](security.md) | Defense-in-depth architecture and control matrix |
| [cli_reference.md](cli_reference.md) | Every `tee-crafter` command and flag |
| [examples.md](examples.md) | Example applications and how to build your own |
| [container_build.md](container_build.md) | Container build, scan, and measurement pipeline |
| [nitro_flow.md](nitro_flow.md) · [sgx_flow.md](sgx_flow.md) · [tdx_flow.md](tdx_flow.md) · [snp_flow.md](snp_flow.md) · [gpu_flow.md](gpu_flow.md) | Per-platform deep dives |
| [aws_setup.md](aws_setup.md) · [azure_setup.md](azure_setup.md) · [gcp_setup.md](gcp_setup.md) | Cloud credential setup |
| [siem.md](siem.md) · [byok.md](byok.md) · [compliance.md](compliance.md) | Add-on features |
| [audit_matrix.md](audit_matrix.md) | Check catalogue for `verify-provenance` |
| [optimizations.md](optimizations.md) | Build/deploy performance |
| [pending.md](pending.md) | The to-do list: everything not yet done or verified |
| [hardware_verification.md](hardware_verification.md) | Rules for spending on a live run, each learned from a wasted one |
| [watchlist.md](watchlist.md) | Provider capabilities to re-check before acting on them |
| [report.tex](report.tex) | Technical report: system, trust model per backend, and the empirical measurement findings |
