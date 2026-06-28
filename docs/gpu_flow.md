# NVIDIA Confidential GPU Flow

TEE-Crafter supports **NVIDIA Confidential Computing** across all three clouds,
enabling AI/ML workloads to run on hardware-encrypted GPUs with cryptographic
attestation of both CPU and GPU execution environments.

| Platform | Cloud | CPU TEE | GPU | Attestation | PCIe Encrypted | Security Model |
|----------|-------|---------|-----|-------------|---------------|----------------|
| `gpu-cc-gcp` | GCP A3 | Intel TDX | H100 | Dual: TDX quote + NVIDIA NRAS | Yes | Full-confidential |
| `gpu-cc-azure` | Azure NCC H100 v5 | AMD SEV-SNP | H100 | Dual: SNP report (VCEK→ASK→ARK) + NVIDIA NRAS | Yes | Full-confidential |
| `gpu-cc-aws` | AWS P5/P5en/P6 | **None** | H100/H200/B200 | Dual: NVIDIA NRAS + NitroTPM measured boot (PCR4/PCR7, chain-validated to the pinned Nitro root) | **No** | **GPU TEE + CPU measured boot** |

> **`gpu-cc-aws` attests the CPU host's boot chain but not its memory**, and
> refuses to connect if the peer presents no attestation document. "CPU TEE:
> None" above is accurate and is the point: measured boot is not memory
> encryption. See [CPU attestation on `gpu-cc-aws`](#cpu-attestation-on-gpu-cc-aws-measured-boot-verified-locally)
> below before choosing this platform.

---

## How NVIDIA Confidential Computing Works

NVIDIA Confidential Computing (CC) protects data processed on GPUs by
encrypting GPU memory using hardware keys managed by the GPU's on-die
security processor. When CC mode is enabled:

1. **GPU memory encryption** — all data in GPU HBM is encrypted with
 AES keys that are inaccessible to the host OS, hypervisor, or cloud
 provider.
2. **Firmware attestation** — the GPU's firmware, driver version, and CC
 mode status are attested through the NVIDIA Remote Attestation Service
 (NRAS), which issues a signed Entity Attestation Token (EAT JWT).
3. **CPU-GPU link protection** — on GCP (TDX) and Azure (SEV-SNP), the
 PCIe link between the CPU TEE and GPU is encrypted by the CPU's
 hardware TEE, creating an end-to-end encrypted path from client to
 GPU memory. On AWS, there is no CPU-TEE, so the PCIe link is
 unencrypted.

### Supported GPU Models

| GPU | Instance Types | Driver | CUDA |
|-----|---------------|--------|------|
| **H100 (Hopper)** | GCP A3, Azure NCC H100 v5, AWS P5 | 535+ | 12.4+ |
| **H200 (Hopper)** | AWS P5en | 535+ | 12.4+ |
| **B200 (Blackwell)** | AWS P6 | 590+ | 13.1+ |

---

## Dual Attestation Architecture

TEE-Crafter implements **dual attestation** — independently verifying
both the CPU-side TEE and the GPU-side TEE before transmitting any data.

### GCP (`gpu-cc-gcp`)

```
Client GCP A3 VM (Intel TDX + H100 CC)
 │ ┌─────────────────────────────────┐
 │ 1. TLS connect │ RA-TLS Server │
 │───────────────────────►│ ┌─────────────────────────┐ │
 │ │ │ TDX Quote (MRTD) │ │
 │ 2. Get attestation │ │ + NVIDIA NRAS EAT JWT │ │
 │◄───────────────────────│ │ embedded in X.509 ext │ │
 │ │ └─────────────────────────┘ │
 │ 3. Verify TDX quote │ │
 │ 4. Verify NRAS JWT │ ┌─────────────────────────┐ │
 │ 5. ECDH key exchange │ │ user GPU workload (via proxy) │ │
 │───────────────────────►│ │ runs on H100 GPU │ │
 │ │ │ (CC mode = ON) │ │
 │ 6. AES-GCM response │ └─────────────────────────┘ │
 │◄───────────────────────│ │
 │ │ PCIe link: ENCRYPTED (TDX) │
 │ └─────────────────────────────────┘
```

**CPU TEE extension OID:** `1.2.840.113741.1.13.1` (TDX quote)
**GPU TEE extension OID:** `1.3.6.1.4.1.59386.1.1` (NRAS EAT JWT)

### Azure (`gpu-cc-azure`)

```
Client Azure NCC H100 v5 (SEV-SNP + H100 CC)
 │ ┌──────────────────────────────────┐
 │ 1. TLS connect │ RA-TLS Server │
 │───────────────────────►│ ┌──────────────────────────┐ │
 │ │ │ SNP Report (measurement) │ │
 │ 2. Get attestation │ │ + NVIDIA NRAS EAT JWT │ │
 │◄───────────────────────│ │ embedded in X.509 ext │ │
 │ │ └──────────────────────────┘ │
 │ 3. Verify SNP report │ │
 │ 4. Verify NRAS JWT │ ┌──────────────────────────┐ │
 │ 5. ECDH key exchange │ │ user GPU workload (via proxy) │ │
 │───────────────────────►│ │ runs on H100 GPU │ │
 │ │ │ (CC mode = ON) │ │
 │ 6. AES-GCM response │ └──────────────────────────┘ │
 │◄───────────────────────│ │
 │ │ PCIe link: ENCRYPTED (SEV-SNP) │
 │ └──────────────────────────────────┘
```

**CPU TEE extension OID:** `1.3.6.1.4.1.3704.1.3.1` (SNP report)
**GPU TEE extension OID:** `1.3.6.1.4.1.59386.1.1` (NRAS EAT JWT)

The GPU-CC Azure client verifies all AMD SEV-SNP security properties including
AMD-SB-3015 (`PLATFORM_INFO` bit 5 and SNP firmware SVN from `REPORTED_TCB`).
Both checks are fatal. See [snp_flow.md](snp_flow.md) for details.

### Secure Boot on `gpu-cc-azure` and `gpu-cc-gcp`

Deployed VMs default to **UEFI Secure Boot disabled** for these two platforms (Terraform: `secure_boot_enabled = false` on Azure; `enable_secure_boot = false` in shielded instance config on GCP). The Terraform variable `enable_secure_boot` (default `false`) lets operators flip it on; see [security.md §15.1](security.md#151-uefi-secure-boot-defaults-to-off-on-gpu-cc-azure--gpu-cc-gcp-operational-configurable) for the full trade-off analysis.

**Why default OFF, not "immutable OFF":**

* NVIDIA H100 CC requires the **open** kernel module (`nvidia-*-open`, GSP-driven). Signed pre-built builds *do* exist:
 - **Canonical** ships them in `linux-modules-nvidia-<VER>-<flavour>-<KREL>` for the `generic`, `azure`, `azure-fde`, and `gcp` kernel flavours (versions 495 / 510 / 515 / 520 / 525 / 535 / 550 / 570 across releases).
 - **NVIDIA** ships them as precompiled `kmod` RPMs on RHEL / Rocky / Oracle Linux / SLES (e.g. `kmod-nvidia-open-580.…`). These are not applicable to our Ubuntu CVM image.
 - NVIDIA does **not** ship a separate "CC-mode" build — CC is a runtime GPU configuration applied via `nvidia_gpu_tools.py`; the same `nvidia-driver-XXX-open` package is used for CC and non-CC.
* Our current bake script installs the driver from **NVIDIA's CUDA apt repository** (`nvidia-headless-550-open` via `cuda-keyring`) to **pin the exact driver version** documented by NVIDIA's CC Deployment Guide. That repo's path is DKMS-built and therefore **unsigned** — kernel lockdown rejects it when Secure Boot is on.
* The script already has a **best-effort signed fallback**: when it detects kernel lockdown (`/sys/kernel/security/lockdown`), it walks a candidate list (`570-server-open`, `570-open`, `570-server`, `565-server-open`, `565-server`, `535-server-open`, `535-open`) looking for a Canonical-signed `linux-modules-nvidia-<variant>-${KERNEL_RELEASE}` package and installs that instead. If none matches the current kernel ABI, the script falls back to the DKMS path (which then fails to load under SB-on — a noisy failure rather than a silent one).
* MOK enrollment to sign at install time would *work*, but every MOK change perturbs vTPM `PCR4` / `PCR7`, defeating the F-8 vTPM-PCR binding we use to compensate for Secure Boot being off.

So Secure Boot OFF is the **reliable default**: the deploy is deterministic across NVIDIA driver versions. Secure Boot ON is **available as an opt-in** when the operator has verified that a Canonical-signed module exists for the kernel + driver combination they want.

**What stays in place when Secure Boot is OFF:** AMD SEV-SNP / Intel TDX **guest-memory encryption** is unaffected; the **vTPM** is still active and `PCR0–7` are populated by UEFI / shim regardless of Secure Boot enforcement state; the SNP report is read from vTPM NV `0x01400001` on Azure regardless of Secure Boot status; **`VMGuestStateOnly`** guest-state encryption on Azure, **NRAS** GPU attestation, **dual RA-TLS**, and the **encrypted CPU↔GPU PCIe link** (Azure NCC H100 v5 + GCP A3 Protected PCIe) are all unaffected. What we give up is **boot-chain image integrity enforcement** (firmware / shim / kernel signature checks), compensated for by the vTPM PCR0–7 binding (F-8) and continuous attestation drift detection.

**SNP attestation on Azure GPU CC VMs:** Azure Hyper-V CVMs do **not** expose `/dev/sev-guest` (that device is for KVM guests). The SNP attestation report is obtained from the **vTPM** at NV index `0x01400001` (HCL attestation report with `HCLA` header + 1184-byte SNP report). This path works on all Azure CVMs regardless of Secure Boot status. SNP attestation is **fatal** — if the vTPM report cannot be read, the server refuses to start.

**Bake alignment:** `bake-ami --tee-platform gpu-cc-azure` creates the temporary bake VM with **the same Secure Boot setting** the deploy intends to use (default OFF). Rebaking is required when you toggle `enable_secure_boot` so the bake VM exercises the signed-module probe under the chosen lockdown state and confirms the driver loads.

**How to enable Secure Boot for production (opt-in):**

1. Spin up a throwaway CVM with the same Marketplace image you bake from and confirm a Canonical-signed module is available for your kernel: `apt-cache search "^linux-modules-nvidia-.*-$(uname -r)$"`.
2. Re-bake with `bake-ami --tee-platform gpu-cc-azure --enable-secure-boot` (or `--tee-platform gpu-cc-gcp --enable-secure-boot`) and confirm the bake-time `modprobe nvidia` log says **"signed module installed"**, not **"DKMS fallback"**.
3. Deploy with `TF_VAR_enable_secure_boot=true` (or pass the equivalent flag through your wrapper).
4. Re-bake. Toggling Secure Boot changes the boot chain, so the vTPM PCRs
 change with it — and currently the bake captures them itself and
 `deploy` passes them to the client, so there is nothing to edit by hand.
 The values are read on the probe VM that the MRTD capture already boots
 (`capture_platform_measurements`) and stored as `vtpm_pcrs` in the
 registry record; `deploy` renders them into `EXPECTED_VTPM_PCRS`.
 Editing `client.template.py` — which this step used to tell you to do —
 would be overwritten by the next render.

### CPU attestation on `gpu-cc-aws` (measured boot, verified locally)

```
Client AWS P5/P5en/P6 (GPU CC, no CPU TEE)
 │ ┌──────────────────────────────────┐
 │ 1. TLS connect │ RA-TLS Server │
 │───────────────────────►│ ┌──────────────────────────┐ │
 │ │ │ NitroTPM attestation doc │ │
 │ 2. Verify the doc: │ │ (COSE_Sign1, signed by │ │
 │ chain to pinned │ │ the Nitro Hypervisor) │ │
 │ nitro-root.pem, │ │ + NVIDIA NRAS EAT JWT │ │
 │ COSE signature, │ └──────────────────────────┘ │
 │ PCR4/PCR7 vs bake, │ ┌──────────────────────────┐ │
 │ user_data binding │ │ user GPU workload (proxy)│ │
 │ (fatal on failure) │ │ runs on H100/H200/B200 │ │
 │ 3. Verify NRAS JWT │ │ (CC mode = ON) │ │
 │ 4. ECDH key exchange │ └──────────────────────────┘ │
 │───────────────────────►│ │
 │ 5. AES-GCM response │ PCIe link: ⚠ NOT ENCRYPTED │
 │◄───────────────────────│ CPU memory: ⚠ NOT ENCRYPTED │
 │ └──────────────────────────────────┘
```

**Signed CPU evidence OID:** `1.3.6.1.4.1.59386.2.3` (NitroTPM attestation
document, raw CBOR/COSE_Sign1)
**Unsigned PCR JSON OID:** `1.3.6.1.4.1.59386.2.1` (kept for operator context,
never used as evidence)
**GPU TEE extension OID:** `1.3.6.1.4.1.59386.1.1` (NRAS EAT JWT)

**The CPU side of `gpu-cc-aws` is attested — as measured boot, not as a TEE.**
A NitroTPM attestation document's `cabundle` roots at `CN=aws.nitro-enclaves`,
byte-for-byte the certificate pinned at `certs/nitro-root.pem`
(`sha256=641a0321…`) — the same root used for Nitro Enclaves attestation, not a
separate hierarchy. Measured against a 5163-byte document from a live instance:
the chain is TPM leaf → instance → zonal → region → root, five certificates,
every signature valid, and the COSE_Sign1 signature verifies under the leaf's
P-384 key.

So the client verifies it, with the trust root in this repository and no AWS
credentials involved. Four checks, each fatal:

1. **Chain to the pinned root** — every link's signature and validity window,
 terminating at `certs/nitro-root.pem`. Revocation is deliberately not
 checked, matching AWS's guidance for Nitro attestation documents and the
 existing `nitro-aws` client.
2. **COSE_Sign1 signature** over the payload, with the algorithm read from the
 protected header (`{1: -35}` = ES384 on real documents) rather than assumed.
3. **PCR4 and PCR7** against values captured at bake. PCR4 is the boot manager
 code, PCR7 the Secure Boot policy; the bank is **SHA-384**, which is what the
 document reports. Captured on a cheap probe instance, because those registers
 depend on the AMI's boot chain and not on the GPU.
4. **Channel binding** — the document's `user_data` must equal
 `sha256(ecdh_pub)` for this session. Without it, a genuine document from any
 other instance in the account would pass.

What this does **not** give you is memory encryption. There is no CPU-TEE on AWS
GPU instances: RAM is visible to the hypervisor and the CPU–GPU PCIe link is not
TEE-encrypted. Measured boot proves what booted, not that what is running is
private. That is a real but strictly weaker property, and the client's banner
says so on every connection.

If the certificate carries no document at all, the client fails closed. The
usual cause is an image baked before the bake installed `nitro-tpm-attest`;
re-bake. To proceed anyway on GPU attestation alone:

```bash
TEE_CRAFTER_ALLOW_UNVERIFIED_AWS_CPU_ATTESTATION=1
```

The client then prints a banner stating the CPU host is unattested and reports
the security model as `gpu-only-cpu-unattested` rather than
`gpu-attested-cpu-measured-boot`.

Pick `gpu-cc-gcp` (Intel TDX) or `gpu-cc-azure` (AMD SEV-SNP) if you need CPU
memory encrypted and the PCIe link protected.

---

## NVIDIA Remote Attestation Service (NRAS)

NVIDIA NRAS is a cloud service that verifies GPU integrity:

- **Default remote endpoint (code):** `https://nras.attestation.nvidia.com/v4/attest/gpu` (`apps/cli/src/tee_crafter/core/gpu/nvidia_attestation.py`)
- **JWKS:** `https://nras.attestation.nvidia.com/.well-known/jwks.json`
- **Token format:** Entity Attestation Token (EAT) as a signed JWT
- **Algorithms:** ES384, RS256

### What NRAS Verifies

The NRAS token attests:
- GPU hardware identity (serial, model)
- GPU firmware version and integrity
- GPU driver version (must be 535+ for Hopper, 590+ for Blackwell)
- CC mode status (must be `ON` for production)
- VBIOS integrity

### NRAS trust anchor

TEE-Crafter ships the NVIDIA NRAS **intermediate** CA certificate at
`apps/cli/src/tee_crafter/certs/nvidia-nras-intermediate.pem`, loaded by
`core/builder/platforms.py` (line 290) and embedded into client templates at
build time via the `{nvidia_root_ca}` placeholder. Client templates use it to
verify NRAS JWT signatures without trusting the network.

The filename says *intermediate* because that is what it is — the certificate
is not self-signed:

| Field | Value |
|-------|-------|
| Subject | `CN=NVIDIA Attestation Service GPU Intermediate 004, O=NVIDIA Corporation, C=US` |
| Issuer | `CN=NVIDIA Attestation Service CA 001, O=NVIDIA Corporation, C=US` |
| Self-signed | No |
| Expires | **2029-12-08** |

**Operational dependency worth planning for.** This certificate is pinned by
exact DER comparison, and there is no fallback path. When NVIDIA rotates the
intermediate — at the latest when it expires — every deployed
`gpu-cc-*` client fails closed until it is re-rendered against the new
certificate. Track the expiry alongside your other trust-anchor rotations.

### `NVIDIA_NRAS_API_KEY` (deploy vs runtime)

- **Deploy CLI (`tee-crafter deploy`):** For `--tee-platform gpu-cc-*`, the CLI **requires a non-empty** `NVIDIA_NRAS_API_KEY` in the environment (usually from `.env`). If it is unset or empty, deploy stops before provisioning. GPU CC setup scripts (`*_setup.py`, `*_phase.py`) also require a non-empty value when they write `/opt/tee-crafter-gpu-cc/.env` to the VM.
- **NRAS remote attestation:** TEE-Crafter passes the **v4** endpoint URL to the `nv-attestation-sdk`. The implementation does **not** send `NVIDIA_NRAS_API_KEY` as an NRAS service/Bearer key for that endpoint (an unrelated key caused HTTP 403 in testing). Do **not** assume an [NVIDIA NGC](https://ngc.nvidia.com) API key is an NRAS key—they are different products.
- **On the VM (runtime):** GPU CC app templates read `NVIDIA_NRAS_API_KEY` from the environment; if it is missing they **log a warning** and still run remote GPU attestation. **`sys.exit(1)`** applies when **GPU NRAS verification fails** (`verified` false), not merely when the variable is unset.
- **Store in:** `.env` only for local deploy — never pass via CLI flags or shell history.

---

## Deployment Pipeline

GPU CC deployments follow the same 5-phase pipeline as other TEE-Crafter
platforms, with GPU-specific additions:

### Phase 1: Container Build & Measurement

Same as all platforms: build the user's Docker image, scan with Trivy/Grype,
record digest and measurements. GPU workloads ship CUDA/PyTorch inside their
Dockerfile (see `examples/gpu_confidential_inference/`).

See [container_build.md](container_build.md).

### Phase 2: Crypto Packaging

- RA-TLS templates embed **two** X.509 extensions: CPU attestation
 (TDX/SNP/NitroTPM) + GPU attestation (NRAS EAT JWT).
- Client templates verify **both** attestation reports.
- ECDH protocol ID: `tee-crafter-gpu-cc-v1` (distinct from CPU-only
 templates which use `tee-crafter-tdx-v1` or `tee-crafter-snp-v1`).

### Phase 3: IaC Generation

Terraform templates provision GPU-capable infrastructure:

| Resource | GCP | Azure | AWS |
|----------|-----|-------|-----|
| VM/Instance | A3 Confidential VM | NCC H100 v5 CVM | P5/P5en/P6 |
| CPU TEE | TDX (`confidential_instance_type = "TDX"`) | SEV-SNP (`security_encryption_type = "VMGuestStateOnly"`) | NitroTPM |
| UEFI Secure Boot | **Off by default** (driver pinning); opt-in via `enable_secure_boot=true` | **Off by default** (driver pinning); opt-in via `enable_secure_boot=true` | (AMI / Nitro policy) |
| Disk | 200 GB pd-ssd + CMEK | 200 GB Premium_LRS + guest-state encryption | 200 GB gp3 encrypted |
| Network | Private VPC + IAP + NRAS egress rule | Private VNet + Bastion + NRAS NSG rule | Private VPC + SSM + VPC endpoints |
| Flow logs | Subnet flow logs (5s, 100%) | VNet flow logs + Traffic Analytics | VPC Flow Logs to CloudWatch |
| KMS | Cloud KMS keyring + key | N/A (Azure-managed) | Dedicated KMS key + rotation |
| S3/Storage | GCS bucket (CMEK, lifecycle) | Storage account (TLS 1.2, network rules) | S3 bucket (KMS, lifecycle, SSL-only policy) |
| GPU driver | Installed via setup script / baked image | Installed via setup script / baked image | Installed via setup script / baked image |

### Phase 4: Deploy

1. Terraform provisions the infrastructure.
2. Setup scripts (via SSM/Bastion/IAP) install:
 - NVIDIA GPU drivers (open kernel module packages: `nvidia-headless-550-open` + `nvidia-utils-550`; avoids conflicting proprietary modules on many CVM images). **Azure/GCP deploy** keeps Secure Boot **off** so the DKMS-built module is not rejected by kernel lockdown.
 - CUDA toolkit (currently `cuda-toolkit-12-4`)
 - NVIDIA Container Toolkit (for container mode)
 - `nv-attestation-sdk` (Python attestation SDK)
3. The guest signals GPU readiness via `sudo nvidia-smi conf-compute -srs 1` (run as `ExecStartPre=+...` in systemd). CC mode itself is enforced by the platform/hypervisor; the guest verifies status with `nvidia-smi conf-compute -f`.
4. When the local environment has `NVIDIA_NRAS_API_KEY` set (required for
 the current deploy CLI), that value is written to a `chmod 600` file on
 the VM (`/opt/tee-crafter-gpu-cc/.env`).
5. Systemd unit file uses `EnvironmentFile` to load the key securely.

### Phase 5: Post-Deploy + Verification

1. Server starts, generates RA-TLS certificate with dual extensions.
2. Server requests GPU attestation from NRAS → obtains EAT JWT.
3. Client connects, extracts CPU + GPU attestation from the certificate.
4. Client verifies CPU attestation (TDX quote / SNP report / NitroTPM PCRs).
5. Client verifies GPU attestation (NRAS JWT signature against root CA).
6. The deploy-time client binds the attested ECDH key, prints
 `{"status":"attestation_verified"}`, and exits — it sends no data.
7. In production, the customer's own client (fronted by the attested
 ingress proxy in service mode) opens the same dual-attested channel:
 ECDH key exchange → AES-GCM encrypted request/response → the proxy
 forwards plaintext to the user GPU container on `127.0.0.1` and
 returns the encrypted response.

---

## Quota Requirements

GPU CC instances are large and require specific quotas. **Default is On-Demand**; pass **`--spot`** (or set `TEE_CRAFTER_SPOT=1`) only if you want Spot/preemptible and have the matching quota. Pick a larger GPU SKU with `--instance-type` (see `tee-crafter list-instances --tee-platform gpu-cc-<cloud>`).

| Cloud | Default Instance | vCPUs | GPUs | Default Region | Key Quota |
|---|---|---|---|---|---|
| **AWS** | `p5.4xlarge` | 16 | 1 H100 | `us-east-2` | On-Demand: `Running On-Demand P instances` >= 16. With `--spot`: also `All P Spot Instance Requests` >= 16 |
| **Azure** | `Standard_NCC40ads_H100_v5` | 40 | 1 H100 | `eastus2` | On-Demand: `Standard NCCads2023 Family vCPUs` >= 40. With `--spot`: also `Total Regional Low-priority vCPUs` >= 40 |
| **GCP** | `a3-highgpu-1g` | 26 | 1 H100 | `us-central1-a` | On-Demand: `CPUS` >= 26, `NVIDIA_H100_80GB_GPUS` >= 1. With `--spot`: `PREEMPTIBLE_CPUS` >= 26 (and preemptible GPU quota if applicable) |

For detailed quota check commands and request instructions, see:
- [docs/aws_setup.md](aws_setup.md) -- AWS quotas
- [docs/azure_setup.md](azure_setup.md) -- Azure quotas (region split: West US for CPU TEE, East US 2 for GPU CC)
- [docs/gcp_setup.md](gcp_setup.md) -- GCP quotas

TEE-Crafter runs **pre-flight checks** before deploying or baking and reports actionable quota errors early.

### Quota is necessary but not sufficient — capacity is a separate gate

Having quota does not mean the cloud will give you the instance. These are two
independent failures, and only the first is something a support ticket fixes:

- **Quota** — an account limit. AWS reports `VcpuLimitExceeded`; GCP reports
 `QUOTA_EXCEEDED`. Raise it via a quota-increase request.
- **Capacity** — whether the hardware is free in that zone right now. AWS
 reports `InsufficientInstanceCapacity`; GCP reports
 `ZONE_RESOURCE_POOL_EXHAUSTED`. No ticket helps; you retry, change zone,
 change instance size, or reserve (AWS Capacity Blocks / ODCR, GCP
 future reservations).

Measured by attempting `RunInstances` in every AZ of both regions
(a rejected launch is free, and the error name distinguishes the two causes):

| Instance | GPUs | Region | On-demand | Spot |
|---|---|---|---|---|
| `p5.4xlarge` (the `gpu-cc-aws` default) | 1× H100 | `us-east-2` (3 AZs), `us-west-2` (4 AZs) | `InsufficientInstanceCapacity` everywhere | `InsufficientInstanceCapacity` everywhere |
| `p5.48xlarge` | 8× H100 | same | `InsufficientInstanceCapacity` everywhere | `MaxSpotInstanceCountExceeded` (quota, not capacity) |

Two different walls in one table, which is the point of separating them:
`p5.4xlarge` failed on **capacity** with quota to spare, while `p5.48xlarge`
(192 vCPUs) failed on **spot quota** — so for the larger SKU a quota-increase
request is the correct action, and for the smaller one it would be useless.

> Baking tolerates transient shortages: `bake-ami` retries `RunInstances` for
> `TEE_CRAFTER_AWS_GPU_CAPACITY_WAIT_SECONDS` (default `600`) before giving up.
> For a deadline you cannot miss, reserve ahead rather than retrying — AWS
> Capacity Blocks for ML or an ODCR.

On GCP, note that an H100 quota metric is **absent entirely** from
`gcloud compute regions describe <region>` until your project is granted H100
access — you will not see the metric sitting at `limit=0`, you will see no such
metric at all. Check with:

```bash
gcloud compute regions describe us-central1 --format=json \
  | python3 -c "import json,sys; print([q for q in json.load(sys.stdin)['quotas'] if 'H100' in q['metric']] or 'no H100 metric — request GPU access first')"
```

---

## Pre-Flight Validation

TEE-Crafter validates GPU CC configurations before deployment:

```python
GPU_CC_INSTANCES = {
    ("gcp", "h100", 1): "a3-highgpu-1g",
    ("gcp", "h100", 2): "a3-highgpu-2g",
    ("gcp", "h100", 4): "a3-highgpu-4g",
    ("gcp", "h100", 8): "a3-highgpu-8g",
    ("azure", "h100", 1): "Standard_NCC40ads_H100_v5",
    ("aws", "h100", 1): "p5.4xlarge",
    ("aws", "h100", 8): "p5.48xlarge",
    ("aws", "h200", 8): "p5en.48xlarge",
    ("aws", "b200", 8): "p6-b200.48xlarge",
}
```

**GPU count availability per cloud:**

| Cloud | H100 counts | H200 counts | B200 counts |
|-------|------------|------------|------------|
| GCP | 1, 2, 4, 8 | — | — |
| Azure | 1 only | — | — |
| AWS | 1, 8 | 8 only | 8 only |

GCP is the only cloud that supports a true 2-GPU confidential computing
instance (`a3-highgpu-2g`). Azure NCC H100 v5 comes in 1-GPU only. AWS
offers `p5.4xlarge` (1× H100) or `p5.48xlarge` (8× H100) with no
intermediate sizes.

The CLI validates:
- The chosen `--instance-type` (default: the platform's catalog default) maps to a supported `(cloud, gpu_model, gpu_count)` tuple in the catalog / `GPU_CC_INSTANCES` constraint map (the advanced overrides `TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_MODEL` / `TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_COUNT` / `TEE_CRAFTER_COMPUTE_OVERRIDE_INSTANCE_TYPE` can replace individual dimensions).
- `NVIDIA_NRAS_API_KEY` must be **non-empty** in the environment for GPU CC deploy (CLI gate).

---

## Systemd Hardening

GPU CC services run under the same strict systemd sandbox as CPU-only
TEE platforms:

- `User=tee_enclave` / `Group=tee_enclave` (non-root)
- `ProtectSystem=strict`
- `ProtectHome=yes`
- `PrivateTmp=yes`
- `NoNewPrivileges=yes`
- `ProtectKernelModules=yes`
- `ProtectKernelTunables=yes`
- `ProtectControlGroups=yes`
- `RestrictSUIDSGID=yes`
- `RestrictNamespaces=yes`
- `LockPersonality=yes`
- `EnvironmentFile=-/opt/tee-crafter-gpu-cc/.env` (optional vars incl. `NVIDIA_NRAS_API_KEY`, `chmod 600`)

GPU-specific device access:
- `DeviceAllow=/dev/nvidia* rw` (GPU devices)
- `ReadWritePaths=` includes `/tmp`, `/var/log/tee_crafter` (attestation / key-rotation logs), `/opt/tee-crafter-gpu-cc`, and platform-specific TEE paths (e.g. `/dev/tpm0`, `/sys/kernel/config/tsm` on Azure GPU CC) — see `apps/cli/src/tee_crafter/resources/systemd/gpu-cc-*.service`

---

## Continuous Attestation

The GPU CC attestation monitor (`tee_crafter_attestation_monitor.py`)
extends the standard CPU-only monitor with:

- **GPU health check** — verifies GPU is accessible and responsive
- **CC mode drift detection** — checks `nvidia-smi conf-compute` to
 ensure CC mode hasn't been disabled
- **NRAS token validity** — periodically re-requests GPU attestation
 and validates the token

Default monitoring interval: 300 seconds.

---

## Compliance

Twelve of the fourteen shipped compliance frameworks map at least one control
onto a GPU-CC evidence key. The two that do not are **EU NIS2** and the
**EU AI Act**.

| Evidence Key | Controls mapped | Frameworks | Examples |
|-------------|----------------|-----------|----------|
| `gpu_confidential_computing` | 49 | 12 | NIST 800-53 SC-28 (Protection of Information at Rest), HIPAA 164.312(a)(2)(iv), SOC 2 CC6.1, ISO 27001 A.8.24 |
| `gpu_attestation` | 30 | 12 | NIST 800-53 SI-7 (Software, Firmware, and Information Integrity), NIST CSF DE.CM-01, ISO 27001 A.8.15, SOC 2 CC7.1 |
| `dual_attestation_cpu_gpu` | 28 | 12 | NIST 800-53 AU-10 (Non-repudiation), HIPAA 164.312(d), SOC 2 CC6.7, CSA CCM IAM-14 |

Counts derived by intersecting each control's `evidence_keys` with
`build_default_registry.all`. See [compliance.md](compliance.md) for the
full framework list.

Evidence strength:

- **Strong** on `gpu-cc-gcp` and `gpu-cc-azure` — genuine dual attestation:
 a CPU TEE (TDX on GCP, SEV-SNP on Azure) plus NVIDIA NRAS GPU attestation,
 over an encrypted PCIe link.
- **Partial on `gpu-cc-aws` — real CPU evidence, but not a CPU TEE.** The host
 produces a hypervisor-signed NitroTPM attestation document, which the client
 verifies against the pinned `certs/nitro-root.pem` and compares to bake-time
 PCR4/PCR7. That is genuine measured boot, so `security_model` is
 `gpu-attested-cpu-measured-boot`. What is still absent is memory encryption:
 host RAM is visible to the hypervisor and the PCIe link is not TEE-encrypted,
 so `dual_attestation_cpu_gpu` — which means two *TEEs* — is still not
 satisfiable here. An operator whose image predates the document (no
 `nitro-tpm-attest` in the bake) can set
 `TEE_CRAFTER_ALLOW_UNVERIFIED_AWS_CPU_ATTESTATION=1` to proceed on GPU
 attestation alone and report `security_model=gpu-only-cpu-unattested`. See
 [CPU attestation on `gpu-cc-aws`](#cpu-attestation-on-gpu-cc-aws-measured-boot-verified-locally).

---

## Security Model Comparison

| Property | gpu-cc-gcp | gpu-cc-azure | gpu-cc-aws |
|----------|-----------|-------------|-----------|
| UEFI Secure Boot (deployed VM) | **Off by default**, opt-in supported | **Off by default**, opt-in supported | (varies by AMI) |
| CPU memory encrypted by hardware TEE | Yes (TDX) | Yes (SEV-SNP) | No |
| GPU memory encrypted by hardware CC | Yes | Yes | Yes |
| PCIe CPU↔GPU encrypted by TEE | Yes | Yes | **No** |
| CPU attestation type | TDX DCAP quote | SNP report | NitroTPM PCRs |
| GPU attestation type | NRAS EAT JWT | NRAS EAT JWT | NRAS EAT JWT |
| Client aborts on CPU attest failure | Yes | Yes | Yes |
| Client aborts on GPU attest failure | Yes (mandatory) | Yes (mandatory) | Yes (mandatory) |
| Server exits on GPU attest failure | Yes (`sys.exit(1)`) | Yes (`sys.exit(1)`) | Yes (`sys.exit(1)`) |
| RA-TLS / attestation rotation failure | Fatal (`sys.exit(1)`) | Fatal (`sys.exit(1)`) | Fatal (`sys.exit(1)`) |
| End-to-end confidentiality | Full | Full | Partial |
| Network flow logging | Subnet flow logs | VNet flow logs + Traffic Analytics | VPC Flow Logs |
| KMS for bucket encryption | Cloud KMS (CMEK) | Azure-managed | Dedicated KMS key |

---

## Examples

### Single-GPU Inference (`gpu_confidential_inference`)

Confidential radiology AI pipeline with EfficientNet-B0 backbone,
multi-task prediction, and Grad-CAM explainability.

```bash
tee-crafter deploy \
 --source./examples/gpu_confidential_inference \
  --tee-platform gpu-cc-gcp \
  --persistent \
  --deploy --auto-approve --teardown
```

---

## Attestation hardening controls

The GPU CC clients verify more than just the NRAS token and the CPU TEE
quote. The following additional bindings are enforced on every handshake:

### F-14 — TLS SPKI belt-and-braces

The NRAS nonce-binding X.509 extension embedded in the server's RA-TLS
certificate carries:

- `nonce_hex = SHA-256(ECDH_pub || salt)` — the NRAS nonce the server
 submitted to the NVIDIA NRAS v4 endpoint.
- `tls_spki_sha256 = SHA-256(DER(SubjectPublicKeyInfo))` — the hash of
 the TLS public key that signs the RA-TLS handshake.

Clients recompute `tls_spki_sha256` over the **actual** certificate the
TLS handshake negotiated and fail closed if the value in the extension
does not match. This makes it impossible for an attacker that steals
only the NRAS token to replay it against a cert they control. Servers
whose extensions do not carry `tls_spki_sha256` are rejected as
"out of date".

### F-8 — vTPM measured-boot PCRs (GCP GPU CC)

On GCP, the server reads SHA-256 PCRs 0–7 from `/dev/tpm0` via
`tpm2_pcrread` and embeds the JSON `{pcrs: {idx: hex,...}}` bundle in
a new X.509 extension (OID `1.3.6.1.4.1.59386.2.2`). Clients:

1. Extract the bundle from the cert.
2. Compare against `EXPECTED_VTPM_PCRS` (build-time pin rendered by
 `render_gpu_cc_gcp_client_template(expected_vtpm_pcrs=...)`) or
 `TEE_CRAFTER_EXPECTED_VTPM_PCRS` (runtime override, format
 `idx:hex,idx:hex,...`).
3. Self-pin on first contact if nothing is supplied, logging the
 observed PCRs so an operator can promote them to a pin.

A missing/malformed extension is fatal; a `tpm2_pcrread` failure on
the server is also fatal — there is no "soft" path.

### GPU-10 — no silent fallback (GCP TDX + GCP GPU CC)

Setting `TEE_CRAFTER_STRICT_TSM=1` on the server makes any failure of
the configfs-tsm attestation path (`/sys/kernel/config/tsm/report`)
fatal. The `/dev/tdx-guest` ioctl fallback is then disabled so
a misconfigured TSM cannot silently produce a quote from an
unexpected path.

### NET-GPU — NRAS egress defaults (Azure / GCP / AWS)

NVIDIA NRAS attestation is required at **runtime** on every GPU CC
platform, so the Terraform modules create an egress allow-rule for
`nras.attestation.nvidia.com` by default:

| Platform | Default NRAS egress | Override knob |
|----------|---------------------|---------------|
| `gpu-cc-aws` | AWS managed prefix list `com.amazonaws.global.cloudfront.origin-facing` (narrow) | `nras_egress_cidrs = [...]` to pin further |
| `gpu-cc-azure` | `Internet` service tag, TCP/443 only | `nras_egress_cidrs = [...]`, or `allow_nras_broad_internet = false` to force strict CIDR-only (fails closed) |
| `gpu-cc-gcp` | `0.0.0.0/0`, TCP/443 only | `nras_egress_cidrs = [...]`, or `allow_nras_broad_internet = false` to force strict CIDR-only |

Historically Azure and GCP required the operator to explicitly opt-in
to the broad Internet rule (`allow_nras_broad_internet = true`),
leaving default deploys unable to attest (`Connection to
nras.attestation.nvidia.com timed out`). The audit flipped the
defaults so out-of-box deploys attest, while still letting
security-sensitive operators narrow egress via `nras_egress_cidrs` or
lock it down completely by setting `allow_nras_broad_internet = false`.

### CC-PARSE — `nvidia-smi conf-compute -f` format drift

Driver 550.x emits `CC status: ON` rather than the older label
`Confidential Compute Feature: ON`. The CC-mode parser in
`apps/cli/src/tee_crafter/core/gpu/nvidia_attestation.py` accepts
`Feature|Mode|State|Status` as the keyword and has a key/value
fallback, so any `ON`/`OFF`/`DEVTOOLS` on the right-hand side of
`:` or `=` is honoured. Unknown output still fails closed.

### SNP-3 — vTPM AK binding (Azure GPU CC + Azure SNP)

On `gpu-cc-azure` the CPU-side report is minted by the Hyper-V paravisor, which
fixes `REPORT_DATA` to `sha256(runtime_data)` — so the guest cannot place
`SHA-256(AK_pub)` under AMD's signature, and an AK the guest generates cannot be
attested at all. The server therefore quotes with the **HCL's own attestation
key**, published as `keys[kid == "HCLAkPub"]` in that same runtime data: AMD
signs `REPORT_DATA`, `REPORT_DATA` commits to the runtime data, and the runtime
data names the AK that signed the quote.

Clients fail closed (`TEE_CRAFTER_STRICT_SNP_AK_BINDING=1`, default) unless that
binding holds, which defends against a "valid SNP report, attacker-chosen TPM
AK" splice. The mechanism is shared with `snp-azure`, where it is confirmed on
hardware; on `gpu-cc-azure` it has not yet been exercised, because the platform
has had no `NCCads` capacity. See [security.md](security.md) §13.7.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `NVIDIA_NRAS_API_KEY not set` (deploy) | Set a **non-empty** `NVIDIA_NRAS_API_KEY=` in `.env` so `tee-crafter deploy` / GPU setup can run. This satisfies the CLI gate; the NRAS endpoint does not use it as a Bearer token. Do not pass via CLI. |
| `nvidia-smi: command not found` | GPU driver installation may still be in progress. Wait for setup to complete. |
| `couldn't communicate with the NVIDIA driver` / `Key was rejected by service` (modprobe) | Usually **kernel lockdown** with Secure Boot **on** and an **unsigned** DKMS module. Either (a) redeploy with the default `enable_secure_boot=false`, or (b) confirm that the Canonical-signed `linux-modules-nvidia-<VER>-${KERNEL_RELEASE}` package was actually installed at bake time (check the bake log for "signed module installed"). Do **not** MOK-sign on Azure FDE CVMs without re-baselining the expected vTPM PCR set. |
| `CC mode is DEVTOOLS` | The guest cannot force CC mode. Ensure you are on a GPU-CC-capable instance/VM (NCC H100 v5 / A3 / P5/P6), verify status with `nvidia-smi conf-compute -f`, and set guest readiness with `sudo nvidia-smi conf-compute -srs 1`. |
| `GPU attestation failed` | Verify CC mode is ON, driver is 535+, and NRAS is reachable. |
| `CC feature not ON (parsed='unknown', raw='CC status: ON')` | Re-build with current `tee_crafter.core.gpu.nvidia_attestation` (accepts `Status` and any `key: ON/OFF/DEVTOOLS`). |
| `Connection to nras.attestation.nvidia.com timed out` | NSG/firewall blocks runtime NRAS egress. Default templates open HTTPS/443 to `Internet` (Azure) / `0.0.0.0/0` (GCP) / AWS CloudFront managed prefix list (AWS). To tighten, set `nras_egress_cidrs = [...]` with NVIDIA-published CIDRs. On a running VM the remediation is an `AllowNRAS` rule permitting TCP/443 outbound. |
| `NRAS token verification failed` | Check `nvidia-nras-intermediate.pem` is present and the NRAS endpoint is reachable. If the certificate has been rotated by NVIDIA, re-render the client against the new one. |
| `TLS SPKI mismatch (F-14)` | Client saw a `tls_spki_sha256` in the NRAS nonce-binding extension that does not match the peer cert's SPKI. Almost always an MITM. Abort. |
| `NRAS nonce-binding extension missing 'tls_spki_sha256' (F-14)` | Server was built from an older template — re-render with the current `gpu_cc/*/app.template.py` and redeploy. |
| `vTPM measured boot (F-8): PCR X mismatch` | PCR at index X does not match the pinned value. Either promote the server's current PCRs (`terraform output` + CLI warning shows them) to a new `expected_vtpm_pcrs` pin, or investigate boot-chain changes on the GCP VM. |
| `vTPM measured boot (F-8): FAILED (extension missing or malformed)` | Server could not read `/dev/tpm0`. Confirm the GCP VM has `enable_vtpm = true`. |
| `vTPM measured boot (F-8): FAILED (empty PCR map)` | `tpm2_pcrread` produced nothing, almost always because `tpm2-tools` is absent from the image. It was missing from `setup_gpu_cc_gcp.sh` previously even though the app shells out to it, so **any image baked before then fails here** — re-bake. `tests/cli/test_tpm2_tools_installed_where_used.py` now fails the suite if a template calls `tpm2_*` and its bake does not install it. |
| `vTPM measured boot (F-8): FAILED — no expected PCR set is pinned` | The registry has no `vtpm_pcrs` for this image, so there is nothing to compare against and the client refuses rather than pretending it checked. Bakes currently capture them on the probe VM the MRTD capture already boots; re-bake, or set `TEE_CRAFTER_EXPECTED_VTPM_PCRS` explicitly. |
| `SNP AK binding check failed (SNP-3)` | Client saw a valid SNP report whose `user_data` did not bind the TPM AK used for the quote. This is fatal in strict mode. Confirm the server is the current `snp/azure/app.template.py`. |
| `Quota exceeded for GPU instances` | **Default is On-Demand.** **AWS**: `Running On-Demand P instances` (L-417A185B) >= 16; add `All P Spot Instance Requests` only if using `--spot`. **Azure (East US 2)**: `Standard NCCads2023 Family vCPUs` >= 40; add `Total Regional Low-priority vCPUs` >= 40 only if using `--spot`. **GCP**: `CPUS` >= 26 and `NVIDIA_H100_80GB_GPUS` >= 1; add `PREEMPTIBLE_CPUS` only if using `--spot`. See cloud setup docs. |
| `InsufficientInstanceCapacity` / `ZONE_RESOURCE_POOL_EXHAUSTED` | **Not a quota problem** — the hardware is busy, so a quota-increase ticket will not help. See [Quota is necessary but not sufficient](#quota-is-necessary-but-not-sufficient--capacity-is-a-separate-gate). Retry, try another AZ/zone/region, or try a different GPU SKU with `--instance-type`. Raise `TEE_CRAFTER_AWS_GPU_CAPACITY_WAIT_SECONDS` (default `600`) to let the bake wait longer. For a slot you can count on, reserve: AWS Capacity Blocks for ML / ODCR, GCP future reservations. |
| `VcpuLimitExceeded` (on-demand) / `MaxSpotInstanceCountExceeded` (spot) | **This one _is_ quota** — and the two are separate limits, so raising on-demand does nothing for `--spot`. **AWS**: `Running On-Demand P instances` (L-417A185B) and `All P Spot Instance Requests` (L-7212CCBC), both in vCPUs — `p5.48xlarge` needs 192, `p5.4xlarge` needs 16. Note that reading these needs `servicequotas:GetServiceQuota`; a least-privilege deploy user often lacks it, in which case a launch attempt is the only way to observe the limit. |
| `PCIe link NOT encrypted (AWS)` | Expected behavior — AWS GPU CC is partial-confidential by design. |
| `sys.exit(1) on startup` | Server could not obtain **verified** GPU attestation, CPU attestation (SNP/TDX/NitroTPM), **TPM quote** (Azure SNP paths), or endorsement material where required. See journal logs—not simply “missing NRAS key” on the VM. |

---

## Key Files

| File | Purpose |
|------|---------|
| `apps/cli/src/tee_crafter/templates/gpu_cc/{gcp,azure,aws}/app.template.py` | Server-side RA-TLS template with dual attestation |
| `apps/cli/src/tee_crafter/templates/gpu_cc/{gcp,azure,aws}/client.template.py` | Client-side attestation verification |
| `apps/cli/src/tee_crafter/templates/gpu_cc/{gcp,azure,aws}/main.template.tf` | Terraform infrastructure template |
| `apps/cli/src/tee_crafter/cli/deployment/gpu_cc/{gcp,azure,aws}_setup.py` | First-boot setup scripts (driver, CC mode, NRAS) |
| `apps/cli/src/tee_crafter/cli/deployment/gpu_cc/{gcp,azure,aws}_phase.py` | Deployment phase orchestration |
| `apps/cli/src/tee_crafter/core/gpu/__init__.py` | `GPU_CC_INSTANCES` constraint map + `resolve_gpu_instance` |
| `apps/cli/src/tee_crafter/core/compliance/evidence.py` | GPU CC evidence collectors (3 keys) |
| `apps/cli/src/tee_crafter/certs/nvidia-nras-intermediate.pem` | NVIDIA NRAS intermediate CA certificate (pinned by exact DER; expires 2029-12-08) |
| `examples/gpu_confidential_inference/` | Single-GPU radiology AI inference example |
