# Instance Sizing for TEE-Crafter

TEE-Crafter has **no compute presets**. You pick a shape directly with:

```
--instance-type <type> # e.g. m6a.2xlarge, Standard_DC8as_v5, n2d-standard-16
--spot # optional: spot / low-priority / preemptible
```

When `--instance-type` is omitted, `deploy` uses the platform's **catalog
default** (smallest reviewed shape). The instance type fully determines vCPU /
RAM / GPU on the CVM and GPU platforms; on Nitro it selects the host EC2 type,
and the **enclave** is that host minus a fixed parent reserve (2 vCPU /
2048 MiB) — see [Nitro enclave sizing](#nitro-enclave-sizing-generic-ami).

## Discover shapes

The catalog (`apps/cli/src/tee_crafter/core/catalog.py`) is the single source of
truth for which shapes exist and their specs — and it is what the web UI lists.
From the CLI:

```bash
tee-crafter list-instances # every platform
tee-crafter list-instances --tee-platform snp-aws # one platform
```

Each row shows the instance type, vCPU, RAM (GiB), GPU (model × count) and CPU
generation, with the default marked.

## Supported families

The full cloud-allowed families are supported (any size in them):

| Platform | Families |
|-----------------|------------------------------------------------------------|
| `nitro-aws` | `c6a.*` host (x86_64, Secure-Boot-capable); enclave = host − parent reserve |
| `snp-aws` | `m6a`/`c6a`/`r6a` (Milan) **only** — not `7a`/`8a`, see note below |
| `snp-azure` | `DCas`/`ECas` and `DCads`/`ECads` **v5** (Milan) + **v6** (Genoa) |
| `snp-gcp` | `n2d-standard` / `n2d-highmem` / `n2d-highcpu` |
| `tdx-azure` | `DCes`/`ECes` and `DCeds`/`ECeds` v6 (Sapphire Rapids) |
| `tdx-gcp` | `c3-standard` / `c3-highmem` / `c3-highcpu` |
| `gpu-cc-gcp` | `a3-highgpu-{1,2,4,8}g` (H100) |
| `gpu-cc-azure` | `Standard_NCC40ads_H100_v5` (1 × H100) |
| `gpu-cc-aws` | `p5.4xlarge` / `p5.48xlarge` / `p5en.48xlarge` / `p6-b200.48xlarge` |
| `sgx-azure` | `Standard_DC*s_v3` |

> **`snp-aws` is Milan-only, and it is a hardware limit rather than a
> conservative default.** Of the 69 `m`/`c`/`r` `6a`+`7a` types EC2 publishes in
> us-east-1/us-east-2/us-west-2, only 16 carry the `amd-sev-snp` processor
> feature — all of them `6a`, capped at 128 GiB of guest memory. Newer AMD
> generations on EC2 (`m7a`/`c7a`/`r7a` Genoa, `m8a`/`r8a` Turin) exist but
> expose no SEV-SNP feature, so `deploy` refuses them at preflight. Verify for
> yourself:
>
> ```bash
> aws ec2 describe-instance-types \
> --filters Name=processor-info.supported-features,Values=amd-sev-snp \
> --query 'InstanceTypes[].InstanceType' --output text | tr '\t' '\n' \
> | sed 's/\..*//' | sort -u
> ```

RAM follows the cloud's per-vCPU ratio for the family (e.g. AWS `m`=4, `c`=2,
`r`=8 GiB/vCPU; Azure `DC`=4, `EC`=8 GiB/vCPU).

## Measurement constraint (SNP only)

AMD SEV-SNP launch measurements fold in the host **CPU generation** and **vCPU
count** (not RAM, not the family name). So the only limit on which SNP shape you
may deploy is that its **(generation, vCPU tier)** was measured at bake time.
`bake-ami` captures Milan + Genoa across the tiers in
`TEE_CRAFTER_SNP_CAPTURE_VCPUS` (default `2,4,8,16,32,48,64,96`) and auto-detects
vCPU-independent images (one digest then covers a whole generation). If you
deploy an un-captured shape, `deploy` fails closed with a hint to pick a
captured size, widen the tiers and re-bake, or pin it with `internal
pin-measurement --instance-type`. See [`measurements.md`](measurements.md).

TDX (`MRTD`) and the GPU/Nitro/SGX measurements are generation/vCPU-independent,
so one bake covers the whole family.

## Resolved shapes per platform

* **Nitro Enclaves (`nitro-aws`)** — `--instance-type` selects the host EC2 type
 (default `c6a.xlarge`). The enclave is sized as **host minus a parent reserve**
 (2 vCPU / 2048 MiB), e.g. `c6a.xlarge` → 2 vCPU / 6144 MiB enclave,
 `c6a.2xlarge` → 6 vCPU / 14336 MiB. Override the enclave shape directly with
 `TEE_CRAFTER_COMPUTE_OVERRIDE_CPU` / `_RAM_MB` if needed.
* **CVM platforms (`snp-*`, `tdx-*`, `sgx-azure`)** — the whole VM **is** the
 TEE, so `--instance-type` (vCPU/RAM) is the shape directly.
* **GPU CC platforms (`gpu-cc-*`)** — `--instance-type` selects the GPU SKU
 (model × count come from the catalog entry).

## Nitro enclave sizing (generic AMI)

A Nitro enclave is **not** the whole instance — it is a carve-out that runs
beside the parent OS (which hosts the vsock proxy, `nitro-cli`, and SSM). So:

* The **enclave** gets `host vCPU − 2` and `host RAM − 2048 MiB` (floored at
 2 vCPU / 512 MiB); the parent keeps the rest.
* The **AMI is generic**. `bake-ami` installs the Nitro tooling and a baseline
 `allocator.yaml`, but does **not** bake a hard enclave cap. At deploy,
 `deploy` rewrites the allocator's `memory_mib` **and** `cpu_count` to this
 instance's enclave shape before launching the enclave. One AMI baked on the
 default `c6a.xlarge` therefore runs unchanged on any larger `c6a.*` instance —
 no re-bake needed to scale up.
* The bake flags `--enclave-ram` / `--enclave-cpu` only set that baseline; you
 almost never need to change them.

## Advanced overrides

These environment variables replace individual dimensions of the resolved
shape. Prefer `--instance-type`; reach for these only when you need to pin one
dimension independently of the catalog:

```bash
TEE_CRAFTER_COMPUTE_OVERRIDE_INSTANCE_TYPE=Standard_DC16as_v6 # = --instance-type
TEE_CRAFTER_COMPUTE_OVERRIDE_CPU=8 # Nitro enclave / raw cpu
TEE_CRAFTER_COMPUTE_OVERRIDE_RAM_MB=16384
TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_MODEL=h100
TEE_CRAFTER_COMPUTE_OVERRIDE_GPU_COUNT=8
TEE_CRAFTER_COMPUTE_OVERRIDE_SPOT=1 # = --spot
```

## Platform-specific notes

- **Nitro (AWS)**: defaults to a **`c6a`** host (AMD Milan / x86_64) so the
 default bake + deploy carry **UEFI Secure Boot enrolled** (the AL2023
 `amazon-linux-sb-keys` package only ships pre-signed PK/KEK/db for x86_64,
 so a Graviton bake fails fast if Secure Boot is requested). **Graviton
 hosts are selectable**: the `c`, `m` and `r` families at generations `6g`
 through `9g`, which is the set `ec2:DescribeInstanceTypes` reports as
 `nitro-enclaves-support=supported` on arm64. Sizes differ by generation —
 `6g`/`7g` stop at `16xlarge`, `8g`/`9g` add `24xlarge` and `48xlarge` but
 never `32xlarge`. Choosing a Graviton host means giving up Secure Boot
 enrolment and building an arm64 enclave image; in exchange it is the only
 architecture an Apple Silicon workstation can build natively. See
 [nitro_flow.md](nitro_flow.md#graviton-hosts).
- **SGX / Gramine (Azure)**: requires `Standard_DC*s_v3`; always hardware-backed.
- **TDX (Azure)**: DCesv6 / ECesv6 (Sapphire Rapids), plus the DCedsv6 /
 ECedsv6 local-temp-disk variants. All four went GA in February 2026.
- **SNP (Azure)**: DCasv5 / ECasv5 (Milan) or DCasv6 / ECasv6 (Genoa), plus the
 matching DCads / ECads local-disk variants; default quota is often 0 —
 request an increase.

> **Azure's trailing `d` is a separate SKU, not an option.**
> `Standard_DC2es_v6` and `Standard_DC2eds_v6` are different VM sizes; the `d`
> means the size ships a local temp disk. Both are catalogued, and each `d`
> variant has the same vCPU tiers and the same GiB/vCPU as its non-`d` twin
> (measured against `az vm list-skus --location westus`). Pick the
> `d` variant only if your workload wants ephemeral local scratch — it does not
> change the TEE properties.
- **SNP (AWS)**: M6a/C6a/R6a (Milan) only, `amd_sev_snp = "enabled"`. Genoa
 `m7a`/`c7a`/`r7a` exists on EC2 but **cannot** do SEV-SNP — AWS publishes no
 `amd-sev-snp` processor feature on any 7a or 8a type, so `deploy` refuses
 them. Re-confirmed against the live API.
- **SNP (GCP)**: N2D (Milan default; Genoa via `--min-cpu-platform`).
- **TDX (GCP)**: C3 Sapphire Rapids.
- **GPU CC (GCP)**: A3 + H100 + Intel TDX. Requires `NVIDIA_NRAS_API_KEY`.
- **GPU CC (Azure)**: NCC H100 v5 + AMD SEV-SNP. 1 GPU only.
- **GPU CC (AWS)**: P5 / P5en / P6. **Weaker model** — no hardware CPU-TEE;
 opt-in via `TEE_CRAFTER_ACCEPT_PARTIAL_CC=1`.

**Cost warning:** GPU instances are expensive (P5.48xlarge ~$98/hr, NCC H100 v5
~$55/hr, A3 ~$40/hr). Tear resources down after runs with
`tee-crafter destroy`.

## Practical workflow

1. Run `tee-crafter list-instances --tee-platform <p>` and pick a shape.
2. `deploy` with no `--instance-type` for the default, or pass one explicitly.
3. If a run is slow or OOMs, pick a larger shape (more vCPU / a `highmem`
 family); add `--spot` for cost-sensitive runs (needs spot quota).

See `docs/project.md` for the full security reasoning and `docs/security.md`
for the threat model.
