# AWS Nitro Enclaves — Detailed Flow

## What is AWS Nitro Enclaves?

AWS Nitro Enclaves is a hardware-isolation technology built into the AWS Nitro System. An enclave is an isolated virtual machine carved out of an EC2 instance: it has its own kernel, memory, and CPU cores but **no persistent storage, no network access, and no interactive login**. The only communication channel between the host EC2 instance and the enclave is a local **vsock** (virtio socket) interface.

Nitro Enclaves provide **cryptographic attestation** via the Nitro Security Module (NSM). The NSM produces a signed attestation document containing **Platform Configuration Registers (PCRs)** — cryptographic measurements of the enclave image. These PCRs can be embedded in AWS KMS key policies, ensuring that **only a specific enclave binary** can decrypt data.

### Key Concepts

| Concept | Description |
|---------|-------------|
| **EIF** | Enclave Image File — a signed, immutable disk image containing the enclave OS and application |
| **PCR0** | Hash of the enclave image (code + data) |
| **PCR1** | Hash of the Linux kernel and boot ramdisk inside the enclave |
| **PCR2** | Hash of the application layer (user code) |
| **vsock** | Virtio socket — the only communication channel between host and enclave |
| **NSM** | Nitro Security Module — hardware that signs attestation documents |
| **CMS** | Cryptographic Message Syntax (RFC 5652) — envelope format used by KMS with `Recipient` attestation |

---

## Architecture

```
┌──────────────────┐ ┌───────────────────────────────────────────────────┐
│ │ SSM port-forward │ EC2 Host (Nitro-capable, private, no SSH) │
│ Local Client │ (localhost:PORT → 443) │ │
│ (client.py) │ ─────────────────────────► │ ┌─────────────────────────┐ │
│ │ │ │ host_proxy.py │ vsock CID 16:5005 │
│ 1. Attest │ │ │ (FastAPI, HTTPS) │ ◄──────────────────► │
│ 2. ECIES Encrypt│ │ │ blind proxy: │ │
│ 3. Send data │ │ │ - forwards JSON │ ┌─────────────────┐ │
│ 4. Get result │ │ │ - injects IAM creds │ │ Nitro Enclave │ │
│ │ │ └─────────────────────────┘ │ │ │
└──────────────────┘ │ │ app_vsock.py │ │
 │ ┌─────────────────────────┐ │ (user code) │ │
 │ │ vsock-proxy │ │ │ │
 │ │ (AWS-provided) │ │ KMS Decrypt │ │
 │ │ kms.*.amazonaws.com │ │ via NSM attest │ │
 │ │ CID 3: port 8000 │ │ CMS unwrap │ │
 │ └───────────┬─────────────┘ │ RSA-OAEP │ │
 │ │ └─────────────────┘ │
 │ ┌───────────▼─────────────┐ │
 │ │ VPC Interface │ │
 │ │ Endpoints │ │
 │ │ (KMS, SSM, SSMMessages,│ │
 │ │ EC2Messages, S3) │ │
 │ │ Private DNS enabled │ │
 │ └─────────────────────────┘ │
                                                └───────────────────────────────────────────────────┘
```

### Data Flow

```
Client Host Proxy Enclave KMS (via vsock-proxy)
 │ │ │ │
 │── POST /enclave ─────────► │ │
 │ {get_attestation} │── vsock ──────────────► │
 │ │ │── NSM.GetAttestation ──►│
 │ │ │◄── attestation doc ─────│
 │◄── {attestation_doc,─────│◄── vsock ─────────────│ │
 │ enclave_public_key} │ │ │
 │ │ │ │
 │ verify nonce, PCRs, │ │ │
 │ COSE_Sign1 signature, │ │ │
 │ cert chain → Root CA, │ │ │
 │ extract ECDH pubkey │ │ │
 │ │ │ │
 │ ECIES encrypt data │ │ │
 │ (ECDH + HKDF-SHA256 │ │ │
 │ → AES-256-GCM) │ │ │
 │ │ │ │
 │── POST /enclave ─────────► │ │
 │ {ECIES payload} │── inject IAM creds ──►│ │
 │ │── vsock ──────────────►│ │
 │ │ │ ECIES decrypt │
 │ │ │ user application │
 │ │ │ (optionally seed RNG │
 │ │ │ via KMS.GenerateRandom)│
 │ │ │ │
 │◄── ECIES-encrypted───────│◄── vsock ─────────────│ │
 │ response │ │ │
 │ decrypt with client key │ │ │
```

> The diagram shows the full **production** data path. The bundled
> deploy-time `client.py` runs only the top half — attestation
> verification through "extract ECDH pubkey" — then prints
> `{"status":"attestation_verified"}` and exits. The ECIES
> request/response below is what the customer's own client sends over
> the same attested channel; the framework neither defines nor
> inspects that payload.

---

## Pipeline Phases

### Phase 1: Container Build & Measurement

**Modules:** `cli/commands/deploy/flow_container.py`, `core/packaging/`

| Step | Action | Details |
|------|--------|---------|
| 1a | **Docker build** | Build the user's image from their `Dockerfile` |
| 1b | **Vulnerability scan** | Trivy/Grype gate (CRITICAL/HIGH block unless `--allow-vulnerable`) |
| 1c | **Digest + provenance** | Record OCI digest and layer hashes in `build_provenance.json` |
| 1d | **Artifact staging** | Save `user_container.tar` and platform templates to `builds/<app>_<platform>_<timestamp>/` |

See [container_build.md](container_build.md) for the full build pipeline.

### Phase 1b: Nitro-specific staging (persistent / batch)

| Step | Action | Details |
|------|--------|---------|
| 1e | **Entrypoint generation** | `generate_nitro_entrypoint` wraps the user container command for vsock/EIF path |
| 1f | **Host proxy** | Renders `host_proxy.template.py` — blind FastAPI HTTPS proxy with IAM credential injection |
| 1g | **Client template** | Renders `client.template.py` with PCR hashes and AWS Nitro Root CA |

### Phase 2: Cryptographic Packaging (EIF Build)

**Module:** `core/enclave/`

| Step | Action | Details |
|------|--------|---------|
| 2a | **Docker Image Build** | Builds the app image for the target architecture (`linux/amd64` for the x86_64 default, `c6a.xlarge`) |
| 2b | **EIF Build** | Runs `nitro-cli build-enclave` inside a containerized `amazonlinux:2023` helper image (Docker-in-Docker) |
| 2c | **PCR Extraction** | Captures PCR0, PCR1, PCR2 from `nitro-cli` output — these are the enclave's cryptographic identity |

> **Building an amd64 EIF on Apple Silicon: use the Rosetta backend, not QEMU.**
> `nitro-cli build-enclave` runs `linuxkit` to assemble the enclave's bootstrap
> ramfs. linuxkit is a Go binary, and Go's `lfstack` packs a pointer plus a
> counter into one 64-bit word assuming pointers fit in 48 bits. QEMU's
> amd64-on-aarch64 emulation hands out addresses above that range, so linuxkit
> aborts with `runtime: lfstack.push invalid packing` and `nitro-cli` reports
> only `E48 EIF building error` plus a Go backtrace that never mentions
> emulation.
>
> Measured on one darwin/arm64 machine, Docker 29.6.1:
>
> | Backend | Target | Result |
> |---|---|---|
> | QEMU (default) | `linux/amd64` | fails, `lfstack` abort |
> | **Rosetta** | `linux/amd64` | **builds, real PCR0** |
> | either | `linux/arm64` | builds |
>
> So on Apple Silicon, enable **Settings → General → "Use Rosetta for
> x86_64/amd64 emulation"** (needs `softwareupdate --install-rosetta`). An
> x86_64 Linux build host also works and is what CI should use. `build_enclave`
> does not refuse the combination up front — the emulator cannot be detected
> from where it runs — but it appends this explanation if the build fails with
> the `lfstack`/`E48` signature.

### Phase 3: Infrastructure-as-Code

**Module:** `llm/iac.py`, `core/iac/`

Terraform configuration is generated deterministically from `templates/nitro/main.template.tf` (no LLM involved).

#### Cloud Resources Created

| Resource | Configuration |
|----------|--------------|
| **EC2 Instance** | Nitro-capable (x86_64 default — `c6a.xlarge`; Graviton `c/m/r` `6g`–`9g` selectable when Secure Boot is explicitly disabled, see [Graviton hosts](#graviton-hosts)), `enclave_options.enabled = true`, IMDSv2 enforced, encrypted root volume, no public IP, Spot or On-Demand |
| **IAM Role** | Least privilege: S3 read (deployment bucket), `kms:GenerateRandom` (entropy), SSM Core (remote management) |
| **KMS Key** | Auto-rotating symmetric key. `kms:Decrypt` and `kms:GenerateRandom` gated by PCR0/1/2 attestation conditions; used for entropy seeding and optional KMS-encrypted ciphertext decryption |
| **VPC** | Per-deployment dedicated VPC (`10.0.0.0/16`) with private subnet, route table, and VPC Flow Logs to CloudWatch (ALL traffic, 60s aggregation, 30-day retention). No NAT gateway by default (mandatory pre-baked AMI); a NAT is provisioned only when SIEM (`egress_mode=auto/public`) or the internal `bake-ami` pipeline explicitly requires public egress |
| **Security Groups** | Zero ingress. Egress: HTTPS (443), DNS (53), S3 prefix list. Custom-AMI: HTTPS restricted to VPC CIDR only |
| **VPC Endpoints** | Interface endpoints (private DNS) for KMS, SSM, SSMMessages, EC2Messages. S3 Gateway endpoint on route table |
| **S3 Bucket** | Versioning, 1-day lifecycle, public access blocked, **SSE-KMS** with a dedicated KMS key, SSL-only policy |

#### PCR-Bound KMS Key Policy

```json
{
  "Sid": "AllowEnclaveDecryptViaPCR",
  "Effect": "Allow",
  "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": "<pcr0_hash>",
      "kms:RecipientAttestation:PCR1": "<pcr1_hash>",
      "kms:RecipientAttestation:PCR2": "<pcr2_hash>"
    }
  }
}
```

### Phase 4: Infrastructure Deployment

**Module:** `core/iac/`, `cli/deployment/common/terraform_step.py`

- `terraform apply` with up to 2 retries (hard-capped), 1200s timeout per attempt
- Returns structured outputs: `instance_id`, `private_ip`, `kms_key_arn`, `deployment_bucket`

### Phase 5: Post-Deployment Automation

**Module:** `cli/deployment/nitro/phase.py`, `cli/deployment/common/enclave_proxy.py`, `cli/deployment/common/client_step.py`

| Step | Action | Details |
|------|--------|---------|
| 8a | **SSM Wait** | Polls until instance registers with SSM (300s, 10s interval) |
| 8b | **Allocator Config** | Rewrites `allocator.yaml` `memory_mib` **and** `cpu_count` to this deploy's enclave shape (host vCPU/RAM minus the parent reserve) and restarts `nitro-enclaves-allocator.service`. This deploy-time sizing is what makes the baked AMI **generic** — one AMI runs on any instance size. Readiness is then judged two ways: the unit must report `active` (the allocator is all-or-nothing — it rolls every reservation back and exits non-zero rather than reserving part of the request), and `Hugetlb` in `/proc/meminfo` must cover the requested MiB. **`HugePages_Total` is deliberately not used**: the allocator reserves largest-page-size first, so most of a multi-GiB request lands on 1 GiB pages, and `HugePages_Total` counts only the default 2 MiB size. A shortfall aborts the deploy rather than warning — see the module docstring in `cli/deployment/nitro/allocator.py` for what happened when it did not |
| 8c | **AWS CLI Check** | Pre-flight check: `which aws && aws --version && aws s3 ls` via SSM |
| 8d | **EIF Upload** | Uploads `app.eif` to S3, then downloads on instance via `aws s3 cp` (S3+SSM pattern) |
| 8e | **Enclave Boot** | `nitro-cli run-enclave --cpu-count N --memory M --eif-path /home/ec2-user/app.eif --enclave-cid 16` (up to 3 attempts) |
| 8f | **Host Proxy** | Uploads `host_proxy.py`, verifies it on disk, and (re)starts `host-proxy.service` (uvicorn on `127.0.0.1:443` with TLS). A systemd override + `reset-failed` logic guards against crash loops and fixes older baked images with outdated `ExecStart` lines |
| 8g | **Attestation verification** | Opens SSM port-forward (localhost → instance:443) and runs `client.py` through the tunnel. The verifier completes RA-TLS, validates the COSE_Sign1 signature, cert chain to the Nitro Root CA, nonce freshness, PCR0/1/2, and SPKI binding, prints `{"status":"attestation_verified"}`, and exits. It sends **no** application data — that is the user's own client's job over the same attested channel |
| 9 | **Teardown** | Optional `terraform destroy` to remove all resources |

---

## Security Model

| Property | Implementation |
|----------|---------------|
| **Zero-Trust Host** | Host acts as blind HTTPS proxy. Injects IAM credentials but never sees plaintext — all client↔enclave traffic is ECIES-encrypted (AES-256-GCM with AAD) with an attested ECDH key. SSH is completely disabled |
| **Hardware Attestation** | Client verifies COSE_Sign1 signature (ECDSA P-384), X.509 certificate chain to AWS Nitro Root CA, nonce freshness, and PCR hash matching before trusting the enclave’s ECDH key |
| **KMS PCR-Binding** | `kms:Decrypt` and `kms:GenerateRandom` only permitted with valid attestation document matching exact PCR0/1/2. KMS is used for entropy seeding and optional KMS-encrypted ciphertext decryption; host cannot decrypt data |
| **CMS Envelope (KMS Path)** | For the KMS data path, KMS returns CMS EnvelopedData (RFC 5652); the enclave RSA-OAEP-unwraps the CEK and AES-decrypts the payload entirely inside the enclave |
| **Network Isolation** | No public IP, no ingress, all services on `127.0.0.1`. Traffic to AWS services via VPC endpoints only. Custom-AMI mode: HTTPS restricted to VPC CIDR |
| **Entropy Seeding** | NSM hardware RNG supplemented with 256 bytes from KMS `GenerateRandom` on first use |
| **Error Sanitization** | Enclave error responses contain only generic error string + exception type. No tracebacks or internal state |

---

## Key Files

| File | Purpose |
|------|---------|
| `templates/nitro/app_vsock.template.py` | Enclave application: vsock server, ECIES decrypt (ECDH + AES-256-GCM with AAD `b"tee-crafter-nitro-v1-req"` / `b"tee-crafter-nitro-v1-resp"`), optional KMS decrypt (CMS unwrap), NSM attestation, entropy seeding |
| `templates/nitro/client.template.py` | Deploy-time verifier: full attestation verification (COSE_Sign1, Nitro Root CA chain, nonce, PCR0/1/2) + ECDH key extraction/binding from the attested doc; prints `attestation_verified` and exits. ECIES request/response is a property of the channel (server side in `app_vsock.template.py`); production data is sent by the customer's own client |
| `templates/nitro/host_proxy.template.py` | Host proxy: blind FastAPI HTTPS proxy, IAM credential injection |
| `templates/common/Dockerfile.container.template` | Multi-stage: Rust nsm-cli build + user image base with TEE runtime overlay (boto3 trimmed). **Also carries the in-enclave module set** — see the note below |
| `templates/nitro/main.template.tf` | Terraform: EC2, KMS, IAM, S3, SG, VPC Endpoints |
| `templates/common/nsm_main.rs` | Rust source for the NSM CLI binary (attestation document generation) |
| `scripts/nitro_aws/setup_nitro.sh` | Host setup: packages, allocator, vsock-proxy, systemd services |
| `cli/deployment/nitro/phase.py` | Post-deploy orchestrator: SSM wait, allocator, pre-flight, handoff to enclave_proxy |
| `cli/deployment/common/enclave_proxy.py` | EIF upload, `nitro-cli run-enclave`, host proxy start |
| `cli/deployment/common/client_step.py` | SSM port-forward + local client execution + log collection on failure |
| `core/remote/ssm.py` | SSM command execution, S3 file upload, readiness polling |
| `core/enclave/` | Docker image build, EIF build (Docker-in-Docker), PCR extraction |

> **What lives inside the enclave, and why it matters here more than elsewhere.**
> On every other platform the TEE-Crafter app runs on the CVM host and imports
> its runtime modules from the build directory. On Nitro the **container is the
> enclave**, so `/tee-crafter-runtime` inside the image is the entire import
> path: `tee_entrypoint.sh` runs `python3 /tee-crafter-runtime/app_vsock.py`,
> which makes that directory `sys.path[0]`, and no `PYTHONPATH` is set.
>
> Seven modules therefore have to be `COPY`ed into the image —
> `tee_crafter_audit_logger`, `tee_crafter_runtime_bootstrap`,
> `tee_crafter_handler_sandbox`, `tee_crafter_key_rotation`,
> `tee_crafter_attestation_monitor`, `siem_health`, `byok_health`. Staging them
> into the build directory is **not** sufficient.
>
> `app_vsock.py` imports each with `except ImportError: pass`, so a missing
> module removes a gate without an error: the audit-log wrapper, the SIEM
> freshness gate, the BYOK release gate and the per-request seccomp sandbox all
> disappear quietly. Only the chain-key commitment fails closed, and it does so
> at the *client*. `tests/core/test_enclave_runtime_modules_copied.py` asserts
> the Dockerfile's `COPY` set covers everything the app template imports; keep
> the two in step. Adding or removing a module changes PCR0/PCR2.

---

## AMI Baking

The `tee-crafter internal bake-ami` command pre-installs all dependencies into a golden AMI:

- Docker, `aws-nitro-enclaves-cli`, allocator, vsock-proxy
- Python 3.12, FastAPI, uvicorn, boto3, cryptography
- Self-signed TLS certificates for the host proxy
- Systemd services: `host-proxy.service`, `nitro-enclaves-allocator.service`

Baked AMIs skip cloud-init, package installation, and internet egress at deploy time — the instance boots in a fully locked-down state.

### UEFI Secure Boot (on by default)

`bake-ami` defaults to `--enable-secure-boot`, which enrolls the
AWS-shipped `amazon-linux-sb-keys` PK/KEK/db blobs into the bake
instance's UEFI NVRAM via `efi-updatevar`. `aws ec2 create-image`
captures the resulting UEFI variable store into `Image.UefiData`,
so every instance launched from the AMI boots with Secure Boot
enforcing on its first boot:

The bake produces a **generic** AMI — the enclave allocator is sized at
deploy from the chosen instance (host minus parent reserve), so you do not
pin enclave dimensions at bake time and one AMI runs on any `c6a.*` size:

```bash
# Secure-Boot-enrolled bake (default)
tee-crafter internal bake-ami --tee-platform nitro-aws

# Dev bake without Secure Boot — pass --no-enable-secure-boot:
tee-crafter internal bake-ami --tee-platform nitro-aws --no-enable-secure-boot
```

(`--enclave-ram` / `--enclave-cpu` still exist to tune the baked allocator
baseline, but are rarely needed since `deploy` rewrites it.)

Secure Boot enrolment is currently **x86_64-only** (the AL2023
`amazon-linux-sb-keys` package validation has only been exercised on
x86_64; Graviton/arm64 bakes fail fast with a clear error if SB is
requested). Since that is the dominant code path, the default Nitro
instance type was flipped from `c6g.xlarge` (Graviton) to
**`c6a.xlarge`** (AMD Milan / x86_64) in May 2026 — both `bake-ami`
(`_NITRO_INSTANCE_TYPE`) and `deploy`
(`_PLATFORM_DEFAULTS["nitro-aws"]`). That default has not moved.

### Graviton hosts

Graviton **is** selectable. `--instance-type` (and
`TEE_CRAFTER_COMPUTE_OVERRIDE_INSTANCE_TYPE`, which feeds the same lookup)
accept the `c`, `m` and `r` families at generations `6g` through `9g` — so
`c7g.xlarge`, `m8g.4xlarge`, `r6g.2xlarge` and the rest all resolve.
`tee-crafter list-instances --tee-platform nitro-aws` enumerates them
alongside the x86 `c6a.*` hosts.

Two earlier versions of this page were both wrong about this, in opposite
directions, so here is the provenance rather than an assurance:

- The family list comes from `ec2:DescribeInstanceTypes` filtered on
 `nitro-enclaves-support=supported` **and**
 `processor-info.supported-architecture=arm64` (us-east-2) —
 AWS's own answer, not prose. A deliberately misspelt filter name was used
 as a control: the API rejects an unknown filter outright rather than
 returning an empty list, so the result set is a real answer.
- `catalog.lookup`'s `nitro-aws` branch matches both `^([mcr])([67])a\.` —
 the trailing `a` is the AMD family letter — and `^([mcr])([6789])g\.` for
 Graviton. Matching only the first would make every Graviton type return
 `None`, and `resolve_shape` (`cli/commands/deploy/compute.py`) would reject
 `c7g.xlarge` as "not a supported instance type for nitro-aws".
- `snp-aws` still rejects Graviton, and must: SEV-SNP is an AMD CPU feature,
 so an arm64 type there cannot launch at all.

Sizes differ by generation and are enumerated rather than derived: `6g` and
`7g` stop at `16xlarge`, while `8g` and `9g` add `24xlarge` and `48xlarge`
but never `32xlarge`. A size outside its generation's list is refused here
rather than passed to Terraform, so `c6g.24xlarge` and `m8g.32xlarge` — types
AWS does not sell — fail with a TEE-Crafter message instead of an opaque
`InvalidParameterValue` from EC2.

`large` (2 vCPU) is **refused**, not merely unlisted: an enclave is a
carve-out and the parent reserves 2 vCPU, so a 2-vCPU host has nothing left.
`unsupported_reason` says so explicitly ("below the 4 vCPU minimum"). The same
floor applies on the x86 side, where `c6a.large` is refused for the same
reason even though AWS reports it as Nitro-Enclaves-capable.

**Verified on hardware:** a `c7g.xlarge` deploy completed end to
end with `{"status": "attestation_verified"}` — PCR0
`5ffe53a9cd5174bd…` (COSE_Sign1/ES384), matching the build-time PCR0 in the
provenance. That was the first Graviton attestation to complete; before it, a
readiness check reading the wrong hugepage counter wedged the host (see the
module docstring in `cli/deployment/nitro/allocator.py`). The allocator
reserved the 6144 MiB as `5 × 1 GiB + 32 × 32 MiB` — three page sizes, one of
them arm64-only — which is why a 2 MiB counter could not see it.

Graviton matters beyond cost: it is the only architecture whose enclave
image an Apple Silicon workstation builds natively. `nitro-cli
build-enclave` on darwin/arm64 produces a real PCR0 with no Rosetta
involved, whereas an amd64 EIF build needs the Rosetta backend (see the
table above). Note that Graviton and x86 EIFs measure differently, and PCR0
is not reproducible across build hosts in any case, so pin per host.

`nitro_enclaves` is a *builtin* kernel module on AL2023, so enabling
SB neither requires nor breaks any loadable kernel modules — the
allocator / `nitro-cli build-enclave` / `nitro-cli run-enclave` chain
was exercised end-to-end under enforcing SB on `c6a.xlarge` and
reported `Kernel is locked down from EFI Secure Boot mode` in `dmesg`
with no regression to enclave functionality.

The successful bake stamps `tee-crafter-secure-boot=enabled` on the
AMI tag set. The Terraform variable `enable_secure_boot` *also*
defaults to `true`, so the deploy precondition refuses to launch
unless the supplied AMI carries that tag (or `TF_VAR_enable_secure_boot=false`
is explicitly set for the unbaked dev path). See
[security.md §15.1A](security.md) for the full design.

## Nitro hardening controls

### Nitro-1 — KMS IP range egress hint

`main.template.tf` exposes the regional KMS IP range via
`data "aws_ip_ranges" "kms_region"`. This is a **defense-in-depth
hint**: operators who deploy tee-crafter into a shared VPC without a
KMS interface VPC endpoint can use the data source to narrow
vsock-proxy egress to the KMS prefix list
(`data.aws_ip_ranges.kms_region.cidr_blocks`) rather than the default
`0.0.0.0/0`. The standard, preferred path uses the VPC endpoint for
KMS and does not need this hint.

### Nitro-4 — Digest-pin the EIF builder base

`core/enclave/enclave.py` defaults the EIF builder base image to
`amazonlinux:2023` and logs a warning when the operator has not
digest-pinned the builder. Production deploys should set:

```bash
export TEE_CRAFTER_NITRO_BUILDER_BASE="amazonlinux@sha256:<digest>"
```

so that the builder image is byte-stable across runs and cannot be
silently replaced by a poisoned `latest` tag upstream.

### Nitro-7 — Canonical `pcrs.json`

`build_enclave` writes a stable, sorted, canonical-JSON
`pcrs.json` file next to the built EIF containing:

```json
{
  "PCR0": "...",
  "PCR1": "...",
  "PCR2": "...",
  "eif_sha256": "...",
  "built_at": "<RFC3339>"
}
```

KMS key policies, Terraform pins, and CI verifiers should consume
this single authoritative file rather than re-parsing
`nitro-cli describe-eif` output. Because the file is canonical JSON,
its SHA-256 is directly comparable across runs.

### RMT-2 — Deployer IAM least privilege

`main.template.tf` emits an `rmt2_deployer_iam_policy` Terraform
output that scopes the deployer principal to:

- `ssm:SendCommand` with `ssm:DocumentName == "AWS-RunShellScript"` on
 the deployed instance ARN only.
- `ssm:StartSession` with
 `ssm:DocumentName == "AWS-StartPortForwardingSession"` on the same
 ARN.

Attach this policy to the human or CI principal that runs
`tee-crafter deploy`. At runtime, `core/remote/ssm.py` asserts that
`AWS-RunShellScript` is the only document `send_command` will ever
invoke, so a future refactor cannot silently widen the blast radius.

### LOG-1 — Host-proxy log redaction

The FastAPI host proxy installs `_RedactAuthFilter` on every
logger it creates. The filter scrubs `Authorization`, `Cookie`, and
`X-Api-Key` headers from log lines before they are emitted and the
request handler only logs the **count** of fields and the **keys**
of the payload. Uvicorn's access log is disabled so URLs containing
bearer tokens cannot leak via the journal.

---

## Security Checklist

- [x] **Hardware attestation**: NSM attestation document (COSE_Sign1) verified by the client, including nonce freshness, PCR0/1/2 values, and X.509 chain to the AWS Nitro Root CA.
- [x] **PCR-bound KMS keys**: KMS key policy requires `kms:RecipientAttestation:PCR{0,1,2}` to match the attested enclave; only that EIF can use KMS decrypt / random APIs.
- [x] **Zero-trust host (persistent mode)**: In `--persistent` mode the host proxy only forwards ECIES-encrypted payloads and injects IAM credentials; it never sees plaintext data or decrypted keys.
- [ ] **Zero-trust host does NOT hold in `--batch` mode.** Batch is a different execution path and the host sees plaintext at both ends:
 - `--input-dir` is uploaded as a plain `tar.gz` and extracted in the clear to `/var/lib/tee_crafter/input` on the parent instance.
 - Container batch on `nitro-aws` runs the user image on the parent EC2 instance via Docker, **not** inside the enclave — `docker diff` capture is not available in a Nitro Enclave (`cli/commands/deploy/batch_dispatch.py`, lines 298–309).
 - For the enclave-side batch path, the enclave streams output over vsock unencrypted and the host collector writes it world-readable (`0644`).

 Use `--persistent` on `nitro-aws`, or `snp-aws` for batch, if the host must not see plaintext. `docs/security.md` §16.6 covers the same ground.
- [x] **End-to-end ECIES**: Client encrypts with an ECDH key authenticated by attestation; enclave holds the private key and performs AES-256-GCM (with AAD) decrypt/encrypt entirely inside the enclave.
- [x] **Network isolation**: No public IP, zero ingress security groups; all control paths over SSM and AWS service traffic via VPC endpoints (KMS, S3, SSM, SSMMessages, EC2Messages).
- [x] **IMDS hardening**: IMDSv2 enforced on the host instance; enclave has no direct IMDS or network access.
- [x] **Cryptographic envelope (KMS path)**: CMS EnvelopedData from KMS; CEK unwrapped inside the enclave via RSA-OAEP and used only for AES decrypt.
- [x] **Entropy guarantees**: Enclave seeds its RNG with NSM hardware randomness plus 256 bytes from `kms:GenerateRandom`.
- [x] **File-system & process isolation**: Enclave runs a minimal userspace inside the EIF; host-side services use systemd hardening (allocator, host proxy).
- [x] **Error sanitization**: Enclave and host proxy logs avoid sensitive payloads and internal state; client-visible errors are generic and non-diagnostic.
