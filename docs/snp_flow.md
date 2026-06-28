# AMD SEV-SNP Flow (AWS + Azure + GCP)

## What is AMD SEV-SNP?

AMD **Secure Encrypted Virtualization – Secure Nested Paging** (SEV-SNP) is a whole-VM confidential computing technology built into AMD EPYC processors (3rd Gen Milan, 4th Gen Genoa). It provides:

- **Memory encryption**: Every VM page encrypted with a per-VM key managed by the AMD Secure Processor (SP/PSP)
- **Integrity protection**: SNP adds nested paging integrity checks to prevent hypervisor-based memory remapping attacks
- **Hardware attestation**: The SP generates signed attestation reports binding the VM's launch measurement, guest policy, and user-provided data to AMD's root of trust

Unlike Intel SGX (process-level), SEV-SNP protects the **entire VM** — no code modifications required.

---

## TEE-Crafter SNP Pipeline

Both AWS and Azure follow the same 5-phase pipeline as other TEE-Crafter backends:

```
Phase 1: Container Build & Measurement (docker build + Trivy/Grype scan + digest)
  ↓
Phase 2: SNP Artifact Staging (attested proxy + client_snp_{aws|azure}.py)
  ↓
Phase 3: Terraform Generation (AWS: EC2 + cpu_options | Azure: CVM + vTPM)
  ↓
Phase 4: Terraform Apply
  ↓
Phase 5: Post-Deploy (setup, attestation verification, encrypted data transfer)
```

---

## Architecture (AWS SEV-SNP)

```
┌──────────────────┐ ┌──────────────────────────────────────────────┐
│ │ SSM port-forward │ AWS SEV-SNP VM (M6a/C6a/R6a, private) │
│ Local Client │ (localhost:PORT → 5005) │ │
│ client_snp_aws │ ─────────────────────────► │ ┌──────────────────────────────────────┐ │
│ │ │ │ app_snp.py (RA-TLS SNP server) │ │
│ 1. Attest + │ │ │ • /dev/sev-guest ioctl │ │
│ send request │ │ │ • snpguest certificates (VLEK) │ │
│ │ │ │ • ECDH + AES-GCM (ECIES) │ │
└──────────────────┘ │ └──────────────────────────────────────┘ │
 │ │
 │ Per-deployment VPC (dedicated, flow-logged):│
 │ • SSM / SSMMessages / EC2Messages (VPCE) │
 │ • S3 Gateway endpoint (artifacts) │
 │ • VPC Flow Logs → CloudWatch │
 └──────────────────────────────────────────────┘
```

### Data Flow (AWS SEV-SNP)

```
Client SSM Tunnel SNP VM (app_snp.py) AMD KDS / Certs
 │ │ │ │
 │── SSM StartSession ─────► │ │
 │ (port-forward →5005) │ │ │
 │ │ │ │
 │── RA-TLS connect ───────► │ │
 │ │ │── SNP_GET_REPORT/ioctl ──►│*
 │ │ │◄── VLEK certs (snpguest) ─│*
 │ │ │ │
 │◄── RA-TLS cert+report ──│ │ │
 │ (SNP report + VLEK) │ │ │
 │ │ │ │
 │ Verify AMD chain, │ │ │
 │ report signature, │ │ │
 │ policy, measurement │ │ │
 │ │ │ │
 │── Encrypted request ────► │ │
 │ (ECIES: ECDH+AES-GCM) │ │ │
 │ │ │ Decrypt, run analytics │
 │ │ │ compute result │
 │ │ │ │
 │◄── Encrypted response ──│◄───────────────────────────│ │
 │ │ │ │
 │ Decrypt response │ │ │
 │ │ │ │
```

`*` Depending on configuration, VLEK/VCEK certificates may be fetched via snpguest (KDS)
or from pre-baked certs on the deployer; the client always verifies against baked-in AMD
root certs.

---

## AWS SEV-SNP (`--tee-platform snp-aws`)

### Instance Types
- **M6a** (general purpose), **C6a** (compute), **R6a** (memory) — all AMD EPYC Milan
- SEV-SNP enabled via `cpu_options { amd_sev_snp = "enabled" }` at launch time

### Attestation Flow
1. VM app generates ECDH keypair; places the **v2 binding digest** over
 `(ECDH pubkey, container image digest)` in `report_data[:32]` —
 `SHA-256(lp("tee-crafter/attest-binding/v2") || uint32be(2) || lp(ecdh_pub) || lp(container_digest))`,
 where `lp(x)` is `uint32be(len(x)) || x`
2. Requests SNP attestation report via `/dev/sev-guest` ioctl (or snpguest CLI)
3. Report is signed by AMD SP using **VLEK** (Versioned Loaded Endorsement Key)
4. VLEK cert chain: **VLEK → ASK → ARK** (retrieved from AMD KDS)
5. Report + VLEK cert embedded in X.509 RA-TLS certificate extension (OID `1.3.6.1.4.1.3704.1.1.1`)

### Client Verification
1. Connect via RA-TLS, extract SNP report from certificate
2. Validate `sig_algo == 1` (ECDSA P-384 + SHA-384)
3. Verify ECDSA-384 signature using VLEK public key
4. Verify VLEK → ASK → ARK chain against embedded AMD root certificate
5. Check guest policy: debug disabled, migration disabled
6. **AMD-SB-3015 platform checks** (fatal):
 - `PLATFORM_INFO` bit 5 (`ALIAS_CHECK_COMPLETE`) must be set — confirms the AMD Secure Processor completed memory aliasing mitigation per AMD Security Bulletin SB-3015 (CVE-2024-21944)
 - `REPORTED_TCB` bits 55:48 (SNP firmware SVN) must be ≥ `0x16` (Genoa-class minimum; Milan-class requires ≥ `0x17`)
7. **Anti-rollback** (fatal): `COMMITTED_TCB <= REPORTED_TCB`
8. Verify `report_data[:32]` equals the v2 binding digest the client recomputes
 from its own expected ECDH public key and container digest. Both fields are
 always present — an absent container digest is a zero-length field, not a
 shorter field list — so the client never branches on whether one is expected
9. Self-pin launch measurement (TOFU)
10. Print `{"status":"attestation_verified"}` and exit — the deploy-time client is attestation-only and sends no data. The ECIES request/response channel (ECDH + AES-256-GCM with AAD `b"tee-crafter-snp-v1-req"`/`-resp`, HKDF with `info=b"tee-crafter-snp-v1"`) is keyed from the attested public key and exercised by the customer's own client over the same channel.

### The bake refuses to produce an image that cannot attest

Both attestation binaries — `snpguest` (SEV-SNP reports) and `nitro-tpm-attest`
(NitroTPM documents, for measurement-gated BYOK) — are built from source on the
bake instance, and each build step is individually non-fatal so its failure text
and log survive. That combination used to be a **fail-open**: the bake completed,
the AMI registered normally, and nothing said the image could not attest.

A gate at the end of `setup_snp_aws.sh` prints a tooling
summary and exits non-zero if either binary is missing, before the bake marker
is written:

```
--- attestation tooling ---
snpguest: /usr/local/bin/snpguest
nitro-tpm-attest: /usr/bin/nitro-tpm-attest
tpm2-tools: /usr/bin/tpm2_pcrread
```

Failed builds leave their logs at `/var/log/tee-crafter/snpguest-build-failed.log`
and `/var/log/tee-crafter/nitrotpm-build-failed.log`, which previously lived in
`mktemp` files the script deleted. Set
`TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS=0` on the bake instance to build a plain
SEV-SNP image without them on purpose, accepting that BYOK key release degrades
to identity-gated (`core/keys/gating.py` reports that honestly rather than
claiming a gate that is not there).

The alternative considered was checking at deploy time instead. It detects the
same problem, but one bake later and after an instance is already billing — and
the reason this went unnoticed for months is precisely that the signal was too
far from the cause.

### Two pinned supply-chain values were wrong, and the gate is how we found out

Worth recording because both were silent, both were the *pin* rather than the
verification logic, and both had been wrong for a long time.

**The `snpguest` commit pin did not exist.** The script pinned
`ec1cc1af26b60dced56198e265f78e3fb01f7c28` as `v0.7.0`. A fresh clone of
`github.com/virtee/snpguest` reports `OBJECT ABSENT` for it — not an unreachable
ref, an object that is not in the repository at all. So `git checkout` failed,
the script's own supply-chain guard correctly refused to build an unpinned
revision, and because the step was non-fatal the bake shipped an AMI with no
`snpguest`. The real `refs/tags/v0.7.0` is
`49494ff71b5830a98b15759aae0a43e20e16e798`, confirmed by `version = "0.7.0"` in
the checked-out `Cargo.toml`.

**The pinned AMD "ARK" fingerprints were intermediates.** `certs/amd-ark-milan.pem`
and `certs/amd-ark-genoa.pem` are each a two-certificate bundle,
`[intermediate, ARK]`. The pins had been taken from entry `[0]` —
`CN=SEV-VLEK-Milan` and `CN=SEV-Genoa` — while `verify_amd_chain` compares the
**last** certificate of the downloaded KDS chain, which is the real root. The
comparison could therefore never succeed, and since a rejected chain is deleted
(`rm -f "$chain"`), **no `snp-aws` bake had ever installed an AMD endorsement
chain**. The two pins were also drawn from different endpoints — one from the VLEK chain,
one from the VCEK chain.

Client-side verification was never affected — the SNP client also takes the last
certificate of each baked bundle as the ARK, and that has always been the
genuine root. The defect was confined to the bake-time pin.

The correct values, read from `kdsintf.amd.com` and identical
across the `vcek` and `vlek` endpoints:

| Generation | ARK SHA-256 |
|---|---|
| Milan | `69:D0:63:B4:53:44:D2:6A:2E:94:E1:F4:21:0D:E4:9E:F5:55:30:82:87:D4:C1:74:44:5C:95:63:9A:54:0B:CD` |
| Genoa | `4C:65:98:D1:9C:18:71:9C:5D:FD:4A:7D:33:5F:67:4E:5B:FE:1D:8F:80:0C:EA:2C:F2:70:C1:0D:10:3D:B2:F1` |

`tests/cli/test_amd_ark_pins_match_bundles.py` now asserts each pin equals the
*last* certificate of the corresponding bundle, that the bundle's last entry is
self-signed and named `ARK-*`, and that all three SNP platforms agree — a
per-generation ARK is a property of AMD, not of the cloud. Verify any
replacement by subject before trusting it; the subject must say `ARK`.

### Access Model
- **SSM-only** (no SSH, no public IP) — same pattern as Nitro
- Artifacts uploaded via S3, installed via SSM commands
- Client verification via SSM port-forward

### UEFI Secure Boot (on by default)

Unlike `snp-azure` (which hard-codes `secure_boot_enabled = true` on
the `azurerm_linux_virtual_machine` resource) and `snp-gcp` (which
hard-codes `shielded_instance_config.enable_secure_boot = true`),
**AWS does not expose Secure Boot as a runtime `RunInstances`
parameter** — the enforcement state lives in the AMI's UEFI variable
store (`Image.UefiData`). Secure Boot is therefore enabled at bake
time, on by default, for parity with the Azure / GCP non-GPU
platforms:

```bash
# Default (Secure-Boot-enrolled):
tee-crafter internal bake-ami \
    --tee-platform snp-aws \
    --enclave-ram 4096 --enclave-cpu 2

# Dev bake without SB (rare):
tee-crafter internal bake-ami \
    --tee-platform snp-aws \
    --no-enable-secure-boot \
    --enclave-ram 4096 --enclave-cpu 2
```

Per-bake the script extracts the **Microsoft Corporation UEFI CA 2011**
cert out of `/usr/lib/shim/shimx64.efi.signed` and enrolls a db that
contains *both* that CA (so Ubuntu's shim → grub → kernel chain
continues to verify) and a tee-crafter self-signed db cert (so
operators can later sign their own EFI binaries against this AMI's
chain without re-baking). A fresh RSA-2048 PK and KEK are generated
per bake; the private keys are persisted under
`/etc/tee_crafter/sb-keys/` (mode `0700`, root-only) for later
re-signing.

`sev_guest` is **in-tree** on Ubuntu 22.04's `linux-image-aws` kernel
and signed by Canonical's build-time key, so it loads under
enforcing Secure Boot. Empirically verified end-to-end on an
`m6a.xlarge` SNP instance: `snpguest report` produced a 1184-byte
attestation report with `mokutil --sb-state` reporting `SecureBoot
enabled` and `/sys/kernel/security/lockdown` reporting `[integrity]`.

See [security.md §15.1A](security.md) for the full design rationale
(deploy-time precondition, AMI tagging, threat model).

### Key Files
| File | Purpose |
|------|---------|
| `templates/snp/aws/app.template.py` | Server-side app (attestation, RA-TLS, ECDH) |
| `templates/snp/aws/client.template.py` | Client verification + ECIES encryption |
| `templates/snp/aws/main.template.tf` | Terraform (EC2 + SEV-SNP + SSM + `enable_secure_boot`) |
| `scripts/snp_aws/setup_snp_aws.sh` | Host setup (snpguest, venv, systemd) |
| `scripts/common/secure_boot_enroll_aws.sh` | SB key enrollment block injected when `--enable-secure-boot` is passed |
| `cli/deployment/snp/aws_phase.py` | Deployment orchestrator |
| `cli/deployment/snp/aws_setup.py` | SSM-based setup automation |
| `certs/amd-ark-milan.pem` | AMD ARK/ASK root certificates (Milan) |

---

## Azure SEV-SNP (`--tee-platform snp-azure`)

### Instance Types
- **DCasv5/ECasv5** (3rd Gen EPYC Milan)
- **DCasv6/ECasv6** (4th Gen EPYC Genoa)
- Confidential VM features: `security_encryption_type = "DiskWithVMGuestState"`, `secure_boot_enabled = true`, `vtpm_enabled = true`

### Attestation Flow (Dual-Path)

**Path 1 — Direct (fallback on Azure Hyper-V CVMs):**
1. `/dev/sev-guest` ioctl or snpguest CLI (note: `/dev/sev-guest` is not exposed on Azure Hyper-V CVMs)
2. Report signed by **VCEK** (per-chip, not VLEK)
3. VCEK cert retrieved from **Azure IMDS**: `http://169.254.169.254/metadata/THIM/amd/certification`

**Path 2 — vTPM (primary on Azure Hyper-V CVMs):**
1. Azure's vTPM stores the HCL-wrapped SNP attestation report at NV index `0x01400001`
2. Read via `tpm2_nvread -C o 0x01400001` (owner hierarchy, empty password)
3. Parse 32-byte HCL header + extract 1184-byte SNP report
4. A **TPM2 Quote** binds `SHA256(ECDH_pubkey)` to the vTPM attestation, providing cryptographic key binding even when `report_data` contains the hypervisor's runtime hash
5. Optional integration with **Microsoft Azure Attestation (MAA)** for JWT-based verification

### Client Verification
Same as AWS, plus:
- VCEK → ASK → ARK chain verification (Genoa certs for v6 instances)
- **AMD-SB-3015 platform checks** (fatal): `PLATFORM_INFO` bit 5 (`ALIAS_CHECK_COMPLETE`) must be set and SNP firmware SVN (bits 55:48 of `REPORTED_TCB`) must be ≥ `0x16` (Genoa) or ≥ `0x17` (Milan)
- `sig_algo == 1` (ECDSA P-384 + SHA-384) enforced
- **Anti-rollback** (fatal): `COMMITTED_TCB <= REPORTED_TCB`
- **TPM Quote verification**: When `report_data` doesn't directly bind the ECDH key (Azure vTPM path), the client verifies a TPM2 Quote that binds `SHA256(ECDH_pubkey)` as the qualifying nonce
- Optional MAA JWT token verification (`x-ms-sevsnpvm-is-snp`, `x-ms-sevsnpvm-dbgstat`) with full JWT signature verification against the MAA provider’s published JWKS keys

### Server-Side Boot-Time TCB Checks (All Clouds)

The SNP app template on every cloud (AWS, Azure, GCP) performs fatal boot-time validation before starting the RA-TLS server:

1. Generates a startup attestation report
2. Reads `REPORTED_TCB` and `PLATFORM_INFO` from the raw report
3. Refuses to start if `PLATFORM_INFO` bit 5 (`ALIAS_CHECK_COMPLETE`) is clear (AMD-SB-3015 / CVE-2024-21944 mitigation not confirmed)
4. Refuses to start if SNP firmware SVN (bits 55:48 of `REPORTED_TCB`) is below `0x16` (firmware not patched to AMD-SB-3015 minimum)

This ensures a VM running on non-compliant hardware never serves requests.

### Strict attestation at runtime (all SNP templates)

The following are **fatal** (process exits or connection path fails) in the current templates—there is no “degraded attestation” success path:

- **Endorsement material:** If no usable VCEK/VLEK (or chain) can be obtained after all configured methods, startup fails (`sys.exit(1)` on AWS; `sys.exit(1)` on Azure/GCP after the final guard).
- **Azure TPM quote:** `snp-azure` and `gpu-cc-azure` require a successful **TPM2 Quote** for ECDH binding when using the vTPM SNP path (`_generate_tpm_quote` exits on failure).
- **RA-TLS certificate rotation:** If regenerating the RA-TLS certificate / attestation bundle fails during the rotation loop, the server process exits rather than continuing with a stale cert.
- **`get_attestation` RPC:** Fresh SNP attestation for the JSON probe must succeed; failures are not converted into empty `report_hex` / `measurement: unavailable`.

### SNP-2 — Runtime Milan/Genoa root-CA auto-selection

Every SNP client bakes in **both** AMD Milan and AMD Genoa root CA
chains. At verify time it:

1. Parses the endorsement material (VCEK / VLEK).
2. Tries to validate against the Milan chain.
3. On failure, retries against the Genoa chain.
4. Fails closed if neither chain validates.

This makes the generated deploy artifacts portable across AMD EPYC
generations without a manual "edit the chain" step. The renderer
populates the chains via `render_snp_{aws,azure,gcp}_client_template`.

### SNP-3 — the TPM attestation key must be rooted in AMD's signature

Without this, a "valid SNP report, attacker-chosen TPM AK" splice succeeds: an
attacker replays a genuine report for a vetted measurement, generates their own
attestation key, and signs a quote with it. The quote is internally consistent,
so only a binding between the AK and the report distinguishes it.

How the AK is bound depends on whether the guest controls `REPORT_DATA`:

- **`snp-aws`, `snp-gcp`** (real `/dev/sev-guest`): the server creates an
 ephemeral AK *before* signing, puts `SHA-256(AK_pub)` in the report's
 `user_data` alongside `SHA-256(ECDH_pub)`, and quotes with that same AK
 context. Client reports `binding_mode = report_data_strong`.
- **`snp-azure`** (Hyper-V paravisor, no `/dev/sev-guest`): `REPORT_DATA` is
 fixed by the HCL to `sha256(runtime_data)`, so nothing the guest generates can
 appear under AMD's signature — an ephemeral AK is unattestable here. The
 server instead quotes with the **HCL's own attestation key**, which that same
 runtime data publishes as `keys[kid == "HCLAkPub"]`. AMD signs `REPORT_DATA`,
 `REPORT_DATA` commits to the runtime data, and the runtime data names the AK.
 Client reports `binding_mode = hcl_runtime_data_strong`.

The server finds that key by matching the modulus at each persistent vTPM handle
against `HCLAkPub` rather than trusting a fixed handle, and falls back to an
ephemeral AK if none matches — which the client's strict gate then refuses.

Clients fail closed (`TEE_CRAFTER_STRICT_SNP_AK_BINDING=1`, default) unless one
of the two modes holds. A TPM quote alone never satisfies the gate. Full
reasoning: [security.md](security.md) §13.7.

### Access Model
- **Azure Bastion + SSH** — same pattern as TDX/SGX
- Artifacts uploaded via SCP through Bastion tunnel
- Client verification via SSH port-forward

### Key Files
| File | Purpose |
|------|---------|
| `templates/snp/azure/app.template.py` | Server app (attestation + IMDS VCEK + vTPM fallback) |
| `templates/snp/azure/client.template.py` | Client verification + MAA support |
| `templates/snp/azure/main.template.tf` | Terraform (Azure CVM + Bastion) |
| `scripts/snp_azure/setup_snp_azure.sh` | Host setup (snpguest, tpm2-tools, IMDS) |
| `cli/deployment/snp/azure_phase.py` | Deployment orchestrator |
| `cli/deployment/snp/azure_setup.py` | Bastion/SSH-based setup automation |
| `certs/amd-ark-genoa.pem` | AMD ARK/ASK root certificates (Genoa) |

---

---

## GCP SEV-SNP (`--tee-platform snp-gcp`)

### Instance Types
- **N2D** (AMD EPYC Milan/Genoa) — Confidential VM with `confidential_instance_config { confidential_instance_type = "SEV_SNP" }`

### Attestation Flow
1. VM app generates ECDH keypair; places the v2 binding digest over
 `(ECDH pubkey, container image digest)` in `report_data[:32]` (see above)
2. Requests SNP attestation report + endorsement certs via multi-method probe:
 1. `SNP_GET_EXT_REPORT` ioctl (two-phase, report + certs in one call)
 2. configfs TSM (`/sys/kernel/config/tsm/report/` — kernel 6.7+, report + certs via outblob/auxblob)
 3. `SNP_GET_REPORT` ioctl + GCE metadata for VCEK
 4. `SNP_GET_REPORT` ioctl + snpguest for certs
 5. snpguest CLI for report
 6. Pre-baked certs (last resort)
3. Report is signed by **VCEK** (per-chip key)
4. VCEK cert chain: **VCEK → ASK → ARK** (retrieved from GCE metadata service, configfs TSM auxblob, or snpguest)
5. Report + VCEK cert embedded in X.509 RA-TLS certificate extension (OID `1.3.6.1.4.1.3704.1.1.1`)
6. Boot-time TCB checks: `PLATFORM_INFO` bit 5 + SNP firmware SVN (same as AWS/Azure)

### Client Verification
Same as AWS:
- VCEK/ASK/ARK chain verification against embedded AMD root certificate
- Guest policy checks (debug disabled, migration disabled, VMPL=0)
- AMD-SB-3015 checks (PLATFORM_INFO bit 5, SNP firmware SVN)
- `sig_algo == 1` (ECDSA P-384 + SHA-384) enforced
- **Anti-rollback** (fatal): `COMMITTED_TCB <= REPORTED_TCB`
- Report data binding to server's ECDH public key
- Self-pin launch measurement (TOFU)

### Access Model
- **IAP TCP tunnel** (no SSH keys over the internet, no public IP)
- Artifacts uploaded via SCP through IAP tunnel
- Client verification via SSH port-forward through IAP

### Key Files
| File | Purpose |
|------|---------|
| `templates/snp/gcp/app.template.py` | Server-side app (attestation, RA-TLS, ECDH) |
| `templates/snp/gcp/client.template.py` | Client verification + ECIES encryption |
| `templates/snp/gcp/main.template.tf` | Terraform (GCP Confidential VM + IAP + CMEK) |
| `scripts/snp_gcp/setup_snp_gcp.sh` | Host setup (snpguest, venv, systemd) |
| `cli/deployment/snp/gcp_phase.py` | Deployment orchestrator |
| `cli/deployment/snp/gcp_setup.py` | IAP/SSH-based setup automation |

---

## AWS vs Azure vs GCP SEV-SNP Comparison

| Aspect | AWS (`snp-aws`) | Azure (`snp-azure`) | GCP (`snp-gcp`) |
|--------|-----------------|---------------------|-----------------|
| Instance types | M6a, C6a, R6a | DCasv5, ECasv5, DCasv6, ECasv6 | N2D |
| Endorsement key | VLEK (AWS-specific) | VCEK (per-chip) | VCEK (per-chip) |
| Cert retrieval | AMD KDS (`kdsintf.amd.com`) | Azure IMDS endpoint | GCE metadata / configfs TSM auxblob / snpguest |
| Access method | SSM (no SSH) | Bastion + SSH | IAP TCP tunnel |
| vTPM | Not available | Available (NV indexes) | Not used |
| Disk encryption | EBS encryption | DiskWithVMGuestState | CMEK via Cloud KMS |
| Processor generation | Milan (EPYC 7003) | Milan (v5) or Genoa (v6) | Milan or Genoa |

---

## SNP Attestation Report Format

The AMD SEV-SNP attestation report is a 1184-byte binary structure:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x000 | 4 | version | Report format version |
| 0x004 | 4 | guest_svn | Guest Security Version Number |
| 0x008 | 8 | policy | Guest policy (debug, migrate, SMT, ABI version) |
| 0x030 | 4 | vmpl | VM Privilege Level (0 = highest) |
| 0x034 | 4 | sig_algo | Signature algorithm (1 = ECDSA-384) |
| 0x038 | 8 | current_tcb | Current Trusted Computing Base version |
| 0x040 | 8 | platform_info | Platform info flags (bit 5 = `ALIAS_CHECK_COMPLETE` per AMD-SB-3015) |
| 0x050 | 64 | report_data | User-provided data. Bytes 0-31 hold the v2 binding digest over (ECDH pubkey, container digest); bytes 32-63 are zero |
| 0x090 | 48 | measurement | SHA-384 launch digest |
| 0x0C0 | 32 | host_data | Host-provided data |
| 0x180 | 8 | reported_tcb | Reported TCB: bits 7:0=boot_loader, 15:8=TEE, 23:16=reserved, 31:24=reserved, 39:32=reserved, 47:40=reserved, **55:48=SNP firmware SVN**, 63:56=microcode |
| 0x1A0 | 64 | chip_id | Physical processor identifier |
| 0x1E0 | 8 | committed_tcb | Committed TCB — anti-rollback floor; client asserts `committed_tcb` ≤ `reported_tcb` per AMD SEV-SNP ABI §4.4 |
| 0x2A0 | 512 | signature | ECDSA-384 signature (r ‖ s, little-endian) |

---

## Security Checklist

- [x] AMD hardware root of trust: ARK → ASK → VLEK/VCEK chain verified
- [x] Launch measurement: SHA-384 hash of initial VM memory
- [x] Guest policy: debug disabled, migration disabled, minimum ABI version
- [x] Report data binding: SHA-256(ECDH pubkey) prevents key substitution; TPM2 Quote fallback for Azure vTPM path
- [x] VMPL level check: must be 0 (firmware/kernel level)
- [x] TCB version enforcement (AMD-SB-3015): SNP firmware SVN (bits 55:48 of `REPORTED_TCB`) must be ≥ `0x16` (Genoa) or ≥ `0x17` (Milan); checked at boot and by client, fatal on failure
- [x] Platform info validation (AMD-SB-3015): `PLATFORM_INFO` bit 5 (`ALIAS_CHECK_COMPLETE`) must be set, confirming the AMD SP completed memory aliasing mitigation (CVE-2024-21944); checked at boot and by client, fatal on failure
- [x] Signature algorithm enforcement: `sig_algo` must be `1` (ECDSA P-384 + SHA-384), fatal on failure
- [x] Anti-rollback: `COMMITTED_TCB <= REPORTED_TCB`, fatal on violation
- [x] Zero network exposure: SSM-only (AWS), Bastion-only (Azure), or IAP-only (GCP)
- [x] Encrypted disk: EBS encryption (AWS), DiskWithVMGuestState (Azure), or CMEK-backed persistent disk (GCP)
- [x] Secure boot + vTPM (Azure)
- [x] TLS 1.3 minimum: all RA-TLS connections enforce `TLSv1_3` as minimum version
- [x] AES-GCM Authenticated Associated Data (AAD): request/response payloads use distinct AAD tags
- [x] ECDH key + RA-TLS certificate rotation: server regenerates keypair and attestation certificate every 3600 seconds; **rotation failure is fatal** (`sys.exit(1)`)
- [x] **`get_attestation` RPC:** Fresh SNP attestation must succeed (no empty `report_hex` / placeholder measurement)
- [x] `snpguest` pinned build: version tag (e.g. `v0.7.0`) verified at build time to prevent supply-chain attacks
- [x] Systemd hardening: `MemoryDenyWriteExecute`, `ProtectKernelTunables`, `RestrictNamespaces`, `SystemCallFilter`, etc.
