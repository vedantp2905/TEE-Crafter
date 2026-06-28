# Intel TDX (Azure + GCP) — Detailed Flow

## What is Intel TDX?

**Intel Trust Domain Extensions (TDX)** is a hardware-based confidential computing technology that provides VM-level isolation. Unlike SGX (which protects individual enclaves within a process), TDX protects the **entire virtual machine** — the guest OS, all applications, and all memory — from the hypervisor, host OS, and other VMs on the same physical host.

A TDX-protected VM is called a **Trust Domain (TD)**. The CPU encrypts all TD memory with a unique key (managed by the TDX module in the CPU), and hardware-generated attestation reports allow remote parties to verify the TD's identity and integrity before sending sensitive data.

TDX is conceptually simpler than SGX for application developers: there is no enclave boundary to worry about, no LibOS needed, and standard Linux applications run unmodified inside the TD. The trade-off is a larger Trusted Computing Base (the entire guest kernel + all guest processes).

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Trust Domain (TD)** | A TDX-protected VM — all memory encrypted, isolated from hypervisor |
| **MRTD** | Measurement of the initial TD contents (analogous to SGX MRENCLAVE) |
| **RTMR** | Runtime Measurement Registers — extend-only registers for recording runtime events |
| **TD Report** | Hardware-generated report containing MRTD, RTMRs, and custom report data |
| **TDX Quote** | A DCAP quote (v4/v5) wrapping a TD Report, signed by Intel's QE |
| **configfs-tsm** | Linux 6.7+ interface for generating TDX quotes via `/sys/kernel/config/tsm/report/` |
| **vTPM** | Virtual TPM — Azure TDX CVMs expose TDX reports via the vTPM at NV index `0x01400001` |
| **HCLA** | The 4-byte magic (`0x414c4348`) heading Azure's vTPM attestation report at NV `0x01400001`. A container format, **not** verifiable evidence — see item 9 in Attestation verification |
| **AzureGuest** | MAA's `/attest/AzureGuest` endpoint and the token it issues. The only attestation an Azure paravisor CVM can offer; hardware verdict nested under `x-ms-isolation-tee` |

### TDX vs SGX — Key Differences

| Aspect | SGX | TDX |
|--------|-----|-----|
| **Isolation Scope** | Per-process enclave (EPC memory) | Entire VM (all guest memory) |
| **Application Changes** | Requires LibOS (Gramine) or SDK | None — standard Linux apps |
| **TCB Size** | Small (enclave code only) | Large (guest kernel + all apps) |
| **Measurement** | MRENCLAVE (code hash) | MRTD (VM image hash) |
| **Attestation** | DCAP quote v3 (SGX report body, 384 bytes) | DCAP quote v4/v5 (TD report body, 584 bytes) |
| **Azure VM Series** | DCsv3 / DCdsv3 | DCesv6 / ECesv6 |
| **Key Exchange** | ECIES (ECDH + AES-256-GCM) | ECIES (ECDH + AES-256-GCM) |

---

## Architecture

```
┌──────────────────┐ ┌────────────────────────────────────────────────────┐
│ │ SSH port-forward │ Azure DCesv6 VM (TDX Confidential VM) │
│ Local Client │ via Bastion tunnel │ Entire VM is a Trust Domain │
│ (client_tdx.py) │ (localhost:PORT → VM:5005) │ │
│ │ ─────────────────────────────► │ ┌────────────────────────────────────────────┐ │
│ 1. TLS connect │ │ │ app_tdx.py (systemd service) │ │
│ 2. Extract quote│ RA-TLS │ │ │ │
│ 3. Verify TDX │ │ │ ECDH P-256 keypair │ │
│ DCAP quote │ │ │ RA-TLS certificate (TDX quote in X.509) │ │
│ 4. ECIES encrypt│ │ │ TLS server on 127.0.0.1:5005 │ │
│ 5. Send data │ │ │ ECIES decrypt (AES-256-GCM) │ │
│ 6. Get result │ │ │ forward → user container on 127.0.0.1 │ │
│ │ │ └────────────────────────────────────────────┘ │
└──────────────────┘ │ │
 │ TDX attestation interfaces (probed in order): │
 ┌───────────────┐ │ 1. configfs-tsm (/sys/kernel/config/tsm/report) │
 │ Azure Bastion │ SSH tunnel │ 2. /dev/tdx-guest (kernel 6.x+) │
 │ (Standard SKU) │ ─────────────────────────►│ 3. /dev/tdx_guest (older kernels) │
 │ tunneling_on │ │ 4. vTPM NV index 0x01400001 (Azure fallback) │
 └───────────────┘ └────────────────────────────────────────────────────┘
```

### Data Flow

```
Client TDX Trust Domain
 │ │
  │── TLS connect (verify_mode=CERT_NONE) ──────────► │
 │ │ (RA-TLS cert with TDX quote)
  │◄── Server certificate (DER) ──────────────────────│
 │ │
 │ Extract TDX quote from X.509 extension │
 │ (OID 1.2.840.113741.1.13.1, tee_type=0x81) │
 │ │
 │ parse_tdx_quote: │
 │ MRTD at td_report_body[136:184] (48 bytes) │
 │ RTMR0-3 at td_report_body[328:520] (4×48) │
 │ REPORT_DATA at td_report_body[520:584] (64) │
 │ │
 │ Verify TDX DCAP signature (ECDSA-P256) │
 │ Verify MRTD against expected value │
 │ Verify PCK certificate chain → Intel Root CA │
 │ │
  │── {get_attestation, nonce} ──────────────────────►│
 │ │ Generate TDX quote with
 │ │ SHA256(ECDH_PUB) in report_data
  │◄── {enclave_public_key, attestation_doc_b64} ────│
 │ │
 │ Verify: report_data[:32] == SHA256(pub_key) │
 │ │
 │ ── attestation verified; client prints │
 │ {"status":"attestation_verified"} and exits ──│
```

> The deploy-time client's only job is to **verify attestation** and exit. It
> sends no application data. The RA-TLS server can still forward real requests
> to your container over the attested channel — in production your own client
> opens the same kind of attested tunnel and sends app-specific requests. The
> framework never defines or inspects "the data".

---

## Pipeline Phases

### Phase 1: Container Build & Measurement

**Modules:** `cli/commands/deploy/flow_container.py`

| Step | Action | Details |
|------|--------|---------|
| 1a | **Docker build** | Build user image from `Dockerfile` |
| 1b | **Vulnerability scan** | Trivy/Grype gate |
| 1c | **Proxy staging** | Render attested ingress proxy for `--persistent` |
| 1d | **Batch staging** | Stage batch collector + input mount for `--batch` |
| 1e | **Client template** | Render `templates/tdx/azure/client.template.py` with the MRTD pinned from the measurement registry, plus the evidence format (see item 9) and — on `azure-guest` — the Intel Root CA is unused because the trust root is MAA. If no MRTD is available the client is rendered with `unknown` and **fails closed at run time** — it does not self-pin. |

See [container_build.md](container_build.md) and [attested_proxy.md](attested_proxy.md).

### Phase 2: No Local Build Step

Unlike Nitro (EIF build) or SGX (manifest signing), TDX has no local cryptographic packaging. The application runs as a standard Python process inside the Trust Domain — the hardware itself provides the protection boundary. MRTD is determined by the VM image, not by the application.

### Phase 3: Infrastructure-as-Code (Azure)

Terraform configuration generated from `templates/tdx/azure/main.template.tf`. No LLM involved.

#### Cloud Resources Created

| Resource | Configuration |
|----------|--------------|
| **Resource Group** | `tee-crafter-tdx-rg` in `westus` or `westus3` (TDX-capable regions) |
| **Virtual Network** | `10.1.0.0/16` with app subnet (`10.1.1.0/24`) and Bastion subnet (`10.1.2.0/26`) |
| **Azure Bastion** | Standard SKU with `tunneling_enabled = true` |
| **NSG** | Inbound: SSH from Bastion subnet only + DenyAll. Outbound: Azure platform IP, HTTPS (conditional), DenyAll catch-all |
| **VM** | DCesv6/ECesv6 series, Ubuntu 22.04 Confidential VM (`22_04-lts-cvm`), `secure_boot_enabled`, `vtpm_enabled`, `security_encryption_type = "DiskWithVMGuestState"`, no public IP |
| **Storage Account** | TLS 1.2+, LRS replication, private container for artifact upload |
| **SSH Key** | RSA-4096, generated by Terraform |

#### TDX-Specific VM Configuration

```hcl
resource "azurerm_linux_virtual_machine" "tdx" {
  secure_boot_enabled = true
 vtpm_enabled = true

  os_disk {
    security_encryption_type = "DiskWithVMGuestState"
  }

  source_image_reference {
    publisher = "Canonical"
 offer = "0001-com-ubuntu-confidential-vm-jammy"
 sku = "22_04-lts-cvm"
  }
  }
```

### Phase 4: Infrastructure Deployment

- `terraform apply` with up to 2 retries (hard-capped)
- Outputs: `vm_id`, `vm_private_ip`, `bastion_name`, `resource_group`, `ssh_private_key_path`, `admin_username`

### Phase 5: Post-Deployment Automation

**Modules:** `cli/deployment/tdx/phase.py`, `setup.py` (GCP: `gcp_phase.py`, `gcp_setup.py`)

| Step | Action | Details |
|------|--------|---------|
| 8a | **Bastion Tunnel** | `az network bastion tunnel` opens SSH (port 22) via localhost |
| 8b | **SSH Wait** | Polls SSH via Bastion tunnel (300s) |
| 8c | **Cloud-Init** | Waits for `cloud-init status --wait` |
| 8d | **TDX Host Setup** | Uploads and runs `setup_tdx.sh`: system update, Python 3 venv, TDX guest kernel modules (`tdx_guest`, `configfs`, `tsm_report`), `tpm2-tools`, `tee_enclave` user, systemd service, udev rules |
| 8e | **Artifact Upload** | Uploads app directory as tarball via SCP over Bastion |
| 8f | **Dependency Install** | Downloads Python wheels locally → uploads → offline pip install on VM |
| 8g | **TDX Diagnostics** | Checks: kernel version, TDX devices, configfs-tsm, tpm2-tools, TPM device |
| 8h | **App Service Start** | `systemctl start tee-crafter-tdx.service` (runs as `tee_enclave` user) |
| 8i | **Readiness Poll** | Polls journal for "listening on port" (up to 3 min, 5s interval) |
| 8j | **SSH Port-Forward** | `ssh -L` through Bastion tunnel: `localhost:PORT → VM:5005` |
| 8k | **Client Verification** | Runs `client_tdx.py` against `localhost:PORT` |
| 9 | **Teardown** | Optional `terraform destroy` + `az group delete` |

---

## TDX Attestation Details

### Quote Generation (4 Fallback Paths)

The enclave application probes attestation interfaces in order:

1. **configfs-tsm** (`/sys/kernel/config/tsm/report/`) — Linux 6.7+. Creates a temp directory, writes `report_data`, sets `privlevel` to "0", reads `outblob`. This is the preferred path.

2. **`/dev/tdx-guest` ioctl** — Kernel 6.x+. Uses `TDX_CMD_GET_REPORT0` ioctl (direction=RW, size=1088 bytes). Then fetches the full quote via `TDX_CMD_GET_QUOTE0` ioctl.

3. **`/dev/tdx_guest` ioctl** — Older kernels (underscore variant). Same protocol as above.

4. **Azure vTPM** (`/dev/tpm0`) — the *only* path on an Azure paravisor CVM, not a fallback. Reads the Azure attestation report from vTPM NV index `0x01400001`. The hardware report inside it is a raw `TDREPORT`, not a DCAP quote, so it is never presented as evidence directly: the TD hands it to `AttestationClient`, which has the host convert it into a real DCAP quote via IMDS `/acc/tdquote` and exchanges that for an MAA `/attest/AzureGuest` token. See item 9 below.

### TDX Quote Structure (v4/v5)

```
Quote Header (48 bytes):
 0-1: version (uint16 LE, 4 or 5)
 2-3: att_key_type (uint16 LE, 2 = ECDSA-P256)
 4-7: tee_type (uint32 LE, 0x81 = TDX)

TD Report Body (584 bytes, at offset 48):
 0-15: TEE_TCB_SVN (16 bytes)
 16-63: MR_SEAM (48 bytes)
 64-111: MR_SIGNER_SEAM (48 bytes)
 112-119: SEAM_ATTRIBUTES (8 bytes)
 120-127: TD_ATTRIBUTES (8 bytes)
 128-135: XFAM (8 bytes)
 136-183: MRTD (48 bytes) — Trust Domain measurement
 184-231: MRCONFIGID (48 bytes)
 232-279: MROWNER (48 bytes)
 280-327: MROWNERCONFIG (48 bytes)
 328-519: RTMR0-RTMR3 (4 × 48 bytes)
 520-583: REPORT_DATA (64 bytes) — SHA256(ECDH_PUB) in first 32 bytes

ECDSA Sig Data (at offset 636 = 632 header+body + 4 sig_data_len):
 0-63: signature (64)
 64-127: attestation public key (64)
 128-129: outer cert_data_type (uint16 LE; 6 = QE_REPORT_CERTIFICATION_DATA)
 130-133: outer cert_data_size (uint32 LE)
 134-517: QE report (sgx_report_body_t, 384 bytes)
              +258-259: QE isv_svn (the "QE SVN" fed into TDX-1)
 518-581: QE report signature (64)
 582-583: qe_auth_data_size (2)
  584+Lauth: inner cert_data_type (2) + size (4) + PCK cert chain (PEM)
```

For DCAP-v3-style layouts (no outer cert_data header), the QE
report sits directly at offset 128 within sig-data. The client's
`_locate_qe_report_offset` helper auto-detects both layouts.

### RA-TLS Certificate

The TDX application generates a self-signed RA-TLS certificate at startup:
- Embeds the TDX DCAP quote in an X.509 extension (same OID as SGX: `1.2.840.113741.1.13.1`)
- The `tee_type` field in the quote header (`0x81`) distinguishes it from SGX quotes (`0x00`)
- `report_data` contains `SHA-256(ECDH_public_key)`, binding the TD's identity to its encryption key. This is channel binding, not a client-supplied nonce — see [attested_proxy.md](attested_proxy.md#freshness-channel-binding-not-a-client-nonce).

### Client Verification Steps

1. **Quote Version & TEE Type** — Verify version ≥ 4 and `tee_type == 0x81` (TDX)
2. **ECDSA Signature** — Verify `ECDSA-P256(SHA256(header + td_report_body))` with attestation key
3. **MRTD** — Match against the pinned value. An **unpinned client fails closed**: if `EXPECTED_MRTD` was rendered as `unknown`, the client prints a fatal message and exits 1 rather than accepting whatever Trust Domain answers.

 > **This used to be trust-on-first-use; it no longer is.** Earlier revisions self-pinned the MRTD from the first attested connection and announced that "all subsequent connections will enforce this value" — which meant nothing, because the client is a one-shot script and the only subsequent connection was the next one to the same peer moments later. Both TDX clients now behave like the SGX, SNP and GPU-CC clients (marked `M-06` in the source: `templates/tdx/gcp/client.template.py:588-614`, `templates/tdx/azure/client.template.py:755-780`). The only way to proceed without a pin is the explicit dev opt-out `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1`, which prints a full-width warning banner and states that the identity of the software inside the TD is not being checked.
 >
 > A valid TDX quote proves the *hardware*, not which image booted on it. Get the MRTD pinned properly — bake with `bake-ami` so it is auto-pinned from the measurement registry, or set it explicitly with `tee-crafter internal pin-measurement`.
4. **QE Report Binding** — `QE_report_data[:32] == SHA256(att_key || qe_auth_data)`. For GCP configfs-tsm quotes, the QE report data may be structurally absent (the quote contains only the TD report body without a traditional QE appendix); in this case the check returns N/A rather than failing, since the quote's ECDSA signature and PCK chain already provide integrity.
5. **PCK Certificate Chain** — Verify chain to Intel Root CA. For configfs-tsm quotes that lack embedded PCK certificate data, the check returns N/A (the platform-level quote signature is still verified).
6. **Public Key Binding** — Enforce `report_data[:32] == SHA256(enclave_ECDH_public_key)` on the DCAP quote.
7. **TDX Module Version (TDX-3)** — Extract the TDX module SVN from the quote header and refuse any quote whose module version is below `1.5.x`. Older modules lack the mitigations for attacker-controlled RTMR replay.
8. **Intel TCB collateral evaluation (TDX-1)** — Load `tcb_collateral.json` (staged beside the rendered client during `Phase 2c`) and evaluate it before trusting the quote. The build fetches TCBInfo, QEIdentity and the PCK CRLs from Intel PCS and **verifies each document's ECDSA signature** against a chain anchored on the pinned `certs/intel-sgx-dcap-root.pem`; the client re-verifies every signature offline, so it never egresses to Intel PCS. Verification is over the **raw response bytes** — Intel signs the `tcbInfo` body without whitespace, so a `json.loads` → `json.dumps` round-trip breaks the signature. Enforced in Intel's QVL order: signature → bundle staleness (7 days default, `TEE_CRAFTER_TCB_COLLATERAL_MAX_AGE_HOURS`; Intel's own `nextUpdate` is always enforced and the override cannot relax it) → FMSPC/PCEID applicability → platform `tcbStatus` → QEIdentity → PCK CRL. `UpToDate` only by default; `OutOfDate` and `Revoked` are refused under every policy. Lookup order for the bundle is `$TEE_CRAFTER_TCB_COLLATERAL` → beside the client → `/etc/tee_crafter/`. Air-gapped builds must point **both** `$TEE_CRAFTER_PCS_BASE_URL` (six endpoints on `api.trustedservices.intel.com`) and `$TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL` (the Intel SGX Root CA CRL, served from `certificates.trustedservices.intel.com`) at internal mirrors — seven endpoints across two hosts. The overrides are independent, so setting only the first still reaches the public certificate host. **`TEE_CRAFTER_FMSPC` must be set**: the FMSPC identifies the CPU model and exists only in a real quote's PCK leaf, so the build host cannot discover it — without it the bundle carries no TCBInfo and the client refuses the quote while printing the FMSPC it just parsed, so the fix is one rebuild. The QE SVN is parsed from the nested QE report inside the ECDSA sig-data (for TDX v4 `cert_data_type=6` quotes that is offset `sig_offset + 128 + 6`, not `sig_offset + 128` — see `_locate_qe_report_offset`); reading the header's reserved bytes always observes `qe_svn=0`.
9. **Two evidence formats, and on Azure only one of them exists.** `TEE_CRAFTER_TDX_EVIDENCE_FORMAT` fixes the format at build time for both the app and its client, so a server can never pick its own verifier. The default is `dcap`; Azure requires `azure-guest`.

 | | `dcap` | `azure-guest` |
 |---|---|---|
 | Evidence | Intel DCAP TD quote | MAA `/attest/AzureGuest` token (RS256 JWT) |
 | Trust root | Intel Root CA | Microsoft Azure Attestation |
 | Session binding | hardware-signed `report_data[:32]` | MAA-signed `x-ms-runtime.client-payload.nonce` |
 | Where it works | `tdx-gcp`, bare metal | Azure paravisor CVMs (`tdx-azure`) |

 **Why Azure cannot use `dcap`.** The guest on an Azure confidential VM runs under a Microsoft paravisor and never reaches a Quoting Enclave. vTPM NV index `0x01400001` holds an Azure-format attestation report — 32-byte `HCLA` header, then the *hardware report* at offset 32 (1024 bytes for TDX, 1184 for SEV-SNP), then runtime data at 1216 — and for TDX that hardware report is a **raw `TDREPORT`** whose `REPORTMACSTRUCT` is MAC'd with a key held only by the TDX module and the Quoting Enclave. No client can verify it, and MAA's `/attest/TdxVm`, which verifies *quotes*, rejects it. ([Azure CVM guest attestation design detail](https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design))

 **A DCAP quote does get produced — by the host, not the guest.** `azguestattestation1` POSTs the extracted `TDREPORT` to the instance metadata service at **`http://169.254.169.254/acc/tdquote`**, the host returns an Intel DCAP TD quote, and *that* is what the library submits to `/attest/AzureGuest?api-version=2020-10-01`.

 Established from the shipped artifact rather than from documentation, because the published source and the published package disagree. `libazguestattestation.so.1.1.2` exports `ImdsClient::GetTdxQuote`, `HclReportParser::ExtractTdxReportAndRuntimeDataFromHclReport` and `IsolationInfo::CreateTdxEvidence`, and contains the literal string `/acc/tdquote`. The GitHub source's default build (`#ifndef AZURE_LOCAL`, `AttestationClientImpl.cpp:713`) has *no* TDX branch at all — it labels any CVM `SEV_SNP` — so reasoning from it would have concluded, wrongly, that TDX is unsupported.

 Three consequences worth stating plainly:

 - **The TD needs IMDS reachability, not just MAA reachability.** IMDS is link-local and not subject to NSG rules, but a failure at this step is silent by default (next bullet) and surfaces only as an MAA rejection.
 - **Our trust root is still Microsoft, and the reason is narrower than "no quote exists".** The quote is brokered by the host and consumed by MAA; it never reaches our client, so we can only trust MAA's verdict about it. Intel TCB-status evaluation still has nothing to run against, for the same reason.
 - **The library's own step-by-step trace is what tells you which hop failed** — "Failed to retrieve the TD quote from IMDS", "Empty Quote received from IMDS TD Quote Endpoint", "Failed to parse TD quote response". Upstream ships `Logger::Log` with its only `printf` commented out, which makes all three present identically as an MAA rejection, so the bake re-enables it, redirected to **stderr** so stdout stays the bare JWT (`scripts/common/azure_guest_attestation.sh`).

 So on `azure-guest` the **TD itself** drives that exchange, using Microsoft's `azguestattestation1` library (`AttestationClient`, baked via `scripts/common/azure_guest_attestation.sh`), and puts the resulting JWT in its RA-TLS certificate in place of a quote. The client verifies the token: RS256 against the published JWKS, `iss`, expiry, then `x-ms-isolation-tee.x-ms-attestation-type == "tdxvm"`, `…x-ms-compliance-status == "azure-compliant-cvm"`, the MRTD/RTMRs, the debug flags, and the session nonce.

 > **Both trust properties are weaker than the DCAP path, and are stated on every run rather than buried here.** The trust root becomes Microsoft instead of Intel, and the session binding is MAA's signature over a value the guest supplied instead of the TDX module's signature over `report_data` — because `report_data` on a paravisor CVM is spent by the paravisor on the hash of its own runtime claims. It is still a real binding: the client refuses a token whose nonce is not this session's v2 preimage digest.

 > **A raw `HCLA` blob is refused under either format.** It is unverifiable by the client *and* unacceptable to `/attest/TdxVm`, so a guest presenting one has skipped the MAA exchange rather than found an alternative to it.

 Two prerequisites, both handled by the deploy because getting either wrong costs a live VM: the NSG needs an egress allow to the `AzureAttestation` service tag (`TF_VAR_attest_maa_egress` — the template's default egress is deny-all). Note Azure publishes **no** regional `AzureAttestation` tag, unlike `AzureKeyVault`; scoping below the flat tag means a Private Endpoint (`maa_endpoint_cidr`), and the service user needs the `tss` group for `/dev/tpmrm0`.

 **A third prerequisite: the workload must be able to read the TCG event log.** `AttestationClient` builds the request from the vTPM quote, the HCL report *and* the TCG event log at `/sys/kernel/security/tpm0/binary_bios_measurements`, which the kernel exports `root`-readable only. The workload runs as the unprivileged `tee_enclave` user, and the client does not fail when the log is unreadable — it submits the request without it, and MAA rejects that with `InvalidParameter` / `MissingKey: "TcgLogs is empty in attestation request."`. That error names neither the log nor the permission, and it looks like a wrong `api-version`. `tdx-azure.service` grants read on that one file to the `tee_enclave` group from its privileged `ExecStartPre`; see [security.md](security.md) §13.6 for why a group grant rather than `CAP_DAC_READ_SEARCH`.

10. **MAA verification is shared between the client and the app.** `templates/common/tee_crafter_maa.py` is staged on both sides — `copy_client_support_modules` beside the client, `copy_runtime_modules` into the TEE — so `azure_guest_token` (fetch) and `verify_maa_azure_guest_token` (verify) cannot drift apart on the nonce convention. Both token shapes are handled and they are not interchangeable: `/attest/TdxVm` issues *flat* `tdx_*` claims, `/attest/AzureGuest` nests the hardware verdict under `x-ms-isolation-tee`. Checking only the outer `x-ms-attestation-type` of an AzureGuest token would accept an ordinary Trusted Launch VM, which also attests as `azurevm`. Key Vault release policies address claims through the nested path, which is why `azure-guest` is also the format that makes Secure Key Release work — see [byok.md](byok.md).

### Terraform hardening (TDX-5)

GCP TDX Terraform pins `min_cpu_platform`:

```hcl
variable "min_cpu_platform" {
 type = string
  default = "Intel Sapphire Rapids"
  validation {
    condition = contains([
      "Intel Sapphire Rapids",
      "Intel Emerald Rapids",
    ], var.min_cpu_platform)
    error_message = "min_cpu_platform must be Sapphire Rapids or newer for TDX."
  }
  }
```

which forces Compute Engine to schedule the CVM on a Sapphire-Rapids or
Emerald-Rapids host. Older hosts do not carry TDX and would silently
produce non-TDX VMs with the `TDX` Terraform resource name.

---

## Security Model

| Property | Implementation |
|----------|---------------|
| **VM-Level Isolation** | TDX encrypts all guest memory with a CPU-managed key. Hypervisor and host OS cannot read TD memory |
| **Secure Boot + vTPM** | Azure TDX CVMs require `secure_boot_enabled` and `vtpm_enabled` — ensures boot integrity |
| **RA-TLS Attestation** | TDX DCAP quote in X.509 extension over TLS 1.3. Client verifies ECDSA signature, MRTD, PCK chain, and key binding |
| **ECIES Encryption** | Ephemeral ECDH-P256 + HKDF-SHA256 → AES-256-GCM with AAD (`b"tee-crafter-tdx-v1-req"` / `b"tee-crafter-tdx-v1-resp"`). Data encrypted before transmission |
| **Length-Prefixed Framing** | 4-byte big-endian length prefix on all TLS messages for reliable message boundaries |
| **Network Isolation** | No public IP. SSH only from Azure Bastion. Outbound: HTTPS (conditional), DenyAll catch-all |
| **Least Privilege** | Application runs as `tee_enclave` system user with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes` |
| **Disk Encryption** | OS disk encrypted with `DiskWithVMGuestState` — guest-controlled encryption keys |

---

## Key Files

| File | Purpose |
|------|---------|
| `templates/tdx/azure/app.template.py` | TDX application server: RA-TLS cert (TLS 1.3), TDX quote generation (4 fallback paths), ECDH key exchange with periodic rotation, ECIES decrypt with AAD, length-prefixed messaging |
| `templates/tdx/azure/client.template.py` | TDX client: RA-TLS connection, DCAP quote **or** MAA AzureGuest token verification (fixed at build time), MRTD check, session-binding check, ECIES encrypt |
| `templates/common/tee_crafter_maa.py` | Both halves of the MAA exchange — `azure_guest_token` in the TD, `verify_maa_azure_guest_token` in the client. One file so the nonce convention cannot drift |
| `core/keys/azure_skr_tool.py` | Secure Key Release via `AzureAttestSKR`. The key Key Vault wraps to is sealed to the vTPM, so the unwrap is delegated to the process that holds it |
| `templates/tdx/azure/main.template.tf` | Azure Terraform: resource group, VNet, NSG, Bastion, DCesv6 CVM, storage account |
| `scripts/tdx_azure/setup_tdx.sh` | Host setup: Python venv, TDX kernel modules, tpm2-tools, `tee_enclave` user (`kvm` + `tss` groups), systemd service, udev rules, bake marker |
| `scripts/common/azure_guest_attestation.sh` | Inlined into `setup_tdx.sh` (and the `snp-azure` / `gpu-cc-azure` setup scripts) at a placeholder: **`azguestattestation1` + `AttestationClient` + `AzureAttestSKR`**. One copy, shared by all three Azure CVM bakes |
| `cli/deployment/tdx/phase.py` | Orchestrator: Terraform → Bastion tunnel → setup → artifact upload → app start → client |
| `cli/deployment/tdx/setup.py` | Post-deploy: SSH wait, cloud-init, `setup_tdx.sh` upload and execution |
| `core/remote/azure_ssh.py` | Azure Bastion tunnel management, SSH/SCP helpers, `SSHPortForward` |

---

## Azure VM Requirements

TDX requires Azure **DCesv6** or **ECesv6** series VMs, which are available in **westus** and **westus3** regions. The VM image must be a **Confidential VM** image (e.g., `0001-com-ubuntu-confidential-vm-jammy` with SKU `22_04-lts-cvm`). Secure boot and vTPM are mandatory.

---

## Setup Script Summary (`setup_tdx.sh`)

| Step | Action |
|------|--------|
| 1 | System update (`apt-get update && upgrade`) |
| 2 | Install Python 3, pip, venv, build-essential |
| 3 | Install TDX guest modules (`linux-modules-extra`, `tdx_guest`, `configfs`, `tsm_report`) + `tpm2-tools` |
| 4 | Create `tee_enclave` system user with TDX device access |
| 5 | Create application directory (`/opt/tee-crafter-tdx`) |
| 6 | Create Python venv, install `cryptography` and `pydantic` |
| 7 | Create systemd service (`tee-crafter-tdx.service`) with hardening (NoNewPrivileges, ProtectSystem, PrivateTmp) |
| 8 | Set configfs-tsm permissions, create udev rules for TDX devices |
| 9 | Verify cloud-init and waagent health |
| 10 | Write bake marker (`/etc/tee_crafter/baked_tdx`) |

---

## GCP Intel TDX (`--tee-platform tdx-gcp`)

### Instance Types
- **C3** machines (Intel Sapphire Rapids with TDX support)
- Confidential VM with `confidential_instance_config { confidential_instance_type = "TDX" }`

### Attestation Flow
Same TDX attestation as Azure, using configfs-tsm as the primary quote generation path. TDX quotes are generated locally on the VM and embedded in the RA-TLS certificate.

### Access Model
- **IAP TCP tunnel** (no public IP, no SSH keys over the internet)
- Artifacts uploaded via SCP through IAP tunnel
- Client verification via SSH port-forward through IAP

### Cloud Resources Created (Terraform)

| Resource | Configuration |
|----------|--------------|
| **VPC Network** | Custom mode with private subnet |
| **Firewall Rules** | IAP-only ingress (SSH from `35.235.240.0/20`), deny all other inbound |
| **Cloud NAT + Router** | Conditional. Not provisioned by default (pre-baked image is mandatory). Created only when SIEM (`egress_mode=auto/public`) or the internal `bake-ami` pipeline requires public egress |
| **Confidential VM** | C3 series, Ubuntu 22.04, TDX enabled, no public IP, CMEK-encrypted boot disk |
| **GCS Bucket** | Artifact storage with CMEK encryption, uniform bucket-level access |
| **KMS Keyring + Key** | Customer-managed encryption key for disk and bucket |
| **Service Account** | VM-level SA with `storage.objectViewer`, `cloudkms.cryptoKeyEncrypterDecrypter`, `logging.logWriter` |

### Key Files
| File | Purpose |
|------|---------|
| `templates/tdx/gcp/app.template.py` | TDX application server (RA-TLS, TDX quote via configfs TSM, ECDH, ECIES) |
| `templates/tdx/gcp/client.template.py` | TDX client (RA-TLS verification, TDX quote parsing, ECIES) |
| `templates/tdx/gcp/main.template.tf` | GCP Terraform (Confidential VM, VPC, IAP, KMS, GCS) |
| `scripts/tdx_gcp/setup_tdx_gcp.sh` | Host setup (Python venv, `tee_enclave` user, systemd service) |
| `cli/deployment/tdx/gcp_phase.py` | Deployment orchestrator |
| `cli/deployment/tdx/gcp_setup.py` | IAP/SSH-based setup automation |

### Azure vs GCP TDX Comparison

| Aspect | Azure (`tdx-azure`) | GCP (`tdx-gcp`) |
|--------|---------------------|-----------------|
| VM series | DCesv6 / ECesv6 | C3 |
| Quote generation | configfs-tsm, ioctl, or vTPM fallback | configfs-tsm (primary) |
| Access method | Bastion + SSH | IAP TCP tunnel |
| Disk encryption | DiskWithVMGuestState | CMEK via Cloud KMS |
| Secure Boot + vTPM | Required by Azure CVM config | Enabled by Terraform |

---

## Security Checklist

- [x] **VM-level isolation**: TDX Trust Domain encrypts all guest memory with a CPU-managed key; hypervisor and host OS cannot read TD memory.
- [x] **Secure boot + vTPM**: Azure TDX CVM configuration enforces `secure_boot_enabled = true` and `vtpm_enabled = true`, with OS disk protected via `DiskWithVMGuestState`.
- [x] **Attestation verification**: Client parses TDX DCAP quote (v4/v5), verifies ECDSA-P256 signature, checks `tee_type == 0x81`, and validates MRTD.
- [x] **PCK certificate chain**: DCAP quote’s PCK certificate is validated to the Intel Root CA.
- [x] **Public key binding**: `REPORT_DATA` field must contain `SHA256(enclave_ECDH_public_key)`; client enforces this binding.
- [x] **MRTD pinning, fail-closed**: The client matches the attested MRTD against the value baked in at render time. An unpinned client (`EXPECTED_MRTD == "unknown"`) exits 1 rather than trusting whatever Trust Domain answers; `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1` opts back into accept-anything behind a full-width warning banner (development only). Marked `M-06` in both TDX clients.
- [x] **Network isolation**: No public IP; SSH access is Bastion-only (Azure) or IAP-only (GCP), with restrictive outbound controls.
- [x] **Least-privilege service**: `tee-crafter-tdx.service` runs as `tee_enclave` with systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`, isolated tmp).
- [x] **Offline dependency install**: Python wheels are pre-fetched on the deployer and installed offline on the TD to avoid runtime internet access.
- [x] **TLS 1.3 minimum**: All RA-TLS connections enforce `ssl.TLSVersion.TLSv1_3` as minimum version.
- [x] **AES-GCM AAD**: Request and response payloads use distinct Authenticated Associated Data tags (`b"tee-crafter-tdx-v1-req"` / `b"tee-crafter-tdx-v1-resp"`).
- [x] **ECDH key + RA-TLS certificate rotation**: Server regenerates the ECDH keypair and re-creates the RA-TLS certificate (with fresh TDX quote) every 3600 seconds; **rotation failure is fatal** (`sys.exit(1)`), not silently ignored.
- [x] **`get_attestation` path**: Fresh TDX quote generation for the JSON attestation probe must succeed; failures are **not** masked as empty quote / `mrtd: unavailable`.
