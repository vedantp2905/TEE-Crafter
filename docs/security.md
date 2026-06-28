# TEE-Crafter Security Architecture

This document describes the defense-in-depth security model applied across
all TEE-Crafter deployment paths and platforms.

For the full pass/fail catalogue applied by `tee-crafter verify-provenance`
see [docs/audit_matrix.md](audit_matrix.md).

## Deployment model

TEE-Crafter accepts **one input** (a build-context directory containing a `Dockerfile`) and
**two run modes**, deployable to any of the ten TEE platform targets:

| Run mode | CLI flag | Description |
|----------|----------|-------------|
| **Persistent** | `--persistent` | Long-lived service behind the platform-owned attested ingress proxy (RA-TLS). User container on `127.0.0.1:<port>`. |
| **Batch** | `--batch` | One-shot job; container runs to completion; outputs captured via `docker diff` + `docker cp` into `output.tar.gz`. See [batch_mode.md](batch_mode.md). |

```bash
tee-crafter deploy <path|image> --tee-platform <platform> [--batch | --persistent]...
```

(`tee-crafter deploy` is an alias for `deploy`.)

| Platform | Cloud | TEE Technology |
|----------|-------|---------------|
| `nitro-aws` | AWS | Nitro Enclaves (EIF in isolated VM) |
| `snp-aws` | AWS | AMD SEV-SNP Confidential VM |
| `snp-azure` | Azure | AMD SEV-SNP Confidential VM |
| `snp-gcp` | GCP | AMD SEV-SNP Confidential VM |
| `tdx-azure` | Azure | Intel TDX Confidential VM |
| `tdx-gcp` | GCP | Intel TDX Confidential VM |
| `sgx-azure` | Azure | Intel SGX / Gramine Enclave |
| `gpu-cc-gcp` | GCP | Intel TDX + NVIDIA Confidential Computing (H100) |
| `gpu-cc-azure` | Azure | AMD SEV-SNP + NVIDIA Confidential Computing (H100) |
| `gpu-cc-aws` | AWS | NitroTPM + NVIDIA Confidential Computing (H100/H200/B200) |

---

## 1. Hardware-Level Isolation

Every deployment runs inside a hardware Trusted Execution Environment. The
CPU's memory encryption engine ensures that neither the cloud provider, the
hypervisor, nor any co-tenant can read or tamper with the guest's memory.

| Platform | Isolation Primitive | Attestation Binding |
|----------|-------------------|-------------------|
| Nitro | Enclave Image File (EIF) in isolated VM | PCR0–PCR2 bound to EIF content |
| TDX | Trust Domain with Intel SEAM module | MRTD bound to kernel + initrd |
| SEV-SNP | Encrypted VM with reverse-map table | Launch measurement bound to firmware |
| SGX | Gramine enclave (ring-3 process isolation) | MRENCLAVE bound to manifest + binary |
| GPU CC (GCP) | Intel TDX VM + NVIDIA CC-mode GPU (H100) | Dual: TDX quote (MRTD) + NVIDIA NRAS EAT JWT (GPU firmware/driver/CC mode) |
| GPU CC (Azure) | AMD SEV-SNP VM + NVIDIA CC-mode GPU (H100) | Dual: SNP report (Azure **vTPM** HCL + **TPM quote** key binding) + NVIDIA NRAS EAT JWT |
| GPU CC (AWS) | NitroTPM + NVIDIA CC-mode GPU (H100/H200/B200) | NitroTPM PCRs + NVIDIA NRAS EAT JWT (no CPU-TEE — partial-confidential) |

### Attestation and RA-TLS

**Persistent (VM-class TEEs):** Remote Attestation TLS (RA-TLS) is terminated by
the platform-owned **attested ingress proxy**. A self-signed X.509 certificate
is generated inside the TEE at startup with the hardware attestation report
embedded as an X.509 extension. The report's `report_data` field is
cryptographically bound to the ECDH public key hash.

- **Attestation surface:** the proxy binary and its measurement baseline — not
 the user's container image.
- **User container:** runs on `127.0.0.1` with no attestation code; hardened
 with Docker isolation (cap-drop, seccomp, AppArmor, read-only rootfs).

**Batch (all platforms, including `sgx-azure` via GSC):** there is no live
RA-TLS client channel. Assurance is the signed attestation document captured at
boot, plus provenance and the audit bundle.

**Nitro persistent:** attestation covers the EIF that contains the proxy and
runtime; PCR values bind to exact image content.

Private keys are ephemeral — generated fresh on each boot and never written
to persistent storage.

### AMD SEV-SNP TCB Hardening (AMD-SB-3015)

All AMD SEV-SNP platforms (snp-aws, snp-azure, snp-gcp, gpu-cc-azure) enforce
AMD-SB-3015 (CVE-2024-21944) mitigations at **both** server boot time and
client verification time:

| Check | Field | Requirement | Consequence |
|-------|-------|-------------|-------------|
| Memory aliasing mitigation | `PLATFORM_INFO` bit 5 (`ALIAS_CHECK_COMPLETE`) | Must be set | Server refuses to start; client aborts connection |
| Firmware patch level | `REPORTED_TCB` bits 55:48 (SNP firmware SVN) | Must be >= `0x16` (Genoa-class) | Server refuses to start; client aborts connection |

- **Server-side**: At boot, the SNP app template reads `PLATFORM_INFO` and
 `REPORTED_TCB` from a startup attestation report and calls `sys.exit(1)` if
 either check fails.
- **Client-side**: The client extracts the same fields from the RA-TLS
 certificate's embedded SNP report and fatally aborts if either check fails.
- **Milan note**: Milan-class processors require SNP firmware SVN >= `0x17`;
 clients emit a warning if the platform appears to be Milan with SVN `0x16`.

---

## 2. Network Isolation

### Per-Deployment VPC Isolation

Every deployment creates its own dedicated VPC/VNet with a unique deployment
suffix on all cloud resource names. No two deployments share network
infrastructure, eliminating cross-deployment network bleed and enabling
per-deployment flow logging for audit. N deployments of the same platform can
run fully in parallel without name collisions (VPC, subnet, firewall rule,
VM, resource group, service account, storage — all uniquified).

### AWS (Nitro, SEV-SNP, GPU CC)

- **Per-deployment VPC** — each `tee-crafter deploy` provisions a dedicated
 VPC with its own CIDR block (`10.0.0.0/16`), private subnet, route table,
 and security group. No use of the default VPC.
- **VPC Flow Logs** — all traffic (accept + reject) is logged to a dedicated
 CloudWatch Logs group at 60-second aggregation. Logs are retained for 30
 days and scoped to the deployment VPC.
- **Zero public ingress** — Security Groups allow no inbound rules.
- **Egress restricted to VPC** — pre-baked AMIs are mandatory in the public
 CLI, so every production deploy ships with `allow_setup_egress = false`:
 HTTPS (443) is limited to VPC CIDR + interface endpoints, and DNS (53) is
 restricted to the VPC resolver only.
- **NAT gateway** (conditional, opt-in only) — never provisioned by default.
 A NAT gateway is created only when something explicitly declares the need
 for public egress: SIEM in `egress_mode=auto` or `egress_mode=public`
 (Splunk HEC, Datadog, public Azure Monitor / CloudWatch endpoints), or
 the internal `tee-crafter internal bake-ami` pipeline (which tears the NAT
 down once the image snapshot is taken). SIEM in `egress_mode=private` (AWS
 PrivateLink) or `egress_mode=none` provisions no NAT.
- **VPC Interface Endpoints** for SSM, S3, and KMS — no internet gateway
 required for management or artifact delivery.
- **SSM-only access** — no SSH keys, no public IPs, no bastion hosts.

### Azure (TDX, SEV-SNP, SGX, GPU CC)

- **Per-deployment VNet** — each deployment creates its own Azure Resource
 Group with a dedicated VNet, subnets, and NSG.
- **Virtual network flow logs** — all traffic (accept + reject) is logged
 via Azure Network Watcher VNet flow logs to the deployment's storage account
 with Traffic Analytics enabled (per-deployment Log Analytics workspace,
 10-minute aggregation). Logs are retained for 30 days.
- **NSG with zero public ingress** — SSH allowed only from the Bastion subnet,
 not from the internet.
- **Egress locked to VirtualNetwork by default** — pre-baked images are
 mandatory, so the deploy step provisions only HTTPS to VNet services,
 Azure IMDS (169.254.169.254), and wireserver (168.63.129.16). A NAT
 gateway is created only when SIEM (or another explicit egress requirement)
 asks for it.
- **Bastion-only access** — all SSH sessions tunnel through Azure Bastion.
 Note this means every Azure deployment **does** allocate a public IP: an
 `azurerm_public_ip` for the Bastion host, unconditionally, in all four Azure
 templates. It is attached to the Bastion, never to the TEE VM.

### GCP (TDX, SEV-SNP, GPU CC)

- **Per-deployment VPC** — each deployment creates a dedicated VPC network
 with a private subnet.
- **VPC Subnet Flow Logs** — enabled on all subnets at 5-second aggregation
 with 100% sampling and full metadata. Visible in Cloud Logging.
- **`deny_all_ingress` firewall** at priority 65534 — blocks all traffic
 except IAP SSH (35.235.240.0/20).
- **Egress restricted** to internal VPC ranges and HTTPS to the deployment
 bucket.
- **IAP-tunneled SSH only** — no external IPs assigned to VMs. The
 `google_compute_instance` `network_interface` block in all three GCP
 templates has no `access_config`, which is what actually withholds the
 external IP.

These network controls apply to every deployment.

### Where public IPs do and do not exist

"No public IPs" is true of the **TEE VM on every platform**, and that is the
claim worth making. It is not true of the deployment as a whole on Azure, and
it is conditionally untrue on AWS and GCP. Verified against the Terraform
templates:

| Platform group | TEE VM public IP | Other public IPs created |
|---|---|---|
| `nitro-aws`, `snp-aws`, `gpu-cc-aws` | No — `associate_public_ip_address = false` | A public subnet (`map_public_ip_on_launch = true`) and NAT gateway, **only** when `allow_setup_egress` is true (default false). No bastion — access is SSM-only. |
| `snp-azure`, `tdx-azure`, `sgx-azure`, `gpu-cc-azure` | No | **Always** an `azurerm_public_ip` for the Azure Bastion host. Plus a NAT gateway public IP when NAT is provisioned. |
| `snp-gcp`, `tdx-gcp`, `gpu-cc-gcp` | No — no `access_config` on the instance | Cloud NAT with `nat_ip_allocate_option = "AUTO_ONLY"` when NAT is provisioned. Access is IAP-tunnelled. |

The bastion and NAT addresses are deliberate: they are how you reach and
bootstrap a VM that has no address of its own. They are not a path into the
TEE — inbound reaches the Bastion, not the workload.

---

## 3. OS-Level Hardening

All guest images (CVM, SGX, and Nitro host) apply the following at bake time,
persisted to `/etc/sysctl.d/99-tee-crafter.conf`:

```
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.core_pattern = |/bin/false
```

- ICMP redirects disabled (prevents route-table poisoning).
- Source routing disabled (prevents IP spoofing).
- Core dumps disabled (prevents leaking TEE memory to disk).

### Dedicated Service User

A non-login system user `tee_enclave` runs all application services across
every platform. It has no shell (`/usr/sbin/nologin`), no home directory, and
is granted only the minimum group memberships required for attestation device
access (`kvm` for SEV/TDX device nodes, `tss` for Azure vTPM, `ne` for Nitro
enclaves, `sgx` for SGX devices).

---

## 4. Systemd Service Hardening

The RA-TLS service (`tee-crafter-{snp,tdx}.service` on CVMs,
`sgx-enclave.service` on SGX, `host-proxy.service` on Nitro hosts) runs under
a strict systemd sandbox. This applies to **every persistent deployment** —
the attested ingress proxy runs under the same hardened unit regardless of
  the user's container image.

| Directive | Effect |
|-----------|--------|
| `User=tee_enclave` | Runs as unprivileged service user |
| `ProtectSystem=strict` | Mounts `/usr`, `/boot`, `/etc` read-only |
| `ProtectHome=yes` | Hides `/home`, `/root`, `/run/user` |
| `PrivateTmp=yes` | Isolated `/tmp` namespace |
| `NoNewPrivileges=yes` | Prevents privilege escalation via setuid (TDX uses `NoNewPrivileges=no`, see note below) |
| `ProtectKernelTunables=yes` | Read-only `/proc/sys`, `/sys` (see note below) |
| `ProtectKernelModules=yes` | Blocks module loading |
| `ProtectKernelLogs=yes` | Blocks `dmesg` access |
| `ProtectControlGroups=yes` | Read-only cgroups |
| `ProtectClock=yes` | Blocks clock modification |
| `ProtectHostname=yes` | Blocks hostname changes |
| `RestrictRealtime=yes` | Blocks RT scheduling |
| `RestrictSUIDSGID=yes` | Blocks setuid/setgid file creation |
| `RestrictNamespaces=yes` | Blocks namespace creation |
| `LockPersonality=yes` | Locks execution domain |
| `SystemCallArchitectures=native` | Blocks non-native syscalls |
| `SystemCallFilter=@system-service @resources` | Allowlist of syscall groups |
| `ReadWritePaths=` | App directory, `/tmp`, `/var/log/tee_crafter` (where used), and platform-specific TEE paths (e.g. `/-/sys/kernel/config/tsm`, TPM devices on Azure GPU CC) |
| `AmbientCapabilities=` | Minimal capability grants when required (Nitro: `CAP_NET_BIND_SERVICE`; TDX: `CAP_DAC_OVERRIDE`) |

**`ProtectClock` and `DeviceAllow` note:** `ProtectClock=yes` implicitly
activates the Linux cgroup device controller (`DevicePolicy=closed`), which
blocks ALL device nodes not explicitly whitelisted. Every TEE platform
therefore declares `DeviceAllow` entries for its attestation devices.
SNP and TDX services also set `ProtectKernelTunables=no` because configfs TSM
attestation writes to `/sys/kernel/config/tsm`. On TDX, configfs creates
`inblob` as root-owned write-only, so the service uses
`AmbientCapabilities=CAP_DAC_OVERRIDE` with `NoNewPrivileges=no` to write
attestation input without running as root. All services still run as the
unprivileged `tee_enclave` user with full sandbox — root is not required.

Attestation device access per platform:
- SEV-SNP: `DeviceAllow=/dev/sev-guest rw`, `DeviceAllow=/dev/sev rw`,
 `ReadWritePaths=-/sys/kernel/config/tsm`, `SupplementaryGroups=kvm`
- TDX: `DeviceAllow=/dev/tdx-guest rw`, `DeviceAllow=/dev/tdx_guest rw`,
 `ReadWritePaths=-/sys/kernel/config/tsm`, `SupplementaryGroups=kvm`,
 `AmbientCapabilities=CAP_DAC_OVERRIDE`, `NoNewPrivileges=no`
- Azure vTPM (SNP-Azure, TDX-Azure, GPU-CC-Azure): `DeviceAllow=/dev/tpm0 rw`,
 `DeviceAllow=/dev/tpmrm0 rw`, plus the platform-specific allows above
- SGX: `DeviceAllow=/dev/sgx_enclave rw`, `DeviceAllow=/dev/sgx_provision rw`
- Nitro host: `/opt/tee-crafter`, `/etc/tee_crafter` (certs + app);
 `AmbientCapabilities=CAP_NET_BIND_SERVICE` for port 443 (no device nodes)

---

## 5. Run-Mode Security

### 5a. Persistent mode (`--persistent`)

The user's Docker container runs as a long-lived service on `127.0.0.1`.
Security considerations:

- **Attestation is platform-owned** — the attested ingress proxy terminates
 RA-TLS; the user container never handles keys or quotes.
- **Docker isolation** — `--cap-drop ALL`, `--read-only`, custom seccomp,
 AppArmor MAC, `--pids-limit 512` on the user container.
- **Service profiles** (`--service-profile`) tune proxy cert TTL and
 re-attestation interval, not user code.
- **Continuous attestation** — proxy re-attest events stream to SIEM; see
 [attested_proxy.md](attested_proxy.md).

`sgx-azure` does not support persistent mode in v1 (batch-only via GSC).

### 5b. Batch mode (`--batch`)

The user's Docker image runs to completion with its original `ENTRYPOINT`/`CMD`.
After exit, the batch collector packages every changed file into
`output.tar.gz` with SHA-256 sidecars.

- **No live RA-TLS channel** — assurance is deploy-time attestation +
 signed provenance + audit bundle.
- **Same Docker hardening** as persistent mode during the run.
- **SGX (`sgx-azure`):** image is graminized via GSC before execution;
 `MRENCLAVE`/`MRSIGNER` derived from the signed graminized image.

### 5c. Platform packaging details

#### Nitro

The user's Docker image is merged with the TEE-Crafter runtime via a
multi-stage Docker build:

1. **Stage 1 (nsm-builder):** Compiles `nsm-cli` from Rust (statically
 linked) in an Alpine builder — no user code involved.
2. **Stage 2 (FROM user-image):** The user's image becomes the final base
 layer, preserving their runtime, packages, and `WORKDIR`. TEE-Crafter
 layers on top:
 - `nsm-cli` for Nitro attestation
 - `app_vsock.py` (the vsock RA-TLS proxy)
 - `tee_entrypoint.sh` (orchestrates startup)
 - Minimal Python deps: `cryptography`, `requests`, `boto3` (trimmed)
 - `iproute2` for loopback networking

The `ENTRYPOINT` is locked to `tee_entrypoint.sh`, which:
1. Brings up the loopback interface (required inside the EIF).
2. `cd`s into the user's original `WORKDIR`.
3. Starts the user's original `CMD` in the background.
4. Polls until the user's server accepts connections on the detected port.
5. `exec`s the RA-TLS vsock proxy as PID 1.

The entire merged image is built into an EIF. PCR0–PCR2 bind to the
full image content, so any change to the user's code or the TEE runtime
produces a different measurement. The enclave runs with exactly the
CPU and RAM determined by the chosen instance type (host) and the small
default enclave size (overridable via `TEE_CRAFTER_COMPUTE_OVERRIDE_CPU` /
`_RAM_MB`).

#### CVM / SGX Container Mode (TDX, SEV-SNP, SGX)

The user's Docker image runs as a sidecar container alongside the RA-TLS
proxy inside the confidential VM or SGX host:

- **RA-TLS proxy** (`tee-crafter-{snp,tdx}.service` or `sgx-enclave.service`)
 listens on port 5005, forwards attested requests to
 `localhost:CONTAINER_PORT` via HTTP.
- **User container** (`tee-crafter-container.service`) runs the user's
 original Docker image with full hardening (see section 6).

---

## 6. Docker Container Hardening

On all CVM, SGX, and GPU CC platforms (9 of 10), user containers run under three
layers of mandatory access control:

### 6a. Docker Security Flags

```
docker run --rm --network host \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=/etc/tee_crafter/seccomp-container.json \
  --security-opt apparmor=tee-crafter-container \
  --pids-limit 512 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  tee-crafter
```

| Flag | Effect |
|------|--------|
| `--cap-drop ALL` | Drops all 41 Linux capabilities |
| `--security-opt no-new-privileges` | Prevents setuid escalation |
| `--pids-limit 512` | Prevents fork bombs |
| `--read-only` | Root filesystem is immutable (**persistent mode only** — see below) |
| `--tmpfs /tmp:noexec,nosuid` | Writable temp without execute permission |
| `--network host` | `localhost` forwarding to the RA-TLS proxy (documented residual — see below) |

Resource limits (CPU, memory) are not hardcoded in the Docker flags because
the CVM itself is the resource boundary: Terraform provisions the exact
`--instance-type` chosen (or the platform catalog default). The container
can use all resources available to the confidential VM.

#### Run-mode delta: `--read-only`

The flag set above is the **persistent** (`--persistent`) service unit
(`container.service.template`), which mounts the container root filesystem
read-only. **Batch** (`--batch`) runs the user image *as-is* under
`container.batch.service.template` so the workload can write its result set,
which the platform then captures into a signed, encrypted output bundle —
batch therefore does **not** set `--read-only`. All other hardening
(`--cap-drop ALL`, no-new-privileges, custom seccomp, AppArmor, `--pids-limit`)
applies identically to both modes. The compliance evidence (`docker_hardening`)
reports the accurate per-mode flag set rather than claiming a read-only rootfs
for batch.

#### Documented residual: `--network host`

Both run modes use `--network host` rather than a dedicated container network
namespace. This is a deliberate, accepted residual: the user container talks to
the attested RA-TLS proxy over `localhost`, and the confidential VM itself has
**zero ingress** (no SSH, no inbound security-group rules; all external traffic
is fronted by the platform-owned proxy and egress is allowlisted). The TEE VM
boundary, not a container netns, is the network trust boundary. Operators who
require per-container network isolation in addition to the VM boundary should
treat this as a known limitation.

### 6b. Custom Seccomp Profile

A restricted seccomp profile (`templates/common/seccomp-container.json`) is
baked to `/etc/tee_crafter/seccomp-container.json` by the setup script of **nine
of the ten platforms** — every one except `nitro-aws`, whose workload runs
inside the enclave EIF with no Docker daemon to apply a profile to. The
`__SECCOMP_PROFILE__` placeholder in each `setup_*.sh` is filled from the
packaged JSON at render time (`cli/loaders.py`, lines 25–28), and both container
systemd units refuse to start if the file is absent
(`ExecStartPre=/usr/bin/test -f /etc/tee_crafter/seccomp-container.json`).

It uses a default-deny policy (`defaultAction: SCMP_ACT_ERRNO`) with an
allowlist covering the syscalls a typical web-server workload needs — everything
not on that list returns an errno. Compared to Docker's default profile, it
additionally blocks:

- `ptrace` — no process tracing or debugging
- `mount` / `umount2` — no filesystem mounting
- `bpf` — no BPF program loading
- `kexec_load` / `kexec_file_load` — no kernel replacement
- `init_module` / `finit_module` / `delete_module` — no kernel module ops
- `acct` — no process accounting
- `add_key` / `keyctl` / `request_key` — no kernel keyring access
- `syslog` — no kernel log access
- `settimeofday` / `clock_settime` — no clock manipulation
- `reboot` — no system reboot
- `userfaultfd` — blocks a common exploit vector
- `get_mempolicy` / `set_mempolicy` / `move_pages` — no NUMA manipulation
- `open_by_handle_at` — no file handle bypass (used in container escapes)
- `personality` — restricted to known safe values only

### 6c. AppArmor Mandatory Access Control

Two AppArmor profiles are loaded at bake time and pinned to specific
systemd units. The bake step is fail-closed: if `apparmor_parser -r`
fails on either profile, `setup_*.sh` exits non-zero and the AMI build
aborts.

| Profile | Loaded by | Applied to | Posture |
|---------|-----------|-----------|---------|
| `tee-crafter-container` | the nine Docker-running platforms' `setup_*.sh` | `container.service` (service mode) | Strict path allowlist — read-execute `/app`, `/opt/venv`, `/usr/{bin,lib}` etc.; write only `/tmp`, `/var/{log,lib}/tee-crafter`, `/run/tee-crafter`. Suited to tee-crafter-built images. |
| `tee-crafter-batch-container` | the same nine `setup_*.sh` | `container.batch.service` (mode A batch) | Permissive filesystem (`/** rwlkmix`) — user-supplied images write wherever their ENTRYPOINT expects — combined with the same deny-list of host-kernel interfaces, mount/pivot_root/ptrace, and dangerous capabilities as the strict profile. |

`nitro_aws/setup_nitro.sh` installs neither profile (0 occurrences of
`__APPARMOR_PROFILE__`), for the same reason it installs no seccomp profile.

Both profiles share these denies (kernel-level MAC enforcement beyond
what Docker and seccomp offer):

| Rule | Effect |
|------|--------|
| `deny network raw` | Blocks raw socket creation (no packet sniffing/injection) |
| `deny network packet` | Blocks packet socket access |
| `deny mount` / `deny umount` / `deny pivot_root` | Blocks all mount operations |
| `deny ptrace (read, readby, trace, tracedby)` | Blocks process tracing both directions |
| `deny /proc/kcore`, `kmem`, `mem` | Blocks kernel memory access |
| `deny /proc/sysrq-trigger`, `keys`, `sched_debug` | Blocks privileged process metadata |
| `deny /sys/firmware/**`, `kernel/**`, `power/**`, `module/**` | Blocks firmware / kernel-tunable access |
| `deny /var/run/docker.sock`, `containerd/**` | Blocks container runtime escape |
| `deny capability sys_admin`, `sys_rawio`, `sys_module`, `sys_boot` | Blocks administrative caps |
| `deny capability net_admin`, `net_raw`, `net_broadcast` | Blocks network reconfiguration |
| `deny capability sys_ptrace`, `dac_read_search`, `mac_admin`, `mac_override` | Blocks tracing and ACL bypass |

The batch unit also applies the SELinux MCS label `container_runtime_t`
(`--security-opt label=type:container_runtime_t`). On AppArmor-only
distributions (Ubuntu CVMs) the label is a no-op; on SELinux-enforcing
distributions it enforces the same confinement boundary.

### 6d. Why Nitro Doesn't Need Docker Hardening

On Nitro, the container is merged into the EIF (Enclave Image File) and runs
directly inside the hardware-isolated enclave. There is no Docker runtime, no
kernel, and no host OS inside the enclave — the EIF IS the entire execution
environment. PCR values bind to the exact image content. Docker security
flags, seccomp, and AppArmor are unnecessary because the enclave boundary
provides stronger isolation than any of these controls.

---

## 7. Proxy Security

The attested ingress proxy (present on every persistent VM-class deployment) enforces:

- **Error sanitization** — exception details from user logic or the container
 are never forwarded to the client. Internal errors are logged to the
 journal; clients receive only generic structured errors:
 `{"error": "Internal proxy error", "status": "proxy_error"}`.
- **Request timeout** — 300-second hard timeout on all forwarded requests.
- **JSON-only protocol** — input and output are validated as JSON.
- **Localhost-only forwarding** (container mode) — the proxy only connects
 to `127.0.0.1`, never to external addresses.
- **Client verification** — the automated post-deploy client checks for
 proxy error markers (`Container not reachable`, `connection_refused`) and
 reports failure, preventing false-positive success.

---

## 8. Build Provenance and Cryptographic Signing

Every deployment generates a hash-chained, tamper-evident
`provenance/build_provenance.json` audit trail (under each build's
per-run directory) recording:

- SHA-256 hashes of the Dockerfile, built image digest, staged platform
 artifacts, and all generated IaC.
- Timestamps, pipeline version, and platform metadata.
- Terraform state fingerprints.

### Ed25519 Provenance Signing

At build time the provenance document is signed with Ed25519. Five files
are produced under `<build_dir>/provenance/`:

| File | Content |
|------|---------|
| `provenance/build_provenance.json` | The full hash-chained audit trail |
| `provenance/build_provenance.sig` | Hex-encoded Ed25519 signature over canonical JSON |
| `provenance/build_provenance.pub` | PEM-encoded Ed25519 public key |
| `provenance/build_provenance.pub.sha256` | SHA-256 fingerprint of the SPKI-DER public key |
| `provenance/build_provenance.key_kind.txt`| `longlived` or `ephemeral` plus the resolved source |

> Builds emitted before the subdir layout shipped (or any other tool
> that writes a flat layout) still verify — every reader looks under
> the canonical subdir first and falls back to the top-level path.

The signature covers the canonical (sorted, compact) JSON serialization of
the document. Any modification to the audit trail invalidates the signature.

#### Two signing modes

* **Long-lived key (production).** The operator pre-creates a persistent
 Ed25519 keypair (e.g. via `tee-crafter audit-gen-signing-key`) and
 exposes the private key to every deploy via one of:
 * `TEE_CRAFTER_PROVENANCE_SIGNING_KEY` (PEM text, e.g. CI secret)
 * `TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE` (PEM path)
 * OS keyring entry `tee-crafter` / `provenance-signing-key`
 * `~/.tee-crafter/provenance-signing-key.pem` (mode 0600)
 Every build then ships the *same* `build_provenance.pub`. Verifiers
 pin the SHA-256 fingerprint of that public key in their audit policy
 and require it on every artefact, which is what makes the audit trail
 externally verifiable rather than merely locally tamper-evident.

* **Ephemeral key (development).** When no long-lived key is configured,
 builds abort with a clear error message unless
 `TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL=1` is set. In ephemeral mode a
 per-build keypair is generated; `build_provenance.key_kind.txt` records
 `ephemeral` so production verifiers can refuse the artefact via
 `--require-longlived`.

#### Bootstrap

```bash
$ tee-crafter audit-gen-signing-key
  Private key (0600) : ~/.tee-crafter/provenance-signing-key.pem
  Public key         : ./provenance-signing-key.pub.pem
  SHA-256 fingerprint: 4d2f...a1c8

# Commit the fingerprint to your audit policy, then either rely on the
# default file path (above) or pipe the private key into your CI's
# secret manager and expose it as TEE_CRAFTER_PROVENANCE_SIGNING_KEY.
```

#### Verification

Local (dev) — chain + signature only:

```bash
tee-crafter verify-provenance --file <build_dir>/provenance/build_provenance.json
```

Production — pinned fingerprint, refuse ephemeral signatures:

```bash
   tee-crafter verify-provenance \
  --file <build_dir>/provenance/build_provenance.json \
  --pinned-pubkey-sha256 4d2f...a1c8 \
  --require-longlived
```

Exit codes (all six, from `cli/commands/verify_provenance.py`):

| Code | Meaning |
|------|---------|
| `0` | Everything checked passed |
| `1` | Hash chain tampered |
| `2` | Ed25519 signature invalid / fingerprint mismatch / key kind disallowed |
| `3` | Mutually-exclusive flags (`--skip-signature` with `--pinned-pubkey-sha256` or `--require-longlived`) |
| `4` | `--required-checks` gate failed — a required row is missing or non-passing, or no `audit_evidence.json` was found |
| `5` | Audit-ledger Ed25519 signature failed to verify |

Codes `4` and `5` are the ones CI gates care about; see
[cli_reference.md](cli_reference.md) for the same table.

---

## 9. Supply Chain Controls

- **Pinned tool versions** — `snpguest` is built from a pinned Git tag
 (v0.7.0) with commit-hash verification on Azure.
- **Offline dependency installation** — Python wheels are downloaded on the
 deployer machine, uploaded via S3/GCS/SCP, and installed with
 `pip install --no-index`. The CVM/Nitro host never runs `pip install`
 from the internet (when using baked images).
- **Minimal base images** — Nitro container builds use the user's image
 as-is with a thin overlay. CVM scripts install only required system
 packages.
- **Boto3 trimming** (Nitro) — only the `kms`, `sts`, `s3`, and
 `s3control` service modules are kept; all other botocore data is
 pruned to reduce attack surface (see `templates/common/Dockerfile.container.template`).
- **vsock-proxy allowlist** (Nitro) — the vsock proxy only forwards to the
 KMS endpoint for the deployment region; all other destinations are blocked.
- **Terraform version constraints** — all 10 platform templates declare a
 `required_version` and version constraints on every provider (e.g.
 `required_version = "~> 1.6"`, `hashicorp/aws ~> 6.0`). CI runs
 `terraform validate` against every template on each push.

 **The constraints alone are a floor, not a pin.** `~> 1.6` and `~> 6.0` are
 *ranges*: provider patch and minor versions still float, so two deploys a
 month apart can resolve different provider builds from the same template.
 What actually pins them is a committed `.terraform.lock.hcl`, and each of the
 10 platform templates now ships one. `stage_terraform` copies the lockfile
 next to the generated `main.tf`, so `terraform init` in a build directory
 resolves the recorded provider versions and hashes rather than re-resolving
 the range.

 **Two limits to know about.** The lockfiles record per-platform `h1:` hashes
 for `linux_amd64`, `darwin_arm64` and `linux_arm64` only. On any other host
 `terraform init` does **not** fail — measured on terraform 1.x, it *rewrites*
 the staged lockfile to add the hash it needs and prints "Terraform has made
 some changes to the provider dependency selections recorded in the.terraform.lock.hcl file", exiting 0; under `-lockfile=readonly` it prints
 "Warning: Provider lock file not updated" and still exits 0. An earlier
 version of this document claimed it failed closed, which was wrong.

 The version pin is not at risk either way — that comes from `version =` — and
 neither is authentication, which rides on the `zh:` hashes taken from the
 registry's signed `SHA256SUMS` and covering all platforms at once. (Remove
 those and `init` genuinely does fail closed: `Error: Invalid provider hash
 set`, exit 1.) What an uncovered host costs is that the lockfile terraform ran
 against no longer matches the one the repo ships. The fix is to regenerate:

 1. Add your host to the `PLATFORMS` tuple in
 `.github/scripts/generate_provider_locks.py` (currently
 `("linux_amd64", "darwin_arm64", "linux_arm64")`). Keep the existing
 entries — dropping one removes its hashes and reintroduces the silent
 rewrite for everyone on that host.
 2. Run the full generation:

 ```bash
 python3.github/scripts/generate_provider_locks.py
 ```

 This downloads every provider for every listed platform (multiple GB), so
 it is a deliberate, occasional step rather than something CI does.

 The cheap check is:

 ```bash
 python3.github/scripts/generate_provider_locks.py --check
 ```

 which confirms a lockfile exists for every template and names the providers
 each one pins, without touching the network. That is what CI runs on every
 push, so a template that gains a provider without a lockfile refresh fails
 the build instead of silently floating.

 Regenerating deliberately *raises* the pinned versions to the newest builds
 satisfying each constraint. Review the resulting diff — a lockfile refresh is
 a dependency bump, and this is the only place in the repo where that bump is
 reviewable.

---

## 10. Secrets Management

- **Ephemeral TLS keys** — ECDH key pairs are generated inside the TEE at
 boot and never written to persistent storage.
- **No hardcoded secrets** — credentials flow through IAM roles (AWS),
 managed identities (Azure), or service accounts (GCP).
- **KMS integration** (Nitro) — AWS KMS policies restrict `Decrypt` to
 callers presenting a valid attestation document with expected PCR values.
- **Host proxy TLS** (Nitro) — the EC2 host proxy uses a locally-generated
 self-signed certificate. This channel only carries traffic between the
 client and the host; the actual attestation happens end-to-end via the
 enclave's RA-TLS certificate.
- **NVIDIA NRAS / deploy env** (GPU CC) — `tee-crafter deploy` requires a
 **non-empty** `NVIDIA_NRAS_API_KEY` locally; setup writes it to a `chmod 600`
 file on the VM (`/opt/tee-crafter-gpu-cc/.env`), loaded via systemd
 `EnvironmentFile`. Never passed via CLI flags or shell history. On the VM,
 GPU CC app templates **warn** if the variable is unset but still perform
 NRAS remote attest (v4 endpoint); **`sys.exit(1)`** is used when GPU attestation
 **verification** fails, not when the variable is absent alone.

---

## 11. Security Control Matrix

Summary of which controls apply to each platform family. The only input is the
user's container; the columns distinguish the CVM/SGX packaging (Docker on the
TEE host, fronted by the attested proxy for persistent) from Nitro (the
container is merged into the measured EIF):

| Control | Container (CVM/SGX) | Container (Nitro) |
|---------|---------------------|-------------------|
| Hardware TEE isolation | Yes | Yes |
| RA-TLS attestation | Yes (proxy / batch deploy-time) | Yes (EIF) |
| Measurement binding | Proxy code + container digest | Full merged image |
| Per-deployment VPC/VNet | Yes | Yes |
| Network flow logging | Yes | Yes |
| Zero-ingress network | Yes | Yes |
| Systemd sandboxing | Yes (proxy + Docker) | Yes (host proxy) |
| Docker `--cap-drop ALL` | Yes | N/A (EIF is boundary) |
| Docker `--read-only` | Persistent only¹ | N/A |
| Docker `--pids-limit` | Yes | N/A |
| Custom seccomp profile | Yes | N/A |
| AppArmor MAC profile | Yes | N/A |
| Error sanitization | Yes | Yes |
| JSON-only I/O | Yes | Yes |
| Ed25519 provenance signing | Yes | Yes |
| Hash-chain provenance | Yes | Yes |
| Offline dep install | Yes | Yes |
| Ephemeral TLS keys | Yes | Yes |
| `tee_enclave` user | Yes | Yes |
| Sysctl hardening | Yes | Yes |

¹ `--read-only` applies to `--persistent` services. `--batch` runs the user
image as-is (writable rootfs) so it can emit its result set, which is then
captured into a signed, encrypted bundle; all other hardening flags apply to
both modes. `--network host` is a documented residual in both modes (see §6a).

### Platform Coverage for Container Flow

| Platform | Docker Engine | Seccomp | AppArmor | Container Service |
|----------|-------------|---------|----------|-------------------|
| `nitro-aws` | N/A (EIF) | N/A | N/A | N/A (merged image) |
| `snp-aws` | Yes | Yes | Yes | `tee-crafter-container.service` |
| `snp-azure` | Yes | Yes | Yes | `tee-crafter-container.service` |
| `snp-gcp` | Yes | Yes | Yes | `tee-crafter-container.service` |
| `tdx-azure` | Yes | Yes | Yes | `tee-crafter-container.service` |
| `tdx-gcp` | Yes | Yes | Yes | `tee-crafter-container.service` |
| `sgx-azure` | Yes | Yes | Yes | `tee-crafter-container.service` |
| `gpu-cc-gcp` | Yes | Yes | Yes | `tee-crafter-container.service` |
| `gpu-cc-azure` | Yes | Yes | Yes | `tee-crafter-container.service` |
| `gpu-cc-aws` | Yes | Yes | Yes | `tee-crafter-container.service` |

---

## 12. Full Implementation Matrix (2 Run Modes × 10 Platforms)

Every cell represents a fully implemented, end-to-end deployment path:
CLI command, pipeline artifacts, infrastructure provisioning, workload
deployment, attestation verification, and signed provenance.

### Run mode definitions

| Mode | CLI flag | Description |
|------|----------|-------------|
| **Persistent** | `--persistent` | Attested ingress proxy + user container on `127.0.0.1` |
| **Batch** | `--batch` | Container runs to completion; `output.tar.gz` captured |

### Implementation status

| Platform | `--batch` | `--persistent` |
|----------|-----------|----------------|
| `nitro-aws` | ✅ | ✅ |
| `sgx-azure` | ✅ (GSC) | ❌ (v1) |
| `tdx-azure` / `tdx-gcp` | ✅ | ✅ |
| `snp-aws` / `snp-azure` / `snp-gcp` | ✅ | ✅ |
| `gpu-cc-gcp` / `gpu-cc-azure` / `gpu-cc-aws` | ✅ | ✅ |

### Security controls per combination

| Control | Persistent × 9 VM-class | Batch × 10 | Notes |
|---------|-------------------------|------------|-------|
| Hardware TEE isolation | All 9 | All 10 | |
| RA-TLS / attested channel | All 9 (proxy) | N/A | Batch uses deploy-time attestation only |
| ECIES E2E encryption | All 9 | N/A | |
| Per-deployment VPC/VNet | All 9 | All 10 | |
| Docker `--cap-drop ALL` | All 9 | All 10 | |
| Custom seccomp + AppArmor | All 9 | All 10 | |
| Ed25519 provenance signing | All 9 | All 10 | |
| Hash-chain audit trail | All 9 | All 10 | |
| GPU CC attestation (NRAS) | GPU CC × 3 | GPU CC × 3 | |
| GSC graminize (SGX batch) | N/A | `sgx-azure` only | |

### Per-Cloud Security Summary

#### AWS (Nitro + SNP + GPU CC)

| Control | Nitro | SNP-AWS | GPU-CC-AWS |
|---------|-------|---------|------------|
| TEE hardware | Nitro Security Module | AMD EPYC SEV-SNP | **No CPU TEE** — NVIDIA GPU CC only |
| UEFI Secure Boot | **On by default** — `bake-ami` enrolls `amazon-linux-sb-keys` PK/KEK/db into AMI `UefiData`; Terraform precondition gates the launch (see §15.1A) | **On by default** — `bake-ami` enrolls a PK/KEK/db with MS UEFI CA 2011 into AMI `UefiData`; Terraform precondition gates the launch (see §15.1A) | **Off** — NVIDIA proprietary DKMS driver is not signed by any UEFI vendor key (see [gpu_flow.md](gpu_flow.md#secure-boot-on-gpu-cc-azure-and-gpu-cc-gcp)) |
| CPU attestation | PCR-bound KMS + COSE_Sign1 | SNP report + VLEK chain to the pinned AMD ARK | **Measured boot.** NitroTPM attestation document (COSE_Sign1, hypervisor-signed) chain-validated to the pinned `certs/nitro-root.pem` — the same root a NitroTPM document actually uses, Measured. PCR4/PCR7 compared against bake-time values, `user_data` bound to the session ECDH key. Client exits 1 if no document is presented, unless `TEE_CRAFTER_ALLOW_UNVERIFIED_AWS_CPU_ATTESTATION=1` |
| GPU attestation | N/A | N/A | NVIDIA NRAS EAT JWT |
| PCIe encryption | N/A | N/A | **No** |
| Security model | CPU TEE | CPU TEE | **GPU TEE + CPU measured boot** (`gpu-attested-cpu-measured-boot`). Not a CPU TEE: host RAM is not encrypted, so measured boot proves what booted, not that it stays private |
| Network isolation | Per-deployment VPC with private subnet | Per-deployment VPC with private subnet | Per-deployment VPC with private subnet |
| Flow logging | VPC Flow Logs to CloudWatch (60s, ALL traffic) | VPC Flow Logs to CloudWatch (60s, ALL traffic) | VPC Flow Logs to CloudWatch (60s, ALL traffic) |
| Network access | SSM-only (no SSH, no public IP, no bastion) | SSM-only (VPC endpoints for S3/KMS/SSM) | SSM-only (VPC endpoints for S3/SSM) |
| Instance connectivity | vsock (CID 16, AF_VSOCK only) | TCP on host | TCP on host |
| KMS integration | Condition keys restrict Decrypt to matching PCRs | N/A (ECIES only) | Dedicated KMS key for S3 |
| VPC endpoints | S3, SSM, SSM Messages, KMS | S3, SSM, SSM Messages | S3, SSM, SSM Messages, EC2 Messages |

#### Azure (SGX + TDX + SNP + GPU CC)

| Control | SGX | TDX | SNP-Azure | GPU-CC-Azure |
|---------|-----|-----|-----------|--------------|
| TEE hardware | SGX EPC (ring-3) | TDX Trust Domain (VM) | AMD SEV-SNP (VM) | SEV-SNP + NVIDIA CC |
| UEFI Secure Boot | On (Terraform) | On | On | **Off** (NVIDIA DKMS driver; see [gpu_flow.md](gpu_flow.md#secure-boot-on-gpu-cc-azure-and-gpu-cc-gcp)) |
| Attestation | DCAP quote (MRENCLAVE/MRSIGNER) | TDX DCAP quote (MRTD) | SNP report (VCEK via IMDS) | SNP report + NRAS JWT |
| GPU attestation | N/A | N/A | N/A | NVIDIA NRAS EAT JWT |
| PCIe encryption | N/A | N/A | N/A | Yes (SEV-SNP) |
| Network isolation | Per-deployment VNet | Per-deployment VNet | Per-deployment VNet | Per-deployment VNet |
| Flow logging | VNet flow logs + Traffic Analytics (10min, 30d) | Same | Same | Same |
| Network access | Azure Bastion tunnel only | Azure Bastion tunnel only | Azure Bastion tunnel only | Azure Bastion tunnel only |
| VM family | DCsv3/DCdsv3 | DCesv6/ECesv6 | DCasv5/ECasv5 | NCC H100 v5 |
| NSG policy | Inbound: Bastion→SSH only. Outbound: DenyAll catchall | Same | Same | Same + NRAS HTTPS |
| Disk encryption | Encrypted OS disk | `DiskWithVMGuestState` | Encrypted OS disk | `VMGuestStateOnly` (GPU-CC-Azure) |

#### GCP (TDX + SNP + GPU CC)

| Control | TDX-GCP | SNP-GCP | GPU-CC-GCP |
|---------|---------|---------|------------|
| TEE hardware | Intel TDX (Sapphire Rapids) | AMD SEV-SNP (EPYC Milan) | Intel TDX + NVIDIA CC (H100) |
| UEFI Secure Boot (shielded VM) | On | On | **Off** (NVIDIA DKMS driver; [gpu_flow.md](gpu_flow.md#secure-boot-on-gpu-cc-azure-and-gpu-cc-gcp)) |
| Attestation | TDX DCAP quote (configfs TSM) | SNP report (VCEK via metadata) | Dual: TDX quote + NVIDIA NRAS |
| GPU attestation | N/A | N/A | NVIDIA NRAS EAT JWT (CC mode + driver + firmware) |
| PCIe encryption | N/A | N/A | Encrypted (CPU-TEE → GPU-TEE) |
| Network isolation | Per-deployment VPC + subnet flow logs | Per-deployment VPC + subnet flow logs | Per-deployment VPC + subnet flow logs |
| Network access | IAP-tunneled SSH only | IAP-tunneled SSH only | IAP-tunneled SSH only |
| Machine type | C3 (e.g. c3-standard-4) | N2D (e.g. n2d-standard-2) | A3 (e.g. a3-highgpu-1g) |
| Firewall | `deny_all_ingress` at priority 65534 + IAP allow | Same | Same + NRAS HTTPS egress |
| External IP | None assigned | None assigned | None assigned |

#### AWS (GPU CC — Partial-Confidential)

| Control | GPU-CC-AWS |
|---------|------------|
| TEE hardware | NitroTPM (instance attestation) + NVIDIA CC-mode GPU |
| CPU-TEE | **None** — no hardware CPU-TEE; PCIe link is NOT encrypted |
| GPU attestation | NVIDIA NRAS EAT JWT |
| Network isolation | Per-deployment VPC with VPC flow logs |
| Network access | SSM-only (VPC endpoints for S3/SSM) |
| Security model | **Partial-confidential** — GPU memory is encrypted but CPU-GPU data traverses unencrypted bus |

#### Azure (GPU CC)

| Control | GPU-CC-Azure |
|---------|--------------|
| TEE hardware | AMD SEV-SNP VM + NVIDIA CC-mode GPU (H100) |
| UEFI Secure Boot | **Off** on deployed VM (driver lockdown tradeoff; see gpu_flow.md) |
| Attestation | Dual: SNP report + NVIDIA NRAS EAT JWT |
| PCIe encryption | Encrypted (CPU-TEE → GPU-TEE) |
| Network isolation | Per-deployment VNet with VNet flow logs + Traffic Analytics |
| Network access | Azure Bastion tunnel only |
| VM family | NCC H100 v5 |
| NSG policy | Inbound: Bastion→SSH only. Outbound: DenyAll + NRAS HTTPS |

---

## 13. Security Audit Hardening Controls

The controls in this section form a comprehensive security baseline
covering every TEE type, every cloud, and every deploy flow. Each item
is tagged with a finding ID so that operators, auditors, and downstream
code can cross-reference exactly what is enforced at build time, at
deploy time, and at attestation verification time.

### 13.1 Container isolation (SEC-1 / SEC-2)

User workloads run inside Docker containers with defence-in-depth isolation
rather than in-process sandboxing:

- **`--cap-drop ALL`** — no Linux capabilities in the user container.
- **Custom seccomp profile** — blocks dangerous syscalls at the container boundary.
- **AppArmor MAC** — separate profiles for persistent vs batch containers.
- **`--read-only`** root filesystem with tmpfs for writable paths — **persistent
 mode only** (`container.service.template`, line 32). Batch runs the user image
 writable on purpose, because output capture works by `docker diff`-ing the
 container's own layer after it exits.
- **`--pids-limit 512`** — bounds fork bombs.

These apply on the nine platforms that run Docker inside the TEE VM. `nitro-aws`
has no Docker daemon on the enclave side and installs none of these profiles;
see §6b.

The attested ingress proxy (persistent mode) carries an additional in-process
seccomp fence (`tee_crafter_handler_sandbox.py`) for the platform-owned
attestation surface. When systemd already applies `SystemCallFilter=`, the
in-app filter is skipped to avoid nested-seccomp `SIGSYS` termination.

### 13.2 Audit log hardening (AUD-1 / AUD-2 / AUD-3)

The in-TEE audit logger (`tee_crafter_audit_logger.py`) provides
tamper-evident operation:

| Control | Mechanism |
|---------|-----------|
| AUD-1 | `/var/log/tee_crafter` and each `.jsonl` file are created with mode `0o700` / `0o600`, owned by the `tee_enclave` user. |
| AUD-2 | Every `log_request` and `log_response` call performs `f.flush` + `os.fsync` so an enclave crash cannot lose the last N entries. |
| AUD-3 | Every entry is HMAC-SHA-256 chained with `_CHAIN_KEY` over the prior entry's hash + payload. The log begins with a `_genesis` record carrying `_CHAIN_KEY_COMMITMENT = SHA-256(CHAIN_KEY)`; `verify_chain` replays the HMAC and fails if any line was inserted, deleted, or mutated. |

`verify_chain` is exposed to operators and can be run against logs
collected from the TEE host (via SSM/Bastion/IAP) to prove the log
integrity before rendering compliance reports.

### 13.3 Authorization / header redaction (LOG-1)

The Nitro host proxy (`host_proxy.template.py`) installs a logging
filter (`_RedactAuthFilter`) that strips `Authorization`, `Cookie`,
`X-Api-Key` and similar headers from any log line before it is emitted.
Request handlers only log the **count** of fields and the **keys** of
the payload, never the values. Uvicorn access logs are disabled
entirely so that bearer tokens embedded in URLs cannot leak via the
journal.

### 13.4 TLS SPKI belt-and-braces (F-14)

The NRAS nonce-binding X.509 extension carries
`tls_spki_sha256 = SHA-256(server TLS SubjectPublicKeyInfo)` alongside
the ECDH-nonce hash. Clients:

1. Extract the claimed `tls_spki_sha256` from the extension.
2. Recompute the **actual** SPKI hash from the peer certificate the
 TLS handshake negotiated.
3. Fail-closed if the two do not match.

This prevents an attacker that steals only the NRAS token from
replaying it against a certificate they control. The field is
**mandatory**; servers whose extensions are missing `tls_spki_sha256`
are rejected with a `Server template is out of date` error.

### 13.5 vTPM measured-boot binding (F-8 — GCP GPU CC)

The GCP GPU CC server reads SHA-256 PCRs 0–7 from `/dev/tpm0` via
`tpm2_pcrread` at boot and embeds the JSON bundle in a new X.509
extension (`1.3.6.1.4.1.59386.2.2`) inside the RA-TLS certificate.
The client then:

- Extracts the PCR bundle from the cert.
- Compares it against `EXPECTED_VTPM_PCRS` (build-time pin) or
 `TEE_CRAFTER_EXPECTED_VTPM_PCRS` (runtime pin, format
 `idx:hex,idx:hex,...`).
- Self-pins on first contact when no expected set is supplied
 (permissive mode logs the observed PCRs so an operator can promote
 them to a pin for subsequent runs).

A missing/malformed extension is fatal. `tpm2_pcrread` failures on the
server are fatal — there is no "soft" path that lets a misconfigured
vTPM slip through.

### 13.6 TDX attestation hardening (TDX-1 / TDX-2 / TDX-3 / TDX-5)

- **TDX-1**: all four Intel DCAP clients (`sgx-azure`, `tdx-azure`,
 `tdx-gcp`, `gpu-cc-gcp`) evaluate Intel TCB collateral and refuse any quote
 whose QE identity or platform `tcbStatus` is not accepted by policy. Outdated
 or revoked platforms and QEs are rejected even when the DCAP signature chain
 verifies.
 Scope note: on `tdx-azure` this applies to the `dcap` evidence format only.
 Built for `azure-guest` — which is what an Azure paravisor CVM requires — no
 DCAP quote and no QE report ever reach the client, so the check has nothing to
 run against and MAA performs the platform-TCB judgement instead (§13.8a). A
 quote does exist in that flow; the host brokers it via IMDS and MAA consumes
 it, which is precisely why we cannot evaluate it ourselves.
- **TDX-2 / MAA**: The **SNP (Azure)** client
 (`snp/azure/client.template.py`) verifies optional Microsoft Azure
 Attestation JWTs with issuer / JWKS hostname pinning (suffixes such as
 `attest.azure.net`), so a malicious MAA endpoint cannot steer
 verification.

 **TDX (Azure) now depends on MAA rather than merely permitting it.** The
 *guest* on an Azure paravisor CVM cannot produce an Intel DCAP quote — no
 Quoting Enclave is reachable, and the vTPM hands it a raw `TDREPORT` that
 nothing outside the TDX module and the Quoting Enclave can verify. Azure's
 host brokers a real quote via IMDS `/acc/tdquote`, but it goes to MAA and not
 to us — so `tdx-azure` builds with
 `TEE_CRAFTER_TDX_EVIDENCE_FORMAT=azure-guest`, and MAA's
 `/attest/AzureGuest` verdict *is* the attestation. Two consequences
 worth stating rather than implying: the trust root for that platform is
 Microsoft, not Intel; and the session binding is MAA's signature over a
 guest-supplied nonce rather than the hardware's signature over
 `report_data`, because `report_data` there belongs to the paravisor. The
 MAA endpoint is baked into the measured app source, not read from the
 unit environment, so a compromised host cannot redirect attestation to
 a service it controls. See [tdx_flow.md](tdx_flow.md) item 9.
 **The evidence needs the TCG event log, and the workload is unprivileged.**
 `AttestationClient` builds the `/attest/AzureGuest` request from three inputs:
 the vTPM quote, the HCL hardware report, and the TCG event log at
 `/sys/kernel/security/tpm0/binary_bios_measurements`. The kernel exports that
 log `root`-readable only, and the workload runs as the unprivileged
 `tee_enclave` user. It is not a hard failure — the client sends the request
 without the log and MAA rejects it with `MissingKey: "TcgLogs is empty in
 attestation request."`, which reads like an API-version problem and is not one.
 `tdx-azure.service` therefore grants read on that one file to the
 `tee_enclave` group from its privileged (`+`-prefixed) `ExecStartPre`, the
 same mechanism it already uses for the configfs-TSM report directory and the
 TDX/TPM devices.

 `AmbientCapabilities=CAP_DAC_READ_SEARCH` would also work and is deliberately
 not used: it would let the workload read every file on the system, where the
 group grant opens one append-only kernel log. The unit keeps an empty
 `CapabilityBoundingSet` and no ambient capabilities. Only `tdx-azure` needs
 this — it is the only platform whose app invokes `AttestationClient`.
- **TDX-3**: Clients enforce TDX module version `>= 1.5.x`. Module
 version 1.0–1.4 quotes (which lack CVE mitigations for attacker-
 controlled RTMR replay) are rejected.
- **TDX-5**: GCP TDX Terraform pins `min_cpu_platform =
 "Intel Sapphire Rapids"` (default) or `Intel Emerald Rapids`;
 anything older is rejected by a Terraform `validation` block so an
 operator cannot accidentally schedule on a pre-TDX host.

### 13.7 SEV-SNP hardening (SNP-2 / SNP-3)

- **SNP-2**: Each SNP client template embeds **both** AMD Milan and
 Genoa root CA chains. At runtime the client parses the VCEK leaf and
 attempts both chains; if neither validates the handshake aborts.
 This makes the deploy artifacts portable across CPU generations and
 removes a manual "edit the chain" footgun.
- **SNP-3**: defends against a "valid SNP report, attacker-chosen TPM AK" splice
 — an attacker who captures a genuine SNP report for a vetted measurement,
 generates their own attestation key, and signs a quote with it. The quote is
 internally consistent, so nothing but an AK binding distinguishes it.

 There are two binding mechanisms, because which one is possible depends on
 whether the guest controls REPORT_DATA:

 - **`/dev/sev-guest` platforms** (`snp-aws`, `snp-gcp`): the guest chooses
 REPORT_DATA. It generates its own vTPM Attestation Key **before** signing,
 embeds `SHA-256(AK_pub)` in REPORT_DATA alongside the ECDH key hash, and
 quotes with that same AK. The client sees
 `binding_mode = report_data_strong`.
 - **Azure SEV-SNP** (`snp-azure`, `gpu-cc-azure`): there is no
 `/dev/sev-guest` — a live `Standard_DC2as_v5` exposes only `/dev/tpm0` and
 `/dev/tpmrm0`. The Hyper-V HCL mints the report and fixes REPORT_DATA to
 `sha256(runtime_data)`, so no guest-chosen value can appear in it and
 `report_data_strong` is unreachable. A guest-generated AK is therefore
 unattestable here, and the server does not use one: it quotes with **the
 HCL's own attestation key**, published as `keys[kid == "HCLAkPub"]` inside
 that runtime-data JSON. The chain is

 ```
 VCEK → SNP report → REPORT_DATA = sha256(runtime_data)
 → runtime_data[HCLAkPub] → the AK that signs the quote
 → quote nonce commits to the ECDH public key
 ```

 Since AMD signs REPORT_DATA, AMD transitively vouches for the AK. The client
 checks both hops — the digest, and that the attested modulus is the modulus
 of the presented AK — and reports
 `binding_mode = hcl_runtime_data_strong`.

 The server locates that key by comparing the modulus at each persistent
 vTPM handle against `HCLAkPub`, rather than trusting a fixed handle. If no
 handle matches, it falls back to a generated AK, which the verifier's strict
 gate then refuses — so an unexpected TPM layout degrades to a clear refusal
 rather than a quote signed by a key nothing vouches for.

 Clients fail closed (`TEE_CRAFTER_STRICT_SNP_AK_BINDING=1`, default) unless
 one of those two modes holds. A TPM quote **alone** does not satisfy the gate,
 and deliberately so: an attacker's own AK can sign a quote committing to its
 own key hash, which is exactly the splice this control exists to stop.

 Note what the Azure mechanism does *not* give you. It binds the AK, and
 therefore the channel key, to AMD-signed evidence — but REPORT_DATA is still
 not guest-influenceable, so there is no per-connection freshness value under
 the hardware signature. The client reports RA-TLS channel binding as
 `NOT ESTABLISHED` on that path and says why. A SKU exposing `/dev/sev-guest`
 gets both.

### 13.8 SGX hardening — unpinned-measurement gate

- **Unpinned MRENCLAVE/MRSIGNER is fatal.** When the build host had no
 Gramine and the client was rendered with `unknown` measurements, it
 exits 1 instead of trusting the first enclave that answers. The
 opt-out `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1` prints a
 full-width warning banner and accepts trust-on-first-use — dev only.
 (`templates/sgx/client.template.py`, lines 360–383.)
- **Trust anchor.** The PCK chain is verified to the pinned
 `certs/intel-sgx-dcap-root.pem` (`CN=Intel SGX Root CA`, self-signed,
 ECDSA P-256), with a subject-CN check on the anchor itself.

**No ISV_SVN floor, deliberately.** An SGX client could in principle refuse an
enclave below a minimum `ISV_SVN`, and does not. The Gramine manifest sets no
`sgx.isvsvn`, so Gramine signs every enclave at 0, and any floor above 0 would
reject TEE-Crafter's own enclaves. A floor is therefore not available on this
platform as built, and the identity that *is* enforced is MRENCLAVE — a stronger
statement than a version number, since it pins the exact enclave rather than a
claimed revision.

**What MRENCLAVE covers on a batch run, and what it does not.** `sgx-azure` is
batch-only, and a batch job needs two host-visible paths: `/input`, a read-only
bind mount carrying that run's data, and `/output`, which the capture step reads
back. Both are declared in the enclave manifest as `sgx.allowed_files`, so:

- **Measured, and therefore covered by MRENCLAVE:** every file of the
 application and its runtime, plus the manifest itself — including the
 `allowed_files` declaration. The allowance is part of the signed identity, so
 a verifier pinning MRENCLAVE is pinning the exact set of unmeasured paths too.
- **Not measured, and not verified by the enclave:** the contents of `/input`
 and `/output`. Gramine prints an `insecure configurations` banner naming
 `sgx.allowed_files` on every run, and the deploy repeats it rather than
 leaving it in the container log.

Input integrity therefore rests on the input digest recorded in the signed audit
trail, not on the enclave, and `/output` is written to host-visible storage in
the clear — inherent to capturing output with `docker diff`. Treating the input
as measured instead is possible (its hash is known at deploy time) but makes
MRENCLAVE change with every input, which would defeat comparing a pin across
runs. See [sgx_flow.md](sgx_flow.md).

### 13.8a Intel TCB collateral

All four Intel clients (`sgx`, `tdx/azure`, `tdx/gcp`, `gpu-cc-gcp`) evaluate
**platform** TCB status through `enforce_platform_tcb_status`, backed by
`templates/common/tee_crafter_tcb_eval.py` on the client side and
`core/attestation/tcb_collateral.py` on the build side. A platform Intel
classifies as `OutOfDate` or `Revoked` is refused under every policy setting.

One scope note: on `tdx-azure` built for `azure-guest` evidence, no DCAP quote
reaches the client, so there is nothing for this machinery to evaluate there —
`enforce_platform_tcb_status` is reached only from `_verify_dcap_attestation`.
On that path Microsoft Azure Attestation makes the platform-TCB judgement and
reports it as `attester_tcb_status`. The bundle is still fetched and staged.

**Quoting Enclave identity, on TDX.** The two TDX clients also check the
*Quoting Enclave's* identity — `TDX-1`, `_check_qe_identity_tcb_status`
(`templates/tdx/azure/client.template.py:593-690`, `tdx/gcp` equivalent) —
refusing a quote whose QE `tcbStatus` is `OutOfDate`. Two properties of this
check are worth being precise about, because both are easy to assume wrongly:
the QE identity document is **signature-verified against the pinned Intel root**,
not merely fetched over TLS (TLS alone would let whoever answers for
`api.trustedservices.intel.com` dictate the identity the client enforces); and
the check runs in the **verifier client on the operator's host**, not inside the
enclave.

The build fetches the full DCAP collateral set — TCBInfo
(SGX and TDX), QEIdentity (SGX and TDX), and the platform/processor PCK CRLs —
**verifies each document's ECDSA signature** against a chain anchored on the
pinned `certs/intel-sgx-dcap-root.pem`, and writes a single
`tcb_collateral.json` beside the generated client. The client re-verifies every
signature offline from that bundle, so the verify path still makes exactly one
outbound connection: to the TEE.

Verification is over the **raw response bytes**. Intel signs the `tcbInfo` /
`enclaveIdentity` body without whitespace, so a `json.loads` → `json.dumps`
round-trip breaks the signature. Compact re-serialization happens to work today
because Intel emits whitespace-free JSON and CPython preserves key order — which
is exactly why it is not relied on.

Enforced, in Intel's DCAP QVL order: document signature → bundle staleness (7
days by default; Intel's own `nextUpdate` is always enforced and the age
override cannot relax it) → FMSPC/PCEID applicability → platform `tcbStatus` →
QEIdentity ISVSVN/ISVPRODID and MISCSELECT/ATTRIBUTES masks → PCK CRL
revocation. `UpToDate` only by default; `OutOfDate` and `Revoked` are refused
under every policy.

Still not covered, stated plainly:

- **`tdxModule` / `tdxModuleIdentities`** (MRSIGNERSEAM, TDX module
 attributes/seamsvn) are not evaluated.
- ~~**Root-CA-level revocation.**~~ **Now covered.** The bundle also carries
 `sgx_root_ca_crl` (the Intel SGX Root CA CRL, fetched from
 `certificates.trustedservices.intel.com` — a second host, which air-gapped
 builds must mirror separately). It is verified against the pinned root
 *directly*: `verify_root_ca_crl` takes no chain parameter at all, so there is
 no argument through which an alternative issuer could be supplied. A revoked
 PCK CA is now a hard failure rather than a `NOT COVERED` line.
- **The FMSPC must be supplied at build time** (`TEE_CRAFTER_FMSPC`). It
 identifies the CPU model and exists only in a real quote's PCK leaf, so a build
 host cannot discover it. Without it the bundle carries no TCBInfo and the
 client refuses the quote, printing the FMSPC it just parsed so the fix is one
 rebuild.

#### How the collateral signature algorithm is known

Stated precisely, since a common assumption holds
P-256 / SHA-256 on the strength of five observed samples, which is not a
guarantee.

**Intel's published API documentation does not specify it.** The Get TCB Info
and Get Enclave Identity endpoint documentation shows the `signature` field only
as a hex example, with no statement of algorithm, curve, hash, or which bytes
are covered
([API documentation](https://api.portal.trustedservices.intel.com/content/documentation.html)).
So it cannot be cited from there.

**The signing certificate does specify it**, and that is what this code binds
to. Every collateral response carries its own issuer chain — `TCB-Info-Issuer-Chain`
for TCB information, `SGX-Enclave-Identity-Issuer-Chain` for QE identity, in
`<signing certificate><root certificate>` order. Inspecting the live chain on
```
CN=Intel SGX TCB Signing sig_alg=ecdsa-with-SHA256 key=EC secp256r1 (256-bit)
CN=Intel SGX Root CA sig_alg=ecdsa-with-SHA256 key=EC secp256r1 (256-bit)
```

The algorithm is therefore read off the certificate Intel serves alongside each
document, not inferred from how previous documents happened to look. Reproduce
it with the `TCB-Info-Issuer-Chain` header from any `/tcb` response.

**Anything else fails closed, in both halves, for the same stated reason.**
Both the builder (`core/attestation/tcb_collateral.py`) and the client
(`templates/common/tee_crafter_tcb_eval.py`) check
`isinstance(signer_pub.curve, ec.SECP256R1)` and refuse with the curve named.

Relying on the 64-byte signature length as a proxy would not be equivalent: a
P-384 signature is 96 bytes, and the fixed 32/32 `r`/`s` split would produce
values that are not `r` and `s`. That still fails — but with the wrong
explanation. The signature-mismatch error tells the operator the document was
"modified, or re-serialized", which would send them looking for a JSON
round-trip bug that does not exist. The client carried exactly that gap (it
checked only that the key was an elliptic-curve key) until the explicit curve
check was added alongside the builder's.

### 13.9 Nitro hardening (Nitro-1 / Nitro-4 / Nitro-7)

- **Nitro-1**: `main.template.tf` surfaces the regional KMS IP range
 (`data.aws_ip_ranges.kms_region`) as a defense-in-depth **hint** so
 operators that run tee-crafter in a shared VPC without KMS interface
 endpoints can further narrow vsock-proxy egress to the KMS prefix
 list. This is opt-in; the default VPC-endpoint path is unchanged.
- **Nitro-4**: The Nitro EIF builder defaults to
 `amazonlinux:2023` and **warns** if the builder image is not
 digest-pinned. Operators can set
 `TEE_CRAFTER_NITRO_BUILDER_BASE=amazonlinux@sha256:…` to enforce
 digest pinning and make the builder image byte-stable across runs.
- **Nitro-7**: `build_enclave` writes a canonical stable-sorted
 `pcrs.json` next to the EIF. Downstream tools (Terraform, KMS
 policies, CI verifiers) pin against this single authoritative
 artifact instead of having to re-parse `nitro-cli describe-eif`
 output.

### 13.10 GPU-CC hardening (GPU-10)

GCP TDX and GCP GPU CC app templates default to **strict TSM**: a
failure of the configfs-tsm path (`/sys/kernel/config/tsm/report`)
is fatal instead of silently falling back to the `/dev/tdx-guest`
ioctl. This removes the silent security degradation where a
misconfigured TSM would still produce a quote but via a path the
operator did not expect. The knob `TEE_CRAFTER_STRICT_TSM=0`
re-enables the best-effort ioctl fallback (ad-hoc work on stale
kernels only).

### 13.11 Supply chain (F-15 / SUP-1 / SUP-2)

- **F-15 / SUP-1**: Supply-chain pinning is the user's Dockerfile's
 responsibility — TEE-Crafter runs the image as-is. The
 Dockerfile-hardening checks (`DH-*`) flag an unpinned base image
 (`FROM …:latest` or no digest) and recommend `pip install
 --require-hashes` against a committed `requirements.lock`, but the
 CLI never rewrites the user's dependency set. The built image's
 layers are hashed into `image_digest.json` and fed to the
 attestation baseline.
- **SUP-2**: Every `setup_*.sh` that ingests a `curl | bash` script
 (rustup, Azure CLI, Docker, etc.) downloads to a temp file,
 computes SHA-256, and compares against `TEE_CRAFTER_RUSTUP_SHA256`
 (and the equivalent env vars for other tools). Mismatches are
 fatal; absent env pins produce a warning so CI can enforce them.

### 13.12 Deployer / SSM least privilege (RMT-2)

- `core/remote/ssm.py` asserts `AWS-RunShellScript` is the only SSM
 document `send_command` will ever invoke. This guards against a
 future refactor accidentally letting a caller pass arbitrary SSM
 document names.
- `nitro/main.template.tf` emits an `rmt2_deployer_iam_policy`
 Terraform output that scopes `ssm:SendCommand` to
 `AWS-RunShellScript` and `ssm:StartSession` to
 `AWS-StartPortForwardingSession`, both targeted at the deployed
 instance ARN. Operators attach this policy to the human or CI
 principal that runs `tee-crafter deploy`.

### 13.13 No default NAT egress (NET-1)

Every Terraform template defaults `allow_setup_egress = false`, the
`setup_egress_mode` output reads `locked-down`, and no `0.0.0.0/0` egress route
is created. The CLI **always** requires `--ami-id <baked-id>` (or a pinned image
env var) for `--deploy`; **there is no fallback to a public base AMI**, so a
deploy without a pinned image aborts rather than booting an unhardened image and
opening egress to install packages on first boot
(`cli/commands/deploy/deploy_helpers.py::_resolve_ami_id`). As a result, the
production deploy step **never provisions a NAT gateway / Cloud NAT / Cloud
Router by default**.

The one exception is an internal development hatch: setting
`TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI=1` skips the pin, flips
`TF_VAR_allow_setup_egress=true`, prints a warning, and records
`AMI pinning bypassed (internal dev only)` as a `warn` row in the build
provenance. It is not a supported production path.

A NAT is only stood up when a feature inside the deployment
explicitly declares the need for egress to public endpoints:

- **SIEM in `egress_mode=auto` or `egress_mode=public`** (Splunk
 HEC, Datadog, public Azure Monitor / CloudWatch endpoints). The
 CLI flips `TF_VAR_allow_setup_egress=true` to provision the NAT
 with a tightly scoped security group / NSG / firewall rule that
 only permits 443 (or the configured `egress.ports`) to the CIDRs
 in `egress.cidrs`. SIEM in `egress_mode=private` (AWS PrivateLink
 interface VPC endpoints) or `egress_mode=none` provisions no NAT.
- **The internal `tee-crafter internal bake-ami` pipeline**, which
 provisions a temporary NAT to install wheels and drivers,
 snapshots the image, and tears the NAT down before exit. The
 bake step is internal-only and is not part of the production
 `deploy` path.
- **An internal-only dev knob**
 (`TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI=1`) used by maintainers
 iterating on cloud-init without baking. The public CLI hard-fails
 without `--ami-id`; this env var only flips
 `TF_VAR_allow_setup_egress=true` for the internal dev workflow
 and emits a `post-bake reminder` to bake the image and re-deploy
 with `--ami-id`.

Attestation egress (NRAS, VPC-local endpoints, IMDS, MAA, PCS)
flows over private endpoints regardless and is never gated on a
NAT.

Opening the NAT path does **not** relax the VPC endpoint policies. This
is worth stating because the obvious shortcut is wrong. It is tempting to
detach the S3 gateway endpoint policy whenever `allow_setup_egress` is true, on
the reasoning that cloud-init pulls packages from S3-backed repo mirrors too
numerous to enumerate. But that policy is what pins the endpoint to *this
deployment's* instance role — on a gateway endpoint it governs **who** may use
the endpoint, not whether egress exists — so detaching it would let any
principal in the VPC reach the deployment's artifact bucket path through the
endpoint. It would also be near-invisible: the SIEM module sets
`allow_setup_egress=true` for its NAT path, so adding `--siem` to an otherwise
locked-down deploy would silently drop the control. The policy therefore stays
attached in both modes: on the setup path a
third statement widens `s3:GetObject` to any bucket (so unenumerated repo
mirrors still work) while the `aws:PrincipalArn` condition and the
write-scoping to the deployment bucket are unchanged. `terraform output
vpc_endpoint_policy_mode` reports which of the two forms is in force.

### 13.13a Workload egress allowlist — databases & 3rd-party APIs (EGR-005 / EGR-006)

In the container-orchestrated model the user's image owns its own
data: it may open a database connection, call a SaaS API, or pull
from object storage. The TEE seals *processing*; the **network egress
boundary is therefore the primary data-confidentiality control** — a
confidential workload that can open arbitrary outbound sockets can
exfiltrate plaintext regardless of how good the enclave is. Egress is
consequently **deny-by-default**, and any database / 3rd-party reach
must be declared explicitly:

```bash
# Default — opens nothing beyond VPC-local 443 (KMS / attestation endpoints):
tee-crafter deploy --source./app --persistent --deploy

# Private database inside (or peered into) the deployment VPC — no NAT:
tee-crafter deploy --source./app --persistent --deploy \
 --egress-mode vpc --egress-allow 10.0.5.0/24:5432

# Public managed DB endpoint / SaaS API — requires NAT, but the SG is
# still locked to the resolved CIDRs (0.0.0.0/0 is never opened):
tee-crafter deploy --source./app --persistent --deploy \
 --egress-mode nat \
 --egress-allow db.prod.example.com:5432 \
 --egress-allow api.stripe.com:443
```

| Mode | NAT gateway? | Who can the workload reach |
|------|--------------|----------------------------|
| `deny` (default) | no | Nothing except `443` **inside the VPC** (KMS/attestation VPC endpoints) |
| `vpc` | no | The declared `--egress-allow` CIDRs/ports, **provided they resolve inside the VPC** (private RDS / Cloud SQL / Postgres) |
| `nat` | yes | The declared `--egress-allow` destinations on the public internet; the security group is locked to exactly the resolved CIDRs + ports |

**Do I need NAT?** A TEE runs in a private subnet with no public IP.
A database *inside* the VPC (private RDS / Cloud SQL peered into the
deployment VPC) is reachable with `--egress-mode vpc` and **no NAT**.
A database or API on the *public internet* (a managed DB public
endpoint, a third-party API) needs `--egress-mode nat`: the NAT
gateway provides the route while the allowlist provides the boundary.
`0.0.0.0/0` egress is **never** opened in either mode.

Implementation: `--egress-allow host:port` hostnames are resolved to
`/32` CIDRs at deploy time and **merged into the same locked-down
egress allowlist** the SIEM exporter uses
(`TF_VAR_siem_egress_cidrs` / `TF_VAR_siem_egress_ports`), so a single
security-group ruleset covers both. NAT is provisioned by flipping
`TF_VAR_allow_setup_egress=true` — but because the allowlist is
non-empty, the `0.0.0.0/0` egress rule stays disabled and only the
declared CIDRs are reachable. The decision is written to
`workload_egress.json` (a SLSA-provenance subject, `workload-egress`)
and recorded as **EGR-005** (deny-by-default or explicitly
allowlisted) and **EGR-006** (no `0.0.0.0/0` in the allowlist).

> Note (v1): ports apply across the whole allowlist, so listing both a
> `5432` database and a `443` API opens both ports to both CIDRs.
> Use separate deployments if strict per-destination port isolation is
> required.

### 13.14 SIEM chain forgery resistance (SIEM-CHAIN-1 / SIEM-CHAIN-2)

`verify-siem-chain` recomputes every event digest, checks the
`prev_digest` linkage and per-boot key stability, and verifies each
Ed25519 signature. By itself, though, a signature only proves *internal
consistency*: it is checked against the `public_key_pem` embedded in the
event, so anyone able to inject records into the SIEM stream could present
a fully self-consistent chain signed by their **own** key.

- **SIEM-CHAIN-1 — signing-key pinning.** `--pinned-pubkey-sha256 <hex>`
 (repeatable) and `--pubkey-file <pem>` pin the TEE's per-boot signing
 key. When set, every event's embedded key must hash (SHA-256 of the DER
 `SubjectPublicKeyInfo`) to a pinned value, so a forged-but-self-consistent
 chain is rejected. When **no** key is pinned the command prints a loud
 warning and the success panel reports `VALID (self-asserted; key not
 pinned)`. **Production SOC monitors MUST pin the key.**
- **SIEM-CHAIN-2 — truncation / gap detection.** Consecutive events must
 increment `seq` by exactly 1 (a jump means events were silently dropped);
 `--expect-first-seq 0` asserts the export starts at genesis, defeating
 silent head-truncation that re-anchors the chain. `--allow-seq-gaps` is an
 audit-only escape hatch.

### 13.15 BYOK key release bound to a vetted measurement (BYOK-011)

The in-TEE `KeyReleaseOrchestrator` only compares the live attestation
measurement against `policy.allowed_measurement_sha256` when that allowlist
is **non-empty**. An empty allowlist therefore disables in-guest measurement
binding — release degrades to "any fresh attestation of any measurement".
Nitro is backstopped server-side (the customer KMS key policy enforces
`kms:RecipientAttestation:PCRn` conditions). `azure-skr` also has a server-side
condition, though a weaker guarantee: Key Vault refuses to release an exportable
key without a `release_policy` and evaluates that policy against the MAA token
before the key leaves the vault — but the policy is only *measurement*-bound if
it asserts `x-ms-isolation-tee.x-ms-sevsnpvm-launchmeasurement` (or the TDX
equivalent), which the deploy-time check cannot see. Every remaining platform
uses the `direct_bytes` CVM path with no server-side condition at all.

`record_byok_audit` now emits **BYOK-011** honestly: `pass` when the
allowlist is populated (or the platform is Nitro-Recipient backstopped),
**`warn`** otherwise, and a hard **`fail`** when
`TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT=1` so CI can refuse an unbound BYOK
deploy. **Production BYOK deployments must pin
`policy.allowed_measurement_sha256` in `--byok-config`.**

A populated allowlist is necessary but **not sufficient to bind your software**.
On a confidential VM the launch measurement covers initial guest memory —
firmware/OVMF, boot configuration, vCPU count — and not the contents of the baked
disk: two `snp-azure` bakes differing by `AttestationClient`, `AzureAttestSKR`
and an edited AppArmor profile produced the identical measurement 
(read live from the vTPM; see [measurements.md](measurements.md)). So
`allowed_measurement_sha256` proves "a genuine CVM on the firmware I vetted",
while the container image digest in the attestation's `report_data` is what proves
"running the code I vetted". A BYOK policy that pins only the measurement still
admits a *differently baked* image on the same firmware and vCPU tier.

### 13.16 Fail-closed data residency at deploy (RES-001)

Residency is enforced in the deploy path itself, not left to the standalone
`tee-crafter residency-check` an operator has to remember to run. `deploy` runs
the same `validate_deployment` engine **before any cloud resource is
created**: when `TEE_CRAFTER_RESIDENCY_POLICY` points at a
policy JSON, the chosen cloud/region is validated and the deploy **aborts**
on a violation (recording **RES-001**). It fails closed when the region is
unset or unknown (cannot prove jurisdiction). When the env var is unset the
gate is a no-op, preserving the default behaviour.

### 13.17 Summary table

| Finding | Layer | Where enforced | Fail-open safety net? |
|---------|-------|----------------|-----------------------|
| SIEM-CHAIN-1/2 | Verify (SOC) | `verify_siem_chain.py` | Warns when key not pinned; gaps fatal unless `--allow-seq-gaps` |
| BYOK-011 | Pipeline (deploy) | `byok_mode.record_byok_audit` | `warn`; `fail` under `TEE_CRAFTER_REQUIRE_BYOK_MEASUREMENT=1` |
| RES-001 | Pipeline (pre-apply) | `deploy_helpers.enforce_residency_gate` | No-op unless `TEE_CRAFTER_RESIDENCY_POLICY` set; then fail-closed |
| SEC-1 / SEC-2 | Bake-time (image) + runtime (probe) | `scripts/*/setup_*.sh` + `resources/systemd/container{,.batch}.service.template`; verified by `deployment/common/post_deploy_probes.py` | Bake fails closed if a profile won't load; the units refuse to start if either profile is missing |
| AUD-1..3 | Runtime (in-TEE) | `tee_crafter_audit_logger.py` | No — verify_chain fails closed |
| LOG-1 | Runtime (host) | `host_proxy.template.py` | N/A (redaction) |
| F-14 | Attestation (client) | `client.template.py` (GPU CC × 3) | No — fatal on mismatch |
| F-8 | Attestation (client) | `gpu_cc/gcp/client.template.py` | Self-pin on first contact (logged) |
| TDX-1/2/3/5 | Attestation (client + TF) | `tdx/*/client.template.py` + `tdx/gcp/main.template.tf` | No |
| SNP-2 | Attestation (client) | `snp/*/client.template.py` | Tries Milan then Genoa — fails if neither |
| SNP-3 | Attestation (server + client) | `snp/azure/{app,client}.template.py` and `gpu_cc/azure/{app,client}.template.py` — both Azure SEV-SNP platforms run the same paravisor and the same attack applies to both | `TEE_CRAFTER_STRICT_SNP_AK_BINDING=1` default |
| SGX unpinned-measurement gate | Attestation (client) | `sgx/client.template.py` | No — exits 1 unless `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1` |
| Nitro-1/4/7 | Build + TF | `nitro/main.template.tf` + `enclave/build.py` | Nitro-4 warns on unpinned base |
| GPU-10 | Runtime (server) | `gpu_cc/gcp/app.template.py`, `tdx/gcp/app.template.py` | `TEE_CRAFTER_STRICT_TSM=1` **default ON** (production); knob `=0` re-enables ioctl fallback |
| F-15 / SUP-1 | Build (Docker) | `Dockerfile*.template` + `core/compliance/evidence.py::_dependency_hash_pinning` | Not a warning: the evidence item is graded `STRONG` when the provenance shows `requirements.lock` / `--require-hashes`, and `INFORMATIONAL` otherwise |
| SUP-2 | Setup (shell) | `scripts/*/setup_*.sh` | Warn when SHA env var unset |
| RMT-2 | Deployer IAM + runtime | `ssm.py` assert + `nitro/main.template.tf` output | Assert is fatal |
| NET-1 | Deploy (CLI + TF) | `cli/commands/deploy/*.py` + every `main.template.tf` | CLI reminds operator; TF output surfaces state |

## 14. Production-Audit Verifier Controls

This section catalogues the production-readiness controls that close
the long tail of medium and low findings. Each control is **enforced in
code** and is preserved across the entire build / deploy / verify
pipeline.

### 14.1 SGX-Azure measured boot always-on (`templates/sgx/main.template.tf`)

A naïve template would disable UEFI Secure Boot and vTPM whenever a
custom (baked) image is used, which is the production path. That
would make measured-boot evidence unavailable on the very deploys that
need it. The runtime VM sets `secure_boot_enabled = true` and
`vtpm_enabled = true` unconditionally — SGX is a userspace platform and
all packages installed by `scripts/sgx_azure/setup_sgx.sh` come from
signed Intel / Microsoft / Gramine APT repos with `signed-by` GPG keys,
so kernel lockdown does not block the SGX stack.

### 14.2 Dual provenance verification (`cli/commands/verify_provenance.py`)

`tee-crafter verify-provenance --file <build_dir>/provenance/build_provenance.json`
verifies **both** the SHA-256 hash chain **and** the per-build Ed25519
signature (`provenance/build_provenance.sig` + `provenance/build_provenance.pub`).
Either check failing
exits non-zero. An audit-only `--skip-signature` flag is available for
unsigned artefacts (e.g. captured before a long-lived signing key was provisioned), with a
loud warning printed.

### 14.3 SUP-2 extended to the Azure CLI installer (`scripts/sgx_azure/setup_sgx.sh`)

`aka.ms/InstallAzureCLIDeb` is downloaded over `--proto '=https' --tlsv1.2`,
SHA-256-hashed, optionally compared against
`TEE_CRAFTER_AZ_CLI_INSTALLER_SHA256`, then executed. Joins the existing
SUP-2 pattern in `setup_snp_gcp.sh` (rustup installer).

### 14.4 Explicit Azure CVM `security_type` derivation

azurerm 4.x has no first-class `security_type` attribute on
`azurerm_linux_virtual_machine`; the security type is derived from the
combination of `os_disk.security_encryption_type`, `vtpm_enabled`, and
`secure_boot_enabled`. Each Azure CVM template
(`snp/azure`, `tdx/azure`, `gpu_cc/azure`) carries an explicit comment
block on its `os_disk` documenting this derivation so external reviewers
(OPA, Cloud Foundation, etc.) can audit the chosen mode without having to
re-derive it.

### 14.5 TDX-5 pinned at bake time (`baking/gcp.py`)

GCP TDX bakes pass `--min-cpu-platform "Intel Sapphire Rapids"` to
match the runtime Terraform's TDX-5 floor. Prevents a bake from silently
landing on a non-TDX host and producing an image whose drivers were never
exercised under TDX.

### 14.6 Fail-closed continuous attestation (`tee_crafter_attestation_monitor.py`)

The runtime monitor accepts a `TEE_ATTESTATION_DRIFT_KILL=N` env var.
When `N >= 1` and `N` consecutive measurement / GPU-CC samples report
drift or failure, the in-TEE process calls a configurable `halt_fn`
(default `os._exit(99)`) so the orchestrator detects the missing health
check and tears the VM down. The default is `0` (log-only), because a single
transient sample should not destroy a live service; production deploys set it to
`2` or `3`, which requires the drift to persist.

### 14.7 Real measurement capture in audit (`cli/deployment/common/attestation_report.py`)

A naïve deploy phase would record `attestation_verified=True` after the
client passed, with no platform-specific fields. A shared extractor
parses the verifier's output and records actual TCB / measurement values
(PCR0/4/7, MRTD, MRENCLAVE / MRSIGNER, ISVSVN, container digest, NRAS
EAT key-ID, SPKI SHA-256, …) into the provenance audit chain. Verifiers
that need to replay a quote no longer have to re-run the deploy.

* Forward-going clients emit a single
 `ATTESTATION_REPORT {<json>}` line on stdout (the Nitro client does so
 today; the other platforms fall through to a regex-based fallback that
 parses the existing `MRENCLAVE: …` / `Measurement: …` stderr labels).
* A correct regex in `gcp_phase_client.py` (rather than `\\s` matching
 literal `\s`) is fixed.
* `evidence._tcb_freshness` grades STRONG more often because real TCB
 fields show up in the chain.

#### Measurement baseline pinning vs trust-on-first-use (ATT-003)

The CPU-TEE verifier clients accept a baked-in `EXPECTED_MEASUREMENT` /
`EXPECTED_MRTD` / `EXPECTED_MRENCLAVE`. When that baseline is `unknown` (no
`measurements.json` was pinned into the image at build time) the client falls
back to **trust-on-first-use (TOFU)**: it self-pins the first measurement it
sees after verifying the report signature/cert-chain. This is convenient for
smoke tests but is **not acceptable for production**, because a self-pinned
value proves only internal consistency, not that the runtime measurement
matches a value the operator vetted.

`emit_att_verdicts` now surfaces this honestly. The deploy pipeline detects the
client's self-pin sentinel and:

* records **ATT-003** ("measurement matches build baseline") as **`warn`**
 (instead of silently `pass`) with a note explaining the TOFU fallback, and
* prints an operator warning on the console.

Setting **`TEE_CRAFTER_REQUIRE_PINNED_MEASUREMENT=1`** turns the unpinned case
into a hard **`fail`**, so a build without a baked `measurements.json` cannot
pass the `--required-checks auto` gate. **Production deployments must ship a
baked image whose `measurements.json` pins the platform measurement**
(MRTD / MRENCLAVE / PCR / SNP-measurement) and set this environment variable in
CI.

### 14.8 Container digest pinning evidence (`core/compliance/evidence.py`)

The `container_digest_pinning` evidence collector grades strictly: a
naïve match on any provenance containing the substring "digest" or
"sha256:" would fire STRONG even on unrelated SBOMs. Grading STRONG
requires either a literal `image@sha256:<64-hex>` pin or an explicit
`container_image_digest` audit field.

### 14.9 Strict NRAS egress by default (`templates/gpu_cc/*/main.template.tf`)

The Terraform variable `allow_nras_broad_internet` defaults to
**`false`** so that consumers of the modules (Cloud Foundation, OPA
gates, third-party automation) inherit a safe, locked-down baseline.

The CLI deploy phase still keeps the demo / smoke-test path working
out of the box: `cli/deployment/common/nras_egress.py` makes an
**explicit, audited choice** every run and writes a `Phase 4:
Deployment / NRAS egress policy` audit entry capturing the policy.
Three outcomes:

| Inputs | TF var set | Audit policy |
|--------|-----------|--------------|
| `TF_VAR_nras_egress_cidrs` set, or `TEE_CRAFTER_NRAS_CIDRS=a/32,b/32` | broad-internet=false, cidrs=explicit | `explicit_cidr_allowlist` |
| No CIDRs supplied (production default) | broad-internet=false, no NRAS rule | `strict_no_egress` (attestation will fail until CIDRs are supplied) |
| Knob `TEE_CRAFTER_NRAS_STRICT=0` and no CIDRs | broad-internet=true | `widened_to_internet_default` (loud warning) |

## 15. Platform Constraints (immutable and operational)

A handful of security controls cannot be enabled identically across
every TEE. Some are genuine **hardware / firmware constraints**; others
are **operational trade-offs** that future maintainers should be aware
of so they can opt into the stricter setting when their environment
supports it. Each constraint below explicitly identifies which category
it falls into.

### 15.1 UEFI Secure Boot defaults to OFF on `gpu-cc-azure` / `gpu-cc-gcp` (operational, configurable)

This is **not** an immutable hardware constraint. Secure Boot **can**
be enabled on GPU CC VMs if the operator's chosen driver version has a
Canonical-signed pre-built module for the running kernel. The default
is OFF for *reliability* reasons documented below; the TF variable
`enable_secure_boot` (`gpu_cc/azure` and `gpu_cc/gcp` modules) lets
operators flip it on once they have vetted their kernel + driver combo.

**What signed-module options actually exist for NVIDIA CC GPUs (Hopper / H100):**

| Path | Distribution | Signed-by | Driver versions available | Notes |
|------|--------------|-----------|---------------------------|-------|
| Canonical pre-built `linux-modules-nvidia-<VER>-<flavour>-<KREL>` | Ubuntu 22.04 / 24.04 | Canonical kernel signing key (shim-chained, trusted under Secure Boot) | 495/510/515/520/525/535/550/570 across most generic / azure / azure-fde / gcp flavours | Lags NVIDIA's latest by some weeks; coverage depends on the exact kernel ABI. |
| NVIDIA precompiled `kmod` RPM | RHEL 8/9/10, Rocky, Oracle Linux, SLES | NVIDIA's own key (must be enrolled in MOK or kernel-trusted keyring) | Up to current `nvidia-open` release (e.g. `kmod-nvidia-open-580.…`) | Cleanest path for RHEL/SLES; not applicable to our Ubuntu CVM image. |
| NVIDIA `.run` installer with `--module-signing-secret-key` | Any distro | A key the operator generates and enrols via MOK | Whatever NVIDIA `.run` ships | Requires MOK enrollment, which *changes vTPM-measured boot state* on Azure FDE CVMs — incompatible with sealing measurement baselines. |
| `nvidia-driver-XXX-open` from **NVIDIA's CUDA apt repo** (our current bake path) | Ubuntu | **Unsigned** — DKMS-built at install time | Whatever is in NVIDIA's CUDA channel | Deterministic version-pin (good for QA matching NVIDIA's CC stack); **rejected by kernel lockdown when Secure Boot is on**. |

The Ubuntu-on-Azure / GCP path that *does* support Secure Boot is the
first row — Canonical's signed `linux-modules-nvidia-*` packages. Our
own `scripts/gpu_cc_azure/setup_gpu_cc_azure.sh` already implements a
best-effort version of this path: it detects kernel lockdown at bake
time and, if Secure Boot is on, walks a candidate list
(`570-server-open`, `570-open`, `570-server`, `565-server-open`,
`565-server`, `535-server-open`, `535-open`) looking for a
`linux-modules-nvidia-<variant>-${KERNEL_RELEASE}` package that exists
in the Canonical archives and installs it; only if **none** of those
candidates match the current kernel does it fall through to
NVIDIA's CUDA repo DKMS path.

**Why the default still ships as OFF for GPU CC:**

1. **Driver-version pinning.** NVIDIA's H100 CC stack (`nvidia_gpu_tools.py`,
 NRAS RA-TLS evidence, SPDM session setup) is tied to specific driver
 minor versions documented in NVIDIA's CC Deployment Guide. When we
 force Secure Boot **on**, we are at the mercy of whatever Canonical
 has shipped a signed build for on the exact `${KERNEL_RELEASE}` of
 the current Azure CVM / GCP Confidential VM image; that set may not
 include the driver version we need for a given Hopper microcode /
 GSP firmware release. A signed-module miss with SB on means the
 VM boots without NVIDIA support at all and the deploy silently
 completes with an unusable GPU — a worse failure mode than starting
 with SB off and keeping the deploy path deterministic.
2. **MOK enrollment vs measured boot.** On Azure FDE confidential VMs,
 enrolling a custom MOK certificate changes `PCR7` and (depending on
 distro) `PCR4`, which we *bind into RA-TLS via the vTPM PCR
 extension* (F-8). An MOK-based signing path therefore requires us
 to re-baseline our expected PCR digests after every bake, defeating
 one of the controls that compensates for SB being off in the first
 place.
3. **What we already have without Secure Boot:** AMD SEV-SNP / Intel
 TDX guest memory encryption is unaffected; vTPM is still active
 (PCR0–7 are populated by UEFI / shim regardless of Secure Boot
 enforcement state); the SNP report is read from vTPM NV
 `0x01400001` on Azure regardless of Secure Boot status; GPU
 CC-mode, NVIDIA NRAS attestation, dual RA-TLS, and Azure NCC H100
 v5 / GCP A3 Protected PCIe encryption are all unaffected. What
 we lose is **boot-chain image integrity enforcement** (firmware /
 shim / kernel signature checks) — a control we still need to
 compensate for.
4. **Compensating controls when SB stays off:** vTPM PCR0–7 measured
 boot is still captured by `app.template.py:_get_vtpm_pcrs` and
 bound into the RA-TLS certificate (F-8); drift is caught by the
 continuous attestation monitor (§14.6); the in-image filesystem is
 `cryptsetup`-encrypted on Azure FDE CVMs (VMGS-wrapped key);
 container images are hash-pinned (§14.8).

**How to enable Secure Boot for production (opt-in):**

1. Verify that a Canonical-signed `linux-modules-nvidia-<VER>-<flavour>`
 exists for the exact `${KERNEL_RELEASE}` your bake image runs —
 e.g. `apt-cache search "^linux-modules-nvidia-.*-$(uname -r)$"` on a
 throwaway CVM.
2. Set `TF_VAR_enable_secure_boot=true` for the deploy. The runtime VM
 will boot with `secure_boot_enabled = true` (Azure) or
 `enable_secure_boot = true` (GCP shielded VM).
3. Re-bake the image under the same flag (`bake-ami --tee-platform
 gpu-cc-azure --enable-secure-boot`) so the bake VM exercises the
 signed-module path and confirms the driver loads under lockdown.
4. Re-capture canonical vTPM PCR0–7 values and refresh the expected
 set in `client.template.py`.

If the signed-module probe in the setup script fails under SB-on, the
deploy fails fast at attestation time (RA-TLS handshake refuses to
complete without a working NVIDIA driver), rather than producing a
silently broken VM.

* **Files:** `templates/gpu_cc/azure/main.template.tf` and
 `templates/gpu_cc/gcp/main.template.tf` (`enable_secure_boot`
 variable, default `false`); `scripts/gpu_cc_azure/setup_gpu_cc_azure.sh`
 (Canonical-signed module probe).

### 15.1A UEFI Secure Boot on `nitro-aws` / `snp-aws` is ON by default (operational, configurable)

Unlike Azure (`secure_boot_enabled` on the CVM resource) and GCP
(`shielded_instance_config.enable_secure_boot`), **AWS does not expose
Secure Boot enforcement as a runtime `RunInstances` parameter**. The
enforcement state lives entirely in the AMI's UEFI variable store
(`Image.UefiData`), which the bake instance's UEFI NVRAM is captured
into when `aws ec2 create-image` runs. We therefore enable Secure
Boot at *bake time*, not at deploy time — and starting in 2026 it is
on by default to bring AWS into parity with the Azure / GCP
non-GPU platforms (which already hard-enable SB in Terraform).

**Default operator workflow (Secure Boot on):**

```bash
# 1. Bake — Secure Boot is enrolled by default. Pass --no-enable-secure-boot
# to opt out (unbaked dev workflow only).
tee-crafter internal bake-ami \
 --tee-platform snp-aws \
 --enclave-ram 4096 --enclave-cpu 2

# (or --tee-platform nitro-aws for Nitro Enclaves)

# 2. Deploy normally with --ami-id. The deploy validators auto-detect
# the `tee-crafter-secure-boot=enabled` tag on the AMI and confirm
# the launch matches via Terraform precondition. No env-var
# plumbing required.
tee-crafter deploy --tee-platform snp-aws --ami-id ami-XXXXXXXX --deploy
```

**Opt-out workflow (dev only — for testing the unhardened path):**

```bash
# Bake without enrolling SB keys
tee-crafter internal bake-ami --tee-platform snp-aws --no-enable-secure-boot

# Deploy: tell Terraform not to assert SB
TF_VAR_enable_secure_boot=false tee-crafter deploy --tee-platform snp-aws --ami-id <unbaked-ami> --deploy
```

**Per-distro key sources:**

| Distro | Source of PK/KEK/db | What lands in `db` |
|--------|---------------------|--------------------|
| AL2023 (`nitro-aws`) | `/usr/share/amazon-linux-sb-keys/{PK,KEK,db}.esl.auth` (Amazon-signed) | Amazon Linux Secure Boot Signing CA — same CA that signs `BOOTX64.EFI` (grub) and `/boot/vmlinuz-*`. |
| Ubuntu 22.04 (`snp-aws`) | Generated per-bake (RSA-2048 PK + KEK), plus a `db` extracted from `/usr/lib/shim/shimx64.efi.signed` | Microsoft Corporation UEFI CA 2011 (which signs shim → grub → kernel) **plus** a tee-crafter self-signed db cert so operators can sign their own EFI binaries later. |

**What the bake script does (`scripts/common/secure_boot_enroll_aws.sh`):**

1. Verify the existing bootloader + kernel actually verify against the
 chosen db cert — *before* enrolling. If not, abort. (Prevents
 bricking the AMI by enrolling keys that don't sign the shipped
 binaries.)
2. Enroll `db`, `KEK`, then `PK` (in that order — enrolling PK exits
 Setup Mode and starts SB enforcement).
3. Read back `mokutil --sb-state` and the raw `SecureBoot` /
 `SetupMode` EFI vars. If `mokutil` does not report
 `SecureBoot enabled`, abort the bake and refuse to produce a
 misleadingly-tagged AMI.
4. Persist Ubuntu's per-bake PK/KEK/db private keys under
 `/etc/tee_crafter/sb-keys/` (mode `0700`, root-only) so operators
 can sign their own EFI binaries against this AMI's `db` later
 without re-baking.

The Python `bake_snp_aws_ami` / `bake_nitro_ami` functions run an
additional SSM verification command **after** the setup script, so
the Python-side bake fails fast if anything in the in-VM enrollment
silently broke. Only on success does the AMI get tagged with
`tee-crafter-secure-boot=enabled`.

**Terraform-side enforcement
(`templates/{nitro,snp/aws}/main.template.tf`):**

* `variable "enable_secure_boot"` (**default `true`**) gates
 a launch-time precondition: the operator MUST supply a `custom_ami_id`
 AND that AMI MUST carry the `tee-crafter-secure-boot=enabled` tag.
 Either is missing → `terraform plan` aborts with a clear error
 before any instance is created. To opt out (dev only), set
 `TF_VAR_enable_secure_boot=false`.
* `output "secure_boot_mode"` surfaces the posture so downstream
 consumers (a CI dashboard, say) can render it next to
 `setup_egress_mode`.
* The base-AMI `data` source's `boot-mode` filter is tightened to
 `uefi` / `uefi-preferred` when `enable_secure_boot = true` (defense
 in depth against a future legacy-BIOS regression on Ubuntu /
 AL2023).

**Why this is a CLI/Terraform-level toggle (not a hardware constraint):**

* SB enrollment requires several minutes of additional setup-script
 runtime (rustup→snpguest on Ubuntu, dnf installs on AL2023) plus a
 successful verify-back of the EFI vars. In 2025 it was opt-in; in
 2026 it became default-on because the additional minutes are
 well-spent for the threat-model coverage (kernel lockdown =
 integrity, signed bootloader chain, refusal to load unsigned kmods).
* Operators who legitimately need to side-load an unsigned kernel
 module for debugging (e.g., custom NIC drivers) can re-bake with
 `--no-enable-secure-boot` and deploy with `TF_VAR_enable_secure_boot=false`.
* The Microsoft UEFI CA 2011 used by the Ubuntu / SNP-AWS path is
 scheduled for replacement by Microsoft over the 2026–2027 horizon;
 bake-time enrollment lets us rotate the CA without reissuing every
 deploy's AMI mid-flight.

**Empirical validation:** the live bake/launch loop was exercised end
to end in May 2026 on `m6a.xlarge` (Ubuntu 22.04 + SNP enabled) and
`c6a.xlarge` (AL2023 + Nitro Enclaves):

* `mokutil --sb-state` reported `SecureBoot enabled` post-reboot.
* `/sys/kernel/security/lockdown` reported `[integrity]`.
* `dmesg` showed `Kernel is locked down from EFI Secure Boot mode`.
* `sev_guest` was loaded (`signer: Build time autogenerated kernel
 key`) and produced 1184-byte SNP reports under Secure Boot.
* `nitro_enclaves` is a *builtin* kernel module on AL2023, so the
 Nitro allocator + `nitro-cli build-enclave` + `nitro-cli run-enclave`
 + console worked unchanged under Secure Boot.
* Docker installed cleanly and `docker run --rm hello-world` succeeded
 on both.
* Python venv + `cryptography>=42` + Ed25519 keygen worked on both.

**Files:**

* `scripts/common/secure_boot_enroll_aws.sh` — the shell fragment
 injected into `setup_snp_aws.sh` / `setup_nitro.sh` when
 `--enable-secure-boot` is set.
* `cli/loaders.py::inject_secure_boot_block` — the placeholder
 substitution that swaps `__SECURE_BOOT_ENROLL__` for the enrollment
 block (or a no-op echo when SB is disabled).
* `cli/commands/baking/{snp.py,nitro.py}` — the `_verify_secure_boot_enrolled`
 helper that fails the bake if the in-VM enrollment didn't take.
* `cli/commands/deploy/validators.py::propagate_secure_boot_var_from_ami`
 — the deploy-side auto-detection that flips
 `TF_VAR_enable_secure_boot=true` based on the AMI tag.

### 15.2 No separately-signed "CC-mode" driver build exists (informational)

Operators sometimes ask whether NVIDIA ships a *separate* signed kernel
module specifically for Confidential Computing mode. They do **not**.
"CC mode" on H100 / Blackwell is a **runtime GPU configuration**
(`nvidia_gpu_tools.py --set-cc-mode=on` for Hopper,
`--set-ppcie-mode=on` for Hopper PPCIe / Blackwell), applied either
from the host before passthrough or from inside the guest after
passthrough. The same `nvidia-driver-XXX-open` package is used for
CC and non-CC; CC simply requires a *minimum* driver version (and a
matching GSP firmware blob) that supports the CC RA-TLS / SPDM path.
The signing situation is therefore identical to non-CC: signed via
Canonical (Ubuntu) or NVIDIA precompiled kmod (RHEL/SLES), unsigned
via NVIDIA's CUDA apt repo / `.run` installer.

### 15.3 Nitro Enclaves do not expose `/dev/sev-guest` (immutable)

Nitro Enclaves are **not** SEV-SNP guests. The attestation evidence is
a COSE_Sign1 document signed by the AWS Nitro Hypervisor's leaf
certificate, anchored to the published AWS Nitro Root CA. There is no
hardware AMD/Intel TEE quote to be obtained, and so the SNP-specific
TCB-SVN / VLEK / VCEK fields in the audit record are intentionally
empty for `nitro-aws` deploys.

### 15.4 `/dev/sev-guest` is unavailable on Azure SEV-SNP CVMs (immutable)

Azure runs SEV-SNP guests under Hyper-V, which does not expose the
upstream Linux `/dev/sev-guest` device. The attestation report is
obtained instead from the **vTPM** at NV index `0x01400001` (HCL
attestation report with `HCLA` header + 1184-byte SNP report). This
path is implemented in `templates/snp/azure/app.template.py` and works
on all Azure CVMs regardless of Secure Boot status. Loss of the vTPM
fall-through path is fatal — the server refuses to start.

### 15.5 `gpu-cc-aws` has no CPU TEE and an unencrypted PCIe link (immutable)

AWS does not currently offer a confidential VM that combines SEV-SNP
or TDX with an NVIDIA H100 in CC mode; the platform listed as
`gpu-cc-aws` provides **GPU memory encryption only** with a regular
Nitro host. The CPU↔GPU PCIe link is therefore **not** encrypted by
the hardware TEE. Operators must explicitly acknowledge this weaker
model by setting `TEE_CRAFTER_ACCEPT_PARTIAL_CC=1`; otherwise the
`gpu-cc-aws` deploy phase refuses to start. Compliance evidence for
this platform is downgraded to MODERATE (`evidence.py`).

---

## 16. Operator Runbook

This section is the canonical operator-side configuration reference for
a TEE-Crafter install. Every control listed here is enforced by the
code paths described in the preceding sections; the runbook collects
the day-to-day commands and pre-flight checks for an environment.

### 16.1 Provenance signing

1. Generate a long-lived Ed25519 audit key **once per environment**
 (staging, prod) and store the fingerprint in your audit policy:

 ```bash
 tee-crafter audit-gen-signing-key
 # → ~/.tee-crafter/provenance-signing-key.pem (0600)
 # SHA-256 fingerprint: <fpr>
 ```

2. Distribute the private key to every CI runner that signs builds:
 either drop the PEM at `~/.tee-crafter/provenance-signing-key.pem`,
 set `TEE_CRAFTER_PROVENANCE_SIGNING_KEY=<PEM>`, set
 `TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE=<path>`, or store under
 the OS keyring entry `tee-crafter/provenance-signing-key`.

3. Pin the fingerprint on every verifier:

 ```bash
   tee-crafter verify-provenance \
     --file build/provenance/build_provenance.json \
     --pinned-pubkey-sha256 <fpr> \
     --require-longlived
 ```

4. **Never** export `TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL=1` in
 audited environments. With no long-lived key configured the signer
 refuses to run, which is what blocks an unsigned build from
 reaching a deploy.

### 16.2 Batch AppArmor + SELinux

Bake a fresh AMI/image (`tee-crafter internal bake-ami`) so the new
`tee-crafter-batch-container` AppArmor profile lands in
`/etc/apparmor.d/`. The batch oneshot unit pre-flights both
`/etc/tee_crafter/seccomp-container.json` and
`/etc/apparmor.d/tee-crafter-batch-container` and fails-closed if either
is missing. Re-bake any image whose batch unit reports the pre-flight
file as absent.

### 16.3 Vulnerability gate

The default deploy behaviour aborts when Trivy/Grype reports any
CRITICAL or HIGH CVE. To allow temporary exceptions (e.g. while a CVE
fix is rolling out upstream), set `TEE_CRAFTER_ALLOW_VULNERABLE=1` or
pass `--allow-vulnerable` to the deploy command. Every override is
written to the audit trail as `gate_allowed=True`, so the compliance
report records the exception.

CI policy should refuse merges that set this flag on the audited
release branch.

### 16.4 Post-destroy secret shred

After a successful `terraform destroy`, `core/iac/platforms.run_terraform_destroy`
overwrites and unlinks well-known ephemeral **secret** files in the
build directory:

* `*_ssh_key.pem` (Azure / GCP / GPU-CC RSA-4096 keys)
* `terraform.tfstate.backup` (last copy of sensitive state values)
* `*_authorised_keys.tmp` / `*_authorized_keys.tmp` (IAP OS-Login staging)
* `siem/siem.env`, the top-level `siem.env`, and `app/siem.env` (flattened SIEM bearer material)
* `byok/byok.env`, the top-level `byok.env`, and `app/byok.env` (BYOK unwrap environment)

Each successful pass **appends** a non-secret
`post_destroy_shred_manifest.txt` in the same build directory listing
**only** relative paths and a UTC timestamp — never file contents — so
compliance archives can prove what was cleared without retaining
cryptographic material.

**Failed destroy:** if `terraform destroy` exits non-zero, shredding
does **not** run (same policy as today for SSH keys): the operator may
re-run destroy with the same credentials and TF state.

**Failed or partial deploy:** local `siem.env` / `byok.env` are **not**
auto-shredded on deploy failure — you need those files to iterate on
your `siem.json` / `byok.json` without re-entering secrets from
scratch. The CLI prints structured errors (missing
`--siem-config`, invalid JSON schema, unreachable instance, …). Every
completed phase is also recorded in `build_provenance.json` /
`build_provenance.txt` with **no** embedding of bearer tokens.

**Successful deploy:** the on-VM install script already `shred -u`s the
**disk-resident** copy of `siem.env` after copying to tmpfs (§17.2).
The **workstation** still holds a copy under `builds/…/siem/siem.env`
until a successful `tee-crafter destroy`.

**SLSA provenance:** every `BuildAuditTrail.save` emits
`slsa/slsa_provenance.intoto.json` and `slsa/slsa_provenance.dsse.json`
under the same build directory as `provenance/build_provenance.json`
when a signing key resolves (best-effort; skipped if signing is
unavailable — see `core/audit/slsa.py`).

To disable post-destroy shredding for forensics, set
`TEE_CRAFTER_SKIP_POST_DESTROY_SHRED=1`.

### 16.5 Pre-flight checklist

| # | Item | How to verify |
|---|------|---------------|
| 1 | Long-lived audit signing key is configured | `python -c "from tee_crafter.core.audit.signing import load_signing_key; print(load_signing_key.kind)"` prints `longlived` |
| 2 | Audit fingerprint is pinned in CI | `tee-crafter verify-provenance --pinned-pubkey-sha256... --require-longlived` returns 0 on a signed build |
| 3 | AMI is baked with both AppArmor profiles | `ssh <vm> 'sudo apparmor_status \| grep tee-crafter-batch-container'` shows enforce mode |
| 4 | Vulnerability gate is on | `TEE_CRAFTER_ALLOW_VULNERABLE` is unset in the CI environment |
| 5 | Post-destroy shred is on | `TEE_CRAFTER_SKIP_POST_DESTROY_SHRED` is unset |
| 6 | Egress lockdown is on | `terraform output setup_egress_mode` prints `locked-down` (AWS) / NSG `DenyAllOutbound` at priority 4000 (Azure) / single allowlist (GCP) |
| 7 | KMS / Key Vault policy is PCR-bound | Inspect the rendered `main.tf`: every decrypt grant must include a `kms:RecipientAttestation:PCRn` (AWS), `eat:platform` policy (Azure MAA), or `tdx_quote` clause (GCP) |
| 8 | SSM / Bastion / IAP is the only inbound path | Security Group / NSG has zero inbound rules besides the Bastion subnet (Azure) or no ingress at all (AWS / GCP — orchestrator uses SSM port forwarding / IAP) |
| 9 | Well-known secret files are shredded after a **successful** destroy | `ls builds/<runid>/ builds/<runid>/siem/ builds/<runid>/byok/` shows no `*_ssh_key.pem`, `terraform.tfstate.backup`, `siem.env`, or `byok.env`; verify `post_destroy_shred_manifest.txt` appended an entry |

### 16.6 Scope clarifications

These are honest framings of the trust model that operators should
understand; they are part of the documented architecture, not bugs.

* **Nitro host proxy ↔ enclave TLS is `verify=False` by design.** The
 outer TLS hop terminates on the host's loopback (reached via an SSM
 port-forward tunnel). The real security is the inner attestation +
 ECIES layer: the enclave's ECDH public key is bound to a COSE-signed
 attestation document, so an MITM at the TLS layer cannot read or
 forge the payload. Treat the outer TLS as transport hygiene, the
 inner ECIES as the confidentiality boundary.
* **Nitro batch container runs Docker on the host, not in the enclave — so
 `nitro-aws --batch` is not TEE-protected execution.** `docker diff` capture is
 not available inside Nitro Enclaves, so the user image runs on the parent EC2
 instance, which is an ordinary VM. Memory is not encrypted, the image is not
 measured into the enclave, and `--input-dir` data sits in the clear on that
 instance's disk. The batch systemd unit still requests the full container
 hardening set (cap-drop ALL, seccomp, AppArmor batch profile, SELinux label,
 no-new-privileges, cgroup/pid/ipc namespaces), but that constrains the
 *container*, not the host, and it is not a TEE boundary.

 If you need TEE-protected batch on AWS, use `snp-aws`, where the confidential
 VM itself is the TEE.

 **Known defect — batch container on `nitro-aws` cannot start as shipped.**
 `container.batch.service.template` guards startup with two hard pre-flight
 tests (lines 26-27):

 ```
  ExecStartPre=/usr/bin/test -f /etc/tee_crafter/seccomp-container.json
  ExecStartPre=/usr/bin/test -f /etc/apparmor.d/tee-crafter-batch-container
 ```

 Nine of the ten platform bake scripts write both files, because their
 `setup_*.sh` carries the `__SECCOMP_PROFILE__` / `__APPARMOR_BATCH_PROFILE__`
 placeholders that `cli/loaders.py::_inject_security_profiles` expands at bake
 time. `scripts/nitro_aws/setup_nitro.sh` carries **neither placeholder** and
 writes neither file, and nothing stages them at deploy time either. Since
 `nitro-aws --batch` does route through this unit
 (`batch_dispatch.py:333-341`), the `ExecStartPre` tests fail and the unit
 never reaches `ExecStart`. Fixing this is a code change — adding the two
 placeholders to `setup_nitro.sh` — not a documentation change.
* **The host proxy forwards short-lived STS credentials over vsock to
 the enclave** so the enclave can call KMS (the enclave has no
 network stack). KMS only releases data keys to a principal that
 produces a matching attestation document, so the host proxy is a
 credential courier rather than a confidentiality boundary. The
 PCR-bound KMS policy enforces this: even if the host is compromised
 and presents the STS credentials directly, KMS refuses the decrypt
 because no attestation document is attached.

## 17. SIEM-SEC and SBX hardening controls

This section catalogues the defence-in-depth controls layered on top
of the base attestation/RA-TLS/BYOK architecture. Each control has a
stable identifier (`SIEM-SEC-N`, `SBX-N`) so operators can reference
specific controls in their compliance documentation.

### 17.1 SIEM-SEC-1 — Refuse insecure TLS by default

The continuous-attestation sidecar (`siem_export.py`) **refuses to
start** with `verify_ssl=0` unless the operator additionally sets
`TEE_CRAFTER_SIEM_X_ALLOW_INSECURE=1`. This prevents a copy-pasted
sandbox config (where Splunk is fronted by a self-signed nginx) from
silently MITM-ing in production. Verified by
`apps/cli/tests/cli/test_siem_wiring.py::TestInsecureTlsGate`.

### 17.2 SIEM-SEC-2 — Token-bearing env on tmpfs only

The SIEM bearer credential (Splunk HEC token / Datadog API key /
Azure Monitor bearer) lands in
`/run/tee-crafter-{platform}/siem.env` — a tmpfs path that never
touches the boot disk. Confidential VMs encrypt memory, not the boot
disk; an EBS / managed-disk / persistent-disk snapshot of the VM
yields no usable credential.

* The non-secret half (provider, endpoint, index, fail-closed flag)
 is staged separately as `siem.env.public` and DOES survive
 reboots — so post-reboot the sidecar still knows where to talk to
 even before the operator re-stages the token.
* `TEE_CRAFTER_SIEM_PERSIST=1` at deploy time overrides this and
 leaves `siem.env` on disk (accepting the snapshot risk).
* Token rotation / post-reboot re-staging is exposed via
 ``tee-crafter siem-stage --platform <slug> --siem-config
 config.json --instance-id <id>`` (SSM) or ``--ssh-host``.

### 17.3 BYOK-SEC-1 — Wrapped DEK / HSM bearer on tmpfs only

BYOK policy is staged as `byok.env` + `byok.env.public` + `byok.json`.
The **secret half** (`TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64`, HSM bearer tokens,
and similarly named `TEE_CRAFTER_BYOK_X_*` extras) lives only in the file that
post-deploy relocates to **`/run/tee-crafter-{platform}/byok.env`**; the
installer `shred -u`s the disk copy (same pattern as SIEM-SEC-2). Override
with **`TEE_CRAFTER_BYOK_PERSIST=1`** only when you accept snapshot risk.
`byok.json` on disk **never** contains raw wrapped ciphertext or bearer values
— those fields are redacted in the manifest.

Systemd units load `EnvironmentFile=-/run/.../byok.env` before
`.../app/byok.env.public` on SNP, TDX, and GPU-CC platforms.

### 17.4 SEC-CREDS-1 / SEC-CREDS-2 — Nitro host proxy vs enclave AWS creds

**SEC-CREDS-2 (host):** `host_proxy.template.py` strips any **inbound**
`__aws_credentials` from the HTTP body (client injection is ignored). It only
attaches fresh **instance-role** credentials for requests that actually call
KMS (`ciphertext_b64`, `encrypted_payload`). Attestation-only payloads are
forwarded **without** credential material.

Production posture is **strict IMDSv2** (`TEE_CRAFTER_PROXY_STRICT_IMDS=1`,
the default). When IMDSv2 is unreachable the proxy refuses to forward
credentials — there is no env-cred fallback. The knob
`TEE_CRAFTER_PROXY_STRICT_IMDS=0` re-enables the laptop-style
`AWS_ACCESS_KEY_ID`-from-env fallback (ad-hoc smoke testing only). An
orthogonal operational knob `TEE_CRAFTER_PROXY_NO_CREDS=1` disables
forwarding entirely (used by tests and custom non-KMS paths).

**SEC-CREDS-1 (enclave):** The in-enclave template passes credentials to
boto3 via **per-client kwargs**, not `AWS_*` env vars, so secrets are not
global process state across requests.

Sandbox smoke tests mint **STS session tokens** by default so long-lived IAM-user
keys never cross the SSM tunnel; see `byok-sandbox/README.md`.

### 17.5 SIEM-SEC-3 — Redacted error surfaces

When the sidecar attestation provider fails, only `type(e).__name__`
and a path-stripped (`/opt/tee-crafter-*` → `<base>/`) 160-char
message reach the SIEM operator. No `repr(e)` memory-address leaks,
no absolute paths.

### 17.6 SIEM-SEC-4 — Fail-closed gate (production default, 8 of 10 platforms)

On the **eight CVM platforms** — `snp-aws`, `snp-azure`, `snp-gcp`,
`tdx-azure`, `tdx-gcp`, `gpu-cc-aws`, `gpu-cc-azure`, `gpu-cc-gcp` —
a SIEM-enabled deploy defaults to **fail closed**: the main app imports
`siem_health.py` (auto-staged) and refuses every request whenever the
sidecar:

* has not written its health file inside the grace window
 (`TEE_CRAFTER_SIEM_GRACE_SECONDS`, default 60 s),
* has not exported an event for `TEE_CRAFTER_SIEM_MAX_LAG_SECONDS`
 (default `max(120, 3 × interval)`),
* reports `last_export_status=fail` (SIEM endpoint rejecting events).

Refused requests return a structured `{"error": "siem_blackout",
"policy": "fail_closed"}` payload. This is the SOX / PCI-DSS /
FedRAMP-style logs-or-no-service posture. Verified live on `snp-aws`
: an unresolvable collector produced
`last_export_status=fail` and the deploy itself exited non-zero rather
than reporting success for a service that would answer nothing.

> **`nitro-aws` and `sgx-azure` do not get this gate.** Both run the
> exporter as a **host-side** sidecar, because the enclave has no route to
> a collector, and neither passes the SIEM environment across the TEE
> boundary: the nitro `Dockerfile` never `COPY`s `siem.env.public` into
> the EIF and no SIEM keys reach the measured `app.env`, while the Gramine
> manifest sets `insecure__use_host_env = false` and lists no SIEM
> variables in `[loader.env]`. `TEE_CRAFTER_SIEM_ENABLED` is therefore
> unset inside the TEE, `siem_health.is_fail_closed` returns `False`,
> and `fail_closed_wrap` — which *is* wired into
> `nitro/app_vsock.template.py` and `sgx/app_gramine.template.py` — passes
> every request straight through. The enclave could not read the host's
> `/run/tee-crafter-<platform>/siem.health` even if the flag were set.
>
> On those two, treat continuous-attestation export as a **detective**
> control (the SOC sees the stream stop) rather than a **preventive** one
> (the workload stops serving). Do not carry the logs-or-no-service claim
> above into a control narrative for a Nitro or SGX deployment. The split
> is enforced in code as
> `siem_sidecar.PREVENTIVE_GATE_PLATFORMS` / `DETECTIVE_ONLY_GATE_PLATFORMS`
> rather than left to this paragraph, because per-platform prose in this
> project has been wrong six times.

Knob: set `"fail_open": true` in `siem.json` (or
`TEE_CRAFTER_SIEM_FAIL_OPEN=1`) to revert to log-and-keep-serving
for prototyping / eval workloads — observability degrades but the
service stays up. Note this only changes behaviour on the eight
platforms where the gate is armed at all.

### 17.7 SIEM-SEC-5 — Attested proxy sandbox

The platform-owned attested ingress proxy invokes user traffic forwarding
inside a defence-in-depth fence (`tee_crafter_handler_sandbox.py`):

* `prctl(PR_SET_NO_NEW_PRIVS, 1)` blocks setuid escalation.
* A **seccomp** filter installed via `libseccomp2` rejects (`EPERM`)
 `fork`, `vfork`, `clone3`, `execve`, `execveat`, `ptrace`,
 `unshare`, `mount`, `umount2`, `setns`, `pivot_root`, `chroot`,
 `kexec_load`, `init_module`, `finit_module`, `delete_module`,
 `perf_event_open`, `bpf`, `userfaultfd`, `personality`,
 `io_uring_setup`, `process_vm_*`, all the `set*uid*` /
 `set*gid*` calls, and `capset`. This blocks Python subprocess
 escapes, syscall interposition, and capability escalation while
 still allowing legitimate sockets, file I/O, numpy/torch, and
 Python threading. When a **parent** seccomp filter is already
 active (systemd `SystemCallFilter=` on the per-platform unit),
 TEE-Crafter **skips** installing a second filter — invoking
 `seccomp(2)` would be denied by the parent's allowlist and the
 kernel would terminate the process with `SIGSYS`; coverage is
 delegated to systemd's filter instead. `status_snapshot` reports
 `seccomp_source: parent` vs `in-app`.
* Per-request `RLIMIT_CPU=30s` (configurable via
 `TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_CPU_SEC`) and `RLIMIT_FSIZE`
 fences run-away user code.

When `libseccomp` is absent (some Gramine SGX configurations,
unprivileged containers) the sandbox **falls open with a logged
warning** so the workload still serves — fail-closed is opt-in via
`TEE_CRAFTER_HANDLER_SANDBOX` env.

### 17.8 SIEM-SEC-6 — SLSA Provenance v1 (in-toto + DSSE)

Every `BuildAuditTrail.save` emits a parallel
`slsa/slsa_provenance.intoto.json` (Statement v1) plus a DSSE envelope
(`slsa/slsa_provenance.dsse.json`) signed with the same long-lived
Ed25519 key that signs `provenance/build_provenance.sig`. Downstream
`slsa-verifier`, `cosign attest --type slsaprovenance`,
Sigstore policy-controller, and Kyverno can ingest it directly.

* `predicateType` = `https://slsa.dev/provenance/v1`
* `buildType` = `https://tee-crafter.dev/build/v1`
* `subject` covers every build output (`tee-crafter.tar`, EIF files,
 SGX manifests, `provenance/build_provenance.json`).
* `resolvedDependencies` enumerates git SHA + worktree-clean flag,
 `requirements.txt`/`.lock`, `Dockerfile`,
 `siem/siem.json`, `byok/byok.json` — each with SHA-256.
* `externalParameters` records the full CLI args + redacted env-var
 digest (any var whose name matches token / secret / key /
 password / credential / auth is hashed before inclusion).

We do **not** claim SLSA-3+ (that requires a hermetic, isolated
builder with provenance signed by the builder infrastructure, not
the developer). We produce SLSA-1: "the developer attests to these
inputs with this key." Combine with `--require-longlived` +
`--pinned-pubkey-sha256` for production CI gates.

### 17.9 SBX-1 — Sidecar systemd hardening

The `tee-crafter-siem.service` sidecar runs with:

* `NoNewPrivileges=yes` (strictest — no setuid escalation),
* `CapabilityBoundingSet=CAP_DAC_OVERRIDE` (single capability,
 needed only to read `/sys/kernel/config/tsm/`),
* `SystemCallFilter=@system-service @resources` minus
 `@privileged @raw-io @keyring @mount @pkey @debug …`,
* `MemoryMax=256M`, `TasksMax=32`, `MemoryHigh=128M` (resource
 ceilings prevent a sidecar OOM from cascading into the main app),
* `IPAddressDeny=link-local multicast`.

### 17.10 SBX-2 — Main-app systemd ceilings

Every main app unit declares an explicit `MemoryMax` and
`TasksMax`. These are deliberately generous (16 GiB / 4096 tasks
for CVMs; 80 GiB / 8192 tasks for GPU-CC; 8 GiB / 2048 for SGX
Gramine; 2 GiB / 1024 for the Nitro host-proxy) — large enough that
real workloads don't hit them, small enough that a fork-bomb /
unbounded-allocation user payload that slipped past the seccomp
fence still terminates instead of taking down the host. Verified
by `apps/cli/tests/cli/test_security_hardening.py::TestSystemdUnitsCarryTmpfsPath::test_main_units_set_memory_ceiling`.

### 17.11 Operator runbook: chain verification

The SIEM-side operator runs `tee-crafter verify-siem-chain` against
a windowed export from their SIEM:

```bash
# Pull last 24 h of events from Splunk into events.jsonl.
splunk search 'index=tee_crafter sourcetype=tee_crafter:attestation' \
              -earliest -24h -maxout 0 -output rawdata > events.jsonl

# Verify chain + signatures + measurement against the pinned hash.
# --pubkey-file is the trust anchor and is mandatory: without it the
# command refuses to run (verify_siem_chain.py:203-208).
tee-crafter verify-siem-chain \
    --file events.jsonl \
 --pubkey-file./build_provenance.pub \
    --expect-first-seq 0 \
    --expect-platform snp-aws \
    --expect-measurement <sha256 from build_provenance.json>
```

**Always pass the key out of band.** Supply the operator's own copy of
the TEE's Ed25519 public key with `--pubkey-file <pem>`, `--pubkey <pem>`
or `--pinned-pubkey-sha256 <hex>` (repeatable). Verifying against the
`public_key_pem` embedded in each event would only prove the stream is
internally consistent, not that the TEE you deployed produced it — an
attacker who can rewrite the export can also swap in a key they hold and
re-sign every event. `verify_chain` therefore refuses to verify
signatures when no out-of-band key is supplied
(`apps/cli/src/tee_crafter/cli/commands/verify_siem_chain.py:203-208`);
when `--pubkey*` is omitted it will fall back to a `build_provenance.pub`
sitting next to the events file or in the CWD (`:95-107`), which is a
convenience, not a substitute for pinning.

`--expect-first-seq 0` is what stops a silent head-truncation: without
it, an attacker can delete the first N events and the remaining chain
still verifies against itself.

Exit code 2 → chain break / signature failure / unexpected
measurement. Wire it into a cron / saved-search that pages on
non-zero.

### 17.12 Threat model — what these controls do and don't defend

| Channel | Defended | Still in scope of trust |
|---|---|---|
| Memory privacy | SEV-SNP / TDX / SGX / NitroTPM + measured boot | Hardware vendor compromise, side channels |
| Network confidentiality | RA-TLS + ECDH session keys | Traffic analysis |
| Attestation freshness | SIEM-SEC-4 fail-closed (production default, **8 of 10 platforms** — §17.6) + signed hash chain | A SIEM operator who drops events silently when the dev-hatch `fail_open: true` is set; and on `nitro-aws` / `sgx-azure`, where the gate is inert, anyone content to let the workload keep serving after the stream stops |
| Token confidentiality (at rest) | SIEM-SEC-2 tmpfs + SIEM-SEC-3 redaction | A live process dump of `/proc/<sidecar>/environ` while the VM is running |
| User-code escape | SIEM-SEC-5 seccomp + SBX-2 cgroup ceilings | A Python interpreter RCE that pivots via syscalls not on our deny-list (process_madvise, set_mempolicy, etc.) — file an issue and we'll extend the list |
| Build supply chain | SIEM-SEC-6 SLSA Provenance v1, long-lived Ed25519 signature | A compromised developer machine that re-signs the SLSA envelope after tampering |

---

## 18. Requirement IDs you will find in the source

Several hardening requirements are referenced by short IDs in source comments
and docstrings but were never written down anywhere a reader could look them
up. If you grep the tree and hit one of these, this is what it means. Every
row was read back out of the code it annotates.

| ID | Requirement | Where it is implemented |
|---|---|---|
| `F-4` | A launch measurement the client learns *from the server it is verifying* is worthless. Measurements must be pinned out of band; there is no trust-on-first-use. | `templates/gpu_cc/gcp/client.template.py:736`, `templates/gpu_cc/azure/client.template.py:845`, `templates/gpu_cc/aws/client.template.py:13`. Also cited on the `gpu-cc-aws` deploy gate (`cli/deployment/gpu_cc/aws_phase.py:74`) — see the caveat below. |
| `F-7` | The NVIDIA NRAS EAT nonce must be bound to the TLS key the server will present, so a valid GPU attestation relayed from a different host cannot be paired with an attacker's TLS identity. The nonce is `SHA-256(ECDH_pubkey_uncompressed ‖ salt)`; the client recomputes it and compares against the NRAS-signed `eat_nonce` claim. | `core/gpu/nvidia_attestation.py:212-238` (derivation) and `:254-259` (submission); enforced client-side at `templates/gpu_cc/gcp/client.template.py:595` and `templates/gpu_cc/azure/client.template.py:661`. |
| `F-10` | The Nitro host proxy must bind to loopback only, including when IPv6 is enabled on the host. | `templates/nitro/host_proxy.template.py:415` (`forwarded_allow_ips="127.0.0.1"`). |
| `F-17` | The NVIDIA NRAS API key must not appear verbatim in a command line, an SSM document, or a log. It is base64-encoded in flight and staged via tmpfs. | `cli/deployment/gpu_cc/{aws,gcp,azure}_setup.py` and `{aws,gcp}_phase.py` — five call sites, e.g. `aws_setup.py:112`. |
| `SB-1` | UEFI Secure Boot defaults **off** on `gpu-cc-azure` and `gpu-cc-gcp` — for reliability of the NVIDIA CC driver stack under kernel lockdown, **not** because the hardware forbids it. Flip `enable_secure_boot = true` only after confirming a signed NVIDIA kernel module exists for your exact kernel release. | `templates/gpu_cc/{gcp,azure}/main.template.tf:154` / `:141`. Full trade-off analysis in [§15.1](#151-uefi-secure-boot-defaults-to-off-on-gpu-cc-azure--gpu-cc-gcp-operational-configurable). |
| `SUP-3` | Kernel lockdown stays enforced on production `sgx-azure` deploys. The baked SGX image installs PSW/Gramine from signed Intel and Gramine apt repos with `signed-by` GPG, so no unsigned kernel module is needed and lockdown does not break the SGX userspace stack. | `templates/sgx/main.template.tf:512-521` (`secure_boot_enabled = true`, `vtpm_enabled = true`). |

## 19. Every escape hatch that weakens a default

Each row is a real environment variable, read by the code path named. Production
defaults are the *secure* side of every one; the "weakening value" column is what
you have to set to give something up. Every one of these is recorded in the
audit-evidence ledger when set, so an exception shows up in a compliance report
rather than only in someone's shell history.

Verified against the tree by locating each read, not by
searching for mentions — `TEE_CRAFTER_ALLOW_MIXED_PCS_HOSTS` appears in a
comment in `core/attestation/tcb_collateral.py` explaining why such a flag was
deliberately *not* added, and is therefore absent below.

| Variable | Weakening value | What you give up | Read at |
|---|---|---|---|
| `TEE_CRAFTER_ACCEPT_PARTIAL_CC` | `1` (required to deploy at all) | Acknowledges that `gpu-cc-aws` has no CPU-TEE. The deploy **refuses without it**, so this is an acknowledgement rather than a downgrade. Ledger check `DH-007`. | `cli/deployment/gpu_cc/aws_phase.py:89` |
| `TEE_CRAFTER_ALLOW_UNVERIFIED_AWS_CPU_ATTESTATION` | `1` | Proceeds on `gpu-cc-aws` when the peer presents **no** NitroTPM attestation document. Reports `gpu-only-cpu-unattested`. Normally means the image predates the bake installing `nitro-tpm-attest`; re-bake instead. | `templates/gpu_cc/aws/client.template.py` |
| `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT` | `1` | Releases sealed `.env` / BYOK to a TEE whose launch measurement was never pinned, and accepts an unchecked vTPM boot chain on `gpu-cc-gcp`. | `core/measurements/registry.py`, `cli/commands/deploy/measurement_pin.py` |
| `TEE_CRAFTER_BYOK_ALLOW_ANY_MEASUREMENT` | `1` | Removes the measurement allowlist from the BYOK key-release policy — the key is released to any measurement. | `core/keys/spec.py:118` |
| `TEE_CRAFTER_BYOK_FAIL_OPEN` | `1` | The workload serves requests even when the attested DEK release did not land. Dev hatch; never in production. | `cli/commands/deploy/byok_mode.py:677`, `templates/common/byok_health.py` |
| `TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN` | `1` | Accepts a runtime audit log with no hardware-signed chain-key commitment, so a host-level adversary can replace the log with a self-consistent forgery undetectably. | `templates/gpu_cc/{azure,gcp}/app.template.py` |
| `TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_COMMITMENT` | `1` | The same property on the `sgx-azure` / `tdx-*` templates. | `templates/sgx/app_gramine.template.py`, `templates/tdx/{azure,gcp}/app.template.py` |
| `TEE_CRAFTER_NRAS_STRICT` | `0` | Replaces the resolved NRAS host route with broad HTTPS/443 to `0.0.0.0/0`. Loud warning plus an audit entry. | `cli/deployment/common/nras_egress.py:147` |
| `TEE_CRAFTER_NRAS_RESOLVE` | `0` | Skips deploy-time resolution, so strict mode creates **no** egress rule — correct for an air-gapped or offline-verifier deploy, and fatal to NRAS attestation otherwise. | `cli/deployment/common/nras_egress.py:162` |
| `TEE_CRAFTER_ALLOW_SETUP_EGRESS_NAT` | `1` | Leaves a blanket NAT egress path in place for the workload subnet instead of the narrow allowlist. | `cli/commands/deploy/workload_egress.py:75` |
| `TEE_CRAFTER_ALLOW_NON_ENCLAVE_SGX` | `1` | Runs the `sgx-azure` workload outside a Gramine enclave. There is no SGX protection at all in this mode. | `cli/deployment/sgx/gsc.py:51` |
| `TEE_CRAFTER_SKIP_BUILD_INTEGRITY_CHECK` | `1` | `deploy-from-build` skips the provenance hash chain and Ed25519 signature check on a build directory read straight off local disk — and that directory's artifacts are what get measured into the TEE. | `cli/commands/deploy/from_build.py:258` |
| `TEE_CRAFTER_ALLOW_VULNERABLE` | `1` | Deploys despite CRITICAL/HIGH findings from the image scan. Recorded as `gate_allowed=True`. | see [§ vulnerability gate](cli_reference.md#vulnerability-gate-production-default--override---allow-vulnerable) |
| `TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS` | `0` | Lets an AWS bake finish without `snpguest` / `nitro-tpm-attest`, producing an image that cannot attest. Read **on the bake instance**, not on your workstation. | `scripts/snp_aws/setup_snp_aws.sh`, `scripts/gpu_cc_aws/setup_gpu_cc_aws.sh` |
| `TEE_CRAFTER_SKIP_POST_DESTROY_SHRED` | `1` | Leaves recoverable secret bytes on disk after `destroy`. | `cli_reference.md` § post-destroy secret shred |
| `TEE_CRAFTER_ALLOW_NO_SECURE_BOOT` | `1` | Deploys an AMI whose Secure-Boot posture is unknown or off. Named separately from `TF_VAR_enable_secure_boot` precisely so the gate cannot be disabled as a side effect of setting the Terraform variable for another reason. | `cli/commands/deploy/validators.py:36` |
| `TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI` | `1` | Deploys onto a base AMI that never went through `bake-ami`, so none of the hardening, attestation tooling or measurement capture is present. | `cli/commands/deploy/deploy_helpers.py:153` |
| `TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS` | `1` | Accepts an Intel TCB status the evaluator could not verify, on the DCAP platforms (`sgx-azure`, `tdx-*`, `gpu-cc-gcp`). | `templates/common/tee_crafter_tcb_eval.py:160` |
| `TEE_CRAFTER_SECRETS_FAIL_OPEN` | `1` | The secret-bootstrap oneshot lets the workload start even when sealed `.env` delivery failed, so the workload runs without its secrets rather than not at all. | `templates/common/tee_crafter_secret_bootstrap.py:42` |
| `TEE_CRAFTER_SIEM_FAIL_OPEN` | `1` | The workload serves requests with a dark SIEM collector, so privileged actions can go unlogged. Reverts the fail-closed gate. | `cli/commands/deploy/siem_mode.py:355` |
| `TEE_CRAFTER_SKIP_IMAGE_STALENESS_CHECK` / `TEE_CRAFTER_SKIP_STALE_IMAGE_CHECK` | `1` | Not a TEE control, but the trap that produced two clean-looking runs executing deleted code: the CLI image is built from `apps/cli`, not bind-mounted, so skipping the fingerprint check runs the *previous* build. | `cli/main.py:116`, `cli/stale_image_check.py:47` |

### Knobs that go the other way

Not every switch loosens. These are opt-in hardening, off by default because
they refuse configurations that some providers legitimately hand you:

| Variable | Value | What it adds |
|---|---|---|
| `TEE_CRAFTER_SNP_REQUIRE_SMT_DISABLED` | `1` | Makes a guest policy that permits SMT (SEV-SNP `POLICY` bit 16) fatal rather than a warning. | 
| `TEE_CRAFTER_SNP_EXPECTED_HOST_DATA` | hex | Pins the SNP report's `HOST_DATA` field. |
| `TEE_CRAFTER_SNP_EXPECTED_ID_KEY_DIGEST` / `_AUTHOR_KEY_DIGEST` | hex | Pins the SNP ID-block key digests. |
| `TEE_CRAFTER_EXPECTED_NITROTPM_PCRS` | `idx:hex,…` | Overrides the bake-captured NitroTPM PCR reference on `gpu-cc-aws` at runtime. |
| `TEE_CRAFTER_EXPECTED_VTPM_PCRS` | `idx:hex,…` | Same, for the `gpu-cc-gcp` vTPM bundle. |
| `TEE_CRAFTER_ARK_MILAN_SHA256` / `_GENOA_SHA256` | colon-hex | Overrides the pinned AMD Root Key fingerprint at bake time, for a rotation that lands before this repo updates. Read on the bake instance. Verify by subject first — it must say `ARK` (see [snp_flow.md](snp_flow.md#two-pinned-supply-chain-values-were-wrong-and-the-gate-is-how-we-found-out)). |
| `TEE_CRAFTER_VULN_STRICT` | `1` | Restores zero-tolerance vulnerability gating. |
