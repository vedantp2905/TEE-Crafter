#!/usr/bin/env bash
# TDX host setup for Ubuntu 22.04/24.04 on Azure DCesv6 confidential VMs.
# Installs Python deps, TDX guest attestation tools, and creates a systemd
# service to run the TEE-Crafter app inside the Trust Domain.
set -euo pipefail

ENCLAVE_USER="tee_enclave"
APP_DIR="/opt/tee-crafter-tdx"
VENV_DIR="$APP_DIR/venv"

echo "=== TEE-Crafter TDX Setup (Ubuntu / Azure DCesv6) ==="

# 1. System updates
echo "--- [1/8] System update ---"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# 2. Install Python 3 and pip (system packages only — do NOT pip-install
#    into system python; cloud-init and waagent depend on it).
echo "--- [2/8] Python 3 + pip ---"
apt-get install -y python3 python3-pip python3-venv python3-dev build-essential pigz zstd

# 3. Install TDX guest kernel modules and tools
echo "--- [3/8] TDX guest attestation tools ---"

# The tdx_guest module lives in linux-modules-extra; install it for the
# currently running kernel so /dev/tdx-guest becomes available.
apt-get install -y "linux-modules-extra-$(uname -r)" 2>/dev/null || true

# Load TDX guest module (creates /dev/tdx-guest on kernels 6.x+)
modprobe tdx_guest 2>/dev/null || true

# configfs-tsm support (kernel 6.7+) — load configfs first, then tsm_report
modprobe configfs 2>/dev/null || true
modprobe tsm_report 2>/dev/null || true

# Persist module loading across reboots so deploy-time modprobe is unnecessary
cat > /etc/modules-load.d/tee-crafter-tdx.conf <<MODS
tdx_guest
configfs
tsm_report
MODS

# Install tpm2-tools: Azure TDX CVMs expose TDX reports via the vTPM at
# NV index 0x01400001. This is the fallback if /dev/tdx-guest is absent.
apt-get install -y tpm2-tools 2>/dev/null || true

# Microsoft guest attestation: AttestationClient (the only route to a
# verifiable attestation on a paravisor TD) and AzureAttestSKR (Secure Key
# Release).  Shared with snp-azure and gpu-cc-azure -- see
# scripts/common/azure_guest_attestation.sh.
GA_PURPOSE="attestation (there is no DCAP quote on an Azure paravisor TD) and secure key release"
__AZURE_GUEST_ATTESTATION__

# Verify TDX availability (at least one path must work)
TDX_AVAILABLE=false
if [ -c /dev/tdx-guest ] || [ -e /dev/tdx-guest ]; then
    echo "  /dev/tdx-guest device available"
    TDX_AVAILABLE=true
elif [ -c /dev/tdx_guest ] || [ -e /dev/tdx_guest ]; then
    echo "  /dev/tdx_guest device available"
    TDX_AVAILABLE=true
elif [ -d /sys/kernel/config/tsm/report ]; then
    echo "  configfs-tsm interface available"
    TDX_AVAILABLE=true
elif command -v tpm2_nvread >/dev/null 2>&1; then
    echo "  tpm2-tools available (Azure vTPM fallback)"
    TDX_AVAILABLE=true
fi

if [ "$TDX_AVAILABLE" = false ]; then
    echo "WARNING: No TDX attestation path found."
    echo "  Tried: /dev/tdx-guest, /dev/tdx_guest, configfs-tsm, tpm2-tools"
    echo "  Attestation will fail at runtime."
fi

# Which evidence format this image can actually produce. On Azure the answer is
# almost always azure-guest, and saying so here saves the next reader the three
# live runs it took to find out.
if [ -c /dev/tdx-guest ] || [ -c /dev/tdx_guest ] || [ -d /sys/kernel/config/tsm/report ]; then
    echo "  Evidence: DCAP quote obtainable (TEE_CRAFTER_TDX_EVIDENCE_FORMAT=dcap works)"
else
    echo "  Evidence: no DCAP path -- this is a paravisor CVM."
    echo "            Deploy with TEE_CRAFTER_TDX_EVIDENCE_FORMAT=azure-guest."
fi

echo "  Kernel: $(uname -r)"
echo "  TDX modules: $(lsmod | grep -E 'tdx|tsm' || echo 'none loaded')"
echo "  TDX devices: $(ls /dev/tdx* 2>/dev/null || echo 'none')"
echo "  tpm2-tools: $(command -v tpm2_nvread 2>/dev/null || echo 'not installed')"

# 4. Create dedicated enclave user
echo "--- [4/8] Creating enclave user ---"
if ! id -u "$ENCLAVE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$ENCLAVE_USER"
fi

# Grant TDX device access to the enclave user via kvm group
for dev in /dev/tdx-guest /dev/tdx_guest; do
    if [ -c "$dev" ]; then
        chmod 0660 "$dev"
        chgrp kvm "$dev" 2>/dev/null || chgrp "$ENCLAVE_USER" "$dev"
    fi
done
usermod -aG kvm "$ENCLAVE_USER" 2>/dev/null || true

# vTPM access for the guest-attestation client.
#
# On an Azure paravisor CVM this is not an optional extra path -- it is the only
# source of attestation evidence, and AttestationClient reads the HCL report out
# of the vTPM to build its request. The service runs as the unprivileged
# $ENCLAVE_USER, so without this the attestation call fails with a permission
# error at verify time, on a VM that has already been paid for.
#
# /dev/tpmrm0 is the resource-managed device and the one tpm2-tss uses; Ubuntu
# ships it as tss:tss 0660. Group membership is what grants access here -- no
# capability and no mode-widening to other users.
if getent group tss >/dev/null 2>&1; then
    usermod -aG tss "$ENCLAVE_USER" 2>/dev/null || true
fi
for dev in /dev/tpmrm0 /dev/tpm0; do
    if [ -c "$dev" ]; then
        chmod 0660 "$dev"
        chgrp tss "$dev" 2>/dev/null || chgrp "$ENCLAVE_USER" "$dev"
    fi
done

# 5. Set up application directory
echo "--- [5/8] Application directory ---"
mkdir -p "$APP_DIR"

# 6. Create Python virtual environment and install dependencies
echo "--- [6/8] Python venv + dependencies ---"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install "cryptography>=42.0,<44" "pydantic>=2.7,<3"

# Install user requirements if present
if [ -f "$APP_DIR/app/requirements.txt" ]; then
    "$VENV_DIR/bin/pip" install -r "$APP_DIR/app/requirements.txt"
fi

mkdir -p /etc/tee_crafter
"$VENV_DIR/bin/pip" freeze --all 2>/dev/null \
    > /etc/tee_crafter/image_pip_frozen.txt || true
chmod 0644 /etc/tee_crafter/image_pip_frozen.txt 2>/dev/null || true

# --- Pre-pull common Docker base images for handler / container builds ---
# Saves ~10-20 s per first build at deploy time. Best-effort.
if command -v docker >/dev/null 2>&1; then
    echo "Pre-pulling handler-mode base images..."
    systemctl start docker 2>/dev/null || service docker start 2>/dev/null || true
    sleep 2
    for img in \
        "python:3.12-alpine" \
        "python:3.12-slim" \
        "rust:alpine" \
    ; do
        docker pull "$img" 2>&1 | tail -1 || true
    done
    docker image ls --format '{{.Repository}}:{{.Tag}} {{.Size}}' \
        > /etc/tee_crafter/image_docker_prewarmed.txt 2>/dev/null || true
fi

# 7. Create systemd service for the TDX app
echo "--- [7/8] Creating systemd service ---"
cat > /etc/systemd/system/tee-crafter-tdx.service <<'UNIT'
__SYSTEMD_UNIT__
UNIT

systemctl daemon-reload

# OS-level hardening (persist across reboots)
cat > /etc/sysctl.d/99-tee-crafter.conf <<'SYSCTL'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
SYSCTL
sysctl --system 2>/dev/null || true

# 7b. Ensure configfs-tsm is writable for TDX attestation (restricted to enclave user)
if [ -d "/sys/kernel/config/tsm/report" ]; then
  chgrp "$ENCLAVE_USER" /sys/kernel/config/tsm/report 2>/dev/null || true
  chmod 0770 /sys/kernel/config/tsm/report
  echo "configfs-tsm (/sys/kernel/config/tsm/report) set to group-writable for $ENCLAVE_USER"
fi

# 8. Ensure /dev/tdx_guest permissions persist across reboots
echo "--- [8/8] udev rules for TDX device ---"
cat > /etc/udev/rules.d/90-tdx-guest.rules <<UDEV
KERNEL=="tdx_guest", MODE="0660", GROUP="kvm"
KERNEL=="tdx-guest", MODE="0660", GROUP="kvm"
# The vTPM carries the only attestation evidence a paravisor CVM has; the chgrp
# above does not survive a reboot without this.
KERNEL=="tpmrm0", MODE="0660", GROUP="tss"
KERNEL=="tpm0", MODE="0660", GROUP="tss"
UDEV

udevadm control --reload-rules 2>/dev/null || true

# 9. Ensure cloud-init and waagent are healthy (critical for image capture)
echo "--- [9/9] Verifying cloud-init and waagent ---"
if ! python3 -c "import requests" 2>/dev/null; then
  echo "WARNING: System python3 'requests' module missing — reinstalling..."
  apt-get install -y --reinstall python3-requests 2>/dev/null || true
fi
if ! python3 -c "import cloudinit" 2>/dev/null; then
  echo "WARNING: cloud-init broken — reinstalling..."
  apt-get install -y --reinstall cloud-init 2>/dev/null || true
fi
systemctl enable walinuxagent 2>/dev/null || systemctl enable waagent 2>/dev/null || true
systemctl start walinuxagent 2>/dev/null || systemctl start waagent 2>/dev/null || true
echo "waagent status: $(systemctl is-active walinuxagent 2>/dev/null || systemctl is-active waagent 2>/dev/null || echo 'unknown')"
echo "cloud-init check: $(cloud-init status 2>&1 | head -1 || echo 'unavailable')"

# 10. Docker Engine for container-mode deployments
echo "--- [10/10] Installing Docker Engine (container mode support) ---"
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io
fi
systemctl enable docker 2>/dev/null || true
systemctl start docker 2>/dev/null || true
usermod -aG docker "$ENCLAVE_USER" 2>/dev/null || true

# --- Custom seccomp profile for user containers ---
mkdir -p /etc/tee_crafter
cat > /etc/tee_crafter/seccomp-container.json <<'SECCOMP_EOF'
__SECCOMP_PROFILE__
SECCOMP_EOF

# --- AppArmor profile for user containers ---
cat > /etc/apparmor.d/tee-crafter-container <<'APPARMOR_EOF'
__APPARMOR_PROFILE__
APPARMOR_EOF
cat > /etc/apparmor.d/tee-crafter-batch-container <<'APPARMOR_BATCH_EOF'
__APPARMOR_BATCH_PROFILE__
APPARMOR_BATCH_EOF
if command -v apparmor_parser >/dev/null 2>&1; then
  for _prof in tee-crafter-container tee-crafter-batch-container; do
    apparmor_parser -r "/etc/apparmor.d/${_prof}" || {
      echo "FATAL: AppArmor profile ${_prof} failed to parse" >&2
      exit 1
    }
  done
else
  echo "WARNING: apparmor_parser not installed; container profiles NOT loaded" >&2
fi

# Container-mode systemd unit (loads and runs user container if present)
cat > /etc/systemd/system/tee-crafter-container.service <<'CONTAINER_UNIT'
__CONTAINER_UNIT__
CONTAINER_UNIT

# Secret bootstrap oneshot: delivers sealed/baked .env + BYOK DEK to the
# workload (fail-closed). The container unit Requires= this on CVM platforms.
cat > /etc/systemd/system/tee-crafter-secrets.service <<'SECRETS_UNIT'
__SECRETS_UNIT__
SECRETS_UNIT

systemctl daemon-reload
echo "Docker installed: $(docker --version 2>/dev/null || echo 'failed')"

# 11. Write bake marker so deploy-time code can skip redundant setup
mkdir -p /etc/tee_crafter
cat > /etc/tee_crafter/baked_tdx <<MARKER
platform=tdx
baked_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kernel=$(uname -r)
tpm2_tools=$(command -v tpm2_nvread 2>/dev/null || echo missing)
tdx_available=$TDX_AVAILABLE
MARKER

echo "=== TEE-Crafter TDX setup complete ==="
echo "  App directory:  $APP_DIR"
echo "  Python venv:    $VENV_DIR"
echo "  Systemd unit:   tee-crafter-tdx.service"
echo "  TDX available:  $TDX_AVAILABLE"
