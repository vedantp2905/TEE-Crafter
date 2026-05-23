#!/usr/bin/env bash
set -euxo pipefail

# Bake-time setup script for GCP Intel TDX Confidential VMs.
# Installs Python venv, cryptography, and creates systemd service
# unit for the TDX RA-TLS application.
# (TDX uses configfs-tsm or /dev/tdx-guest; no snpguest needed.)

export DEBIAN_FRONTEND=noninteractive

# --- Wait for cloud-init and apt locks to release ---
echo "Waiting for cloud-init to finish..."
cloud-init status --wait 2>/dev/null || true

echo "Waiting for apt locks to release..."
for i in $(seq 1 60); do
    if ! fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock 2>/dev/null; then
        break
    fi
    echo "  apt lock held, waiting... ($i/60)"
    sleep 5
done

systemctl stop unattended-upgrades 2>/dev/null || true
systemctl disable unattended-upgrades 2>/dev/null || true
killall -9 apt-get 2>/dev/null || true
killall -9 dpkg 2>/dev/null || true
sleep 2
dpkg --configure -a 2>/dev/null || true

BASE_DIR="/opt/tee-crafter-tdx"

# Create service user
id -u tee_enclave &>/dev/null || useradd -r -m -d "$BASE_DIR" -s /usr/sbin/nologin tee_enclave

# System packages
apt-get update -y
apt-get install -y \
    python3-venv python3-dev build-essential curl \
    pkg-config libssl-dev \
    pigz zstd

# Create directory structure
mkdir -p "$BASE_DIR"/{app,wheels}

# Python virtual environment
python3 -m venv "$BASE_DIR/venv"
"$BASE_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
"$BASE_DIR/venv/bin/pip" install "cryptography>=42.0,<44"

mkdir -p /etc/tee_crafter
"$BASE_DIR/venv/bin/pip" freeze --all 2>/dev/null \
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

# TDX guest device permissions (may not exist at bake time)
for dev in /dev/tdx-guest /dev/tdx_guest; do
    if [ -c "$dev" ]; then
        chmod 0660 "$dev"
        chgrp kvm "$dev" 2>/dev/null || chgrp tee_enclave "$dev"
    fi
done
usermod -aG kvm tee_enclave 2>/dev/null || true

# Systemd service unit
cat > /etc/systemd/system/tee-crafter-tdx.service <<'EOF'
__SYSTEMD_UNIT__
EOF

systemctl daemon-reload
# Service will be enabled at deploy time, not during image baking

# udev rules for TDX device access (avoids CAP_DAC_OVERRIDE)
cat > /etc/udev/rules.d/90-tdx-guest.rules <<UDEV
KERNEL=="tdx_guest", MODE="0660", GROUP="kvm"
KERNEL=="tdx-guest", MODE="0660", GROUP="kvm"
UDEV
udevadm control --reload-rules 2>/dev/null || true
udevadm trigger 2>/dev/null || true

# Lock down ownership
chown -R tee_enclave:tee_enclave "$BASE_DIR"
chmod 755 "$BASE_DIR" "$BASE_DIR/app"

# OS hardening (persist across reboots)
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

# Docker Engine for container-mode deployments
echo "--- Installing Docker Engine (container mode support) ---"
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y ca-certificates curl gnupg 2>/dev/null || true
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io
fi
systemctl enable docker 2>/dev/null || true
systemctl start docker 2>/dev/null || true
usermod -aG docker tee_enclave 2>/dev/null || true

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

# Bake marker
mkdir -p /etc/tee_crafter
echo "tdx-gcp-$(date -u +%Y%m%d-%H%M%S)" > /etc/tee_crafter/baked_tdx

echo "=== TDX GCP bake setup complete ==="
