#!/usr/bin/env bash
set -euxo pipefail

# GPU CC host setup for GCP (A3 High-GPU + Intel TDX + NVIDIA CC).
# Installs NVIDIA drivers, CUDA toolkit, nv-attestation-sdk, TDX guest
# modules, Python venv, Docker, seccomp/AppArmor profiles, udev rules,
# and systemd units with full sandbox hardening — matching CPU TEE scripts.

export DEBIAN_FRONTEND=noninteractive

echo "=== TEE-Crafter: GPU CC (GCP A3 + Intel TDX + NVIDIA CC) host setup ==="

# --- Wait for cloud-init and apt locks ---
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

BASE_DIR="/opt/tee-crafter-gpu-cc"

# --- Service user ---
id -u tee_enclave &>/dev/null || useradd -r -m -d "$BASE_DIR" -s /usr/sbin/nologin tee_enclave
echo "✓ tee_enclave user ready"

# --- System packages ---
#
# tpm2-tools is not optional here even though nothing in this script calls it:
# the runtime app shells out to `tpm2_pcrread` to build the vTPM PCR bundle it
# publishes in the RA-TLS certificate (`_get_vtpm_pcrs` in
# templates/gpu_cc/gcp/app.template.py).  Without the binary that function
# returns an empty map, the certificate carries an empty PCR bundle, and the
# client's `verify_vtpm_pcrs` fails closed on "empty PCR map" -- so every
# deploy from an image baked without it would be refused at the last step,
# after paying for an A3 instance.
apt-get update -y
apt-get install -y \
    python3-venv python3-dev build-essential curl wget \
    pkg-config libssl-dev ca-certificates \
    gnupg lsb-release tpm2-tools \
    pigz zstd

# --- NVIDIA driver + CUDA toolkit ---
echo "Installing NVIDIA CUDA keyring..."
DISTRO="ubuntu$(lsb_release -rs | tr -d '.')"
ARCH="x86_64"
wget -q "https://developer.download.nvidia.com/compute/cuda/repos/${DISTRO}/${ARCH}/cuda-keyring_1.1-1_all.deb" -O /tmp/cuda-keyring.deb
dpkg -i /tmp/cuda-keyring.deb
apt-get update -y

# Detect Secure Boot. Default deploys ship with SB OFF for *reliability* —
# our deterministic driver-version pin comes from NVIDIA's CUDA apt repo
# (DKMS, unsigned) which kernel lockdown rejects.  Operators can opt in to
# SB via the ``enable_secure_boot`` Terraform variable; this script then
# falls through to Canonical's pre-built signed packages
# (linux-modules-nvidia-<VER>-<KREL>, where ${KERNEL_RELEASE} encodes the
# GCP kernel flavour) and only resorts to the DKMS path when no signed
# candidate matches the running kernel ABI.  See docs/security.md §15.1
# for the full trade-off analysis.
SB_ENABLED="no"
LOCKDOWN=$(cat /sys/kernel/security/lockdown 2>/dev/null || true)
if echo "$LOCKDOWN" | grep -qE '\[integrity\]|\[confidentiality\]'; then
    SB_ENABLED="yes"
    echo "Secure Boot detected via kernel lockdown mode: $LOCKDOWN"
elif command -v mokutil &>/dev/null && mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then
    SB_ENABLED="yes"
    echo "Secure Boot detected via mokutil"
fi
KERNEL_RELEASE=$(uname -r)
KERNEL_SERIES=$(echo "$KERNEL_RELEASE" | cut -d. -f1-2)
KERNEL_FLAVOR=$(echo "$KERNEL_RELEASE" | sed 's/^[0-9]*\.[0-9]*\.[0-9]*-[0-9]*-//')
echo "Kernel: ${KERNEL_RELEASE}, series: ${KERNEL_SERIES}, flavor: ${KERNEL_FLAVOR}, Secure Boot: ${SB_ENABLED}"

if [ "$SB_ENABLED" = "yes" ]; then
    echo "Secure Boot enabled — installing pre-built Canonical-signed NVIDIA kernel module..."
    SIGNED_INSTALLED=false

    # Use kernel-version-specific packages (e.g., linux-modules-nvidia-570-server-open-6.8.0-1037-gcp).
    # ${KERNEL_RELEASE} already encodes the GCP kernel flavour; the metapackages
    # (e.g. linux-modules-nvidia-570-gcp-6.8) are dummy transitional packages that
    # don't install actual modules.
    for variant in "570-server-open" "570-open" "570-server" "565-server-open" "565-server" "535-server-open" "535-open"; do
        PKG="linux-modules-nvidia-${variant}-${KERNEL_RELEASE}"
        echo "  Checking: $PKG"
        if apt-cache show "$PKG" >/dev/null 2>&1; then
            echo "  Installing: $PKG"
            if apt-get install -y "$PKG"; then
                SIGNED_INSTALLED=true
                echo "  ✓ $PKG installed successfully"
                break
            else
                echo "  ✗ $PKG install failed, trying next candidate..."
            fi
        fi
    done

    if [ "$SIGNED_INSTALLED" = "true" ]; then
        NVIDIA_KM_VER=$(dpkg -l 'nvidia-kernel-common-*' 2>/dev/null \
            | awk '/^ii/{print $2}' | head -1 | sed 's/^nvidia-kernel-common-//')
        echo "  Kernel module driver version: ${NVIDIA_KM_VER:-unknown}"
        apt-get install -y --no-install-recommends \
            "nvidia-utils-${NVIDIA_KM_VER:-570-server}" 2>/dev/null || \
            apt-get install -y --no-install-recommends nvidia-utils-570-server 2>/dev/null || \
            apt-get install -y --no-install-recommends nvidia-utils-550
    else
        echo "WARNING: No pre-built signed module for ${KERNEL_RELEASE}; DKMS fallback (may fail at boot)"
        apt-get install -y --no-install-recommends nvidia-headless-550-open nvidia-utils-550
    fi
else
    echo "Secure Boot not enabled — installing NVIDIA driver via DKMS..."
    apt-get install -y --no-install-recommends nvidia-headless-550-open nvidia-utils-550
fi

apt-get install -y --no-install-recommends cuda-toolkit-12-4

modprobe nvidia 2>/dev/null || true
echo "Verifying NVIDIA driver..."
nvidia-smi || echo "WARNING: nvidia-smi failed (expected at bake time if no GPU present)"

echo "nvidia" >> /etc/modules-load.d/nvidia.conf 2>/dev/null || true

# --- TDX guest kernel modules ---
echo "Loading TDX guest modules..."
apt-get install -y "linux-modules-extra-$(uname -r)" 2>/dev/null || \
    echo "WARNING: linux-modules-extra not available for $(uname -r)"
modprobe tdx_guest 2>/dev/null || true
modprobe configfs 2>/dev/null || true
modprobe tsm_report 2>/dev/null || true

cat > /etc/modules-load.d/tee-crafter-tdx.conf <<MODS
tdx_guest
configfs
tsm_report
MODS

# --- TDX guest device permissions (restrictive, not world-writable) ---
echo "Setting up TDX guest device access..."
for dev in /dev/tdx-guest /dev/tdx_guest; do
    if [ -c "$dev" ]; then
        chmod 0660 "$dev"
        chgrp kvm "$dev" 2>/dev/null || chgrp tee_enclave "$dev"
        echo "✓ TDX device $dev: permissions set (0660)"
    fi
done
usermod -aG kvm tee_enclave 2>/dev/null || true

if [ -d /sys/kernel/config/tsm/report ]; then
    chgrp kvm /sys/kernel/config/tsm/report 2>/dev/null || true
    chmod 0775 /sys/kernel/config/tsm/report 2>/dev/null || true
    echo "✓ configfs-tsm: available and group-writable"
fi

# --- udev rules for persistent TDX device permissions ---
cat > /etc/udev/rules.d/90-tdx-guest.rules <<UDEV
KERNEL=="tdx_guest", MODE="0660", GROUP="kvm"
KERNEL=="tdx-guest", MODE="0660", GROUP="kvm"
UDEV
udevadm control --reload-rules 2>/dev/null || true
udevadm trigger 2>/dev/null || true

# --- Python virtual environment ---
# Pre-install the GPU ML stack (torch + CUDA wheels + common ML utilities)
# directly into the baked image's venv.  At deploy time the user's
# requirements.txt typically pulls in torch + the full nvidia-cu12 wheel set
# (~2.9 GB); shipping that over an IAP tunnel is slow and times out SCP.
# Baking once trades ~2.9 GB image size for near-instant deploy uploads —
# the deploy-time dedupe pass reads /etc/tee_crafter/image_pip_frozen.txt
# and only uploads wheels not already on the image.  See
# docs/optimizations.md §1.
mkdir -p "$BASE_DIR"/{app,wheels}
python3 -m venv "$BASE_DIR/venv"
"$BASE_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
"$BASE_DIR/venv/bin/pip" install \
    "nv-attestation-sdk==2.7.0" \
    "pyjwt[crypto]>=2.7.0,<2.8.0"

echo "Pre-installing GPU ML stack (torch + CUDA wheels) into bake venv..."
"$BASE_DIR/venv/bin/pip" install --no-cache-dir \
    "torch==2.5.1" \
    "torchvision==0.20.1" \
    "triton==3.1.0" \
    "numpy<2" \
    "Pillow" \
    "safetensors" \
    "huggingface-hub" \
    "transformers" \
    "tokenizers" \
    "sentencepiece" \
    "scipy" \
    "scikit-learn" || {
        echo "WARNING: GPU ML stack pre-install failed; deploys will fall back to host-side download."
}

mkdir -p /etc/tee_crafter
"$BASE_DIR/venv/bin/pip" freeze --all 2>/dev/null \
    > /etc/tee_crafter/image_pip_frozen.txt || true
chmod 0644 /etc/tee_crafter/image_pip_frozen.txt 2>/dev/null || true
echo "✓ Image pip manifest captured: $(wc -l < /etc/tee_crafter/image_pip_frozen.txt 2>/dev/null || echo 0) packages"

# --- Pre-pull common Docker base images used by handler / container deploys ---
# Saves ~30-60 s at deploy time by avoiding a ~3 GB nvidia/cuda pull over
# CVM-restricted egress.  Best-effort — silent if registry unreachable.
if command -v docker >/dev/null 2>&1; then
    echo "Pre-pulling GPU CC base images (handler-mode prewarm)..."
    systemctl start docker 2>/dev/null || service docker start 2>/dev/null || true
    sleep 3
    for img in \
        "nvidia/cuda:12.4.1-runtime-ubuntu22.04" \
        "nvidia/cuda:12.4.1-base-ubuntu22.04" \
    ; do
        echo "  -> $img"
        docker pull "$img" 2>&1 | tail -2 || echo "  (skip, registry unreachable)"
    done
    docker image ls --format '{{.Repository}}:{{.Tag}} {{.Size}}' \
        > /etc/tee_crafter/image_docker_prewarmed.txt 2>/dev/null || true
    chmod 0644 /etc/tee_crafter/image_docker_prewarmed.txt 2>/dev/null || true
    echo "✓ Pre-pulled $(wc -l < /etc/tee_crafter/image_docker_prewarmed.txt 2>/dev/null || echo 0) docker images"
fi

# --- Log directory ---
mkdir -p /var/log/tee_crafter
chown tee_enclave:tee_enclave /var/log/tee_crafter
chmod 750 /var/log/tee_crafter

# --- Lock down permissions ---
chown -R tee_enclave:tee_enclave "$BASE_DIR"
chmod 755 "$BASE_DIR" "$BASE_DIR/app"

# --- Enable NVIDIA persistence daemon ---
systemctl enable nvidia-persistenced 2>/dev/null || true

# --- Systemd service with full sandbox hardening ---
cat > /etc/systemd/system/tee-crafter-gpu-cc.service <<'UNIT'
__SYSTEMD_UNIT__
UNIT

systemctl daemon-reload

# --- OS-level hardening (persist across reboots) ---
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

# --- Docker Engine for container-mode deployments ---
echo "--- Installing Docker Engine (container mode support) ---"
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y ca-certificates curl gnupg 2>/dev/null || true
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io
fi
systemctl enable docker 2>/dev/null || true
systemctl start docker 2>/dev/null || true
usermod -aG docker tee_enclave 2>/dev/null || true

# --- NVIDIA Container Toolkit (required for --gpus / CDI) ---
echo "--- Installing NVIDIA Container Toolkit ---"
if ! dpkg -l nvidia-container-toolkit >/dev/null 2>&1; then
  curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
    | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg 2>/dev/null || true
  DIST=$(. /etc/os-release; echo "${ID}${VERSION_ID}")
  echo "deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://nvidia.github.io/libnvidia-container/stable/deb/\$(ARCH) /" \
    | sed "s|\\\$(ARCH)|$(dpkg --print-architecture)|g" \
    > /etc/apt/sources.list.d/nvidia-container-toolkit.list
  apt-get update -y
  apt-get install -y nvidia-container-toolkit
fi
nvidia-ctk runtime configure --runtime=docker 2>/dev/null || true
nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml 2>/dev/null || true
systemctl restart docker 2>/dev/null || true
echo "NVIDIA Container Toolkit: $(nvidia-ctk --version 2>/dev/null || echo 'installed')"

cat > /etc/systemd/system/nvidia-cdi-generate.service <<'CDI_UNIT'
[Unit]
Description=Regenerate NVIDIA CDI spec on boot
After=nvidia-persistenced.service
Wants=nvidia-persistenced.service

[Service]
Type=oneshot
ExecStart=/usr/bin/nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
CDI_UNIT
systemctl daemon-reload
systemctl enable nvidia-cdi-generate.service 2>/dev/null || true

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

# --- Bake marker ---
mkdir -p /etc/tee_crafter
echo "gpu-cc-gcp-$(date -u +%Y%m%d-%H%M%S)" > /etc/tee_crafter/baked_gpu_cc_gcp

echo "=== TEE-Crafter GPU CC GCP setup complete ==="
