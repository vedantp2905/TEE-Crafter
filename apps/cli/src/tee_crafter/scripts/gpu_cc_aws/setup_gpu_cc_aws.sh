#!/bin/bash
set -euo pipefail

# GPU CC host setup for AWS (P5/P5en/P6 + NitroTPM + NVIDIA CC).
# Installs NVIDIA drivers, CUDA toolkit, nv-attestation-sdk, tpm2-tools,
# Python venv, Docker, seccomp/AppArmor profiles, and systemd units with
# full sandbox hardening — matching the security posture of CPU TEE scripts.

export HOME="${HOME:-/root}"
export DEBIAN_FRONTEND=noninteractive

echo "=== TEE-Crafter: GPU CC (AWS P5/P5en/P6 + NitroTPM + NVIDIA CC) host setup ==="

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
apt-get update -y
apt-get install -y \
    python3-venv python3-dev build-essential curl wget \
    pkg-config libssl-dev tpm2-tools ca-certificates \
    gnupg lsb-release \
    pigz zstd

# --- NVIDIA driver + CUDA toolkit ---
echo "Installing NVIDIA CUDA keyring..."
DISTRO="ubuntu$(lsb_release -rs | tr -d '.')"
ARCH="x86_64"
wget -q "https://developer.download.nvidia.com/compute/cuda/repos/${DISTRO}/${ARCH}/cuda-keyring_1.1-1_all.deb" -O /tmp/cuda-keyring.deb
dpkg -i /tmp/cuda-keyring.deb
apt-get update -y

# Detect Secure Boot — AWS CVM images may enable it, blocking unsigned DKMS modules.
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

    # Use kernel-version-specific packages (e.g., linux-modules-nvidia-570-server-open-6.8.0-1044-azure-fde).
    # The metapackages (*-<flavor>-<series>) are dummy transitional packages that don't install actual modules.
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

# --- NitroTPM verification + group access ---
echo "Setting up NitroTPM access..."
usermod -aG tss tee_enclave 2>/dev/null || true
# sha384, not sha256: a NitroTPM attestation document reports `digest: SHA384`
# and its PCR values are 48 bytes, so reading the sha256 bank here produced a
# value that could never be compared against the document.
tpm2_pcrread sha384:0 2>/dev/null && echo "✓ NitroTPM: available" || echo "NitroTPM: not available at bake time (expected)"

# --- Python virtual environment ---
# Pre-install the GPU ML stack (torch + CUDA wheels + common ML utilities)
# directly into the baked image's venv.  Even though AWS deploys upload
# bundles via S3 (gigabit) rather than Bastion, the 2.9 GB transfer still
# adds 30-90 s of latency and S3 egress cost per deploy.  Baking once
# makes deploy uploads delta-only.  See docs/optimizations.md §1.
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
# Saves ~30-60 s at deploy time on the user's first build.  Even though
# AWS GPU-CC deploys can pull through S3-VPC-endpoint (no CVM egress
# restriction), the docker.io registry roundtrip is still the dominant
# cost on cold caches.  Best-effort — silent if registry unreachable.
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
chmod 700 "$BASE_DIR"

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

__NITRO_TPM_ATTEST_INSTALL__

# --- Verify the attestation tooling actually landed (fail closed) ---
#
# This platform's CPU-side evidence is a NitroTPM attestation document, which
# the client verifies against the pinned AWS Nitro root. Without the binary
# there is no document, and the client is then asked to accept an unattested
# CPU host -- which is the situation this platform was stuck in before the
# installer was added here at all.
REQUIRE_ATTESTATION_TOOLS="${TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS:-1}"
echo "--- attestation tooling ---"
echo "nitro-tpm-attest:  $(command -v nitro-tpm-attest || echo MISSING)"
echo "tpm2-tools:        $(command -v tpm2_pcrread || echo MISSING)"
if ! command -v nitro-tpm-attest >/dev/null 2>&1; then
    if [ "$REQUIRE_ATTESTATION_TOOLS" = "0" ]; then
        echo "WARNING: nitro-tpm-attest missing — continuing because TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS=0" >&2
    else
        echo "FATAL: nitro-tpm-attest missing — this image could not produce CPU attestation evidence." >&2
        [ -f /var/log/tee-crafter/nitrotpm-build-failed.log ] && \
            tail -30 /var/log/tee-crafter/nitrotpm-build-failed.log >&2
        echo "Set TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS=0 to bake without it on purpose." >&2
        exit 1
    fi
fi

# --- Bake marker ---
mkdir -p /etc/tee_crafter
echo "baked_gpu_cc_aws $(date -u +%Y%m%dT%H%M%SZ)" > /etc/tee_crafter/baked_gpu_cc_aws

echo "=== TEE-Crafter GPU CC AWS setup complete ==="
