#!/usr/bin/env bash
set -euo pipefail

# GPU CC host setup for Azure (NCC H100 v5 + AMD SEV-SNP + NVIDIA CC).
# Installs NVIDIA drivers, CUDA toolkit, nv-attestation-sdk, snpguest
# (pinned, only when /dev/sev-guest exists — skipped on Azure Hyper-V), tpm2-tools, AMD root certs, Python venv, Docker, seccomp/
# AppArmor profiles, and systemd units with full sandbox hardening —
# matching the security posture of CPU TEE scripts.

export HOME="${HOME:-/root}"
export DEBIAN_FRONTEND=noninteractive

echo "=== TEE-Crafter: GPU CC (Azure NCC H100 v5 + SEV-SNP + NVIDIA CC) host setup ==="

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
    python3-venv python3-dev build-essential curl wget git \
    pkg-config libssl-dev ca-certificates tpm2-tools \
    gnupg lsb-release \
    pigz zstd

apt-get install -y "linux-modules-extra-$(uname -r)" 2>/dev/null || \
    echo "WARNING: linux-modules-extra not available for $(uname -r)"

# Microsoft guest attestation, for AzureAttestSKR only.
#
# gpu-cc-azure does *not* need AttestationClient: the CPU side reads a real
# SEV-SNP ATTESTATION_REPORT and the GPU side gets an NRAS EAT JWT. What it
# cannot do without this block is Secure Key Release -- Key Vault wraps a
# released key to `TpmEphemeralEncryptionKey`, sealed to the vTPM, so
# `--byok azure-skr` must delegate release *and* unwrap to Microsoft's tool.
# Baking it only into the tdx-azure image is what left this platform with no
# working BYOK path at all.
GA_PURPOSE="secure key release with --byok azure-skr"
__AZURE_GUEST_ATTESTATION__

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
# (linux-modules-nvidia-<VER>-azure-fde-<KREL>) and only resorts to the
# DKMS path when no signed candidate matches the running kernel ABI.
# See docs/security.md §15.1 for the full trade-off analysis.
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
    # The metapackages (*-azure-fde-6.8) are dummy transitional packages that don't install actual modules.
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

# Ensure the module loads now (on the bake VM the GPU is present)
modprobe nvidia 2>/dev/null || true
echo "Verifying NVIDIA driver..."
nvidia-smi || echo "WARNING: nvidia-smi failed (expected at bake time if no GPU present)"

# Ensure the NVIDIA module loads automatically on boot
echo "nvidia" >> /etc/modules-load.d/nvidia.conf 2>/dev/null || true

# --- SEV-SNP guest device ---
echo "Checking AMD SEV-SNP status..."
dmesg | grep -i "Memory Encryption" || true

SEV_DEV=""
for dev_candidate in /dev/sev-guest /dev/sev; do
    if [ -c "$dev_candidate" ]; then
        SEV_DEV="$dev_candidate"
        echo "✓ $SEV_DEV found"
        chmod 0660 "$SEV_DEV"
        chgrp kvm "$SEV_DEV" 2>/dev/null || true
        break
    fi
done
if [ -z "$SEV_DEV" ]; then
    modprobe sev-guest 2>/dev/null || modprobe ccp 2>/dev/null || true
    sleep 2
    for dev_candidate in /dev/sev-guest /dev/sev; do
        if [ -c "$dev_candidate" ]; then
            SEV_DEV="$dev_candidate"
            chmod 0660 "$SEV_DEV"
            chgrp kvm "$SEV_DEV" 2>/dev/null || true
            echo "✓ $SEV_DEV found after modprobe"
            break
        fi
    done
fi
if [ -z "$SEV_DEV" ]; then
    echo "INFO: /dev/sev-guest not present (expected on Azure Hyper-V CVMs)."
    echo "      SNP attestation will use vTPM NV index 0x01400001 instead."
fi

# snpguest only talks to /dev/sev-guest (KVM). Azure NCC uses vTPM + tpm2_nvread — skip
# the multi-minute Rust/cargo build on bake/deploy to avoid timeouts and OOM on the VM.
SNPGUEST_NEEDED=0
if [ -c /dev/sev-guest ] || [ -c /dev/sev ]; then
    SNPGUEST_NEEDED=1
fi

usermod -aG kvm tee_enclave 2>/dev/null || true
usermod -aG tss tee_enclave 2>/dev/null || true
echo "✓ tee_enclave added to kvm and tss groups"

# --- Verify vTPM ---
if command -v tpm2_getrandom &>/dev/null; then
    if tpm2_getrandom 8 >/dev/null 2>&1; then
        echo "✓ vTPM accessible via tpm2-tools"
    else
        echo "WARNING: tpm2_getrandom failed (vTPM may not be ready)"
    fi
fi

# --- Rust toolchain + snpguest (KVM /dev/sev-guest only; not used on Azure Hyper-V) ---
if [ "$SNPGUEST_NEEDED" != 1 ]; then
    echo "Skipping Rust/snpguest build: no /dev/sev-guest on this host (Azure Hyper-V NCC uses vTPM for SNP)."
else
    CARGO_BIN="$HOME/.cargo/bin"
    export PATH="$CARGO_BIN:$PATH"

    if ! command -v cargo &>/dev/null; then
        echo "Installing Rust via rustup..."
        RUSTUP_SCRIPT=$(mktemp)
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$RUSTUP_SCRIPT"
        # SUP-2: verify the rustup installer's SHA-256 before executing.
        RUSTUP_OBSERVED_SHA=$(sha256sum "$RUSTUP_SCRIPT" | awk '{print $1}')
        echo "rustup installer sha256=$RUSTUP_OBSERVED_SHA"
        if [ -n "${TEE_CRAFTER_RUSTUP_SHA256:-}" ]; then
            if [ "$RUSTUP_OBSERVED_SHA" != "$TEE_CRAFTER_RUSTUP_SHA256" ]; then
                echo "FATAL [SUP-2]: rustup installer sha256 mismatch (expected $TEE_CRAFTER_RUSTUP_SHA256, got $RUSTUP_OBSERVED_SHA)" >&2
                rm -f "$RUSTUP_SCRIPT"
                exit 1
            fi
            echo "✓ rustup installer sha256 matches pinned value (SUP-2)"
        fi
        chmod +x "$RUSTUP_SCRIPT"
        sh "$RUSTUP_SCRIPT" -y --default-toolchain stable --profile minimal
        rm -f "$RUSTUP_SCRIPT"
        set +u; [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"; set -u
        export PATH="$CARGO_BIN:$PATH"
        echo "✓ Rust $(rustc --version 2>&1) installed"
    else
        echo "✓ Rust already available: $(cargo --version 2>&1)"
    fi

    SNPGUEST_TAG="v0.7.0"
    SNPGUEST_COMMIT="49494ff71b5830a98b15759aae0a43e20e16e798"
    if ! command -v snpguest &>/dev/null && command -v cargo &>/dev/null; then
        echo "Building snpguest ${SNPGUEST_TAG} (commit ${SNPGUEST_COMMIT:0:12}) from source..."
        SNPGUEST_DIR=$(mktemp -d) || {
            echo "WARNING: Failed to create temp dir for snpguest build; skipping."
        }
        if [ -n "${SNPGUEST_DIR:-}" ] && [ -d "$SNPGUEST_DIR" ]; then
            if git clone https://github.com/virtee/snpguest.git "$SNPGUEST_DIR"; then
                cd "$SNPGUEST_DIR"
                if ! git checkout "$SNPGUEST_COMMIT"; then
                    echo "FATAL: snpguest commit ${SNPGUEST_COMMIT} not found — supply chain risk"
                    cd /; rm -rf "$SNPGUEST_DIR"
                else
                    ACTUAL_COMMIT=$(git rev-parse HEAD)
                    if [ "$ACTUAL_COMMIT" != "$SNPGUEST_COMMIT" ]; then
                        echo "FATAL: snpguest commit mismatch: expected $SNPGUEST_COMMIT, got $ACTUAL_COMMIT"
                        cd /; rm -rf "$SNPGUEST_DIR"
                    else
                        if cargo build --release; then
                            cp target/release/snpguest /usr/local/bin/snpguest
                            chmod 755 /usr/local/bin/snpguest
                            echo "✓ snpguest ${SNPGUEST_TAG} (${SNPGUEST_COMMIT:0:12}) installed"
                        else
                            echo "WARNING: cargo build for snpguest failed; continuing without snpguest."
                        fi
                        cd /
                        rm -rf "$SNPGUEST_DIR"
                    fi
                fi
            else
                echo "WARNING: git clone for snpguest failed; continuing without snpguest."
                rm -rf "$SNPGUEST_DIR"
            fi
        fi
    elif command -v snpguest &>/dev/null; then
        echo "✓ snpguest already installed"
    fi
fi

# --- Download AMD root certificates + VCEK ---
AMD_CERT_DIR="$BASE_DIR/certs"
mkdir -p "$AMD_CERT_DIR"

echo "Retrieving VCEK certificates from Azure IMDS..."
IMDS_RESP=$(curl -sSf -H "Metadata: true" \
    "http://169.254.169.254/metadata/THIM/amd/certification" 2>/dev/null || echo "")

if [ -n "$IMDS_RESP" ]; then
    echo "$IMDS_RESP" | python3 -c "
import sys, json
data = json.load(sys.stdin)
vcek = data.get('vcekCert', '')
chain = data.get('certificateChain', '')
if vcek:
    with open('$AMD_CERT_DIR/vcek.pem', 'w') as f:
        f.write(vcek)
    print('  ✓ VCEK cert saved')
if chain:
    with open('$AMD_CERT_DIR/cert_chain.pem', 'w') as f:
        f.write(chain)
    print('  ✓ Certificate chain saved')
" || echo "  WARNING: Failed to parse IMDS cert response"
else
    echo "  WARNING: IMDS cert retrieval failed (may work at runtime)"
fi

echo "Downloading AMD root certificates from KDS..."
curl --proto '=https' --tlsv1.2 -sSf \
    "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain" \
    -o "$AMD_CERT_DIR/cert_chain_milan.pem" 2>/dev/null || \
    echo "  WARNING: Failed to download Milan cert chain"
curl --proto '=https' --tlsv1.2 -sSf \
    "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain" \
    -o "$AMD_CERT_DIR/cert_chain_genoa.pem" 2>/dev/null || \
    echo "  WARNING: Failed to download Genoa cert chain"

# --- Test SNP attestation ---
if { [ -c /dev/sev-guest ] || [ -c /dev/sev ]; } && command -v snpguest &>/dev/null; then
    echo "Testing SNP attestation..."
    TEST_REPORT=$(mktemp)
    TEST_REQUEST=$(mktemp)
    echo -n "test-attestation" > "$TEST_REQUEST"
    if snpguest report "$TEST_REPORT" "$TEST_REQUEST" --random 2>/dev/null; then
        REPORT_SIZE=$(stat -c%s "$TEST_REPORT" 2>/dev/null || stat -f%z "$TEST_REPORT")
        echo "✓ SNP attestation report generated ($REPORT_SIZE bytes)"
    else
        echo "WARNING: SNP attestation test failed"
    fi
    rm -f "$TEST_REPORT" "$TEST_REQUEST"
fi

# Check vTPM NV index for Azure HCL report
if command -v tpm2_nvread &>/dev/null; then
    echo "Checking vTPM NV index 0x01400001 for HCL report..."
    HCL_DATA=$(tpm2_nvread 0x01400001 -C o -s 36 2>/dev/null || true)
    if [ -n "$HCL_DATA" ]; then
        echo "✓ vTPM NV 0x01400001 readable — SNP attestation via vTPM will work"
    else
        echo "  vTPM NV 0x01400001 not readable (attestation may fail)"
    fi
fi

# --- Python virtual environment ---
# We pre-install the GPU ML stack (torch + CUDA wheels + common ML utilities)
# directly into the baked image's venv.  Rationale: at deploy time the user's
# requirements.txt almost always pulls in torch + the full nvidia-cu12 wheel
# set (~2.9 GB).  Shipping that over an Azure Bastion SSH tunnel (~1.3 MB/s
# effective) takes 30-40 minutes per deploy and routinely exceeds SCP
# timeouts.  By baking it once we trade ~2.9 GB of one-time image size for
# essentially-instant deploy uploads (only the small app + any user-specific
# wheels not already on the image).  Versions are pinned to torch 2.5.1's
# own transitive lock so the bake matches what `pip install torch==2.5.1`
# would resolve at deploy time — letting the dedupe pass skip them entirely.
# See docs/optimizations.md §1 for the full rationale.
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

# Capture the exact wheel set installed in the bake venv so deploy-time
# wheel collection can skip anything already present (delta-only upload).
# Stored in /etc/tee_crafter so it survives image capture and is readable
# by the deployer over SSH/SSM without any extra privileges.
mkdir -p /etc/tee_crafter
"$BASE_DIR/venv/bin/pip" freeze --all 2>/dev/null \
    > /etc/tee_crafter/image_pip_frozen.txt || true
chmod 0644 /etc/tee_crafter/image_pip_frozen.txt 2>/dev/null || true
echo "✓ Image pip manifest captured: $(wc -l < /etc/tee_crafter/image_pip_frozen.txt 2>/dev/null || echo 0) packages"

# --- Pre-pull common Docker base images used by handler / container deploys ---
# Without this, the first `docker build` at deploy time spends ~30-60s
# pulling the ~3 GB nvidia/cuda runtime over CVM-restricted egress.
# Pulling at bake time means deploys only push the small app layer.
# (Pulls are best-effort — if the registry is unreachable at bake time
# we still produce a usable image, just without the prewarm.)
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

# Set SEV device permissions for tee_enclave
for SEV_DEV in /dev/sev-guest /dev/sev; do
    if [ -c "$SEV_DEV" ]; then
        chmod 0660 "$SEV_DEV"
        chgrp kvm "$SEV_DEV" 2>/dev/null || true
        echo "✓ Set permissions on $SEV_DEV"
    fi
done

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

# Regenerate CDI spec on every boot (driver version may differ from bake image)
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

# --- Ensure waagent is healthy (critical for image capture) ---
systemctl enable walinuxagent 2>/dev/null || systemctl enable waagent 2>/dev/null || true
systemctl start walinuxagent 2>/dev/null || systemctl start waagent 2>/dev/null || true

# --- Bake marker ---
mkdir -p /etc/tee_crafter
echo "baked_gpu_cc_azure $(date -u +%Y%m%dT%H%M%SZ)" > /etc/tee_crafter/baked_gpu_cc_azure

echo "=== TEE-Crafter GPU CC Azure setup complete ==="
