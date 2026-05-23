#!/usr/bin/env bash
set -euxo pipefail

# Bake-time setup script for GCP AMD SEV-SNP Confidential VMs.
# Installs snpguest, Python venv, cryptography, and creates
# systemd service unit for the SNP RA-TLS application.

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
for i in $(seq 1 60); do
    if ! pgrep -x apt-get >/dev/null 2>&1 \
       && ! pgrep -x apt >/dev/null 2>&1 \
       && ! pgrep -x dpkg >/dev/null 2>&1 \
       && ! pgrep -x unattended-upgr >/dev/null 2>&1; then
        break
    fi
    echo "  waiting for apt/dpkg to exit cleanly... ($i/60)"
    sleep 5
done
dpkg --configure -a 2>/dev/null || true

BASE_DIR="/opt/tee-crafter-snp"

# Create service user
id -u tee_enclave &>/dev/null || useradd -r -m -d "$BASE_DIR" -s /usr/sbin/nologin tee_enclave

# System packages
apt-get update -y
apt-get install -y \
    python3-venv python3-dev build-essential curl git \
    pkg-config libssl-dev \
    pigz zstd

# Install Rust toolchain (for snpguest build)
if ! command -v rustc &>/dev/null; then
    # SUP-2: download, verify SHA-256, then execute — never `curl | sh`.
    RUSTUP_SCRIPT=$(mktemp)
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$RUSTUP_SCRIPT"
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
fi
export PATH="$HOME/.cargo/bin:$PATH"

# Build and install snpguest (pinned to a specific tag for supply-chain safety)
SNPGUEST_TAG="v0.7.0"
SNPGUEST_COMMIT="ec1cc1af26b60dced56198e265f78e3fb01f7c28"
if ! command -v snpguest &>/dev/null; then
    echo "Building snpguest ${SNPGUEST_TAG} (commit ${SNPGUEST_COMMIT:0:12}) from source..."
    SNPGUEST_DIR=$(mktemp -d)
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

# Create directory structure
mkdir -p "$BASE_DIR"/{app,certs,wheels}

# --- Download & pin AMD root certificates ---
# Pinned ARK SHA-256 fingerprints (colon-separated, uppercase).  Any chain
# whose ARK does not match is rejected.
# ARK (AMD Root Key) fingerprints, read off kdsintf.amd.com 2026-08-24.
# These previously held the fingerprints of entry [0] of the two-cert
# bundles in certs/amd-ark-*.pem -- the SEV-VLEK-Milan / SEV-Genoa
# intermediates -- rather than entry [1], the actual self-signed root.
# verify_amd_chain compares against the last certificate of the chain,
# so the check could never pass and the downloaded chain was deleted
# every time. Same ARK terminates the vcek and vlek endpoints.
AMD_ARK_MILAN_SHA256="${TEE_CRAFTER_ARK_MILAN_SHA256:-69:D0:63:B4:53:44:D2:6A:2E:94:E1:F4:21:0D:E4:9E:F5:55:30:82:87:D4:C1:74:44:5C:95:63:9A:54:0B:CD}"
AMD_ARK_GENOA_SHA256="${TEE_CRAFTER_ARK_GENOA_SHA256:-4C:65:98:D1:9C:18:71:9C:5D:FD:4A:7D:33:5F:67:4E:5B:FE:1D:8F:80:0C:EA:2C:F2:70:C1:0D:10:3D:B2:F1}"

verify_amd_chain() {
    local chain="$1"; local expected="$2"
    local last_cert; last_cert=$(mktemp)
    awk '
        /-----BEGIN CERTIFICATE-----/ { buf=""; inblock=1 }
        inblock { buf = buf $0 "\n" }
        /-----END CERTIFICATE-----/   { last=buf; inblock=0 }
        END { printf "%s", last }
    ' "$chain" > "$last_cert"
    local got
    got=$(openssl x509 -in "$last_cert" -noout -fingerprint -sha256 2>/dev/null \
          | sed -n 's/^sha256 Fingerprint=//p')
    rm -f "$last_cert"
    if [ "$got" != "$expected" ]; then
        echo "FATAL: AMD ARK fingerprint mismatch for $chain (expected $expected, got $got)" >&2
        rm -f "$chain"
        return 1
    fi
    echo "✓ AMD ARK fingerprint verified for $(basename "$chain"): $got"
}

for gen in Milan Genoa; do
    chain="$BASE_DIR/certs/cert_chain_${gen,,}.pem"
    if ! curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
            "https://kdsintf.amd.com/vcek/v1/${gen}/cert_chain" -o "$chain"; then
        echo "  WARNING: Failed to download ${gen} cert chain"
        continue
    fi
    expected_var="AMD_ARK_${gen^^}_SHA256"
    verify_amd_chain "$chain" "${!expected_var}" || true
done

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

# SEV guest device permissions (may not exist at bake time)
for dev in /dev/sev-guest /dev/sev; do
    if [ -c "$dev" ]; then
        chmod 0660 "$dev"
        chgrp kvm "$dev" 2>/dev/null || chgrp tee_enclave "$dev"
    fi
done
usermod -aG kvm tee_enclave 2>/dev/null || true

# Systemd service unit
cat > /etc/systemd/system/tee-crafter-snp.service <<'EOF'
__SYSTEMD_UNIT__
EOF

systemctl daemon-reload
# Service will be enabled at deploy time, not during image baking

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
echo "snp-gcp-$(date -u +%Y%m%d-%H%M%S)" > /etc/tee_crafter/baked_snp

echo "=== SNP GCP bake setup complete ==="
