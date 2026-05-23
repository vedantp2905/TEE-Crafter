#!/bin/bash
set -euo pipefail

# AMD SEV-SNP host setup for Azure (DCasv5/ECasv5/DCasv6/ECasv6)
# Installs snpguest, tpm2-tools, Python venv, creates service user, systemd unit.

export DEBIAN_FRONTEND=noninteractive

echo "=== TEE-Crafter: AMD SEV-SNP (Azure) host setup ==="

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
# Wait for apt/dpkg to exit cleanly instead of SIGKILLing — killing dpkg
# mid-transaction leaves the package DB inconsistent.
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

# --- Check SEV status (Azure Hyper-V CVMs use vTPM, not /dev/sev-guest) ---
echo "Checking AMD SEV memory encryption..."
dmesg | grep -i "Memory Encryption" || true

SEV_DEV=""
for dev_candidate in /dev/sev-guest /dev/sev; do
    if [ -c "$dev_candidate" ]; then
        SEV_DEV="$dev_candidate"
        echo "✓ $SEV_DEV found"
        chmod 0660 "$SEV_DEV"
        break
    fi
done
if [ -z "$SEV_DEV" ]; then
    echo "INFO: /dev/sev-guest not present (expected on Azure Hyper-V CVMs)."
    echo "      SNP attestation will use vTPM NV index 0x01400001 instead."
fi

# --- System packages (including Rust toolchain and kernel modules) ---
echo "Installing system packages (Python, build tools, Rust, TPM tools)..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    build-essential pkg-config libssl-dev \
    curl git \
    tpm2-tools \
    pigz zstd

# Install extra kernel modules (contains sev-guest.ko for non-Hyper-V use)
apt-get install -y -qq "linux-modules-extra-$(uname -r)" 2>/dev/null || \
    echo "WARNING: linux-modules-extra not available for $(uname -r)"

# Microsoft guest attestation, for AzureAttestSKR only.
#
# snp-azure does *not* need AttestationClient: it reads a real SEV-SNP
# ATTESTATION_REPORT from the vTPM and the client verifies it against AMD's ARK.
# What it cannot do without this block is Secure Key Release. Key Vault wraps a
# released key to `TpmEphemeralEncryptionKey`, whose private half is sealed to
# the vTPM, so `--byok azure-skr` has to delegate release *and* unwrap to
# Microsoft's tool. Baking the tool only into the tdx-azure image is what left
# this platform with no working BYOK path at all -- `azure-kv` refuses (no
# authenticated transport, wrong KEK) and `azure-skr` had no binary to call.
GA_PURPOSE="secure key release with --byok azure-skr"
__AZURE_GUEST_ATTESTATION__

# --- Rust toolchain via rustup (apt's rustc is too old for snpguest) ---
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
    export PATH="$HOME/.cargo/bin:$PATH"
    echo "✓ Rust $(rustc --version) installed via rustup"
else
    echo "✓ Rust already available: $(cargo --version)"
fi
export PATH="$HOME/.cargo/bin:$PATH"

# --- Verify vTPM is accessible ---
if command -v tpm2_getrandom &>/dev/null; then
    if tpm2_getrandom 8 >/dev/null 2>&1; then
        echo "✓ vTPM accessible via tpm2-tools"
    else
        echo "WARNING: tpm2_getrandom failed (vTPM may not be ready)"
    fi
fi

# --- Build and install snpguest (best-effort, pinned to commit) ---
SNPGUEST_TAG="v0.7.0"
SNPGUEST_COMMIT="ec1cc1af26b60dced56198e265f78e3fb01f7c28"
if ! command -v snpguest &>/dev/null; then
    echo "Building snpguest ${SNPGUEST_TAG} (commit ${SNPGUEST_COMMIT:0:12}) from source (best-effort)..."
    SNPGUEST_DIR=$(mktemp -d) || {
        echo "WARNING: Failed to create temp dir for snpguest build; skipping snpguest."
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
else
    echo "✓ snpguest already installed"
fi

# --- Download AMD root certificates + VCEK from IMDS ---
AMD_CERT_DIR="/opt/tee-crafter-snp/certs"
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

# Fallback: download from AMD KDS (pinned to ARK SHA-256).
# Any chain whose root key does not match the pinned fingerprint is rejected;
# this defends against KDS compromise and DNS/BGP hijack of kdsintf.amd.com.
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

echo "Downloading AMD SEV-SNP cert chains from KDS..."
for gen in Milan Genoa; do
    chain="$AMD_CERT_DIR/cert_chain_${gen,,}.pem"
    if ! curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
            "https://kdsintf.amd.com/vcek/v1/${gen}/cert_chain" -o "$chain"; then
        echo "  WARNING: Failed to download ${gen} cert chain"
        continue
    fi
    expected_var="AMD_ARK_${gen^^}_SHA256"
    verify_amd_chain "$chain" "${!expected_var}" || true
done

# --- Test attestation ---
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

# Check vTPM NV index for Azure HCL report (primary attestation path on Azure)
if command -v tpm2_nvread &>/dev/null; then
    echo "Checking vTPM NV index 0x01400001 for HCL report..."
    HCL_DATA=$(tpm2_nvread 0x01400001 -C o -s 36 2>/dev/null || true)
    if [ -n "$HCL_DATA" ]; then
        MAGIC=$(echo -n "$HCL_DATA" | head -c4)
        if [ "$MAGIC" = "HCLA" ]; then
            echo "✓ vTPM HCL report readable (magic=HCLA) — SNP attestation via vTPM will work"
        else
            echo "✓ vTPM NV 0x01400001 readable but unexpected header"
        fi
    else
        echo "  vTPM NV 0x01400001 not readable (attestation may fail)"
    fi
fi

# --- Service user ---
if ! id tee_enclave &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir /opt/tee-crafter-snp tee_enclave
    echo "✓ Created tee_enclave user"
fi

# Grant TPM access (tss group owns /dev/tpm0 and /dev/tpmrm0)
usermod -aG tss tee_enclave 2>/dev/null || true
echo "✓ tee_enclave added to tss group (vTPM access)"

# --- Application directory + venv ---
APP_DIR="/opt/tee-crafter-snp"
mkdir -p "$APP_DIR/app"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install "cryptography>=42.0,<44"

mkdir -p /etc/tee_crafter
"$APP_DIR/venv/bin/pip" freeze --all 2>/dev/null \
    > /etc/tee_crafter/image_pip_frozen.txt || true
chmod 0644 /etc/tee_crafter/image_pip_frozen.txt 2>/dev/null || true

# --- Pre-pull common Docker base images for handler / container builds ---
# Azure CVMs have outbound internet by default but registry RTT and pull
# latency still cost ~10-20 s per build.  Pre-pulling at bake time means
# user docker builds at deploy time only push the small final layer.
# Best-effort — silent if registry unreachable.
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

chown -R tee_enclave:tee_enclave "$APP_DIR"

for SEV_DEV in /dev/sev-guest /dev/sev; do
    if [ -c "$SEV_DEV" ]; then
        usermod -aG kvm tee_enclave 2>/dev/null || true
        chmod 0660 "$SEV_DEV"
        chgrp kvm "$SEV_DEV" 2>/dev/null || true
        echo "✓ Set permissions on $SEV_DEV"
    fi
done

# --- Systemd service ---
cat > /etc/systemd/system/tee-crafter-snp.service <<'UNIT'
__SYSTEMD_UNIT__
UNIT

systemctl daemon-reload
# Do NOT enable the service at bake time — app artifacts are not present yet.
# The deploy step will start (and optionally enable) the service after uploading
# app code + wheels to /opt/tee-crafter-snp/app/.

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

# --- Ensure waagent and cloud-init are healthy (critical for image capture) ---
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

# --- Bake marker ---
mkdir -p /etc/tee_crafter
echo "baked_snp_azure $(date -u +%Y%m%dT%H%M%SZ)" > /etc/tee_crafter/baked_snp_azure

echo "=== TEE-Crafter: AMD SEV-SNP (Azure) setup complete ==="
