#!/bin/bash
set -euo pipefail

# SSM runs in a minimal env; ensure HOME is set (set -u would fail otherwise)
export HOME="${HOME:-/root}"

# AMD SEV-SNP host setup for AWS (M6a/C6a/R6a instances)
# Installs snpguest, Python venv, creates service user and systemd unit.

export DEBIAN_FRONTEND=noninteractive

echo "=== TEE-Crafter: AMD SEV-SNP (AWS) host setup ==="

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

# Disable unattended-upgrades so it doesn't race our package installs.
# Do NOT SIGKILL apt/dpkg — that leaves the dpkg DB half-written and any
# subsequent install will fail or install an inconsistent package set.
# Instead wait (bounded) for whatever dpkg is doing to finish cleanly.
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

# --- Verify SEV-SNP is available ---
if [ ! -c /dev/sev-guest ]; then
    echo "WARNING: /dev/sev-guest not found. Checking dmesg for SEV-SNP..."
    dmesg | grep -i "sev-snp\|sev_snp\|Memory Encryption" || true
    # Try loading the module
    modprobe sev-guest 2>/dev/null || modprobe ccp 2>/dev/null || true
    sleep 2
    if [ ! -c /dev/sev-guest ]; then
        echo "ERROR: /dev/sev-guest still not available after module load attempt."
        echo "This instance may not have AMD SEV-SNP enabled."
        echo "Ensure you launched with: --cpu-options AmdSevSnp=enabled"
    fi
fi

if [ -c /dev/sev-guest ]; then
    echo "✓ /dev/sev-guest found — AMD SEV-SNP is active"
    chmod 0660 /dev/sev-guest
fi

# --- System packages (Python, build tools, AWS CLI) ---
echo "Installing system packages..."
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    build-essential pkg-config libssl-dev \
    curl git \
    awscli \
    tpm2-tools \
    pigz zstd > /dev/null 2>&1
echo "✓ System packages installed"

# --- Rust toolchain (rustup preferred; apt fallback) ---
CARGO_BIN="$HOME/.cargo/bin"
export PATH="$CARGO_BIN:$PATH"

# Disable pipefail for Rust/snpguest section (pipe to tail must not fail the script)
set +o pipefail

if ! command -v cargo &>/dev/null || ! cargo --version &>/dev/null; then
    echo "Installing Rust via rustup..."
    rm -rf "$HOME/.rustup" "$HOME/.cargo"
    RUSTUP_SCRIPT=$(mktemp)
    RUSTUP_LOG=$(mktemp)
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$RUSTUP_SCRIPT"
    # SUP-2: verify the rustup installer's SHA-256 before executing it.
    # If TEE_CRAFTER_RUSTUP_SHA256 is set, enforce an exact match; a
    # mismatch aborts the build.  When unset we log the observed hash
    # so operators can pin it on subsequent runs, but do not block
    # (preserves out-of-the-box installability).
    RUSTUP_OBSERVED_SHA=$(sha256sum "$RUSTUP_SCRIPT" | awk '{print $1}')
    echo "rustup installer sha256=$RUSTUP_OBSERVED_SHA"
    if [ -n "${TEE_CRAFTER_RUSTUP_SHA256:-}" ]; then
        if [ "$RUSTUP_OBSERVED_SHA" != "$TEE_CRAFTER_RUSTUP_SHA256" ]; then
            echo "FATAL [SUP-2]: rustup installer sha256 mismatch (expected $TEE_CRAFTER_RUSTUP_SHA256, got $RUSTUP_OBSERVED_SHA)" >&2
            rm -f "$RUSTUP_SCRIPT" "$RUSTUP_LOG"
            exit 1
        fi
        echo "✓ rustup installer sha256 matches pinned value (SUP-2)"
    fi
    chmod +x "$RUSTUP_SCRIPT"
    sh "$RUSTUP_SCRIPT" -y --default-toolchain stable --profile minimal > "$RUSTUP_LOG" 2>&1 || true
    tail -3 "$RUSTUP_LOG"
    rm -f "$RUSTUP_SCRIPT" "$RUSTUP_LOG"
    set +u; [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"; set -u
    export PATH="$CARGO_BIN:$PATH"
fi

if ! command -v cargo &>/dev/null; then
    echo "Rustup failed; trying apt rustc/cargo..."
    apt-get install -y -qq rustc cargo > /dev/null 2>&1 || true
fi

if command -v cargo &>/dev/null; then
    echo "✓ Rust available: $(cargo --version 2>&1)"
else
    echo "WARNING: Could not install Rust; snpguest build will be skipped."
fi
export PATH="$CARGO_BIN:$PATH"

# --- Build and install snpguest ---
SNPGUEST_TAG="v0.7.0"
# The commit that `refs/tags/v0.7.0` actually points at, verified 2026-08-24 with
# `git ls-remote --tags https://github.com/virtee/snpguest.git` and confirmed by
# `version = "0.7.0"` in the checked-out Cargo.toml.
#
# The previous value, ec1cc1af26b60dced56198e265f78e3fb01f7c28, does not exist in
# that repository at all -- a fresh clone reports "OBJECT ABSENT", not merely an
# unreachable ref. So `git checkout` failed, the script's own supply-chain guard
# correctly refused to build an unpinned revision, and because the step is
# non-fatal the bake completed anyway and produced an AMI with no snpguest. That
# is the whole explanation for the "unexplained" missing binary; the tooling gate
# near the end of this script is what turned it from silent into a bake failure.
SNPGUEST_COMMIT="49494ff71b5830a98b15759aae0a43e20e16e798"
if ! command -v snpguest &>/dev/null && command -v cargo &>/dev/null; then
    echo "Building snpguest ${SNPGUEST_TAG} (commit ${SNPGUEST_COMMIT:0:12}) from source (this takes a few minutes)..."
    SNPGUEST_DIR=$(mktemp -d)
    CLONE_LOG=$(mktemp)
    if git clone https://github.com/virtee/snpguest.git "$SNPGUEST_DIR" > "$CLONE_LOG" 2>&1; then
        cd "$SNPGUEST_DIR"
        if ! git checkout "$SNPGUEST_COMMIT"; then
            echo "FATAL: snpguest commit ${SNPGUEST_COMMIT} not found — supply chain risk"
            cd /; rm -rf "$SNPGUEST_DIR"; rm -f "$CLONE_LOG"
        else
            ACTUAL_COMMIT=$(git rev-parse HEAD)
            if [ "$ACTUAL_COMMIT" != "$SNPGUEST_COMMIT" ]; then
                echo "FATAL: snpguest commit mismatch: expected $SNPGUEST_COMMIT, got $ACTUAL_COMMIT"
                cd /; rm -rf "$SNPGUEST_DIR"; rm -f "$CLONE_LOG"
            else
                BUILD_LOG=$(mktemp)
                if cargo build --release > "$BUILD_LOG" 2>&1; then
                    cp target/release/snpguest /usr/local/bin/snpguest
                    chmod 755 /usr/local/bin/snpguest
                    echo "✓ snpguest ${SNPGUEST_TAG} (${SNPGUEST_COMMIT:0:12}) installed"
                else
                    echo "WARNING: cargo build for snpguest failed; continuing without snpguest."
                    tail -10 "$BUILD_LOG"
                    # Keep the log in the image. A bake on 2026-08-24 produced an
                    # AMI with no snpguest and the reason was unrecoverable: the
                    # log lived in a mktemp file that this line used to delete.
                    mkdir -p /var/log/tee-crafter
                    cp "$BUILD_LOG" /var/log/tee-crafter/snpguest-build-failed.log || true
                fi
                rm -f "$BUILD_LOG"
                cd /
                rm -rf "$SNPGUEST_DIR"
            fi
        fi
    else
        echo "WARNING: git clone for snpguest failed; continuing without snpguest."
        cat "$CLONE_LOG"
    fi
    rm -f "$CLONE_LOG"
elif command -v snpguest &>/dev/null; then
    echo "✓ snpguest already installed"
else
    echo "WARNING: skipping snpguest build (no cargo available)"
fi

# Re-enable pipefail
set -o pipefail

# --- Download & verify AMD root certificates ---
# We pin the ARK (AMD Root Key) SHA-256 fingerprints for both currently
# supported generations.  Any downloaded chain whose root does not match
# the pin below is rejected — this defends against KDS compromise and
# BGP/DNS hijack of kdsintf.amd.com.
AMD_CERT_DIR="/opt/tee-crafter-snp/certs"
mkdir -p "$AMD_CERT_DIR"
chmod 0755 "$AMD_CERT_DIR"

# Pinned fingerprints (colon-separated uppercase hex, matches
# `openssl x509 -fingerprint -sha256` output).
#
# These are the self-signed AMD Root Keys, `CN=ARK-Milan` and `CN=ARK-Genoa`,
# read off kdsintf.amd.com on 2026-08-24.  The same ARK terminates both the
# `/vcek/v1/<gen>/cert_chain` and `/vlek/v1/<gen>/cert_chain` endpoints, so
# pinning it is robust to which of the two this script fetches.
#
# The previous two values were intermediates, not roots, so the check could
# never pass.  `certs/amd-ark-milan.pem` and `certs/amd-ark-genoa.pem` are each
# a two-certificate bundle, and whoever produced these pins fingerprinted
# entry [0] instead of entry [1]:
#
#   * "Milan ARK" was C5:E0:81:F5…, i.e. `CN=SEV-VLEK-Milan`, the VLEK
#     intermediate that sits above the ARK in that bundle;
#   * "Genoa ARK" was 54:64:73:8C…, i.e. `CN=SEV-Genoa`, the VCEK intermediate.
#
# `verify_amd_chain` extracts the *last* certificate of the downloaded chain,
# which is correct and did report the real ARKs -- the pins were what
# disagreed.  Because a rejected chain is deleted (`rm -f "$chain"`), the effect
# was that no snp-aws bake ever installed an AMD endorsement chain.
#
# Client-side verification was never affected: the snp client also takes the
# last certificate of each baked bundle as the ARK, and that has always been the
# genuine root.
#
# Verify a replacement before trusting it -- the subject must say ARK:
#   curl -s https://kdsintf.amd.com/vcek/v1/Milan/cert_chain \
#     | openssl storeutl -noout -text /dev/stdin | grep -E 'subject|Fingerprint'
AMD_ARK_MILAN_SHA256="69:D0:63:B4:53:44:D2:6A:2E:94:E1:F4:21:0D:E4:9E:F5:55:30:82:87:D4:C1:74:44:5C:95:63:9A:54:0B:CD"
AMD_ARK_GENOA_SHA256="4C:65:98:D1:9C:18:71:9C:5D:FD:4A:7D:33:5F:67:4E:5B:FE:1D:8F:80:0C:EA:2C:F2:70:C1:0D:10:3D:B2:F1"

# Override support: TEE_CRAFTER_ARK_MILAN_SHA256 / _GENOA_ env vars let
# operators rotate pins without rebuilding the AMI.
AMD_ARK_MILAN_SHA256="${TEE_CRAFTER_ARK_MILAN_SHA256:-$AMD_ARK_MILAN_SHA256}"
AMD_ARK_GENOA_SHA256="${TEE_CRAFTER_ARK_GENOA_SHA256:-$AMD_ARK_GENOA_SHA256}"

verify_amd_chain() {
    # $1 = chain PEM path; $2 = expected ARK fingerprint (colon hex)
    local chain="$1"; local expected="$2"
    # Extract the last cert in the chain (the self-signed ARK root) into its
    # own file.  awk lets us grab the final -----BEGIN/END CERTIFICATE----- block.
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
    if [ -z "$got" ]; then
        echo "FATAL: could not compute ARK fingerprint from $chain" >&2
        return 1
    fi
    if [ "$got" != "$expected" ]; then
        echo "FATAL: AMD ARK fingerprint mismatch for $chain" >&2
        echo "  expected: $expected" >&2
        echo "  got     : $got" >&2
        return 1
    fi
    echo "✓ AMD ARK fingerprint verified for $(basename "$chain"): $got"
    return 0
}

echo "Downloading AMD SEV-SNP cert chains from KDS..."
for gen in Milan Genoa; do
    chain="$AMD_CERT_DIR/cert_chain_${gen,,}.pem"
    if ! curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
            "https://kdsintf.amd.com/vlek/v1/${gen}/cert_chain" -o "$chain"; then
        echo "WARNING: Failed to download ${gen} cert chain (may be offline); continuing"
        continue
    fi
    expected_var="AMD_ARK_${gen^^}_SHA256"
    expected="${!expected_var}"
    if ! verify_amd_chain "$chain" "$expected"; then
        rm -f "$chain"
        # Hard fail only when we're running on that generation.  We don't
        # know the CPU generation yet, so stash the failure and let later
        # code decide — but keep the file removed so a downstream verifier
        # cannot accidentally trust an unpinned chain.
        echo "ERROR: rejected ${gen} cert chain"
    fi
done

# Also copy the tee-crafter-bundled pinned ARK PEMs into the cert dir as a
# belt-and-braces local reference (used by snpguest verify --pinned).
if [ -f /opt/tee-crafter-snp/bundled-certs/amd-ark-milan.pem ]; then
    cp /opt/tee-crafter-snp/bundled-certs/amd-ark-*.pem "$AMD_CERT_DIR/" || true
fi

# Retrieve VLEK/VCEK cert from the host
if [ -c /dev/sev-guest ] || [ -c /dev/sev ]; then
    echo "Retrieving endorsement certificates via snpguest..."
    snpguest certificates pem "$AMD_CERT_DIR" 2>/dev/null || \
        echo "WARNING: snpguest certificates failed (may work at runtime)"
fi

# --- Test attestation ---
if { [ -c /dev/sev-guest ] || [ -c /dev/sev ]; } && command -v snpguest &>/dev/null; then
    echo "Testing SNP attestation report generation..."
    TEST_REPORT=$(mktemp)
    TEST_REQUEST=$(mktemp)
    echo -n "test-attestation" > "$TEST_REQUEST"
    if snpguest report "$TEST_REPORT" "$TEST_REQUEST" --random 2>/dev/null; then
        REPORT_SIZE=$(stat -c%s "$TEST_REPORT" 2>/dev/null || stat -f%z "$TEST_REPORT")
        echo "✓ SNP attestation report generated ($REPORT_SIZE bytes)"

        if [ -f "$AMD_CERT_DIR/vlek.pem" ] || [ -f "$AMD_CERT_DIR/vcek.pem" ]; then
            if snpguest verify attestation "$AMD_CERT_DIR" "$TEST_REPORT" 2>/dev/null; then
                echo "✓ SNP attestation report signature verified"
            else
                echo "WARNING: SNP attestation signature verification failed (may succeed at runtime)"
            fi
        fi
    else
        echo "WARNING: SNP attestation test failed"
    fi
    rm -f "$TEST_REPORT" "$TEST_REQUEST"
fi

# --- Service user ---
if ! id tee_enclave &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir /opt/tee-crafter-snp tee_enclave
    echo "✓ Created tee_enclave user"
fi

# --- Application directory + venv ---
APP_DIR="/opt/tee-crafter-snp"
mkdir -p "$APP_DIR/app"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip -q 2>&1 | tail -1
"$APP_DIR/venv/bin/pip" install "cryptography>=42.0,<44" -q 2>&1 | tail -1
echo "✓ Python venv and cryptography installed"

# Image pip manifest: deploy-time dedupe reads this and skips any wheels
# the user's requirements.txt declares that are already present at a
# compatible version on the image.  See docs/optimizations.md §2.
mkdir -p /etc/tee_crafter
"$APP_DIR/venv/bin/pip" freeze --all 2>/dev/null \
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

chown -R tee_enclave:tee_enclave "$APP_DIR"

# Allow tee_enclave to read /dev/sev-guest or /dev/sev (kernel >=6.8 renamed it)
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
# Do NOT enable the service at bake time — app artifacts are not present yet.
# The deploy step will start (and optionally enable) the service after uploading
# app code + wheels to /opt/tee-crafter-snp/app/.

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

__NITRO_TPM_ATTEST_INSTALL__

# --- Custom seccomp profile for user containers ---
mkdir -p /etc/tee_crafter
cat > /etc/tee_crafter/seccomp-container.json <<'SECCOMP_EOF'
__SECCOMP_PROFILE__
SECCOMP_EOF

# --- AppArmor profile for user containers (service mode + batch mode) ---
cat > /etc/apparmor.d/tee-crafter-container <<'APPARMOR_EOF'
__APPARMOR_PROFILE__
APPARMOR_EOF
cat > /etc/apparmor.d/tee-crafter-batch-container <<'APPARMOR_BATCH_EOF'
__APPARMOR_BATCH_PROFILE__
APPARMOR_BATCH_EOF
if command -v apparmor_parser >/dev/null 2>&1; then
  for _prof in tee-crafter-container tee-crafter-batch-container; do
    apparmor_parser -r "/etc/apparmor.d/${_prof}" || {
      echo "FATAL: AppArmor profile ${_prof} failed to parse — container will not start" >&2
      apparmor_parser -r -d "/etc/apparmor.d/${_prof}" 2>&1 | head -20 >&2 || true
      exit 1
    }
  done
else
  echo "WARNING: apparmor_parser not installed; container security profiles NOT loaded" >&2
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

# --- UEFI Secure Boot enrollment (optional; replaced at bake-time) ---
#
# When `bake-ami --enable-secure-boot` is passed, the loader substitutes
# this placeholder with `scripts/common/secure_boot_enroll_aws.sh` which
# enrolls PK/KEK/db into the firmware via `efi-updatevar`.  Without that
# flag the placeholder is replaced by the no-op comment below so the
# bake produces a UEFI-but-SB-disabled AMI (matching pre-2026 behaviour).
__SECURE_BOOT_ENROLL__

# --- Verify the attestation tooling actually landed (fail closed) ---
#
# Both builds above are individually non-fatal, which turned out to be a
# fail-open: a bake on 2026-08-24 completed successfully and produced an AMI
# containing neither snpguest nor nitro-tpm-attest. Nothing in the bake output
# said so, the AMI registered normally, and the miss only surfaced when a
# hardware run tried to use them. An image that cannot attest is worse than a
# bake that stops, so this gate refuses to mark the image baked.
#
# Default is strict. Set TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS=0 to bake a
# plain SEV-SNP image deliberately without them, accepting that BYOK key
# release degrades to identity-gated (core/keys/gating.py reports that
# honestly rather than claiming a gate that is not there).
#
# Rejected alternative: keep both warnings and add the check to the deploy
# path instead. That detects the same problem, but one bake later and after
# an instance is already billing -- and the whole reason this went unnoticed
# is that the signal was too far from the cause.
REQUIRE_ATTESTATION_TOOLS="${TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS:-1}"
MISSING_TOOLS=""
command -v snpguest >/dev/null 2>&1 || MISSING_TOOLS="${MISSING_TOOLS} snpguest"
command -v nitro-tpm-attest >/dev/null 2>&1 || MISSING_TOOLS="${MISSING_TOOLS} nitro-tpm-attest"

echo "--- attestation tooling ---"
echo "snpguest:          $(command -v snpguest || echo MISSING)"
echo "nitro-tpm-attest:  $(command -v nitro-tpm-attest || echo MISSING)"
echo "tpm2-tools:        $(command -v tpm2_pcrread || echo MISSING)"

if [ -n "$MISSING_TOOLS" ]; then
    if [ "$REQUIRE_ATTESTATION_TOOLS" = "0" ]; then
        echo "WARNING: missing attestation tooling:${MISSING_TOOLS} — continuing because TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS=0" >&2
    else
        echo "FATAL: missing attestation tooling:${MISSING_TOOLS}" >&2
        echo "This image would register as a working SEV-SNP AMI while being unable to" >&2
        echo "produce an attestation report or a NitroTPM document. Refusing to bake it." >&2
        for _log in /var/log/tee-crafter/snpguest-build-failed.log \
                    /var/log/tee-crafter/nitrotpm-build-failed.log; do
            [ -f "$_log" ] && { echo "--- $_log (tail) ---" >&2; tail -30 "$_log" >&2; }
        done
        echo "Set TEE_CRAFTER_REQUIRE_ATTESTATION_TOOLS=0 to bake without them on purpose." >&2
        exit 1
    fi
fi

# --- Bake marker ---
mkdir -p /etc/tee_crafter
echo "baked_snp_aws $(date -u +%Y%m%dT%H%M%SZ)" > /etc/tee_crafter/baked_snp_aws

echo "=== TEE-Crafter: AMD SEV-SNP (AWS) setup complete ==="
