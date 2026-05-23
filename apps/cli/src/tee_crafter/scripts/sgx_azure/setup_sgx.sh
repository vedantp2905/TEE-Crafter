#!/bin/bash
# SGX/Gramine host setup for Ubuntu 22.04 on Azure DCsv3 instances.
# Installs SGX PSW, DCAP, Gramine, Python deps.
# Every literal brace below is doubled; loaders.render_sgx_setup_script undoes
# that.  There are no substitution placeholders — do not add a str.format()
# caller, the awk and JSON braces here would break it.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

wait_for_dpkg_lock() {{
  local lock_file="/var/lib/dpkg/lock-frontend"
  local waited=0
  local max_wait=600
  local delay=5

  while fuser "$lock_file" >/dev/null 2>&1; do
    echo "dpkg lock ($lock_file) held by another process; waiting $delay seconds..."
    sleep "$delay"
    waited=$((waited + delay))
    if [ "$waited" -ge "$max_wait" ]; then
      echo "Timed out waiting for dpkg lock after $max_wait seconds; continuing anyway."
      break
    fi
  done
}}

retry_apt() {{
  n=0
  max=10
  delay=15
  while [ "$n" -lt "$max" ]; do
    wait_for_dpkg_lock
    if apt-get "$@"; then
      return 0
    fi
    n=$((n+1))
    echo "apt-get failed (attempt $n/$max), sleeping $delay seconds before retrying..."
    sleep "$delay"
  done
  echo "apt-get failed after $max attempts; giving up."
  return 1
}}

echo "=== TEE-Crafter SGX Setup (Ubuntu 22.04 / Azure DCsv3) ==="

# 1. System update and base packages; prefer Python 3.12 but gracefully
#    fallback to distro python when 3.12 packages are unavailable.
retry_apt update -y
retry_apt install -y \
  git wget curl \
  gcc g++ make cmake \
  openssl libssl-dev \
  gnupg2 software-properties-common \
  unzip \
  || true
add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null || true
retry_apt update -y
retry_apt install -y python3.12 python3.12-venv python3.12-dev || true
retry_apt install -y python3 python3-venv python3-dev || true
# distutils is removed in newer Python packaging; avoid hard dependency on it.
# pip will be installed inside the venv later; don't install into system python
if [ -x /usr/bin/python3.12 ]; then
  PYTHON_BIN="/usr/bin/python3.12"
else
  PYTHON_BIN="/usr/bin/python3"
fi
"$PYTHON_BIN" -m ensurepip --upgrade 2>/dev/null || true

# 2. Install Azure CLI (for Blob Storage operations in post-deploy)
#    SUP-2: download → checksum → execute.  When the operator passes the
#    expected SHA-256 via $TEE_CRAFTER_AZ_CLI_INSTALLER_SHA256 (set by the
#    bake script from a known good value), the installer is rejected if its
#    hash drifts.  Otherwise the observed hash is just logged for review.
if ! command -v az >/dev/null 2>&1; then
  AZ_INSTALL_SCRIPT=$(mktemp)
  curl --proto '=https' --tlsv1.2 -fsSL https://aka.ms/InstallAzureCLIDeb -o "$AZ_INSTALL_SCRIPT"
  AZ_INSTALLER_SHA=$(sha256sum "$AZ_INSTALL_SCRIPT" | awk '{print $1}')
  echo "azure-cli installer sha256=$AZ_INSTALLER_SHA"
  if [ -n "${TEE_CRAFTER_AZ_CLI_INSTALLER_SHA256:-}" ]; then
    if [ "$AZ_INSTALLER_SHA" != "$TEE_CRAFTER_AZ_CLI_INSTALLER_SHA256" ]; then
      echo "FATAL [SUP-2]: azure-cli installer sha256 mismatch (expected $TEE_CRAFTER_AZ_CLI_INSTALLER_SHA256, got $AZ_INSTALLER_SHA)" >&2
      rm -f "$AZ_INSTALL_SCRIPT"
      exit 1
    fi
    echo "✓ azure-cli installer sha256 matches pinned value (SUP-2)"
  fi
  bash "$AZ_INSTALL_SCRIPT"
  rm -f "$AZ_INSTALL_SCRIPT"
fi

# 3. Install Intel SGX PSW and DCAP from Intel's Ubuntu repo
echo "Installing Intel SGX PSW and DCAP..."
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
  gpg --dearmor -o /usr/share/keyrings/intel-sgx-keyring.gpg 2>/dev/null || true
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" \
  > /etc/apt/sources.list.d/intel-sgx.list
retry_apt update -y
# Do NOT install libsgx-dcap-default-qpl — it conflicts with az-dcap-client.
# Azure provides its own QPL (Quote Provider Library) via az-dcap-client.
retry_apt install -y \
  libsgx-launch libsgx-urts \
  libsgx-epid libsgx-quote-ex \
  libsgx-dcap-ql \
  sgx-aesm-service \
  2>/dev/null || echo "Some SGX packages may not be available; continuing..."

# 3b. Azure DCAP client — replaces Intel's default QPL with Azure-hosted
# provisioning certificate caching service. MUST be installed BEFORE
# starting AESM so it picks up the Azure QPL on first start.
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" \
  > /etc/apt/sources.list.d/msprod.list
curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add - 2>/dev/null || true
retry_apt update -y
retry_apt install -y az-dcap-client 2>/dev/null || {{
  echo "WARNING: Could not install az-dcap-client — DCAP attestation may fail"
}}
# Remove Intel default QPL if it was pulled in as a dependency
dpkg -l libsgx-dcap-default-qpl 2>/dev/null | grep -q "^ii" && {{
  apt-get remove -y libsgx-dcap-default-qpl 2>/dev/null || true
  echo "Removed libsgx-dcap-default-qpl (conflicts with az-dcap-client)"
}}

# 4. Start SGX AESM service (manages quoting enclaves for DCAP).
# Restart to ensure it picks up az-dcap-client QPL.
systemctl enable aesmd 2>/dev/null || true
systemctl restart aesmd 2>/dev/null || true
sleep 2
if systemctl is-active --quiet aesmd 2>/dev/null; then
  echo "AESM service started with Azure DCAP QPL"
else
  echo "WARNING: AESM service not running (SGX may not be available on this instance)"
  journalctl -u aesmd --no-pager -n 10 2>/dev/null || true
fi

# 5. Install Gramine from official Ubuntu PPA
echo "Installing Gramine..."
if command -v gramine-sgx &>/dev/null; then
  echo "Gramine already installed"
else
  curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg \
    https://packages.gramineproject.io/gramine-keyring.gpg 2>/dev/null || true
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ jammy main" \
    > /etc/apt/sources.list.d/gramine.list
  retry_apt update -y
  retry_apt install -y gramine || {{
    echo "apt install gramine failed; trying pip in venv..."
    mkdir -p /opt/tee-crafter-sgx
    "$PYTHON_BIN" -m venv /opt/tee-crafter-sgx/venv 2>/dev/null || true
    /opt/tee-crafter-sgx/venv/bin/pip install gramine 2>/dev/null || echo "WARNING: Could not install Gramine"
  }}
fi

# 5b. Install Gramine Shielded Containers (GSC) so the *VM* can graminize.
#
# `sgx-azure --batch` used to graminize on the operator's workstation and upload
# the result.  That cannot work off an amd64 host: GSC never passes a platform to
# `docker build` (there is no `platform` anywhere in gsc.py), so it builds for the
# daemon's native architecture, and Gramine/SGX is x86-only.  On an Apple Silicon
# machine it produced an arm64 Gramine — verified on 2026-08-22, where the build
# pulled `libcurl4t64:arm64`.  Graminizing here instead is both correct and
# better: this VM is amd64, has real SGX, and can therefore report a MRENCLAVE
# that was measured rather than guessed.
#
# Pins are duplicated from apps/cli/Dockerfile deliberately (this script runs on
# a VM with no access to that file); tests/cli/test_sgx_gsc_pin_parity.py asserts
# they stay equal.  GSC_REF is a commit rather than v1.9 because v1.9's
# `extract_user_from_image_config` does `config['User']` unguarded and Docker
# omits that key when the image sets no USER.
GSC_REF=0b2ba9312c6120b5ebe2e55fb2bd7315b334361e
GRAMINE_BRANCH=v1.9
if command -v gsc &>/dev/null; then
  echo "GSC already installed"
else
  echo "Installing GSC at ${{GSC_REF}} (Gramine ${{GRAMINE_BRANCH}})..."
  retry_apt install -y git python3-pip || true
  GSC_VENV=/opt/tee-crafter-gsc/venv
  mkdir -p /opt/tee-crafter-gsc
  "$PYTHON_BIN" -m venv "$GSC_VENV" 2>/dev/null || true
  "$GSC_VENV/bin/pip" install --no-cache-dir --upgrade pip >/dev/null 2>&1 || true
  "$GSC_VENV/bin/pip" install --no-cache-dir docker jinja2 tomli tomli-w pyyaml \
    || echo "WARNING: GSC python deps failed"
  rm -rf /opt/gsc
  git init -q /opt/gsc \
    && git -C /opt/gsc remote add origin https://github.com/gramineproject/gsc.git \
    && git -C /opt/gsc fetch -q --depth 1 origin "$GSC_REF" \
    && git -C /opt/gsc checkout -q FETCH_HEAD \
    || echo "WARNING: could not fetch GSC"
  # GSC's Debian template adds Intel's SGX apt repo with `apt-key`, which
  # Debian 13 removed, and Debian 13's apt verifies with sqv (which rejects
  # Intel's otherwise-valid signature) rather than gpgv.  Untouched, every
  # `gsc build` on a python:3.x-slim image dies with `apt-key: not found`.
  # The patch script carries the full reasoning and the measurements.
  #
  # Ubuntu shares that template, so this is not Debian-only insurance: it is
  # what keeps three of the four shipped examples graminizable.
  cat > /opt/tee-crafter-gsc/patch_gsc_debian_template.py <<'TEE_CRAFTER_GSC_PATCH_EOF'
__GSC_DEBIAN_PATCH_SCRIPT__
TEE_CRAFTER_GSC_PATCH_EOF
  "$GSC_VENV/bin/python" /opt/tee-crafter-gsc/patch_gsc_debian_template.py /opt/gsc \
    || echo "WARNING: could not patch GSC's debian template for Debian 13"

  if [ -f /opt/gsc/config.yaml.template ]; then
    sed -e "s|Branch:.*|Branch:     \"${{GRAMINE_BRANCH}}\"|" \
      /opt/gsc/config.yaml.template > /opt/gsc/config.yaml
    # gsc.py resolves config.yaml and templates/ against the *cwd*, so the
    # wrapper has to cd into the checkout.
    printf '#!/bin/sh\ncd /opt/gsc && exec %s ./gsc "$@"\n' "$GSC_VENV/bin/python" \
      > /usr/local/bin/gsc
    chmod +x /usr/local/bin/gsc
    # Fail loudly here rather than at deploy time: without this fix every
    # `gsc build` dies with KeyError: 'User'.
    grep -q "config.get('User')" /opt/gsc/gsc.py \
      && echo "GSC installed (User fix present)" \
      || echo "WARNING: pinned GSC lacks the config.get('User') fix"
    # Same idea for the apt-key patch: assert the post-condition here, where
    # the operator is already reading cloud-init output, rather than letting it
    # surface 20 minutes later as a failed `gsc build`.
    grep -q "signed-by=/etc/apt/keyrings/intel-sgx.asc" \
      /opt/gsc/templates/debian/Dockerfile.compile.template \
      && echo "GSC installed (Debian 13 apt-key patch present)" \
      || echo "WARNING: GSC debian template still uses apt-key; SGX builds from a Debian 13 base will fail"
    gsc --help >/dev/null 2>&1 && echo "gsc wrapper OK" || echo "WARNING: gsc wrapper broken"
  fi
fi

# 5c. Pre-build the base-Gramine image, HERE, while this VM still has egress.
#
# This is the difference between a platform that works and one that does not.
# `sgx-azure` is pre-baked-only -- `--batch` never runs this script at deploy
# time (that call sits on the unreachable `--persistent` path) -- and the deploy
# VM's NSG denies all outbound except HTTPS to VirtualNetwork.  But the config
# written above says `Repository` + `Branch`, which instructs GSC to *clone and
# compile Gramine from source*, and it defers that to `gsc build` at deploy
# time.  So the network-dependent half of the work was being handed to the one
# machine that has no network: `gsc build` died at `Step 1/30 : FROM debian:13`
# with a Docker Hub i/o timeout, twenty-five minutes into a deploy.
#
# `gsc build-gramine` exists precisely for this.  It renders the compile stage
# on its own and produces a self-contained base-Gramine image; setting
# `Gramine.Image` afterwards makes `gsc build` skip the compile stage entirely
# (templates/Dockerfile.common.build.template lines 1-6).  That removes the
# debian:13 pull, Intel's SGX repository, the GitHub clone and the ~8-minute
# compile from deploy time -- and moves the Debian-13 apt-key patch to bake
# time, where egress exists and where it belongs.
#
# What this does NOT remove: GSC's *build* stage is `FROM <the user's image>`
# and apt-installs Gramine's runtime dependencies into it.  The user's image is
# unknown until deploy, so that one apt transaction cannot be pre-baked.  It is
# the entire remaining egress requirement -- see docs/sgx_flow.md.
#
# Distro is pinned rather than "auto" because `gsc build-gramine` refuses auto,
# and because the compile stage's distro should match the app image's: our
# examples are python:3.12-slim, i.e. debian:13.  An app image from a different
# distro family may hit a glibc mismatch against these binaries; that is the
# documented cost of pre-building.
GRAMINE_BASE_DISTRO="debian:13"
GRAMINE_BASE_IMAGE="tee-crafter/gramine:${{GRAMINE_BRANCH}}-debian13"
if command -v gsc >/dev/null 2>&1 && [ -f /opt/gsc/config.yaml ]; then
  if docker image inspect "$GRAMINE_BASE_IMAGE" >/dev/null 2>&1; then
    echo "Base-Gramine image $GRAMINE_BASE_IMAGE already present"
  else
    echo "Pre-building base-Gramine image $GRAMINE_BASE_IMAGE (compiles Gramine; several minutes)..."
    # `gsc build-gramine` refuses to run when Gramine.Image is set, so it gets
    # its own config file and the deploy-time one is rewritten afterwards.
    cat > /opt/gsc/config.build-gramine.yaml <<GRAMINECFG
Distro: "$GRAMINE_BASE_DISTRO"
Registry: ""
Gramine:
    Repository: "https://github.com/gramineproject/gramine.git"
    Branch:     "${{GRAMINE_BRANCH}}"
GRAMINECFG
    if gsc build-gramine -c /opt/gsc/config.build-gramine.yaml "$GRAMINE_BASE_IMAGE"; then
      echo "Base-Gramine image built: $GRAMINE_BASE_IMAGE"
    else
      echo "WARNING: gsc build-gramine failed; deploy will fall back to compiling Gramine on the VM (needs egress)" >&2
    fi
  fi

  # Point the deploy-time config at the pre-built image.  Distro stays "auto"
  # so GSC still detects the *app* image's distro for its build stage; only the
  # Gramine binaries are pinned to what we compiled above.
  if docker image inspect "$GRAMINE_BASE_IMAGE" >/dev/null 2>&1; then
    cat > /opt/gsc/config.yaml <<DEPLOYCFG
Distro: "auto"
Registry: ""
Gramine:
    Image:      "$GRAMINE_BASE_IMAGE"
DEPLOYCFG
    grep -q "Image:" /opt/gsc/config.yaml \
      && echo "GSC configured to use the pre-built Gramine image (no compile at deploy)" \
      || echo "WARNING: could not point GSC at the pre-built Gramine image" >&2
  fi
fi

# 6. Generate Gramine SGX signing key
if [ ! -f /root/.config/gramine/enclave-key.pem ]; then
  mkdir -p /root/.config/gramine
  gramine-sgx-gen-private-key -o /root/.config/gramine/enclave-key.pem 2>/dev/null || \
    openssl genrsa -3 3072 > /root/.config/gramine/enclave-key.pem
  chmod 600 /root/.config/gramine/enclave-key.pem
  echo "Generated Gramine SGX signing key"
fi

# 7. Install Python 3.12 dependencies in an isolated venv (do NOT pollute
#    the system Python 3.10 — cloud-init and waagent depend on it).
VENV_DIR="/opt/tee-crafter-sgx/venv"
mkdir -p /opt/tee-crafter-sgx
"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install --no-cache-dir \
  "cryptography>=42.0,<44" \
  "boto3>=1.34,<2" \
  "requests>=2.31,<3" \
  "cbor2>=5.6,<6" \
  "pydantic>=2.7,<3" \
  || true

mkdir -p /etc/tee_crafter
"$VENV_DIR/bin/pip" freeze --all 2>/dev/null \
  > /etc/tee_crafter/image_pip_frozen.txt || true
chmod 0644 /etc/tee_crafter/image_pip_frozen.txt 2>/dev/null || true

# --- Pre-pull common Docker base images for handler / container builds ---
# Saves ~10-20 s per first build at deploy time. Best-effort.
# Note: this file is loaded via load_setup_script with .replace("{{","{")
# so quad-brace is the source form for a literal {{ in the rendered shell.
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
  docker image ls --format '{{{{.Repository}}}}:{{{{.Tag}}}} {{{{.Size}}}}' \
      > /etc/tee_crafter/image_docker_prewarmed.txt 2>/dev/null || true
fi

# 7b. Ensure cloud-init and waagent are healthy (critical for image capture).
#     Our pip installs above used a venv, so the system Python 3.10 should
#     be untouched — but verify and repair if needed.
if ! /usr/bin/python3.10 -c "import requests" 2>/dev/null; then
  echo "WARNING: System python3.10 'requests' module missing — reinstalling..."
  apt-get install -y --reinstall python3-requests 2>/dev/null || true
fi
if ! /usr/bin/python3.10 -c "import cloudinit" 2>/dev/null; then
  echo "WARNING: cloud-init broken — reinstalling..."
  apt-get install -y --reinstall cloud-init 2>/dev/null || true
fi

# 7c. Ensure waagent is running
systemctl enable walinuxagent 2>/dev/null || systemctl enable waagent 2>/dev/null || true
systemctl start walinuxagent 2>/dev/null || systemctl start waagent 2>/dev/null || true
echo "waagent status: $(systemctl is-active walinuxagent 2>/dev/null || systemctl is-active waagent 2>/dev/null || echo 'unknown')"
echo "cloud-init status: $(cloud-init status 2>&1 | head -1 || echo 'unavailable')"

# 8. Create dedicated service user and application directory
# Install parallel compressors used by deploy-time tarball transfer.
apt-get install -y pigz zstd 2>/dev/null || true
id -u tee_enclave >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin tee_enclave
# tee_enclave needs access to SGX devices for DCAP attestation
getent group sgx >/dev/null 2>&1 && usermod -aG sgx tee_enclave 2>/dev/null || true
chmod 0660 /dev/sgx_enclave 2>/dev/null || true
chgrp sgx /dev/sgx_enclave 2>/dev/null || true
chmod 0660 /dev/sgx/enclave 2>/dev/null || true
chgrp sgx /dev/sgx/enclave 2>/dev/null || true
chmod 0660 /dev/sgx_provision 2>/dev/null || true
chgrp sgx /dev/sgx_provision 2>/dev/null || true
mkdir -p /home/azureuser/sgx-app/app
chmod o+x /home/azureuser
chown -R tee_enclave:tee_enclave /home/azureuser/sgx-app

# 9. (SGX only) No host-side TLS certificate is generated.
# The SGX enclave always terminates TLS itself via RA-TLS: Gramine's
# librats library mints a fresh ECDSA keypair on startup, binds it to an
# SGX DCAP quote (SHA-256(EC pubkey) → quote.report_data), and issues a
# self-signed X.509 whose custom extension contains the quote.  Any
# non-RA-TLS cert on disk would be a trust-anchor the client cannot
# verify via hardware attestation, so we deliberately do NOT produce one
# here to avoid silent fallbacks.  If operators need a plaintext TLS
# endpoint for testing they must generate their own cert and point
# uvicorn at it explicitly.
mkdir -p /etc/tee_crafter/certs
chmod 0750 /etc/tee_crafter/certs
# Remove any stale self-signed cert that might have been baked into a
# previous image — we never want the SGX enclave trusting it.
rm -f /etc/tee_crafter/certs/host.key /etc/tee_crafter/certs/host.crt

# 10. Require SGX hardware (Azure DCsv3 exposes /dev/sgx_enclave)
if [ -e /dev/sgx_enclave ] || [ -e /dev/sgx/enclave ]; then
  GRAMINE_BIN="/usr/bin/gramine-sgx"
  SGX_MODE="hw"
  echo "SGX hardware detected (/dev/sgx_enclave). Using gramine-sgx (hardware mode)."
else
  echo "ERROR: No /dev/sgx_enclave device found."
  echo "  SGX requires an Azure DCsv3 or DCdsv3 confidential VM."
  echo "  Use: tee-crafter deploy --tee-platform sgx-azure ..."
  echo "  (SGX deploys default to Standard_DC2s_v3; override via"
  echo "  --instance-type Standard_DC4s_v3 if needed.)"
  exit 1
fi

echo "$SGX_MODE" > /home/azureuser/sgx-app/.sgx_mode

# 11. Create systemd service for the SGX enclave
cat > /etc/systemd/system/sgx-enclave.service <<'EOF'
__SYSTEMD_UNIT__
EOF

systemctl daemon-reload
systemctl enable sgx-enclave.service || true

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

# 11b. Docker Engine for container-mode deployments
echo "--- Installing Docker Engine (container mode support) ---"
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y ca-certificates curl gnupg pigz zstd 2>/dev/null || true
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

systemctl daemon-reload
echo "Docker installed: $(docker --version 2>/dev/null || echo 'failed')"

# 12. Write bake marker so deploy-time code can skip redundant setup
mkdir -p /etc/tee_crafter
cat > /etc/tee_crafter/baked_sgx <<MARKER
platform=sgx
baked_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gramine=$(gramine-sgx --version 2>/dev/null || echo unknown)
kernel=$(uname -r)
MARKER

echo "=== SGX Setup Complete ==="
echo "SGX mode: $SGX_MODE (binary: $GRAMINE_BIN)"
echo "Gramine version: $(gramine-sgx --version 2>/dev/null || echo 'not available')"
echo "SGX driver: $(ls /dev/sgx* 2>/dev/null || echo 'not found')"
echo "gramine-sgx-sign: $(which gramine-sgx-sign 2>/dev/null || echo 'not found')"
echo "gramine-manifest: $(which gramine-manifest 2>/dev/null || echo 'not found')"
