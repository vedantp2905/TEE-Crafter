#!/bin/bash
# Nitro Enclaves host setup: install CLI, allocator, vsock proxy, docker.
# Placeholders: {allocator_mb}, {cpu}, {aws_region} (replaced by Python .format).
#
# PRODUCTION NOTE: For the highest security, build a custom AMI with all
# dependencies pre-baked so this script is never run at boot and the instance
# never needs outbound internet access at all. This eliminates supply-chain
# risk from runtime package fetching.

set -euo pipefail
retry_dnf() {{
  n=0
  max=3
  delay=10
  while [ "$n" -lt "$max" ]; do
    dnf "$@" && return 0
    n=$((n+1))
    sleep "$delay"
  done
  return 1
}}

retry_dnf update -y || true
retry_dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker aws-cli || true
retry_dnf install -y python3.12 python3.12-pip || retry_dnf install -y python3 python3-pip || true
# Parallel compressors for deploy-time tarball transfer (see docs/optimizations.md §4)
retry_dnf install -y pigz zstd || true

# Verify aws CLI is available (critical for S3 EIF download at deploy time)
if ! command -v aws >/dev/null 2>&1; then
  echo "WARNING: aws CLI not found after dnf install — installing manually"
  ARCH=$(uname -m)
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${{ARCH}}.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install || true
  rm -rf /tmp/aws /tmp/awscliv2.zip
fi
echo "aws CLI: $(command -v aws 2>/dev/null || echo 'NOT FOUND')"
aws --version 2>/dev/null || true

# Pin versions to reduce supply-chain risk. Bump deliberately after review.
# Prefer Python 3.12 when available, otherwise fallback to system python3.
if [ -x /usr/bin/python3.12 ]; then
  PYTHON_BIN="/usr/bin/python3.12"
else
  PYTHON_BIN="/usr/bin/python3"
fi
"$PYTHON_BIN" -m pip install --no-cache-dir \
  "cbor2>=5.6,<6" \
  "cryptography>=42.0,<44" \
  "requests>=2.31,<3" \
  "pydantic>=2.7,<3" \
  "fastapi>=0.111,<1" \
  "uvicorn>=0.29,<1" \
  "boto3>=1.34,<2" \
  || true

mkdir -p /etc/tee_crafter
"$PYTHON_BIN" -m pip freeze 2>/dev/null \
  > /etc/tee_crafter/image_pip_frozen.txt || true
chmod 0644 /etc/tee_crafter/image_pip_frozen.txt 2>/dev/null || true

# --- Pre-pull common Docker base images for handler / container builds ---
# Saves ~15-30 s per first build at deploy time, and is essential on
# Nitro where the enclave docker build has no public-internet egress —
# the parent EIF builder reads from the host's local registry cache.
# Best-effort — silent if registry unreachable.
# Note: this file is rendered through Python str.format(), so use
# quad-brace ({{{{...}}}}) so the rendered shell sees {{...}}.
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

# Generate a self-signed TLS certificate for the Host Proxy
mkdir -p /etc/tee_crafter/certs
openssl req -x509 -nodes -days 365 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout /etc/tee_crafter/certs/host.key -out /etc/tee_crafter/certs/host.crt -subj "/C=US/ST=State/L=City/O=TEECrafter/CN=tee-enclave.local"
chmod 600 /etc/tee_crafter/certs/host.key

systemctl start docker || true
systemctl enable docker || true
usermod -aG docker ec2-user || true
usermod -aG ne ec2-user || true

# Dedicated unprivileged runtime account for host-proxy service
id -u tee_enclave >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/tee_enclave --shell /usr/sbin/nologin tee_enclave
usermod -aG ne tee_enclave || true
# host-proxy.service uses ReadWritePaths=/var/log/tee_crafter; systemd 226/NAMESPACE
# fails if this path is missing at unit start.  Create explicitly for bakes that
# skip LogsDirectory= (older units) or odd ordering.
mkdir -p /var/log/tee_crafter
chown tee_enclave:tee_enclave /var/log/tee_crafter 2>/dev/null || chown root:root /var/log/tee_crafter || true
chmod 755 /var/log/tee_crafter 2>/dev/null || true
chown -R tee_enclave:tee_enclave /opt/tee-crafter 2>/dev/null || true
chmod 755 /opt/tee-crafter 2>/dev/null || true
chown root:tee_enclave /etc/tee_crafter/certs/host.key /etc/tee_crafter/certs/host.crt || true
chmod 640 /etc/tee_crafter/certs/host.key /etc/tee_crafter/certs/host.crt || true

mkdir -p /etc/nitro_enclaves
cat > /etc/nitro_enclaves/allocator.yaml <<ALLOC
---
memory_mib: {allocator_mb}
cpu_count: {cpu}
ALLOC

systemctl enable --now nitro-enclaves-allocator.service || true

systemctl stop nitro-enclaves-vsock-proxy.service 2>/dev/null || true

# vsock-proxy allowlist: the enclave talks to exactly one hostname — the
# regional KMS endpoint — over TLS.  Any other allowlist entry would be a
# covert exfiltration channel into the enclave, so we write a single-host
# config with strict file permissions and verify it at each boot.
install -m 0644 -o root -g root /dev/null /etc/nitro_enclaves/vsock-proxy.yaml
cat > /etc/nitro_enclaves/vsock-proxy.yaml <<VSOCKCFG
# Managed by tee-crafter — do not edit.
# Any new entry here becomes a tunnel into the Nitro Enclave; review carefully.
allowlist:
  - {{address: kms.{aws_region}.amazonaws.com, port: 443}}
VSOCKCFG
chmod 0644 /etc/nitro_enclaves/vsock-proxy.yaml
chown root:root /etc/nitro_enclaves/vsock-proxy.yaml

# Fail loudly if something rewrote the allowlist to contain >1 entry.
ALLOWLIST_COUNT=$(grep -c '^[[:space:]]*-[[:space:]]*{{address' /etc/nitro_enclaves/vsock-proxy.yaml || echo 0)
if [ "$ALLOWLIST_COUNT" != "1" ]; then
    echo "FATAL: vsock-proxy allowlist must contain exactly 1 entry (found $ALLOWLIST_COUNT)" >&2
    exit 1
fi

mkdir -p /etc/systemd/system/nitro-enclaves-vsock-proxy.service.d
cat > /etc/systemd/system/nitro-enclaves-vsock-proxy.service.d/override.conf <<VSOCKOVERRIDE
[Service]
ExecStart=
# --num_workers (-w) bounds concurrent enclave<->KMS tunnels.  --max_connections_per_worker
# bounds per-worker connection reuse to prevent a compromised enclave from
# keeping a socket open indefinitely and using the proxy for persistent C2.
ExecStart=/usr/bin/vsock-proxy 8000 kms.{aws_region}.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml -w 8
Environment=RUST_LOG=info
Restart=always
RestartSec=2
# systemd hardening for the host-side proxy process.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @resources
SystemCallFilter=~@privileged @obsolete @raw-io @reboot @swap @debug @cpu-emulation @module @mount @keyring @pkey
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_VSOCK
UMask=0077
ReadWritePaths=/var/log
TimeoutStartSec=60s
VSOCKOVERRIDE

systemctl daemon-reload
systemctl enable nitro-enclaves-vsock-proxy.service || true
systemctl restart nitro-enclaves-vsock-proxy.service || true

# Verify vsock-proxy is running
sleep 2
if systemctl is-active --quiet nitro-enclaves-vsock-proxy.service; then
  echo "vsock-proxy is running"
else
  echo "WARNING: vsock-proxy failed to start" >&2
  journalctl -u nitro-enclaves-vsock-proxy.service --no-pager -n 20 >&2
fi

mkdir -p /opt/tee-crafter
chown tee_enclave:tee_enclave /opt/tee-crafter || true
chmod 755 /opt/tee-crafter || true

cat > /etc/systemd/system/host-proxy.service <<EOF
__SYSTEMD_UNIT__
EOF

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

systemctl daemon-reload
# We don't start it yet since host_proxy.py hasn't been uploaded
systemctl enable host-proxy.service || true

# --- UEFI Secure Boot enrollment (optional; replaced at bake-time) ---
#
# When `bake-ami --enable-secure-boot` is passed, the loader substitutes
# this placeholder with `scripts/common/secure_boot_enroll_aws.sh` which
# enrolls PK/KEK/db (Amazon Linux pre-signed blobs on AL2023) into the
# firmware NVRAM via `efi-updatevar`.  Without that flag the placeholder
# is replaced by a no-op so the bake produces a UEFI-but-SB-disabled AMI.
__SECURE_BOOT_ENROLL__

# --- Bake marker ---
mkdir -p /etc/tee_crafter
echo "baked_nitro_aws $(date -u +%Y%m%dT%H%M%SZ)" > /etc/tee_crafter/baked_nitro_aws
