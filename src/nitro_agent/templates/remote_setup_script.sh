#!/bin/bash
# Nitro Enclaves host setup: install CLI, allocator, vsock proxy, docker.
# Placeholders: {allocator_mb}, {cpu}, {aws_region} (replaced by Python .format).

set -e
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
retry_dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker python3-pip || true

# Install Python libraries for attestation verification (used by client.py)
pip3 install cbor2 cryptography requests pydantic fastapi uvicorn boto3 || true

# Generate a self-signed TLS certificate for the Host Proxy
mkdir -p /etc/nitro_agent/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nitro_agent/certs/host.key -out /etc/nitro_agent/certs/host.crt -subj "/C=US/ST=State/L=City/O=NitroAgent/CN=nitro-enclave.local"
chmod 600 /etc/nitro_agent/certs/host.key

systemctl start docker || true
systemctl enable docker || true
usermod -aG docker ec2-user || true
usermod -aG ne ec2-user || true

mkdir -p /etc/nitro_enclaves
cat > /etc/nitro_enclaves/allocator.yaml <<ALLOC
---
memory_mib: {allocator_mb}
cpu_count: {cpu}
ALLOC

systemctl enable --now nitro-enclaves-allocator.service || true

systemctl stop nitro-enclaves-vsock-proxy.service 2>/dev/null || true

# Write a minimal allowlist (avoids DNS issues with the default global config)
cat > /etc/nitro_enclaves/vsock-proxy.yaml <<VSOCKCFG
allowlist:
  - {{address: kms.{aws_region}.amazonaws.com, port: 443}}
VSOCKCFG

mkdir -p /etc/systemd/system/nitro-enclaves-vsock-proxy.service.d
cat > /etc/systemd/system/nitro-enclaves-vsock-proxy.service.d/override.conf <<VSOCKOVERRIDE
[Service]
ExecStart=
ExecStart=/usr/bin/vsock-proxy 8000 kms.{aws_region}.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml -w 8
Environment=RUST_LOG=info
Restart=always
RestartSec=2
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

cat > /etc/systemd/system/host-proxy.service <<EOF
[Unit]
Description=Host API Proxy for Nitro Enclave
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/ec2-user
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=/usr/bin/python3 -m uvicorn host_proxy:app --host 0.0.0.0 --port 443 --ssl-keyfile=/etc/nitro_agent/certs/host.key --ssl-certfile=/etc/nitro_agent/certs/host.crt
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
# We don't start it yet since host_proxy.py hasn't been uploaded
systemctl enable host-proxy.service || true
