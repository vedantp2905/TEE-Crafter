# syslog-CEF SIEM sandbox

Local `syslog-ng` receiver for the `syslog-cef` `--siem` provider. Listens for **RFC 5424** syslog (with `flags(syslog-protocol)`) on UDP `:514` and TCP `:601` inside the container, mapped to **UDP `localhost:5514`** and **TCP `localhost:6601`** on the host so you do not clash with the OS syslog daemon.

## Tier 1 — localhost smoke (no cloud, no TEE)

```bash
cd siem-sandbox/syslog
cp .env.example .env          # optional
docker compose up -d
docker compose logs -f syslog-ng | grep -m1 "syslog-ng starting up"

cd ../..
python siem-sandbox/scripts/smoke_syslog.py
# udp:PASS  tcp:PASS — real SyslogCefExporter + ContinuousAttestor + Ed25519 verify
```

See `siem-sandbox/configs/syslog-local-udp.json` and `syslog-local-tcp.json` for drop-in `--siem-config` examples.

## Tier 2 — cloud TEE → laptop syslog-ng via ngrok (TCP)

Splunk HEC is HTTP, so Splunk’s sandbox uses `ngrok http` → `nginx-alb`. **Syslog is not HTTP** — the analogue is **`ngrok tcp`**, which publishes a public `tcp://host:port` that forwards raw bytes into syslog-ng’s TCP listener (`syslog-ng:601` on the docker network).

The ngrok **local agent API** defaults to `:4040`. The Splunk stack already binds `:4040`, so this compose mounts a small **ngrok Agent v3** config that sets `agent.web_addr: 0.0.0.0:4041` (v3 removed the `--web-addr` CLI flag) and maps **`4041:4041`**. `make_remote_syslog_siem_config.py` reads `http://localhost:4041/api/tunnels`.

```bash
# 1. Same free ngrok account as siem-sandbox/splunk/
echo "NGROK_AUTHTOKEN=<paste>" >> siem-sandbox/syslog/.env

# 2. syslog-ng + ngrok (TCP tunnel)
cd siem-sandbox/syslog
docker compose --profile ngrok up -d

# 3. Render --siem-config (host, port, protocol=tcp, egress_mode=public, egress_ports)
cd ../..
python siem-sandbox/scripts/make_remote_syslog_siem_config.py
#  -> wrote siem-sandbox/configs/syslog-via-ngrok.json
#     host = 0.tcp.ngrok.io, port = <assigned>

# 4. Deploy a real cloud TEE that ships syslog-CEF to your laptop
tee-crafter deploy-container \
    --tee-platform snp-aws \
    --ami-id "$SNP_AMI_AWS" \
    --source ./examples/docker_flask_api \
    --siem syslog-cef \
    --siem-config siem-sandbox/configs/syslog-via-ngrok.json \
    --deploy --auto-approve --teardown

# 5. Verify on the laptop
docker exec tee-crafter-syslog-ng tail -50 /var/log/tee-crafter/teelog.log
```

### Why `egress_mode` is `public` in the generated JSON

For `syslog-cef`, `egress_mode: auto` means **intra-VPC only** (no NAT) — correct for a collector inside the VPC, wrong for a public ngrok endpoint. The generated file sets **`egress_mode: public`** so the cloud VM gets NAT egress, and **`egress_ports: [<ngrok port>]`** so when you add `egress_allowlist_cidrs`, AWS security-group rules target the right outbound destination port.

### UDP syslog over the public internet

Free ngrok is **TCP-oriented** for this workflow. **Tier 2 here is TCP-only.** If you must exercise UDP from a cloud TEE, use a VPN / tailscale / site-to-site path into your lab VLAN instead of raw UDP through ngrok.

### Paid ngrok — stable TCP address

Set `NGROK_TCP_URL` in `siem-sandbox/syslog/.env` to the reserved endpoint from the ngrok dashboard (example: `1.tcp.ngrok.io:27210`). The compose command passes `ngrok tcp … --url=$NGROK_TCP_URL` when that variable is non-empty (see `ngrok tcp --help`).

## Teardown

```bash
cd siem-sandbox/syslog
docker compose --profile ngrok down -v   # `-v` drops the log volume too
```
