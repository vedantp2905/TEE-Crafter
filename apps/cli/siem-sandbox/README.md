# SIEM Sandbox — *who owns what?*

**The customer brings the SIEM endpoint.** TEE-Crafter never ingests, stores, or hosts attestation events. The exporter inside the TEE sends to whatever endpoint the operator hands us via `--siem-config` (HTTPS for Splunk HEC / Datadog / Azure Monitor, or RFC 5424 syslog for `syslog-cef`). That's the entire runtime story.

This directory is a **dev-time receiver** for *us* (the framework authors) and for *prospective customers evaluating TEE-Crafter*. Splunk HEC runs behind an `nginx` stand-in for the AWS ALB; syslog-CEF uses `syslog-ng` as an RFC 5424 receiver. The smoke tests exercise the same exporter classes that ship inside TEEs — expect to add at least one similar sandbox per provider over time.

Nothing in this directory is a runtime dependency of any TEE-Crafter customer.

## Provider matrix

| Provider | Status | Sandbox dir | Real image used |
|---|---|---|---|
| **Splunk HEC** | ready | [`splunk/`](./splunk) | `splunk/splunk:latest` (the same image you put behind an ALB in Fargate) |
| **syslog-CEF** | ready | [`syslog/`](./syslog) | `balabit/syslog-ng:4.8.3` (the same RFC 5424 receiver behind a Fluent Bit / rsyslog forwarder in prod) |
| Datadog | planned | `datadog/` | `mockserver/mockserver` (Datadog Logs intake is SaaS-only — no self-hosted variant) |
| CloudWatch | planned | `cloudwatch/` | `localstack/localstack` (real AWS SDK over a local endpoint) |
| Azure Monitor | planned | `azure-monitor/` | `mockserver/mockserver` (Log Ingestion API is SaaS-only) |

## Mental model — production-shaped HTTPS in every tier

```
   ┌──────────────────────────┐                ┌───────────────────────────────────────┐
   │   TEE workload           │  exactly one   │   "ALB" — TLS terminator              │
   │   - SNP/TDX/Nitro/SGX    │  TLS hop ─────▶│   - Tier 1:  nginx-alb in docker      │
   │   - reads siem.env @boot │  on the wire   │              (self-signed dev cert)   │
   │   - emits Attestation    │  the TEE sees  │   - Tier 2:  ngrok edge               │
   │     Events               │                │              (real Let's-Encrypt)     │
   └──────────────────────────┘                │   - Tier 3:  AWS ALB + ACM cert       │
                                               └───────────────────┬───────────────────┘
                                                                   │ plain HTTP
                                                                   ▼
                                                    ┌──────────────────────────────┐
                                                    │  SIEM backend                │
                                                    │  splunk / datadog / syslog / │
                                                    │  cloudwatch / azure-monitor  │
                                                    └──────────────────────────────┘
```

**Splunk HEC:** identical wire shape in every tier — exactly one TLS terminator at the front of the chain, plain HTTP to Splunk. Only the *identity* of the TLS terminator changes (nginx → ngrok → ALB). Same JSON config shape; only the `endpoint` URL differs.

**syslog-CEF:** there is no HTTP layer — the TEE emits RFC 5424 + CEF over UDP or TCP. Tier 2 uses **`ngrok tcp`** (public `tcp://host:port` → local syslog-ng). See [`syslog/README.md`](./syslog/README.md).

---

## Tier 1: local smoke (laptop only, no cloud)

```bash
cd siem-sandbox/splunk
cp .env.example .env
docker compose up -d
docker compose logs -f splunk | grep -m1 "Ansible playbook complete"   # ~2 min first boot
python siem-sandbox/scripts/smoke_splunk.py
# -> 3 events sent, 3 events found in Splunk index=tee_crafter, p50 ~8 ms — PASS
```

Brings up two containers: Splunk (HEC HTTP `:8088`) and `nginx-alb` (HTTPS `:8443` w/ self-signed dev cert, reverse-proxies to Splunk). The smoke test posts at `https://localhost:8443/services/collector` — exactly the same wire shape as Tier 3.

---

## Tier 2: real cloud TEE → laptop Splunk, via ngrok

The TEE runs in AWS / GCP / Azure; your laptop's `:8443` isn't reachable from the cloud. ngrok publishes a public HTTPS URL (real Let's-Encrypt cert at its edge) and forwards plain HTTP into the docker network — specifically to `nginx-alb:8080`, so the **same nginx ALB layer is exercised in this tier** too.

```bash
# 1. Free ngrok authtoken: https://dashboard.ngrok.com → Your Authtoken
echo "NGROK_AUTHTOKEN=<paste>" >> siem-sandbox/splunk/.env

# 2. Bring up Splunk + nginx-alb + ngrok together
cd siem-sandbox/splunk
docker compose --profile ngrok up -d

# 3. Render a TEE-Crafter siem-config pointed at the live ngrok URL
python ../scripts/make_remote_splunk_siem_config.py
#  -> wrote siem-sandbox/configs/splunk-via-ngrok.json
#     endpoint = https://abc-123.ngrok-free.app/services/collector

# 4. Deploy a real SNP-AWS TEE that ships its attestation feed to your laptop
cd ../..
tee-crafter deploy-container \
    --tee-platform snp-aws \
    --ami-id "$SNP_AMI_AWS" \
    --source ./examples/docker_flask_api \
    --siem splunk-hec \
    --siem-config siem-sandbox/configs/splunk-via-ngrok.json \
    --deploy --auto-approve --teardown

# 5. Watch events live: open http://localhost:8000 → Search & Reporting
#    SPL:  index=tee_crafter | head 50
```

ngrok terminates real Let's-Encrypt TLS at its edge; the TEE sees a real CA-signed cert so `verify_ssl=0` is NOT needed. Free-tier ngrok rotates the public URL on each container restart — re-run `make_remote_splunk_siem_config.py` (or `make_remote_syslog_siem_config.py`) after every `docker compose restart ngrok`. Paid ngrok plans get reserved domains.

---

## Tier 3: production parity — Splunk in your AWS account

Same Splunk image, same `:8088` HTTP backend, same exporter code path. Replace `nginx-alb` with AWS ALB + ACM. Only the customer's `endpoint` URL changes.

| | Tier 1 (localhost) | Tier 2 (ngrok) | Tier 3 (Fargate prod) |
|---|---|---|---|
| Container image | `splunk/splunk:latest` | `splunk/splunk:latest` | `splunk/splunk:latest` |
| HEC backend | plain HTTP `:8088` | plain HTTP `:8088` | plain HTTP `:8088` |
| TLS terminator | `nginx-alb` (self-signed) | ngrok edge (Let's Encrypt) | ALB + ACM cert |
| Customer-facing URL | `https://localhost:8443/...` | `https://*.ngrok-free.app/...` | `https://splunk-hec.example.com/...` |
| Token storage | `.env` | `.env` | AWS Secrets Manager → ECS task secret |
| `extra.verify_ssl` | `"0"` (self-signed) | unset (real cert) | unset (real cert) |
| `egress_mode` | `none` | `public` | `public` + ALB CIDR in `egress_allowlist_cidrs` |

Fargate Terraform recipe (ECS service + ALB + ACM + Secrets Manager + outputs the HEC URL) is planned at `siem-sandbox/splunk/terraform/fargate/` — ~150 lines, ask when you want it scaffolded.

---

## syslog-CEF sandbox (syslog-ng)

```bash
cd siem-sandbox/syslog
docker compose up -d
cd ../..
python siem-sandbox/scripts/smoke_syslog.py
```

**Tier 2 (ngrok TCP)** — same pattern as Splunk, but `ngrok tcp` instead of `ngrok http` (syslog is not HTTPS). Agent API on **:4041** so it does not collide with Splunk’s ngrok on :4040.

```bash
echo "NGROK_AUTHTOKEN=<paste>" >> siem-sandbox/syslog/.env
cd siem-sandbox/syslog && docker compose --profile ngrok up -d
cd ../.. && python siem-sandbox/scripts/make_remote_syslog_siem_config.py
# -> siem-sandbox/configs/syslog-via-ngrok.json
```

Full walk-through: [`syslog/README.md`](./syslog/README.md).
