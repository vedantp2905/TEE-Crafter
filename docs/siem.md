# Continuous attestation → SIEM / log pipeline

TEE-Crafter can stream **tamper-evident attestation events** (Ed25519-
signed and hash-chained) from inside the enclave to your existing log
pipeline. Auditors see one continuous stream of TEE health, and your
SOC can alert on attestation drift the same way it alerts on anything
else.

The core engine lives in
[`tee_crafter.core.audit.continuous`](../apps/cli/src/tee_crafter/core/audit/continuous.py);
exporters live under
[`tee_crafter.core.audit.exporters/`](../apps/cli/src/tee_crafter/core/audit/exporters).

## Supported pipelines

| Provider | Exporter | Transport | Egress style |
|-------------------|-----------------------------------|-------------------------|-------------------------------------|
| `none` | (off) | — | — |
| `syslog-cef` | RFC 5424 syslog with CEF payload | TCP (default) / UDP | Direct to SIEM, optional via VPC |
| `splunk-hec` | Splunk HTTP Event Collector | HTTPS | Public endpoint or PrivateLink |
| `datadog` | Datadog Logs Intake | HTTPS | Public endpoint |

> **`cloudwatch` and `azure-monitor` are not offered.** Exporter classes for
> both exist under `core/audit/exporters/`, but the sidecar that actually runs
> in the deployment (`templates/common/siem_export.py::_build_exporter`) has no
> case for them, so selecting either produced a sidecar that raised on every
> start and crash-looped while the deploy reported "SIEM sidecar active —
> events streaming". For `cloudwatch` Terraform also provisioned a CloudWatch
> Logs interface endpoint and a `logs:PutLogEvents` grant for a stream nothing
> wrote to. Both are removed from `--siem` until the sidecar factory
> implements them; re-adding one is a change to that factory, not new protocol
> work.

Exporters **fail-closed by default**: the `SiemConfig` dataclass
defaults `fail_open` to `False`
([`apps/cli/src/tee_crafter/cli/commands/deploy/siem_mode.py`](../apps/cli/src/tee_crafter/cli/commands/deploy/siem_mode.py)),
so on the nine platforms that serve requests — the eight CVMs and `nitro-aws` —
the main app refuses every request whenever the exporter can't prove freshness
(no health file inside the grace window, last export older than the lag
threshold, or the SIEM endpoint rejecting events).

### Which control you actually get, per platform and per run mode

The gate that refuses requests is `siem_health.fail_closed_wrap`, and it wraps
`process_request`. That single fact decides the whole table below: a platform
needs a request path for it to mean anything, and a `--batch` run does not have
one.

| Run mode | Platforms | Control | Mechanism |
|---|---|---|---|
| `--persistent` | the 8 CVM platforms | **preventive** | exporter runs in the VM; app loads `siem.env.public` via the unit's `EnvironmentFile=`, so it reads the same `siem.health` |
| `--persistent` | `nitro-aws` | **preventive** (since 2026-08) | exporter runs *inside the enclave* — see below |
| `--batch` | the 9 batch-capable platforms (everything except `nitro-aws`) | **preventive**, but on the output | no delivered audit trail → `output.tar.gz` is withheld and the deploy exits non-zero |

**`nitro-aws` is preventive, and that depends on where the exporter runs.** A
host-side sidecar cannot make this gate work: it would write
`/run/tee-crafter-nitro-aws/siem.health` on the *parent instance*, which the
enclave cannot read, and no SIEM variable would cross into the EIF — so
`TEE_CRAFTER_SIEM_ENABLED` would be unset in-enclave, `is_fail_closed` would
return `False`, and `fail_closed_wrap` would pass every request through. The
exporter therefore runs **inside** the enclave
(`app_vsock.start_in_enclave_siem_export`): the EIF carries
`siem_export.py` and a measured `siem.env.public`, the exporter writes its
health file to the enclave's own tmpfs, and it delivers over TLS it terminates
itself through a dedicated vsock tunnel (`127.0.0.2` → vsock 8001 → the
collector, alongside the existing KMS tunnel on `127.0.0.1` → vsock 8000). A
compromised parent instance can drop that traffic; it cannot read it, and it
cannot forge the collector's acceptance — which is what makes
`last_export_status` trustworthy in-enclave.

The bearer credential is **not** baked into the EIF. `siem.env.public` carries
only the non-secret half (provider, collector host/port, interval, flags); the
Splunk HEC token and Datadog API key are stripped by
`siem_mode.SECRET_ENV_KEYS` and reach the enclave over the attested
`--secrets-env` channel instead, so no live credential lands in an image whose
hash is published.

> **Not yet verified on hardware.** The fail path — a dark collector leaving the
> enclave fail-closed — is testable and tested. That events actually *arrive* at
> a collector from inside an enclave has not been demonstrated, because this
> project has no SIEM endpoint to point at on every platform. See
> [pending.md](pending.md) — the fail-closed direction has been exercised on
> `snp-aws` only.

**`sgx-azure` remains detective at request time, and always will.** It is
batch-only, so there are no requests to refuse. Its preventive control is the
batch output gate in the table above.
The in-TEE guard lives at
[`templates/common/siem_health.py`](../apps/cli/src/tee_crafter/templates/common/siem_health.py)
and the attested ingress proxy wraps request forwarding with
`siem_health.fail_closed_wrap` so a blackout
returns `{"error":"siem_blackout","reason":...,"policy":"fail_closed"}`
to the caller instead of touching user code. See
`docs/security.md §17.4` for the exact semantics and
`apps/cli/tests/cli/test_security_hardening.py::TestFailClosedGate` for the
behaviour matrix.

> **This gate only started acting on `splunk-hec` and `datadog` in
> 2026-08.** Until then both exporters caught every delivery failure —
> `HTTPError` for a bad token, and a bare `except Exception` covering DNS
> failure, connection refused, TLS errors and timeouts — logged a warning, and
> returned normally. `AttestationLoop.tick` derives `last_export_status` purely
> from whether `emit` raised, so those two providers reported `pass` forever
> and the gate above never engaged. Measured on a live `nitro-aws` deploy with
> the collector pointed at an RFC 2606 `.invalid` hostname: every POST failed
> with `gaierror(-2, 'Name or service not known')`, `siem.health` recorded
> `"last_export_status":"pass"`, and the deploy printed *"✓ SIEM sidecar active
> — events streaming (export confirmed)"*. `syslog-cef` over TCP was always
> correct; its UDP branch had the same flaw and was fixed at the same time.
>
> **Operational consequence, please read before upgrading — and note it is
> per-platform.** Now that these exporters report honestly, the fail-closed
> default does what it always claimed **on the eight CVM platforms**
> (`snp-aws`, `snp-azure`, `snp-gcp`, `tdx-azure`, `tdx-gcp`, `gpu-cc-aws`,
> `gpu-cc-azure`, `gpu-cc-gcp`) — and, since the exporter moved into the
> enclave in 2026-08, on `nitro-aws` too: a workload whose collector is unreachable or
> whose HEC token is wrong **will refuse every request** with
> `{"error":"siem_blackout"}`. That is the intended posture for PHI, and it is a
> behaviour change for any such deployment that has been quietly failing to
> export. Check `last_export_status` in
> `/run/tee-crafter-<platform>/siem.health` first, and set `"fail_open": true`
> in the `--siem-config` if you need to accept an unaudited workload while you
> fix the collector path.
>
> On those eight the exporter runs *inside* the VM and the app process loads
> `siem/siem.env.public` through the systemd unit's `EnvironmentFile=`, so
> `TEE_CRAFTER_SIEM_ENABLED=1` is set in the same namespace that reads
> `siem.health`.
>
> A UDP `sendto` that succeeds still proves only that the datagram reached the
> local kernel — never that the collector received it. That limit is inherent to
> UDP, so `syslog-cef` over UDP remains the weakest of the three delivery
> signals; prefer TCP where the gate's verdict matters.

### What happens when the SIEM endpoint goes dark mid-flight

The sidecar (`tee-crafter-siem.service`) keeps trying to deliver
events on the next tick; the **TEE process does not crash**. What
changes is the in-TEE attestation gate (``process_request`` wrappers):

1. `siem_export` writes `/run/tee-crafter-{platform}/siem.health`
 every `interval_seconds` with the last export status.
2. The next request triggers `assert_siem_healthy` which reads the
 health file. If `last_export_status != "pass"`, or the file is
 older than `max(120s, 3*interval_seconds)`, or the file disappeared
 after the `TEE_CRAFTER_SIEM_GRACE_SECONDS` (default 60s) grace
 window, the gate returns a 503-equivalent `siem_blackout`
 refusal payload.
3. The wrapper short-circuits before user code runs, so
 the workload never observes data without an audit trail.

Recover by either restoring the SIEM endpoint (next tick lands, the
gate re-opens) or rotating the bearer with `tee-crafter siem-stage`.
Setting `TEE_CRAFTER_SIEM_FAIL_OPEN=1` in the deploy env reverts to
log-and-keep-serving for prototyping; the override is recorded on
`SIEM-002`.

You can flip the posture **without editing the JSON** by exporting
the `TEE_CRAFTER_SIEM_FAIL_OPEN` env var in `.env` or your shell:

| Env value | Effect | When to use |
|---|---|---|
| `0` (or `false` / `no` / `off`) | **Force fail-closed** even if the JSON sets `"fail_open": true` (the production posture). | Promoting a sandbox config to a real deploy. The one config that ships in the repo, `apps/cli/siem-sandbox/configs/splunk-local.json`, carries `"fail_open": true` for local prototyping — set this to `0` before pointing it at anything real. |
| `1` (or `true` / `yes` / `on`) | **Force fail-open** even if the JSON sets `"fail_open": false`. | Eval/perf runs where you can tolerate lossy audit. |
| unset | Use whatever the JSON config says (default `false` if omitted). | Production with a hand-curated SIEM config. |

`SIEM-002` in the audit-evidence matrix records the **effective**
posture after this override and explicitly notes when an env override
was applied.

### Observing the gate on a run you are already paying for

The fail-closed direction is the one that matters and the harder one to see: a
collector that is *up* proves delivery, not refusal. It has been watched end to
end on `snp-aws`, where a deliberately dark collector correctly aborts the
deploy with `siem_blackout`. The other platforms take the same code path — the
seam is `install_siem_sidecar`, called once per platform phase — and have not
been watched.

Confirming it does **not** need its own deploy. On a persistent run that is
already up and verified, both observations come from the same VM:

1. Verify the healthy path first, so a later failure is attributable. The
 sidecar is delivering and the workload is serving.
2. Break the collector path, not the workload: revoke the bearer token at the
 SIEM, or point the collector's DNS/route at a black hole. Do not stop the
 sidecar — a stopped unit is a different failure from a delivery that fails,
 and only the second is what the gate reads.
3. Wait one `max(120s, 3 × interval_seconds)` staleness window, then send a
 request. Expect `{"error":"siem_blackout"}` and **no** user code having run.
4. Restore the collector, wait one tick, and confirm the gate re-opens.

Order matters: do this **before** teardown and after everything else on the run,
because step 2 deliberately makes the deployment refuse traffic. `nitro-aws` is
the one worth prioritising — its in-enclave exporter is proven to deliver, and
delivery is the direction that does not test the control.

## Token storage — tmpfs only (SIEM-SEC-2)

The bearer credential (`token`, `api_key`, `bearer`, …) never
touches the boot disk after deploy. The build directory stages
`siem/siem.env` (and the in-TEE bundle staging copy `app/siem.env`)
on the workstation; the install script then relocates it to
`/run/tee-crafter-{platform}/siem.env` (tmpfs, 0600,
`tee_enclave:tee_enclave`) and `shred -u` overwrites the disk copy
before unlinking it. Confidential VMs encrypt **memory**, not the
boot disk — without this control an EBS/managed-disk/PD snapshot
would expose the token in plaintext.

The non-secret half (provider, endpoint, index, the fail-closed
flag) is staged separately as `siem/siem.env.public` and **does**
survive reboots so the sidecar still has its non-credential config
after a reboot wipes /run.

### Rotation / post-reboot re-staging

```bash
# Rotate to a fresh HEC token without redeploying:
tee-crafter siem-stage \
    --platform snp-aws \
    --siem-config new-config.json \
    --instance-id i-0abc...

# Or via SSH (Azure / GCP):
tee-crafter siem-stage \
    --platform tdx-azure \
    --siem-config new-config.json \
    --ssh-host <vm-private-ip> \
 --ssh-key./build/azure_ssh_key.pem
```

Operators who explicitly accept the snapshot risk can keep the
on-disk copy by setting `TEE_CRAFTER_SIEM_PERSIST=1` in the deploy
environment — the install script then skips the shred step.

### Is rotation “on by default”?

**No.** `tee-crafter siem-stage` is **operator-triggered** (CLI or your
own automation). The product does **not** call your SIEM vendor to mint
new tokens on a schedule — that would require long-lived cloud-admin
credentials inside the CLI, which we deliberately avoid.

Best practice: when your vendor rotates the HEC/API key, drop the new
value into `siem.json`, run `tee-crafter siem-stage` against the live
instance, or wire an internal cron/GitHub Action that invokes the same
command with a refetched config. After **reboot**, tmpfs is empty; use
the same command to **re-stage** the secret half without rebuilding the
image.

### Workstation copies after `destroy`

After a **successful** `tee-crafter destroy`, `siem/siem.env` /
`siem.env` / `app/siem.env` (and `byok/byok.env` / `byok.env` /
`app/byok.env` if present) in the local build directory are
**overwritten and unlinked** together with SSH keys — see
`docs/security.md` §16.4 and `post_destroy_shred_manifest.txt`
(paths-only audit trail). Failed deploys **retain** those files so
you can fix config without re-pasting secrets.

## SIEM-side chain verification

The events form a hash-chained Ed25519-signed stream. Run
`tee-crafter verify-siem-chain` against a SIEM export to detect:

* dropped events (chain break — `prev_digest` mismatch),
* tampered events (`digest mismatch`),
* signature mismatches (`signature verification failed`),
* unexpected measurements (`--expect-measurement`),
* unexpected platform / instance (`--expect-platform`,
 `--expect-instance-id`).

**Always supply an out-of-band signing key.** Every event carries the public key
it was signed with, so verifying against *that* proves only that the stream is
internally consistent — anyone who can inject into your SIEM can present a
self-consistent chain signed by a key they generated. The trust anchor has to
come from somewhere the attacker does not control.

**Usually you do not have to supply it by hand.** The exporter publishes the
SHA-256 of its own public key in the SIEM-SEC-4 health file, the deploy copies
that into the signed build ledger as `siem_signing_key_sha256`, and
`verify-siem-chain` reads it back from `build_provenance.json` next to the
export (or in the CWD). When that works the summary prints
`Signing key: recorded at deploy (<ledger path>)`.

```bash
# Anchor discovered from the signed ledger — nothing to pass.
tee-crafter verify-siem-chain \
    --file events.jsonl \
    --expect-first-seq 0 \
    --expect-platform snp-aws \
    --expect-measurement <sha256-from-build-provenance>

# Or pin it yourself. Fingerprint = SHA-256 of the DER SubjectPublicKeyInfo,
# the same normalisation verify_siem_chain.pubkey_sha256 applies.
tee-crafter verify-siem-chain --file events.jsonl \
 --pinned-pubkey-sha256 <fpr>
```

> **Do not reach for `build_provenance.pub`.** It signs *build provenance* and
> never signs an event, so passing it fails every event with
> `InvalidSignature`. The event signing key is a different key, generated per
> process and held in memory (`siem_export.py`, `AttestationLoop.__init__`;
> `_Ed25519Signer` in `core/audit/continuous.py` for the in-TEE path). Until
> 2026-08 this command *auto-loaded* that wrong key from beside the events file
> and it outranked `--pinned-pubkey-sha256`, so keeping an export in its own
> build directory turned a passing run into a hard failure. That auto-discovery
> is gone; only the ledger lookup remains.

**What the recorded anchor does and does not prove.** It pins the key the
deploy observed at sidecar-install time, over the deploy's own channel, and
it is only used when the ledger is *signed* — an unsigned or tampered ledger is
refused or ignored exactly as it is for `--expect-chain-commitment`. It is
**not** hardware-attested: on `nitro-aws` and `sgx-azure` the exporter runs on
the VM host, outside the TEE, so it cannot be. What it buys is that a stream
signed by any *other* key is detectable, which is the injection case the anchor
exists for. It does not prove the host never had access to the signing key.

- `--pubkey` / `--pubkey-file` / `--pinned-pubkey-sha256` override the
 discovered value; an explicit anchor always wins. With none of them and no
 usable ledger the command **refuses to run** rather than verifying against
 the key embedded in the events (`verify_siem_chain.py`, `verify_chain`).
- `--expect-first-seq 0` requires the export to start at genesis, which is what
 defends against silent head truncation. Without it an attacker can drop the
 beginning of the stream and the remaining chain still verifies.

Exit code 2 means a problem was found — wire it into a Splunk saved
search or a cron job and page on non-zero.

## CLI surface

The public CLI is intentionally small:

```
--siem {none|syslog-cef|splunk-hec|datadog}
--siem-config <path/to/config.json> (required when --siem != none)
```

Equivalent `.env` keys:

```
TEE_CRAFTER_SIEM=splunk-hec
TEE_CRAFTER_SIEM_CONFIG=/path/to/siem.json
```

Everything provider-specific (endpoint, token, host, port, egress
allowlist, egress mode, …) lives in the JSON document. The public
CLI does not expose per-field flags such as `--siem-host`,
`--siem-token`, or `--siem-egress-cidr` — the JSON schema covers
every provider.

## Config schema

```json
{
  "provider": "splunk-hec",
  "interval_seconds": 30,
  "sign_events": true,
  "fail_open": true,

  // ----- syslog-cef -----
  "host": "siem.internal",
  "port": 514,
  "protocol": "tcp",
  "facility": 13,
  "hostname": "tee-svc",

  // ----- splunk-hec -----
  "endpoint": "https://hec.example.com:8088/services/collector",
  "token": "00000000-0000-0000-0000-000000000000",
  "index": "main",
  "sourcetype": "tee_crafter:attestation",
  "source": "tee-crafter",

  // ----- datadog -----
  "api_key": "dd-api-key",
  "site": "datadoghq.com",
  "service": "tee-crafter",
  "ddsource": "tee-crafter",
  "env": "prod",

  // ----- networking -----
  "egress_mode": "auto",
  "egress_allowlist_cidrs": ["52.51.0.0/16"],
  "egress_ports": [443],

  "extra": {"my_key": "my_value"}
}
```

Only fields relevant to the chosen `provider` need to be populated;
leave the others off. Config is validated by
[`tee_crafter.cli.commands.deploy.siem_mode.SiemConfig.validate`](../apps/cli/src/tee_crafter/cli/commands/deploy/siem_mode.py).

### Egress modes

| Mode | Behaviour |
|-----------|---------------------------------------------------------------------------------------------------------------|
| `auto` | Provider-aware: intra-VPC for `syslog-cef`, NAT for `splunk-hec` / `datadog`. |
| `private` | Force private connectivity only. Fails closed if the provider needs the public internet. |
| `public` | Force NAT egress. Combine with `egress_allowlist_cidrs` to lock the SG / NSG / GCP firewall to specific prefixes. |
| `none` | Operator owns egress (transit gateway, forward proxy, …). TEE-Crafter does not mutate network rules. |

## Examples

### Splunk Cloud, NAT with allowlist

`configs/splunk.json`:

```json
{
  "provider": "splunk-hec",
  "interval_seconds": 30,
  "endpoint": "https://prd-p-xyz.splunkcloud.com:8088/services/collector",
  "token": "${SPLUNK_HEC_TOKEN}",
  "egress_mode": "public",
  "egress_allowlist_cidrs": ["52.51.0.0/16", "18.130.0.0/16"]
}
```

```bash
tee-crafter deploy \
  --source examples/docker_flask_api \
  --tee-platform snp-aws \
  --instance-type m6a.xlarge \
  --ami-id <baked-id> \
  --service-profile long-lived \
  --siem splunk-hec --siem-config configs/splunk.json \
  --deploy --auto-approve
```

### Datadog (US site)

```json
{
  "provider": "datadog",
  "api_key": "${DATADOG_API_KEY}",
  "site": "datadoghq.com",
  "service": "tee-crafter",
  "env": "prod",
  "egress_mode": "public",
  "egress_allowlist_cidrs": ["52.96.0.0/14"]
}
```

### syslog-CEF to an intra-VPC collector

```json
{
  "provider": "syslog-cef",
  "host": "siem.internal",
  "port": 514,
  "protocol": "tcp",
  "egress_mode": "none"
}
```

## What lands in the SIEM

Each event is the JSON body of an
[`AttestationEvent`](../apps/cli/src/tee_crafter/core/audit/continuous.py)
object plus a CEF / syslog / HEC framing layer:

```json
{
  "event_id": "8b3f...",
  "seq": 17,
  "event_type": "attestation_refresh",
  "timestamp": "2026-04-26T18:11:01Z",
  "pipeline_version": "0.4.2",
  "instance_id": "i-0abc...",
  "tee_platform": "snp-aws",
  "measurement_sha256": "9b2c...",
  "attestation_sha256": "f8a3...",
  "attestation_size_bytes": 1184,
  "status": "pass",
  "prev_digest": "5210...",
  "digest": "ab90...",
  "signature": "3045...",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
  "extra": {}
}
```

Possible `event_type` values: `attestation_boot` (one per process
startup) and `attestation_refresh` (every `interval_seconds` tick).
Failures are encoded by `status="fail"` on the same event, with the
exception text captured in `extra.error` — the chain is not broken by
a failing refresh. The hash chain (`seq` + `prev_digest` + `digest`)
means a silent gap or a tampered event is detectable downstream — see
[`ContinuousAttestor.verify_chain`](../apps/cli/src/tee_crafter/core/audit/continuous.py).

## Who owns the SIEM?

**The customer owns the SIEM endpoint.** TEE-Crafter never hosts, ingests, or stores attestation events — the exporter inside the TEE sends to whatever endpoint the operator gives us via `--siem-config` (HTTPS POST for Splunk HEC / Datadog / Azure Monitor, or RFC 5424 syslog + CEF for `syslog-cef`). There is no platform-side telemetry pipeline a customer needs to opt into.

> The only SIEM config checked into the repo is
> `apps/cli/siem-sandbox/configs/splunk-local.json`. Every other
> `configs/*.json` path in this document — and the sandbox `.env` files — is
> **generated** by the scripts in `apps/cli/siem-sandbox/scripts/` (or created
> by you), so it will not exist until you run them.

The `apps/cli/siem-sandbox/` directory is a **dev-time receiver** for developing against TEE-Crafter. It runs the exact production container image you'd put in Fargate / ECS / AKS, so you can verify the wire format against a real implementation. Nothing in `apps/cli/siem-sandbox/` is a runtime dependency of a deployment.

## Local development sandbox

Splunk HEC is documented below in three tiers; each tier has exactly **one TLS terminator at the front of the chain** (the "ALB"), then plain HTTP to the Splunk backend — mirroring the AWS ALB → ECS task pattern. **syslog-CEF** does not use HTTP; see the [syslog-CEF sandbox](#syslog-cef-sandbox-syslog-ng) subsection for `syslog-ng` + **ngrok tcp** Tier 2.

```
 Tier 1 (laptop): client ── HTTPS ──▶ nginx-alb (self-signed) ── HTTP ──▶ splunk
 Tier 2 (ngrok): TEE ── HTTPS ──▶ ngrok edge (Let's Encrypt) ── HTTP ──▶ nginx-alb ── HTTP ──▶ splunk
 Tier 3 (prod): TEE ── HTTPS ──▶ AWS ALB + ACM ── HTTP ──▶ splunk on ECS
```

`nginx-alb` in the sandbox is the dev-time stand-in for the AWS ALB; in Tier 2 the ngrok edge plays the public-internet front and forwards through the same nginx so the chain is identical to Tier 1 plus one external hop.

### Tier 1 — localhost smoke (no cloud, no TEE, ~3 s)

```bash
cd apps/cli/siem-sandbox/splunk
cp.env.example.env
docker compose up -d
docker compose logs -f splunk | grep -m1 "Ansible playbook complete" # ~2 min first boot

python apps/cli/siem-sandbox/scripts/smoke_splunk.py
# -> 3 events sent, 3 events found in Splunk index=tee_crafter,
# p50 HEC POST latency ~8 ms — PASS
```

Brings up two containers: `splunk` (HEC on plain HTTP `:8088`) and `nginx-alb` (HTTPS `:8443` with a self-signed dev cert generated on first boot, reverse-proxies to Splunk). The smoke test posts at `https://localhost:8443/services/collector` and verifies ingest via Splunk's REST API.

### Tier 2 — real cloud TEE → laptop Splunk via ngrok

The TEE in AWS / GCP / Azure cannot reach `localhost:8443` on your laptop. ngrok publishes a public HTTPS URL (real Let's-Encrypt cert at its edge) and forwards plain HTTP to `nginx-alb:8080` inside the docker network. ngrok is opt-in via a Compose profile so the Tier-1 flow stays one-command.

```bash
# 1. Free ngrok authtoken: https://dashboard.ngrok.com → Your Authtoken
echo "NGROK_AUTHTOKEN=<paste>" >> apps/cli/siem-sandbox/splunk/.env

# 2. Bring up Splunk + nginx-alb + ngrok together
cd apps/cli/siem-sandbox/splunk
docker compose --profile ngrok up -d

# 3. Render a TEE-Crafter siem-config pointed at the live ngrok URL.
# Free-tier ngrok rotates the URL on each restart so we generate the
# config dynamically by reading ngrok's local agent API on:4040.
python../scripts/make_remote_splunk_siem_config.py
# -> wrote apps/cli/siem-sandbox/configs/splunk-via-ngrok.json
# endpoint = https://abc-123.ngrok-free.app/services/collector

# 4. Deploy a real SNP-AWS TEE that ships its attestation feed to your laptop
cd../..
tee-crafter deploy \
    --tee-platform snp-aws \
    --ami-id "$SNP_AMI_AWS" \
 --source./examples/docker_flask_api \
    --siem splunk-hec \
    --siem-config apps/cli/siem-sandbox/configs/splunk-via-ngrok.json \
    --deploy --auto-approve --teardown

# 5. Verify: open http://localhost:8000 (admin / SPLUNK_PASSWORD),
# Search & Reporting → `index=tee_crafter | head 50`
```

The TEE sees `https://*.ngrok-free.app/...` with a real CA-signed cert, so no `verify_ssl` override needed — `make_remote_splunk_siem_config.py` deliberately omits that knob for the ngrok config. The nginx-alb container is in the chain for Tier 2 the same as Tier 1; ngrok is just the public-internet edge.

### Tier 3 — production: Splunk in Fargate

Same image, same `:8088` HTTP backend, same exporter code path. Replace `nginx-alb` with AWS ALB + ACM. Only the customer's `endpoint` URL changes:

| | Tier 1 / Tier 2 (sandbox) | Tier 3 (Fargate prod) |
|---|---|---|
| Container image | `splunk/splunk:latest` | `splunk/splunk:latest` |
| HEC backend | plain HTTP `:8088` | plain HTTP `:8088` |
| TLS terminator | `nginx-alb` (self-signed) or ngrok edge | ALB + ACM cert |
| Customer-facing URL | `https://localhost:8443/...` or `https://*.ngrok-free.app/...` | `https://splunk-hec.example.com/services/collector` |
| Token storage | `.env` | AWS Secrets Manager → ECS task secret |
| `extra.verify_ssl` | `"0"` (Tier 1 self-signed) / unset (Tier 2 real cert) | unset (real cert) |
| `egress_mode` | `none` / `public` | `public` + ALB CIDR in `egress_allowlist_cidrs` |

Fargate Terraform recipe (`terraform/fargate/`, ~150 lines) is planned; ask when you want it scaffolded.

### Splunk HEC `time` field (gotcha worth knowing)

Splunk HEC requires the `time` field to be a **numeric UNIX epoch** (seconds, with optional fractional component) — it returns `HTTP 400 "Error in handling indexed fields" (code 15)` for ISO-8601 strings. `SplunkHecExporter` converts `AttestationEvent.timestamp` (ISO-8601) to epoch via `_iso_to_epoch`. Regression-tested in `apps/cli/tests/core/test_continuous_attest.py::TestSplunkHecExporter::test_time_field_is_epoch_seconds`.

### Self-signed Splunk HEC certs

If you're pointing at a *self-hosted* Splunk that serves HEC on HTTPS with a self-signed cert (a default Splunk Enterprise install does this until you swap the cert), add `"extra": {"verify_ssl": "0"}` to your `--siem-config` JSON. The runtime bootstrap reads it as `TEE_CRAFTER_SIEM_X_VERIFY_SSL=0` and constructs `SplunkHecExporter(verify_ssl=False)`. Splunk Cloud and the Fargate-behind-ALB pattern both terminate real TLS so this knob is normally absent in prod.

### syslog-CEF sandbox (`syslog-ng`)

Tier 1 (laptop smoke, no cloud) and Tier 2 (cloud TEE → laptop via **ngrok TCP**) live under [`apps/cli/siem-sandbox/syslog/`](../apps/cli/siem-sandbox/syslog). Splunk’s Tier 2 uses `ngrok http` + `nginx-alb` because HEC is HTTPS; syslog is raw **TCP or UDP**, so Tier 2 uses **`ngrok tcp`** into syslog-ng’s RFC-5424 TCP listener. The ngrok agent API is bound to **`:4041`** so it does not collide with Splunk’s ngrok on `:4040`.

```bash
# Tier 1 — same exporter classes as production
cd apps/cli/siem-sandbox/syslog && docker compose up -d
cd../../../.. && python apps/cli/siem-sandbox/scripts/smoke_syslog.py

# Tier 2 — render syslog-via-ngrok.json (egress_mode=public, egress_ports=[ngrok port])
echo "NGROK_AUTHTOKEN=<paste>" >> apps/cli/siem-sandbox/syslog/.env
cd apps/cli/siem-sandbox/syslog && docker compose --profile ngrok up -d
cd../../../.. && python apps/cli/siem-sandbox/scripts/make_remote_syslog_siem_config.py
```

Details: [`apps/cli/siem-sandbox/syslog/README.md`](../apps/cli/siem-sandbox/syslog/README.md).

### Production-readiness bar (Splunk vs syslog-CEF)

Both exporters meet the same production checklist; the sandbox smoke tests pin each requirement to a real artefact on disk:

| Requirement | Splunk HEC | syslog-CEF |
|---|---|---|
| Authenticated transport | HTTPS + bearer token (`TEE_CRAFTER_SIEM_TOKEN`); `verify_ssl=1` enforced, sandbox-only knob `extra.verify_ssl=0` is gated behind `TEE_CRAFTER_SIEM_X_ALLOW_INSECURE=1`. | Plain TCP/UDP; treat as intra-VPC (forwarder pattern) or hop through ngrok TCP for cross-cloud testing. Production hardening = TLS-wrapped rsyslog/syslog-ng forwarder one hop inside the VPC. |
| Wire format | Splunk HEC `/services/collector/event` JSON envelope; same shape as ECS task-mode. | RFC 5424 framing (`<PRI>1 TS HOST APP - - - CEF:0\|...`), CEF extension layout identical between the in-tree exporter and the CVM sidecar. |
| Connection lifecycle | Stateless HTTPS request per emit. | Persistent TCP with `SO_KEEPALIVE` + tight `TCP_KEEPIDLE/INTVL/CNT` (10s/5s/3), `connect_timeout=10s`, `send_timeout=5s`, `select(timeout=0)` pre-send liveness probe, single-retry redial on `OSError` or `socket.timeout`. UDP path is fire-and-forget. |
| Peer-bounce survival | Each emit opens a fresh socket — free for free. | Pre-send probe catches half-closed peers; one redial per emit covers ngrok edge rotation, docker proxy restarts, rsyslog graceful reloads, k8s Service IP churn. Proven by the **TCP reconnect drill** in [`smoke_syslog.py`](../apps/cli/siem-sandbox/scripts/smoke_syslog.py) — emit, `docker restart` the syslog-ng container, emit again, verify all events land. |
| Cross-cloud test path | `ngrok http` → `nginx-alb` → `splunk` (HTTPS terminator at the ngrok edge). | `ngrok tcp` → `syslog-ng:601` (raw TCP edge — same framing as a production forwarder). |
| Cloud egress | `egress_mode=public` opens 443/tcp; `egress_allowlist_cidrs` narrows to the SIEM CIDR. | Same `egress_mode=public`; the ngrok config-renderer resolves the ngrok edge host to a `/32` and emits `egress_allowlist_cidrs` so AWS `siem_egress_ports` actually opens the (non-443) ngrok TCP port — without the CIDR allowlist, the SG would fall back to 443/tcp only and silently drop the syslog connection. |
| Audit trail | Hash-chained, Ed25519-signed `AttestationEvent` (`prev_digest` → `digest` → `signature`). | Same — both exporters serialise the same `AttestationEvent` dataclass. |
| Failure mode | Raises `SiemExportError` on any HTTP error, non-2xx status, DNS failure or timeout, so the tick records `last_export_status=fail`. The next tick still fires — a single failure is not fatal to the sidecar — but the in-TEE gate refuses requests while the status stays `fail`. (Before 2026-08 this row read "fail-open: HTTP error logged"; that was the defect, not the design.) | Same: TCP raises after one redial, and the UDP path now raises on locally-detectable failures such as an unresolvable host. Health-state file at `/run/tee-crafter-<platform>/siem.health` records `last_export_status`, which is what the main-app gate reads. |

The reconnect drill is the explicit production-grade proof for syslog: pre-restart events land on the wire, syslog-ng is force-bounced, post-restart events land on the *same* exporter instance without raising. That's the same robustness Splunk gets from per-emit HTTPS, achieved over a long-lived TCP socket.

When you point this at a real production collector (rsyslog, syslog-ng cluster, Sumo Cloud Syslog, ArcSight SmartConnector, Sentinel Linux Agent), the wire format is byte-for-byte what they expect — verified by the smoke test running against the real `balabit/syslog-ng` image with `flags(syslog-protocol)` (strict RFC 5424 parsing).

## Runtime wiring

The CLI writes two files into `<build_dir>/siem/` and mirrors them
into `build_dir/app/` so they're visible to whichever bundle layout
the TEE uses (Nitro EIF, SGX manifest, CVM rootfs, container, …):

* `siem/siem.json` — full structured config.
* `siem/siem.env` — flattened `KEY=value` env vars, used as a `systemd`
 `EnvironmentFile=` and as Docker `--env-file`.

A third file `siem/siem_egress.json` records the resolved egress
decision (cloud, CIDRs, ports, fail-closed flags) that flowed into
the Terraform plan.

At deploy time, every supported platform automatically installs and
starts the **tee-crafter-siem.service** sidecar on the VM whenever
`siem.env` has `TEE_CRAFTER_SIEM_ENABLED=1`. The sidecar:

* reads the same `siem.env` the build phase produced;
* signs each `AttestationEvent` with a per-boot Ed25519 key;
* hash-chains events with `prev_digest` so a gap or replay is visible;
* POSTs to the chosen exporter (Splunk HEC, Datadog Logs, syslog-CEF);
* fails open — exporter errors are logged, the next tick fires anyway.

Per-platform attestation provider:

| Platform | Provider | Source of measurement |
|-----------------|---------------------------------------------------------|------------------------|
| `snp-aws` | imports `app_snp.generate_snp_attestation` each tick | Fresh SNP report from `/dev/sev-guest` |
| `snp-azure` | imports `app_snp.generate_snp_attestation` each tick | Fresh SNP report |
| `snp-gcp` | imports `app_snp_gcp.generate_snp_attestation` | Fresh SNP report |
| `tdx-azure` | imports `app_tdx.generate_tdx_quote` | Fresh TDX quote |
| `tdx-gcp` | imports `app_tdx_gcp.generate_tdx_quote` | Fresh TDX quote |
| `gpu-cc-aws` | imports `app_snp` (CPU side) | Fresh SNP report |
| `gpu-cc-azure` | imports `app_snp` (CPU side) | Fresh SNP report |
| `gpu-cc-gcp` | imports `app_tdx_gcp` (CPU side) | Fresh TDX quote |
| `nitro-aws` | boot-anchored heartbeat, **host side and in-enclave** | Measurement from `provenance/build_provenance.json` |
| `sgx-azure` | boot-anchored heartbeat (host side) | MRENCLAVE from sign step |

The sidecar on the **host** emits a boot-anchored heartbeat — the measurement is
pinned at boot, and the freshness signal is *event continuity*. A
SIEM dashboard that stops receiving events for an instance knows the
enclave is gone, even though individual events don't carry a freshly
re-signed report. Per-tick fresh-attestation from the heartbeat provider is
still a documented enhancement; see
[`siem_export._provider_heartbeat`](../apps/cli/src/tee_crafter/templates/common/siem_export.py).

On `nitro-aws` a **second** exporter now runs inside the enclave as well, and
the two are not redundant. The host-side one is what a fleet dashboard watches
when the thing that stopped is the enclave itself — an in-enclave exporter
cannot report its own death. The in-enclave one is the only one whose verdict
the fail-closed gate reads, because it is the only one whose `siem.health` lives
in the namespace the gate can see and whose delivery the parent instance cannot
fake.

The deploy-time installer lives at
[`tee_crafter.cli.deployment.common.siem_sidecar`](../apps/cli/src/tee_crafter/cli/deployment/common/siem_sidecar.py).
It renders the unit from
[`tee-crafter-siem.service.template`](../apps/cli/src/tee_crafter/resources/systemd/tee-crafter-siem.service.template),
drops it into `/etc/systemd/system/`, and `systemctl enable --now`s it
after the main app service comes up. Skip-if-disabled is enforced at
every call site — no SIEM in `siem.env` means no sidecar install, no
extra processes on the VM.

If nothing is showing up in your SIEM but the deploy reported success,
walk this checklist:

```bash
# 1. Is the SIEM env file present and populated?
sudo cat /opt/tee-crafter-snp/app/siem.env

# 2. Did the app process actually pick up the env vars?
PID=$(pgrep -f 'python3 app_snp.py' | head -1)
sudo cat /proc/$PID/environ | tr '\0' '\n' | grep TEE_CRAFTER_SIEM

# 3. Is the sidecar exporter running?
sudo systemctl status tee-crafter-siem.service --no-pager -l
sudo journalctl -u tee-crafter-siem.service --no-pager -n 50

# 4. Can the VM reach your SIEM endpoint at all?
curl -v -m 5 https://<your-siem-endpoint>/services/collector \
     -H "Authorization: Splunk <token>" \
     -H "Content-Type: application/json" \
     -d '{"event":{"probe":"vm-egress-test"}}'
```

If (3) is missing entirely, the build was produced before the SIEM
sidecar landed — re-deploy from `main` after pulling. If (4) fails,
your egress policy is the issue, not the exporter.
