# TEE-Crafter Example Applications

Every example under `examples/` ships a **`Dockerfile`**. Deploy with the
unified command:

```bash
tee-crafter deploy --source./examples/<name> \
  --tee-platform <platform> \
  [--batch | --persistent] \
  --ami-id <ID> --deploy --auto-approve
```

See [execution_model.md](execution_model.md) for run modes and the platform
matrix. The repo ships **four** end-to-end examples — persistent services, batch
workloads, and GPU — cataloged in [examples/README.md](../examples/README.md):

| Example | Mode | Demonstrates |
|---------|------|--------------|
| `hello_http` | persistent | Minimal FastAPI service (health, time, echo) |
| `docker_flask_api` | persistent | Minimal container service + `.env` (config/secrets) |
| `fintech_fraud_detection` | batch | Sealed secrets + default-deny DB egress |
| `gpu_confidential_inference` | persistent / GPU | H100 CC dual attestation |

---

## Directory layout

Each example is a self-contained build context:

| File | Purpose |
|------|---------|
| `Dockerfile` | How the workload is built and started |
| `requirements.txt` | Runtime dependencies (all four examples are Python) |
| `.env` | Sample config/secrets for `--secrets-env` — all four examples ship one |
| `input/data.json` | Sample batch input for `--input-dir` — the two batch examples only (`fintech_fraud_detection`, `gpu_confidential_inference`) |
| `.dockerignore` | Present on `fintech_fraud_detection`, `gpu_confidential_inference` and `hello_http`. Only the first two exclude `input/`; `hello_http`'s excludes `.env` and scan output. `docker_flask_api` has none, and does not need one — its Dockerfile's single `COPY` is `COPY app.py.` |
| `README.md` | Platform-specific deploy commands |

**Persistent examples** expose an HTTP port (`EXPOSE`) and run a web server.
**Batch examples** read from `/input` and write to `/output` inside the
container. `/input` is bind-mounted by the batch systemd unit; `/output` is
**not** — your image has to create it (`RUN mkdir -p /output`), because batch
capture works by `docker diff`-ing the container's own writable layer after it
exits. See `apps/cli/src/tee_crafter/resources/systemd/container.batch.service.template`.

Examples do **not** import TEE-Crafter libraries. Attestation, RA-TLS, audit,
and hardening are platform-owned.

---

## Persistent examples

### `hello_http`

Smallest FastAPI starter — health check, UTC clock, and a JSON echo endpoint.
See [`examples/hello_http/README.md`](../examples/hello_http/README.md).

```bash
tee-crafter deploy --source./examples/hello_http \
  --tee-platform snp-aws --persistent --deploy --auto-approve
```

### `docker_flask_api`

Minimal Flask JSON API — the canonical "bring your container" starter.
Ships a `.env` (`PORT`, `ENVIRONMENT`, `API_TOKEN`) delivered via
`--secrets-env`; see the combined `.env` + SIEM + BYOK form under
[Advanced in the top-level README](../README.md#advanced-keys-secrets-and-continuous-attestation).

```bash
tee-crafter deploy --source./examples/docker_flask_api \
  --tee-platform snp-aws --persistent --deploy --auto-approve
```

### `gpu_confidential_inference`

Confidential radiology AI on NVIDIA H100 with dual CPU+GPU attestation.
Requires a non-empty `NVIDIA_NRAS_API_KEY` in `.env` for any `gpu-cc-*`
platform (see [gpu_flow.md](gpu_flow.md)).

```bash
tee-crafter deploy --source./examples/gpu_confidential_inference \
  --tee-platform gpu-cc-gcp --persistent --deploy --auto-approve
```

On `gpu-cc-azure` and `gpu-cc-gcp`, UEFI Secure Boot is disabled at deploy
time so the NVIDIA DKMS driver loads; memory encryption and attestation are
unchanged.

---

## Batch examples

Batch mode runs the container to completion and downloads `output.tar.gz`
with every file the workload wrote.

### `fintech_fraud_detection`

Confidential transaction risk scoring — a `stdin → stdout` rule engine that
also ships a `.env` (`DATABASE_URL`, `RISK_API_TOKEN`) for sealed-secret +
default-deny egress demos. Input is supplied via `--input-dir` — as a plain
`tar.gz` extracted on the host, **not** encrypted to the TEE (see
[the caveat in examples/README.md](../examples/README.md#what---input-dir-actually-does--read-this-before-sending-real-data)):

```bash
tee-crafter deploy --source./examples/fintech_fraud_detection \
  --tee-platform snp-aws --batch \
 --input-dir./examples/fintech_fraud_detection/input \
  --batch-timeout 600 --deploy --auto-approve --teardown
```

The batch Dockerfile pattern is:

```dockerfile
RUN mkdir -p /output
CMD ["sh", "-c", "python app.py < /input/data.json > /output/results.json"]
```

The `mkdir` is not optional — without it the redirect fails at runtime because
nothing mounts or creates `/output`.

`sgx-azure` is batch-only and uses the same source (images are graminized via
GSC when available):

```bash
tee-crafter deploy --source./examples/fintech_fraud_detection \
  --tee-platform sgx-azure --batch \
 --input-dir./examples/fintech_fraud_detection/input \
  --deploy --auto-approve --teardown
```

---

## Building your own app

### Persistent service

1. Write a normal web server (Flask, FastAPI, Express, Go `net/http`, …).
2. Add a `Dockerfile` with `EXPOSE <port>`.
3. Deploy with `--persistent`.

The attested ingress proxy terminates RA-TLS and forwards to
`127.0.0.1:<EXPOSE port>`. Your code never implements attestation.

### Batch job

1. Write a program that reads inputs and writes outputs to disk.
2. Add a `Dockerfile` whose `CMD` reads `/input` and writes `/output`.
3. Deploy with `--batch` and optional `--input-dir`.

### Optional: sealed inputs

For sensitive staging data, use `tee-crafter seal-input` before deploy so
inputs are encrypted to the TEE's public key. See [byok.md](byok.md) and
[security.md](security.md).

---

## Attestation guarantees (summary)

| Mode | Client assurance |
|------|------------------|
| **Persistent** | Live RA-TLS: verify measurement + signer + nonce before sending data |
| **Batch** | Deploy-time attestation document + signed provenance + audit bundle |

Platform-specific measurement fields (PCR, MRTD, MRENCLAVE, NRAS JWT, …) are
documented in each platform flow guide.

---

## Further reading

- [execution_model.md](execution_model.md) — one input, two run modes
- [attested_proxy.md](attested_proxy.md) — how persistent services are verified
- [batch_mode.md](batch_mode.md) — output capture and security delta
- [cli_reference.md](cli_reference.md) — full flag reference
