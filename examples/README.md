# TEE-Crafter examples

Four end-to-end examples — persistent services, batch workloads, and GPU.
Each is a **Dockerfile + application code** you deploy with
``tee-crafter deploy``. See [docs/execution_model.md](../docs/execution_model.md).

| Example | Description | Mode |
|---------|-------------|------|
| [`hello_http/`](./hello_http/) | Minimal FastAPI JSON API (health, time, echo) | **persistent** |
| [`docker_flask_api/`](./docker_flask_api/) | Minimal Flask JSON API (config/secrets via `.env`) | **persistent** |
| [`fintech_fraud_detection/`](./fintech_fraud_detection/) | Transaction fraud scoring (secrets + DB egress) | **batch** |
| [`gpu_confidential_inference/`](./gpu_confidential_inference/) | H100 CC radiology pipeline (dual attestation) | **persistent / GPU** |

## Run modes

| Mode | Flag | What runs |
|------|------|-----------|
| **Persistent** | ``--persistent`` | Long-lived service behind the attested ingress proxy (RA-TLS) |
| **Batch** | ``--batch`` | Container runs to completion; outputs captured as ``output.tar.gz`` |

Pass **exactly one** of the two flags (there is no default).

> **Only `fintech_fraud_detection` is batch-shaped.** The other three examples
> `EXPOSE 8080` and run a listener, so they never exit. Batch mode waits for the
> container to exit before it captures anything, which means pointing `--batch`
> at one of them does not fail fast — it sits until `--batch-timeout` elapses
> (3600s by default) and then fails having captured nothing. `sgx-azure` is
> batch-only, so on that platform `fintech_fraud_detection` is the only example
> that will run to completion.
>
> `deploy` now checks this for you: if a `--batch` image declares any exposed
> port, it warns immediately after the image is built and before any cloud
> resource is created. It is a heuristic and only a warning — a batch job is
> free to expose a port.

```bash
tee-crafter internal bake-ami --tee-platform <platform> --region <region>

# Persistent service (+ optional app config/secrets via --secrets-env)
tee-crafter deploy --source ./docker_flask_api \
  --tee-platform snp-aws --ami-id <ID> \
  --secrets-env ./docker_flask_api/.env \
  --persistent --deploy --auto-approve --teardown

# Batch job (input supplied via --input-dir; see the caveat below)
tee-crafter deploy --source ./fintech_fraud_detection \
  --tee-platform snp-aws --ami-id <ID> \
  --batch --input-dir ./fintech_fraud_detection/input \
  --deploy --auto-approve --teardown
```

## Comprehensive deploy (`.env` + SIEM + BYOK)

The full fail-closed shape — sealed secrets, continuous-attestation SIEM,
and customer-managed key release — is in the top-level
[README "Full comprehensive deploy"](../README.md#full-comprehensive-deploy-env--syslog-siem--byok).
A checked-in SIEM sandbox config lives at
[`apps/cli/siem-sandbox/configs/splunk-local.json`](../apps/cli/siem-sandbox/configs/splunk-local.json);
the other SIEM configs and every BYOK config are **generated**, not
checked in — run the helper scripts in
[`apps/cli/siem-sandbox/scripts/`](../apps/cli/siem-sandbox/scripts) and
[`apps/cli/byok-sandbox/`](../apps/cli/byok-sandbox) first, which write into
`configs/` next to themselves:

```bash
python3 apps/cli/siem-sandbox/scripts/make_remote_syslog_siem_config.py
python3 apps/cli/byok-sandbox/generate_byok_config.py aws \
  --tee-platform snp-aws --region us-east-2 --alias tee-byok-snp

tee-crafter deploy --source ./docker_flask_api \
  --tee-platform snp-aws --ami-id <ID> \
  --persistent --service-profile long-lived \
  --secrets-env ./docker_flask_api/.env \
  --siem syslog-cef --siem-config ../apps/cli/siem-sandbox/configs/syslog-via-ngrok.json \
  --byok aws-kms     --byok-config ../apps/cli/byok-sandbox/configs/byok-snp-aws.json \
  --deploy --auto-approve
```

## Input data (batch) — kept out of the image

The example images contain **code only**. Sample input lives in
`<example>/input/` and is supplied at deploy time with `--input-dir`:

```bash
--input-dir ./fintech_fraud_detection/input
```

Keeping input out of the Dockerfile is worth doing on its own: `COPY`-ing data
into an image leaves the plaintext in the image layers, in your registry, and in
every provenance record of that image. `--input-dir` avoids all of that, and it
costs nothing when unused — omit the flag and `/input` is simply empty.

### What `--input-dir` actually does — read this before sending real data

`--input-dir` is **not** encrypted to the TEE. The CLI creates a plain
`tar.gz` of the directory, uploads it over the deploy channel (SCP over SSH for
Azure/GCP, SSM + S3 for AWS), and the **host** extracts it in the clear to
`/var/lib/tee_crafter/input`, which is then bind-mounted read-only at `/input`
inside your container
(`apps/cli/src/tee_crafter/cli/commands/deploy/batch.py`, lines 531–560;
`apps/cli/src/tee_crafter/resources/systemd/container.batch.service.template`,
line 58). Concretely:

| Platform | Where the plaintext lands | Inside the TEE boundary? |
|---|---|---|
| `snp-aws`, `snp-azure`, `snp-gcp`, `tdx-azure`, `tdx-gcp`, `gpu-cc-*` | Confidential VM disk | The VM **is** the TEE (encrypted memory), but the attached disk is an ordinary cloud volume |
| `nitro-aws` with `--batch` | Parent EC2 instance disk | **No.** Container batch on Nitro runs the image on the host VM, not in the enclave (`batch_dispatch.py`, lines 298–309) |
| `sgx-azure` with `--batch` | Azure VM disk before GSC hand-off | The Gramine enclave is the TEE; the staging path is not |

The transport is encrypted, but **the cloud operator's view of the host disk is
not**. Do not treat `--input-dir` as a confidentiality control.

### If the input itself is sensitive

Use `tee-crafter seal-input`, which really does wrap the directory to an enclave
public key (RSA-OAEP-SHA256 + AES-256-GCM, with the build ID bound into the AAD
— `apps/cli/src/tee_crafter/core/sealing/seal.py`):

```bash
tee-crafter seal-input \
  --input-dir ./fintech_fraud_detection/input \
  --target-pub <build_dir>/seal_pub.pem \
  --out ./input.sealed \
  --build-id <sha256-of-build-dir>
```

The in-TEE batch runner unwraps it when `BATCH_SEALED_INPUT` points at the
bundle (`apps/cli/src/tee_crafter/templates/common/batch_runner.py::_maybe_unseal_input`,
lines 211–239). Note that today this is a **manual** path: `--input-dir` does
not produce a sealed bundle, and nothing in the deploy flow sets
`BATCH_SEALED_INPUT` or writes `seal_pub.pem` for you — so you have to stage
both yourself.

Two of the four examples exclude `input/` via `.dockerignore`
(`fintech_fraud_detection`, `gpu_confidential_inference`). `hello_http` has a
`.dockerignore` that does not list `input/`, and `docker_flask_api` has none at
all — neither is a batch example, but add the rule before you put data in either.

Local testing without a TEE: mount the dir yourself
(`docker run -v "$PWD/input:/input:ro" <image>`), or run the script on the host.

## App config & secrets — `.env` via `--secrets-env`

Pass a dotenv to the CLI with `--secrets-env <file>`. With `--byok` it is
envelope-sealed at deploy time; without it the file is baked into the measured
image. See [`docker_flask_api/.env`](./docker_flask_api/.env) and
[`fintech_fraud_detection/.env`](./fintech_fraud_detection/.env):

```bash
tee-crafter deploy --source ./docker_flask_api \
  --tee-platform snp-aws --ami-id <ID> \
  --secrets-env ./docker_flask_api/.env \
  --byok aws-kms --byok-config ../apps/cli/byok-sandbox/configs/byok-snp-aws.json \
  --persistent --deploy --auto-approve --teardown
```

- **With `--byok aws-kms`/`gcp-kms`/`azure-kv`** the `.env` is envelope-sealed to
  your BYOK key, so the cleartext never touches the build host, image, or
  Terraform — use this for real secrets.
- **Without `--byok`** it is baked into the measured image — fine for non-secret
  config, but the value becomes part of the image.

The `.env` is delivered to the container at `/run/tee_crafter/app.env`. On CVM
platforms (SNP/TDX/GPU) the `tee-crafter-secrets.service` oneshot runs first and
either copies the baked file or releases the DEK and unseals —
**fail-closed**: if that fails the container never starts. On Nitro baked mode
the EIF entrypoint sources the file. The only paths that do not deliver are
**Nitro sealed** (needs NSM recipient-unwrap) and **SGX**; the CLI warns for
those. Sealed/BYOK release on CVM is bound to the image's bake-time measurement
(auto-pinned). See [`docs/byok.md`](../docs/byok.md) (Delivery) and
[`docs/measurements.md`](../docs/measurements.md).

Each subdirectory has its own ``README.md`` with platform-specific commands.
