# Execution model — Dockerfile in, attested + audited run out

> Canonical reference for the TEE-Crafter execution model.
> See also [attested_proxy.md](attested_proxy.md) and [batch_mode.md](batch_mode.md).

TEE-Crafter has exactly **one input** and **two run modes**.

## The one input: your Dockerfile

You bring a **directory** containing a `Dockerfile`. That is the only thing
`--source` accepts — it is declared `dir_okay=True, file_okay=False`, so an
image reference is rejected at parse time. To deploy an image you already have,
point `--source` at a directory whose `Dockerfile` is a single
`FROM myorg/app@sha256:<digest>`. TEE-Crafter:

1. **Builds** it reproducibly.
2. **Measures** it (the measurement becomes part of the attestation baseline).
3. **Runs it as-is** inside the TEE — no rewriting, no injected handler, no
 language-specific SDK.
4. **Emits** an attestation document, the full audit-evidence bundle, and
 signed build provenance.

There is no application-level attestation contract and no language SDK.
If your workload needs a particular language or runtime, it ships inside
your image.

## The two run modes

You must pass **exactly one** of `--batch` or `--persistent` — there is no
default. Omitting both is rejected at the CLI.

### `--batch` (one-shot)

Runs the container to completion, then captures **everything it wrote** via the
existing `docker diff` / `docker cp` collector and downloads `output.tar.gz`.

- No live client, so the assurance is the **signed attestation document +
 provenance + audit bundle** captured at deploy time (this is exactly how
 batch has always worked).
- Use for preprocessing, ML training, batch inference, scheduled jobs, and
 anything that does not need a long-lived endpoint.

### `--persistent` (long-lived service)

Runs your container as a long-lived service behind the platform-owned
**attested ingress proxy** (RA-TLS terminator). The proxy terminates the
attested channel and forwards plaintext to your container on
`127.0.0.1:<EXPOSE port>`. Your container stays unmodified; attestation is the
platform's job. See [attested_proxy.md](attested_proxy.md).

- `--service-profile <long-lived|short-lived|streaming>` configures the
 **proxy** (cert TTLs, re-attest interval, connection limits), not your code.

## Platform support matrix

| TEE platform | `--batch` | `--persistent` |
|---|---|---|
| `nitro-aws` | ✅ | ✅ (attested proxy) |
| `snp-aws` / `snp-azure` / `snp-gcp` | ✅ | ✅ (attested proxy) |
| `tdx-azure` / `tdx-gcp` | ✅ | ✅ (attested proxy) |
| `gpu-cc-gcp` / `gpu-cc-azure` / `gpu-cc-aws` | ✅ | ✅ (attested proxy) |
| `sgx-azure` | ✅ (via GSC) | ❌ **not supported in v1** |

### SGX is batch-only for v1

Arbitrary Docker images don't run under raw Gramine, so SGX (`sgx-azure`) stays
in the unified model via **Gramine Shielded Containers (GSC)** on the `--batch`
path only:

- `gsc build` graminizes your built image; `gsc sign-image` signs it with the
 operator's SGX signing key.
- `MRENCLAVE` / `MRSIGNER` are derived from the graminized image.
- The container runs to completion with the batch collector; assurance is
 deploy-time attestation + provenance + signed audit bundle.

`--persistent` (and therefore `--service-profile`) is **rejected** for
`sgx-azure` at CLI parse time by
`cli/commands/deploy/deploy_helpers.py::validate_run_mode`:

> Persistent services on Intel SGX are not supported yet; use Batch or pick a
> VM-class TEE.

Persistent SGX (the attested ingress proxy inside a graminized enclave) is
deferred to a future plan. If a workload can't be graminized via GSC, the
documented, batch-only fallback is a constrained **Python-only** source app.
SGX stays amd64-only.

## What the guarantee still is

The core confidential-computing promise — *a remote client can prove it's
talking to the expected code in a real TEE before sending data* — is preserved:

- **Persistent (VM-class):** the attested ingress proxy serves an RA-TLS cert
 with the attestation embedded; the client verifies measurement + signer
 before sending any data.
- **Batch (all platforms incl. SGX):** there is no live client, so the
 assurance is the signed attestation document captured at boot, plus the
 provenance and audit bundle.

## Public deploy command

```
tee-crafter deploy <path|image> \
  --tee-platform <platform> \
 (--batch | --persistent) \ # one required
 [--service-profile long-lived|short-lived|streaming] # persistent, VM-class only \
  [--byok-config <json>] [--siem-config <json>] \
  [--instance-type <type>] [--spot] [--region <r>] [--deploy]
```

(`--persistent` is unavailable for `sgx-azure`.)
