# Container build pipeline

> Phase 1 of the TEE-Crafter deploy pipeline: from your `Dockerfile` to a
> measured, scanned OCI image ready for TEE deployment.
> See [execution_model.md](execution_model.md) for the full five-phase flow.

When you run `tee-crafter deploy --source <dir>`, TEE-Crafter treats `<dir>` as
a Docker build context — a **directory** containing a `Dockerfile`.

`--source` is declared `click.Path(exists=True, file_okay=False, dir_okay=True)`
(`cli/commands/deploy/deploy_container.py`, lines 28–32), so a directory is the
only accepted value. Passing an image reference such as `myorg/app:1.2.3` is
rejected by Click before the command body runs. To deploy an image you already
have, write a one-line build context:

```dockerfile
FROM myorg/app@sha256:<digest>
```

which also gets you a digest pin and a Trivy/Grype scan of the exact image.

---

## Pipeline overview

```
 Your Dockerfile TEE-Crafter CLI Artifacts
 ┌──────────────┐ ┌─────────────────────────┐ ┌──────────────────────────────┐
 │ FROM … │ │ 1. Validate context │ │ <build>/user_container.tar │
 │ COPY … │───►│ 2. docker build │───►│ <build>/app/ │
 │ CMD … │ │ 3. Trivy/Grype scan │ │ container_digest.txt │
 └──────────────┘ │ 4. Record provenance │ │ <source>/.tee_crafter_scan/ │
 └─────────────────────────┘ │ trivy_report.json │
 │ <build>/provenance/ │
 │ build_provenance.json │
                                                    └──────────────────────────────┘
```

Nothing in this phase rewrites your application. The image you build locally
is the image that runs inside the TEE (subject to platform packaging in
Phase 2 — proxy staging, GSC graminize for SGX batch, EIF for Nitro, etc.).

---

## Step 1 — Context validation

The CLI verifies:

- A `Dockerfile` exists in the directory passed to `--source`.
- The build context is readable and within size limits.
- For `--batch`, an optional `--input-dir` is staged for mount into `/input`.
- For `--persistent`, a container port is inferred from `EXPOSE` or
 `--container-port`.

---

## Step 2 — Image build

TEE-Crafter runs `docker build` on the context with:

- **Reproducible tagging** — image ID recorded in `build_provenance.json`.
- **Architecture alignment** — build target matches the selected TEE platform
 (e.g. `linux/amd64` for most CVMs; SGX is amd64-only).
- **Offline-friendly layers** — when possible, dependencies are resolved at
 build time so the TEE host does not need wide egress during deploy.

The built image is saved as `<build_dir>/user_container.tar` for transport to
the TEE host during Phase 4.

---

## Step 3 — Vulnerability scan

Before any cloud resources are provisioned, the image is scanned with
**Trivy** (Grype as fallback):

| Severity | Upstream fix available? | Default action |
|----------|------------------------|----------------|
| CRITICAL / HIGH | **Yes** | Block deploy unless `--allow-vulnerable` |
| CRITICAL / HIGH | No (`affected`, `fix_deferred`, `will_not_fix`, …) | Counted, printed, recorded — does **not** block |
| MEDIUM / LOW | either | Recorded in audit trail |

**Why the gate is scoped to fixable findings.** It used to demand zero
CRITICAL/HIGH outright. Scanning the shipped example
(`examples/docker_flask_api`, a `python:3.12-slim` base) gave
4 CRITICAL / 15 HIGH — of which **17 of 19 had no upstream fix**, and *not one
CRITICAL was fixable*. `python:3.13-slim`, `python:3.14-slim` and
`python:3.13-alpine` were all scanned too and carry the same unfixed
`util-linux` set, so no base-image choice satisfied the rule.

A gate nobody can satisfy is worse than a narrower one: the only way past it is
`--allow-vulnerable`, which switches the scan off completely and quickly becomes
routine. Blocking on *"a fix exists and you haven't applied it"* is a gate that
means something and that a maintainer can clear. Unfixed findings are demoted
from blocking, **not hidden** — they stay in the summary line, the report and the
build provenance (`fixable_critical` / `unfixed_critical` and friends).

Set `TEE_CRAFTER_VULN_STRICT=1` to restore zero-tolerance if your policy needs
it, in which case the panel says so when it blocks.

**Accepting a specific finding.** Drop a `.trivyignore` in the source directory
listing CVE IDs. Its use and entry count are recorded in the build provenance
(`accepted_findings`, `accepted_findings_file`), so an auditor sees that risks
were *accepted* rather than absent. Prefer this to `--allow-vulnerable`: it is
reviewable in a PR, names the specific IDs, and leaves every other finding
blocking. `examples/docker_flask_api/.trivyignore` is a worked example — two pip
*vendored-manifest* entries that no upgrade can clear, with the trace that
established that. Only Trivy honours the file; the Grype fallback does not, and
leaves everything blocking rather than silently ignoring it.

Scan results are written to `<source>/.tee_crafter_scan/trivy_report.json` (or
`grype_report.json` on the fallback path) — note this lands next to your source,
not in the build directory — and the verdict is referenced by check IDs `VLN-*`
in [audit_matrix.md](audit_matrix.md).

The scan is best-effort: if neither Trivy nor Grype is installed, the deploy
continues and the gate does not fire. It only blocks when a scanner actually ran
and reported *fixable* CRITICAL/HIGH findings.

---

## Step 4 — Measurement and provenance

The CLI records:

| Artifact | Where | Contents |
|----------|-------|----------|
| `container_digest.txt` | `<build_dir>/app/` | The built image's OCI digest. Rendered into the client template so the attestation check is bound to this exact image. |
| `build_provenance.json` | `<build_dir>/provenance/` | Hash-chained ledger of every phase, Ed25519-signed. |
| `audit_evidence.json` | `<build_dir>/audit/` | Structured `check_id` verdict matrix, separately signed. |
| `<image-id>.json` | `apps/cli/src/tee_crafter/measurements/<platform>/` | Bake-time launch measurement registry. Written by `bake-ami`, read by `deploy` to auto-pin. Not a per-build artifact. |

> The list above is exhaustive; the scan reports are `trivy_report.json` /
> `grype_report.json`. There are no files named `image_digest.json` or
> `scan_report.json` — those strings appear nowhere in `apps/cli/src`.
>
> One caveat on `measurements.json`: the string *is* used as a **label**
> rather than a path — the `ATT-*` audit rows carry `evidence_pointer="measurements.json"`
> (`cli/deployment/common/attestation_report.py:239,252`) and several operator
> warnings say "ship a pinned measurements.json" (e.g. `client_step.py:93`). What
> those all refer to is the per-image registry file in row 4 above,
> `measurements/<platform>/<image-id>.json`. Do not go looking for a file called
> `measurements.json`; there isn't one.

These artifacts become part of the signed audit bundle produced at the end of
deploy and are consumed by `tee-crafter verify-provenance`.

---

## Phase 2 handoff — platform packaging

After the container build completes, platform-specific packaging runs:

| Platform / mode | Phase 2 action |
|-----------------|----------------|
| CVM + `--persistent` | Stage attested ingress proxy + load user container |
| CVM + `--batch` | Stage batch collector systemd unit + input mount |
| `sgx-azure` + `--batch` | GSC `build` + `sign-image` when `gsc` CLI is present |
| `nitro-aws` | EIF build path when the Nitro enclave wrapper is required |

See the per-platform flow docs: [nitro_flow.md](nitro_flow.md),
[sgx_flow.md](sgx_flow.md), [tdx_flow.md](tdx_flow.md), [snp_flow.md](snp_flow.md),
[gpu_flow.md](gpu_flow.md).

---

## CLI flags that affect Phase 1

| Flag | Effect |
|------|--------|
| `--source` | Build context directory or image reference |
| `--container-port` | Override inferred `EXPOSE` port (persistent) |
| `--container-cmd` | Override container command |
| `--allow-vulnerable` | Skip CRITICAL/HIGH scan gate |
| `--input-dir` | Stage plaintext inputs for batch. Uploaded as a plain `tar.gz` and extracted on the host — not sealed to the TEE. Use `tee-crafter seal-input` for sensitive data. |
| `--egress-mode` | Workload egress posture: `deny` (default), `vpc` (intra-VPC DB, no NAT), `nat` (public DB/API via NAT, SG locked to allowlist) |
| `--egress-allow` | `host:port` / `cidr:port` the workload may reach (repeatable); requires `--egress-mode vpc`/`nat` |
| `--secrets-env` | Plaintext dotenv. With `--byok aws-kms`/`gcp-kms` it is envelope-sealed (cleartext bound to the key's attestation policy); without BYOK it is baked into the measured image. Delivered to the workload at `/run/tee_crafter/app.env` on CVM (fail-closed secrets oneshot) and Nitro baked — see `docs/byok.md` (Delivery) |

---

## What TEE-Crafter does *not* do in Phase 1

- No LLM translation or code generation.
- No injection of a `process_request` handler contract.
- No language-specific SDK or sidecar scaffold.
- No modification of your source tree beyond copying it into the build
 directory for provenance hashing.

Your Dockerfile is the contract. Ship any Linux workload that fits your
compliance and resource constraints.

---

## Further reading

- [execution_model.md](execution_model.md) — run modes and platform matrix
- [batch_mode.md](batch_mode.md) — batch output capture
- [attested_proxy.md](attested_proxy.md) — persistent RA-TLS topology
- [security.md](security.md) — container hardening and scan policy
