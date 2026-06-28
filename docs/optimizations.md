# Deploy-Time Performance Optimizations

This document is the canonical map of every host-side bandwidth /
latency hotspot in TEE-Crafter's deploy paths, what we do about each
one, and what's still on the bench. It complements `docs/security.md`
(which has the security-first defaults) and `docs/cli_reference.md`
(user-facing flags).

> ## Read every number here as an estimate
>
> The timings, throughputs and speed-up factors below are **order-of-magnitude
> engineering estimates**, not measurements you can reproduce. They came from
> ad-hoc runs on specific hardware, cloud regions and network conditions that
> were never captured, and the harness that produced some of them
> (`evaluation/`) has been removed from the repo. Nothing in this document is
> backed by a committed benchmark.
>
> Treat them as: *this is the shape of the problem and roughly how much the fix
> is worth.* Do not quote them in a proposal, a comparison, or anything an
> auditor will read. Your own numbers will differ — Azure Bastion throughput
> alone varies by more than the size of several of the wins described here.
>
> The **mechanisms** described below are real and are in the code; the file and
> function references are accurate and worth reading. It is only the magnitudes
> that are unverified.

Two headlines worth calling out up front (again, estimated):

1. An unoptimized GPU-CC Azure deploy of the
 `gpu_confidential_inference` example sends a **2.9 GB** wheel
 bundle through an Azure Bastion SSH tunnel (effective throughput
 ~1.3 MB/s), which takes 30-40 minutes and frequently exceeds
 SCP's hardcoded timeout. §1-2 collapse that to a small-MB delta
 on every subsequent deploy.
2. Even after §1-2 the deploy path was bottlenecked by **per-call
 SSH handshake overhead** (30-40 distinct SSH/SCP invocations,
 each paying ~1-3 s of KEX latency over the Bastion local
 listener). §3-7 cut total deploy wall-clock by another
 ~45-90 s by reusing connections, parallelising CPU compression,
 shortening the SSH-readiness probe, parallelising pre-Terraform
 work, and batching small SSH commands.

§8 finally moves the last few seconds of `docker pull` latency out
of the deploy critical path and into bake.

---

## §1. Pre-bake the GPU ML stack into the GPU-CC image

**Where:** `apps/cli/src/tee_crafter/scripts/gpu_cc_{azure,gcp,aws}/setup_gpu_cc_*.sh`.

The three GPU-CC bake scripts pre-install the heavy GPU ML stack
into the image's `/opt/tee-crafter-gpu-cc/venv` at bake time:

| Package | Pin | Why pinned |
| --- | --- | --- |
| `torch` | `==2.5.1` | Matches `examples/gpu_confidential_inference/requirements.txt`. |
| `torchvision` | `==0.20.1` | Matches torch 2.5.1's tested companion. |
| `triton` | `==3.1.0` | Pulled by torch; pin so it's deduped at deploy. |
| `numpy` | `<2` | Torch 2.5.1 is incompatible with numpy 2.x. |
| `Pillow`, `safetensors`, `huggingface-hub`, `transformers`, `tokenizers`, `sentencepiece` | (latest at bake) | The de-facto "every HF inference example" set. |
| `scipy`, `scikit-learn` | (latest at bake) | Common in the analytics / fraud / health examples. |

The `nvidia-cu12-*` runtime wheels (cuDNN, cuBLAS, NCCL, NVRTC, …) are
pulled in transitively as torch 2.5.1 dependencies — pinned to the
exact versions in torch's metadata, so they match what a user's
`pip install torch==2.5.1` would resolve at deploy time, and the
dedupe pass (§2) skips them entirely.

**Trade-off.** Image grows by ~2.9 GB (most of which is the CUDA
runtime libraries inside the `nvidia-*-cu12` wheels). In exchange
every subsequent deploy of any GPU example uploads only the app code
plus genuinely-new user wheels — typically a few MB.

**Tensorflow?** Not baked by default. Modern H100 / A100 inference
work runs on torch in practice, and TF + JAX double the image size
without serving any of the examples in this repo. Users who need TF
should fork the bake script or add it to a follow-up bake on top of
the GPU-CC image.

---

## §2. Image-aware delta-only deploy uploads

**Where:** every bake script writes
`/etc/tee_crafter/image_pip_frozen.txt`; deploy paths read it back
through the same transport that ran the bake.

### Bake side

After every venv is provisioned, the bake script runs
`pip freeze --all > /etc/tee_crafter/image_pip_frozen.txt` (mode
0644). Every platform (SGX, SNP-AWS/Azure/GCP, TDX-Azure/GCP,
GPU-CC-AWS/Azure/GCP, Nitro) writes the manifest, so the optimization
is available everywhere — not just GPU-CC.

### Deploy side

`tee_crafter.cli.deployment.common.wheel_manager` gained two new
helpers:

* `fetch_image_pip_manifest(run_remote)` — opportunistic read of the
 bake manifest over SSH / SSM. Missing file, empty file, transport
 failure, and runtime exceptions all return `{}`, which keeps deploys
 on an *unbaked* image (the `--ami-id` is omitted) on the full
 download path with zero behaviour change.
* `download_wheels_delta(req_file, …, image_pins=…)` — drops any
 `==` pin from the user's requirements that the manifest already
 satisfies, then calls `download_wheels` on the residual set.
 Returns 0 when the manifest covers everything (we don't even start
 pip).

The dedupe is **conservative by design**. Only exact `==` pins with
no extra constraints and no environment markers are dropped. Range
specifiers (`torch>=2.5,<3`), looseners (`numpy~=1.26`), markers
(`torch==2.5.1; sys_platform == "linux"`), editables, direct URLs,
and VCS refs are all preserved verbatim and re-downloaded. This means
the optimization can never silently violate a user's spec — at worst
it falls back to the pre-existing behaviour.

The remote offline-install step (`pip install --no-index --find-links wheels -r requirements.txt`)
uses the user's **original** requirements file, not the filtered one,
because `pip install` is happy with "Requirement already satisfied"
for any package whose version is already present in the target venv
— so dropping a wheel from the upload does not break the install.

### Wired into

* `azure_bastion_client.py` — covers `snp-azure`, `tdx-azure`,
 `gpu-cc-azure` (and the host venv for container mode on all of
 them).
* `gcp_phase_client.py` — covers `snp-gcp`, `tdx-gcp`, `gpu-cc-gcp`.
* `snp/aws_artifacts.py` — covers `snp-aws` (container mode).

### Test coverage

`apps/cli/tests/cli/test_wheel_dedupe.py` pins the contract end-to-end —
parsing, filtering, and the integration `download_wheels_delta`
behaviour — including the "image satisfies everything", "version
mismatch", "range specs preserved", "environment markers preserved",
and "unbaked deploy falls through" paths.

---

## §2b. Race-free systemd oneshot wait

**Where:** `apps/cli/src/tee_crafter/cli/deployment/common/file_download.py`'s
`wait_for_oneshot_completion`, plus the activation probe in
`apps/cli/src/tee_crafter/cli/commands/deploy/batch.py`'s
`_start_oneshot_and_wait`.

Not strictly a bandwidth optimization, but it converts a class of
silent failures (the orchestrator declared the batch job "done" the
instant `systemctl start --no-block` returned, before `ExecStopPost`
had built `/var/lib/tee_crafter/output.tar.gz`) into either correct
behaviour or an explicit `not-activated` error with the journal
dumped. The host refuses to accept `inactive` as completion
until it has observed the unit in a *running* state, an
`ExecMainStart` timestamp, or a populated `Result` field — proof
that the unit actually ran.

Test coverage: `apps/cli/tests/cli/test_oneshot_wait.py`.

---

## §2c. Transport already in use per platform

The dedupe in §2 reduces the bytes-on-the-wire; the table below
documents what's actually carrying those bytes today.

| Platform | Bundle path (deploy) | Container path (deploy) | Observed throughput |
| --- | --- | --- | --- |
| `snp-aws`, `gpu-cc-aws`, `nitro-aws` | S3 → SSM pull | S3 → SSM pull | Gigabit+ (S3 region-local). |
| `snp-azure`, `tdx-azure`, `gpu-cc-azure`, `sgx-azure` | SCP over Bastion tunnel | SCP over Bastion tunnel | ~1.3-1.5 MB/s effective. |
| `snp-gcp`, `tdx-gcp`, `gpu-cc-gcp` | SCP over IAP tunnel | SCP over IAP tunnel | ~5-10 MB/s effective. |

Azure Bastion is the bottleneck. Even after §1 + §2 collapse the
GPU-CC bundle from ~2.9 GB to a few MB, large *user containers*
(custom Docker images built from the operator's `Dockerfile`) still flow
through the same tunnel.

---

## §3. SSH connection multiplexing (Azure Bastion + GCP IAP)

**Where:** `apps/cli/src/tee_crafter/core/remote/azure_ssh.py`,
`apps/cli/src/tee_crafter/core/remote/gcp_ssh.py`.

A typical Azure CVM deploy issues 30-40 individual `ssh`/`scp`
invocations (setup probes, capability discovery, env upload, service
start, journal tails, output download). Without multiplexing each
invocation negotiates a full TCP + SSH KEX + auth handshake — ~1-3 s
of latency per call, *and* it doubles as the primary trigger for the
`kex_exchange_identification` flakes we still retry around in §
`docs/security.md` (sshd's `MaxStartups` limiter and Bastion's local
listener both rate-limit fresh handshakes).

The fix is the standard OpenSSH idiom:

```text
-o ControlMaster=auto
-o ControlPath=$TMPDIR/tee-crafter-ssh-mux-<uid>/cm-%C
-o ControlPersist=5m
```

The first call opens a master connection over the Bastion / IAP
local listener; every subsequent call attaches as a sub-session in
single-digit milliseconds. `ControlPersist=5m` keeps the master
alive across phases so Step 3 (artifact upload) doesn't repay the
handshake cost paid by Step 1 (setup probe).

| Footprint | Detail |
| --- | --- |
| Socket path | `$TMPDIR/tee-crafter-ssh-mux-<uid>/cm-%C` — `%C` is a host:port:user-keyed hash so concurrent deploys don't collide. |
| Permissions | `0700` on the directory; SSH refuses to use the socket otherwise. |
| Disable | `TEE_CRAFTER_SSH_MUX=0` (debugging only). |
| Persist override | `TEE_CRAFTER_SSH_MUX_PERSIST=10m` etc. |
| Teardown | `BastionTunnel.stop` / `IAPTunnel.stop` call `close_ssh_mux(local_port)` before killing the tunnel. Otherwise the master would linger for `ControlPersist` seconds against a dead local listener and the *next* deploy would block trying to reuse a dead socket. |

**Expected savings.** With ~30 small SSH calls in a typical deploy
and ~1-2 s of avoided handshake per call, total deploy time drops by
30-60 s. The biggest absolute win is on Azure Bastion, where the
local listener also benefits from the lower KEX rate (fewer transient
retries to absorb).

---

## §4. Parallel-gzip (`pigz`) for local tarball compression

**Where:**
`apps/cli/src/tee_crafter/cli/deployment/common/wheel_manager.py::make_tarball_fast`,
called from `azure_bastion_client.py`, `gcp_phase_client.py`, and
`snp/aws_artifacts.py`.

Python's built-in `tarfile.open("w:gz")` compresses on a single
thread at ~30 MB/s on modern silicon — the dominant CPU cost for any
bundle bigger than 100 MB. When `pigz` is available on the deployer
(`brew install pigz` on macOS, `apt install pigz` on Linux) we shell
out to:

```bash
tar -C <src_parent> --transform=s,^<src_base>,<arcname>, -rf <raw.tar> <src_base>
…
pigz -p $(nproc) <raw.tar> > <out.tar.gz>
```

This produces a standard gzip stream (identical wire format, the
remote `tar xzf` does not change) but compresses linearly with the
deployer's core count — typically 3-6× faster on a modern laptop.
The pure-Python `tarfile` path is still the fallback when `pigz` /
`tar` are missing or when the caller forces it (`force_python=True`,
used by the unit tests).

We also install `pigz` and `zstd` into **every bake image**, so the
remote `tar xzf` step has parallel decompression available for any
future format change.

---

## §5. Exponential-backoff `wait_for_ssh`

**Where:** `azure_ssh.py::wait_for_ssh`, `gcp_ssh.py::wait_for_ssh`.

A naïve loop that sleeps a flat 10 s between probes wastes wall-clock
on baked images, which are typically SSH-ready in 5-15 s. The TEE-Crafter
prober paces itself for the fast-path images so the first probe rarely
   path.

The new loop starts at 2 s and multiplies by 1.5 each iteration up
to a 10 s cap. Worst case is unchanged (we still hit the 10 s cap
for slow-booting VMs); best case is ~7-9 s faster.

---

## §6. Image vulnerability scan in the build phase

**Where:** `apps/cli/src/tee_crafter/cli/commands/deploy/flow_container.py`.

The container build flow scans the **built image** with Trivy (Grype
fallback) as part of Phase 1, before any cloud resources are
provisioned. Scanning the assembled image — rather than only the raw
source tree — means the gate (`VLN-*`) covers OS packages and every
transitive layer, not just the app's direct dependencies.

CRITICAL/HIGH findings block the deploy unless `--allow-vulnerable`
is set (each override is recorded in `build_provenance.json` with
`gate_allowed=True`). The scan runs once, locally, so a vulnerable
image never reaches the slow Terraform-apply step.

---

## §7. Batched SSH setup commands

**Where:** `azure_bastion_client.py`, `gcp_phase_client.py`.

Two patterns recurred in the deploy clients:

1. **Pre-app-start setup** — three sequential SSH calls
 (`systemctl reset-failed`, device `chmod`, `chown -R` + `chmod` +
 `systemctl start`).
2. **Service readiness polling** — two SSH calls per cycle
 (`systemctl is-active`, `journalctl | grep -c 'listening on
 port'`).

Both are merged into a single round-trip per logical
event. Even with §3's connection multiplexing each extra
round-trip pays a small (~50-200 ms) latency cost over the
Bastion / IAP local listener; collapsing the 36-cycle readiness loop
from 72 to 36 round trips saves ~5 s on a slow tunnel.

The collapsed pre-start command is one string with `;`/`&&`
sequencing so the failure semantics match the prior split (a hard
failure in `systemctl start` still surfaces a non-zero exit). The
collapsed poll command emits `ACTIVE=<state>\nLISTENING=<count>` and
the client parses both halves in Python.

---

## §8. Pre-pull Docker base images at bake time

**Where:** every bake script writes the prewarmed image inventory to
`/etc/tee_crafter/image_docker_prewarmed.txt`.

Container deploys end with `docker build` / `docker load` inside the
TEE host. The base layer
(`python:3.12-alpine`, `rust:alpine`, or
`nvidia/cuda:12.4.1-runtime-ubuntu22.04` for GPU CC) is identical
across every user deploy; pulling it at bake time means:

- The user's first build at deploy time is ~10-30 s faster on CPU
 TEEs (`python:3.12-alpine` is small but pulls over the Bastion
 egress path still cost RTT × layer count).
- The user's first build at deploy time is ~30-60 s faster on GPU
 CC (`nvidia/cuda` runtime is ~3 GB).
- On platforms whose CVM has no public-internet egress at deploy
 time (Azure SNP/TDX with the NSG locked, and Nitro Enclaves
 always), this is also a *correctness* win — without the prewarm
 the Dockerfile build inside the TEE simply cannot resolve the
 `FROM` line.

Pre-pulled images for non-GPU TEEs:

- `python:3.12-alpine` — common slim Python base.
- `python:3.12-slim` — container common base.
- `rust:alpine` — NSM proxy multi-stage build.

Pre-pulled images for GPU-CC:

- `nvidia/cuda:12.4.1-runtime-ubuntu22.04` — common GPU base.
- `nvidia/cuda:12.4.1-base-ubuntu22.04` — for users who supply a
 thinner base.

All pulls are best-effort — if the bake VM cannot reach
`registry-1.docker.io` (e.g. private CI runner) the bake still
succeeds and the deploy-time pull just pays its normal cost.

---

## §9. Future work (not yet implemented)

These are queued but deferred — each is a meaningfully larger change
than §1-8 and the current path already works.

### §9.1 Azure Storage SAS staging for large bundles

Above a threshold (currently proposed at 200 MB) the deployer would:

1. Upload `app_bundle.tar.gz` / `user_container.tar` to an ephemeral
 container in an Azure Storage account in the same region as the
 target VM.
2. Mint a short-lived (15 min) read-only SAS token.
3. Have the VM `curl` the blob directly over the platform VNet —
 throughput jumps to ~1 Gbit/s and Bastion stays out of the data
 path.
4. Delete the blob after the install completes.

This mirrors what the AWS path already does with S3, and requires the
deployer to have `az login` (already a hard prerequisite of the
existing Azure deploys).

### §9.2 GCS staging for the GCP path

Same shape as §9.1 but with GCS for `snp-gcp` / `tdx-gcp` /
`gpu-cc-gcp`. IAP is faster than Bastion in practice so the win is
smaller, but it disappears entirely once a user uploads a multi-GB
custom container image.

### §9.3 Container image layer dedupe

`tee-crafter deploy` ships the whole `docker save` tarball
even if the user is just iterating on the top application layer. A
layered upload (`docker save base_image` once into the image / blob
storage, then only the changed top layers per deploy) would compress
GPU container deploys to a few MB of upload after the first one.

### §9.4 Optional `requirements-pinned.txt` materialization

The dedupe in §2 only fires on exact `==` pins. For users who write
`torch>=2.5,<3` the optimization is a no-op. A future
`tee-crafter freeze` subcommand could resolve the user's spec against
the image manifest and write `requirements-pinned.txt` with exact
pins, which then gets deduped end-to-end on every subsequent deploy.

---

## Verifying the optimizations in practice

After redeploying with a freshly-baked image:

```
tee-crafter deploy \
 --source./examples/gpu_confidential_inference \
  --tee-platform gpu-cc-azure \
  --ami-id /subscriptions/.../tee_crafter_gpu_cc_ubuntu/versions/<latest> \
  --persistent \
  --deploy --auto-approve --teardown
```

Expected behaviour with the full optimization stack:

```
gpu-cc-azure: skipping 14 wheel(s) already on image: torch==2.5.1, torchvision==0.20.1, nvidia-cuda-nvrtc-cu12==12.4.127, …
gpu-cc-azure: 0 wheel/sdist files downloaded
```

…and the `Uploading GPU CC Azure artifacts...` step should complete
in seconds rather than minutes (§1 + §2).

`tail -f` the deployer's stdout and look for an unbroken sequence of
SSH commands all completing in <1 s — that's §3's connection
multiplexing. The very first SSH probe after Terraform apply
returns in 2-5 s instead of 10 s — that's §5's
exponential-backoff `wait_for_ssh`. And the local tarball-creation
step (`Uploading … artifacts`) finishes in <3 s on multi-core
machines — that's §4's `pigz`.

To temporarily disable any of these for benchmarking:

```bash
# Per-call SSH multiplexing off
export TEE_CRAFTER_SSH_MUX=0

# Force pure-Python tarball compression (skip pigz)
# (no env knob; pass force_python=True if calling make_tarball_fast directly)
```

There are no env knobs for §1 / §2 / §6 / §7 / §8 — they are pure
wins with zero downside and ship enabled by default.
