# Batch Mode

Batch mode runs your **Docker image as authored** inside a Trusted Execution
Environment, captures every file it produces, and downloads the result back to
your build directory. There is no ``process_request`` contract and no live
RA-TLS client channel — assurance is deploy-time attestation + the signed
audit bundle.

```bash
tee-crafter deploy \
 --source./my_image_dir \
  --tee-platform tdx-azure \
  --ami-id <baked-id> \
  --batch \
  --batch-timeout 1800 \
 --input-dir./inputs \
  --deploy --auto-approve --teardown
```

* ``--source`` must contain a ``Dockerfile``. The pipeline builds your image,
 saves ``user_container.tar``, and runs it to completion on the TEE host.
* ``--input-dir`` is uploaded to ``/var/lib/tee_crafter/input`` on the host
 and mounted as ``/input:ro`` inside the container.
* Intel SGX (``sgx-azure``) supports **batch only** for v1 (GSC path when
 ``gsc`` is available on the build host; see ``cli/deployment/sgx/gsc.py``).
* When the container exits, ``tee_crafter_capture_container.sh`` runs as a
 systemd ``ExecStopPost`` hook: ``docker logs``, ``docker inspect``,
 ``docker diff``, and ``docker cp`` for every added/changed path.
* The bundle is pulled back to ``<build_dir>/output/`` as ``output.tar.gz``.

## Bundle layout

```
output/
 files/... # captured paths, at their original locations
  _logs/stdout.log
  _logs/stderr.log
  _logs/exit_code.txt
  _meta/inspect.json
  _meta/diff.txt
```

## Common flags

| Flag | Default | Notes |
| --- | --- | --- |
| ``--batch`` | off | Mutually exclusive with ``--persistent``. |
| ``--batch-timeout`` | ``3600`` | Hard wall-clock timeout (seconds) for the run + capture. |
| ``--input-dir`` | none | Local directory uploaded as a plain ``tar.gz`` and extracted **in the clear on the host**, then bind-mounted read-only at ``/input``. Not encrypted to the TEE — see below. |
| ``--keep-on-failure`` | off | Leave infrastructure running on failure for debugging; default tears it down. |

The bundle size cap is **internalised** at 2 GiB. See
[docs/execution_model.md](execution_model.md) for the full unified model.

## Mutual exclusion

* ``--batch`` and ``--persistent`` cannot be combined.
* ``--batch`` and ``--service-profile != default`` cannot be combined.
* ``sgx-azure`` requires ``--batch`` (persistent services are not offered on SGX in v1).

## Security model deltas

| Constraint | Persistent mode | Batch mode |
| --- | --- | --- |
| Live RA-TLS client channel | attested ingress proxy | deploy-time attestation + bundle SHA |
| ``docker run --read-only`` | enforced | lifted — ``docker diff`` needs writes |
| Network egress allowlist | enforced | enforced |
| Cap-drop / no-new-privileges / seccomp | enforced | enforced |
| AppArmor profile | `tee-crafter-container` (strict, path-allowlisted) | `tee-crafter-batch-container` (broad paths — see below) |
| Host sees plaintext input | no | **yes** — see below |
| Available on ``nitro-aws`` | yes (enclave) | **no** — rejected in pre-flight; batch needs a CVM platform |

### Why batch mode uses a looser AppArmor profile

Batch runs *arbitrary* user images whose filesystem layout is unknown at deploy
time, so path allowlisting would routinely break workloads that legitimately
write to `/data`, `/output` or `/workspace`. The batch profile therefore allows
broad filesystem access and keeps confinement in the layers that do not depend
on knowing the paths: `--cap-drop ALL`, seccomp, `no-new-privileges`, the
network deny-list, and an explicit deny-list for host kernel interfaces
(`/proc/kcore`, `/sys/kernel/**`, `mount`, `pivot_root`, `ptrace`, the dangerous
capabilities). Service mode, which runs a TEE-Crafter-built image with a known
layout, keeps the strict profile.

One footnote with teeth: the broad rule is `/** rwlkmix,`, and in AppArmor
`/**` does **not** match the bare `/`. A profile that reads as "allow
everything" denied `open("/")`, which is exactly what Gramine's loader does —
so every `sgx-azure --batch` run failed to start its enclave. Both profiles now
carry an explicit rule for `/`; see
[sgx_flow.md](sgx_flow.md#two-things-the-enclave-needs-from-outside-itself).

### The host sees your batch input

``--input-dir`` is **not** a confidentiality control. The CLI tars the directory,
uploads it over the deploy channel, and the host extracts it in the clear to
``/var/lib/tee_crafter/input`` before bind-mounting it read-only at ``/input``
(``cli/commands/deploy/batch.py``, lines 531–560). The transport is encrypted;
the copy on the host's disk is not.

``nitro-aws`` does not appear here, because container batch is rejected on it
outright: a Nitro Enclave boots a signed EIF rather than an operator-supplied
OCI image, so it is absent from ``resources.CONTAINER_PLATFORMS`` and
``--batch --tee-platform nitro-aws`` fails in pre-flight before Terraform runs
(``cli/preflight.py::_check_container_batch_supported``).

If the input is sensitive, wrap it with ``tee-crafter seal-input``. Be aware
that this currently produces a bundle with **no in-TEE consumer** — see the
warning in [cli_reference.md](cli_reference.md#sealed-input-bundles).

### Batch output is captured by ``docker diff``

Nothing mounts or creates ``/output``. Capture works by diffing the container's
own writable layer after it exits, so your image must create any output
directory it writes to (``RUN mkdir -p /output``), and everything it writes ends
up in ``output.tar.gz``.

Full rationale: ``docs/security.md``.
