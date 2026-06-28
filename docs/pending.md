# Pending: what has not been done

Only outstanding work. What *has* been verified is described in the per-platform
documents ([nitro](nitro_flow.md) · [snp](snp_flow.md) · [sgx](sgx_flow.md) ·
[tdx](tdx_flow.md) · [gpu](gpu_flow.md)) and in
[measurements.md](measurements.md) and [byok.md](byok.md); this file is the
to-do list, so an item leaving it means it is done.

Eight of the ten platforms have been deployed to real hardware and verified end
to end. Before spending on a run, read
[hardware_verification.md](hardware_verification.md).

---

## Two platforms have never run on hardware

Both are blocked on accelerator supply, not on code. The code is written; what
is missing is a machine to run it on.

**Re-bake before either run.** Fixes have landed in the bake scripts since these
platforms were last attempted, and an existing image carries the older setup.

### `gpu-cc-aws` — needs P5 capacity

`p5.4xlarge` returned `InsufficientInstanceCapacity` in all seven availability
zones of `us-east-2` and `us-west-2`, on-demand and spot. The account's quota
permits the launch; AWS had no capacity to give, so raising a quota will not
help. What would: an **AWS Capacity Block for ML**, or an **On-Demand Capacity
Reservation** for a P5 shape in a named zone.

Everything else is implemented. CPU-side attestation is now a verified NitroTPM
measured-boot check — the document is chain-validated to the pinned
`certs/nitro-root.pem`, its COSE_Sign1 signature checked, PCR4/PCR7 compared
against values the bake captures, and its `user_data` bound to the session's
ECDH key. The bake installs `nitro-tpm-attest` and refuses to complete without
it. See [gpu_flow.md](gpu_flow.md#cpu-attestation-on-gpu-cc-aws-measured-boot-verified-locally).

**To close: obtain capacity, deploy once, and iterate on whatever the run
surfaces.**

### `gpu-cc-gcp` — needs an H100 allowlist grant

The validation project has **no H100 quota metric at all** — `us-central1`
reports 113 metrics covering K80, P100, V100, P4 and T4, and nothing matching
H100. That is stronger than a limit of zero: the shape cannot be requested, so
there is no limit to file an increase against. What unblocks it is an
**allowlist grant**, which is a conversation with Google Cloud rather than a
self-service form.

Everything else is implemented. `verify_ratls_connection` assembles a real TDX
quote, a real PCK chain and a real NVIDIA token, and the orderings where one
check is worthless without its predecessor are pinned by
`tests/core/test_gpu_client_check_composition.py`. Two gaps that would have
failed the first hardware run were closed: the image did not
install `tpm2-tools` even though the app shells out to `tpm2_pcrread`, so the
vTPM PCR bundle would have been empty and the client would have failed closed;
and no reference PCR set was ever captured or passed, so the comparison had
nothing to compare against. The PCRs are now read on the probe VM that the MRTD
capture already boots, at no extra cost.

**To close: obtain the grant, deploy once, and iterate on whatever the run
surfaces.**

---

## The SIEM fail-closed gate is unexercised on eight platforms

A deliberately dark collector aborts the deploy on `snp-aws` and `nitro-aws`.
The other eight take the same code path — the seam is `install_siem_sidecar`,
reached by all ten through seven call sites — and have not been run against one.

This needs **no extra deploy**: the procedure in
[siem.md](siem.md#observing-the-gate-on-a-run-you-are-already-paying-for) takes
both observations from a run that is already up.

## The README's deploy commands have not been run verbatim

The quickstart is verified on a clean checkout. The `bake-ami` and `deploy`
commands have been run many times since, but with flags chosen for whatever was
being verified rather than copied out of the README. Run them verbatim on the
next round: shell history is where flags missing from the documentation come
from.
