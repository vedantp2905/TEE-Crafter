# Watch list: provider capabilities to re-check before acting on them

Nothing in this file is a task. It is a record of cloud-provider capabilities
and warnings that would change TEE-Crafter's supported platform list if they
changed status — collected so that a future decision starts from what was
already established rather than from a fresh search.

Two things to keep straight while reading:

- **These are point-in-time observations, not current truth.** Each was recorded
  from provider documentation on the date given. Preview features graduate,
  get cancelled, and get renamed. Re-check the provider's own documentation
  before acting on any entry here; do not treat this file as authoritative.
- **The machine-family names below are Google Cloud machine families**, not
  identifiers from this project's open-items list. "C3" and "C4" here mean the
  Compute Engine C3 and C4 families. That collision is unfortunate and is the
  reason each entry spells out which family it means.

Recorded as of **2026-08-22** unless an entry says otherwise. The
**provider-side** claims below carry that date and have not been re-checked
since. The **repo-side** claims — which platform accepts which machine type,
and what the templates set — were re-verified against the code on
**2026-08-23** and are pinned by `tests/core/test_watchlist_family_exclusions.py`,
so a change that contradicts one of them fails the suite rather than silently
landing.

---

## Intel TDX on the Google Cloud C4 machine family — Preview

Intel TDX is in Preview on the **C4** machine family. If it reaches general
availability it becomes a second hardware option for the `tdx-gcp` platform,
alongside the C3 family that platform uses today.

Today `tdx-gcp` accepts C3 machine types only: the catalog matches
`^c3-(standard|highmem|highcpu)-N$` and the default is `c3-standard-4`, so
`c4-standard-4` is rejected today (verified). Adding C4 would mean widening that
gate and extending the instance catalog, and — more importantly — capturing a
fresh reference measurement, because the launch measurement (`MRTD`) is specific
to the platform firmware and will not carry over from C3.

**Do not widen the gate on the strength of this entry alone.** Confirm general
availability first.

## Intel TDX on the local-SSD C3 variants (`c3-standard-*-lssd`) — Preview

The local-SSD variants of the C3 family are a separate Preview from C3 itself.
They are relevant only if a workload needs local NVMe scratch space inside a TDX
guest. Note that local SSD is ephemeral by design, which interacts awkwardly with
attested, reproducible runs: anything written there is neither measured nor
persisted, so it should not hold state a verifier is expected to reason about.

`c3-standard-4-lssd` is rejected by the catalog today (verified) — the `-lssd`
suffix does not match the C3 pattern the gate accepts, so this needs a
deliberate change rather than being reachable by accident.

## The C4D, C2D and C3D machine families are AMD SEV *only* — not SEV-SNP

This entry exists specifically to stop someone adding these families to
`snp-gcp` because the generation number looks newer.

`snp-gcp` requires **AMD SEV-SNP**, and its platform gate accordingly accepts
only machine types beginning `n2d-`; `c4d-`, `c2d-` and `c3d-` shapes are
rejected today, and no row for any of them exists in the catalog (both
verified). The C4D, C2D and C3D families offer plain AMD SEV, which is a
materially weaker guarantee: SEV without SNP lacks the integrity protection and
the attestation report that this project's evidence chain depends on. C4D being
the newest AMD silicon in Compute Engine makes this an easy mistake, which is
why it is written down.

If any of these families gains SEV-SNP support, that is a genuine platform
addition and needs its own measurement capture, not just a catalog row.

## The Google Cloud G4 family offers AMD SEV plus NVIDIA confidential computing

G4 pairs AMD SEV on the CPU side with NVIDIA confidential computing on the GPU
side. That combination is close enough to `gpu-cc-gcp` to be tempting and
different enough to be misleading.

`gpu-cc-gcp` uses Intel TDX on the CPU side — the template sets
`confidential_instance_type = "TDX"` explicitly (verified), and `g4-` shapes are
rejected by the catalog. G4's CPU side is SEV *without* SNP, so its CPU evidence
would be strictly weaker than what `gpu-cc-gcp` produces today.

Adding G4 would therefore be a new platform with a different trust model, not a
new instance type on an existing one. It needs its own trust-model write-up
stating plainly what a verifier can and cannot conclude from SEV-only CPU
evidence, before any code is written.

## Google warns of AMD SEV-SNP performance degradation, roughly August to November 2026

Google has warned that SEV-SNP boot times and general performance may degrade
during a guest-kernel migration in this window.

This one is operationally useful rather than architectural: **if `snp-gcp`
deployments start timing out during that period, check this before hunting for a
regression in this repository.** A slower boot can surface as a deployment
timeout that looks exactly like a bug in the setup scripts. Confirm against
Google's current status notices before spending time on it, since the window may
have moved or closed.

## NVIDIA's NRAS endpoint address is stable by architecture, not by promise

GPU CC deploys pin egress to whatever `nras.attestation.nvidia.com` resolves to
at deploy time, because NVIDIA publishes no ranges for it. On 2026-08-23 that was
a single address, `34.120.45.54`, identical from two independent resolvers and
inside `34.64.0.0/10` — the range GCP assigns to global external Application Load
Balancers. An anycast VIP in front of one load balancer is about as stable as an
unpublished address gets, which is why pinning it is reasonable.

It is still not a commitment. **If GPU attestation starts failing with a
connection timeout rather than a rejection, re-resolve the hostname before
looking for a code regression** — a redeploy re-pins it. Check with:

```bash
dig +short nras.attestation.nvidia.com
```

Do not widen to the enclosing `/10` as a workaround: that is four million
Google-owned addresses and would make the allowlist meaningless.

Strict resolve-and-pin was exercised on hardware on 2026-08-24: a
`gpu-cc-azure` deploy in `eastus2` resolved the hostname at deploy time, pinned
the resulting host route, and passed GPU attestation with no broad-internet
rule. That closed the standing item this entry used to point at, so what remains
here is the caveat rather than a task. Note that the SDK's local verifier is not
an escape — it needs `rim.attestation.nvidia.com` and `ocsp.ndis.nvidia.com`
instead, and its OCSP check has no skip flag.

---

## `snp-azure` has a Genoa launch digest and no Milan one

Recorded **2026-08-24**. The registry holds one generation: `AMD EPYC 9V74`,
`cpu_gen: genoa`, observed. Azure schedules the confidential-computing v5
families on Milan **or** Genoa and offers no equivalent of Google Cloud's
`min_cpu_platform`, so no SKU forces Milan. A deploy that lands on Milan fails
closed with a measurement mismatch, warned about up front.

Getting the second digest is luck, not engineering: re-bake until one lands on
Milan hardware. Worth doing opportunistically on a bake that is happening
anyway; not worth paying for on its own. Do not hand-pin it — an unmeasured
value is the `manual` pin the registry rejects by test.

The version suffix is *not* a second axis: `Standard_DC2as_v5`, `DC4as_v5` and
`DC4as_v6` all produced the same digest on 2026-08-24, all observed as `genoa`.
The determinant is the host CPU generation. vCPU count still is an input, since
SEV-SNP measures one VMSA per vCPU.

---

## Related

- [pending.md](pending.md) — the two platforms that have never run on real
  hardware, and what procurement would unblock them
- [instance_sizing.md](instance_sizing.md) — the instance catalog and how
  platform gates restrict machine types
- [measurements.md](measurements.md) — why a new hardware family needs a fresh
  reference measurement rather than an inherited one
