# Launch-measurement auto-pinning

TEE-Crafter binds attestation and key release to a **launch measurement** — the
firmware's hash of the initial guest state (AMD SEV-SNP `MEASUREMENT`, Intel TDX
`MRTD`, AWS Nitro `PCR0`, Intel SGX `MRENCLAVE`). For Nitro and SGX this is
computable at build time (from the EIF / Gramine manifest) and is already pinned
into the verifier client. For **confidential VMs** (SNP/TDX/GPU-CC) the
measurement only exists once the baked image boots, so it cannot be derived on
the build host.

> ## What a pinned SNP measurement does and does not cover
>
> **It does not cover the contents of your baked OS image**, and that is worth
> stating plainly because "measurement-pinned image" reads as though it does.
>
> Measured on `snp-azure`: two independent bakes whose disks
> differ materially — the second added `AttestationClient`, `AzureAttestSKR` and
> an edited AppArmor profile — produced the **identical** launch measurement,
> `b2b53ada66639958…`. Both values were read live from the vTPM on the booted
> image (`tpm2_nvread 0x01400001`, `core/measurements/capture.py`), so this is
> not a caching artefact.
>
> That is correct SEV-SNP behaviour rather than a defect: on an Azure CVM with
> `security_encryption_type = DiskWithVMGuestState`, the launch measurement
> covers the *initial guest memory* — firmware/OVMF plus boot configuration and
> vCPU count — and the OS disk is attached after launch, its integrity anchored
> by confidential-disk encryption and the vTPM rather than by the measurement.
> It is also why the measurement varies by vCPU tier but not by software.
>
> So the pin is a real control with a narrower meaning than the name suggests:
>
> | Pinning the SNP measurement **does** stop | It **does not** stop |
> |---|---|
> | A launch on different firmware or boot configuration | A change to the software you baked into the image |
> | A non-confidential or differently-configured VM presenting itself as this one | An operator baking a new image and deploying it under the same pin |
>
> **What binds your workload is the container image digest**, which the CVM app
> hashes into the attestation's `report_data` alongside its ECDH key, and which
> the verifier client recomputes and refuses on mismatch — see the v2 binding in
> [snp_flow.md](snp_flow.md). Treat the measurement pin as "this is a genuine
> CVM on the firmware I expect" and the digest binding as "running the code I
> expect". Both are needed; neither substitutes for the other.
>
> **`snp-aws` behaves the same way**, and the registry already proved it without
> spending anything. Two independently baked AMIs —
> `ami-0dc3a149b36b33fff` and
> `ami-0a6e51a20a2d3ed81` — report the *identical*
> measurement `507e82d27ea5b951…` for the same `m6a.large` / 2-vCPU / Milan
> variant, and in fact agree at all five captured vCPU tiers. Two bake runs two
> days apart cannot produce byte-identical disks: each
> generates a fresh `/etc/machine-id` and new SSH host keys, and installs whatever
> package versions the archives served that day. A measurement that covered the
> disk would have moved. It did not.
>
> The same record also shows what the measurement *does* track: five distinct
> digests across the five `m6a` vCPU tiers, from `507e82d2…` at 2 vCPU to
> `ecb285bd…` at 32. Sensitive to boot configuration, blind to the filesystem —
> exactly the SEV-SNP semantics described above, now on two clouds.
>
> Weaker in one respect than the `snp-azure` experiment: there the software
> difference was introduced deliberately (`AttestationClient`, `AzureAttestSKR`,
> an edited AppArmor profile), whereas here the disks merely *cannot* have been
> identical. Both point the same way.
>
> ### `snp-gcp`: the digest moves, but not because of the disk
>
> This was tested rather than assumed, twice, and the first conclusion was wrong.
>
> Two independently baked `snp-gcp` images gave **different** measurements for the
> same machine type, which looked like the measurement covering more of the image
> than on Azure/AWS. A third bake then matched the **first**, not the
> second — so the second was the outlier, and "every re-bake changes it" could not
> be right, because two bakes three days apart agreed exactly.
>
> The deciding experiment was to re-measure the outlier image itself. Booted again
> a day later, same machine type, same `min_cpu_platform`, it produced
> `2d24cf9624ee3644…` — the value the *other two* images give, not the
> `0e017d2fba7c4964…` recorded for it at bake. One image, identical disk contents,
> two different launch measurements depending on when it booted. The measuring VM
> reported `AMD EPYC 7B13` (Milan) both times, so this is host firmware or
> microcode beneath a single generation, not a generation change.
>
> So the disk-blindness result **does** hold on GCP. What does not hold is
> stability over time:
>
> | | `n2d-standard-2` | `n2d-standard-8` |
> |---|---|---|
> | bakes 1 and 3 | `2d24cf9624ee3644…` | `63e1ed00252d6e47…` |
> | bake 2 (outlier) | `0e017d2fba7c4964…` | `69da361d9e3b09fb…` |
> | outlier image, re-measured 08-24 | `2d24cf9624ee3644…` | — |
>
> Operationally this is the important case: a correctly pinned `snp-gcp` image can
> begin failing attestation **because Google updated host firmware**, with nothing
> about the image or the deploy having changed. Read a mismatch there as
> "re-measure and compare" before "the image is wrong" — while still treating it as
> a mismatch, never as a reason to widen an allowlist.
>
> Scope of the evidence, in one line: the measurement is blind to the baked disk
> on `snp-azure` (deliberate software change) and `snp-aws` (two bakes 31 h
> apart), and also blind to it on `snp-gcp`, where the digest instead moves with host
> firmware over time (established by re-measuring one image twice).

To close that gap without a manual operator step, `bake-ami` captures the
measurement of every CVM image it produces and stores it in a packaged
registry, and `deploy` looks it up automatically.

## Registry layout

```
apps/cli/src/tee_crafter/measurements/<tee-platform>/<sanitized-image-id>.json
```

Each record (SNP may contain several digests — one per vCPU tier — or a single
digest flagged `vcpu_independent` that covers the whole family):

```json
{
  "platform": "snp-aws",
  "image_id": "ami-0123456789abcdef0",
  "field": "measurement",
  "measurement": "b756dd…e107",
  "measurements": ["b756dd…e107", "c812ff…a901", "d903ee…b002"],
  "variants": [
    {"instance_type": "m6a.large", "vcpu": 2, "cpu_gen": "milan", "measurement": "b756dd…e107"},
    {"instance_type": "m6a.xlarge", "vcpu": 4, "cpu_gen": "milan", "measurement": "c812ff…a901"},
    {"instance_type": "m7a.large", "vcpu": 2, "cpu_gen": "genoa", "measurement": "d903ee…b002"}
  ],
  "vcpu_independent_gens": ["genoa"],
  "captured_at": "2026-06-01T07:00:00Z",
  "source": "bake-ami"
}
```

``measurement`` is the primary (first) entry for backward compatibility.
``measurements`` is the full allowlist used at deploy time. ``variants``
records the instance type, **vCPU count** and **CPU generation** behind each
digest. ``vcpu_independent_gens`` lists generations whose single digest covers
every vCPU size of that generation.

### Measured-boot registers, which are not launch measurements

Two platforms carry PCR values in the record as well, and they are a different
kind of thing from a launch digest: a launch measurement is the firmware's hash
of initial VM memory, whereas a PCR is a hash of what the boot chain executed.
They are not interchangeable, and neither substitutes for the other.

```json
{
  "nitrotpm_pcrs": {"4": "5a3f83…779e", "7": "5ddaeb…7972"},
  "vtpm_pcrs": {"0": "a1b2…", "1": "c3d4…", "…": "…"}
}
```

| Field | Platforms | Bank | Signed? | Consumed by |
|---|---|---|---|---|
| `nitrotpm_pcrs` | `snp-aws`, `gpu-cc-aws` | **SHA-384** | Yes — a NitroTPM attestation document is COSE_Sign1-signed by the Nitro Hypervisor | The BYOK key policy's `kms:RecipientAttestation:NitroTPMPCR<n>` conditions, and the `gpu-cc-aws` client's `EXPECTED_NITROTPM_PCRS` |
| `vtpm_pcrs` | `gpu-cc-gcp` | SHA-256 | **No** — the server publishes them about itself, unsigned | The `gpu-cc-gcp` client's `EXPECTED_VTPM_PCRS`, as a tripwire; its real CPU anchor is the TDX quote |

The **bank difference is load-bearing**, not incidental. A NitroTPM document
reports `digest: SHA384` and 48-byte values; a policy or client pin written with
32-byte SHA-256 values denies the *legitimate* caller, which is how this was
found. `core/keys/nitrotpm.py` now rejects a 32-byte value rather
than storing it. The GCP vTPM is read as SHA-256 because that is the bank the
server reads (`_get_vtpm_pcrs`); comparing across banks fails every time.

Only these two platforms record PCRs. Other CVMs have vTPMs that would answer
the probe, but nothing consumes their values, and recording them under these
names would be a lie of labelling.

**Measured.** One `snp-aws` image captured across four
vCPU tiers (2, 4, 8, 32) on observed Milan hosts produced **four distinct launch
measurements** and **one identical PCR4/PCR7 pair**. That is why the PCRs are
stored once at record level: they describe the boot chain, which does not depend
on the number of virtual processors, while the launch digest folds in one VMSA
per vCPU and therefore does. A practical consequence: a BYOK policy pinned to
PCR4/PCR7 survives an instance resize; one pinned to the launch measurement does
not.

**Where each is captured, and why the instance type differs:**

* `snp-aws` — folded into the SEV-SNP capture, on the VM already booted for the
 launch measurement. No extra instance.
* `gpu-cc-gcp` — folded into the MRTD capture, likewise. No extra instance.
* `gpu-cc-aws` — has no launch measurement to fold into, so it boots its own
 probe, and deliberately on a **cheap non-GPU shape** (`m6a.large` by default).
 PCR4 hashes the binaries UEFI executed and PCR7 the Secure Boot policy; both
 are properties of the AMI's boot chain and its `UefiData`, not of an attached
 GPU. Booting a `p5.4xlarge` to read two registers would cost orders of
 magnitude more and answer the same question. The recorded field
 `nitrotpm_pcr_probe_instance_type` says which shape was used, so the
 assumption is auditable rather than implicit.

The bake instance itself cannot be reused for any of this: it booted the *base*
image, so its PCRs measure the boot chain being replaced.

The registry ships inside the package (`pyproject.toml` `package-data`), so a
pinned image is available to every `deploy` invocation from the same checkout.
Do not hand-edit these files — re-bake to regenerate.

**Pins are per-checkout, so commit them.** `bake-ami` writes the record into the
checkout it ran from and nowhere else. Bake on a build host, then deploy the
same AMI from your laptop, and the laptop's registry has no entry — so any
`--byok` or `--secrets-env` deploy fails closed with *"No bake-time launch
measurement for this image"*, and a plain deploy renders a client that refuses
with *"No launch measurement is pinned into this client"*. Neither message is
wrong; the pin simply never travelled. Commit
`apps/cli/src/tee_crafter/measurements/<platform>/<image-id>.json` along with
the AMI id (these files are not gitignored, and that is deliberate), or
re-record it on the deploying machine with `internal pin-measurement` once you
have vetted the digest.

**Docker re-exec / persistence.** The CLI re-execs into a `--rm` Docker
container where the in-container packaged path
(`/opt/tee-crafter/src/tee_crafter/measurements`) is a throwaway layer — pins
written there would vanish on exit and a later `deploy` (a separate container)
would never see them. The wrapper therefore bind-mounts the host's packaged
registry and sets `TEE_CRAFTER_MEASUREMENTS_DIR` so `bake-ami` writes (and
`deploy` reads) the operator's repo copy at
`apps/cli/src/tee_crafter/measurements`. Set `TEE_CRAFTER_MEASUREMENTS_DIR`
yourself only to point at a custom/shared registry root.

## Capture (bake time)

After `bake-ami` finishes `create_image`, it boots throwaway TEE instance(s)
from the new image, reads the firmware measurement over the cloud's remote-exec
channel, writes the registry record, and tears each instance down. The reader is
platform-aware (`core/measurements/capture.py`): SNP reads the report
`MEASUREMENT` (offset `0x90`); TDX reads the `MRTD` via configfs-tsm — the
**same framing the runtime TDX client verifies**.

The TDX offset depends on which container you were handed, so do not hard-code
one. `core/keys/attestation_providers.py::detect_tdx_mrtd_offset` sniffs it:

| Container | MRTD offset | How it is recognised |
|---|---|---|
| TD Quote v4/v5 | **184** (48-byte header + 136 into the body) | header `version` 4 or 5 **and** `tee_type == 0x81` |
| Bare `TDREPORT_STRUCT` | **528** (TDINFO at 512, + 16) | length is exactly 1024 bytes |
| Azure HCLA blob | **560** (32-byte header + 528) | leading `HCLA` magic |

configfs-tsm `outblob` is filled with a TD Quote by the Linux `tdx-guest` TSM
provider, so 184 is the common case. If none of the three patterns match, the
helper **raises** rather than guessing — hashing the wrong 48 bytes produces a
plausible-looking measurement that silently never matches the allowlist, which
is worse than a hard failure.

**The catalog + `shapes.py` are the source of truth.**
``core/catalog.py`` enumerates every selectable instance type and its specs
(vCPU, RAM, **CPU generation**, GPU); ``core/measurements/shapes.py`` decides,
from that catalog, which generations and vCPU tiers the bake measures. The whole
cloud-supported family is allowed — `m6a`/`c6a`/`r6a` (Milan) + `m7a`/`c7a`/`r7a`
(Genoa) on AWS, `DCas`/`ECas` v5+v6 on Azure, `n2d-*` on GCP — not a shortlist.

**SNP (bake once, deploy any size in the family).** AMD SEV-SNP launch
``MEASUREMENT`` folds in the host **CPU generation** (Milan vs Genoa) and one
VMSA **per vCPU** (RAM size and family name do **not** change it). So the bake
walks each supported generation and, within it, the vCPU tiers **ascending**
(default `2,4,8,16,32,48,64,96`, override with `TEE_CRAFTER_SNP_CAPTURE_VCPUS`).
After the two smallest tiers of a generation it does an **early-stop
independence probe**:

* if their digests are **identical**, the bake stops walking that generation's
 larger tiers (each one is a real VM, so this is cost control) and — **only if
 the generation was observed for both samples**, see below — records it in
 ``vcpu_independent_gens``, meaning one digest covers every size of that
 generation;
* if they **differ**, the generation is vCPU-sensitive and the bake keeps
 walking, storing one digest per tier in ``measurements[]`` (each ``variant``
 carries its ``vcpu``, ``cpu_gen``, and ``cpu_gen_source``).

### The CPU generation is read from the VM, not from the instance type

The generation cannot be inferred from the instance type on Azure.
``Standard_DCxas_v5`` is scheduled on Milan **or** Genoa hosts, so a label
derived from the ``v5``/``v6`` suffix is a guess — and a live
``Standard_DC2as_v5`` validated its VCEK against the **Genoa** chain and had its
firmware SVN checked as Genoa-class, while the suffix says Milan.

That is worse than a cosmetic mislabel, because the digest depends on the host
firmware. Two probes of the *same* instance type can legitimately return
different digests, and a bake that groups them by an inferred generation records
that difference as a **vCPU-tier** difference instead. The visible symptom is
bakes of the same platform disagreeing with each other: two concluding that
``DC2as_v5`` and ``DC4as_v5`` share a digest and are therefore vCPU-independent,
a third recording two different digests for the same pair.

So the measuring VM reports its own CPU model — one extra line in the same SSH
command, no extra VM and no extra cost — and each variant records:

| Field | Meaning |
|---|---|
| ``cpu_model`` | verbatim ``model name`` from the VM's ``/proc/cpuinfo`` |
| ``cpu_gen`` | the generation, observed where possible |
| ``cpu_gen_source`` | ``observed`` (read off the CPU) or ``instance_type`` (inferred) |

An unrecognised model yields **no** generation rather than a default, so a
guessed label is never indistinguishable from a measured one. This is also why
``vcpu_independent_gens`` is only written when every sample in the group was
observed: two equal digests under two guessed labels are equally consistent with
both probes having landed on the same host generation, which does not establish
independence from the vCPU tier. AWS and GCP report a distinct digest for every
vCPU tier, so independence is the surprising claim and needs the evidence.

Registry entries written before a bake reported ``cpu_model`` carry no
``cpu_gen_source``; treat their ``cpu_gen`` as inferred, and re-bake to get an
observed one.

#### The Azure ``_v5``/``_v6`` suffix is not a second axis — measured

An open question here was whether ``_v5``-on-Genoa and ``_v6``-on-Genoa produce
the same launch digest. If they differed, the launch measurement would depend on
the SKU family's firmware and not only on the CPU generation, and a deploy gate
on the suffix would be load-bearing.

With ``standardDCasv6Family`` quota granted, a bake
settled it: ``Standard_DC2as_v5``, ``Standard_DC4as_v5`` and
``Standard_DC4as_v6`` all produced the **same digest**, with ``cpu_gen``
observed as ``genoa`` for each. The determinant is the host CPU generation —
precisely the thing an Azure instance type cannot select — and not the version
suffix.

A refusal keyed on the suffix was written, measured against, and then
**removed**, because it rejected deploys that work. ``shape_series`` survives
only to warn about an uncaptured series. vCPU count still refuses, because
SEV-SNP measures one VMSA per vCPU and that genuinely changes the digest. The
reasoning is preserved in ``tests/core/test_azure_sku_series_gate.py``, whose
assertions were inverted on this evidence.

Each generation has its own firmware/microcode digest, so all are kept in the
allowlist. Deploy, BYOK, and the client verifier accept **any** entry.

### What the deploy can and cannot check before spending money

A deploy whose **vCPU tier** was never captured is rejected up front, with a hint
to pick a captured shape, re-bake with a wider `TEE_CRAFTER_SNP_CAPTURE_VCPUS`,
or pin that shape with `internal pin-measurement --instance-type`.

The **generation** is different, and the difference follows from the section
above. Where the instance type determines the generation, it is checked the same
way — on `snp-aws` `m6a` is Milan and `m7a` is Genoa, different hardware
families; on `snp-gcp` both the bake and the deploy pin `min_cpu_platform`, which
is what makes it determined.

Where it does not — Azure, where `DCas_v5` has been seen on two generations —
there is nothing to check against. The stored generation was read off a booted
CPU and the deploy's is inferred from the SKU, so comparing them refuses images
that are fine. On those platforms the pre-deploy gate matches on vCPU alone.

That leaves a real gap and the deploy names it rather than hiding it: when the
bake captured fewer generations than the platform can schedule, the deploy warns
that it is a coin flip. Land on the captured generation and it works; land on the
other and attestation **fails closed** with a measurement mismatch — safe, but
indistinguishable from a broken image unless you were told. The fix is a re-bake
until capture reports both generations, never a hand-pinned second digest: a
value nobody measured is not evidence.

Clouds that share one SKU name across generations (GCP N2D) capture the default
generation (Milan). ``gpu-cc-azure`` (SNP H100, Genoa) captures on its single
shape ``Standard_NCC40ads_H100_v5``.

**TDX** ``MRTD`` is vCPU-independent — one capture covers every supported size,
so the validator accepts the whole DCes/ECes (Azure) or C3 (GCP) family.
``gpu-cc-gcp`` (TDX H100) captures on a cheap ``c3-standard-4`` VM.

**gpu-cc-aws** is NitroTPM (no SEV-SNP): its measured-boot PCR digest is
self-pinned at runtime (or pinned with `internal pin-measurement`), not read
via the SEV-SNP bake reader, so it is not auto-captured.

**Nitro (`PCR0`) and SGX (`MRENCLAVE`)** are build-time deterministic — the
builder derives and pins them into the verifier client directly — so they are
not captured from a booted instance.

Capture is **best-effort**: it never fails the bake. If it cannot read the
measurement (capacity, kernel, networking), it prints a warning and leaves the
image unpinned; the downstream fail-closed gate then engages until the image is
pinned.

## Comparing bakes: is the digest disk-independent here?

On `snp-azure`, two bakes built from materially different disks produce the
**same** launch measurement. That is correct AMD SEV-SNP behaviour — the launch
digest covers initial guest memory (firmware, boot configuration, one VMSA per
vCPU), not the OS disk — and the workload is bound separately, by the container
digest inside `report_data`.

The important word is *here*. `snp-aws` and `snp-gcp` boot through different
firmware, so the result has to be re-established per platform rather than
assumed. The experiment is: bake, change something that lands on disk, bake
again, then compare.

```
tee-crafter internal compare-measurements --tee-platform snp-aws
```

It reads only what the bake already wrote to the registry, so it costs nothing.
The comparison is deliberately narrow, because doing it by hand is what produced
the disagreeing `snp-azure` entries described above:

* only the **same shape** is compared — same generation, same vCPU count.
 Different shapes are expected to differ and say nothing about the disk;
* only a generation that was **observed** counts. An inferred label is reported
 but never compared, since two variants labelled `milan` from the SKU may have
 run on different hosts;
* platforms whose digest does not vary by shape at all — TDX `MRTD`, Nitro
 `PCR0`, SGX `MRENCLAVE` — are compared on their single digest. The SEV-SNP
 platforms are explicitly excluded from that shortcut.

Verdicts are `disk_independent`, `disk_dependent`, `contradictory` (some shapes
agreed and others did not — a real signal, not a tie to break) and
`insufficient_data`. The last is the normal state before the experiment has been
run and is not a failure.

Two bakes of the same platform always differ on disk, so the precondition is met
by construction: every setup script ends by writing a timestamped marker to
`/etc/tee_crafter/baked_<platform>`. What the command cannot tell you is *how
much* they differ — a marker line is a smaller change than a package upgrade.

### What has been measured

Results from real bakes, recorded here because the registry ships only the
current image per platform and so cannot reproduce a two-bake comparison:

| Platform | Bakes compared | Result |
|---|---|---|
| `snp-aws` | `ami-0dc3a149b36b33fff` vs `ami-0a6e51a20a2d3ed81` | **Identical at all five captured vCPU tiers** (2/4/8/16/32) |
| `tdx-azure` | `2026.0822.075741` vs `2026.0823.065615` | **Identical** `MRTD` `a2e61f13…` |
| `snp-gcp` | three bakes | bakes 1 and 3 **identical** at both shared tiers; bake 2 differed at every tier |

So the property holds on AWS SEV-SNP and Azure TDX, and on GCP for two of three
bakes. The GCP outlier is why the comparison reports a *partition* of images per
digest rather than a set of digests: two bakes three days apart and in different
zones agreeing exactly, with a third disagreeing, is not "a re-bake changes the
measurement" — if it were, the two that agree could not have.

### On GCP a pinned digest can go stale without the image changing

The outlier was settled by re-measuring it. The **same image**
(`tee-crafter-snp-gcp-20260823-212601`), booted again a day later on the same
machine type with the same `min_cpu_platform`, produced
`2d24cf9624ee36449e50…` — the digest the *other two* bakes produced, not the
`0e017d2fba7c…` recorded for it at bake time.

One image, identical disk contents, two different launch measurements depending
on when it was booted. That isolates the variable completely: the disk is not
what moves this digest, and the launch measurement on GCP is **not stable over
time**. The measuring VM reported `AMD EPYC 7B13` (Milan) on both occasions, so
this is not a generation change — it is host firmware or microcode underneath a
single generation.

The operational consequence matters more than the taxonomy. A correctly pinned
`snp-gcp` image can begin failing attestation with a measurement mismatch
**because Google updated host firmware**, with nothing about the image or the
deploy having changed. On that platform, read a mismatch as "re-capture and
compare" before "the image is wrong": re-bake or re-measure, and if the new
digest is stable across two probes, pin it. This is the one case where a
measurement mismatch is expected maintenance rather than a security signal —
which is also why it must never be handled by widening the allowlist blindly.

An image flagged as an outlier is reported, never silently dropped, and the
verdict is recomputed from the bakes that are mutually consistent.

## The record says which bake-time inputs produced the image

Each registry entry carries `bake_inputs_sha256`: the digest of the *rendered*
setup script for that platform, with the security profiles, systemd units and
helper scripts already substituted in. One value therefore covers every input
whose effect is baked into the image, and nothing that is not.

A deploy compares it against the current tree and warns when they differ. This
catches a failure that is otherwise invisible. `stale_image_check` compares the
CLI image against the checkout, but a VM image is baked once and reused for
weeks, so a fix to something baked in never reaches an existing image and nothing
in the deploy says so. On An `sgx-azure --batch` run died with Gramine
unable to mount its root filesystem because AppArmor denied `open("/")` — a bug
whose fix was already in the tree *and* already covered by a test, on an image
baked hours before it landed. The symptom named a Gramine mount, so it read as a
fresh regression in the enclave manifest.

The distinction worth remembering: `templates/common/*.py` and the Terraform
templates are re-rendered and re-uploaded on **every** deploy, so they cannot go
stale this way. Security profiles, systemd units and setup scripts run **once**,
at bake.

It is a warning, not a block — an older image is often the pinned baseline you
meant to deploy — and records written before this existed carry no digest and stay
silent, because unknown is not stale.

## Manual / portable pin (any cloud + TEE)

For an image left unpinned (capture warned, an air-gapped read, or Nitro/SGX),
record the measurement explicitly — `deploy` then treats it exactly like a
bake-time capture:

```
tee-crafter internal pin-measurement \
  --tee-platform tdx-gcp \
  --image-id projects/<p>/global/images/<name> \
  --measurement <hex MRTD>
```

The measurement is the hex launch digest (SNP `MEASUREMENT` / TDX `MRTD` /
Nitro `PCR0` = 96 hex; SGX `MRENCLAVE` = 64 hex). `source` is recorded as
`manual`.

**`manual` means unverified, and the command validates nothing beyond the
hex.** It cannot: the value arrives on the command line, so there is no way to
check that it was read on this platform, from this image, or from a TEE at all.
A `manual` entry is worth exactly as much as the process that produced it, and
`source` is recorded precisely so a reader can tell the two apart —
`bake-ami` entries came from a booted instance's own firmware. When auditing a
registry, treat every `manual` entry as a claim to be re-derived rather than as
evidence.

To add a single SNP vCPU tier to an already-captured allowlist, pass
`--instance-type` (its vCPU count is parsed and recorded so deploy accepts that
size); the pin **merges** into the existing allowlist by default
(`--replace` to overwrite):

```
tee-crafter internal pin-measurement \
  --tee-platform snp-aws --image-id ami-0123… \
  --instance-type m6a.16xlarge --measurement <hex MEASUREMENT>
```

## Auto-pin (deploy time)

`deploy` resolves the requested image id (`--ami-id` / pinned `.env`) to a
registry record and feeds the measurement allowlist into three fail-closed
consumers:

1. **Client verifier** — the rendered `client.py` receives
 ``EXPECTED_MEASUREMENTS`` (all bake-time digests) instead of the
 ``"unknown"`` trust-on-first-use placeholder, so the post-deploy
 attestation check accepts any vCPU-tier variant of the vetted image.
2. **BYOK key-release policy** — ``allowed_measurement_sha256`` is set to
 ``SHA-256(measurement)`` for **each** pinned digest (matching the in-guest
 ``AttestationProvider``), so the customer key is only released to that
 image.
3. **Sealed-``.env` release** — uses the same BYOK orchestrator/allowlist.

### Fail-closed without a pin

If sealed `--secrets-env` or BYOK is requested for a **CVM** image that has no
registry entry, `deploy` aborts with a hard error:

```
No pinned measurement for <image> — sealed/BYOK release is fail-closed.
Re-bake with `tee-crafter internal bake-ami` (capture is automatic), pin it
with `tee-crafter internal pin-measurement`, or set
TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1 for dev/prototyping only.
```

Set `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1` to proceed unpinned (dev only —
key release is then not bound to a vetted measurement).

## Related

- [byok.md](byok.md) — BYOK + sealed `.env` delivery and the fail-closed gates.
- [security.md](security.md) — attestation trust model.
- Code: `core/measurements/registry.py`, `core/measurements/capture.py`,
 `cli/commands/deploy/measurement_pin.py`,
 `cli/commands/baking/common/measurement_capture.py`,
 `cli/commands/pin_measurement.py`.
