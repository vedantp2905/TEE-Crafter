# Running verification on real hardware

Live runs cost money. Every rule below was bought with a wasted one, and each was
learned by believing something a test said.

## 1. "Verified only by unit test" means "not yet known to work"

Tests in this repository have repeatedly been green while the thing they covered
was unreachable: the Microsoft Azure Attestation verifier passed 27 tests without
ever being called, because a build-time format gate stood in front of it, and
`--byok azure-skr` passed 60 tests while Click rejected the flag at parse time. A
test that exercises an internal proves the internal.

The sharper version of the same trap: a verifier-side check can be correct, fully
tested, and still inert because the server never presents the input it checks
for. When adding a check to a client, prove the server produces that input — on
hardware, not in a fixture.

## 2. Local edits do nothing until `make docker-build-cli`

The CLI image carries its own copy of `src/` (`apps/cli/Dockerfile` does
`COPY src/ src/`, then installs from `/opt/tee-crafter`); `/workspace` is only
the output mount and nothing imports from it. This catches people out because
**templates, setup scripts and Terraform are read at run time**, so they look
like they should not need a rebuild. Two live SEV-SNP runs once "verified" a
change that was not in the image — and both passed, because the old code was
self-consistent on both sides of the channel, which is indistinguishable from
success.

So before writing "verified on hardware": confirm the stale-image guard
(`cli/stale_image_check.py`) stayed silent, and grep the *deployed* artifact under
`builds/<id>/` for the change. The second check takes seconds. The same applies to
a build directory reused across a code change — the rendered `app_*.py` and
`client_*.py` inside it are snapshots, so a resumed deploy runs the snapshot, not
the edit.

**A baked VM image is the version of this trap that a rebuild does not fix.**
Security profiles, systemd units and setup scripts are baked in once and then
reused for weeks, so a fix to one of them never reaches an existing image. On
An `sgx-azure --batch` run died with Gramine unable to mount its root
filesystem because AppArmor denied `open("/")` — a bug whose fix was already in
the tree *and* already covered by a test, on an image baked hours earlier. Each
registry record now carries a `bake_inputs_sha256` and the deploy warns when it
no longer matches; see [measurements.md](measurements.md).

## 3. Log the whole failure on any path that has already decided to fail

A `tdx-azure` run reached MAA, got `InvalidParameter`, and this project's own
message truncated the reply to 40 characters — cutting off the field that named
the bad parameter — on a VM the failure path then destroyed. A diagnostic that
elides the answer is worse than none, because it looks like it worked.

## 4. Confirm the spend actually stopped

Interrupting a deploy does not cancel what the cloud has already been asked to
build. An `apply` killed in its first minute still produced a running H100 half an
hour later, and the resource-group delete issued during that window was
abandoned — see [teardown.md](teardown.md#interrupted-applies). After any
interruption, destroy explicitly and then check:

```bash
az vm list -d --query "[].{n:name,s:powerState}" -o tsv
az network bastion list --query "length(@)" -o tsv # bastions bill without a VM
```

---

[pending.md](pending.md) is the list of what has not been verified yet.
