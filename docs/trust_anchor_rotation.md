# Rotating a pinned trust anchor

Every verifier client TEE-Crafter generates is built around a hardcoded vendor
certificate. That is the point — a verifier that fetches its own trust anchor
at verify time can be pointed somewhere else. The cost is that when a vendor
rotates a certificate we pin, **already deployed clients stop verifying**, and
they stop all at once.

This page covers what is pinned, which pin is actually at risk, how to find out
before your users do, and what to do about it.

## What is pinned

All anchors live in `apps/cli/src/tee_crafter/certs/` and are copied into the
generated client at build time by `_load_trust_anchor()`
(`apps/cli/src/tee_crafter/core/builder/platforms.py`). A missing file is fatal
at build time, never skipped.

| File | Role | Expires | Risk |
|---|---|---|---|
| `intel-sgx-dcap-root.pem` | Intel SGX Root CA — anchors DCAP quotes and all PCS collateral on `sgx-azure`, `tdx-azure`, `tdx-gcp`, `gpu-cc-gcp` | 2049-12-31 | Low |
| `nitro-root.pem` | `aws.nitro-enclaves` root — anchors Nitro attestation documents | 2049-10-28 | Low |
| `amd-ark-milan.pem` | AMD ARK-Milan + SEV-VLEK-Milan (the **VLEK**-signing intermediate, which is what AWS returns) — anchors SEV-SNP on Milan | 2045-10-22 | Low |
| `amd-ask-milan.pem` | AMD ARK-Milan + SEV-Milan (the **VCEK**-signing ASK) — needed wherever a Milan host returns a VCEK rather than a VLEK, as GCP does. Loaded by `platforms._load_amd_ask_ca` | 2045-10-22 | Low |
| `amd-ark-genoa.pem` | AMD ARK-Genoa + SEV-Genoa — anchors SEV-SNP on Genoa. Already carries the ASK, which is why only Milan needs a second file | 2047-01-26 | Low |
| `nvidia-nras-intermediate.pem` | NVIDIA Attestation Service GPU Intermediate 004 — anchors the NRAS EAT token on all GPU-CC platforms | **2029-12-08** | **High — see below** |

The three AMD files are **bundles of two certificates each**, and the *Expires*
column gives the earliest expiry in the bundle — which is the date that matters,
since the chain fails when any link lapses. A quick `openssl x509 -noout
-enddate` reads only the *first* certificate in a bundle and will disagree with
this table on the AMD rows; `openssl storeutl -noout -certs <file>` shows both.

Verified against the files in this tree on 2026-08-25 with
`.github/scripts/check_pinned_anchors.py`, which enumerates every certificate in
every bundle.

## Why the NVIDIA pin is the one to watch

Four differences from every other anchor above:

1. **It is an intermediate, not a root.** Its issuer, `NVIDIA Attestation
   Service CA 001`, is not pinned anywhere in this repo. Intermediates rotate
   far more often than roots.
2. **NVIDIA's own naming says they rotate.** The subject CN is
   `NVIDIA Attestation Service GPU Intermediate 004`. There were three before
   it.
3. **It expires 2029-12-08** — about 20 years before every other anchor.
4. **It is enforced by exact DER equality, with no fallback.**
   `_verify_jwks_x5c_chain()` — present in all three GPU-CC client templates
   (`gpu_cc/gcp`, `gpu_cc/azure`, `gpu_cc/aws`) — compares `x5c[1]`
   byte-for-byte against the pinned PEM. There is no name match, no walk to a
   root, and no second accepted value. When NVIDIA serves a different
   intermediate, the comparison fails and the client refuses the connection.

That behaviour is correct — failing closed is the right choice, and a client
that accepted an unpinned intermediate would accept an attacker's. But it means
rotation is a **fleet-wide outage that starts the moment NVIDIA switches**,
affecting every client already built and shipped, not just new builds.

### What is *not* the risk

The NRAS **leaf** certificates are short-lived: as of 2026-08-20 the live JWKS
served 32 keys whose leaves expired the same day or the next. That is by design
and is why the client fetches the JWKS live on every verification rather than
pinning a key. Leaf churn is normal operation and needs no action.

## Detecting rotation before it hurts

   ```bash
# Offline: expiry report for every pinned anchor. No network, no credentials.
python3 .github/scripts/check_pinned_anchors.py

# Also poll the public NRAS JWKS and compare its intermediate to the pin.
   python3 .github/scripts/check_pinned_anchors.py --live
   ```

Exit status is non-zero when an anchor is within the warning horizon
(`--warn-days`, default 365) or when the live JWKS no longer serves the pinned
intermediate — so it drops straight into a cron job or a scheduled CI workflow.

The check reports three distinct states, and the middle one is the one worth
having:

- **`live match: YES`, one intermediate served** — nothing to do.
- **`live match: YES` plus other intermediates served** — NVIDIA is
  mid-rotation and is serving old and new in parallel. **This is the window to
  re-pin in.** Exit status is non-zero here on purpose: acting during the
  overlap turns an outage into a routine release.
- **`live match: NO`** — the pinned intermediate is gone. Every deployed
  GPU-CC client is already failing GPU attestation closed.

A JWKS that cannot be reached is reported as "pin NOT checked" and does *not*
fail the run. An unreachable endpoint is not evidence of rotation, and a check
that cries wolf on every network blip is a check people learn to ignore.

## Rotating the pin

1. **Get the new certificate from the live service**, not from a web page — the
   bytes that matter are the ones NVIDIA actually serves as `x5c[1]`:

   ```bash
   curl -sS https://nras.attestation.nvidia.com/.well-known/jwks.json \
     | python3 -c '
   import base64, json, sys
   from cryptography import x509
   from cryptography.hazmat.primitives import serialization
   keys = json.load(sys.stdin)["keys"]
   der = base64.b64decode(keys[0]["x5c"][1])
   cert = x509.load_der_x509_certificate(der)
   print(cert.subject.rfc4514_string(), cert.not_valid_after_utc, file=sys.stderr)
   print(cert.public_bytes(serialization.Encoding.PEM).decode(), end="")
   ' > apps/cli/src/tee_crafter/certs/nvidia-nras-intermediate.pem
   ```

2. **Confirm what you just wrote.** Check the subject is the expected next
   intermediate, the expiry is further out than the old one, and — importantly
   — that its issuer is still `NVIDIA Attestation Service CA 001`. A change of
   issuer is not a routine rotation and should be investigated before shipping.

   ```bash
   python3 .github/scripts/check_pinned_anchors.py --live
   ```

3. **Rebuild and redeploy every GPU-CC deployment.** The certificate is baked
   into `client.py` at build time, so an existing deployment does not pick this
   up. Affected platforms: `gpu-cc-gcp`, `gpu-cc-azure`, `gpu-cc-aws`.

4. **Run the test suite.** `tests/core/test_gpu_cc_attest.py` renders the real
   templates and will fail if the new PEM does not parse or does not substitute
   cleanly.

There is deliberately **no** environment-variable override to accept an
unpinned intermediate. Adding one would mean the fastest fix for a mid-outage
operator is to disable GPU attestation verification entirely — and that hatch
would then stay set. Rotation is a rebuild.

## Why not pin the NVIDIA root instead?

It would survive intermediate rotation, which is the whole problem above. Two
reasons it was not done:

- The JWKS carries `x5c = [leaf, intermediate]` and **stops there**. Pinning
  the root means obtaining it out of band and trusting a chain the service does
  not serve, which is a larger change than it looks.
- A root pin accepts *any* intermediate that root ever signs, including ones
  issued for unrelated NVIDIA services. The intermediate pin is a materially
  tighter statement about who signed the token.

Pinning the root, or accepting a set of intermediates with an explicit
retirement date per entry, is a reasonable future change. It is a design
decision with a real tradeoff, not an oversight — and it should be made with
the security-vs-availability call stated out loud, not by adding a fallback
because an outage was inconvenient.

## Related

- `docs/security.md` — the trust model these anchors implement.
- `docs/gpu_flow.md` — where NRAS verification sits in the GPU-CC flow.
- `.github/scripts/check_pinned_anchors.py` — the check described above.
