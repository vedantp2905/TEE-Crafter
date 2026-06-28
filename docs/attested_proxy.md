# The attested ingress proxy (persistent mode)

> How a remote client verifies it is talking to the expected code inside a real
> TEE before sending data, when running `--persistent` on a VM-class TEE.
> Part of the unified execution model — see [execution_model.md](execution_model.md).

## Why a proxy

Under the unified model the user ships a **plain Dockerfile** and never
implements attestation. For persistent (long-lived) services, attestation is
relocated into a single **platform-owned attested ingress gateway** that fronts
the user's container.

This keeps the confidential-computing guarantee intact while consolidating
attestation into **one generic proxy app per TEE family** and **one generic
client verifier**.

## Topology

```
   remote client
 │ RA-TLS (attestation embedded in served cert)
        ▼
┌─────────────────────────── TEE (VM-class) ───────────────────────────┐
│ attested ingress proxy ──plaintext──▶ user container │
│ (RA-TLS terminator) 127.0.0.1:<EXPOSE port> (unmodified) │
└───────────────────────────────────────────────────────────────────────┘
```

1. The proxy obtains a fresh TEE attestation (quote / report) and binds it into
 the TLS certificate it serves (RA-TLS).
2. The client connects, **verifies the embedded attestation** (measurement +
 expected signer, plus the binding of the evidence to this TLS session's key)
 against its pinned baseline, and only then sends application data.
3. The proxy terminates TLS and forwards plaintext to the user's container on
 `127.0.0.1:<EXPOSE port>`. The container is a normal web server; it neither
 sees nor implements attestation.

## Supported platforms

VM-class TEEs only: `nitro-aws`, `snp-aws`, `snp-azure`, `snp-gcp`,
`tdx-azure`, `tdx-gcp`, `gpu-cc-gcp`, `gpu-cc-azure`, `gpu-cc-aws`.

On `gpu-cc-aws` the proxy attests the GPU **and** the host's measured boot,
but not host memory: there is no CPU TEE on AWS GPU instances. The client
verifies a hypervisor-signed NitroTPM attestation document against the
pinned `certs/nitro-root.pem` and compares PCR4/PCR7 to bake-time values,
and refuses to connect if no document is presented unless
`TEE_CRAFTER_ALLOW_UNVERIFIED_AWS_CPU_ATTESTATION=1` is set. See
[gpu_flow.md](gpu_flow.md#cpu-attestation-on-gpu-cc-aws-measured-boot-verified-locally).

**`sgx-azure` does not support persistent mode** (it is batch-only via GSC).
`validate_run_mode` rejects `--persistent --tee-platform sgx-azure` at CLI parse
time (`cli/commands/deploy/deploy_helpers.py::validate_run_mode`, the
`tee_platform == "sgx-azure" and not batch_mode` branch at line 279).

## Service profiles configure the proxy

`--service-profile` tunes the **proxy**, not user code:

| Profile | Cert TTL | Re-attest | Max conns | Notes |
|---|---|---|---|---|
| `long-lived` | 24 h | hourly | 1 024 | What `--persistent` gets when you leave `--service-profile` at `default` |
| `short-lived` | 1 h | every 10 min | 256 | Tighter freshness |
| `streaming` | 1 h | every 10 min | 4 096 | SSE / WebSocket / gRPC server-streaming |

Values transcribed from `SERVICE_PROFILES` in
`cli/commands/deploy/service_mode.py:30-58`. The fourth choice, `default`, is
the `--batch` setting (service mode off); under `--persistent` it is silently
promoted to `long-lived` (`deploy_helpers.py::validate_run_mode:289-291`), so a
persistent deploy that omits the flag gets the **loosest** of the three profiles.

The proxy is driven by `core/service/{policy,reattest,cert_rotation}.py`:

- **policy** — declarative TTLs, re-attest interval, failure actions.
- **cert_rotation** — TTL-driven RA-TLS cert rotation with a grace period.
- **reattest** — periodic re-attestation; on failure it drains connections
 (`on-attestation-failure`).

## How a client verifies an endpoint

A single generic verifier (the client template) performs:

1. TLS handshake; extract the attestation evidence embedded in the cert.
2. Verify the evidence signature and walk the endorsement chain to a trust
 anchor **baked into the client at build time**:

 | Family | Chain | Anchor |
 |---|---|---|
 | AMD SEV-SNP (`snp-*`, `gpu-cc-azure`) | VCEK/VLEK → ASK → ARK | `certs/amd-ark-{milan,genoa}.pem`. Every link's signature is verified (RSASSA-PSS or ECDSA), and the chain's own ARK must match the SHA-256 of a baked-in ARK's SubjectPublicKeyInfo — the key, not the subject name, so a self-signed cert calling itself `CN=ARK-Milan` cannot pass (`templates/snp/aws/client.template.py`, `_trusted_ark_spki_digests` at line 288 and the `_spki_sha256_of_cert(ark) not in trusted` gate at line 337) |
 | Intel TDX (`tdx-*`) and SGX (`sgx-azure`) | PCK leaf → intermediates → root | `certs/intel-sgx-dcap-root.pem`. The client additionally asserts the anchor's subject CN equals `Intel SGX Root CA` (`_EXPECTED_ROOT_CA_CN`, `templates/tdx/azure/client.template.py:22`, checked at line 384). The shipped anchor is self-signed (subject == issuer), ECDSA P-256, valid to 2049-12-31 |
 | AWS Nitro (`nitro-aws`) | COSE_Sign1 cert chain | `certs/nitro-root.pem` |
 | NVIDIA (`gpu-cc-*`) | NRAS EAT JWT | `certs/nvidia-nras-intermediate.pem` — an *intermediate* (`CN=NVIDIA Attestation Service GPU Intermediate 004`, issued by `CN=NVIDIA Attestation Service CA 001`), pinned by exact DER comparison rather than chain-walked. It expires **2029-12-08**; the pin must be refreshed before then |

3. Compare the measurement (PCRs / MRTD / MRENCLAVE+MRSIGNER) to the pinned
 baseline. Unpinned measurements are fatal unless
 `TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT=1`.
4. Only on success, send the request body.

### Freshness: channel binding, not a client nonce

Step 4 is **not** "check a client nonce to defeat replay", and the distinction
matters when you are reasoning about replay.

On every RA-TLS platform the evidence's `report_data` is bound to a hash of the
**server's ephemeral ECDH public key**, and the client checks that binding
(`report_data[:32] != SHA-256(SPKI)` is fatal). That is *channel* binding: it
proves the attested TEE holds the private key for this TLS session, so evidence
cannot be lifted onto a different endpoint. It is **not** a freshness check —
nothing the client chooses goes into the quote, so a `report_data` value stays
valid for as long as the server keeps that ECDH key.

Where each platform stands:

| Platform | Client-chosen nonce in the evidence? | What is actually checked |
   |---|---|---|
| `nitro-aws` | **Yes** | Not RA-TLS. The client generates a fresh 32-byte `client_nonce` (`templates/nitro/client.template.py:267`), sends it with the attestation request, and `verify_attestation` exits 1 when `doc['nonce'] != client_nonce` (lines 106–117). This is genuine client-nonce anti-replay. |
| `snp-aws`, `snp-azure`, `snp-gcp`, `gpu-cc-*` | No | The client generates a `ratls_nonce` but never transmits it. It is round-tripped into the `ATTESTATION_REPORT` audit line for correlation only — the templates say so in their own docstrings (`templates/snp/aws/client.template.py:496-502`, `snp/azure:540-543`, `snp/gcp:435-438`). Channel binding to the ECDH SPKI is checked at `snp/aws:758`. |
| `sgx-azure` | No | Same as SNP: `ratls_nonce` is informational (`templates/sgx/client.template.py:398-412`); channel binding checked at line 619. |
| `tdx-azure`, `tdx-gcp` | **No — and no nonce is generated at all** | The TDX clients have no `ratls_nonce`. Freshness rests entirely on channel binding plus the TDX quote's own structure; the check is `report_data[:32] != pub_key_hash` → fatal (`templates/tdx/azure/client.template.py:885`, `tdx/gcp:735`). |

So: **replay defence is client-nonce-based only on `nitro-aws`.** Everywhere else
it is channel binding, and TDX has the least of it. If you need per-request
freshness on an RA-TLS platform today, get it from the re-attestation interval
(`--service-profile short-lived` re-attests every 10 minutes) rather than from
the attestation evidence itself.

## Audit / continuous attestation

For persistent VM-class runs:

- `ATT` verifies the boot attestation document **and** the proxy's live RA-TLS
 re-attestation.
- `SIEM` continuous-attestation export streams from the proxy / host re-attest
 loop.
- The signed audit ledger (`audit/audit_evidence.json`) carries the `ATT` and
 `CT` rows for boot attestation and continuous re-attestation.

For **SGX batch**, assurance is deploy-time attestation + the audit bundle only
(no proxy, no live re-attest).
