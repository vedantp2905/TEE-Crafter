# Customer-managed keys (BYOK)

TEE-Crafter implements **bring-your-own-key**: the data-encryption key (DEK)
that protects your workload's secrets is wrapped by a key you own, in your
cloud account, and unwrapped inside the TEE.

**Read the gating table below before assuming this is attestation-gated.** Out
of the box *no* provider × platform combination is gated by the key custodian:
every row starts at `iam-scoped`, where the custodian checks *identity*, not
*attestation*, and the measurement allowlist TEE-Crafter applies is advisory
rather than enforcing. Three of them can be *upgraded* to `kms-enforced` by
supplying the right policy conditions, and the table says which and how.

## What actually stands between an attacker and your key

The question that matters is: *if an attacker skipped TEE-Crafter's Python
entirely and called the provider API directly with the credentials the instance
already holds, would the provider still refuse?*

The answer is recorded as data in
[`core/keys/gating.py`](../apps/cli/src/tee_crafter/core/keys/gating.py), keyed
by `(provider, tee_platform)`, so the release path, the audit ledger and this
document all read the same value. The three verdicts are:

| Verdict | Meaning |
|---|---|
| `kms-enforced` | **Yes, the provider refuses.** It evaluates a hardware-attestation claim naming *this* workload. |
| `iam-scoped` | **No.** The provider only checks identity — and root on the CVM can read those credentials out of IMDS. Our measurement allowlist still runs, but in-process on the untrusted host, so it is **advisory**. |
| `none` | We cannot assert anything (customer-owned HSM policy, or a dev-only local file). |

### Per-provider gating

| Provider | Platform | Default | Upgradeable to `kms-enforced`? |
|---|---|---|---|
| `aws-kms` | `nitro-aws` | `iam-scoped` | **Yes — this is the reference implementation.** Supply `--pcrs-json` when creating the key so the policy carries `kms:RecipientAttestation:PCR{0,1,2}` equality conditions. KMS then evaluates the Nitro attestation document and re-encrypts to the enclave's attested public key. Without it the policy degrades to "*some* enclave in this account". |
| `aws-kms` | `snp-aws`, `gpu-cc-aws` | `iam-scoped` | **Yes, via measured boot.** `kms:RecipientAttestation:NitroTPMPCR{4,7,12}` applies to ordinary EC2 instances, not only Nitro Enclaves. Verified end-to-end on hardware. Binds **measured boot** (PCR4 boot-manager code, PCR7 Secure Boot policy), not the SEV-SNP launch measurement — AWS publishes no condition key for that, so this gate is weaker than `nitro-aws`'s while still being attestation rather than identity. Requires: AMI registered with `TpmSupport=v2.0`, and explicit **`Deny`** statements in the policy — a conditional `Allow` alone is not a gate. See [Known limitations](#known-limitations). |
| `azure-kv` | `snp-azure`, `tdx-azure`, `gpu-cc-azure` | `iam-scoped` | Yes. Secure Key Release is real, but the shipped policy pins only `x-ms-attestation-type` against the *shared public* MAA authorities — which any SEV-SNP/TDX CVM in any Azure tenant satisfies. Bind `x-ms-sevsnpvm-launchmeasurement` (and ideally `-hostdata`) to name your workload. |
| `azure-kv` | `sgx-azure` | `iam-scoped` | No. SGX is served the combined SNP+TDX release policy, whose `x-ms-attestation-type` an SGX workload does not present. Expect SKR itself to fail; this combination is not wired end to end. |
| `azure-skr` | `tdx-azure`, `snp-azure`, `gpu-cc-azure` | `iam-scoped` | Yes, and this is the only Azure choice that yields a usable DEK. `azure-kv` cannot finish on a CVM: Key Vault wraps the released key to `x-ms-runtime.keys[kid=TpmEphemeralEncryptionKey]`, whose private half is sealed to the vTPM, so no Python process can unwrap it. `azure-skr` delegates release *and* unwrap to Microsoft's `AzureAttestSKR`, which holds that key. Requires `TEE_CRAFTER_MAA_ENDPOINT`, and the deploy refuses without it rather than letting the VM discover it. **Setup steps:** [azure_setup.md](azure_setup.md#secure-key-release-on-azure----byok-azure-skr). |
| `azure-skr` | `sgx-azure` and all non-Azure platforms | — | Refused at build time. `TpmEphemeralEncryptionKey` is a paravisor artefact; an SGX enclave has no vTPM-sealed KEK, and AWS/GCP have their own providers. |
| `gcp-kms` | `snp-gcp`, `tdx-gcp`, `gpu-cc-gcp` | `iam-scoped` | Yes. Cloud KMS AAD carries no policy semantics — it is a plain AEAD binding, not an authorisation input. Add a Confidential Space workload-identity attribute condition (e.g. on `assertion.submods.container.image_digest`) to the key's IAM binding. |
| `external-hsm` | any | `none` | N/A. The decision is delegated to your HSM gateway; TEE-Crafter forwards the raw attestation blob and cannot assert what the gateway does with it. The unwrap algorithm is pinned client-side so a hostile gateway cannot downgrade it. |

**If you need attestation-gated key release today, there are two proven
routes on AWS.** `nitro-aws` with `--pcrs-json` binds a Nitro Enclave's
PCR0/1/2 and is the stronger of the two. `snp-aws` and `gpu-cc-aws` bind
**measured boot** via `kms:RecipientAttestation:NitroTPMPCR{4,7}` — proven on
hardware, and weaker in a specific way an auditor should know:
it attests the boot chain, not the SEV-SNP launch measurement, for which AWS
still publishes no condition key. Everything else in the table is a
defence-in-depth arrangement whose real gate is IAM until you add the
provider-side conditions the last column names, and should be described that
way.

### The measurement allowlist is not a gate where the provider does not enforce

`allowed_measurement_sha256` is checked by TEE-Crafter's own code, in-process,
against a report it received — on the host, which is the thing you are trying to
defend against. Where the row above says `iam-scoped`, that check is
`advisory`; the code labels it exactly that way (`ProviderGating.measurement_gate`).
Do not present it to an auditor as an enforcing control.

The rows above are a transcription of `_TABLE` in `core/keys/gating.py`
(15 `(provider, platform)` entries, collapsed here by shared verdict) — with one
exception worth knowing before you diff them. **`azure-skr` is a CLI-level
choice, not a `KeyProvider`.** The enum has five members (`aws_kms`, `azure_kv`,
`gcp_kms`, `external_hsm`, `local_file`), so `--byok azure-skr` resolves to the
`azure_kv` rows for gating purposes; its own rows above describe CLI behaviour
and will not appear in the dump below. Dump the
table and diff it against this section if providers or platforms are added:

```bash
python3 -c "
import sys; sys.path.insert(0, 'apps/cli/src')
from tee_crafter.core.keys.gating import _TABLE
for (prov, plat), row in sorted(_TABLE.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
    up = row.upgraded.gating.value if row.upgraded else '-'
    print(f'{prov.value:14} {plat or \"(any)\":14} {row.gating.value:12} by={row.enforced_by:18} upgrade_when={row.upgrade_when} -> {up}')
"
```

`local-file` also appears in that table (verdict `none`, enforced by `nobody`)
but is not a `--byok` choice — the CLI accepts only `aws-kms`, `azure-kv`,
`azure-skr`, `gcp-kms`, `external-hsm` and `none`.

## Known limitations

- **Sealed `.env` does not work on `azure-kv`, and that is now a routing
 problem rather than a dead end.** The Azure Key Vault adapter returns
 `plaintext=None` because the key-encryption key Key Vault wraps to is sealed
 to the vTPM — see `core/keys/azure_kv.py`. Use **`azure-skr`** on Azure CVMs,
 which delegates the unwrap to `AzureAttestSKR` and does produce a DEK.
 `azure-kv` remains correct only where you genuinely hold the recipient private
 key (an external HSM flow, or tests), and it fails closed rather than quietly
 producing nothing.

 > **`azure-skr` has completed a release against a real vault** — on a live
 > `snp-azure` CVM. `AzureAttestSKR` attested to MAA, Key Vault
 > evaluated the key's measurement-bound release policy, released the
 > exportable RSA-3072 key and unwrapped the DEK; the returned bytes hashed to
 > `564dcc0261e9082b9d8369276a95f9ab…`, identical to the SHA-256 of the 32-byte
 > DEK that had been wrapped. Exit codes alone would only have shown that
 > *something* was released, so the hash equality is the result.
 >
 > **The tool's wire contract is asymmetric: base64 in, raw binary out.** The
 > wrapped DEK goes in as base64 on argv, but stdout is the released key bytes
 > verbatim — no trailing newline, no encoding — with the library's diagnostics
 > on stderr. Assuming symmetry corrupts the key silently: decoding stdout as
 > UTF-8 with `errors="replace"` mangles roughly half the bytes of a random
 > key, and a base64 parser then rejects what is left. If you drive the tool
 > yourself, read its stdout as **bytes**.
 >
 > **The automated in-guest release also works on `snp-azure`**, not just the
 > tool driven by hand: `tee-crafter-secrets.service` performed the release and
 > the workload started behind it. Note the ordering that makes this work — the
 > oneshot reads the wrapped DEK from a tmpfs `byok.env`, so the deploy puts
 > that file in place *before* starting any unit that `Requires=` the oneshot.
 >
 > Not yet exercised on hardware: `tdx-azure` and `gpu-cc-azure` releases (same
 > code path, different platform).

- **`snp-aws` measurement-gated release works, and five things about it are
 counter-intuitive enough to be worth stating.** All measured on a live
 instance: a real 5163-byte NitroTPM attestation document,
 `kms:Decrypt` returning a 477-byte `CiphertextForRecipient` and no
 `Plaintext`, and the production CMS parser recovering the DEK.

 > **A conditional `Allow` in a KMS key policy gates nothing on its own.**
 > This is the important one. KMS authorizes a request if *any* statement
 > allows it, so an `Allow` carrying
 > `kms:RecipientAttestation:NitroTPMPCR4` conditions is bypassed entirely by
 > account-root delegation plus an identity-based `kms:Decrypt` on the caller.
 > Both negative cases — no attestation document, and a deliberately wrong
 > PCR4 — *succeeded* before this was fixed. Explicit **`Deny`** is the only
 > thing that closes it, and because condition keys inside one block are
 > AND-ed together, each pinned PCR needs its own `Deny` statement. After the
 > fix: correct PCRs → success, no document → `AccessDenied`, wrong PCR4 →
 > `AccessDenied`.
 >
 > **The PCR bank is SHA-384, not SHA-256.** The document reports
 > `digest: SHA384` and its values are 48 bytes. A policy written with
 > SHA-256 values denies the *legitimate* caller.
 > `core/keys/nitrotpm.py` now rejects a 32-byte value rather than pinning it.
 >
 > **Documents expire after five minutes.** KMS answers
 > `ValidationException: exceeded the five-minute age limit`. Any flow that
 > generates a document and then does slow work before calling KMS fails.
 >
 > **PCR4 and PCR7 survive a reboot.** Both were byte-identical across a real
 > reboot (`uptime` confirming `up 0 minutes`), and a second decrypt succeeded
 > against the unchanged key policy. This is what makes pinning viable rather
 > than an outage waiting to happen — AWS's own guidance assumes `erofs` plus
 > `dm-verity`, which this image does not use.
 >
 > **`RegisterImage` is the only API that can set `TpmSupport`**, and it
 > silently drops `UefiData` unless you pass it explicitly — which disables
 > Secure Boot on the resulting AMI and so changes PCR7. `CreateImage` cannot
 > set `TpmSupport` at all.

- **The attestation document can also be verified locally, without KMS.** Its
 `cabundle` roots at `CN=aws.nitro-enclaves` — byte-for-byte
 `certs/nitro-root.pem`, the certificate already pinned for `nitro-aws`
 (`sha256=641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`).
 Verified against a real document: a five-certificate chain (TPM
 leaf → instance → zonal → region → root) with every signature valid, and the
 COSE_Sign1 signature verifying under the leaf's P-384 key.

 This corrects a claim that had propagated to four places in the tree — that
 the Nitro Enclaves root "endorses a different key hierarchy", so a NitroTPM
 document could only be checked by delegating to AWS KMS. It was wrong, and it
 was the stated reason `gpu-cc-aws` reported its CPU evidence as
 `SELF-REPORTED, UNVERIFIED`. KMS remains the verifier for *key release*,
 where the condition keys do the work; it is not required to verify a
 document. See `verify_document_locally` in `core/keys/nitrotpm.py`.

Every BYOK-relevant check (provider resolved, unwrap mode, allowlist
size, key_id tail, BYOK env tmpfs relocation, KMS policy diff) is
emitted as a verdict in the audit-evidence ledger. See
[docs/audit_matrix.md](audit_matrix.md) for the catalogue and
[docs/cli_reference.md](cli_reference.md) for the `--required-checks`
gate.

The orchestration code lives in
[`tee_crafter.core.keys.release`](../apps/cli/src/tee_crafter/core/keys/release.py),
the per-cloud adapters live next to it
([`aws_kms.py`](../apps/cli/src/tee_crafter/core/keys/aws_kms.py),
[`azure_kv.py`](../apps/cli/src/tee_crafter/core/keys/azure_kv.py),
[`gcp_kms.py`](../apps/cli/src/tee_crafter/core/keys/gcp_kms.py),
[`external_hsm.py`](../apps/cli/src/tee_crafter/core/keys/external_hsm.py)).

## Supported providers

| Provider | Wrap algorithm | Attestation primitive the custodian *can* consume |
|-------------------|-------------------------------------------|---------------------------------------|
| `aws-kms` | AWS Nitro Enclaves recipient (`Decrypt`) | Nitro PCRs (PCR0/1/2) in `kms:RecipientAttestation:*` conditions — **only on `nitro-aws`, only with `--pcrs-json`**. |
| `azure-kv` | Azure Key Vault `release` (SKR) | MAA token claims — enforcing only once the policy pins `x-ms-sevsnpvm-launchmeasurement`. |
| `gcp-kms` | Cloud KMS + Confidential Space | Confidential-Space attestation token — enforcing only via an IAM attribute condition. |
| `external-hsm` | RSA-OAEP wrapped DEK | Bearer token + whatever your gateway checks. |

Three of the four adapters return raw key material (`bytes`) inside the TEE;
`azure-kv` returns only the wrapped blob (see Known limitations above).
The orchestrator never logs the key; it only logs the policy decision
and a SHA-256 prefix of the resulting DEK for audit.

## CLI surface

The public CLI is intentionally small:

```
--byok {none|aws-kms|azure-kv|azure-skr|gcp-kms|external-hsm}
--byok-config <path/to/policy.json> (required when --byok != none)
```

Equivalent `.env` keys:

```
TEE_CRAFTER_BYOK=aws-kms
TEE_CRAFTER_BYOK_CONFIG=/path/to/policy.json
```

Everything provider-specific (`key_id`, `region`, `unwrap`,
`encryption_context`, `policy.allowed_measurement_sha256`, …) lives in
the JSON policy file. The CLI does not expose per-field flags: the earlier
`--byok-key-id`, `--byok-region`, `--byok-allowed-measurement` and friends have
been removed from the public CLI.

## Policy schema

```json
{
  "provider": "aws-kms",
  "key_id": "arn:aws:kms:us-east-2:123456789012:key/abc-123",
  "region": "us-east-2",
  "label": "acme-prod",
  "unwrap": "aws_nitro_recipient",

  "encryption_context": {
    "tenant": "acme",
    "env": "prod"
  },

  "hsm_endpoint": "https://hsm.example.com",
  "hsm_bearer_token": "${HSM_BEARER_TOKEN}",

  "policy": {
    "max_attestation_age_seconds": 300,
    "allowed_measurement_sha256": ["9b2c...64hex"],
    "require_encryption_context_keys": ["tenant", "env"],
    "require_signed_audit": true
  },

  "dek_path": "/run/tee_crafter/byok_dek.bin",

  "extra": {"my_key": "my_value"}
}
```

| Field | Notes |
|--------------------------------------------------------|----------------------------------------------------------------------------------------|
| `provider` | Must match `--byok` on the command line. |
| `key_id` | KMS key ARN / Key Vault key URL / KMS resource name / HSM key id. |
| `region` | KMS region (`aws-kms`, `gcp-kms`). Required for those. |
| `label` | Audit-only friendly name. |
| `unwrap` | One of `direct_bytes`, `aws_nitro_recipient`, `aws_nitrotpm_recipient`, `rsa_oaep_sha256`. `aws_nitrotpm_recipient` is the measured-boot-gated mode on `snp-aws` / `gpu-cc-aws`: it makes the release path attach a NitroTPM attestation document, and `deploy` **refuses** if no NitroTPM PCRs are recorded for the image rather than silently degrading to identity-gated. |
| `encryption_context` | Object of `{key:value}` pairs forwarded to KMS where the provider supports it. |
| `hsm_endpoint` / `hsm_bearer_token` | `external-hsm` only. |
| `policy.max_attestation_age_seconds` | Default 300. Stale attestations are rejected. |
| `policy.allowed_measurement_sha256` | List of 64-hex digests. Whitelist of acceptable enclave measurements. |
| `policy.require_encryption_context_keys` | Policy fails closed if the runtime hasn't supplied each named key. |
| `policy.require_signed_audit` | Default `true`. Audit decision is signed before being chained into the SIEM stream. |
| `dek_path` | Where the bootstrap drops the released DEK (tmpfs-backed, `0600`). |

Validation lives in
[`tee_crafter.cli.commands.deploy.byok_mode.ByokConfig.validate`](../apps/cli/src/tee_crafter/cli/commands/deploy/byok_mode.py).

### BYOK-SEC-1 — Staged files on disk vs tmpfs

`write_byok_config` emits three files into `<build_dir>/byok/`
(mirrors SIEM’s split):

| File | Contents | After deploy |
|------|----------|--------------|
| `byok/byok.json` | Manifest with **redacted** secrets (wrapped DEK and HSM bearer show as `<redacted>`). | Stays on disk. |
| `byok/byok.env` | Full env, including `TEE_CRAFTER_BYOK_X_CIPHERTEXT_B64` and `TEE_CRAFTER_BYOK_HSM_BEARER` when present. | Relocated to `/run/tee-crafter-{platform}/byok.env` (tmpfs); disk copy **shredded** unless `TEE_CRAFTER_BYOK_PERSIST=1`. |
| `byok/byok.env.public` | Non-secret keys only (provider, `key_id`, region, policy knobs, non-sensitive `extra.*`). | Survives reboot; workload units load this from disk. |

> The in-TEE bundle uploader still rsyncs an `app/byok.{env,env.public,json}`
> copy that lands flat next to the workload binary; nothing in the
> uploader chain changed.

Implementers: [`install_byok_sidecar`](../apps/cli/src/tee_crafter/cli/deployment/common/byok_sidecar.py) runs post-deploy on platforms that consume `app/byok.env` from disk (SNP, TDX, GPU CC). Nitro’s per-request path does not use these env files for `ciphertext_b64` unwrap.

### AWS SNP / GPU-CC — automatic `TF_VAR_byok_aws_kms_arn`

On `snp-aws` and `gpu-cc-aws`, the instance role only receives
`kms:Decrypt` on the **customer** key when Terraform sees
`var.byok_aws_kms_arn`. You no longer need to export this by hand:
when `--byok aws-kms` and `--byok-config` are set, the CLI copies
`key_id` from the policy JSON into `TF_VAR_byok_aws_kms_arn` before
`terraform apply` (unless you already set that env var). The audit row
`DH-016` records whether it was present. **Nitro** does not set this
variable — the enclave unwraps via `kmstool-enclave-cli` and a
`Recipient` attestation document, not the host instance role.

### AWS SNP and GPU-CC: the instance-role ARN is the whole gate

There is no AWS KMS condition key for an AMD SEV-SNP (or NitroTPM) launch
measurement, so on `snp-aws` and `gpu-cc-aws` the key policy cannot check
anything about the workload — the only thing it can check is *which IAM
principal is calling*. That makes the principal condition the entire access
control on the customer's DEK.

Consequently `byok-sandbox/aws/create_kms_key.py` **requires** the exact
instance-role ARN on those two platforms and pins it with `ArnEquals`:

```bash
# There is no `terraform output` for the role ARN. From the deploy directory:
terraform state show 'aws_iam_role.snp_role[0]' # gpu_cc_role for gpu-cc-aws
# or, by name prefix:
aws iam list-roles \
  --query "Roles[?starts_with(RoleName, 'tee-crafter-snp-role-')].Arn" --output text

python3 apps/cli/byok-sandbox/aws/create_kms_key.py \
  --tee-platform snp-aws --region us-east-2 --alias tee-byok-snp \
  --instance-role-arn arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-snp-role-<suffix>
```

If you supplied your own role instead of letting Terraform create one, it is the
value you passed as `existing_enclave_role_arn` / `TF_VAR_existing_enclave_role_arn`.

Running without `--instance-role-arn` exits non-zero and prints the commands
above; it does **not** fall back to a role-name pattern. The earlier default was
`ArnLike aws:PrincipalArn = arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-snp-role-*`,
which — with no attestation condition behind it — granted `kms:Decrypt` on the
DEK to *every* role in the account whose name happened to match, so anyone
holding `iam:CreateRole` there could mint one and read the data key. That pattern
now requires the explicit `--allow-wildcard-role` opt-in, which prints a warning
naming that exposure, and is appropriate only in a throwaway sandbox account.

Exact pinning is still `iam-scoped`, not `kms-enforced`: it narrows *who* may
decrypt, it does not prove *what* is running. Root on the CVM can read that
role's credentials from IMDS and call `kms:Decrypt` directly. Keep the role's
trust policy and `iam:PassRole` tight, and treat the measurement allowlist as
advisory (see [the gating table](#per-provider-gating)).

### In-TEE KMS / Key Vault reachability (locked-down networks)

The DEK release / sealed-`.env` unseal happens **inside the TEE at boot** (the
`tee-crafter-secrets` oneshot, or the Nitro enclave entrypoint). TEE-Crafter
deploys into a private, deny-all-egress network, so there is no public route to
the KMS/Key Vault endpoint. The CLI therefore provisions a **private
reachability path** per cloud, gated on the BYOK provider (via
`export_byok_tf_vars`); without it the release would hang and the workload
would never start (fail-closed).

| Cloud | BYOK provider | Gating TF var | Reachability path |
|-------|---------------|---------------|-------------------|
| AWS (`snp-aws`, `gpu-cc-aws`) | `aws-kms` | `byok_aws_kms_arn` | KMS **interface VPC endpoint** (`com.amazonaws.<region>.kms`, private DNS), shares the VPC-endpoint SG |
| AWS (`nitro-aws`) | `aws-kms` (recipient) | `create_kms_vpc_endpoint` | own KMS interface endpoint for the enclave `Recipient` path |
| GCP (`snp/tdx/gpu-cc -gcp`) | `gcp-kms` | `byok_gcp_kms` | private **Cloud DNS zone** `googleapis.com` → restricted VIP `199.36.153.8/30` (the only allowed HTTPS egress), served by the metadata resolver |
| Azure (`snp/tdx/gpu-cc -azure`) | `azure-kv` | `byok_azure_kv` | **`Microsoft.KeyVault` service endpoint** on the VM subnet + NSG outbound allow (443) to the `AzureKeyVault` service tag (Azure backbone, no NAT) |

> **Identity (customer side):** reachability is necessary but not sufficient —
> the TEE's workload identity must also be authorized on the customer key.
> AWS grants the instance role `kms:Decrypt` automatically (`byok_aws_kms_arn`),
> but the **customer KMS key policy** must still allow that role. For GCP the
> instance service account needs `roles/cloudkms.cryptoKeyDecrypter` on the key;
> for Azure the VM managed identity needs Key Vault crypto/SKR permission on the
> vault. These bind to the **customer's** resource, so grant them when you
> create the key (the `byok-sandbox` create scripts do this for the smoke keys).
> If the customer vault/key has a network firewall, also add the deploy subnet
> (Azure VNet rule) or allow the restricted VIP (GCP) on that resource.

### Container mode — host-venv runtime dependencies

In **container mode** the CVM host venv is normally stripped to proxy deps
only. Because the attested release runs through
`tee_crafter.core.keys.<provider>` on the host, deploy adds the pieces back
**only when BYOK is enabled** (detected from the staged `byok.env.public`):

* the provider SDK is appended to `host_venv_requirements.txt` — `boto3`
 (`aws-kms`), `google-cloud-kms` (`gcp-kms`), or `azure-identity` +
 `azure-keyvault-keys` (`azure-kv`); `external-hsm` needs nothing extra; and
* a **minimal `tee_crafter` runtime subpackage** (`core/keys` + `core/measurements`)
 is staged next to the workload so `import tee_crafter.core.keys...` resolves.

This is handled once in
[`write_cvm_container_host_requirements`](../apps/cli/src/tee_crafter/cli/deployment/common/wheel_manager.py),
so every CVM container platform (SNP / TDX / GPU-CC) gets it uniformly.

Committed smoke configs (run `apps/cli/byok-sandbox/aws/create_kms_key.py` and
`wrap_dek.py` first if `extra.ciphertext_b64` is empty):

These files are **generated**, not checked in — `apps/cli/byok-sandbox/configs/`
does not exist until you run one of the helper scripts
(`apps/cli/byok-sandbox/generate_byok_config.py`, or the per-cloud
`create_*_key.py` + `wrap_dek.py` pair), which write into it. On `snp-aws` and
`gpu-cc-aws` those helpers need `--instance-role-arn` — see
[the instance-role ARN is the whole gate](#aws-snp-and-gpu-cc-the-instance-role-arn-is-the-whole-gate).

| Generated file | Platform |
|------|----------|
| `apps/cli/byok-sandbox/configs/byok-nitro-aws.json` | `nitro-aws` (`unwrap`: `aws_nitro_recipient`) |
| `apps/cli/byok-sandbox/configs/byok-snp-aws.json` | `snp-aws` (`unwrap`: `direct_bytes`) |
| `apps/cli/byok-sandbox/configs/byok-gcp.json` | `snp-gcp`, `tdx-gcp`, `gpu-cc-gcp` |

### Nitro — per-request AWS credentials (SEC-CREDS-1 / SEC-CREDS-2)

The enclave has no direct network to AWS; credentials are supplied per request
either by the **host proxy** (instance role, IMDSv2) or, in dev, by
`apps/cli/byok-sandbox/aws/smoke_byok_aws.py` (short-lived STS by default). boto3 is
called with **explicit** `aws_access_key_id` / `aws_secret_access_key` /
`aws_session_token` on the client — not via `os.environ`. The **customer KMS
key policy** and attestation conditions remain the real gate for unwrap.

## Examples

### AWS KMS, Nitro recipient

`configs/aws-kms.json`:

```json
{
  "provider": "aws-kms",
  "key_id": "arn:aws:kms:us-east-2:123456789012:key/abc-123",
  "region": "us-east-2",
  "unwrap": "aws_nitro_recipient",
  "encryption_context": {"tenant": "acme"},
  "policy": {
    "max_attestation_age_seconds": 300,
    "allowed_measurement_sha256": ["9b2c...64hex"],
    "require_encryption_context_keys": ["tenant"]
  }
}
```

```bash
tee-crafter deploy \
  --source examples/docker_flask_api \
  --tee-platform nitro-aws \
  --instance-type c6a.2xlarge \
  --ami-id <baked-id> \
  --service-profile long-lived \
  --byok aws-kms --byok-config configs/aws-kms.json \
  --deploy --auto-approve
```

### Azure Key Vault SKR

```json
{
  "provider": "azure-kv",
  "key_id": "https://my-vault.managedhsm.azure.net/keys/my-key",
  "unwrap": "rsa_oaep_sha256",
  "policy": {
    "max_attestation_age_seconds": 300,
    "allowed_measurement_sha256": ["..."]
  }
}
```

### GCP KMS + Confidential Space

```json
{
  "provider": "gcp-kms",
  "key_id": "projects/my-proj/locations/us-central1/keyRings/cs/cryptoKeys/dek",
  "region": "us-central1",
  "unwrap": "direct_bytes",
  "policy": {
    "max_attestation_age_seconds": 180,
    "allowed_measurement_sha256": ["..."]
  }
}
```

### External HSM (RSA-OAEP)

```json
{
  "provider": "external-hsm",
  "key_id": "kid-prod-001",
  "unwrap": "rsa_oaep_sha256",
  "hsm_endpoint": "https://hsm.example.com",
  "hsm_bearer_token": "${HSM_BEARER_TOKEN}",
  "policy": {
    "max_attestation_age_seconds": 120
  }
}
```

## Policy fail-closed gates

The orchestrator
([`KeyReleaseOrchestrator.release`](../apps/cli/src/tee_crafter/core/keys/release.py))
raises `KeyReleaseError` — and the DEK is **never** released — when
any of these conditions hits. Every refusal is captured as a signed
audit row before the call returns, so an auditor can replay every
rejection from the build's audit trail.

| Condition | Behaviour | Audit anchor |
|-----------|-----------|--------------|
| Attestation provider raised | `KeyReleaseError("attestation provider failed:...")` | `key_release_decision status=fail` |
| Attestation older than `policy.max_attestation_age_seconds` | `KeyReleaseError("Attestation is Ns old; policy max is Ms")` | `BYOK-005` + `key_release_decision` |
| `policy.allowed_measurement_sha256` non-empty and live measurement not in list | `KeyReleaseError("Measurement X is not in the policy allowlist")` | `BYOK-002` / `BYOK-004` + `key_release_decision` |
| `policy.allowed_measurement_sha256` non-empty and provider returned empty measurement | `KeyReleaseError("Policy requires a measurement allowlist but provider did not supply one")` | `key_release_decision` |
| `policy.require_encryption_context_keys` lists keys not present in the runtime context | `KeyReleaseError("Policy requires encryption context keys [...]")` | `key_release_decision` |
| Adapter `preflight` failed (e.g. AWS KMS refused, MAA token rejected by Key Vault) | adapter exception propagated | `BYOK-008` + `key_release_decision` |
| Required provider does not match `key_ref.provider` | `KeyReleaseError("Policy fixes provider to X, requested Y")` | `key_release_decision` |
| Unwrap algorithm not valid for `tee_platform` (e.g. `aws_nitro_recipient` selected on SNP) | refused by `BYOK-002` at build time | `BYOK-002` |

`policy.require_signed_audit` (default `true`) additionally requires
the audit row itself to be Ed25519-signed before the release is
considered final.

## Audit trail

Every call to `KeyReleaseOrchestrator.release` emits an audit entry
of type `key_release_decision` with:

* `provider`, `key_id_tail` (last 32 chars), `region`, `unwrap`.
* The attestation digest the policy evaluated.
* The decision (`granted` / `denied: <reason>`).
* The resulting DEK SHA-256 prefix (the DEK itself is **never** logged).

This entry is signed and chained into the SIEM stream alongside the
attestation snapshots, so a single SIEM dashboard shows both the
TEE's health *and* every time a customer-managed key was released to
it.

## Key rotation / post-reboot re-staging — `byok-stage`

`tee-crafter byok-stage` pushes a fresh BYOK config to a **running** TEE
without redeploying. It is the sister command to `siem-stage`, and you need it
in two situations:

1. **Rotating the wrapped DEK.** Re-wrap a fresh DEK against your KMS key
 (`apps/cli/byok-sandbox/aws/wrap_dek.py` or the equivalent for your cloud), then push
 the resulting `byok-config.json`. The workload's systemd unit reads
 `EnvironmentFile=/run/tee-crafter-<platform>/byok.env`, so the new material
 is picked up on the next service restart.
2. **After a reboot.** `byok.env` lives on tmpfs (BYOK-SEC-1), so it vanishes
 when the VM restarts. This re-stages it without rebuilding any artifacts.

```bash
# AWS platforms (SSM transport)
tee-crafter byok-stage \
    --platform snp-aws \
 --byok-config./rotated-byok.json \
    --instance-id i-0abc... \
    --region us-east-2

# Azure (Bastion) / GCP (IAP) — SSH transport
tee-crafter byok-stage \
    --platform tdx-azure \
 --byok-config./rotated-byok.json \
    --ssh-host <vm-private-ip> \
 --ssh-key./build/azure_ssh_key.pem
```

### Options

| Flag | Meaning |
|---|---|
| `--platform` | **Required.** One of `snp-aws`, `snp-azure`, `snp-gcp`, `tdx-azure`, `tdx-gcp`, `gpu-cc-aws`, `gpu-cc-azure`, `gpu-cc-gcp`. |
| `--byok-config` | **Required.** Same schema as `--byok-config` at deploy time. Must carry the rotated wrapped DEK (`extra.ciphertext_b64`) or an HSM bearer. |
| `--instance-id` | SSM instance id (AWS platforms). |
| `--region` | AWS region; defaults to `$AWS_REGION`, else `us-east-2`. |
| `--ssh-host` / `--ssh-key` / `--ssh-port` / `--ssh-user` | SSH path (Azure Bastion / GCP IAP). `--ssh-port` defaults to `22`, `--ssh-user` to `azureuser`. |
| `--no-restart` | Stage the new env but skip the workload restart, so you can time the cutover yourself (blue/green, scheduled windows). Without it the command `systemctl try-restart`s whichever of the platform / container / batch units exist. |
| `--dry-run` | Print the remote script instead of running it. **The output contains the secret material** — treat it accordingly. |

### What it does on the host

- Secret half → `/run/tee-crafter-<platform>/byok.env`, tmpfs, `0600`,
 owned `tee_enclave:tee_enclave`.
- Non-secret half (provider, `key_id`, region, policy knobs) →
 `<install-dir>/app/byok.env.public` on disk, `0640`, so the workload keeps
 its non-sensitive config across a reboot even when the secret half is gone.
- Any stale on-disk `byok.env` left by an older full deploy is `shred -u`'d
 (BYOK-SEC-1: the secret half must never persist).

### Refusals

- **`nitro-aws` and `sgx-azure` are rejected.** BYOK on those platforms ships
 inside the build artifact (the EIF / Gramine manifest), not via a runtime
 env-file, so there is nothing to re-stage. Re-bake and redeploy to rotate.
- **A config that produces no secret keys is rejected.** Pushing a config with
 neither a wrapped DEK nor an HSM bearer would silently wipe the live key
 without replacing it, so the command refuses rather than succeed emptily —
 usually it means `wrap_dek.py` was not run first.

## Runtime wiring

The CLI writes `byok.json` and `byok.env` into `<build_dir>/byok/`
and mirrors them into `build_dir/app/` for the in-TEE uploader. At
startup, the in-TEE script
[`tee_crafter_runtime_bootstrap.py`](../apps/cli/src/tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py)
reads those env vars, instantiates the configured KMS adapter, runs
a provider `release` (attestation-gated only where the gating table says
`kms-enforced`), and atomically writes the DEK to
`TEE_CRAFTER_BYOK_DEK_PATH` (default `/run/tee_crafter/byok_dek.bin`)
with `0600` permissions. The application just reads that file.

If the release fails (any of the conditions in the *Policy
fail-closed gates* table above), `bootstrap_byok_release` logs the
exception via the `tee_crafter.runtime_bootstrap` logger and returns
`None` — the user's container then has no DEK to open and
returns its own error path (typically a 500), which fails the
`/healthz` probe and causes `tee-crafter deploy` to mark the
deployment unhealthy. The audit ledger row (`key_release_decision`
`status=fail`) is the authoritative record of what went wrong.

## Application `.env` (`--secrets-env`) — BYOK optional

`--secrets-env <path>` lets the operator hand a **plaintext dotenv** at
deploy time. There are two modes, chosen automatically by whether BYOK is
configured. Both are delivered to the workload at `/run/tee_crafter/app.env`
on CVM and Nitro baked — see **Delivery** below.

| Mode | When | Where the cleartext lives | Use for |
|------|------|---------------------------|---------|
| **Sealed** (BYOK-012) | `--byok aws-kms`/`gcp-kms` | Nowhere at rest — envelope-sealed at build time; cleartext recoverable only by a workload satisfying the key's attestation policy | Real secrets (DB passwords, API tokens) |
| **Baked** | no BYOK (or a non-sealable provider) | Inside the **measured** image artifact (attested, never exposed to clients) | Non-secret config (ports, thresholds, env name) |

You are **not** forced to use BYOK to ship a `.env`. Without it, the file is
baked into the measured image so the app still gets its config — just prefer
sealed mode for anything sensitive.

### Sealed mode (BYOK-012)

When BYOK is configured the CLI envelope-seals the `.env` so the cleartext is
only recoverable **inside an attested TEE**, gated by the *same attestation
policy as the BYOK key*:

1. A random 256-bit data key (DEK) is generated.
2. The `.env` bytes are AES-256-GCM encrypted with the DEK (any size — no
 KMS 4 KiB plaintext limit), with the BYOK encryption context bound as
 AAD.
3. The 32-byte DEK is KMS-encrypted with the customer's BYOK key. The
 wrapped DEK is only decryptable by a workload whose attestation document
 satisfies the key policy (e.g. `kms:RecipientAttestation:ImageSha384`).

```bash
tee-crafter deploy --source./app --persistent --deploy \
    --byok aws-kms --byok-config byok.json \
 --secrets-env./app.env
```

The sealed bundle ships as a BYOK **secret** extra
(`TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64`), so — like the wrapped DEK —
it only ever lands in the tmpfs `byok.env`, never on the host disk or in
`byok.json`. Recorded as **BYOK-012**.

The matching in-TEE consumer,
[`bootstrap_secret_env_release`](../apps/cli/src/tee_crafter/templates/common/tee_crafter_runtime_bootstrap.py),
reuses the BYOK orchestrator to attested-decrypt the DEK, AES-GCM-decrypts
the payload, and atomically writes the cleartext to
`/run/tee_crafter/app.env` (tmpfs, `0600`).

> **Runtime delivery (wired, fail-closed).** On CVM platforms the
> `tee-crafter-secrets.service` oneshot calls `bootstrap_secret_env_release`
> with the platform's concrete `AttestationProvider`
> ([attestation_providers.py](../apps/cli/src/tee_crafter/core/keys/attestation_providers.py))
> **before** the user container starts; the container `Requires=` the oneshot,
> so a failed unseal keeps the workload stopped (dev hatch
> `TEE_CRAFTER_SECRETS_FAIL_OPEN=1`). The release is bound to the image's
> bake-time launch measurement (auto-pinned — see
> [measurements.md](measurements.md)) **and** to the container image digest.
> Both halves matter, because the launch measurement covers initial guest memory
> (firmware, boot configuration, vCPU count) rather than the software on the
> baked disk — two `snp-azure` bakes with different disk contents measure
> identically. The digest is what ties a release to your code; see
> [what the pin does and does not cover](measurements.md). Nitro **sealed** still
> needs NSM recipient-unwrap and is not yet delivered; the CLI warns for that
> path.

### Baked mode (no BYOK)

Without BYOK the `.env` is written to `app.env` in the build directory and
`COPY`-ed into the **measured** TEE image at `/tee-crafter-runtime/app.env`.
It is part of the attested boundary and never exposed to clients, but it does
live in the image artifact — so use it for non-secret config and prefer
sealed mode for credentials.

### Delivery

| Platform / mode | Surfaced to workload at runtime? |
|-----------------|----------------------------------|
| **CVM (SNP/TDX/GPU) — baked** | **Yes.** The `tee-crafter-secrets.service` oneshot copies `app.env` to `/run/tee_crafter/app.env` before the container starts (`--env-file`). |
| **CVM (SNP/TDX/GPU) — sealed (BYOK)** | **Yes, on `aws-kms` / `gcp-kms`.** The same oneshot releases the DEK and unseals to `/run/tee_crafter/app.env`, **fail-closed** (container `Requires=` the oneshot). The measurement binding is enforcing only where the gating table says `kms-enforced`; otherwise advisory. **Not `azure-kv`** — that adapter returns no plaintext DEK, so sealing does not work there. |
| **Nitro — baked (no BYOK)** | **Yes.** `tee_entrypoint.sh` `source`s `/tee-crafter-runtime/app.env` before starting your server. |
| Nitro — sealed (BYOK) | **No** — requires NSM recipient-unwrap (not yet supported); the CLI warns. Use baked mode or the Dockerfile (`ENV`). |
| SGX | **No** — no secrets oneshot; carry config in the Dockerfile (`ENV`). |

Recorded per-deploy as **BYOK-014** (delivery verdict for the chosen
platform/mode) and **BYOK-013** (the runtime fail-closed gate is engaged).
The wired path runs end-to-end: host seal → tmpfs `byok.env` transport →
oneshot `bootstrap_secret_env_release` (concrete `AttestationProvider`) →
`/run/tee_crafter/app.env` → container `--env-file`.
