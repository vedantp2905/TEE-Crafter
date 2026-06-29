# BYOK sandbox

Companion to `siem-sandbox/`.  Each subdirectory contains the helper
scripts needed to:

1. **Create** a customer-managed key in the target cloud (AWS KMS,
   Azure Key Vault, GCP KMS).
2. **Wrap a DEK** with that key (so the plaintext DEK never leaves the
   operator's laptop and the wrapped ciphertext is what ships into the
   TEE).
3. **Smoke-test** the wrapped DEK end-to-end against a running TEE
   deployed by `tee-crafter deploy-container --byok <provider>
   --byok-config <path>`.

Each helper emits a `byok-config.json` file under
`byok-sandbox/configs/` that matches the schema in
[`docs/byok.md`](../../../docs/byok.md) and can be passed verbatim to
`tee-crafter`.

## One command entrypoint (optional)

```bash
# Same as python3 byok-sandbox/aws/create_kms_key.py ...
python3 byok-sandbox/generate_byok_config.py aws \
  --tee-platform snp-aws --region us-east-2 --alias tee-byok-snp

python3 byok-sandbox/generate_byok_config.py gcp --tee-platform tdx-gcp ...

python3 byok-sandbox/generate_byok_config.py azure --tee-platform snp-azure ...
```

Shared helpers live in [`byok_platforms.py`](./byok_platforms.py) (KMS key-policy
shape + unwrap algorithm names).

### AWS: pick `--tee-platform` before `create_kms_key.py`

| `--tee-platform` | KMS decrypt gate | `unwrap` in JSON | Terraform note |
|------------------|------------------|------------------|----------------|
| `nitro-aws` | Nitro `Recipient` attestation | `aws_nitro_recipient` | optional PCR pin via `--pcrs-json` |
| `snp-aws` | exact instance-role ARN(s) — `--instance-role-arn` **required** | `direct_bytes` | CLI auto-sets `TF_VAR_byok_aws_kms_arn` from `key_id` |
| `gpu-cc-aws` | exact instance-role ARN(s) — `--instance-role-arn` **required** | `direct_bytes` | CLI auto-sets `TF_VAR_byok_aws_kms_arn` from `key_id` |

On `snp-aws` / `gpu-cc-aws` there is no AWS KMS condition key for an AMD SEV-SNP
(or NitroTPM) launch measurement, so the caller's IAM principal is the *entire*
access control on the key — see [`docs/byok.md`](../../../docs/byok.md#per-provider-gating),
which reports both platforms as `iam-scoped`, not attestation-gated. Because of
that, `create_kms_key.py` **refuses to run** on those platforms unless you name
the role explicitly, and pins it with `ArnEquals`:

```bash
# In the deploy directory (there is no `terraform output` for the role ARN):
terraform state show 'aws_iam_role.snp_role[0]'        # gpu_cc_role for gpu-cc-aws
# or:
aws iam list-roles \
  --query "Roles[?starts_with(RoleName, 'tee-crafter-snp-role-')].Arn" --output text

python3 byok-sandbox/aws/create_kms_key.py \
  --tee-platform snp-aws --region us-east-2 --alias tee-byok-snp \
  --instance-role-arn arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-snp-role-<suffix>
```

`--allow-wildcard-role` restores the old `role/tee-crafter-<plat>-role-*`
pattern. It prints a warning first, and it is for throwaway sandbox accounts
only: with no attestation condition behind it, that pattern grants `kms:Decrypt`
on the customer's DEK to every matching role in the account, so anyone holding
`iam:CreateRole` there can mint one and read the data key.

### GCP / Azure

`gcp/create_kms_key.py` and `azure/create_kv_key.py` accept `--tee-platform` to
pick default output filenames and record `_metadata.tee_platform`. Azure also
narrows the Key Vault **release policy** when `--tee-platform` is set (omit it
for the legacy combined SNP+TDX policy). `--release-policy-file` overrides both.

| Provider   | Create-key script                                         | Wrap-DEK script                              | Per-request smoke test                                  |
|------------|-----------------------------------------------------------|----------------------------------------------|---------------------------------------------------------|
| `aws-kms`  | `aws/create_kms_key.py`                                   | `aws/wrap_dek.py`                            | `aws/smoke_byok_aws.py`                                 |
| `azure-kv` | `azure/create_kv_key.py` (Premium Vault or Managed HSM)   | `azure/wrap_dek.py`                          | reuse `aws/smoke_byok_aws.py` (vsock client is the same) |
| `gcp-kms`  | `gcp/create_kms_key.py`                                   | `gcp/wrap_dek.py`                            | reuse `aws/smoke_byok_aws.py` *(GCP path tested via SNP/TDX templates; the same `ciphertext_b64` request shape is supported)* |

## Quick start — AWS BYOK on Nitro

```bash
# 1. Create the BYOK KMS key (default --tee-platform nitro-aws).
python3 byok-sandbox/aws/create_kms_key.py \
  --region us-east-2 \
  --alias tee-crafter-byok-smoke

# SNP-AWS / GPU-CC-AWS instead (--instance-role-arn is required there):
# python3 byok-sandbox/aws/create_kms_key.py \
#   --tee-platform snp-aws --region us-east-2 --alias tee-byok-snp \
#   --instance-role-arn arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-snp-role-<suffix>

# 2. Wrap a random 32-byte DEK.  Plaintext is written to the .dek.b64
#    file (TREAT AS SECRET; it is excluded from git via .gitignore).
python3 byok-sandbox/aws/wrap_dek.py \
  --config byok-sandbox/configs/byok-nitro-aws.json \
  --tee-platform nitro-aws

# SNP-AWS deploy (set TF_VAR_byok_aws_kms_arn from create_kms_key output):
# export TF_VAR_byok_aws_kms_arn="$(jq -r .key_id byok-sandbox/configs/byok-snp-aws.json)"
# tee-crafter deploy-container ... --tee-platform snp-aws \
#   --byok aws-kms --byok-config byok-sandbox/configs/byok-snp-aws.json ...

# 3. Plug into a Nitro deploy.
tee-crafter deploy-container \
  --source examples/docker_flask_api \
  --tee-platform nitro-aws \
  --ami-id <baked-id> \
  --byok aws-kms \
  --byok-config byok-sandbox/configs/byok-nitro-aws.json \
  --deploy --auto-approve

# 4. Smoke-test the per-request `ciphertext_b64` path against the
#    live enclave (the host-proxy is private, so we tunnel over SSM).
python3 byok-sandbox/aws/smoke_byok_aws.py \
  --config byok-sandbox/configs/byok-nitro-aws.json \
  --instance-id <i-...> \
  --json-payload '{"task":"ping","data":"hello"}'
```

### Smoke test — credentials and threat model

**Default behaviour (from a developer laptop with long-lived IAM-user keys):**
the script calls `sts:GetSessionToken` and only forwards the **short-lived**
session credentials (default 15-minute TTL, `--cred-duration` up to the IAM
limit). Your long-lived `AWS_SECRET_ACCESS_KEY` never enters the SSM tunnel.

**Production traffic (no laptop in the path):** `host_proxy.template.py` on
the Nitro host injects **fresh instance-role** credentials **only** when the
JSON body needs AWS (`ciphertext_b64` or `encrypted_payload`). Pure
`get_attestation` requests carry no `__aws_credentials`. The enclave uses
**explicit boto3 client kwargs** — it does not set global `AWS_*` env vars.

**CLI overrides:**

| Flag | Meaning |
|------|---------|
| `--use-ambient-creds` | Skip STS minting; forward whatever boto3 resolves (use on EC2 when creds are already temporary). |
| `--skip-creds` | Omit `__aws_credentials`; exercises the path where the host proxy alone supplies creds. |
| `--mfa-serial` / `--mfa-token` | Required when your IAM user mandates MFA for `GetSessionToken`. |

The smoke driver wraps a fresh JSON payload with `kms:Encrypt`, opens an SSM
port-forward to `:443`, POSTs JSON to `https://localhost:<port>/enclave`, and
prints whatever `process_request` returned. Any non-200 / error payload is
failure. See also `docs/byok.md` and `docs/security.md` §17.3–17.5.

## Tightening the AWS key policy with PCRs

`create_kms_key.py` accepts `--pcrs-json <path>` to bind the key to
specific Nitro PCRs.  Use this AFTER the first build:

```bash
tee-crafter deploy-container ... --no-deploy   # builds, emits builds/.../pcrs.json
python3 byok-sandbox/aws/create_kms_key.py \
  --alias tee-crafter-byok-smoke \
  --pcrs-json builds/<latest>/pcrs.json \
  --out byok-sandbox/configs/byok-nitro-aws-prod.json
```

This re-applies the key policy to add
`StringEqualsIgnoreCase: kms:RecipientAttestation:PCR{0,1,2}` clauses
so only the exact build can decrypt.

## GCP

`gcp/create_kms_key.py` creates a `tee-crafter-byok` keyring with a
single symmetric encrypt/decrypt key, grants
`roles/cloudkms.cryptoKeyEncrypterDecrypter` to the current user **and**
to the impersonated service account behind ADC.  Then
`gcp/wrap_dek.py` calls `cloudkms.Encrypt()` and writes the
base64-encoded ciphertext into the byok-config.

## Azure

`azure/create_kv_key.py --mode premium` creates (or re-uses) a Premium
Key Vault and a releasable RSA-3072 key with a default release policy
matching SEV-SNP / TDX-VM MAA attestations.  For FIPS-validated
production deployments, use `--mode mhsm --print-only` to get the
Managed HSM commands; that path is opt-in because Managed HSM costs
~$3/hr base.

## Files this directory produces

```
byok-sandbox/
├── README.md                   <-- this file
├── configs/                    <-- byok-config.json files (ready to deploy)
│   ├── byok-nitro-aws.json     <-- Nitro Recipient-gated KMS + wrapped DEK
│   ├── byok-snp-aws.json       <-- SNP instance-role KMS + wrapped DEK
│   ├── byok-gcp.json           <-- GCP KMS (snp-gcp) + wrapped DEK
│   └── byok-snp-azure.json     <-- Azure Key Vault (RSA-HSM SKR, snp-azure) + wrapped DEK
├── aws/  azure/  gcp/          <-- helper scripts
```

`.dek.b64` files are gitignored.  Treat them as production secrets.
