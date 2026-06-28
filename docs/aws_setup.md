# AWS IAM Policies for TEE-Crafter (Nitro / SNP-AWS / GPU CC)

TEE-Crafter uses **AWS** for the Nitro (`--tee-platform nitro-aws`), SNP-AWS
(`--tee-platform snp-aws`), and GPU CC (`--tee-platform gpu-cc-aws`) backends.
Everything else (VPCs, security groups, IAM roles attached to the EC2
instance, S3 deployment buckets, KMS keys) is created automatically by the
TEE-Crafter Terraform stack on every deploy.

You only need to do two things up front:

1. Have an **IAM user** (or role) whose credentials live in your `.env`.
2. Attach the **two customer-managed IAM policies** below to that
 principal via the AWS Console.

> **Cloud isolation — AWS-only deploys do NOT need Azure or GCP credentials.**
> When `--tee-platform` is `nitro-aws`, `snp-aws`, or `gpu-cc-aws`, the
> CLI validates AWS credentials only. The Azure CLI (`az`) and gcloud
> are never invoked, and any stale `AZURE_*` / `GOOGLE_*` entries in
> your `.env` are ignored for that run. Sandbox helpers under
> `byok-sandbox/` follow the same rule: `byok-sandbox/aws/*` only need
> AWS creds, `byok-sandbox/gcp/*` only need GCP creds, etc.

---

## `.env` keys TEE-Crafter reads

```ini
AWS_ACCESS_KEY_ID=<AKIA…>
AWS_SECRET_ACCESS_KEY=<…>
TF_VAR_aws_region=us-east-2 # any region you have quota in
```

That's all the AWS-side configuration the CLI needs. `AWS_REGION`
is derived from `TF_VAR_aws_region` automatically.

---

## Quota requirements (for reference)

AWS instance launches are gated by **EC2 Service Quotas**. TEE-Crafter
uses **On-Demand instances by default**. Pass `--spot`
(or `TEE_CRAFTER_SPOT=1`) on `deploy` or `deploy-from-build`, to use Spot
(requires spot quota). On `deploy-from-build` the flag is only worth passing to
*change* the setting: with it omitted, the resume reuses whatever the build
directory was applied with.

| Platform | Default Instance | vCPUs | On-Demand Quota | Spot Quota |
|---|---|---|---|---|
| `nitro-aws` | `c6a.xlarge` | 4 | `L-1216C47A` | `L-34B43A08` |
| `snp-aws` | `m6a.xlarge` | 4 | `L-1216C47A` | `L-34B43A08` |
| `gpu-cc-aws` | `p5.4xlarge` | 16 | `L-417A185B` | `L-7212CCBC` |

Request increases from
[AWS Console → Service Quotas → EC2](https://console.aws.amazon.com/servicequotas/home/services/ec2/quotas)
in **the same region** as `TF_VAR_aws_region`. Quotas are regional.

> **Note:** GPU CC AWS deployments are pinned to **`us-east-2a`** by
> default to avoid AZ capacity drift. TEE-Crafter runs pre-flight
> quota checks before any deploy and reports actionable errors early.

---

## The two IAM policies

AWS limits customer-managed policies to 6,144 characters each. The
full TEE-Crafter permission set exceeds this, so we split it into two
policies by domain — **Compute** (EC2 + IAM + KMS) and **DataOps**
(S3 + SSM + CloudWatch + audit-matrix read). Attach **both** to the
same IAM user.

Replace `<ACCOUNT_ID>` with your 12-digit AWS account ID before saving
each policy.

### Policy 1 — `TeeCrafterCompute`

EC2, IAM (scoped to `tee-crafter-*` roles), PassRole, and KMS.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2Permissions",
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances",
        "ec2:DescribeInstances",
        "ec2:TerminateInstances",
        "ec2:StopInstances",
        "ec2:CreateTags",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcAttribute",
        "ec2:DescribeSubnets",
        "ec2:DescribeImages",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeInstanceTypeOfferings",
        "ec2:DescribeTags",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeVolumes",
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:DescribeSecurityGroups",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:DescribeSpotInstanceRequests",
        "ec2:CancelSpotInstanceRequests",
        "ec2:CreateVpcEndpoint",
        "ec2:DeleteVpcEndpoints",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcEndpointServices",
        "ec2:ModifyVpcEndpoint",
        "ec2:DescribePrefixLists",
        "ec2:DescribeManagedPrefixLists",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRouteTables",
        "ec2:CreateVpc",
        "ec2:DeleteVpc",
        "ec2:ModifyVpcAttribute",
        "ec2:CreateSubnet",
        "ec2:DeleteSubnet",
        "ec2:ModifySubnetAttribute",
        "ec2:CreateRouteTable",
        "ec2:DeleteRouteTable",
        "ec2:AssociateRouteTable",
        "ec2:DisassociateRouteTable",
        "ec2:CreateRoute",
        "ec2:DeleteRoute",
        "ec2:CreateInternetGateway",
        "ec2:DeleteInternetGateway",
        "ec2:AttachInternetGateway",
        "ec2:DetachInternetGateway",
        "ec2:DescribeInternetGateways",
        "ec2:CreateNatGateway",
        "ec2:DeleteNatGateway",
        "ec2:DescribeNatGateways",
        "ec2:AllocateAddress",
        "ec2:ReleaseAddress",
        "ec2:DescribeAddresses",
        "ec2:CreateFlowLogs",
        "ec2:DeleteFlowLogs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeAvailabilityZones",
        "ec2:CreateImage",
        "ec2:DeregisterImage",
        "ec2:RegisterImage",
        "ec2:DescribeSnapshots",
        "ec2:DeleteSnapshot",
        "ec2:GetManagedPrefixListEntries",
        "ec2:DescribeImageAttribute",
        "ec2:GetConsoleOutput",
        "ec2:DescribeAddressesAttribute"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMPermissions",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:GetRole",
        "iam:DeleteRole",
        "iam:PutRolePolicy",
        "iam:GetRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:ListRolePolicies",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:CreateInstanceProfile",
        "iam:GetInstanceProfile",
        "iam:DeleteInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile",
        "iam:ListInstanceProfilesForRole",
        "iam:TagRole"
      ],
      "Resource": [
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-role-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-snp-role-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-gpu-cc-role-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-flow-log-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-snp-flow-log-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-gpu-cc-flow-log-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-bake-ami-role",
        "arn:aws:iam::<ACCOUNT_ID>:instance-profile/tee-crafter-profile-*",
        "arn:aws:iam::<ACCOUNT_ID>:instance-profile/tee-crafter-snp-profile-*",
        "arn:aws:iam::<ACCOUNT_ID>:instance-profile/tee-crafter-gpu-cc-profile-*",
        "arn:aws:iam::<ACCOUNT_ID>:instance-profile/tee-crafter-bake-ami-profile"
      ]
    },
    {
      "Sid": "PassRolePermissions",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": [
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-role-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-snp-role-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-gpu-cc-role-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-bake-ami-role"
      ],
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "ec2.amazonaws.com"
        }
      }
    },
    {
      "Sid": "PassFlowLogRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": [
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-flow-log-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-snp-flow-log-*",
        "arn:aws:iam::<ACCOUNT_ID>:role/tee-crafter-gpu-cc-flow-log-*"
      ],
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "vpc-flow-logs.amazonaws.com"
        }
      }
    },
    {
      "Sid": "KMSPermissions",
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:DescribeKey",
        "kms:EnableKeyRotation",
        "kms:GetKeyRotationStatus",
        "kms:ScheduleKeyDeletion",
        "kms:PutKeyPolicy",
        "kms:GetKeyPolicy",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:Decrypt",
        "kms:TagResource",
        "kms:ListResourceTags",
        "kms:CreateAlias",
        "kms:UpdateAlias",
        "kms:DeleteAlias",
        "kms:ListAliases"
      ],
      "Resource": "*"
    }
  ]
}
```

### Policy 2 — `TeeCrafterDataOps`

S3 (scoped to `tee-crafter-deployment-*` / `tee-crafter-gpu-cc-*`), SSM
(tag-conditioned), CloudWatch Logs (scoped to `/tee-crafter/*`), STS,
and the read-only actions the audit matrix needs (`CT-001 / CT-002` +
`IAM-004`).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3BucketPermissions",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:DeleteObjectVersion",
        "s3:ListBucketVersions",
        "s3:PutBucketVersioning",
        "s3:GetBucketVersioning",
        "s3:PutLifecycleConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:PutEncryptionConfiguration",
        "s3:GetEncryptionConfiguration",
        "s3:PutBucketPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "s3:PutBucketPolicy",
        "s3:GetBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketLogging",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketTagging",
        "s3:GetBucketRequestPayment",
        "s3:GetReplicationConfiguration",
        "s3:GetAccelerateConfiguration",
        "s3:GetBucketCORS",
        "s3:GetBucketWebsite",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::tee-crafter-deployment-*",
        "arn:aws:s3:::tee-crafter-gpu-cc-*"
      ]
    },
    {
      "Sid": "S3ObjectPermissions",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Resource": [
        "arn:aws:s3:::tee-crafter-deployment-*/*",
        "arn:aws:s3:::tee-crafter-gpu-cc-*/*"
      ]
    },
    {
      "Sid": "SSMSendCommandOnInstances",
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": "arn:aws:ec2:*:<ACCOUNT_ID>:instance/*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Project": "tee-crafter"
        }
      }
    },
    {
      "Sid": "SSMSendCommandDocuments",
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": "arn:aws:ssm:*::document/AWS-RunShellScript"
    },
    {
      "Sid": "SSMCommandResults",
      "Effect": "Allow",
      "Action": [
        "ssm:GetCommandInvocation",
        "ssm:ListCommandInvocations"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SSMStartSessionOnInstances",
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": "arn:aws:ec2:*:<ACCOUNT_ID>:instance/*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Project": "tee-crafter"
        }
      }
    },
    {
      "Sid": "SSMStartSessionDocuments",
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": "arn:aws:ssm:*::document/AWS-StartPortForwardingSession"
    },
    {
      "Sid": "SSMSessionManagement",
      "Effect": "Allow",
      "Action": [
        "ssm:TerminateSession",
        "ssm:DescribeSessions"
      ],
      "Resource": "arn:aws:ssm:*:<ACCOUNT_ID>:session/*"
    },
    {
      "Sid": "SSMDescribe",
      "Effect": "Allow",
      "Action": "ssm:DescribeInstanceInformation",
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogsDescribe",
      "Effect": "Allow",
      "Action": "logs:DescribeLogGroups",
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogsManage",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:PutRetentionPolicy",
        "logs:ListTagsLogGroup",
        "logs:ListTagsForResource",
        "logs:TagResource",
        "logs:UntagResource"
      ],
      "Resource": "arn:aws:logs:*:<ACCOUNT_ID>:log-group:/tee-crafter/*"
    },
    {
      "Sid": "STSPermissions",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Sid": "PreflightQuotaCheck",
      "Effect": "Allow",
      "Action": "servicequotas:GetServiceQuota",
      "Resource": "*"
    },
    {
      "Sid": "AuditMatrixCloudTrailLookup",
      "Effect": "Allow",
      "Action": "cloudtrail:LookupEvents",
      "Resource": "*"
    },
    {
      "Sid": "AuditMatrixSimulatePolicy",
      "Effect": "Allow",
      "Action": "iam:SimulatePrincipalPolicy",
      "Resource": "*"
    }
  ]
}
```

> **`ec2:DescribePrefixLists` is not the same action as
> `ec2:DescribeManagedPrefixLists`**, and `gpu-cc-aws` needs the second one.
> Its `data "aws_ec2_managed_prefix_list" "cloudfront_origin_facing"` lookup
> evaluates whenever `allow_nras_egress = true` and `nras_egress_cidrs` is
> empty — which is the **default pair**, and NRAS egress is required for GPU CC
> attestation at all. Without it `terraform plan` fails with
> `UnauthorizedOperation... ec2:DescribeManagedPrefixLists`. Both permissions are
> required; a policy carrying only the first cannot deploy `gpu-cc-aws` at all.
> The full set was derived by simulating every (action, resource) pair the
> templates need with `iam:SimulatePrincipalPolicy` against a real principal.
>
> **Audit-matrix read-only IAM**: the two `AuditMatrix*` statements
> above let `tee-crafter verify-provenance` emit `CT-001 / CT-002`
> verdicts (from CloudTrail) and `IAM-004` (from policy simulation).
> Both are read-only. Failing to attach them downgrades the matrix
> to `warn` rows rather than blocking deploy.

---

## How to put them in the AWS IAM console

For each of the two policies above:

1. Open the [AWS Console → IAM → Policies → Create policy](https://console.aws.amazon.com/iam/home#/policies$new?step=edit).
2. Switch the editor to the **JSON** tab.
3. Paste the entire JSON block (replace `<ACCOUNT_ID>` with your account ID — find it under IAM → top-right account menu, or by clicking your username in the console header).
4. Click **Next** → name the policy **`TeeCrafterCompute`** (or **`TeeCrafterDataOps`**) → **Create policy**.

Then attach both policies to your IAM user:

1. **IAM → Users → `<your-user>` → Permissions → Add permissions → Attach policies directly**.
2. Tick **`TeeCrafterCompute`** and **`TeeCrafterDataOps`** → **Next** → **Add permissions**.

The two policies together cover every action TEE-Crafter performs from
your laptop on AWS, including:

- baking AMIs (`ec2:CreateImage`, `ec2:RunInstances`, …),
- deploy + teardown (`ec2:*`, `iam:CreateRole`/`PassRole`, KMS, S3, SSM),
- `tee-crafter verify-provenance` (`cloudtrail:LookupEvents`,
 `iam:SimulatePrincipalPolicy`),
- the SIEM / BYOK / `byok-stage` flows documented below.

### Tag convention

All TEE-Crafter EC2 instances (bake and deploy) are tagged with
`Project = "tee-crafter"`. The SSM statements above use
tag-conditioned resource scoping (`aws:ResourceTag/Project =
tee-crafter`) so the policy can only target TEE-Crafter VMs.

### Batch mode (`--batch`) and S3 uploads

The EC2 instance uses its **instance profile role** to upload the
captured bundle to S3, **not** the IAM user from `aws configure`. Your
IAM user still needs permissions to run Terraform and SSM from your
laptop (that's what the policies above grant), but `AccessDenied` on
that upload usually means missing **S3 write** or
**KMS Encrypt / GenerateDataKey** on the *instance role* for the
deployment bucket (SSE-KMS). Default TEE-Crafter Terraform grants
those for the managed bucket and its key automatically; if you use an
**existing** deployment bucket, attach equivalent permissions to the
instance role and KMS key policy yourself.

---

## SIEM (`--siem...`) — what extra IAM is required?

Continuous-attestation export with `--siem <provider> --siem-config
<path>` adds **no new permissions on the deploy user** for most
providers, because the events are POSTed from inside the TEE to
whatever endpoint the customer points us at. The only cases where
IAM matters:

| Provider | `egress_mode` | Extra IAM on the deploy user | Notes |
|---|---|---|---|
| `splunk-hec`, `datadog`, `syslog-cef` | `auto` (default) or `public` | **None.** Already covered by `TeeCrafterCompute` (`ec2:*` on VPC/SG/NAT) and `TeeCrafterDataOps`. | TEE reaches the SIEM over NAT egress; CIDR allowlists are enforced via `aws_security_group` rules using actions you already have. |
| any provider | `private` | **`ec2:CreateVpcEndpoint`, `ec2:ModifyVpcEndpoint`, `ec2:DeleteVpcEndpoints`** (already covered). | TEE-Crafter provisions an **Interface VPC Endpoint** for `logs.<region>.amazonaws.com` — set `TF_VAR_siem_provision_logs_endpoint=true`. No public egress. |

In other words: **for `--siem splunk-hec` (the most common case) the
deploy IAM user does not need any SIEM-specific permission.** The
two policies above are sufficient.

---

## BYOK (`--byok aws-kms`) — what extra IAM is required?

Attestation-gated key release with `--byok aws-kms --byok-config
<path>` (see [`docs/byok.md`](byok.md)) splits into two pieces:

| Where | What it does | IAM it needs |
|---|---|---|
| **Operator laptop** (`byok-sandbox/aws/create_kms_key.py` + `wrap_dek.py`) | Creates the customer-managed KMS key, sets its key policy, optionally creates an alias, and `kms:Encrypt`s a sample DEK that gets baked into `byok-config.json`. | Covered by `TeeCrafterCompute`: `kms:CreateKey`, `kms:PutKeyPolicy`, `kms:DescribeKey`, `kms:Encrypt`, `kms:CreateAlias`, `kms:UpdateAlias`, `kms:DeleteAlias`, `kms:ListAliases`, `kms:TagResource`. Plus `sts:GetCallerIdentity` from `TeeCrafterDataOps`. |
| **Inside the enclave** (per-request `ciphertext_b64` path in `app_vsock.template.py`) | Calls `kms:Decrypt` with `Recipient` carrying the Nitro attestation document; AWS KMS evaluates the **customer's** key policy and only releases the DEK if `kms:RecipientAttestation:ImageSha384` / `PCR0..2` match. | **Nothing extra on the deploy user.** Decrypt authorization comes from the *customer's* key policy (which the sandbox helper writes), not from the enclave's instance role. |

If you want to harden the key policy to a specific enclave build,
re-run `create_kms_key.py --pcrs-json builds/<latest>/pcrs.json` after
a successful bake — that adds
`StringEqualsIgnoreCase: kms:RecipientAttestation:PCR{0,1,2}` clauses
so only the exact measurement can decrypt. No IAM change on the
deploy user is needed for this.

> **What if the enclave needs to call `kms:Decrypt` using its own
> instance role?** That mode (BYOK-at-boot via `bootstrap_byok_release`
> rather than the per-request `ciphertext_b64` smoke path) is
> wired with the optional Terraform variable
> **`TF_VAR_byok_aws_kms_arn`** on `nitro`, `snp-aws`, and
> `gpu-cc-aws`. When you set that to the customer's KMS key ARN at
> deploy time, the stock template attaches a least-privilege
> `kms:Decrypt` + `kms:DescribeKey` IAM policy to the instance role
> scoped to exactly that ARN (Sid `ByokKmsDecrypt`). The customer's
> KMS key policy must allow the call too, so this is dual-authorization
> — IAM and key policy must both allow it. What the key policy checks
> differs by platform: on `nitro` it can gate on the Nitro
> `Recipient` attestation and PCR0/1/2; on `snp-aws` / `gpu-cc-aws`
> AWS KMS offers no SEV-SNP or NitroTPM condition key, so the key
> policy can only pin the instance-role ARN — `create_kms_key.py`
> requires you to name it exactly (`--instance-role-arn`) and pins it
> with `ArnEquals`. See [`docs/byok.md`](byok.md#aws-snp-and-gpu-cc-the-instance-role-arn-is-the-whole-gate).
> Leave the variable empty (default) for the smoke /
> forwarded-credentials flow.

---

## `tee-crafter byok-stage` — what IAM is required?

For platforms that load BYOK config from a runtime env-file (`snp-aws`,
`snp-azure`, `snp-gcp`, `tdx-azure`, `tdx-gcp`, and all `gpu-cc-*`),
TEE-Crafter ships a sister command to `siem-stage`. It pushes a fresh
`byok.env` to **tmpfs** at `/run/tee-crafter-<platform>/byok.env`
(mode 0600, owner `tee_enclave`), writes the non-secret half to
`byok.env.public`, scrubs any stale on-disk `byok.env`, and
`try-restart`s the workload.

`byok-stage` reuses the same SSM / SSH-via-Bastion / SSH-via-IAP
transports the deploy phase used, so **no additional IAM is
required** beyond what `TeeCrafterCompute` + `TeeCrafterDataOps`
already grant. It refuses for Nitro / SGX — those workloads receive
BYOK config inside the build artifact (EIF / Gramine manifest), so
re-staging from outside is conceptually wrong; rotate by re-baking
instead.

---

## IMDSv2 enforcement (instance metadata)

Every AWS `aws_instance` block we ship (`nitro`, `snp-aws`,
`gpu-cc-aws`) hard-sets:

```hcl
metadata_options {
 http_tokens = "required"
 http_endpoint = "enabled"
  http_put_response_hop_limit = 1
}
```

This is what lets the Nitro host proxy refuse to forward credentials
to the enclave when IMDSv2 isn't actually available — see SEC-CREDS-1
in [`docs/security.md`](security.md). You do **not** need to opt
into this; it is a baked-in posture invariant that fails closed.

---

## Why SSM is split across multiple statements

AWS evaluates `ssm:SendCommand` against **two** resource types
simultaneously — the target EC2 instance and the SSM document.
Placing both in a single statement with a tag condition fails because
AWS-managed documents (`AWS-RunShellScript`) don't carry user tags.
Splitting the instance (tag-conditioned) and document (no condition)
into separate statements ensures both are authorized correctly. The
same applies to `ssm:StartSession` with `AWS-StartPortForwardingSession`.

---

## Retiring an AMI leaves its EBS snapshot behind

`aws ec2 create-image` creates one EBS snapshot per block device and
attaches it to the new AMI. `ec2:DeregisterImage` removes the AMI but
**not** the snapshot: a retired 30 GiB AMI keeps billing at roughly
$1.50/month forever. Retiring an AMI is therefore two calls, not one:

```bash
aws ec2 deregister-image --region us-east-2 --image-id ami-...
aws ec2 delete-snapshot --region us-east-2 --snapshot-id snap-...
```

Do them in that order and **look the snapshot id up first**, because the
only call that reports it is `ec2:DescribeImages` on an AMI that still
exists:

```bash
aws ec2 describe-images --region us-east-2 --image-ids ami-... \
  --query 'Images[].BlockDeviceMappings[].Ebs.SnapshotId' --output text
```

If the policy above is missing `ec2:DescribeSnapshots` and
`ec2:DeleteSnapshot` — as it was until now — then deregistering first
strands the snapshot permanently: it cannot be deleted, and it cannot
even be listed to find out that it exists. That happened once already: `snap-05f937c10555a08ea`, orphaned from
`ami-070603b2133e92fef`. It was finally reclaimed, together
with thirteen other orphans totalling 420 GiB — roughly $21/month that had
been billing for snapshots whose AMIs no longer existed.

To make this survivable regardless, every AWS bake now records the
snapshot ids it created in `aws_ebs_snapshots.json`, in the same
directory as the measurement registry (see
`cli/commands/baking/common/ebs_ledger.py`). Read that file before
cleaning up:

```bash
cat apps/cli/src/tee_crafter/measurements/aws_ebs_snapshots.json
```
