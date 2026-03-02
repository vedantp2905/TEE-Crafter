# IAM Permissions for Nitro-Agent

To run `nitro-agent` successfully, your executing AWS IAM User or Role must have the following least-privilege permissions to provision infrastructure via Terraform and execute SSM commands for post-deployment automation.

## Required Policy

Attach the following inline policy to your IAM User (or create a custom managed policy and attach it):

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
                "ec2:CreateTags",
                "ec2:DescribeVpcs",
                "ec2:DescribeVpcAttribute",
                "ec2:DescribeSubnets",
                "ec2:DescribeImages",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeTags",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeVolumes",
                "ec2:CreateSecurityGroup",
                "ec2:DescribeSpotInstanceRequests",
                "ec2:CancelSpotInstanceRequests",
                "ec2:DeleteSecurityGroup",
                "ec2:DescribeSecurityGroups",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:CreateVpcEndpoint",
                "ec2:DeleteVpcEndpoints",
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeVpcEndpointServices",
                "ec2:ModifyVpcEndpoint",
                "ec2:DescribeRouteTables",
                "ec2:DescribePrefixLists",
                "ec2:DescribeNetworkInterfaces"
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
                "iam:ListInstanceProfilesForRole"
            ],
            "Resource": [
                "arn:aws:iam::<ACCOUNT_ID>:role/nitro-role-*",
                "arn:aws:iam::<ACCOUNT_ID>:instance-profile/nitro-profile-*"
            ]
        },
        {
            "Sid": "PassRolePermissions",
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::<ACCOUNT_ID>:role/nitro-role-*",
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": "ec2.amazonaws.com"
                }
            }
        },
        {
            "Sid": "KMSPermissions",
            "Effect": "Allow",
            "Action": [
                "kms:DescribeKey",
                "kms:EnableKeyRotation",
                "kms:GetKeyRotationStatus",
                "kms:ScheduleKeyDeletion",
                "kms:PutKeyPolicy",
                "kms:GetKeyPolicy",
                "kms:Encrypt",
                "kms:TagResource",
                "kms:ListResourceTags"
            ],
            "Resource": "arn:aws:kms:*:<ACCOUNT_ID>:key/*"
        },
        {
            "Sid": "KMSCreateKeyPermissions",
            "Effect": "Allow",
            "Action": "kms:CreateKey",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": "<AWS_REGION>"
                }
            }
        },
        {
            "Sid": "S3BucketPermissions",
            "Effect": "Allow",
            "Action": [
                "s3:CreateBucket",
                "s3:DeleteBucket",
                "s3:GetBucketAcl",
                "s3:GetBucketCORS",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetBucketObjectLockConfiguration",
                "s3:GetBucketWebsite",
                "s3:GetBucketTagging",
                "s3:GetBucketRequestPayment",
                "s3:GetLifecycleConfiguration",
                "s3:GetReplicationConfiguration",
                "s3:GetAccelerateConfiguration",
                "s3:PutEncryptionConfiguration",
                "s3:GetEncryptionConfiguration",
                "s3:PutBucketPublicAccessBlock",
                "s3:GetBucketPublicAccessBlock",
                "s3:PutBucketPolicy",
                "s3:GetBucketPolicy",
                "s3:DeleteBucketPolicy",
                "s3:ListBucket"
            ],
            "Resource": "arn:aws:s3:::nitro-deployment-*"
        },
        {
            "Sid": "S3ObjectPermissions",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::nitro-deployment-*/*"
        },
        {
            "Sid": "SSMPermissions",
            "Effect": "Allow",
            "Action": [
                "ssm:SendCommand",
                "ssm:GetCommandInvocation",
                "ssm:ListCommandInvocations",
                "ssm:DescribeInstanceInformation"
            ],
            "Resource": "*"
        },
        {
            "Sid": "STSPermissions",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## What Each Permission Block Covers

| Block | Used By | Purpose |
|-------|---------|---------|
| **EC2** | Terraform (Phase 4) | Provision EC2 instances, security groups, VPC endpoints for KMS and S3 |
| **IAM** | Terraform (Phase 4) | Create enclave IAM role, instance profile, inline policies, attach SSM managed policy |
| **KMS** | Terraform (Phase 4) + Client (Phase 5) | Create PCR-locked encryption key; client uses `kms:Encrypt` to encrypt data before sending to enclave |
| **S3** | Terraform (Phase 4) + SSM (Phase 5) | Create deployment bucket; upload EIF, scripts, and proxy code; enforce encryption and public access block |
| **SSM** | CLI (Phase 5) | Send commands to EC2 host for setup, enclave boot, log retrieval; poll for command completion |
| **STS** | Terraform (Phase 4) | `GetCallerIdentity` used to construct KMS key policy ARN referencing the account root |

## How to Apply

1. Replace every occurrence of **`<ACCOUNT_ID>`** with your 12-digit AWS account ID (e.g. `aws sts get-caller-identity --query Account --output text`).
2. Replace **`<AWS_REGION>`** with the AWS region you use for deployment (e.g. `us-east-2`). This must match `TF_VAR_aws_region` in your `.env`.
3. Go to **AWS Console** → **IAM** → **Users** → your user → **Permissions** → **Add inline policy** (JSON editor).
4. Paste the edited policy.
5. Configure your `.env` with `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `TF_VAR_aws_region` from the user's security credentials.

## EC2 Instance IAM Role (Created Automatically)

The Terraform template automatically creates a least-privilege IAM role for the EC2 host with:

- **AmazonSSMManagedInstanceCore** (managed policy): SSM agent connectivity.
- **S3 Read-Only** (inline): `s3:GetObject` and `s3:ListBucket` on the deployment bucket only.
- **KMS GenerateRandom** (inline): For enclave entropy seeding.
- **KMS Decrypt/GenerateDataKey**: Granted via the KMS key policy (not the IAM role), conditional on valid PCR attestation (`kms:RecipientAttestation:PCR0/1/2`).
