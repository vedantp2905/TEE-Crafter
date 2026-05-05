terraform {
  # Pin the CLI itself, not just the providers: an un-pinned Terraform is free
  # to introduce state-format or HCL-evaluation changes between operator
  # workstations, and this state carries SSH private keys.  1.6 is the floor
  # for the `test` command and the current lockfile format; `~>` keeps us on
  # 1.x.  `.terraform.lock.hcl` is now committable (the .gitignore rule was
  # removed), so run `terraform providers lock` and commit the result to pin
  # the resolved provider hashes too.
  required_version = "~> 1.6"

  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- Variables ---

variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "gpu_availability_zone" {
  type        = string
  default     = "us-east-2a"
  description = "Availability zone to pin GPU-CC deployments to (avoids AZ capacity drift)."
}

variable "instance_type" {
  type        = string
  default     = "__INSTANCE_TYPE__"
  description = "EC2 instance type. P5 (H100), P5en (H200), or P6 (B200) for NVIDIA CC."
}

variable "subnet_id" {
  type        = string
  default     = ""
  description = "Target subnet. If empty, a new private subnet is created."
}

variable "use_spot_instance" {
  type        = bool
  default     = false
  description = "If true, requests a Spot Instance to reduce cost. Default false (On-Demand)."
}

variable "allow_setup_egress" {
  type        = bool
  default     = false
  description = "Allow HTTP/HTTPS egress to 0.0.0.0/0 for cloud-init package installs. Defaults to false (locked down). Set to true only during first-time setup without a pre-baked AMI."
}

variable "allow_nras_egress" {
  type        = bool
  default     = true
  description = "Allow HTTPS egress for NVIDIA NRAS attestation (nras.attestation.nvidia.com). Required for GPU CC attestation. The egress destination is governed by nras_egress_cidrs below — do NOT set 0.0.0.0/0 unless absolutely necessary."
}

variable "nras_egress_cidrs" {
  type        = list(string)
  default     = []
  description = "Explicit CIDR list for NRAS egress. When empty, this module uses the AWS managed prefix list `com.amazonaws.global.cloudfront.origin-facing` (NVIDIA NRAS is served via CloudFront). Set this to a concrete list of NVIDIA-published IPs to further narrow egress. Never set [\"0.0.0.0/0\"] in production."
}

variable "require_nitro_tpm" {
  type        = bool
  default     = true
  description = "Enable NitroTPM v2.0 on the instance and require UEFI boot. Disables only if you explicitly want a platform without a hardware TPM (not recommended for GPU CC — CPU-side attestation degrades to host-trust)."
}

variable "custom_ami_id" {
  type        = string
  default     = ""
  description = "Custom AMI with pre-baked dependencies. Overrides base AMI when set."
}

variable "measurement" {
  type        = string
  default     = ""
  description = "Expected NitroTPM PCR measurement."
}

# WARNING — `skip_vpc_endpoints`, `create_s3_gateway_endpoint` and
# `create_kms_vpc_endpoint` are also written into `terraform.tfvars` by the
# CLI's preflight probe
# (cli/deployment/common/vpc_endpoints.py::detect_and_skip_existing_vpc_endpoints).
# That probe inspects the account's **default VPC**, but this module builds its
# own dedicated VPC (`aws_vpc.deployment`).  An endpoint that exists in the
# default VPC is not reachable from the dedicated one, so an unrelated
# pre-existing endpoint can turn these flags off and leave the deployment with
# no private path to KMS/SSM/S3 at all.  Under the shipped deny-all egress
# posture that means the boot-time BYOK release hangs and the workload never
# starts.  If the probe has run, confirm these values before applying.
variable "skip_vpc_endpoints" {
  type        = bool
  default     = false
  description = "Skip all VPC endpoint creation. Set true when endpoints already exist."
}

variable "existing_instance_profile_name" {
  type        = string
  default     = ""
  description = "Pre-created IAM Instance Profile name. Skips IAM role/profile creation."
}

variable "existing_enclave_role_arn" {
  type        = string
  default     = ""
  description = "ARN of the pre-created IAM role."
}

variable "existing_security_group_id" {
  type        = string
  default     = ""
  description = "Pre-created Security Group ID. Skips SG creation when set."
}

variable "existing_deployment_bucket" {
  type        = string
  default     = ""
  description = "Pre-created S3 bucket name. Skips bucket creation when set."
}

variable "create_s3_gateway_endpoint" {
  type        = bool
  default     = true
  description = "Create an S3 Gateway VPC endpoint for private S3 access (free). Set false if one already exists."
}

variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block for the per-deployment VPC. Each deployment gets its own isolated VPC."
}

# --- SIEM egress (continuous-attestation export) ---

variable "siem_provision_logs_endpoint" {
  type        = bool
  default     = false
  description = "When true, create a com.amazonaws.<region>.logs Interface VPC Endpoint so the in-TEE SIEM exporter can ship to CloudWatch Logs without leaving the VPC.  Auto-set by --siem cloudwatch + --siem-egress private/auto."
}

# NOTE — egress CIDR allowlists are a POINT-IN-TIME DNS SNAPSHOT.
#
# `--egress-allow host:port` and `--siem-egress-cidr` are resolved on the
# DEPLOYER'S WORKSTATION at plan time (a single `socket.getaddrinfo`, see
# cli/commands/deploy/workload_egress.py::_resolve_host_to_cidrs) and the
# answer is frozen into the rules below as /32s.  Consequences an operator
# needs to know before relying on this as a control:
#
#   * A destination behind DNS round-robin, a CDN, or regional failover will
#     move to an address that is NOT in this allowlist.  The workload then
#     loses connectivity with no diagnostic beyond a connection timeout.
#   * The rule contents depend on the deployer's resolver, so two engineers
#     deploying the same config can produce different security groups.
#   * Nothing re-resolves after apply.  There is no TTL honoured here.
#
# Prefer literal CIDRs you control.  For AWS, an FQDN-matching Network
# Firewall rule group avoids the problem entirely at meaningfully higher cost
# and complexity; it was considered and judged disproportionate for the
# current scope.
variable "siem_egress_cidrs" {
  type        = list(string)
  default     = []
  description = "When non-empty, replaces the host SG's 0.0.0.0/0 egress on `siem_egress_ports` with one rule per listed CIDR. Use to lock SIEM egress down to specific public collectors (Splunk Cloud / Datadog IP ranges)."
}

variable "siem_egress_ports" {
  type        = list(number)
  default     = [443]
  description = "Ports the SIEM egress allowlist applies to.  Defaults to 443.  Add 6514 (TLS syslog) or 514 (plain syslog) if your collector is exposed elsewhere."
}

variable "siem_cloudwatch_log_group" {
  type        = string
  default     = ""
  description = "When non-empty AND --siem cloudwatch is selected, attach a least-privilege IAM policy letting the host role write SIEM events to this CloudWatch log group."
}

# BYOK on AWS KMS for GPU-CC-AWS workloads.  See nitro/main.template.tf
# for the canonical doc string.  Empty (default) leaves IAM untouched.
variable "byok_aws_kms_arn" {
  type        = string
  default     = ""
  description = "Optional customer KMS key ARN to grant the GPU-CC-AWS instance role kms:Decrypt on (for --byok aws-kms boot-time release)."
}

# --- Data Sources ---

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# --- Per-Deployment VPC (network isolation + flow logging) ---

resource "aws_vpc" "deployment" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name         = "tee-crafter-gpu-cc-vpc-${local.did}"
    Project      = "tee-crafter-gpu-cc"
    DeploymentId = local.did
  }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.deployment.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = var.gpu_availability_zone
  map_public_ip_on_launch = false

  tags = {
    Name    = "tee-crafter-gpu-cc-private-subnet"
    Project = "tee-crafter-gpu-cc"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.deployment.id

  tags = {
    Name    = "tee-crafter-gpu-cc-private-rt"
    Project = "tee-crafter-gpu-cc"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# NAT gateway for NRAS attestation and/or setup egress.
# Required whenever traffic must leave the VPC to reach the internet
# (NVIDIA NRAS uses dynamic IPs, so VPC endpoints cannot substitute).

locals {
  need_nat = var.allow_nras_egress || var.allow_setup_egress
}

resource "aws_subnet" "public" {
  count                   = local.need_nat ? 1 : 0
  vpc_id                  = aws_vpc.deployment.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  availability_zone       = var.gpu_availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name    = "tee-crafter-gpu-cc-public-subnet"
    Project = "tee-crafter-gpu-cc"
  }
}

resource "aws_internet_gateway" "igw" {
  count  = local.need_nat ? 1 : 0
  vpc_id = aws_vpc.deployment.id

  tags = {
    Name    = "tee-crafter-gpu-cc-igw"
    Project = "tee-crafter-gpu-cc"
  }
}

resource "aws_route_table" "public" {
  count  = local.need_nat ? 1 : 0
  vpc_id = aws_vpc.deployment.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw[0].id
  }

  tags = {
    Name    = "tee-crafter-gpu-cc-public-rt"
    Project = "tee-crafter-gpu-cc"
  }
}

resource "aws_route_table_association" "public" {
  count          = local.need_nat ? 1 : 0
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_eip" "nat" {
  count  = local.need_nat ? 1 : 0
  domain = "vpc"

  tags = {
    Name    = "tee-crafter-gpu-cc-nat-eip"
    Project = "tee-crafter-gpu-cc"
  }
}

resource "aws_nat_gateway" "nat" {
  count         = local.need_nat ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name    = "tee-crafter-gpu-cc-nat-gw"
    Project = "tee-crafter-gpu-cc"
  }
}

resource "aws_route" "private_nat" {
  count                  = local.need_nat ? 1 : 0
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat[0].id
}

# --- VPC Flow Logs (deployment-scoped audit trail) ---

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/tee-crafter/gpu-cc-vpc-flow-logs/${random_id.bucket_suffix.hex}"
  retention_in_days = 30

  tags = {
    Project = "tee-crafter-gpu-cc"
  }
}

resource "aws_iam_role" "flow_log_role" {
  name_prefix = "tee-crafter-gpu-cc-flow-log-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })

  # Destroy this role (and the inline policy attached to it) BEFORE the log
  # group. Terraform only orders a destroy where a dependency exists, and
  # nothing previously tied the role to the group, so on teardown the delivery
  # service could still hold valid credentials at the moment the group was
  # deleted. See the comment on aws_iam_role_policy.flow_log_policy below.
  depends_on = [aws_cloudwatch_log_group.vpc_flow_logs]
}

# Deliberately WITHOUT logs:CreateLogGroup. Terraform creates the group above,
# so the delivery service never needs to create one -- and granting it leaked a
# log group on every single teardown.
#
# Measured on a real snp-aws deploy in us-east-2 on 2026-08-21 (the resource
# shape is identical in the nitro and gpu-cc templates, only the group name
# prefix differs), sampling the group's CreationTime every 20 seconds across
# `terraform destroy`:
#
#   00:37:45  /tee-crafter/snp-vpc-flow-logs/a97b3666  created=00:31:15  retention=30
#   00:38:05  /tee-crafter/snp-vpc-flow-logs/a97b3666  created=00:37:53  retention=null
#
# The CreationTime moved, so Terraform really did delete the group -- and the
# flow-log delivery service re-created it seconds later through CreateLogGroup,
# this time with no retention policy, meaning it never expires. The destroy
# still exited 0 and printed "Destroy complete", so the leak was invisible:
# 75 orphaned /tee-crafter/*vpc-flow-logs/* groups had piled up in the test
# account, the oldest dating back four months.
#
# A control stack with CreateLogGroup removed and the role ordered ahead of the
# group reached FlowLogStatus=ACTIVE / DeliverLogsStatus=SUCCESS and left
# nothing behind after destroy.
#
# Alternative considered and rejected: sweep leftover groups with
# DeleteLogGroup after `terraform destroy`. That treats the symptom, needs a
# new logs:DeleteLogGroup grant on the deployer, and still races the delivery
# service, which can re-create the group after the sweep has run.
#
# Writes are scoped to this deployment's own group. DescribeLogGroups has no
# resource-level form in IAM, so it stays on "*".
resource "aws_iam_role_policy" "flow_log_policy" {
  name_prefix = "tee-crafter-gpu-cc-flow-log-"
  role        = aws_iam_role.flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          aws_cloudwatch_log_group.vpc_flow_logs.arn,
          "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:DescribeLogGroups"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.deployment.id
  traffic_type             = "ALL"
  log_destination          = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_log_role.arn
  max_aggregation_interval = 60

  tags = {
    Name    = "tee-crafter-gpu-cc-vpc-flow-log"
    Project = "tee-crafter-gpu-cc"
  }
}

locals {
  did           = random_id.bucket_suffix.hex
  create_bucket = var.existing_deployment_bucket == ""
  create_iam    = var.existing_instance_profile_name == ""
  create_sg     = var.existing_security_group_id == ""
  create_vpce   = !var.skip_vpc_endpoints
}

# Ubuntu 22.04 LTS x86_64 base AMI, used only when no baked AMI is supplied.
#
# This lookup previously carried two extra filters when `require_nitro_tpm` was
# true (its default), and BOTH matched zero images, so the default deploy path
# could never resolve a base AMI at all. Verified against the live EC2 API in
# us-east-2 on 2026-08-20:
#
#   boot-mode = ["uefi"] (exact)  ->  0 images.  All 18 Canonical jammy amd64
#       AMIs report boot-mode `uefi-preferred`, which boots via UEFI. The
#       sibling snp/aws template already filtered on
#       ["uefi", "uefi-preferred"]; this one had drifted.
#   tpm-support = ["v2.0"]        ->  0 images, and not a transient gap:
#       Canonical publishes NO AMI of ANY release declaring tpm-support
#       (jammy and noble both return null), while 194 amazon-owned AMIs do.
#
# So NitroTPM cannot be obtained from a stock Canonical image. It is a property
# set when an AMI is *registered*, which means a baked AMI — consistent with
# the NitroTPM prerequisites recorded as tracker C5. Requiring it is therefore
# enforced by the postcondition below, which says so, instead of by a filter
# that silently matches nothing and fails with "your query returned no
# results".
data "aws_ami" "ubuntu" {
  # Skipped entirely when a baked AMI is supplied, so a NitroTPM deploy does
  # not depend on this lookup succeeding.
  count       = var.custom_ami_id == "" ? 1 : 0
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "boot-mode"
    values = ["uefi", "uefi-preferred"]
  }

  lifecycle {
    postcondition {
      # Fail closed and explain. Dropping the tpm-support filter without this
      # would silently launch a NitroTPM-less AMI while `require_nitro_tpm`
      # was true — trading an obscure error for a silent downgrade of the
      # CPU-side attestation this platform already struggles to provide.
      condition     = !var.require_nitro_tpm
      error_message = <<-EOT
        require_nitro_tpm is true but no custom_ami_id was supplied.

        NitroTPM v2.0 is a property set when an AMI is registered, and no
        Canonical Ubuntu AMI declares it (verified against the live EC2 API:
        zero Canonical images report tpm-support for any release). A stock
        base AMI therefore cannot satisfy this requirement.

        Either bake an attestable AMI and pass custom_ami_id, or set
        require_nitro_tpm = false to deploy without a hardware TPM — in which
        case CPU-side attestation degrades to host trust and the client will
        report GPU attestation only.
      EOT
    }
  }
}

# --- S3 Deployment Bucket ---

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "deployment_bucket" {
  count         = local.create_bucket ? 1 : 0
  bucket        = "tee-crafter-gpu-cc-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "deployment_bucket_versioning" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.deployment_bucket[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "deployment_bucket_public_access" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.deployment_bucket[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "bucket_key" {
  count                   = local.create_bucket ? 1 : 0
  description             = "SSE-KMS key for TEE-Crafter GPU CC deployment bucket"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags = {
    Project = "tee-crafter-gpu-cc"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "deployment_bucket_encryption" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.deployment_bucket[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.bucket_key[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "deployment_bucket_lifecycle" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.deployment_bucket[0].id

  rule {
    id     = "expire-deployment-artifacts"
    status = "Enabled"
    # An empty `filter {}` means "every object", which is what this rule always
    # meant. Omitting filter/prefix entirely made the AWS provider warn
    # "No attribute specified when one (and only one) of
    # [rule[0].filter, rule[0].prefix] is required. This will be an error in a
    # future version of the provider" — i.e. a provider bump inside the pinned
    # `~> 5.0` range would turn every AWS deploy's apply into a hard failure.
    # Surfaced by the first `terraform plan` ever run against live AWS.
    filter {}
    expiration {
      days = 1
    }
  }
}

resource "aws_s3_bucket_policy" "deployment_bucket_ssl_only" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.deployment_bucket[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.deployment_bucket[0].arn,
          "${aws_s3_bucket.deployment_bucket[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.deployment_bucket_public_access]
}

# --- Managed Prefix Lists ---

data "aws_prefix_list" "s3" {
  filter {
    name   = "prefix-list-name"
    values = ["com.amazonaws.${var.aws_region}.s3"]
  }
}

# CloudFront origin-facing prefix list: NVIDIA NRAS
# (nras.attestation.nvidia.com) is fronted by CloudFront, so egress to this
# managed list is strictly narrower than 0.0.0.0/0.  This is used as the
# default egress target for NRAS when `nras_egress_cidrs` is not provided.
data "aws_ec2_managed_prefix_list" "cloudfront_origin_facing" {
  count = var.allow_nras_egress && length(var.nras_egress_cidrs) == 0 ? 1 : 0
  name  = "com.amazonaws.global.cloudfront.origin-facing"
}

locals {
  nras_uses_managed_prefix = var.allow_nras_egress && length(var.nras_egress_cidrs) == 0
  nras_uses_explicit_cidrs = var.allow_nras_egress && length(var.nras_egress_cidrs) > 0
}

# --- Security Group: Zero ingress, minimal egress ---

resource "aws_security_group" "gpu_cc_sg" {
  count       = local.create_sg ? 1 : 0
  name_prefix = "tee-crafter-gpu-cc-sg-"
  description = "GPU CC VM: no ingress, narrowly scoped egress"
  vpc_id      = aws_vpc.deployment.id

  # Default intra-VPC HTTPS (for SSM/KMS VPC endpoints that sit inside the
  # VPC CIDR).  NRAS and setup egress are added via the dedicated rules
  # below so auditors see each external destination on its own line.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.deployment.cidr_block]
    description = "HTTPS to in-VPC endpoints (SSM, KMS, SSMMessages, EC2Messages)"
  }

  egress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_prefix_list.s3.id]
    description     = "HTTPS to S3 via Gateway endpoint"
  }

  # NVIDIA NRAS attestation egress — narrowly scoped.
  # Preferred: user provides explicit NVIDIA CIDRs in var.nras_egress_cidrs.
  # Fallback: AWS managed prefix list for CloudFront origin-facing IPs
  # (NVIDIA NRAS is fronted by CloudFront).  The NRAS rules below are never
  # 0.0.0.0/0.  That is a statement about NRAS only: the setup-phase rules
  # further down DO open 80/443 to 0.0.0.0/0, gated on
  # `var.allow_setup_egress` (default false).
  dynamic "egress" {
    for_each = local.nras_uses_explicit_cidrs ? [1] : []
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = var.nras_egress_cidrs
      description = "HTTPS to NVIDIA NRAS (explicit CIDR allowlist)"
    }
  }

  dynamic "egress" {
    for_each = local.nras_uses_managed_prefix ? [1] : []
    content {
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront_origin_facing[0].id]
      description     = "HTTPS to NVIDIA NRAS via CloudFront origin-facing prefix list"
    }
  }

  # Setup-phase egress (package repos + NVIDIA driver stack).  Opens 80/443
  # to 0.0.0.0/0 and is only present when the operator explicitly sets
  # allow_setup_egress=true.
  #
  # NOTHING ENFORCES THE LOCKDOWN.  Closing this back up is a manual step:
  # after baking the AMI, re-apply with `-var='allow_setup_egress=false'` and
  # confirm `terraform output setup_egress_mode` reads "locked-down".  The CLI
  # prints a reminder when it notices it opened this
  # (`remind_post_bake_lockdown` in
  # cli/deployment/common/wheel_manager.py) — that is a console panel, not a
  # control.  There is no `post_bake_lockdown` Terraform resource; an earlier
  # version of this comment claimed there was.
  dynamic "egress" {
    for_each = var.allow_setup_egress ? [1] : []
    content {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTP for package repos during setup (bake-time only)"
    }
  }
  dynamic "egress" {
    for_each = var.allow_setup_egress ? [1] : []
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTPS for package repos during setup (bake-time only)"
    }
  }

  # SIEM egress allowlist (continuous-attestation export to a public
  # collector).  Auto-set by the CLI when --siem-egress-cidr is passed.
  dynamic "egress" {
    for_each = length(var.siem_egress_cidrs) > 0 ? var.siem_egress_ports : []
    content {
      from_port   = egress.value
      to_port     = egress.value
      protocol    = "tcp"
      cidr_blocks = var.siem_egress_cidrs
      description = "SIEM egress allowlist (port ${egress.value})"
    }
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [aws_vpc.deployment.cidr_block]
    description = "DNS (UDP) restricted to VPC resolver"
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.deployment.cidr_block]
    description = "DNS (TCP) restricted to VPC resolver"
  }

  tags = {
    Name    = "tee-crafter-gpu-cc-sg-${local.did}"
    Project = "tee-crafter-gpu-cc"
  }
}

# --- VPC Endpoints ---

locals {
  subnet_id = var.subnet_id != "" ? var.subnet_id : aws_subnet.private.id

  instance_profile_name  = local.create_iam ? aws_iam_instance_profile.gpu_cc_profile[0].name : var.existing_instance_profile_name
  security_group_id      = local.create_sg ? aws_security_group.gpu_cc_sg[0].id : var.existing_security_group_id
  enclave_role_arn       = local.create_iam ? aws_iam_role.gpu_cc_role[0].arn : var.existing_enclave_role_arn
  deployment_bucket_name = local.create_bucket ? aws_s3_bucket.deployment_bucket[0].id : var.existing_deployment_bucket
  deployment_bucket_arn  = local.create_bucket ? aws_s3_bucket.deployment_bucket[0].arn : "arn:aws:s3:::${var.existing_deployment_bucket}"
}

# --- VPC endpoint policies (scope each endpoint to THIS deployment) ---
#
# A VPC endpoint created without a `policy` argument gets the AWS default
# "full access" document: every principal that can reach the endpoint may
# call every action of that service against **any** resource, in **any**
# AWS account.  The security group cannot help -- our key and an attacker's
# key are reached at the same endpoint IP -- so a compromised workload could
# encrypt under a foreign key and ship the ciphertext out through the same
# private path we opened to reach our own.
#
# Each document below pins the principal to the role this deployment runs
# under, and (where the service supports resource-level policy) pins the
# resources to the ones this deployment created.
#
# The policies are only attached when we know the role ARN.  When the
# operator supplies `existing_instance_profile_name` but leaves
# `existing_enclave_role_arn` empty we cannot name a principal, so we fall
# back to the AWS default rather than emit an invalid document -- that
# combination is reported in the `vpc_endpoint_policy_mode` output.
locals {
  endpoint_policy_principal = local.enclave_role_arn
  endpoint_policies_active  = local.endpoint_policy_principal != ""

  # Restrict the endpoint to our role by CONDITION, not by Principal.
  # `CreateVpcEndpoint` existence-checks a named Principal and the role is
  # created in this same apply, so IAM propagation made every endpoint fail
  # with `InvalidPolicyDocument: UnknownError`.  Condition values are not
  # existence-checked and `aws:PrincipalArn` is equivalent in effect.  See the
  # matching comment in snp/aws and nitro, and
  # tests/core/test_s3_gateway_endpoint_policy.py for the live proof.
  endpoint_principal_condition = {
    ArnEquals = { "aws:PrincipalArn" = local.endpoint_policy_principal }
  }

  # Keys reachable through the KMS interface endpoint: the deployment
  # bucket's SSE-KMS key and (for `--byok aws-kms`) the customer key.
  # `compact` drops the empty BYOK ARN when BYOK is off, and the `[*]` splat
  # yields `[]` when the bucket key is not created.
  kms_endpoint_key_arns = compact(concat(
    aws_kms_key.bucket_key[*].arn,
    [var.byok_aws_kms_arn],
  ))

  kms_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DeploymentKeysOnly"
      Effect    = "Allow"
      Principal = "*"
      Condition = local.endpoint_principal_condition
      Action = [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:DescribeKey",
      ]
      Resource = local.kms_endpoint_key_arns
    }]
  })

  # SSM / SSMMessages / EC2Messages take no resource-level scoping that is
  # meaningful here (Session Manager's control- and data-channel actions are
  # `*`-resource APIs), so the narrowing these policies buy is on the
  # principal: only this deployment's instance role may use the endpoint.
  ssm_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DeploymentRoleOnly"
      Effect    = "Allow"
      Principal = "*"
      Condition = local.endpoint_principal_condition
      Action = [
        "ssm:DescribeAssociation",
        "ssm:GetDeployablePatchSnapshotForInstance",
        "ssm:GetDocument",
        "ssm:DescribeDocument",
        "ssm:GetManifest",
        "ssm:ListAssociations",
        "ssm:ListInstanceAssociations",
        "ssm:PutInventory",
        "ssm:PutComplianceItems",
        "ssm:PutConfigurePackageResult",
        "ssm:UpdateAssociationStatus",
        "ssm:UpdateInstanceAssociationStatus",
        "ssm:UpdateInstanceInformation",
      ]
      Resource = "*"
    }]
  })

  ssmmessages_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DeploymentRoleOnly"
      Effect    = "Allow"
      Principal = "*"
      Condition = local.endpoint_principal_condition
      Action = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
      ]
      Resource = "*"
    }]
  })

  ec2messages_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DeploymentRoleOnly"
      Effect    = "Allow"
      Principal = "*"
      Condition = local.endpoint_principal_condition
      Action = [
        "ec2messages:AcknowledgeMessage",
        "ec2messages:DeleteMessage",
        "ec2messages:FailMessage",
        "ec2messages:GetEndpoint",
        "ec2messages:GetMessages",
        "ec2messages:SendReply",
      ]
      Resource = "*"
    }]
  })

  # CloudWatch Logs endpoint: only the SIEM log group this deployment was
  # told to write to.  Wildcards to the account's log groups when the
  # operator did not name one (the endpoint is only created on request).
  siem_logs_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DeploymentSiemLogGroupOnly"
      Effect    = "Allow"
      Principal = "*"
      Condition = local.endpoint_principal_condition
      Action = [
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents",
      ]
      Resource = var.siem_cloudwatch_log_group != "" ? [
        "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${var.siem_cloudwatch_log_group}:*"
        ] : [
        "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"
      ]
    }]
  })

  # S3 gateway endpoint.  Two statements, and both are load-bearing:
  #
  #  1. This deployment's bucket, for the instance role only.
  #  2. The AWS-managed buckets SSM Agent reads.  AWS documents these as a
  #     hard requirement when SSM traffic goes through a VPC endpoint --
  #     "Your VPC endpoint policy must allow access to at least the Amazon S3
  #     buckets listed in SSM Agent communications with AWS managed S3
  #     buckets" (Systems Manager User Guide, "Improve the security of EC2
  #     instances by using VPC endpoints for Systems Manager"; bucket list in
  #     "SSM Agent communications with AWS managed S3 buckets").  Drop these
  #     and SSM Agent self-update silently stops working.
  #
  #  3. On the `allow_setup_egress = true` path only, `s3:GetObject` on any
  #     bucket -- see below.
  #
  # `allow_setup_egress = true` covers first-boot package installs on an unbaked
  # AMI (which on this platform also pulls the NVIDIA driver stack) *and* the NAT
  # path that `--siem` export takes.  cloud-init pulls packages from S3-backed
  # repo mirrors whose bucket names are region- and distro-version-specific, so
  # enumerating them here would rot; a partial allowlist fails the bake in a way
  # that looks like a network problem.  The policy used to be detached entirely
  # in that case, which also dropped the `aws:PrincipalArn` condition -- and at a
  # *gateway* endpoint that condition is the control that matters, because it
  # governs **who** may use the endpoint rather than whether egress exists.
  # Detaching therefore let any principal in the VPC reach this deployment's
  # artifact bucket through the endpoint, and an operator who added `--siem` lost
  # that control with no indication.  So the policy now stays attached in both
  # modes and only the *reads* widen; writes remain scoped to this deployment's
  # bucket either way.
  # NOTE: this policy scopes the principal with a `aws:PrincipalArn` *condition*
  # rather than the `Principal` element, unlike every interface-endpoint policy
  # above.  That asymmetry is deliberate and load-bearing — do not "tidy" it.
  #
  # An EC2 instance calls S3 as an assumed-role session
  # (`arn:aws:sts::<acct>:assumed-role/<role>/<instance-id>`).  In an *interface*
  # endpoint policy, `Principal = { AWS = "<role-arn>" }` matches that session,
  # which is why the KMS/SSM/SSMMessages/EC2Messages policies work.  In an S3
  # *gateway* endpoint policy it does **not**: every request was refused with
  #
  #   is not authorized to perform: s3:ListBucket ... because no VPC endpoint
  #   policy allows the s3:ListBucket action
  #
  # even though the role ARN, actions and resources were all correct.  Measured
  # on a live deploy (2026-08-20): `aws s3 cp` of the EIF failed with HeadObject
  # 403 on all 3 retries; swapping to the form below made the same command
  # succeed at 37 MiB/s, with a KMS `generate-random` control call through the
  # *interface* endpoint succeeding under the role-ARN principal throughout.
  #
  # `aws:PrincipalArn` resolves to the **role** ARN for a role session, not the
  # session ARN, so the scoping stays exactly as tight as before: only this
  # deployment's enclave role.  This is also the form AWS documents for
  # granting a role access through an S3 gateway endpoint:
  #   https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html
  #   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
  s3_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "DeploymentBucket"
          Effect    = "Allow"
          Principal = "*"
          Action = [
            "s3:GetObject",
            "s3:ListBucket",
            "s3:PutObject",
            "s3:AbortMultipartUpload",
          ]
          Resource = [
            local.deployment_bucket_arn,
            "${local.deployment_bucket_arn}/*",
          ]
          Condition = {
            ArnEquals = { "aws:PrincipalArn" = local.endpoint_policy_principal }
          }
        },
        {
          Sid       = "SsmAgentManagedBuckets"
          Effect    = "Allow"
          Principal = "*"
          Action    = "s3:GetObject"
          Resource = [
            "arn:aws:s3:::amazon-ssm-${var.aws_region}/*",
            "arn:aws:s3:::aws-ssm-${var.aws_region}/*",
            "arn:aws:s3:::${var.aws_region}-birdwatcher-prod/*",
            "arn:aws:s3:::patch-baseline-snapshot-${var.aws_region}/*",
          ]
          Condition = {
            ArnEquals = { "aws:PrincipalArn" = local.endpoint_policy_principal }
          }
        },
      ],
      # Setup / NAT path only.  Reads widen to any bucket; the principal
      # condition and the write scoping above both stay exactly as they are.
      var.allow_setup_egress ? [
        {
          Sid       = "SetupPackageRepoReads"
          Effect    = "Allow"
          Principal = "*"
          Action    = "s3:GetObject"
          Resource  = "*"
          Condition = {
            ArnEquals = { "aws:PrincipalArn" = local.endpoint_policy_principal }
          }
        },
      ] : []
    )
  })
}

resource "aws_security_group" "vpce_sg" {
  count       = local.create_vpce ? 1 : 0
  name_prefix = "tee-crafter-gpu-cc-vpce-sg-"
  description = "Allow HTTPS from VPC to shared Interface endpoints"
  vpc_id      = aws_vpc.deployment.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.deployment.cidr_block]
    description = "HTTPS from VPC CIDR"
  }
}

resource "aws_vpc_endpoint" "ssm" {
  count               = local.create_vpce ? 1 : 0
  vpc_id              = aws_vpc.deployment.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [local.subnet_id]
  security_group_ids  = [aws_security_group.vpce_sg[0].id]
  policy              = local.endpoint_policies_active ? local.ssm_endpoint_policy : null
}

resource "aws_vpc_endpoint" "ssmmessages" {
  count               = local.create_vpce ? 1 : 0
  vpc_id              = aws_vpc.deployment.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [local.subnet_id]
  security_group_ids  = [aws_security_group.vpce_sg[0].id]
  policy              = local.endpoint_policies_active ? local.ssmmessages_endpoint_policy : null
}

resource "aws_vpc_endpoint" "ec2messages" {
  count               = local.create_vpce ? 1 : 0
  vpc_id              = aws_vpc.deployment.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [local.subnet_id]
  security_group_ids  = [aws_security_group.vpce_sg[0].id]
  policy              = local.endpoint_policies_active ? local.ec2messages_endpoint_policy : null
}

resource "aws_vpc_endpoint" "s3_gateway" {
  count             = var.create_s3_gateway_endpoint ? 1 : 0
  vpc_id            = aws_vpc.deployment.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  policy            = local.endpoint_policies_active ? local.s3_endpoint_policy : null
}

# --- AWS KMS Interface Endpoint (BYOK attested-release path) ---
#
# Created when --byok aws-kms is in play (byok_aws_kms_arn set).  The in-TEE
# `tee-crafter-secrets` oneshot calls kms:Decrypt at boot to release the
# customer DEK / unseal the .env.  On a locked-down VPC (deny-all egress, no
# NAT) there is no public route to KMS, so without this private endpoint the
# release hangs and the workload never starts (fail-closed).
resource "aws_vpc_endpoint" "kms" {
  count               = var.byok_aws_kms_arn != "" && local.create_vpce ? 1 : 0
  vpc_id              = aws_vpc.deployment.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [local.subnet_id]
  security_group_ids  = [aws_security_group.vpce_sg[0].id]

  # Endpoint policy: this ENI exists to reach exactly the keys this
  # deployment owns.  AWS applies a full-access policy when `policy` is
  # omitted, so without this any principal that can reach the ENI from inside
  # the VPC could call any KMS API against any key in any account (subject to
  # IAM / key policy).  Scoping it here bounds the blast radius of a
  # compromised workload at the network layer, which is the whole point of
  # having a private endpoint for a single-key path.
  #
  # `local.kms_endpoint_policy` additionally pins the *principal* to this
  # deployment's instance role; the earlier version of this block used
  # `Principal = "*"`, which left any identity reachable from the VPC free to
  # use the endpoint against the BYOK key.
  policy = local.endpoint_policies_active ? local.kms_endpoint_policy : null

  tags = {
    Name    = "tee-crafter-gpu-cc-byok-kms-vpce"
    Project = "tee-crafter"
  }
}

# --- SIEM CloudWatch Logs Interface Endpoint (private SIEM path) ---
resource "aws_vpc_endpoint" "siem_logs" {
  count               = var.siem_provision_logs_endpoint && local.create_vpce ? 1 : 0
  vpc_id              = aws_vpc.deployment.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [local.subnet_id]
  security_group_ids  = [aws_security_group.vpce_sg[0].id]
  policy              = local.endpoint_policies_active ? local.siem_logs_endpoint_policy : null

  tags = {
    Name    = "tee-crafter-gpu-cc-siem-logs-vpce"
    Project = "tee-crafter"
    Purpose = "siem-egress-private"
  }
}

# --- IAM ---

resource "aws_iam_role" "gpu_cc_role" {
  count       = local.create_iam ? 1 : 0
  name_prefix = "tee-crafter-gpu-cc-role-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = { Project = "tee-crafter-gpu-cc" }
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  count      = local.create_iam ? 1 : 0
  role       = aws_iam_role.gpu_cc_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "gpu_cc_policy" {
  count       = local.create_iam ? 1 : 0
  name_prefix = "tee-crafter-gpu-cc-policy-"
  role        = aws_iam_role.gpu_cc_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid = "S3DeploymentBucketReadOnly"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect = "Allow"
        Resource = [
          local.deployment_bucket_arn,
          "${local.deployment_bucket_arn}/*"
        ]
      },
      {
        Sid = "S3BatchOutputWrite"
        Action = [
          "s3:PutObject",
          "s3:AbortMultipartUpload"
        ]
        Effect = "Allow"
        Resource = [
          "${local.deployment_bucket_arn}/batch-output/*"
        ]
      },
      {
        Sid      = "KMSGenerateRandom"
        Action   = "kms:GenerateRandom"
        Effect   = "Allow"
        Resource = "*"
      }
      ],
      local.create_bucket ? [{
        Sid = "KMSBucketKeyDataPlane"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Effect   = "Allow"
        Resource = aws_kms_key.bucket_key[0].arn
    }] : [])
  })
}

resource "aws_iam_instance_profile" "gpu_cc_profile" {
  count       = local.create_iam ? 1 : 0
  name_prefix = "tee-crafter-gpu-cc-profile-"
  role        = aws_iam_role.gpu_cc_role[0].name
}

# Least-privilege CloudWatch Logs PutEvents grant for the SIEM exporter
# running inside the TEE.
resource "aws_iam_role_policy" "gpu_cc_siem_cloudwatch_logs" {
  count       = local.create_iam && var.siem_cloudwatch_log_group != "" ? 1 : 0
  name_prefix = "tee-crafter-gpu-cc-siem-logs-"
  role        = aws_iam_role.gpu_cc_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SiemCloudWatchPut"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ]
      Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${var.siem_cloudwatch_log_group}:*"
    }]
  })
}

# BYOK kms:Decrypt grant — see nitro/main.template.tf for the
# canonical comment block.  Created only when var.byok_aws_kms_arn
# is non-empty.
resource "aws_iam_role_policy" "gpu_cc_byok_kms_decrypt" {
  count       = local.create_iam && var.byok_aws_kms_arn != "" ? 1 : 0
  name_prefix = "tee-crafter-gpu-cc-byok-decrypt-"
  role        = aws_iam_role.gpu_cc_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ByokKmsDecrypt"
      Effect = "Allow"
      Action = [
        "kms:Decrypt",
        "kms:DescribeKey"
      ]
      Resource = var.byok_aws_kms_arn
    }]
  })
}

# --- GPU CC Instance (P5/P5en/P6 + NitroTPM) ---

resource "aws_instance" "gpu_cc_spot" {
  count         = var.use_spot_instance ? 1 : 0
  ami           = var.custom_ami_id != "" ? var.custom_ami_id : one(data.aws_ami.ubuntu[*].id)
  instance_type = var.instance_type

  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [local.security_group_id]
  iam_instance_profile        = local.instance_profile_name
  associate_public_ip_address = false

  instance_market_options {
    market_type = "spot"
    spot_options {
      instance_interruption_behavior = "terminate"
    }
  }

  # NitroTPM v2.0: enforced by the postcondition on data.aws_ami.ubuntu,
  # which requires a baked custom_ami_id (no Canonical AMI declares
  # tpm-support). The old comment claimed a tpm-support filter enforced
  # it; that filter matched zero images.
  # not aws_instance.tpm_support (unsupported by the AWS provider).

  # Nitro Enclaves are explicitly disabled here: GPU CC deployments do not
  # use the enclave fabric (there is no GPU passthrough to enclaves).
  enclave_options {
    enabled = false
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_size           = 200
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  depends_on = [aws_vpc_endpoint.ssm, aws_vpc_endpoint.ssmmessages, aws_vpc_endpoint.ec2messages, aws_vpc_endpoint.s3_gateway, aws_vpc_endpoint.kms]

  tags = {
    Name         = "TEECrafterGPUCC-Spot-${local.did}"
    Project      = "tee-crafter-gpu-cc"
    DeploymentId = local.did
    TEE          = var.require_nitro_tpm ? "NitroTPM-NVIDIA-CC" : "NVIDIA-CC-only"
  }
}

resource "aws_instance" "gpu_cc_ondemand" {
  count         = var.use_spot_instance ? 0 : 1
  ami           = var.custom_ami_id != "" ? var.custom_ami_id : one(data.aws_ami.ubuntu[*].id)
  instance_type = var.instance_type

  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [local.security_group_id]
  iam_instance_profile        = local.instance_profile_name
  associate_public_ip_address = false

  enclave_options {
    enabled = false
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_size           = 200
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  depends_on = [aws_vpc_endpoint.ssm, aws_vpc_endpoint.ssmmessages, aws_vpc_endpoint.ec2messages, aws_vpc_endpoint.s3_gateway, aws_vpc_endpoint.kms]

  tags = {
    Name         = "TEECrafterGPUCC-OnDemand-${local.did}"
    Project      = "tee-crafter-gpu-cc"
    DeploymentId = local.did
    TEE          = var.require_nitro_tpm ? "NitroTPM-NVIDIA-CC" : "NVIDIA-CC-only"
  }
}

# --- Outputs ---

# The IAM role the instance actually runs as.  Exposed because BYOK key-policy
# pinning needs it *during* the deploy: the role name carries a per-deploy
# suffix, so the exact ARN cannot be known when the KMS key is created.  Until
# this existed the only way to read it was
# `terraform state show 'aws_iam_role.snp_role[0]'`, which is why
# byok-sandbox/aws/create_kms_key.py still documents that as the manual route.
output "instance_role_arn" {
  value = local.enclave_role_arn
}

output "instance_id" {
  value = var.use_spot_instance ? aws_instance.gpu_cc_spot[0].id : aws_instance.gpu_cc_ondemand[0].id
}

output "private_ip" {
  value = var.use_spot_instance ? aws_instance.gpu_cc_spot[0].private_ip : aws_instance.gpu_cc_ondemand[0].private_ip
}

output "deployment_bucket" {
  value = local.deployment_bucket_name
}

output "measurement" {
  value = var.measurement
}

output "vpc_id" {
  value = aws_vpc.deployment.id
}

output "vpc_flow_log_group" {
  value = aws_cloudwatch_log_group.vpc_flow_logs.name
}

output "vpc_endpoint_policy_mode" {
  value = (
    !local.endpoint_policies_active ? "aws-default (no role ARN known: set existing_enclave_role_arn alongside existing_instance_profile_name)" :
    var.allow_setup_egress ? "scoped (S3 gateway reads widened to any bucket for setup egress; principal still pinned to this deployment's role)" :
    "scoped"
  )
  description = "Whether the VPC endpoints carry a deployment-scoped endpoint policy. 'scoped' means every endpoint is pinned to this deployment's instance role, and KMS/S3/Logs are additionally pinned to this deployment's keys, bucket and log group. 'aws-default' means AWS's permit-everything default is in force, which lets anything in this VPC reach any account's resources for that service."
}

output "security_group_id" {
  value = local.security_group_id
}

output "nitro_tpm_enabled" {
  value       = var.require_nitro_tpm
  description = "True when the instance provisions NitroTPM v2.0 for CPU-side attestation."
}

output "nras_egress_mode" {
  value = (
    !var.allow_nras_egress ? "denied" :
    local.nras_uses_explicit_cidrs ? "explicit-cidrs" :
    "cloudfront-prefix-list"
  )
  description = "Which egress rule governs NRAS attestation traffic."
}

output "setup_egress_mode" {
  value       = var.allow_setup_egress ? "open-for-setup" : "locked-down"
  description = "NET-1: post-bake egress lockdown state (open-for-setup means a NAT gateway is attached and package-repo egress is permitted; locked-down means only attestation-scoped egress remains)."
}

output "secure_boot_mode" {
  value       = "off (gpu-cc-aws — NVIDIA proprietary DKMS driver is not signed by any vendor UEFI key)"
  description = "UEFI Secure Boot is intentionally OFF on gpu-cc-aws.  Enabling SB would prevent the NVIDIA Open / proprietary kernel modules from loading at boot, which in turn breaks GPU attestation.  Trust on this platform is anchored by NitroTPM + NVIDIA NRAS (driver-level attestation) instead of UEFI SB.  See docs/gpu_flow.md."
}

# DEP-005: structured evidence that the launched instance has IMDSv2
# *required*.  Both ``aws_instance`` blocks above set
# ``http_tokens = "required"`` unconditionally, so this output is a
# fixed ``true``.  If a future edit downgrades to ``optional`` this
# output should be wired off the actual resource value.
output "imdsv2_required_only" {
  value       = true
  description = "DEP-005: true means every launched instance enforces IMDSv2 (http_tokens=required, hop_limit=1, http_endpoint=enabled)."
}
