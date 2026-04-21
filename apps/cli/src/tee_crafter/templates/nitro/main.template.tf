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

# Batch mode marker.  Substituted by the orchestrator at apply-time when the
# operator passes --batch.  The literal string lives in a local so anyone
# auditing the planned graph can trivially see whether this build will run as
# the long-running RA-TLS service ("false") or as a one-shot batch job that
# streams output back over vsock 5006 ("true").  Vsock-proxy allowlist entries
# only govern outbound enclave→KMS forwarding, so no firewall changes are
# required for inbound batch streaming on port 5006.
locals {
  batch_mode = "__BATCH_MODE__"
}

provider "aws" {
  region = var.aws_region
}

# --- Variables ---

variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "instance_type" {
  type    = string
  default = "__INSTANCE_TYPE__"
}

variable "allocator_mb" {
  type    = number
  default = __ALLOCATOR_MB__
}

variable "cpu_count" {
  type    = number
  default = __CPU_COUNT__
}

variable "subnet_id" {
  type        = string
  default     = ""
  description = "Target subnet. If empty, uses the first subnet of the default VPC."
}

variable "create_kms_vpc_endpoint" {
  type        = bool
  default     = true
  description = "Whether to create a KMS VPC endpoint. Set to false if one already exists in the VPC."
}

variable "create_s3_gateway_endpoint" {
  type        = bool
  default     = true
  description = "Create an S3 Gateway VPC endpoint for private S3 access (free). Set false if one already exists."
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

variable "custom_ami_id" {
  type        = string
  default     = ""
  description = "Custom AMI with pre-baked dependencies. Overrides base AMI and skips user_data when set."
}

variable "ami_architecture" {
  type        = string
  default     = "__AMI_ARCH__"
  description = "CPU architecture for the base AMI lookup: arm64 (Graviton) or x86_64."
}

variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block for the per-deployment VPC. Each deployment gets its own isolated VPC."
}

# PCR Hash variables (populated by the Python Agent)
variable "pcr0_hash" { type = string }
variable "pcr1_hash" { type = string }
variable "pcr2_hash" { type = string }

# --- Pre-existing resource variables (one-time admin setup) ---

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
  description = "Skip all VPC endpoint creation (SSM, KMS, S3). Set true when endpoints already exist in the VPC."
}

variable "existing_instance_profile_name" {
  type        = string
  default     = ""
  description = "Pre-created IAM Instance Profile name. Skips IAM role/profile/policy creation when set."
}

variable "existing_enclave_role_arn" {
  type        = string
  default     = ""
  description = "ARN of the pre-created enclave IAM role. Required when existing_instance_profile_name is set (used in KMS key policy)."
}

variable "existing_security_group_id" {
  type        = string
  default     = ""
  description = "Pre-created Security Group ID for the enclave host. Skips SG creation when set."
}

variable "existing_deployment_bucket" {
  type        = string
  default     = ""
  description = "Pre-created S3 bucket name for deployment artifacts. Skips bucket creation when set. Admin should configure SSE-KMS on this bucket."
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

# BYOK on AWS KMS (boot-time release path).
# When this is set to a customer-owned KMS key ARN, the deployed instance's
# IAM role gets least-privilege kms:Decrypt + kms:DescribeKey on that ARN.
# This is what unlocks the in-enclave "bootstrap_byok_release" flow: the
# enclave hands its attestation document to a sigv4-signed kms:Decrypt
# call via the host proxy, the KMS key policy validates the PCR set, and
# only then unwraps the DEK.  Leave empty for the alternative "smoke"
# flow (operator forwards short-lived STS creds with the request).
# Pair with the BYOK key policy that pins this role's ARN as a
# Decrypt principal AND requires PCR matches in the encryption context.
variable "byok_aws_kms_arn" {
  type        = string
  default     = ""
  description = "Optional customer KMS key ARN to grant the enclave instance role kms:Decrypt on (for --byok aws-kms boot-time release).  Empty (default) leaves IAM untouched."
}

# UEFI Secure Boot — for nitro-aws this is an *AMI property* baked into
# Image.UefiData at bake time (`bake-ami --tee-platform nitro-aws` enrolls
# /usr/share/amazon-linux-sb-keys into the bake instance's UEFI NVRAM by
# default; `aws ec2 create-image` then captures it).  This Terraform
# variable does NOT enable SB at apply time — it asserts the AMI is SB-baked
# and gates the launch via a precondition so a misconfigured deploy fails
# fast instead of silently producing a deployment whose attestation posture
# doesn't match the operator's stated intent.
# Defaults to TRUE since 2026 — Secure Boot is the assumed posture for every
# non-GPU TEE-Crafter platform.  The deploy validators auto-set this from
# the AMI tag, and the bake CLI defaults to enrolling SB keys.  To deploy a
# non-SB AMI (legacy unbaked dev workflow), set TF_VAR_enable_secure_boot=false
# and use TEE_CRAFTER_ALLOW_UNBAKED_BASE_AMI=1.
variable "enable_secure_boot" {
  type        = bool
  default     = true
  description = "Assert that the AMI being launched has UEFI Secure Boot keys pre-enrolled (bake with `bake-ami --tee-platform nitro-aws`; on by default). When true, the instance precondition fails fast unless the AMI carries the `tee-crafter-secure-boot=enabled` tag. Set to false explicitly only for legacy unbaked dev AMIs."
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
    Name         = "tee-crafter-enclave-vpc-${local.did}"
    Project      = "tee-crafter"
    DeploymentId = local.did
  }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.deployment.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name    = "tee-crafter-private-subnet"
    Project = "tee-crafter"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.deployment.id

  tags = {
    Name    = "tee-crafter-private-rt"
    Project = "tee-crafter"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# NAT gateway for setup egress (package installs on first boot)

resource "aws_subnet" "public" {
  count                   = var.allow_setup_egress ? 1 : 0
  vpc_id                  = aws_vpc.deployment.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name    = "tee-crafter-public-subnet"
    Project = "tee-crafter"
  }
}

resource "aws_internet_gateway" "igw" {
  count  = var.allow_setup_egress ? 1 : 0
  vpc_id = aws_vpc.deployment.id

  tags = {
    Name    = "tee-crafter-igw"
    Project = "tee-crafter"
  }
}

resource "aws_route_table" "public" {
  count  = var.allow_setup_egress ? 1 : 0
  vpc_id = aws_vpc.deployment.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw[0].id
  }

  tags = {
    Name    = "tee-crafter-public-rt"
    Project = "tee-crafter"
  }
}

resource "aws_route_table_association" "public" {
  count          = var.allow_setup_egress ? 1 : 0
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_eip" "nat" {
  count  = var.allow_setup_egress ? 1 : 0
  domain = "vpc"

  tags = {
    Name    = "tee-crafter-nat-eip"
    Project = "tee-crafter"
  }
}

resource "aws_nat_gateway" "nat" {
  count         = var.allow_setup_egress ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name    = "tee-crafter-nat-gw"
    Project = "tee-crafter"
  }
}

resource "aws_route" "private_nat" {
  count                  = var.allow_setup_egress ? 1 : 0
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat[0].id
}

# --- VPC Flow Logs (deployment-scoped audit trail) ---

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/tee-crafter/vpc-flow-logs/${random_id.bucket_suffix.hex}"
  retention_in_days = 30

  tags = {
    Project = "tee-crafter"
  }
}

resource "aws_iam_role" "flow_log_role" {
  name_prefix = "tee-crafter-flow-log-"

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
  name_prefix = "tee-crafter-flow-log-"
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
    Name    = "tee-crafter-vpc-flow-log"
    Project = "tee-crafter"
  }
}

locals {
  ami_arch_suffix = var.ami_architecture == "arm64" ? "arm64" : "x86_64"
  did             = random_id.bucket_suffix.hex

  create_bucket = var.existing_deployment_bucket == ""
  create_iam    = var.existing_instance_profile_name == ""
  create_sg     = var.existing_security_group_id == ""
  create_vpce   = !var.skip_vpc_endpoints
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-*-${local.ami_arch_suffix}"]
  }
  filter {
    name   = "architecture"
    values = [var.ami_architecture]
  }
  # Force a UEFI-capable AL2023 AMI when SB is asserted (defense in depth
  # against any future legacy-BIOS AL2023 channel; current AL2023 ships
  # uefi-preferred so this filter is a no-op today).
  dynamic "filter" {
    for_each = var.enable_secure_boot ? [1] : []
    content {
      name   = "boot-mode"
      values = ["uefi", "uefi-preferred"]
    }
  }
}

# When `enable_secure_boot = true`, fetch the custom AMI tags so the
# instance precondition can confirm it was baked with the
# `tee-crafter-secure-boot=enabled` tag from `bake-ami --enable-secure-boot`.
data "aws_ami" "custom_for_sb_check" {
  count       = var.enable_secure_boot && var.custom_ami_id != "" ? 1 : 0
  most_recent = false
  owners      = ["self"]
  filter {
    name   = "image-id"
    values = [var.custom_ami_id]
  }
}

# --- S3 Deployment Bucket ---

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "deployment_bucket" {
  count         = local.create_bucket ? 1 : 0
  bucket        = "tee-crafter-deployment-${random_id.bucket_suffix.hex}"
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
  description             = "SSE-KMS key for TEE-Crafter deployment bucket"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags = {
    Project = "tee-crafter"
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

# --- S3 Prefix List (for Gateway endpoint egress) ---

data "aws_prefix_list" "s3" {
  filter {
    name   = "prefix-list-name"
    values = ["com.amazonaws.${var.aws_region}.s3"]
  }
}

# --- Nitro-1: KMS IP range allowlist hint (optional, opt-in) ---
# The primary KMS egress constraint for tee-crafter is the VPC
# Interface endpoint (`aws_vpc_endpoint.kms` below): the host SG's
# 443/tcp egress is already restricted to `aws_vpc.deployment.cidr_block`
# when `allow_setup_egress = false`, so only the VPC-local endpoint is
# reachable.  This data source is kept as a defense-in-depth reference
# for operators who run tee-crafter in a shared VPC without an
# interface endpoint — they can consume `data.aws_ip_ranges.kms_region.cidr_blocks`
# in an additional egress rule.  The `services` value uses "amazon"
# because AWS does not publish a distinct "KMS" service key in the
# public ip-ranges.json; "amazon" is the tightest public allowlist
# that still includes KMS control-plane IPs.  Consult the bundled
# `docs/nitro_flow.md` for the opt-in pattern.
data "aws_ip_ranges" "kms_region" {
  regions  = [var.aws_region]
  services = ["amazon"]
}

# --- Security Group: Zero ingress, minimal egress ---

resource "aws_security_group" "enclave_sg" {
  count       = local.create_sg ? 1 : 0
  name_prefix = "tee-crafter-enclave-sg-"
  description = "Nitro enclave host: no ingress, egress only for setup and VPC endpoints"
  vpc_id      = aws_vpc.deployment.id

  # Default 443/tcp egress rule.  Replaced by per-CIDR rules below when
  # ``siem_egress_cidrs`` is non-empty (lock SIEM egress down to a known
  # collector list).
  dynamic "egress" {
    for_each = length(var.siem_egress_cidrs) == 0 ? [1] : []
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = var.allow_setup_egress ? ["0.0.0.0/0"] : [aws_vpc.deployment.cidr_block]
      description = var.allow_setup_egress ? "HTTPS for VPC endpoints + package repos during setup" : "HTTPS restricted to VPC endpoints (custom AMI mode)"
    }
  }

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

  dynamic "egress" {
    for_each = length(var.siem_egress_cidrs) > 0 ? [1] : []
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [aws_vpc.deployment.cidr_block]
      description = "HTTPS within VPC (Interface Endpoints, KMS, S3, etc.)"
    }
  }

  egress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_prefix_list.s3.id]
    description     = "HTTPS to S3 via Gateway endpoint (prefix list)"
  }

  dynamic "egress" {
    for_each = var.allow_setup_egress ? [1] : []
    content {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTP for yum package repos during cloud-init setup"
    }
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [aws_vpc.deployment.cidr_block]
    description = "DNS restricted to VPC resolver only"
  }
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.deployment.cidr_block]
    description = "DNS (TCP) restricted to VPC resolver only"
  }
}

# --- VPC Endpoints ---

resource "aws_security_group" "vpce_sg" {
  count       = local.create_vpce ? 1 : 0
  name_prefix = "tee-crafter-vpce-sg-"
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

locals {
  subnet_id = var.subnet_id != "" ? var.subnet_id : aws_subnet.private.id

  instance_profile_name  = local.create_iam ? aws_iam_instance_profile.enclave_profile[0].name : var.existing_instance_profile_name
  security_group_id      = local.create_sg ? aws_security_group.enclave_sg[0].id : var.existing_security_group_id
  enclave_role_arn       = local.create_iam ? aws_iam_role.enclave_role[0].arn : var.existing_enclave_role_arn
  deployment_bucket_name = local.create_bucket ? aws_s3_bucket.deployment_bucket[0].id : var.existing_deployment_bucket
  deployment_bucket_arn  = local.create_bucket ? aws_s3_bucket.deployment_bucket[0].arn : "arn:aws:s3:::${var.existing_deployment_bucket}"
}

# --- VPC endpoint policies (scope each endpoint to THIS deployment) ---
#
# A VPC endpoint created without a `policy` argument gets the AWS default
# "full access" document: every principal that can reach the endpoint may
# call every action of that service against **any** resource, in **any**
# AWS account.  That defeats the point of the private path.  Concretely,
# for the KMS endpoint: the security group cannot tell our key from an
# attacker's, because both are reached at the same endpoint IP, so a
# compromised host could `kms:Encrypt` under a key in an account we have
# never heard of and ship the ciphertext out through the same hole.
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
  #
  # `CreateVpcEndpoint` validates that a Principal named in the policy actually
  # exists, and the role is created in this same apply, so IAM's eventual
  # consistency made every endpoint fail with the famously unhelpful
  # `InvalidPolicyDocument: UnknownError` -- deterministically, because the
  # apply retry destroys and recreates the role and races again.  It took out
  # both AWS platforms.
  #
  # Condition values are NOT existence-checked, and `aws:PrincipalArn` is
  # equivalent in effect: only that role's calls are allowed, and a caller with
  # no `aws:PrincipalArn` (anonymous / service principal) fails the condition
  # and is denied.  Proven side-by-side against the live API on 2026-08-23 with
  # a deliberately nonexistent role ARN: the Principal form returned
  # InvalidPolicyDocument, this form created the endpoint.
  endpoint_principal_condition = {
    ArnEquals = { "aws:PrincipalArn" = local.endpoint_policy_principal }
  }

  # Keys reachable through the KMS interface endpoint: the PCR-bound enclave
  # key, the deployment bucket's SSE-KMS key, and (for `--byok aws-kms`) the
  # customer key.  `compact` drops the empty BYOK ARN when BYOK is off, and
  # the `[*]` splat yields `[]` when the bucket key is not created.
  kms_endpoint_key_arns = compact(concat(
    [aws_kms_key.enclave_key.arn],
    aws_kms_key.bucket_key[*].arn,
    [var.byok_aws_kms_arn],
  ))

  kms_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
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
      },
      {
        # kms:GenerateRandom is granted in `aws_iam_role_policy.enclave_policy`
        # and has no resource to scope to -- the API takes no key.  Keeping it
        # in its own statement means the resource-scoped statement above stays
        # exact.
        Sid       = "GenerateRandomHasNoResource"
        Effect    = "Allow"
        Principal = "*"
        Condition = local.endpoint_principal_condition
        Action    = "kms:GenerateRandom"
        Resource  = "*"
      },
    ]
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
  # AMI *and* the NAT path that `--siem` export takes.  cloud-init pulls packages
  # from S3-backed repo mirrors whose bucket names are region- and
  # distro-version-specific, so enumerating them here would rot; a partial
  # allowlist fails the bake in a way that looks like a network problem.  The
  # policy used to be detached entirely in that case, which also dropped the
  # `aws:PrincipalArn` condition -- and at a *gateway* endpoint that condition is
  # the control that matters, because it governs **who** may use the endpoint
  # rather than whether egress exists.  Detaching therefore let any principal in
  # the VPC reach this deployment's artifact bucket through the endpoint, and an
  # operator who added `--siem` lost that control with no indication.  So the
  # policy now stays attached in both modes and only the *reads* widen; writes
  # remain scoped to this deployment's bucket either way.
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

resource "aws_security_group" "kms_vpce_sg" {
  count       = var.create_kms_vpc_endpoint ? 1 : 0
  name_prefix = "tee-crafter-kms-vpce-sg-"
  description = "Allow HTTPS from VPC to KMS Interface endpoint"
  vpc_id      = aws_vpc.deployment.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.deployment.cidr_block]
    description = "HTTPS from VPC CIDR"
  }
}

resource "aws_vpc_endpoint" "kms" {
  count               = var.create_kms_vpc_endpoint ? 1 : 0
  vpc_id              = aws_vpc.deployment.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [local.subnet_id]
  security_group_ids  = [aws_security_group.kms_vpce_sg[0].id]
  policy              = local.endpoint_policies_active ? local.kms_endpoint_policy : null
}

resource "aws_vpc_endpoint" "s3_gateway" {
  count             = var.create_s3_gateway_endpoint ? 1 : 0
  vpc_id            = aws_vpc.deployment.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  policy            = local.endpoint_policies_active ? local.s3_endpoint_policy : null
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
    Name    = "tee-crafter-nitro-siem-logs-vpce"
    Project = "tee-crafter"
    Purpose = "siem-egress-private"
  }
}

# --- IAM (least privilege) ---

resource "aws_iam_role" "enclave_role" {
  count       = local.create_iam ? 1 : 0
  name_prefix = "tee-crafter-role-"

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
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  count      = local.create_iam ? 1 : 0
  role       = aws_iam_role.enclave_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "enclave_policy" {
  count       = local.create_iam ? 1 : 0
  name_prefix = "tee-crafter-policy-"
  role        = aws_iam_role.enclave_role[0].id

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

resource "aws_iam_instance_profile" "enclave_profile" {
  count       = local.create_iam ? 1 : 0
  name_prefix = "tee-crafter-profile-"
  role        = aws_iam_role.enclave_role[0].name
}

# Least-privilege CloudWatch Logs PutEvents grant for the SIEM exporter
# running inside the TEE.
resource "aws_iam_role_policy" "enclave_siem_cloudwatch_logs" {
  count       = local.create_iam && var.siem_cloudwatch_log_group != "" ? 1 : 0
  name_prefix = "tee-crafter-siem-logs-"
  role        = aws_iam_role.enclave_role[0].id

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

# Least-privilege kms:Decrypt on a customer-owned BYOK key.
# Created only when var.byok_aws_kms_arn is non-empty.  The KMS key
# policy is the actual gate (it pins the enclave's PCR set and this
# role ARN as a Decrypt principal); this IAM policy just satisfies
# the IAM-side half of the dual-control "principal must be allowed
# by BOTH key policy AND IAM" rule for cross-account / scoped keys.
resource "aws_iam_role_policy" "enclave_byok_kms_decrypt" {
  count       = local.create_iam && var.byok_aws_kms_arn != "" ? 1 : 0
  name_prefix = "tee-crafter-byok-decrypt-"
  role        = aws_iam_role.enclave_role[0].id

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

# --- KMS (PCR-bound, least privilege) ---

resource "aws_kms_key" "enclave_key" {
  description             = "KMS key bound to Enclave PCR Hashes"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags = {
    Project = "tee-crafter"
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowKeyManagement"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion",
          "kms:Encrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowEnclaveDecryptViaPCR"
        Effect = "Allow"
        Principal = {
          AWS = local.enclave_role_arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:PCR0" = var.pcr0_hash
            "kms:RecipientAttestation:PCR1" = var.pcr1_hash
            "kms:RecipientAttestation:PCR2" = var.pcr2_hash
          }
        }
      }
    ]
  })
}

# --- EC2 Instance (private-only, no SSH) ---

resource "aws_instance" "enclave_host_spot" {
  count         = var.use_spot_instance ? 1 : 0
  ami           = var.custom_ami_id != "" ? var.custom_ami_id : data.aws_ami.al2023.id
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

  enclave_options {
    enabled = true
  }

  lifecycle {
    # SB assertion: refuse to launch unless the operator-supplied AMI was
    # actually baked with `bake-ami --enable-secure-boot` (now the default).
    # The bake step tags successful SB AMIs with
    # `tee-crafter-secure-boot=enabled`; if that tag is missing — or no
    # custom AMI was supplied at all (stock AL2023 has no pre-enrolled SB
    # keys) — we abort here rather than producing a deployment whose
    # attestation posture silently doesn't match the operator's intent.
    # Set TF_VAR_enable_secure_boot=false to opt out (legacy unbaked dev only).
    precondition {
      condition     = !var.enable_secure_boot || (var.custom_ami_id != "" && try(data.aws_ami.custom_for_sb_check[0].tags["tee-crafter-secure-boot"], "") == "enabled")
      error_message = "enable_secure_boot=true (the default since 2026) requires a custom AMI baked with `tee-crafter internal bake-ami --tee-platform nitro-aws` carrying tag tee-crafter-secure-boot=enabled. Stock AL2023 AMIs are not Secure-Boot-enrolled. Either re-bake with --enable-secure-boot (default), or pass TF_VAR_enable_secure_boot=false to opt out (dev only)."
    }
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = 32
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  depends_on = [aws_vpc_endpoint.kms, aws_vpc_endpoint.ssm, aws_vpc_endpoint.ssmmessages, aws_vpc_endpoint.ec2messages, aws_vpc_endpoint.s3_gateway]

  tags = {
    Name         = "TEECrafterEnclaveHost-Spot-${local.did}"
    Project      = "tee-crafter"
    DeploymentId = local.did
  }
}

resource "aws_instance" "enclave_host_ondemand" {
  count         = var.use_spot_instance ? 0 : 1
  ami           = var.custom_ami_id != "" ? var.custom_ami_id : data.aws_ami.al2023.id
  instance_type = var.instance_type

  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [local.security_group_id]
  iam_instance_profile        = local.instance_profile_name
  associate_public_ip_address = false

  enclave_options {
    enabled = true
  }

  lifecycle {
    precondition {
      condition     = !var.enable_secure_boot || (var.custom_ami_id != "" && try(data.aws_ami.custom_for_sb_check[0].tags["tee-crafter-secure-boot"], "") == "enabled")
      error_message = "enable_secure_boot=true (the default since 2026) requires a custom AMI baked with `tee-crafter internal bake-ami --tee-platform nitro-aws` carrying tag tee-crafter-secure-boot=enabled. Stock AL2023 AMIs are not Secure-Boot-enrolled. Either re-bake with --enable-secure-boot (default), or pass TF_VAR_enable_secure_boot=false to opt out (dev only)."
    }
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = 32
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  depends_on = [aws_vpc_endpoint.kms, aws_vpc_endpoint.ssm, aws_vpc_endpoint.ssmmessages, aws_vpc_endpoint.ec2messages, aws_vpc_endpoint.s3_gateway]

  tags = {
    Name         = "TEECrafterEnclaveHost-OnDemand-${local.did}"
    Project      = "tee-crafter"
    DeploymentId = local.did
  }
}

# --- Outputs ---

output "instance_id" {
  value = var.use_spot_instance ? aws_instance.enclave_host_spot[0].id : aws_instance.enclave_host_ondemand[0].id
}

output "private_ip" {
  value = var.use_spot_instance ? aws_instance.enclave_host_spot[0].private_ip : aws_instance.enclave_host_ondemand[0].private_ip
}

output "kms_key_arn" {
  value = aws_kms_key.enclave_key.arn
}

output "deployment_bucket" {
  value = local.deployment_bucket_name
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

# NET-1: surface the current egress posture so operators can confirm
# with `terraform output setup_egress_mode` whether the NAT path is
# still open for first-boot package installs.  After baking a golden
# AMI, re-apply with -var='allow_setup_egress=false' and confirm this
# output flips to "locked-down".
output "setup_egress_mode" {
  value       = var.allow_setup_egress ? "open-for-setup" : "locked-down"
  description = "NET-1: post-bake egress lockdown state (open-for-setup means a NAT gateway is attached and package-repo egress is permitted; locked-down means only attestation-scoped VPC/KMS/S3 egress remains)."
}

output "secure_boot_mode" {
  value       = var.enable_secure_boot ? "enforcing (PK/KEK/db baked into AMI NVRAM)" : "permissive (UEFI boot mode but no enrolled keys)"
  description = "UEFI Secure Boot posture for this deployment. enforcing → AMI was baked with `bake-ami --enable-secure-boot --tee-platform nitro-aws` and instances boot with kernel lockdown=integrity. permissive → instances boot UEFI but firmware is in Setup Mode."
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

# --- RMT-2: least-privilege deployer policy (reference output) ---
# tee-crafter only ever calls `ssm:SendCommand` with the built-in
# `AWS-RunShellScript` document and opens port-forwarding sessions
# with `AWS-StartPortForwardingSession`.  Operators should attach the
# following policy (rendered here so it always matches the deployed
# instance ARN) to the human or CI principal that runs
# `tee-crafter deploy`; it denies every other SSM document, which
# prevents a compromised deployer token from being used to run
# operator-facing automation (e.g. AWS-UpdateSSMAgent, AWS-ConfigureAWSPackage)
# against the enclave host.
output "rmt2_deployer_iam_policy" {
  description = "Minimum deployer IAM policy for tee-crafter (RMT-2)."
  value = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "SSMSendRunShellScriptOnly",
        Effect = "Allow",
        Action = "ssm:SendCommand",
        Resource = [
          "arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript",
          "arn:aws:ec2:${var.aws_region}:*:instance/${var.use_spot_instance ? aws_instance.enclave_host_spot[0].id : aws_instance.enclave_host_ondemand[0].id}",
        ],
        Condition = {
          StringEquals = {
            "ssm:DocumentName" = ["AWS-RunShellScript"]
          }
        }
      },
      {
        Sid    = "SSMStartPortForwardSessionOnly",
        Effect = "Allow",
        Action = "ssm:StartSession",
        Resource = [
          "arn:aws:ssm:${var.aws_region}::document/AWS-StartPortForwardingSession",
          "arn:aws:ec2:${var.aws_region}:*:instance/${var.use_spot_instance ? aws_instance.enclave_host_spot[0].id : aws_instance.enclave_host_ondemand[0].id}",
        ],
        Condition = {
          StringEquals = {
            "ssm:DocumentName" = ["AWS-StartPortForwardingSession"]
          }
        }
      },
      {
        Sid    = "SSMCommandReadOnly",
        Effect = "Allow",
        Action = [
          "ssm:ListCommandInvocations",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceInformation",
          "ssm:DescribeSessions",
          "ssm:TerminateSession"
        ],
        Resource = "*"
      }
    ]
  })
}
