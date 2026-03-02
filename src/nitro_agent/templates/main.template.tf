terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- Variables (Passed in by Python Agent during execution) ---

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

variable "create_s3_vpc_endpoint" {
  type        = bool
  default     = false
  description = "Whether to create an S3 VPC endpoint. Defaults to false so existing VPC endpoints are reused."
}

variable "key_name" {
  type        = string
  default     = ""
  description = "Name of the EC2 Key Pair to allow SSH access."
}

variable "use_spot_instance" {
  type        = bool
  default     = true
  description = "If true, requests a Spot Instance to reduce cost."
}

# PCR Hash variables (populated by the Python Agent)
variable "pcr0_hash" { type = string }
variable "pcr1_hash" { type = string }
variable "pcr2_hash" { type = string }

# --- Data Sources ---

data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-arm64"]
  }
  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

# --- S3 Deployment Bucket ---

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "deployment_bucket" {
  bucket        = "nitro-deployment-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "deployment_bucket_public_access" {
  bucket = aws_s3_bucket.deployment_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "deployment_bucket_encryption" {
  bucket = aws_s3_bucket.deployment_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "deployment_bucket_ssl_only" {
  bucket = aws_s3_bucket.deployment_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.deployment_bucket.arn,
          "${aws_s3_bucket.deployment_bucket.arn}/*"
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

# --- Networking ---

resource "aws_security_group" "enclave_sg" {
  name_prefix = "nitro-enclave-sg-"
  description = "Allow HTTPS for Enclave Host Proxy API"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS access to Host Proxy API"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for KMS, S3, SSM, and package repos"
  }
}

# --- VPC Endpoint for KMS (keeps KMS traffic within the AWS network) ---

resource "aws_security_group" "kms_endpoint_sg" {
  name_prefix = "nitro-kms-vpce-sg-"
  description = "Allow HTTPS from enclave host to KMS VPC endpoint"
  count       = var.create_kms_vpc_endpoint ? 1 : 0
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.enclave_sg.id]
    description     = "HTTPS from enclave host"
  }
}

resource "aws_vpc_endpoint" "kms" {
  count               = var.create_kms_vpc_endpoint ? 1 : 0
  vpc_id              = data.aws_vpc.default.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [var.subnet_id != "" ? var.subnet_id : tolist(data.aws_subnets.default.ids)[0]]
  security_group_ids  = [aws_security_group.kms_endpoint_sg[0].id]
}

# --- VPC Gateway Endpoint for S3 (free, keeps S3 traffic within AWS) ---

data "aws_route_table" "main" {
  vpc_id = data.aws_vpc.default.id

  filter {
    name   = "association.main"
    values = ["true"]
  }
}

resource "aws_vpc_endpoint" "s3" {
  count              = var.create_s3_vpc_endpoint ? 1 : 0
  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [data.aws_route_table.main.id]
}

# --- IAM ---

resource "aws_iam_role" "enclave_role" {
  name_prefix = "nitro-role-"

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

# Attach AWS managed policy for SSM Core
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.enclave_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "enclave_policy" {
  name_prefix = "nitro-policy-"
  role        = aws_iam_role.enclave_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.deployment_bucket.arn,
          "${aws_s3_bucket.deployment_bucket.arn}/*"
        ]
      },
      {
        Action   = "kms:GenerateRandom"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "enclave_profile" {
  name_prefix = "nitro-profile-"
  role        = aws_iam_role.enclave_role.name
}

# --- KMS ---

resource "aws_kms_key" "enclave_key" {
  description              = "KMS key bound to Enclave PCR Hashes"
  deletion_window_in_days  = 7
  enable_key_rotation      = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Enclave Access via PCR Verification"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.enclave_role.arn
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
      },
      {
        Sid    = "Allow IAM Root to Manage Key"
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
          "kms:Encrypt" # Allow the client to encrypt data using this key
        ]
        Resource = "*"
      }
    ]
  })
}

# --- EC2 Instance ---

resource "aws_instance" "enclave_host_spot" {
  count         = var.use_spot_instance ? 1 : 0
  ami           = data.aws_ami.al2023.id
  instance_type = var.instance_type
  key_name      = var.key_name
  
  subnet_id = var.subnet_id != "" ? var.subnet_id : tolist(data.aws_subnets.default.ids)[0]

  vpc_security_group_ids = [aws_security_group.enclave_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.enclave_profile.name

  instance_market_options {
    market_type = "spot"
    spot_options {
      instance_interruption_behavior = "terminate"
    }
  }

  enclave_options {
    enabled = true
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_size = 32
    encrypted   = true
  }

  # Ensure the instance is created after any KMS endpoint (if present).
  # Using the resource (not an indexed instance) keeps this a static dependency.
  depends_on = [aws_vpc_endpoint.kms]

  tags = {
    Name = "NitroEnclaveHost-Spot"
  }
}

resource "aws_instance" "enclave_host_ondemand" {
  count         = var.use_spot_instance ? 0 : 1
  ami           = data.aws_ami.al2023.id
  instance_type = var.instance_type
  key_name      = var.key_name
  
  subnet_id = var.subnet_id != "" ? var.subnet_id : tolist(data.aws_subnets.default.ids)[0]

  vpc_security_group_ids = [aws_security_group.enclave_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.enclave_profile.name

  enclave_options {
    enabled = true
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_size = 32
    encrypted   = true
  }

  # Ensure the instance is created after any KMS endpoint (if present).
  depends_on = [aws_vpc_endpoint.kms]

  tags = {
    Name = "NitroEnclaveHost-OnDemand"
  }
}

# --- Outputs ---

output "instance_id" {
  value = var.use_spot_instance ? aws_instance.enclave_host_spot[0].id : aws_instance.enclave_host_ondemand[0].id
}

output "public_ip" {
  value = var.use_spot_instance ? aws_instance.enclave_host_spot[0].public_ip : aws_instance.enclave_host_ondemand[0].public_ip
}

output "kms_key_arn" {
  value = aws_kms_key.enclave_key.arn
}

output "deployment_bucket" {
  value = aws_s3_bucket.deployment_bucket.id
}