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
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
  zone    = var.gcp_zone
}

# --- Variables ---

variable "gcp_project" {
  type        = string
  description = "GCP project ID."
}

variable "gcp_region" {
  type        = string
  default     = "us-central1"
  description = "GCP region for deployment."
}

variable "gcp_zone" {
  type        = string
  default     = "us-central1-a"
  description = "GCP zone for the Confidential VM."
}

variable "machine_type" {
  type        = string
  default     = "__INSTANCE_TYPE__"
  description = "GCP machine type. Must be C3 series for Intel TDX."
}

# TDX-5: minimum CPU platform.  "Intel Sapphire Rapids" is the earliest
# GCP CPU platform that supports Intel TDX.  Pinning this prevents the
# GCE scheduler from landing the VM on an older SKU in the same zone.
variable "min_cpu_platform" {
  type        = string
  default     = "Intel Sapphire Rapids"
  description = "Minimum CPU platform for TDX (TDX-5)."
  validation {
    condition = contains([
      "Intel Sapphire Rapids",
      "Intel Emerald Rapids",
    ], var.min_cpu_platform)
    error_message = "min_cpu_platform must be Sapphire Rapids or newer for TDX."
  }
}

variable "admin_username" {
  type    = string
  default = "tee_admin"
}

variable "custom_image" {
  type        = string
  default     = ""
  description = "Custom image self-link or name. If empty, uses Ubuntu 22.04 LTS."
}

variable "allow_setup_egress" {
  type        = bool
  default     = false
  description = "Allow HTTP/HTTPS egress for package installation during setup."
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
  description = "Public CIDRs the in-TEE SIEM exporter is allowed to reach on `siem_egress_ports`. When non-empty, an EGRESS firewall rule scoped to these prefixes is added at priority 250."
}

variable "siem_egress_ports" {
  type        = list(number)
  default     = [443]
  description = "Ports the SIEM egress allowlist applies to (defaults to 443)."
}

# --- BYOK (Cloud KMS) reachability ---
# Set by the CLI (export_byok_tf_vars) when --byok gcp-kms is used.  The in-TEE
# secret bootstrap calls Cloud KMS to release the DEK / unseal the .env at boot;
# egress is deny-all except the restricted Google APIs VIP (199.36.153.8/30),
# so we publish a private Cloud DNS zone routing *.googleapis.com to that VIP.
variable "byok_gcp_kms" {
  type        = bool
  default     = false
  description = "When true (--byok gcp-kms), publish a private googleapis.com DNS zone routing to the restricted Google APIs VIP so the in-TEE Cloud KMS decrypt is reachable under deny-all egress."
}

# The flag above buys reachability, not authorization.  The CVM service account
# is created below with a `random_id` suffix, so an operator cannot pre-grant it
# on the customer's key, and no other resource here gives it a Cloud KMS role.
# Without this key id the in-TEE unwrap fails PERMISSION_DENIED while BYOK is
# fully configured -- the failure `TF_VAR_byok_aws_kms_arn` prevents on AWS.
variable "byok_gcp_kms_key_id" {
  type        = string
  default     = ""
  description = "Cloud KMS key id (--byok gcp-kms) the CVM service account is allowed to decrypt with. Empty string disables the IAM binding."
}

variable "use_spot_instance" {
  type        = bool
  default     = false
  description = "If true, uses Spot (preemptible) provisioning to reduce cost. Default false (On-Demand)."
}

variable "mrtd" {
  type        = string
  default     = ""
  description = "Expected MRTD value for the TDX Trust Domain."
}

# --- SSH Key ---

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_sensitive_file" "ssh_private_key" {
  content         = tls_private_key.ssh.private_key_pem
  filename        = abspath("${path.module}/tdx_gcp_ssh_key")
  file_permission = "0600"
}

# --- Network ---

resource "google_compute_network" "vpc" {
  name                    = "tee-crafter-tdx-vpc-${local.did}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "tee-crafter-tdx-subnet-${local.did}"
  ip_cidr_range = "10.1.1.0/24"
  region        = var.gcp_region
  network       = google_compute_network.vpc.id

  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# --- Private googleapis DNS (BYOK Cloud KMS reachability) ---
# Routes *.googleapis.com to the restricted VIP (199.36.153.8/30, the only
# allowed HTTPS egress) so the in-TEE Cloud KMS decrypt resolves to a reachable
# private address under deny-all egress.  Only for --byok gcp-kms.
resource "google_dns_managed_zone" "googleapis" {
  count       = var.byok_gcp_kms ? 1 : 0
  name        = "tee-crafter-tdx-googleapis-${local.did}"
  dns_name    = "googleapis.com."
  description = "tee-crafter: route googleapis to restricted VIP for BYOK Cloud KMS"
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc.id
    }
  }
}

resource "google_dns_record_set" "googleapis_restricted_a" {
  count        = var.byok_gcp_kms ? 1 : 0
  name         = "restricted.googleapis.com."
  type         = "A"
  ttl          = 300
  managed_zone = google_dns_managed_zone.googleapis[0].name
  rrdatas      = ["199.36.153.8", "199.36.153.9", "199.36.153.10", "199.36.153.11"]
}

# Only the hostnames the BYOK path actually needs resolve to the restricted
# VIP.  This used to be a `*.googleapis.com.` CNAME, which made EVERY Google
# API reachable — storage.googleapis.com included — from a workload whose whole
# posture is deny-all egress.  That is a data-exfiltration channel opened by a
# change whose stated goal was "reach Cloud KMS".
#
# Everything not listed here keeps resolving via the public resolver to an
# address the firewall does not permit, i.e. it stays unreachable.
#
# Note the restricted VIP carries no security weight on its own: it only
# restricts which Google *services* are reachable, not which projects or
# buckets.  Add a VPC Service Controls perimeter if this needs to bound data
# movement rather than just reachability.
locals {
  byok_googleapis_hosts = [
    "cloudkms.googleapis.com.",
    # Cloud KMS clients resolve the OAuth token endpoint too; without it the
    # google-cloud-kms client cannot mint a credential and the release hangs.
    "oauth2.googleapis.com.",
    "www.googleapis.com.",
  ]
}

resource "google_dns_record_set" "googleapis_service_cnames" {
  for_each     = var.byok_gcp_kms ? toset(local.byok_googleapis_hosts) : toset([])
  name         = each.value
  type         = "CNAME"
  ttl          = 300
  managed_zone = google_dns_managed_zone.googleapis[0].name
  rrdatas      = ["restricted.googleapis.com."]
}

# --- Firewall Rules ---

resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "tee-crafter-tdx-allow-iap-ssh-${local.did}"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = [local.tag]
  description   = "Allow SSH from IAP tunnel range only"
}

resource "google_compute_firewall" "deny_all_ingress" {
  name    = "tee-crafter-tdx-deny-ingress-${local.did}"
  network = google_compute_network.vpc.name

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = [local.tag]
  priority      = 65534
  description   = "Deny all ingress except IAP"
}

resource "google_compute_firewall" "allow_egress_internal" {
  name      = "tee-crafter-tdx-egress-internal-${local.did}"
  network   = google_compute_network.vpc.name
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  destination_ranges = ["199.36.153.8/30"]
  target_tags        = [local.tag]
  priority           = 100
  description        = "Allow HTTPS to Google Private API endpoints"
}

resource "google_compute_firewall" "allow_egress_metadata" {
  name      = "tee-crafter-tdx-egress-metadata-${local.did}"
  network   = google_compute_network.vpc.name
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  destination_ranges = ["169.254.169.254/32"]
  target_tags        = [local.tag]
  priority           = 100
  description        = "Allow HTTP to GCE metadata service"
}

resource "google_compute_firewall" "allow_egress_dns" {
  name      = "tee-crafter-tdx-egress-dns-${local.did}"
  network   = google_compute_network.vpc.name
  direction = "EGRESS"

  allow {
    protocol = "udp"
    ports    = ["53"]
  }

  allow {
    protocol = "tcp"
    ports    = ["53"]
  }

  destination_ranges = ["169.254.169.254/32", "10.0.0.0/8"]
  target_tags        = [local.tag]
  priority           = 100
  description        = "Allow DNS to metadata and internal"
}

resource "google_compute_firewall" "allow_egress_setup" {
  count     = var.allow_setup_egress ? 1 : 0
  name      = "tee-crafter-tdx-egress-setup-${local.did}"
  network   = google_compute_network.vpc.name
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [local.tag]
  priority           = 200
  description        = "Temporary egress for package installation during setup"
}

# Cloud NAT provides the actual internet route for setup egress.
# Without it, firewall allow rules have no effect because the VM has no
# public IP and private_ip_google_access only covers Google APIs.

locals {
  needs_nat = var.allow_setup_egress || length(var.siem_egress_cidrs) > 0
}

resource "google_compute_router" "nat_router" {
  count   = local.needs_nat ? 1 : 0
  name    = "tee-crafter-tdx-router-${local.did}"
  region  = var.gcp_region
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "nat" {
  count                              = local.needs_nat ? 1 : 0
  name                               = "tee-crafter-tdx-nat-${local.did}"
  router                             = google_compute_router.nat_router[0].name
  region                             = var.gcp_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.subnet.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_firewall" "allow_egress_siem" {
  count     = length(var.siem_egress_cidrs) > 0 ? 1 : 0
  name      = "tee-crafter-tdx-egress-siem-${local.did}"
  network   = google_compute_network.vpc.name
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = [for p in var.siem_egress_ports : tostring(p)]
  }

  destination_ranges = var.siem_egress_cidrs
  target_tags        = [local.tag]
  priority           = 250
  description        = "SIEM egress allowlist (continuous-attestation export)"
}

resource "google_compute_firewall" "deny_all_egress" {
  name      = "tee-crafter-tdx-deny-egress-${local.did}"
  network   = google_compute_network.vpc.name
  direction = "EGRESS"

  deny {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [local.tag]
  priority           = 65534
  description        = "Deny all egress except allowed rules"
}

# --- Cloud KMS (CMEK for bucket encryption at rest) ---
# GCP key rings are permanent (cannot be deleted), so we add a random suffix
# to avoid 409 conflicts on re-deploy after a previous teardown.

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

locals {
  did = random_id.bucket_suffix.hex
  tag = "tee-crafter-tdx-${local.did}"
}

resource "google_kms_key_ring" "tee_crafter" {
  name     = "tee-crafter-tdx-kr-${random_id.bucket_suffix.hex}"
  location = var.gcp_region
}

resource "google_kms_crypto_key" "bucket_key" {
  name            = "tee-crafter-tdx-key-${random_id.bucket_suffix.hex}"
  key_ring        = google_kms_key_ring.tee_crafter.id
  # No rotation_period, deliberately.
  #
  # This key's lifetime is one deployment; `terraform destroy` schedules its
  # versions for destruction. But GCP has no API to delete a CryptoKey or a
  # KeyRing, so both outlive the deploy permanently -- and a rotation schedule
  # outlives it too, quietly minting a new billable ENABLED version every 90
  # days, forever, for a deployment that no longer exists.
  #
  # Measured in the test project on 2026-08-22: seven abandoned per-deploy
  # keyrings from 2026-03-23/25 and 2026-05-13 each had a *second* ENABLED
  # version created exactly 90 days after the first, with nextRotationTime
  # still scheduled for 2026-09 / 2026-11. The three `tee-crafter-byok` keys,
  # which carry no rotation_period, had exactly one version each -- the control
  # group. One ring had version 1 DESTROYED and version 2 ENABLED, which shows
  # that destroying the stragglers does not help: rotation just makes more.
  #
  # Rotation protects long-lived keys. Ninety days is far longer than any
  # deploy, so the schedule could only ever fire after abandonment -- it was
  # dead configuration with a recurring bill attached. Removing it makes an
  # abandoned keyring flat at one version instead of unbounded.
  purpose         = "ENCRYPT_DECRYPT"
}

data "google_storage_project_service_account" "gcs_sa" {}

data "google_project" "current" {}

resource "google_kms_crypto_key_iam_member" "gcs_cmek" {
  crypto_key_id = google_kms_crypto_key.bucket_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs_sa.email_address}"
}

# Separate CMEK for the VM boot disk.  The boot disk and the deployment
# artifact bucket sit in different trust domains with different lifecycles;
# sharing one key means disabling it to revoke bucket access simultaneously
# bricks the VM's boot disk, and vice versa — so in practice neither ever gets
# rotated.  Two resources, no behavioural change.
resource "google_kms_crypto_key" "disk_key" {
  name            = "tee-crafter-tdx-disk-key-${random_id.bucket_suffix.hex}"
  key_ring        = google_kms_key_ring.tee_crafter.id
  # No rotation_period -- see the bucket_key above for why.
  purpose         = "ENCRYPT_DECRYPT"
}

resource "google_kms_crypto_key_iam_member" "compute_disk_cmek" {
  crypto_key_id = google_kms_crypto_key.disk_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@compute-system.iam.gserviceaccount.com"
}

# --- GCS Bucket (CMEK-encrypted) ---

resource "google_storage_bucket" "deployment" {
  name     = "tee-crafter-tdx-${random_id.bucket_suffix.hex}"
  location = var.gcp_region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket_key.id
  }

  lifecycle_rule {
    condition {
      age = 1
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs_cmek]
}

# --- Service Account ---

resource "google_service_account" "vm_sa" {
  account_id   = "tc-tdx-${local.did}"
  display_name = "TEE-Crafter TDX VM Service Account"
}

resource "google_storage_bucket_iam_member" "vm_gcs_read" {
  bucket = google_storage_bucket.deployment.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.vm_sa.email}"
}

resource "google_project_iam_member" "vm_log_writer" {
  project = var.gcp_project
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vm_sa.email}"
}

resource "google_project_iam_member" "vm_metric_writer" {
  project = var.gcp_project
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.vm_sa.email}"
}

# Authorize the CVM's own service account to unwrap the customer DEK.
# `cryptoKeyDecrypter`, not `cryptoKeyEncrypterDecrypter`: the TEE only ever
# unwraps a DEK, never wraps one, so encrypt is authority it does not need.
resource "google_kms_crypto_key_iam_member" "vm_byok_decrypt" {
  count         = var.byok_gcp_kms_key_id == "" ? 0 : 1
  crypto_key_id = var.byok_gcp_kms_key_id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${google_service_account.vm_sa.email}"
}

# --- Confidential VM (Intel TDX) ---

data "google_compute_image" "ubuntu" {
  family  = "ubuntu-2204-lts"
  project = "ubuntu-os-cloud"
}

resource "google_compute_instance" "tdx_vm" {
  name                = "tee-crafter-tdx-vm-${local.did}"
  machine_type        = var.machine_type
  zone                = var.gcp_zone
  deletion_protection = false

  # TDX-5: Pin the minimum CPU platform to Intel Sapphire Rapids.  GCP's
  # C3 family can land on either Sapphire Rapids (SPR, TDX 1.0/1.5) or
  # Emerald Rapids (EMR, TDX 1.5+) hosts.  Without this constraint the
  # scheduler may place the VM on an older Ice Lake host that happens to
  # be in the same zone — which does not support TDX at all and will
  # silently break `confidential_instance_type = "TDX"` provisioning.
  # Operators that want the newer Emerald Rapids floor can override the
  # variable to "Intel Emerald Rapids".
  min_cpu_platform = var.min_cpu_platform

  tags = [local.tag]

  boot_disk {
    initialize_params {
      image = var.custom_image != "" ? var.custom_image : data.google_compute_image.ubuntu.self_link
      size  = 50
      type  = "pd-ssd"
    }
    kms_key_self_link = google_kms_crypto_key.disk_key.id
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet.id
  }

  confidential_instance_config {
    confidential_instance_type = "TDX"
  }

  scheduling {
    on_host_maintenance  = "TERMINATE"
    provisioning_model   = var.use_spot_instance ? "SPOT" : "STANDARD"
    preemptible          = var.use_spot_instance
    automatic_restart    = var.use_spot_instance ? false : true
    instance_termination_action = var.use_spot_instance ? "STOP" : null
  }

  service_account {
    email  = google_service_account.vm_sa.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    ssh-keys                = "${var.admin_username}:${tls_private_key.ssh.public_key_openssh}"
    enable-oslogin          = "FALSE"
    block-project-ssh-keys  = "TRUE"
    serial-port-enable      = "FALSE"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  labels = {
    project = "tee-crafter"
    tee     = "intel-tdx"
  }

  depends_on = [
    google_compute_firewall.allow_iap_ssh,
    google_storage_bucket.deployment,
    google_kms_crypto_key_iam_member.gcs_cmek,
    # The VM calls Cloud KMS during its own boot, so the BYOK grant has to
    # exist before it starts -- otherwise the unwrap races IAM creation.
    google_kms_crypto_key_iam_member.vm_byok_decrypt,
  ]
}

# --- Outputs ---

output "instance_name" {
  value = google_compute_instance.tdx_vm.name
}

output "instance_zone" {
  value = google_compute_instance.tdx_vm.zone
}

output "vm_private_ip" {
  value = google_compute_instance.tdx_vm.network_interface[0].network_ip
}

output "project" {
  value = var.gcp_project
}

output "deployment_bucket" {
  value = google_storage_bucket.deployment.name
}

output "ssh_private_key_path" {
  value     = local_sensitive_file.ssh_private_key.filename
  sensitive = true
}

output "admin_username" {
  value = var.admin_username
}

output "mrtd" {
  value = var.mrtd
}

output "setup_egress_mode" {
  value       = var.allow_setup_egress ? "open-for-setup" : "locked-down"
  description = "NET-1: post-bake egress lockdown state for the GCP TDX CVM. open-for-setup attaches a Cloud Router + Cloud NAT for first-boot package installs; locked-down keeps only intra-VPC + metadata + attestation egress."
}

output "secure_boot_mode" {
  value       = "enforcing (GCP Shielded VM — enable_secure_boot = true)"
  description = "UEFI Secure Boot posture for this GCP TDX deployment. Always enforcing — google_compute_instance.shielded_instance_config hard-codes enable_secure_boot = true plus vTPM + integrity monitoring."
}
