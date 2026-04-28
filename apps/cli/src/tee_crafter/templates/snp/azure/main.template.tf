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
    azurerm = {
      source  = "hashicorp/azurerm"
      # >= 4.x required for virtual network flow logs (target_resource_id);
      # NSG flow logs cannot be created after June 2025.  5.x keeps
      # azurerm_network_watcher_flow_log and drops
      # skip_provider_registration, which is why every Azure template
      # now sets resource_provider_registrations instead.
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
  resource_provider_registrations = "none"
}

# --- Variables ---

variable "azure_location" {
  type        = string
  default     = "westus"
  description = "Azure region with AMD SEV-SNP confidential VM support."
}

variable "vm_size" {
  type        = string
  default     = "__INSTANCE_TYPE__"
  description = "Azure VM size. Must be DCasv5, ECasv5, DCasv6, or ECasv6 for AMD SEV-SNP."
}

variable "admin_username" {
  type    = string
  default = "azureuser"
}

variable "custom_image_id" {
  type        = string
  default     = ""
  description = "Custom image ID. If empty, uses Canonical confidential VM image."
}

variable "use_spot_instance" {
  type        = bool
  default     = false
  description = "If true, deploys an Azure Spot VM to reduce cost. Default false (On-Demand)."
}

variable "allow_setup_egress" {
  type        = bool
  default     = false
  description = "Allow HTTP/HTTPS egress for package installation during setup. Defaults to false (locked down). Set to true only during first-time setup without a pre-baked image."
}

variable "measurement" {
  type        = string
  default     = ""
  description = "Expected AMD SEV-SNP launch measurement (SHA-384 hex)."
}

# --- SIEM egress (continuous-attestation export) ---

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
  description = "Public CIDRs the in-TEE SIEM exporter is allowed to reach on `siem_egress_ports`. When non-empty, an Outbound NSG rule scoped to these prefixes is added at priority 130+. Auto-set by --siem-egress-cidr."
}

variable "siem_egress_ports" {
  type        = list(number)
  default     = [443]
  description = "Ports the SIEM egress allowlist applies to (defaults to 443)."
}

# --- BYOK (Key Vault) reachability ---
# Set by the CLI (export_byok_tf_vars) when --byok azure-kv is used.  The in-TEE
# secret bootstrap calls Key Vault (Secure Key Release) to release the DEK /
# unseal the .env at boot.  Outbound is deny-all (NSG DenyAllOutbound), so we
# add a Microsoft.KeyVault service endpoint + a narrow NSG allow to the
# AzureKeyVault service tag so the call reaches the vault over the Azure
# backbone without a NAT.  Without it the release hangs (fail-closed).
variable "byok_azure_kv" {
  type        = bool
  default     = false
  description = "When true (--byok azure-kv), add a Microsoft.KeyVault service endpoint + NSG egress allow to the AzureKeyVault service tag so the in-TEE Key Vault release is reachable under deny-all egress."
}

# --- Scoping the BYOK Key Vault egress destination ---
#
# The default `AzureKeyVault` service tag covers EVERY Key Vault in Azure,
# across every tenant.  A compromised workload can therefore write PHI to an
# attacker-owned vault in an attacker-owned subscription and the NSG permits
# it — which turns a rule whose stated purpose is "reach OUR vault" into an
# exfiltration channel.  NSG rules cannot match FQDNs, so narrow it with one
# of the two variables below, in descending order of preference:
#
#   1. byok_kv_private_endpoint_cidr — front the vault with a Private Endpoint
#      and allow only its address (e.g. "10.0.1.7/32").  This is the only
#      option that limits egress to *your* vault.  It removes the service tag
#      from the rule entirely.
#   2. byok_kv_service_tag_region — use the REGIONAL tag
#      "AzureKeyVault.<Region>", which at least bounds the destination
#      geographically.  Supply the region exactly as Azure spells the tag
#      suffix (e.g. "WestUS", not "westus"); we deliberately do not derive it
#      from `azure_location`, because the tag suffix casing is not simply the
#      location string and a wrong tag fails the apply.
#
# Leaving both empty preserves the previous behaviour (global tag) so this
# change cannot break an existing deploy — but it is not a scoped control.
variable "byok_kv_private_endpoint_cidr" {
  type        = string
  default     = ""
  description = "CIDR of the Key Vault Private Endpoint (e.g. 10.0.1.7/32). When set, BYOK egress is allowed only to this address and the AzureKeyVault service tag is not used."
}

variable "byok_kv_service_tag_region" {
  type        = string
  default     = ""
  description = "Region suffix for the regional AzureKeyVault.<Region> service tag, spelled as Azure spells it (e.g. WestUS). Ignored when byok_kv_private_endpoint_cidr is set. Empty falls back to the global AzureKeyVault tag, which covers every vault in every tenant."
}

# --- MAA reachability for Secure Key Release (--byok azure-skr) -------------
#
# `AzureAttestSKR` attests the VM to Microsoft Azure Attestation *before* it
# asks Key Vault to release, so a deny-all-egress NSG blocks the release at the
# first hop. Reachability is not authorization: this opens a path, and the Key
# Vault release policy is what decides whether the evidence is good enough.
#
# Gated on `byok_azure_kv` rather than on its own flag because on this platform
# MAA has exactly one caller. Attestation here reads a SEV-SNP report and
# verifies it against AMD's root — it never talks to MAA — so opening this when
# BYOK is off would grant egress nothing uses.
#
# Azure publishes NO regional AzureAttestation service tag: `az network
# list-service-tags` returns exactly `AzureAttestation` for every location, in
# contrast to `AzureKeyVault`, which has dozens of regional variants. An earlier
# attempt at `AzureAttestation.<Region>` failed the apply after the VM had
# already been created. `maa_endpoint_cidr` (a Private Endpoint) is therefore
# the only way to scope this below "every MAA instance in Azure".
variable "maa_endpoint_cidr" {
  type        = string
  default     = ""
  description = "CIDR of an MAA Private Endpoint. When set, SKR attestation egress is allowed only to this address instead of the global AzureAttestation service tag."
}
locals {
  # No regional branch: `AzureAttestation.<Region>` is not a tag Azure knows.
  maa_destination = (
    var.maa_endpoint_cidr != "" ? var.maa_endpoint_cidr : "AzureAttestation")

  byok_kv_destination = (
    var.byok_kv_private_endpoint_cidr != ""
    ? var.byok_kv_private_endpoint_cidr
    : (var.byok_kv_service_tag_region != ""
      ? "AzureKeyVault.${var.byok_kv_service_tag_region}"
      : "AzureKeyVault")
  )

  byok_kv_scope = (
    !var.byok_azure_kv ? "not-applicable (byok_azure_kv = false)" :
    var.byok_kv_private_endpoint_cidr != "" ? "private-endpoint (${var.byok_kv_private_endpoint_cidr})" :
    var.byok_kv_service_tag_region != "" ? "regional-service-tag (AzureKeyVault.${var.byok_kv_service_tag_region})" :
    "global-service-tag (every Key Vault in every Azure tenant)"
  )
}

# Surface the unscoped fallback instead of letting it pass silently.  Terraform
# cannot derive the regional service-tag suffix offline -- the suffix casing is
# not the `azure_location` string, and guessing it produces a tag Azure rejects
# at apply time -- so the mechanism is the two variables above and this check is
# the signal that neither was used.  `check` emits a plan/apply warning rather
# than failing, because failing here would break every existing --byok azure-kv
# deployment that has not yet been given a Private Endpoint.
check "byok_key_vault_egress_is_scoped" {
  assert {
    condition = !var.byok_azure_kv || var.byok_kv_private_endpoint_cidr != "" || var.byok_kv_service_tag_region != ""
    error_message = join("", [
      "BYOK Key Vault egress is allowed to the GLOBAL `AzureKeyVault` service tag, ",
      "which covers every Key Vault in every Azure tenant -- a compromised workload ",
      "can write PHI to an attacker-owned vault and this NSG permits it. ",
      "Scope it: set `byok_kv_private_endpoint_cidr` to the CIDR of a Private Endpoint ",
      "fronting your vault (preferred, and the only option that limits egress to YOUR ",
      "vault), or set `byok_kv_service_tag_region` to the regional tag suffix spelled ",
      "as Azure spells it (e.g. \"WestUS\", not \"westus\").",
    ])
  }
}

# --- Resource Group ---

resource "azurerm_resource_group" "rg" {
  name     = "tee-crafter-snp-rg-${local.did}"
  location = var.azure_location
}

# --- Networking ---

resource "azurerm_virtual_network" "vnet" {
  name                = "tee-crafter-snp-vnet-${local.did}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "vm_subnet" {
  name                 = "vm-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
  # azurerm 5.0 replaced the ``service_endpoints`` list with repeatable
  # ``service_endpoint`` blocks (each carrying an optional
  # ``network_identifier``).  Kept as a dynamic block so the set still tracks
  # ``byok_azure_kv``: Key Vault's endpoint is only opened when a sealed-.env
  # or BYOK flow actually needs to reach it.
  dynamic "service_endpoint" {
    for_each = var.byok_azure_kv ? ["Microsoft.Storage", "Microsoft.KeyVault"] : ["Microsoft.Storage"]
    content {
      service = service_endpoint.value
    }
  }
}

resource "azurerm_subnet" "bastion_subnet" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.2.0/26"]
}

# --- Bastion (Standard SKU with tunneling) ---

resource "azurerm_public_ip" "bastion_pip" {
  name                = "tee-crafter-snp-bastion-pip-${local.did}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_bastion_host" "bastion" {
  name                = "tee-crafter-snp-bastion-${local.did}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard"
  tunneling_enabled   = true

  ip_configuration {
    name                 = "bastion-ip-config"
    subnet_id            = azurerm_subnet.bastion_subnet.id
    public_ip_address_id = azurerm_public_ip.bastion_pip.id
  }
}

# --- NSG: Locked egress ---

resource "azurerm_network_security_group" "nsg" {
  name                = "tee-crafter-snp-nsg-${local.did}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "AllowBastionSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.2.0/26"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Azure platform IP — required for waagent, DNS, DHCP, health reporting
  security_rule {
    name                       = "AllowAzurePlatform"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "168.63.129.16/32"
  }

  # HTTPS for storage service endpoint + VNet comms (always on);
  # opens to all destinations during setup for package installation
  security_rule {
    name                       = "AllowHTTPSEgress"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = var.allow_setup_egress ? "*" : "VirtualNetwork"
  }

  dynamic "security_rule" {
    for_each = var.allow_setup_egress ? [1] : []
    content {
      name                       = "AllowHTTPEgressSetup"
      priority                   = 120
      direction                  = "Outbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "80"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
  }

  # IMDS endpoint for VCEK cert retrieval (AMD SEV-SNP attestation)
  security_rule {
    name                       = "AllowIMDS"
    priority                   = 200
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "169.254.169.254"
  }

  # SIEM egress allowlist — narrow Outbound rule per port to a known
  # collector CIDR list.  Active only when --siem-egress-cidr was passed.
  dynamic "security_rule" {
    for_each = length(var.siem_egress_cidrs) > 0 ? var.siem_egress_ports : []
    content {
      name                         = "AllowSiemEgress${security_rule.value}"
      priority                     = 130 + security_rule.key
      direction                    = "Outbound"
      access                       = "Allow"
      protocol                     = "Tcp"
      source_port_range            = "*"
      destination_port_range       = tostring(security_rule.value)
      source_address_prefix        = "*"
      destination_address_prefixes = var.siem_egress_cidrs
    }
  }

  # BYOK Key Vault egress.  Active only for --byok azure-kv.
  #
  # Scope: prefer an explicit destination, then the REGIONAL service tag, and
  # only fall back to the global tag if the operator asks for it.  The global
  # `AzureKeyVault` tag covers every Key Vault in Azure across every tenant —
  # which turns a rule whose stated purpose is "reach OUR vault" into an
  # exfiltration channel to an attacker-owned vault in an attacker-owned
  # tenant.  NSG rules cannot match FQDNs, so the ordering below is the best
  # available without a Private Endpoint.
  #
  # Destination is `local.byok_kv_destination`; see the
  # byok_kv_private_endpoint_cidr / byok_kv_service_tag_region variables above
  # for how to scope it below the global tag.
  dynamic "security_rule" {
    for_each = var.byok_azure_kv ? [1] : []
    content {
      name                   = "AllowKeyVaultEgress"
      priority               = 125
      direction              = "Outbound"
      access                 = "Allow"
      protocol               = "Tcp"
      source_port_range      = "*"
      destination_port_range = "443"
      source_address_prefix  = "*"
      destination_address_prefix = local.byok_kv_destination
    }
  }

  # MAA egress for Secure Key Release. See the maa_endpoint_cidr variable for
  # why there is no regional service tag to narrow this to.
  dynamic "security_rule" {
    for_each = var.byok_azure_kv ? [1] : []
    content {
      name                       = "AllowMaaEgressForSkr"
      priority                   = 126
      direction                  = "Outbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "443"
      source_address_prefix      = "*"
      destination_address_prefix = local.maa_destination
    }
  }

  security_rule {
    name                       = "DenyAllOutbound"
    priority                   = 4000
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "nsg_assoc" {
  subnet_id                 = azurerm_subnet.vm_subnet.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# NAT Gateway for setup egress. Azure's default outbound SNAT is
# deprecated for new deployments after Sep 2025.

locals {
  needs_nat = var.allow_setup_egress || length(var.siem_egress_cidrs) > 0
}

resource "azurerm_public_ip" "nat_pip" {
  count               = local.needs_nat ? 1 : 0
  name                = "tee-crafter-snp-nat-pip-${local.did}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = { Project = "tee-crafter-snp" }
}

resource "azurerm_nat_gateway" "nat" {
  count                   = local.needs_nat ? 1 : 0
  name                    = "tee-crafter-snp-nat-${local.did}"
  location                = azurerm_resource_group.rg.location
  resource_group_name     = azurerm_resource_group.rg.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 4

  tags = { Project = "tee-crafter-snp" }
}

resource "azurerm_nat_gateway_public_ip_association" "nat_pip_assoc" {
  count                = local.needs_nat ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.nat[0].id
  public_ip_address_id = azurerm_public_ip.nat_pip[0].id
}

resource "azurerm_subnet_nat_gateway_association" "vm_subnet_nat" {
  count          = local.needs_nat ? 1 : 0
  subnet_id      = azurerm_subnet.vm_subnet.id
  nat_gateway_id = azurerm_nat_gateway.nat[0].id
}

# --- Virtual network flow logs (NSG flow log creation blocked by Azure after June 2025) ---

data "azurerm_network_watcher" "regional" {
  name                = "NetworkWatcher_${replace(var.azure_location, " ", "")}"
  resource_group_name = "NetworkWatcherRG"
}

resource "azurerm_log_analytics_workspace" "flow_logs" {
  name                = "tee-crafter-snp-flow-${local.did}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Project = "tee-crafter-snp"
  }
}

resource "azurerm_network_watcher_flow_log" "vnet" {
  network_watcher_name = data.azurerm_network_watcher.regional.name
  resource_group_name  = data.azurerm_network_watcher.regional.resource_group_name
  name                 = "tee-crafter-snp-vnet-flow-${local.did}"

  target_resource_id = azurerm_virtual_network.vnet.id
  storage_account_id = azurerm_storage_account.artifacts.id
  enabled            = true

  retention_policy {
    enabled = true
    days    = 30
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.flow_logs.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.flow_logs.location
    workspace_resource_id = azurerm_log_analytics_workspace.flow_logs.id
    interval_in_minutes   = 10
  }

  tags = {
    Project = "tee-crafter-snp"
  }
}

# --- NIC ---

resource "azurerm_network_interface" "nic" {
  name                = "tee-crafter-snp-nic-${local.did}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vm_subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

# --- SSH Key ---

resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_sensitive_file" "ssh_private_key" {
  content         = tls_private_key.ssh_key.private_key_pem
  filename        = "${path.module}/snp_ssh_key.pem"
  file_permission = "0600"
}

resource "random_id" "deployment_suffix" {
  byte_length = 4
}

locals {
  did = random_id.deployment_suffix.hex
}

# --- Storage Account for artifact upload ---

resource "azurerm_storage_account" "artifacts" {
  name                          = "teecrsnp${substr(md5(azurerm_resource_group.rg.id), 0, 8)}"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  min_tls_version               = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "artifacts" {
  name                  = "artifacts"
  # azurerm 5.0 removed ``storage_account_name`` from
  # azurerm_storage_container in favour of the account's resource id.
  storage_account_id    = azurerm_storage_account.artifacts.id
  container_access_type = "private"
}

# Pad the destroy ordering so that, after the network rules are
# torn down (control-plane PATCH that resets ``default_action`` to
# ``Allow``), the change has time to propagate to the blob data
# plane before Terraform issues the container DELETE.  Without this
# pause, the container delete fires the moment the PATCH ARM call
# returns and routinely 403s against the still-locked-down blob
# endpoint.  ``create_duration`` is zero so the apply path is
# unaffected.
resource "time_sleep" "wait_for_storage_fw_propagation" {
  create_duration  = "0s"
  destroy_duration = "90s"

  depends_on = [azurerm_storage_container.artifacts]
}

# Lock down storage networking AFTER the container is created, so the
# Terraform SP (running outside the VNet) can perform the data-plane
# PUT that creates the container before the firewall goes up.
#
# Destroy order is enforced via ``time_sleep`` above: firewall is
# destroyed first (control-plane PATCH → ``default_action = Allow``),
# then the time_sleep destroy waits ``destroy_duration`` for the PATCH
# to reach the blob data plane, then the container is deleted via the
# blob endpoint without hitting a 403. Destroy MUST be invoked with
# ``-refresh=false`` (see
# ``tee_crafter.core.iac.platforms.run_terraform_destroy``); the
# pre-destroy refresh reads the container via the blob endpoint and
# would otherwise 403 against the locked-down account.
resource "azurerm_storage_account_network_rules" "artifacts_fw" {
  storage_account_id         = azurerm_storage_account.artifacts.id
  default_action             = "Deny"
  virtual_network_subnet_ids = [azurerm_subnet.vm_subnet.id]
  bypass                     = ["AzureServices"]

  # Also waits on every resource that MUTATES the subnet, not just on the
  # storage container.  Azure validates `virtual_network_subnet_ids` against
  # the subnet's live provisioning state, and attaching an NSG or a NAT gateway
  # puts the subnet into `Updating` for a few seconds.  Terraform saw no
  # ordering constraint between those attachments and this rule, so it ran them
  # concurrently and the ACL call failed:
  #
  #   NetworkAclsValidationFailure: SubnetsNotProvisioned: Cannot proceed with
  #   operation because subnets tee-crafter-sgx-subnet-... are not provisioned.
  #   They are in Updating state.
  #
  # Observed on sgx-azure on 2026-08-23.  It is a race, so it is intermittent,
  # and the cost of losing it is high: the apply fails near the end and the
  # retry rebuilds the Bastion host from scratch (~10 min, billed).
  depends_on = [
    time_sleep.wait_for_storage_fw_propagation,
    azurerm_subnet_network_security_group_association.nsg_assoc,
    azurerm_subnet_nat_gateway_association.vm_subnet_nat,
  ]
}

# --- AMD SEV-SNP Confidential VM ---

resource "azurerm_linux_virtual_machine" "snp_vm" {
  name                  = "tee-crafter-snp-vm-${local.did}"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = var.vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.nic.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = tls_private_key.ssh_key.public_key_openssh
  }

  # System-assigned managed identity, only when BYOK is on.
  #
  # Key Vault authorises `release` against an AAD principal, and the in-TEE
  # caller gets its token from IMDS -- so without an identity there is no way
  # for this VM to authenticate the release call at all, no matter how good its
  # attestation is. Microsoft's CVM SKR walkthrough makes this step 1.
  #
  # Gated rather than unconditional: an identity that exists is one more
  # principal a future role assignment could be hung off, and every process on
  # the VM can mint tokens for it via IMDS. Attestation does not need it -- the
  # SEV-SNP report is verified against AMD's root, and MAA (on the SKR path)
  # authenticates the *evidence*, not the caller -- so a deploy without --byok
  # has no identity.
  dynamic "identity" {
    for_each = var.byok_azure_kv ? [1] : []
    content {
      type = "SystemAssigned"
    }
  }

  os_disk {
    caching                  = "ReadWrite"
    storage_account_type     = "Premium_LRS"
    disk_size_gb             = 64
    # `DiskWithVMGuestState` triggers the Azure CRP confidential-VM provisioning
    # path (security_type = ConfidentialVM is inferred from this + vtpm_enabled +
    # secure_boot_enabled; azurerm 4.x has no direct `security_type` attribute
    # on `azurerm_linux_virtual_machine`). Encrypts both the OS disk and the
    # VMGS blob with a platform-managed key wrapped to the SNP guest.
    security_encryption_type = "DiskWithVMGuestState"
  }

  dynamic "source_image_reference" {
    for_each = var.custom_image_id == "" ? [1] : []
    content {
      publisher = "Canonical"
      offer     = "0001-com-ubuntu-confidential-vm-jammy"
      sku       = "22_04-lts-cvm"
      version   = "latest"
    }
  }

  source_image_id = var.custom_image_id != "" ? var.custom_image_id : null

  priority        = var.use_spot_instance ? "Spot" : "Regular"
  eviction_policy = var.use_spot_instance ? "Deallocate" : null
  max_bid_price   = var.use_spot_instance ? -1 : null

  secure_boot_enabled = true
  vtpm_enabled        = true

  boot_diagnostics {}

  timeouts {
    create = "45m"
    delete = "30m"
  }

  tags = {
    Project = "tee-crafter-snp"
    TEE     = "AMD-SEV-SNP"
  }

  depends_on = [azurerm_bastion_host.bastion]
}

# --- Outputs ---

output "vm_private_ip" {
  value = azurerm_network_interface.nic.private_ip_address
}

output "vm_id" {
  value = azurerm_linux_virtual_machine.snp_vm.id
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.snp_vm.name
}

output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "bastion_name" {
  value = azurerm_bastion_host.bastion.name
}

output "ssh_private_key_path" {
  value     = local_sensitive_file.ssh_private_key.filename
  sensitive = true
}

output "admin_username" {
  value = var.admin_username
}

output "storage_account_name" {
  value = azurerm_storage_account.artifacts.name
}

output "measurement" {
  value = var.measurement
}

output "vnet_flow_log_workspace" {
  value = azurerm_log_analytics_workspace.flow_logs.name
}

output "byok_kv_egress_scope" {
  value       = local.byok_kv_scope
  description = "How far the BYOK Key Vault NSG egress rule reaches. private-endpoint = one address, your vault only. regional-service-tag = every Key Vault in that Azure region, any tenant. global-service-tag = every Key Vault in Azure, any tenant -- scope it with byok_kv_private_endpoint_cidr or byok_kv_service_tag_region."
}

output "setup_egress_mode" {
  value       = var.allow_setup_egress ? "open-for-setup" : "locked-down"
  description = "NET-1: post-bake egress lockdown state. open-for-setup attaches a NAT gateway + public IP for first-boot package installs; locked-down keeps only VirtualNetwork + IMDS + wireserver + attestation egress."
}

output "secure_boot_mode" {
  value       = "enforcing (Azure Trusted Launch — secure_boot_enabled = true)"
  description = "UEFI Secure Boot posture for this Azure SNP deployment. Always enforcing — the azurerm_linux_virtual_machine resource hard-codes secure_boot_enabled = true and vtpm_enabled = true (implies security_type = ConfidentialVM)."
}

output "vm_identity_principal_id" {
  # Empty unless byok_azure_kv is set (see the `identity` block on the VM).
  # The deploy grants this principal `release` on the Key Vault key; that grant
  # cannot be pre-made because the principal does not exist until apply.
  value       = try(one(azurerm_linux_virtual_machine.snp_vm.identity[*].principal_id), "")
  description = "System-assigned managed identity of the SEV-SNP CVM, for Key Vault `release`."
}
