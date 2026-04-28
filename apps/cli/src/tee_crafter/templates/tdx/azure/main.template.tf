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
  features {}
  resource_provider_registrations = "none"
}

# --- Variables ---

variable "azure_location" {
  type        = string
  default     = "westus"
  description = "Azure region for deployment. TDX (DCesv6/ECesv6) requires westus or westus3."
}

variable "vm_size" {
  type        = string
  default     = "__INSTANCE_TYPE__"
  description = "Azure VM size. Must be a DCesv6/ECesv6 series for TDX support."
}

variable "admin_username" {
  type        = string
  default     = "azureuser"
  description = "Admin username for the VM."
}

variable "mrtd" {
  type        = string
  default     = ""
  description = "Expected MRTD value for the TDX Trust Domain."
}

variable "custom_image_id" {
  type        = string
  default     = ""
  description = "Custom Azure VM image with pre-baked dependencies. Overrides base image when set."
}

variable "use_spot_instance" {
  type        = bool
  default     = false
  description = "If true, deploys an Azure Spot VM to reduce cost. Default false (On-Demand)."
}

variable "allow_setup_egress" {
  type        = bool
  default     = false
  description = "Allow HTTP/HTTPS egress for package installs. Defaults to false (locked down). Set to true only during first-time setup without a pre-baked image."
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
  description = "Public CIDRs the in-TEE SIEM exporter is allowed to reach on `siem_egress_ports`. When non-empty, an Outbound NSG rule scoped to these prefixes is added at priority 130+."
}

variable "siem_egress_ports" {
  type        = list(number)
  default     = [443]
  description = "Ports the SIEM egress allowlist applies to (defaults to 443)."
}

# --- SSH Key ---

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_sensitive_file" "ssh_private_key" {
  content         = tls_private_key.ssh.private_key_pem
  filename        = abspath("${path.module}/tdx_ssh_key")
  file_permission = "0600"
}

# --- BYOK (Key Vault) reachability ---
# Set by the CLI (export_byok_tf_vars) when --byok azure-kv is used.  Adds a
# Microsoft.KeyVault service endpoint + NSG egress allow to the AzureKeyVault
# service tag so the in-TEE Secure Key Release reaches the vault over the Azure
# backbone under deny-all egress.  Without it the release hangs (fail-closed).
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

# --- MAA egress (TEE_CRAFTER_TDX_EVIDENCE_FORMAT=azure-guest) ---------------
#
# Required, not optional, on a paravisor CVM. The guest there cannot produce an
# Intel DCAP quote -- the vTPM yields a raw MAC'd TDREPORT -- so its only
# verifiable evidence is an MAA token, and fetching one means reaching
# *.attest.azure.net on 443. Under the deny-all Outbound rule below, without
# this the TD cannot attest at all and the deploy fails at verify time, after
# the money has been spent.
#
# Same scoping discipline as the Key Vault rule: prefer the REGIONAL service
# tag. The global `AzureAttestation` tag covers every MAA instance in Azure, and
# a rule whose purpose is "reach our attestation provider" should not double as
# a channel to an attacker's.
variable "attest_maa_egress" {
  type        = bool
  default     = false
  description = "When true (TEE_CRAFTER_TDX_EVIDENCE_FORMAT=azure-guest), add an NSG egress allow to the AzureAttestation service tag so the in-TEE guest-attestation client can reach MAA under deny-all egress."
}

# Retained only so an existing tfvars file does not error, and deliberately
# unused. Azure publishes NO regional AzureAttestation service tag -- verified
# with `az network list-service-tags`, which returns exactly `AzureAttestation`
# for every location, in contrast to `AzureKeyVault`, which has dozens of
# regional variants. Setting this used to emit `AzureAttestation.<Region>`,
# an NSG rule Azure rejects at apply time -- after the VM exists.
variable "maa_service_tag_region" {
  type        = string
  default     = ""
  description = "UNUSED. Azure has no regional AzureAttestation service tag; scope MAA egress with maa_endpoint_cidr instead. Kept only for tfvars compatibility."
}

variable "maa_endpoint_cidr" {
  type        = string
  default     = ""
  description = "CIDR of a private MAA endpoint. When set, MAA egress is allowed only to this address and no service tag is used."
}

locals {
  # No regional branch: `AzureAttestation.<Region>` is not a tag Azure knows.
  maa_destination = (
    var.maa_endpoint_cidr != "" ? var.maa_endpoint_cidr : "AzureAttestation"
  )

  maa_scope = (
    !var.attest_maa_egress ? "not-applicable (attest_maa_egress = false)" :
    var.maa_endpoint_cidr != "" ? "private-endpoint (${var.maa_endpoint_cidr})" :
    "global-service-tag (every Azure Attestation provider in every Azure tenant; Azure publishes no regional variant)"
  )

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

check "maa_egress_is_scoped" {
  assert {
    condition = !var.attest_maa_egress || var.maa_endpoint_cidr != ""
    error_message = join("", [
      "MAA egress is allowed to the GLOBAL `AzureAttestation` service tag, which ",
      "covers every Azure Attestation provider in every Azure tenant. That is wider ",
      "than this rule needs: the TD only ever talks to the one provider baked into ",
      "its image, and a workload that can reach any attestation endpoint can also ",
      "use one as an egress channel. ",
      "Unlike the Key Vault rule above there is no regional tag to fall back to -- ",
      "Azure publishes only the flat `AzureAttestation` tag -- so the single way to ",
      "scope this is `maa_endpoint_cidr`, pointing at a Private Endpoint for your ",
      "own attestation provider. Warning rather than error: the flat tag is the ",
      "documented default and must not break existing deploys.",
    ])
  }
}

# --- Resource Group ---

resource "azurerm_resource_group" "tdx" {
  name     = "tee-crafter-tdx-rg-${local.did}"
  location = var.azure_location

  tags = {
    Project = "tee-crafter-tdx"
  }
}

# --- Network ---

resource "azurerm_virtual_network" "tdx" {
  name                = "tee-crafter-tdx-vnet-${local.did}"
  address_space       = ["10.1.0.0/16"]
  location            = azurerm_resource_group.tdx.location
  resource_group_name = azurerm_resource_group.tdx.name
}

resource "azurerm_subnet" "tdx" {
  name                 = "tee-crafter-tdx-subnet-${local.did}"
  resource_group_name  = azurerm_resource_group.tdx.name
  virtual_network_name = azurerm_virtual_network.tdx.name
  address_prefixes     = ["10.1.1.0/24"]
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

resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.tdx.name
  virtual_network_name = azurerm_virtual_network.tdx.name
  address_prefixes     = ["10.1.2.0/26"]
}

resource "azurerm_public_ip" "bastion" {
  name                = "tee-crafter-tdx-bastion-pip-${local.did}"
  location            = azurerm_resource_group.tdx.location
  resource_group_name = azurerm_resource_group.tdx.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# --- Azure Bastion (Standard SKU for native SSH + tunneling) ---

resource "azurerm_bastion_host" "tdx" {
  name                = "tee-crafter-tdx-bastion-${local.did}"
  location            = azurerm_resource_group.tdx.location
  resource_group_name = azurerm_resource_group.tdx.name
  sku                 = "Standard"
  tunneling_enabled   = true

  ip_configuration {
    name                 = "bastion-ip-config"
    subnet_id            = azurerm_subnet.bastion.id
    public_ip_address_id = azurerm_public_ip.bastion.id
  }

  tags = {
    Project = "tee-crafter-tdx"
  }
}

# --- NSG: Zero public ingress, locked-down egress ---

resource "azurerm_network_security_group" "tdx" {
  name                = "tee-crafter-tdx-nsg-${local.did}"
  location            = azurerm_resource_group.tdx.location
  resource_group_name = azurerm_resource_group.tdx.name

  security_rule {
    name                       = "AllowSSHFromBastion"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.1.2.0/26"
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

  # Azure platform IP (168.63.129.16) — required for waagent provisioning,
  # health reporting, DNS resolution, and DHCP. Must always be reachable
  # on all ports/protocols. NOT internet egress; Azure internal infra only.
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

  # MAA egress. Active only when the build produces AzureGuest evidence.
  # Destination is `local.maa_destination`; see maa_endpoint_cidr /
  # maa_service_tag_region above for how to scope it below the global tag.
  dynamic "security_rule" {
    for_each = var.attest_maa_egress ? [1] : []
    content {
      name                       = "AllowMaaEgress"
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

resource "azurerm_network_interface" "tdx" {
  name                = "tee-crafter-tdx-nic-${local.did}"
  location            = azurerm_resource_group.tdx.location
  resource_group_name = azurerm_resource_group.tdx.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.tdx.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_subnet_network_security_group_association" "tdx" {
  subnet_id                 = azurerm_subnet.tdx.id
  network_security_group_id = azurerm_network_security_group.tdx.id
}

# NAT Gateway for setup egress. Azure's default outbound SNAT is
# deprecated for new deployments after Sep 2025.

locals {
  needs_nat = var.allow_setup_egress || length(var.siem_egress_cidrs) > 0
}

resource "azurerm_public_ip" "nat_pip" {
  count               = local.needs_nat ? 1 : 0
  name                = "tee-crafter-tdx-nat-pip-${local.did}"
  location            = azurerm_resource_group.tdx.location
  resource_group_name = azurerm_resource_group.tdx.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = { Project = "tee-crafter-tdx" }
}

resource "azurerm_nat_gateway" "nat" {
  count                   = local.needs_nat ? 1 : 0
  name                    = "tee-crafter-tdx-nat-${local.did}"
  location                = azurerm_resource_group.tdx.location
  resource_group_name     = azurerm_resource_group.tdx.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 4

  tags = { Project = "tee-crafter-tdx" }
}

resource "azurerm_nat_gateway_public_ip_association" "nat_pip_assoc" {
  count                = local.needs_nat ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.nat[0].id
  public_ip_address_id = azurerm_public_ip.nat_pip[0].id
}

resource "azurerm_subnet_nat_gateway_association" "vm_subnet_nat" {
  count          = local.needs_nat ? 1 : 0
  subnet_id      = azurerm_subnet.tdx.id
  nat_gateway_id = azurerm_nat_gateway.nat[0].id
}

# --- Virtual network flow logs (NSG flow log creation blocked by Azure after June 2025) ---

data "azurerm_network_watcher" "regional" {
  name                = "NetworkWatcher_${replace(var.azure_location, " ", "")}"
  resource_group_name = "NetworkWatcherRG"
}

resource "azurerm_log_analytics_workspace" "flow_logs" {
  name                = "tee-crafter-tdx-flow-${local.did}"
  location            = azurerm_resource_group.tdx.location
  resource_group_name = azurerm_resource_group.tdx.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Project = "tee-crafter-tdx"
  }
}

resource "azurerm_network_watcher_flow_log" "vnet" {
  network_watcher_name = data.azurerm_network_watcher.regional.name
  resource_group_name  = data.azurerm_network_watcher.regional.resource_group_name
  name                 = "tee-crafter-tdx-vnet-flow-${local.did}"

  target_resource_id = azurerm_virtual_network.tdx.id
  storage_account_id = azurerm_storage_account.tdx.id
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
    Project = "tee-crafter-tdx"
  }
}

# --- Storage Account (for artifact upload) ---

resource "random_id" "storage_suffix" {
  byte_length = 4
}

locals {
  did = random_id.storage_suffix.hex
}

resource "azurerm_storage_account" "tdx" {
  name                            = "teecraftertdx${random_id.storage_suffix.hex}"
  resource_group_name             = azurerm_resource_group.tdx.name
  location                        = azurerm_resource_group.tdx.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "artifacts" {
  name                  = "tdx-artifacts"
  # azurerm 5.0 removed ``storage_account_name`` from
  # azurerm_storage_container in favour of the account's resource id.
  storage_account_id    = azurerm_storage_account.tdx.id
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

# Lock down storage networking AFTER the container is created so the
# Terraform SP (running outside the VNet) can complete the data-plane
# PUT for the container before the firewall goes up. ``depends_on``
# (via ``time_sleep.wait_for_storage_fw_propagation``) also makes the
# firewall the leaf of the artifacts subgraph, so ``terraform destroy``
# removes the rules first (control-plane PATCH back to
# ``default_action = Allow``) and then waits before the container
# delete.  Destroy MUST be run with ``-refresh=false`` (see
# ``tee_crafter.core.iac.platforms.run_terraform_destroy``) — the
# pre-destroy refresh would otherwise call the blob data plane on the
# container and 403 against the still-locked-down account.
resource "azurerm_storage_account_network_rules" "tdx_fw" {
  storage_account_id         = azurerm_storage_account.tdx.id
  default_action             = "Deny"
  virtual_network_subnet_ids = [azurerm_subnet.tdx.id]
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
    azurerm_subnet_network_security_group_association.tdx,
    azurerm_subnet_nat_gateway_association.vm_subnet_nat,
  ]
}

# --- Confidential VM (TDX — no public IP, Bastion-only access) ---

resource "azurerm_linux_virtual_machine" "tdx" {
  name                  = "tee-crafter-tdx-vm-${local.did}"
  resource_group_name   = azurerm_resource_group.tdx.name
  location              = azurerm_resource_group.tdx.location
  size                  = var.vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.tdx.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = tls_private_key.ssh.public_key_openssh
  }

  # Managed identity for Secure Key Release, and only for that.
  #
  # Key Vault authorises `release` against an AAD principal, and the in-TEE
  # caller gets its token from IMDS -- so without an identity there is no way
  # for the TD to authenticate the release call at all, no matter how good its
  # attestation is. Microsoft's CVM SKR walkthrough makes this step 1.
  #
  # Gated rather than unconditional: an identity that exists is one more
  # principal that a future role assignment could be hung off, and every
  # process on the VM can mint tokens for it via IMDS. When BYOK is off it
  # would authorise nothing, but "authorises nothing today" is not a reason to
  # create it. Attestation does not need it -- MAA authenticates the *evidence*,
  # not the caller -- so a plain `tdx-azure` deploy has no identity.
  dynamic "identity" {
    for_each = var.byok_azure_kv ? [1] : []
    content {
      type = "SystemAssigned"
    }
  }

  os_disk {
    caching                  = "ReadWrite"
    storage_account_type     = "Premium_LRS"
    disk_size_gb             = 30
    # `DiskWithVMGuestState` triggers the Azure CRP confidential-VM provisioning
    # path (security_type = ConfidentialVM is inferred from this + vtpm_enabled
    # + secure_boot_enabled; azurerm 4.x has no direct `security_type`
    # attribute on `azurerm_linux_virtual_machine`).
    security_encryption_type = "DiskWithVMGuestState"
  }

  # TDX requires secure boot + vTPM
  priority        = var.use_spot_instance ? "Spot" : "Regular"
  eviction_policy = var.use_spot_instance ? "Deallocate" : null
  max_bid_price   = var.use_spot_instance ? -1 : null

  secure_boot_enabled = true
  vtpm_enabled        = true

  source_image_id = var.custom_image_id != "" ? var.custom_image_id : null

  dynamic "source_image_reference" {
    for_each = var.custom_image_id == "" ? [1] : []
    content {
      publisher = "Canonical"
      offer     = "0001-com-ubuntu-confidential-vm-jammy"
      sku       = "22_04-lts-cvm"
      version   = "latest"
    }
  }

  boot_diagnostics {
    # Managed storage — Azure auto-creates a storage account for serial console logs
  }

  timeouts {
    create = "45m"
    delete = "30m"
  }

  tags = {
    Name    = "TEECrafterTDXHost"
    Project = "tee-crafter-tdx"
  }
}

# --- Outputs ---

output "vm_private_ip" {
  value = azurerm_network_interface.tdx.private_ip_address
}

output "vm_id" {
  value = azurerm_linux_virtual_machine.tdx.id
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.tdx.name
}

output "resource_group" {
  value = azurerm_resource_group.tdx.name
}

output "bastion_name" {
  value = azurerm_bastion_host.tdx.name
}

output "ssh_private_key_path" {
  value     = local_sensitive_file.ssh_private_key.filename
  sensitive = true
}

output "admin_username" {
  value = var.admin_username
}

output "storage_account_name" {
  value = azurerm_storage_account.tdx.name
}

output "vm_identity_principal_id" {
  # Empty unless byok_azure_kv is set (see the `identity` block on the VM).
  # The deploy grants this principal `release` on the Key Vault key; that grant
  # cannot be pre-made because the principal does not exist until apply.
  value       = try(one(azurerm_linux_virtual_machine.tdx.identity[*].principal_id), "")
  description = "System-assigned managed identity of the TDX CVM, for Key Vault `release`."
}

output "mrtd" {
  value = var.mrtd
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
  description = "NET-1: post-bake egress lockdown state for the TDX CVM. open-for-setup attaches a NAT gateway for first-boot package installs; locked-down keeps only VirtualNetwork + IMDS + attestation egress."
}

output "secure_boot_mode" {
  value       = "enforcing (Azure Trusted Launch — secure_boot_enabled = true)"
  description = "UEFI Secure Boot posture for this Azure TDX deployment. Always enforcing — the azurerm_linux_virtual_machine resource hard-codes secure_boot_enabled = true and vtpm_enabled = true (implies security_type = ConfidentialVM)."
}
