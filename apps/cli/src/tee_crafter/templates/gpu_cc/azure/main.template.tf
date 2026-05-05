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
  default     = "eastus2"
  description = "Azure region with NCC H100 v5 confidential GPU VM support."
}

variable "vm_size" {
  type        = string
  default     = "__INSTANCE_TYPE__"
  description = "Azure VM size. Must be NCC H100 v5 series for NVIDIA Confidential GPU."
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
  description = "Public CIDRs the in-TEE SIEM exporter is allowed to reach on `siem_egress_ports`. When non-empty, an Outbound NSG rule scoped to these prefixes is added at priority 130+."
}

variable "siem_egress_ports" {
  type        = list(number)
  default     = [443]
  description = "Ports the SIEM egress allowlist applies to (defaults to 443)."
}

variable "allow_nras_egress" {
  type        = bool
  default     = true
  description = "Allow HTTPS egress to NVIDIA NRAS for GPU attestation. The destination is governed by nras_egress_cidrs below; setting this to false disables NRAS egress entirely (GPU CC attestation will fail)."
}

variable "nras_egress_cidrs" {
  type        = list(string)
  default     = []
  description = "Explicit CIDR list for NRAS egress, and the production path. NVIDIA does not publish NRAS ranges, so the CLI resolves nras.attestation.nvidia.com at deploy time and pins the resulting host routes here (see cli/deployment/common/nras_egress.py). When this is empty the NSG creates no NRAS rule at all and GPU attestation fails closed, unless allow_nras_broad_internet is explicitly set true."
}

variable "allow_nras_broad_internet" {
  type        = bool
  # NET-X: production-safe default is *strict* (false), and strict is now
  # satisfiable rather than merely fail-closed — the CLI resolves the NRAS
  # hostname and fills ``nras_egress_cidrs``. This knob is the dev hatch
  # (``TEE_CRAFTER_NRAS_STRICT=0``), set by the deploy phase only after a loud
  # warning plus an audit-trail entry. With the default ``false`` and an empty
  # ``nras_egress_cidrs`` the NSG creates no NRAS egress rule and the
  # application fails fast at attestation time.
  default     = false
  description = "Dev hatch. When true and nras_egress_cidrs is empty, the NSG opens HTTPS/443 egress to the Azure `Internet` service tag. Default false: strict CIDR-only, which the CLI satisfies by resolving nras.attestation.nvidia.com at deploy time."
}

variable "enable_secure_boot" {
  type    = bool
  default = false
  # SB-1: defaults OFF for *reliability* of the NVIDIA CC GPU stack, NOT
  # because the hardware forbids it.  Canonical ships signed pre-built
  # NVIDIA open kernel modules in linux-modules-nvidia-<VER>-azure-fde-
  # <KREL>; ``scripts/gpu_cc_azure/setup_gpu_cc_azure.sh`` already
  # detects kernel lockdown and walks a candidate list to install one of
  # those signed packages when Secure Boot is on.  Set this to ``true``
  # only after you have (a) verified a signed module exists for the
  # exact ${KERNEL_RELEASE} of the bake image, and (b) re-baked under
  # ``--enable-secure-boot`` so the bake VM exercises the signed path.
  # See docs/security.md §15.1 for the full trade-off analysis.
  description = "Opt-in: enable UEFI Secure Boot on the deployed CVM. Requires that a Canonical-signed linux-modules-nvidia-<VER>-azure-fde-<KREL> package exists for the running kernel; otherwise the NVIDIA driver will fail to load under kernel lockdown."
}

variable "measurement" {
  type        = string
  default     = ""
  description = "Expected AMD SEV-SNP launch measurement (SHA-384 hex)."
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
  name     = "tee-crafter-gpu-cc-rg-${local.did}"
  location = var.azure_location
}

# --- Networking ---

resource "azurerm_virtual_network" "vnet" {
  name                = "tee-crafter-gpu-cc-vnet-${local.did}"
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

# --- Bastion ---

resource "azurerm_public_ip" "bastion_pip" {
  name                = "tee-crafter-gpu-cc-bastion-pip-${local.did}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_bastion_host" "bastion" {
  name                = "tee-crafter-gpu-cc-bastion-${local.did}"
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

# --- NSG ---

resource "azurerm_network_security_group" "nsg" {
  name                = "tee-crafter-gpu-cc-nsg-${local.did}"
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

  # NVIDIA NRAS egress.
  # Priority: explicit CIDR list > "Internet" service tag, and the CIDR list is
  # what a normal deploy uses. GPU CC attestation MUST reach
  # nras.attestation.nvidia.com at runtime; because NVIDIA publishes no ranges
  # for it, the CLI resolves the hostname at deploy time and passes the
  # resulting /32s as `nras_egress_cidrs` (cli/deployment/common/nras_egress.py).
  # The Internet-tag rule below is NOT the default — `allow_nras_broad_internet`
  # defaults to `false`, and reaching it means someone set the
  # TEE_CRAFTER_NRAS_STRICT=0 dev hatch. With neither a CIDR list nor that
  # hatch, no NRAS rule is created and attestation fails fast, which is the
  # intended fail-closed posture.
  dynamic "security_rule" {
    for_each = var.allow_nras_egress && length(var.nras_egress_cidrs) > 0 ? [1] : []
    content {
      name                         = "AllowNRAS"
      priority                     = 210
      direction                    = "Outbound"
      access                       = "Allow"
      protocol                     = "Tcp"
      source_port_range            = "*"
      destination_port_range       = "443"
      source_address_prefix        = "*"
      destination_address_prefixes = var.nras_egress_cidrs
      description                  = "NVIDIA NRAS attestation (explicit CIDR allowlist)"
    }
  }

  dynamic "security_rule" {
    for_each = (
      var.allow_nras_egress
      && length(var.nras_egress_cidrs) == 0
      && var.allow_nras_broad_internet
    ) ? [1] : []
    content {
      name                       = "AllowNRAS"
      priority                   = 210
      direction                  = "Outbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "443"
      source_address_prefix      = "*"
      destination_address_prefix = "Internet"
      description                = "NRAS attestation via Azure Internet tag (default; narrow with nras_egress_cidrs)"
    }
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

# NAT Gateway for NRAS/setup egress. Azure's default outbound SNAT is
# deprecated for new deployments after Sep 2025. An explicit NAT gateway
# provides a deterministic, auditable internet path.

locals {
  needs_nat = (
    var.allow_nras_egress
    || var.allow_setup_egress
    || length(var.siem_egress_cidrs) > 0
  )
}

resource "azurerm_public_ip" "nat_pip" {
  count               = local.needs_nat ? 1 : 0
  name                = "tee-crafter-gpu-cc-nat-pip-${local.did}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = { Project = "tee-crafter-gpu-cc" }
}

resource "azurerm_nat_gateway" "nat" {
  count                   = local.needs_nat ? 1 : 0
  name                    = "tee-crafter-gpu-cc-nat-${local.did}"
  location                = azurerm_resource_group.rg.location
  resource_group_name     = azurerm_resource_group.rg.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 4

  tags = { Project = "tee-crafter-gpu-cc" }
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

# --- Flow Logs ---

data "azurerm_network_watcher" "regional" {
  name                = "NetworkWatcher_${replace(var.azure_location, " ", "")}"
  resource_group_name = "NetworkWatcherRG"
}

resource "azurerm_log_analytics_workspace" "flow_logs" {
  name                = "tee-crafter-gpu-cc-flow-${local.did}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = { Project = "tee-crafter-gpu-cc" }
}

resource "azurerm_network_watcher_flow_log" "vnet" {
  network_watcher_name = data.azurerm_network_watcher.regional.name
  resource_group_name  = data.azurerm_network_watcher.regional.resource_group_name
  name                 = "tee-crafter-gpu-cc-vnet-flow-${local.did}"

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

  tags = { Project = "tee-crafter-gpu-cc" }
}

# --- NIC ---

resource "azurerm_network_interface" "nic" {
  name                = "tee-crafter-gpu-cc-nic-${local.did}"
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
  filename        = "${path.module}/gpu_cc_ssh_key.pem"
  file_permission = "0600"
}

resource "random_id" "deployment_suffix" {
  byte_length = 4
}

locals {
  did = random_id.deployment_suffix.hex
}

# --- Storage Account ---

resource "azurerm_storage_account" "artifacts" {
  name                            = "teecrgpucc${substr(md5(azurerm_resource_group.rg.id), 0, 8)}"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
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

# --- NCC H100 v5 Confidential GPU VM (AMD SEV-SNP + NVIDIA H100 CC) ---

resource "azurerm_linux_virtual_machine" "gpu_cc_vm" {
  name                  = "tee-crafter-gpu-cc-vm-${local.did}"
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
    disk_size_gb             = 200
    # `VMGuestStateOnly` (rather than `DiskWithVMGuestState`) lets the OS disk
    # remain readable by the host while still encrypting the SEV-SNP VMGS blob
    # that holds register state and the vTPM. This is the only mode Azure CRP
    # accepts for NCC H100 v5 confidential GPU VMs at this time; the GPU CC
    # threat model still relies on SNP memory encryption + NVIDIA NRAS, not
    # disk-at-rest encryption inside the guest.
    security_encryption_type = "VMGuestStateOnly"
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

  # SB-1: Secure Boot defaults OFF for the GPU CC Azure platform — see
  # docs/security.md §15.1 for the full analysis.  Short version:
  # Canonical *does* ship signed pre-built NVIDIA open kernel modules
  # (linux-modules-nvidia-<VER>-azure-fde-<KREL>) that work under
  # lockdown, but pinning to the exact driver version NVIDIA's CC
  # Deployment Guide recommends ties us to NVIDIA's CUDA apt repo (the
  # DKMS path), which is unsigned and rejected by lockdown.  Operators
  # whose driver version *is* covered by Canonical's signed modules can
  # flip ``var.enable_secure_boot = true`` — the bake script's
  # signed-module fallback then activates automatically.  vTPM stays on
  # so vTPM PCR0–7 measured boot (F-8) is captured either way.
  secure_boot_enabled = var.enable_secure_boot
  vtpm_enabled        = true

  boot_diagnostics {}

  timeouts {
    create = "60m"
    delete = "30m"
  }

  tags = {
    Project = "tee-crafter-gpu-cc"
    TEE     = "AMD-SEV-SNP-NVIDIA-CC"
  }

  depends_on = [azurerm_bastion_host.bastion]
}

# NOTE: NVIDIA GPU Driver Extension removed — driver comes from the bake image.

# --- Outputs ---

output "vm_private_ip" {
  value = azurerm_network_interface.nic.private_ip_address
}

output "vm_id" {
  value = azurerm_linux_virtual_machine.gpu_cc_vm.id
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.gpu_cc_vm.name
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
  description = "NET-1: post-bake egress lockdown state for the Azure GPU CC CVM. open-for-setup attaches a NAT gateway for first-boot driver installs; locked-down keeps only VirtualNetwork + IMDS + NRAS + attestation egress."
}

output "secure_boot_mode" {
  value       = var.enable_secure_boot ? "enforcing (operator opted in; NVIDIA driver must be signed by Canonical or shim MOK)" : "off by default (NVIDIA proprietary DKMS driver not signed)"
  description = "UEFI Secure Boot posture for this Azure GPU CC deployment. Defaults to OFF — the proprietary NVIDIA DKMS module isn't signed by Canonical's SB key out of the box, so enabling SB would prevent the GPU CC driver from loading at boot and break attestation. Operators on driver versions covered by Canonical's signed module set can flip var.enable_secure_boot = true; see docs/gpu_flow.md."
}

output "vm_identity_principal_id" {
  # Empty unless byok_azure_kv is set (see the `identity` block on the VM).
  # The deploy grants this principal `release` on the Key Vault key; that grant
  # cannot be pre-made because the principal does not exist until apply.
  value       = try(one(azurerm_linux_virtual_machine.gpu_cc_vm.identity[*].principal_id), "")
  description = "System-assigned managed identity of the GPU CC CVM, for Key Vault `release`."
}
