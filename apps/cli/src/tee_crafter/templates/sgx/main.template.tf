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
      source = "hashicorp/azurerm"
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
  # Rely on pre-registered resource providers; avoid attempting
  # to register providers (e.g., Microsoft.NotificationHubs,
  # Microsoft.Security) that this service principal cannot register.
  resource_provider_registrations = "none"
}

# --- Variables ---

variable "azure_location" {
  type        = string
  default     = "westus"
  description = "Azure region for deployment."
}

variable "vm_size" {
  type        = string
  default     = "__INSTANCE_TYPE__"
  description = "Azure VM size. Must be a DCsv3/DCdsv3 series for SGX support."
}

variable "admin_username" {
  type        = string
  default     = "azureuser"
  description = "Admin username for the VM."
}

variable "mrenclave" {
  type        = string
  default     = ""
  description = "Expected MRENCLAVE value for the SGX enclave."
}

variable "mrsigner" {
  type        = string
  default     = ""
  description = "Expected MRSIGNER value for the SGX enclave."
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

variable "graminize_egress" {
  type        = bool
  default     = true
  description = <<-EOT
    Open outbound 80/443 (via the NAT gateway) for the GSC build only, as a
    separately-named NSG rule the CLI deletes once graminizing is done and
    before the workload runs. Defaults to true because `sgx-azure --batch`
    cannot graminize without it: GSC's build stage is `FROM <the user's image>`
    and apt-installs Gramine's runtime dependencies into it, and that image is
    not known until deploy so it cannot be pre-baked. Everything else GSC needs
    IS pre-baked (see setup_sgx.sh §5c). Set false only if you have arranged
    another way for that apt transaction to succeed.
  EOT
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
  filename        = abspath("${path.module}/sgx_ssh_key")
  file_permission = "0600"
}

# --- Resource Group ---

resource "azurerm_resource_group" "sgx" {
  name     = "tee-crafter-sgx-rg-${local.did}"
  location = var.azure_location

  tags = {
    Project = "tee-crafter-sgx"
  }
}

# --- Network ---

resource "azurerm_virtual_network" "sgx" {
  name                = "tee-crafter-sgx-vnet-${local.did}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.sgx.location
  resource_group_name = azurerm_resource_group.sgx.name
}

resource "azurerm_subnet" "sgx" {
  name                 = "tee-crafter-sgx-subnet-${local.did}"
  resource_group_name  = azurerm_resource_group.sgx.name
  virtual_network_name = azurerm_virtual_network.sgx.name
  address_prefixes     = ["10.0.1.0/24"]
  # azurerm 5.0 replaced the ``service_endpoints`` list with repeatable
  # ``service_endpoint`` blocks.
  service_endpoint {
    service = "Microsoft.Storage"
  }
}

# Azure Bastion requires a subnet named exactly "AzureBastionSubnet" with at least /26
resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.sgx.name
  virtual_network_name = azurerm_virtual_network.sgx.name
  address_prefixes     = ["10.0.2.0/26"]
}

# Bastion needs its own public IP (the VM does NOT get one)
resource "azurerm_public_ip" "bastion" {
  name                = "tee-crafter-sgx-bastion-pip-${local.did}"
  location            = azurerm_resource_group.sgx.location
  resource_group_name = azurerm_resource_group.sgx.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# --- Azure Bastion (Standard SKU for native SSH + tunneling) ---

resource "azurerm_bastion_host" "sgx" {
  name                = "tee-crafter-sgx-bastion-${local.did}"
  location            = azurerm_resource_group.sgx.location
  resource_group_name = azurerm_resource_group.sgx.name
  sku                 = "Standard"
  tunneling_enabled   = true

  ip_configuration {
    name                 = "bastion-ip-config"
    subnet_id            = azurerm_subnet.bastion.id
    public_ip_address_id = azurerm_public_ip.bastion.id
  }

  tags = {
    Project = "tee-crafter-sgx"
  }
}

# --- NSG: Zero public ingress, locked-down egress ---

resource "azurerm_network_security_group" "sgx" {
  name                = "tee-crafter-sgx-nsg-${local.did}"
  location            = azurerm_resource_group.sgx.location
  resource_group_name = azurerm_resource_group.sgx.name

  # Allow SSH only from the Bastion subnet (not from the internet)
  security_rule {
    name                       = "AllowSSHFromBastion"
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

  # HTTPS for VPC endpoints + package repos (conditional)
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

  # Ephemeral egress for the GSC build, and nothing else.
  #
  # Graminizing is a source build.  Almost all of it is pre-baked now — the
  # image ships a base-Gramine image built at bake time, so `gsc build` skips
  # the compile stage — but GSC's *build* stage is `FROM <the user's image>` and
  # apt-installs Gramine's runtime dependencies into it.  The user's image is
  # not known until deploy, so that one apt transaction is the only thing left
  # that needs the internet.
  #
  # This rule is deliberately separate from `allow_setup_egress`, which rewrites
  # `AllowHTTPSEgress` in place and stays for the life of the VM.  This one is
  # its own named rule so `batch.close_graminize_egress` can delete exactly it,
  # by name, once the build is done and before the workload runs — the deploy
  # fails if that deletion does not succeed.  Bare minimum in time as well as
  # in scope: the workload itself still runs under DenyAllOutbound.
  dynamic "security_rule" {
    for_each = var.graminize_egress ? [1] : []
    content {
      name                       = "AllowGraminizeEgress"
      priority                   = 125
      direction                  = "Outbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_ranges    = ["80", "443"]
      source_address_prefix      = "*"
      destination_address_prefix = "Internet"
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

# --- Virtual network flow logs (NSG flow log creation blocked by Azure after June 2025) ---

data "azurerm_network_watcher" "regional" {
  name                = "NetworkWatcher_${replace(var.azure_location, " ", "")}"
  resource_group_name = "NetworkWatcherRG"
}

resource "azurerm_log_analytics_workspace" "flow_logs" {
  name                = "tee-crafter-sgx-flow-${local.did}"
  location            = azurerm_resource_group.sgx.location
  resource_group_name = azurerm_resource_group.sgx.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Project = "tee-crafter-sgx"
  }
}

resource "azurerm_network_watcher_flow_log" "vnet" {
  network_watcher_name = data.azurerm_network_watcher.regional.name
  resource_group_name  = data.azurerm_network_watcher.regional.resource_group_name
  name                 = "tee-crafter-sgx-vnet-flow-${local.did}"

  target_resource_id = azurerm_virtual_network.sgx.id
  storage_account_id = azurerm_storage_account.sgx.id
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
    Project = "tee-crafter-sgx"
  }
}

resource "azurerm_network_interface" "sgx" {
  name                = "tee-crafter-sgx-nic-${local.did}"
  location            = azurerm_resource_group.sgx.location
  resource_group_name = azurerm_resource_group.sgx.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.sgx.id
    private_ip_address_allocation = "Dynamic"
    # No public IP — access is via Azure Bastion only
  }
}

resource "azurerm_subnet_network_security_group_association" "sgx" {
  subnet_id                 = azurerm_subnet.sgx.id
  network_security_group_id = azurerm_network_security_group.sgx.id
}

# NAT Gateway for setup egress. Azure's default outbound SNAT is
# deprecated for new deployments after Sep 2025.

locals {
  # The NAT gateway is the *path* to the internet; the NSG rules above are the
  # *policy*. Both are required — an NSG Allow with no NAT still cannot leave
  # the VNet, because these VMs have no public IP and Azure withdrew default
  # outbound access. `graminize_egress` is in here for the same reason
  # `allow_setup_egress` is: without NAT its rule would permit traffic that has
  # nowhere to go, and `gsc build` would fail exactly as if the rule were absent.
  needs_nat = var.allow_setup_egress || var.graminize_egress || length(var.siem_egress_cidrs) > 0
}

resource "azurerm_public_ip" "nat_pip" {
  count               = local.needs_nat ? 1 : 0
  name                = "tee-crafter-sgx-nat-pip-${local.did}"
  location            = azurerm_resource_group.sgx.location
  resource_group_name = azurerm_resource_group.sgx.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = { Project = "tee-crafter-sgx" }
}

resource "azurerm_nat_gateway" "nat" {
  count                   = local.needs_nat ? 1 : 0
  name                    = "tee-crafter-sgx-nat-${local.did}"
  location                = azurerm_resource_group.sgx.location
  resource_group_name     = azurerm_resource_group.sgx.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 4

  tags = { Project = "tee-crafter-sgx" }
}

resource "azurerm_nat_gateway_public_ip_association" "nat_pip_assoc" {
  count                = local.needs_nat ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.nat[0].id
  public_ip_address_id = azurerm_public_ip.nat_pip[0].id
}

resource "azurerm_subnet_nat_gateway_association" "vm_subnet_nat" {
  count          = local.needs_nat ? 1 : 0
  subnet_id      = azurerm_subnet.sgx.id
  nat_gateway_id = azurerm_nat_gateway.nat[0].id
}

# --- Storage Account (for artifact upload) ---

resource "random_id" "storage_suffix" {
  byte_length = 4
}

locals {
  did = random_id.storage_suffix.hex
}

resource "azurerm_storage_account" "sgx" {
  name                            = "teecraftersgx${random_id.storage_suffix.hex}"
  resource_group_name             = azurerm_resource_group.sgx.name
  location                        = azurerm_resource_group.sgx.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "artifacts" {
  name = "sgx-artifacts"
  # azurerm 5.0 removed ``storage_account_name`` from
  # azurerm_storage_container in favour of the account's resource id.
  storage_account_id    = azurerm_storage_account.sgx.id
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
resource "azurerm_storage_account_network_rules" "sgx_fw" {
  storage_account_id         = azurerm_storage_account.sgx.id
  default_action             = "Deny"
  virtual_network_subnet_ids = [azurerm_subnet.sgx.id]
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
    azurerm_subnet_network_security_group_association.sgx,
    azurerm_subnet_nat_gateway_association.vm_subnet_nat,
  ]
}

# --- VM (private-only, no public IP, no SSH from internet) ---

resource "azurerm_linux_virtual_machine" "sgx" {
  name                  = "tee-crafter-sgx-vm-${local.did}"
  resource_group_name   = azurerm_resource_group.sgx.name
  location              = azurerm_resource_group.sgx.location
  size                  = var.vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.sgx.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = tls_private_key.ssh.public_key_openssh
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = 30
  }

  priority        = var.use_spot_instance ? "Spot" : "Regular"
  eviction_policy = var.use_spot_instance ? "Deallocate" : null
  max_bid_price   = var.use_spot_instance ? -1 : null

  # SGX-on-Azure DCsv3 is an application-enclave platform, not a Confidential
  # VM — the host kernel is fully trusted by the application's threat model.
  # Even so, we keep Secure Boot + vTPM on unconditionally so the *host*
  # provides measured-boot evidence (vTPM PCRs) alongside the SGX quote.
  # The baked SGX image (from ``tee-crafter internal bake-ami --tee-platform
  # sgx-azure``) installs SGX/PSW/Gramine from signed Intel + Gramine apt
  # repos with `signed-by` GPG, so no unsigned kernel module is loaded;
  # therefore kernel lockdown under Secure Boot does not block the SGX
  # userspace stack. SUP-3: lockdown stays enforced on production deploys.
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
    Name    = "TEECrafterSGXHost"
    Project = "tee-crafter-sgx"
  }
}

# --- Outputs ---

output "vm_private_ip" {
  value = azurerm_network_interface.sgx.private_ip_address
}

output "vm_id" {
  value = azurerm_linux_virtual_machine.sgx.id
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.sgx.name
}

output "resource_group" {
  value = azurerm_resource_group.sgx.name
}

output "bastion_name" {
  value = azurerm_bastion_host.sgx.name
}

output "ssh_private_key_path" {
  value     = local_sensitive_file.ssh_private_key.filename
  sensitive = true
}

output "admin_username" {
  value = var.admin_username
}

output "storage_account_name" {
  value = azurerm_storage_account.sgx.name
}

output "mrenclave" {
  value = var.mrenclave
}

output "mrsigner" {
  value = var.mrsigner
}

output "vnet_flow_log_workspace" {
  value = azurerm_log_analytics_workspace.flow_logs.name
}

output "setup_egress_mode" {
  value       = var.allow_setup_egress ? "open-for-setup" : "locked-down"
  description = "NET-1: post-bake egress lockdown state for the SGX VM. open-for-setup attaches a NAT gateway for first-boot DCAP/driver installs; locked-down keeps only VirtualNetwork + IMDS + PCCS/DCAP egress."
}

output "secure_boot_mode" {
  value       = "enforcing (Azure Trusted Launch — secure_boot_enabled = true)"
  description = "UEFI Secure Boot posture for this Azure SGX deployment. Always enforcing — the azurerm_linux_virtual_machine resource hard-codes secure_boot_enabled = true and vtpm_enabled = true, which implies security_type = TrustedLaunch."
}
