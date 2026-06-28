## Azure Setup for TEE-Crafter (SGX, TDX & AMD SEV-SNP)

TEE-Crafter uses **Azure** for the SGX (`--tee-platform sgx-azure`), TDX (`--tee-platform tdx-azure`), AMD SEV-SNP (`--tee-platform snp-azure`), and GPU CC (`--tee-platform gpu-cc-azure`) backends.
**All infrastructure (resource groups, VMs, networking, storage, VNet flow logs with Traffic Analytics) is created automatically** by TEE-Crafter via Terraform and the Azure CLI. You only need to set up credentials and ensure your subscription has the right quota. Each deployment creates a dedicated VNet with virtual network flow logs stored to a per-deployment Log Analytics workspace (10-minute aggregation, 30-day retention).

| Platform | VM Series | TEE Technology |
|---|---|---|
| **SGX** | DCsv3 / DCdsv3 | Intel SGX process-level enclaves via Gramine |
| **TDX** | DCesv6 / ECesv6 | Intel TDX whole-VM confidential computing |
| **SNP-Azure** | DCasv5 / ECasv5 | AMD SEV-SNP whole-VM confidential computing |
| **GPU CC** | NCC H100 v5 | AMD SEV-SNP + NVIDIA Confidential Computing |

**GPU CC (`gpu-cc-azure`) — Secure Boot:** Deployed NCC H100 v5 VMs use **`secure_boot_enabled = false`** in Terraform so the NVIDIA **open** DKMS driver can load. Azure NCC H100 v5 VMs expose the GPU with PCI ID `10de:2321` (GA103), which is not supported by any pre-built Canonical-signed kernel module — only the DKMS-compiled `nvidia-headless-550-open` can initialize this device. **SEV-SNP**, **`VMGuestStateOnly`**, **vTPM**, dual attestation (SNP + NRAS), and Bastion-only access are unchanged. CPU-only Azure flows (`sgx-azure`, `tdx-azure`, `snp-azure`) still use **Secure Boot on**. **`bake-ami --tee-platform gpu-cc-azure`** uses **`--enable-secure-boot false`** on the temporary bake VM for consistency. See [gpu_flow.md](gpu_flow.md#secure-boot-on-gpu-cc-azure-and-gpu-cc-gcp).

---

### Step 1. Install and log in to Azure CLI

```bash
# macOS
brew install azure-cli

# Log in (opens browser)
az login

# If the browser cannot reach the localhost callback (SSH session, container,
# CI), use the device-code flow instead — it prints a URL and a short code:
az login --use-device-code
```

> On macOS with Homebrew's `azure-cli` 2.89.1, `az` runs on Python 3.14 and
> prints a `SyntaxWarning: "\/" is an invalid escape sequence` from
> `azure/mgmt/resource/.../_models.py` on some commands. It is harmless noise,
> but it lands on the same stream you are parsing and will corrupt a
> `--query... -o tsv` value you capture into a variable. Export
> `PYTHONWARNINGS=ignore` for scripted use.

---

### Step 2. Select the right subscription

```bash
az account list -o table
az account set --subscription <SUBSCRIPTION_ID_OR_NAME>

# Confirm
az account show --query "{name:name, id:id, state:state}" -o table
```

---

### Step 3. Register required resource providers

Run these once per subscription:

```bash
az provider register --namespace Microsoft.Compute --wait
az provider register --namespace Microsoft.Network --wait
az provider register --namespace Microsoft.Storage --wait
az provider register --namespace Microsoft.Resources --wait
az provider register --namespace Microsoft.OperationalInsights --wait
```

`Microsoft.OperationalInsights` is easy to miss: every Azure deploy creates an
`azurerm_log_analytics_workspace` for the per-deployment VNet flow logs, so it
is not optional even though nothing in the VM path needs it. Add
`Microsoft.KeyVault` too if you plan to use BYOK (`--byok azure-skr` on a CVM — see
[Secure Key Release on Azure](#secure-key-release-on-azure----byok-azure-skr)).

Verify:

```bash
for ns in Microsoft.Compute Microsoft.Network Microsoft.Storage \
          Microsoft.Resources Microsoft.OperationalInsights; do
  printf '%-32s %s\n' "$ns" \
    "$(PYTHONWARNINGS=ignore az provider show --namespace $ns \
        --query registrationState -o tsv)"
done
# All should print: Registered
```

Many subscriptions have these registered already — check before assuming you
need to run the register commands at all.

---

### Step 4. Ensure VM quota in your region

TEE-Crafter uses **On-Demand VMs by default**. Pass **`--spot`** (or set `TEE_CRAFTER_SPOT=1`) on `deploy` to use Azure Spot / low-priority (requires `Total Regional Low-priority vCPUs` quota). The internal `tee-crafter internal bake-ami` also accepts a `--spot` flag for the bake VM.

#### Region strategy

Azure confidential VM SKUs vary by region. TEE-Crafter defaults:

| Flow | Default Region | Reason |
|---|---|---|
| CPU TEE (SGX, TDX, SNP) | **`westus`** | All three CPU TEE families available |
| GPU CC | **`eastus2`** | `Standard_NCC40ads_H100_v5` available (also `centralus`, `westeurope`) — **TEE-Crafter always deploys `gpu-cc-azure` in `eastus2`** (ignores `AZURE_LOCATION`; matches NCC bake default) |

> **Important:** `Standard_NCC40ads_H100_v5` is **not available** in `westus` or `southcentralus`.

#### Quota summary per platform

| Platform | Default VM | vCPUs | Family Quota | Default Region |
|---|---|---|---|---|
| `sgx-azure` | `Standard_DC2s_v3` | 2 | `Standard DCSv3 Family vCPUs` | `westus` |
| `tdx-azure` | `Standard_DC2es_v6` | 2 | `Standard DCEV6 Family vCPUs` | `westus` |
| `snp-azure` | `Standard_DC2as_v5` | 2 | `Standard DCASv5 Family vCPUs` | `westus` |
| `gpu-cc-azure` | `Standard_NCC40ads_H100_v5` | 40 | `Standard NCCads2023 Family vCPUs` | `eastus2` |

#### Spot instances require an additional quota

Azure has a **separate Spot ceiling**: `Total Regional Low-priority vCPUs`. This must be >= the vCPUs of any Spot VM you launch. It defaults to **3** in most subscriptions.

| Quota | For | Minimum |
|---|---|---|
| `Total Regional Low-priority vCPUs` (West US) | Spot CPU TEE VMs | **2** (one at a time) |
| `Total Regional Low-priority vCPUs` (East US 2) | Spot GPU CC VM | **40** |

#### Minimum quotas needed (one VM at a time)

**West US (CPU TEE flows):**

| Quota Name | Current Default | Minimum Needed |
|---|---|---|
| Standard DCSv3 Family vCPUs | 8 | **2** (SGX) |
| Standard DCASv5 Family vCPUs | 8 | **2** (SNP) |
| Standard DCEV6 Family vCPUs | 10 | **2** (TDX) |
| Total Regional vCPUs | 26--48 | **2** |
| Total Regional Low-priority vCPUs | 3 | **2** (Spot, one VM at a time) |

**East US 2 (GPU CC flow):**

| Quota Name | Current Default | Minimum Needed |
|---|---|---|
| Standard NCCads2023 Family vCPUs | 0 | **40** |
| Total Regional vCPUs | 58 | **40** |
| Total Regional Low-priority vCPUs | 3 | **40** (only if using `--spot`) |

> **Note:** The GPU CC family quota is called `Standard NCCads2023 Family vCPUs`, **not** `NCCadsH100v5`. The latter is for non-confidential H100 VMs.

#### How to check your quotas

```bash
# West US (CPU TEE flows)
az vm list-usage --location westus --query "[?contains(name.value,'DCSv3') || contains(name.value,'DCASv5') || contains(name.value,'DCEV6') || contains(name.localizedValue,'Low-priority') || name.value=='cores']" --output table

# East US 2 (GPU CC)
az vm list-usage --location eastus2 --query "[?contains(name.value,'NCC') || contains(name.localizedValue,'Low-priority') || name.value=='cores']" --output table
```

#### How to request increases

1. Open **[Azure Portal > Quotas](https://portal.azure.com/#view/Microsoft_Azure_Quotas/QuotaOverview.ReactView)**
2. Select **Compute**
3. Filter by region and search for the quota family name
4. Click **Request increase**

Or via Azure CLI:

```bash
# Example: request NCCads2023 quota in East US 2
az quota create \
  --resource-name standardNCCads2023Family \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/providers/Microsoft.Compute/locations/eastus2" \
  --limit-object value=40 limit-object-type=LimitValue \
  --resource-type dedicated
```

#### SKU availability check

```bash
# Check if NCC H100 v5 exists in a region
az vm list-skus --location eastus2 \
  --query "[?name=='Standard_NCC40ads_H100_v5'].[name,family]" --output table

# Check CPU TEE SKUs in West US
az vm list-skus --location westus \
  --query "[?name=='Standard_DC2s_v3' || name=='Standard_DC2es_v6' || name=='Standard_DC2as_v5'].[name,family]" --output table
```

#### For SGX (`--tee-platform sgx-azure`): DCsv3/DCdsv3

```bash
az vm list-skus --location westus --resource-type virtualMachines \
  --query "[?starts_with(name,'Standard_DC') && contains(name,'v3')].[name]" -o tsv | sort -u
```

If **Standard DCSv3 Family vCPUs** shows `0/0`, request a quota increase.

#### For TDX (`--tee-platform tdx-azure`): DCesv6/ECesv6

```bash
az vm list-skus --location westus --resource-type virtualMachines \
  --query "[?starts_with(name,'Standard_DC') && contains(name,'v6')].[name]" -o tsv | sort -u
```

If quota is `0/0`, request an increase for **Standard DCEV6 Family vCPUs** -- at least **4 vCPUs**.

#### For AMD SEV-SNP (`--tee-platform snp-azure`): DCasv5/ECasv5

```bash
az vm list-skus --location westus --resource-type virtualMachines \
  --query "[?starts_with(name,'Standard_DC') && contains(name,'as_v5')].[name]" -o tsv | sort -u
```

If **Standard DCASv5 Family vCPUs** shows `0/0`, request a quota increase.

#### For GPU CC (`--tee-platform gpu-cc-azure`): NCC H100 v5

```bash
az vm list-skus --location eastus2 --resource-type virtualMachines \
  --query "[?contains(name,'NCC') && contains(name,'H100')].[name]" -o tsv

az vm list-usage --location eastus2 -o json | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
[print(f\"{i['name']['localizedValue']}: {i['currentValue']}/{i['limit']}\") \
 for i in d if 'NCC' in str(i['name'])]"
```

NCC H100 v5 is available in **East US 2**, **Central US**, and **West Europe**.
The family quota is `Standard NCCads2023 Family vCPUs` -- request at least **40 vCPUs**.

> **Common regions with AMD SEV-SNP support:** `eastus`, `westus`, `westus2`, `northeurope`, `westeurope`, `southcentralus`
>
> **Note:** Some student/credit subscriptions block confidential VM quota entirely.
> You may need a Pay-As-You-Go or sponsored subscription.

---

### Step 5. Create a service principal and configure `.env`

TEE-Crafter authenticates to Azure via a **service principal**. Give it **Contributor** on the subscription (or a specific resource group if you prefer tighter scoping):

> **The service principal is required — `az login` as yourself is not a
> substitute.** The CLI re-executes itself inside its Docker image, and the
> container has no access to your host's `az` token cache. Instead
> `bootstrap_cloud_auth` runs `az login --service-principal` inside the
> container using `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID`
> from your `.env` (see
> [`cli/cloud_auth.py`](../apps/cli/src/tee_crafter/cli/cloud_auth.py)). Your
> interactive login is only the means to *create* the SP in the first place. To
> confirm the container side works before spending money on a deploy:
>
> ```bash
> docker run --rm --env-file.env -e TEE_CRAFTER_IN_DOCKER=1 \
> --entrypoint /usr/bin/python3.12 tee-crafter:latest -c \
> "from tee_crafter.cli.cloud_auth import bootstrap_cloud_auth; \
> bootstrap_cloud_auth('snp-azure'); \
> import subprocess; print(subprocess.run(['az','account','show','-o','tsv','--query','user.type'],capture_output=True,text=True).stdout)"
> # -> servicePrincipal
> ```

```bash
# Get your subscription ID
az account show --query id -o tsv

# Create SP with Contributor on the subscription
az ad sp create-for-rbac \
  --name tee-crafter-sgx-sp \
  --role Contributor \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

This prints:

```json
{
  "appId": "00000000-...",
  "password": "xxxxxxxx-...",
  "tenant": "11111111-..."
}
```

Add these to your `.env`:

```ini
AZURE_SUBSCRIPTION_ID=<SUBSCRIPTION_ID>
AZURE_TENANT_ID=<tenant>
AZURE_CLIENT_ID=<appId>
AZURE_CLIENT_SECRET=<password>
AZURE_LOCATION=westus
# For GPU CC, use: AZURE_LOCATION=eastus2
```

> **Leave `TF_VAR_azure_location` unset.** It takes precedence over
> `AZURE_LOCATION` on the CPU TEE paths, but the GPU CC phase reads it with its
> *own* default of `eastus2`
> ([`deployment/gpu_cc/azure_phase.py`](../apps/cli/src/tee_crafter/cli/deployment/gpu_cc/azure_phase.py)).
> So pinning `TF_VAR_azure_location=westus` globally to serve SGX/TDX/SNP would
> also drag the GPU CC Network Watcher into `westus` while the NCC VM itself is
> created in `eastus2` — a region mismatch that `AZURE_LOCATION` alone avoids,
> because the GPU CC default then still applies.

> **`NVIDIA_NRAS_API_KEY`** (GPU CC only): `tee-crafter deploy` requires a **non-empty** value in the environment (typically this `.env` file) for `--tee-platform gpu-cc-azure`. Setup writes it to the VM’s `/opt/tee-crafter-gpu-cc/.env`. The NRAS GPU attestation path (v4 endpoint) does **not** send this variable as a Bearer token to NRAS—do not substitute an [NVIDIA NGC](https://ngc.nvidia.com) key and expect it to be an NRAS service key. **Do not pass secrets via CLI flags or shell history.**

> TEE-Crafter creates all resource groups automatically:
> - **`tee-crafter-bake-sgx-rg`** / **`tee-crafter-bake-tdx-rg`** / **`tee-crafter-bake-snp-rg`** / **`tee-crafter-bake-gpu-cc-rg`** — temporary, used during `bake-ami` and deleted after
> - **`tee-crafter-images-sgx-rg`** / **`tee-crafter-images-tdx-rg`** / **`tee-crafter-images-snp-rg`** / **`tee-crafter-images-gpu-cc-rg`** — persistent, stores captured VM images per platform
> - **`tee-crafter-sgx-rg`** / **`tee-crafter-tdx-rg`** / **`tee-crafter-snp-rg`** — created by Terraform during `deploy`
> - **`tee-crafter-gpu-cc-rg`** — auto-created during GPU CC deploy (Terraform)
>
> Every Azure bake (`sgx-azure`, `tdx-azure`, `snp-azure`, `gpu-cc-azure`) publishes
> the captured image as an **Azure Compute Gallery image version**. Trusted Launch
> and Confidential VMs cannot be captured to a managed image
> (`OperationNotAllowed: Creation of managed images are not supported for virtual
> machine with TrustedLaunch security type`), so the bake stages the generalized
> OS disk as a VHD and publishes it to a per-platform SIG:
>
> - `tee_crafter_sgx_gallery` / `tee_crafter_sgx_ubuntu` (`SecurityType=TrustedLaunchSupported`)
> - `tee_crafter_tdx_gallery` / `tee_crafter_tdx_ubuntu` (`SecurityType=ConfidentialVmSupported`)
> - `tee_crafter_snp_gallery` / `tee_crafter_snp_ubuntu` (`SecurityType=ConfidentialVmSupported`)
> - `tee_crafter_gpu_cc_gallery` / `tee_crafter_gpu_cc_ubuntu` (`SecurityType=ConfidentialVmSupported`)
>
> The bake prints a full gallery image-version ARM ID — that is the value to pass to
> `tee-crafter deploy --ami-id …` / `AZURE_*_IMAGE` in `.env`. VHD blobs live in a
> per-platform staging storage account (`teecraftersgxvhd`, `teecraftertdxvhd`,
> `teecraftersnpvhd`, `teecraftergpuccvhd`), overridable via
> `TEE_CRAFTER_{SGX,TDX,SNP,GPU_CC}_STORAGE_ACCOUNT`.
>
> You do **not** need to create any resource groups, galleries, or storage accounts manually.

If you already have an SP and lost the secret:

```bash
az ad sp list --display-name tee-crafter-sgx-sp --query "[0].appId" -o tsv
az ad app credential reset --id <APP_ID> --append --years 1
```

> **Cloud isolation — Azure-only deploys do NOT need AWS or GCP credentials.**
> When `--tee-platform` is `sgx-azure`, `tdx-azure`, `snp-azure`, or
> `gpu-cc-azure`, the CLI validates Azure (`az`) credentials only. AWS
> (`boto3`) and gcloud are never invoked, and any stale `AWS_*` /
> `GOOGLE_*` entries in your `.env` are ignored for that run. If Azure
> creds are missing, the CLI fails fast with an error pointing back to
> this document. Sandbox helpers under `apps/cli/byok-sandbox/azure/` follow the
> same rule (only need Azure creds; do not require AWS or GCP).

---

### Secure Key Release on Azure — `--byok azure-skr`

Works on all three Azure confidential-VM platforms: **`tdx-azure`**,
**`snp-azure`** and **`gpu-cc-azure`**.

> **History, because two earlier versions of this section were wrong in opposite
> directions.** The first said the deploy Terraform "creates the Confidential VM
> with a system-assigned managed identity"; it did not — no Azure template had an
> `identity` block. A later revision corrected that but then said
> `azure-skr` was `tdx-azure`-only, which was true of the *implementation* and
> not of the mechanism: the `AzureAttestSKR` install lived in
> `scripts/tdx_azure/setup_tdx.sh` and nowhere else. It is now
> `scripts/common/azure_guest_attestation.sh`, shared by all three bakes, and
> each of the three templates gained the managed identity and the MAA egress
> rule that a release needs. The commands below were run against a real
> subscription rather than written from the Azure docs.

#### Why `--byok azure-kv` is not the Azure path

Two reasons, either of which is fatal on its own:

1. **The release call was never authenticated.** Key Vault's `release` is an
 authenticated data-plane operation needing `Authorization: Bearer <AAD
 token>` for `https://vault.azure.net`. `AzureKeyVaultAdapter`'s default
 transport sent `Content-Type` and nothing else, so every real call returns
 401. It now refuses up front and says so instead of making the request.
2. **The key is wrapped to a key we cannot hold.** Key Vault picks the
 key-encryption key from the attestation token's top-level
 `x-ms-runtime.keys`, and on a CVM that key is `TpmEphemeralEncryptionKey` —
 *"a public RSA key owned and protected by the target execution
 environment"*, whose private half is sealed to the vTPM and reachable only
 through `azguestattestation1`. No Python process can unwrap it, so even with
 a token the release yields ciphertext nobody can open.

So Azure CVMs use **`--byok azure-skr`**, which delegates the release *and* the
unwrap to Microsoft's `AzureAttestSKR` — the process that holds the sealed key.
What comes back is the unwrapped DEK; the Key Vault key never enters our
process. `--byok azure-kv` remains correct only where you genuinely hold the
recipient private key (an external HSM flow, or tests).

#### What the deploy sets up for you

Three things, all gated on `--byok azure-{kv,skr}` so a deploy without BYOK gets
none of them:

| | Why a release fails without it |
|---|---|
| **System-assigned managed identity** on the VM | Key Vault authorises `release` against an AAD principal, and the in-TEE caller gets its token from IMDS. With no identity there is nothing to authenticate as, however good the attestation is. Gated because every process on the VM can mint tokens for an identity that exists. |
| **NSG egress to `AzureAttestation:443`** | `AzureAttestSKR` attests to MAA *before* it asks for the release, so under the template's deny-all egress MAA is the first hop that blocks. Scope it below the global tag with `TF_VAR_maa_endpoint_cidr` (a Private Endpoint) — Azure publishes no regional `AzureAttestation` tag, unlike `AzureKeyVault`. |
| **NSG egress to `AzureKeyVault:443`** + a `Microsoft.KeyVault` service endpoint | The release call itself. Narrow it with `TF_VAR_byok_kv_private_endpoint_cidr` or at least `TF_VAR_byok_kv_service_tag_region`; the global tag covers every vault in every tenant, which turns a rule meaning "reach our vault" into an exfiltration path. Terraform emits a `check` block that says so. |

What you still do by hand is **Steps A–D below**: the vault, the exportable key,
its release policy, and the `release` grant to the VM's identity. The grant
cannot be pre-made — the principal does not exist until after `terraform apply`,
which is why `vm_identity_principal_id` is a Terraform output.

#### It does *not* require a particular attestation format

`azure-skr` does **not** require
`TEE_CRAFTER_TDX_EVIDENCE_FORMAT=azure-guest`, and the reasoning that suggests
it should is inverted. The release policy does have to match
`x-ms-isolation-tee.*`, and only an `/attest/AzureGuest` token carries those
claims — but the token in question is the one **`AzureAttestSKR` fetches for
itself**, and that tool always uses `/attest/AzureGuest`. Our RA-TLS evidence
format is a separate decision: `snp-azure` and `gpu-cc-azure` have no
`TEE_CRAFTER_TDX_EVIDENCE_FORMAT` variable at all and SKR works on them
regardless. `core/keys/azure_skr_tool.py` reads exactly one endpoint variable,
`TEE_CRAFTER_MAA_ENDPOINT`, and nothing about the evidence format.

That variable is required, and the deploy refuses without it rather than letting
the VM find out — see `byok_mode.azure_skr_prerequisite_error`. Point it at the
same MAA instance your release policy names; releasing a key against a different
authority than the one that vouched for the channel would be two unrelated trust
decisions wearing one name.

#### Step A — create the vault in **access-policy** mode

`az keyvault create` now defaults to **RBAC** authorization, and that default is
a trap for the TEE-Crafter service principal:

- On an RBAC vault, every data-plane call needs a role such as
 `Key Vault Crypto Officer`.
- Granting a role needs `Microsoft.Authorization/roleAssignments/write`, which a
 plain **Contributor** SP does **not** have.
- `az keyvault update --enable-rbac-authorization false` is itself blocked, for
 the same reason — so the vault cannot be repaired after the fact and has to be
 deleted.

Pass the flag at creation time:

```bash
RG=tee-crafter-skr-rg
VAULT=tcskr$RANDOM # vault names are globally unique

az group create -n "$RG" -l westus -o none

az keyvault create -n "$VAULT" -g "$RG" -l westus \
 --sku premium \
 --enable-rbac-authorization false \
 --retention-days 7 \
 --query "{name:name, rbac:properties.enableRbacAuthorization}"
```

`--sku premium` is deliberate: Premium is HSM-backed and costs about **$1 per
key per month**, while Managed HSM is about **$3–5 per hour** whether or not you
use it. SKR works on both.

Then grant yourself data-plane access. This needs only vault-level management
rights, which Contributor has:

```bash
OID=$(az ad sp show --id "$AZURE_CLIENT_ID" --query id -o tsv)

az keyvault set-policy -n "$VAULT" --object-id "$OID" \
 --key-permissions create get list release update import delete -o none
```

#### Step B — create the exportable key and its release policy

The policy must address claims through the **nested** `x-ms-isolation-tee`
object. A policy written against the flat `/attest/TdxVm` claim names
(`tdx_mrtd`, a top-level `x-ms-attestation-type` of `tdxvm`) will never match,
because a CVM cannot produce that token shape at all:

```bash
cat > skr_policy.json <<'JSON'
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://sharedwus.wus.attest.azure.net",
      "allOf": [
        { "claim": "x-ms-isolation-tee.x-ms-attestation-type", "equals": "tdxvm" },
        { "claim": "x-ms-isolation-tee.x-ms-compliance-status", "equals": "azure-compliant-cvm" },
        { "claim": "x-ms-attestation-type", "equals": "azurevm" }
      ]
    }
  ]
}
JSON

az keyvault key create --vault-name "$VAULT" -n tee-crafter-dek \
 --kty RSA-HSM --size 3072 \
 --exportable true \
 --policy skr_policy.json \
 --ops encrypt decrypt \
 --query "key.kid"
```

`authority` must equal `TEE_CRAFTER_MAA_ENDPOINT` exactly — Key Vault compares
it against the token's `iss`.

**Match the isolation type to the platform, or nothing will ever release.** The
policy above pins `"tdxvm"`, which only `tdx-azure` presents; `snp-azure` and
`gpu-cc-azure` present `"sevsnpvm"` and Key Vault will refuse them for a reason
that has nothing to do with your code. A vault provisioned for one platform and
pointed at another is a silent trap — it was hit here, caught by
reading the attached policy before launching rather than after.

Use `anyOf` to cover more than one, and **bind the launch measurement**: without
a measurement claim the policy is satisfied by *any* compliant CVM in *any*
Azure tenant, which makes attestation-gated release nominal rather than real.
The SNP bake pins one measurement per vCPU tier (Milan and Genoa), so a policy
that should work across the instance family needs a branch per pinned value:

```bash
cat > skr_policy.json <<'JSON'
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://sharedwus.wus.attest.azure.net",
      "allOf": [
        { "claim": "x-ms-attestation-type", "equals": "azurevm" },
        { "claim": "x-ms-isolation-tee.x-ms-attestation-type", "equals": "sevsnpvm" },
        { "claim": "x-ms-isolation-tee.x-ms-compliance-status", "equals": "azure-compliant-cvm" },
        { "claim": "x-ms-isolation-tee.x-ms-sevsnpvm-launchmeasurement", "equals": "<measurement for tier 1>" }
      ]
    },
    {
      "authority": "https://sharedwus.wus.attest.azure.net",
      "allOf": [
        { "claim": "x-ms-attestation-type", "equals": "azurevm" },
        { "claim": "x-ms-isolation-tee.x-ms-attestation-type", "equals": "sevsnpvm" },
        { "claim": "x-ms-isolation-tee.x-ms-compliance-status", "equals": "azure-compliant-cvm" },
        { "claim": "x-ms-isolation-tee.x-ms-sevsnpvm-launchmeasurement", "equals": "<measurement for tier 2>" }
      ]
    }
  ]
}
JSON
```

The measurements come from the bake, which prints them and writes them to the
registry:

```bash
python3 -c "import json,glob;print(json.load(open(glob.glob(
 'apps/cli/src/tee_crafter/measurements/snp-azure/*.json')[-1]))['measurements'])"
```

To change a policy on an existing key (the attribute is mutable unless you set
`--immutable true`):

```bash
az keyvault key set-attributes --vault-name "$VAULT" -n tee-crafter-dek \
 --immutable false --policy skr_policy.json
```

**Verify the policy actually attached**, and mind the casing:

```bash
az keyvault key show --vault-name "$VAULT" -n tee-crafter-dek \
 --query "releasePolicy.encodedPolicy" -o tsv
```

The field is **`releasePolicy`** (camelCase). Querying `release_policy` returns
`null`, which looks exactly like a policy that failed to attach — it cost a
round of debugging here.

#### Step C — grant the VM's managed identity `release`

The identity is created by Terraform **only when BYOK is enabled**
(`byok_azure_kv`), and deliberately so: an identity that exists is one more
principal a future role assignment can be hung off, and every process on the VM
can mint tokens for it via IMDS. Attestation does not need it — MAA
authenticates the *evidence*, not the caller — so a plain deploy has none.

The principal does not exist until after `apply`, so this grant is a post-deploy
step:

```bash
VM_OID=$(az vm show -g tee-crafter-tdx-rg \
 -n "$(az vm list -g tee-crafter-tdx-rg --query '[0].name' -o tsv)" \
 --query 'identity.principalId' -o tsv)

az keyvault set-policy -n "$VAULT" --object-id "$VM_OID" \
 --key-permissions get release -o none
```

`get` and `release` only — the TD never needs to create, import or delete.

> On an **RBAC** vault this step is
> `az role assignment create --role "Key Vault Crypto Service Release User"`,
> which the TEE-Crafter SP cannot perform. That is the other reason Step A uses
> access-policy mode.

#### Step D — wrap the DEK and point the deploy at it

Wrap it **locally**, against the key's public half. Do not use
`az keyvault key encrypt` for this: that call sends your plaintext DEK to Azure
over the wire, which defeats the point of holding it yourself — and Azure's own
help says the operation "is only strictly necessary for symmetric keys... since
protection with an asymmetric key can be performed using public portion of the
key". Download the public half instead and never let the DEK leave the machine:

```bash
# Public half only — no secret leaves Azure, no secret goes to Azure.
az keyvault key download --vault-name "$VAULT" -n tee-crafter-dek \
 -e PEM -f dek-pub.pem

python3 - <<'PY' > wrapped_dek.b64
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

pub = serialization.load_pem_public_key(open("dek-pub.pem", "rb").read)
dek = open("dek.bin", "rb").read # your 32-byte DEK
print(base64.b64encode(pub.encrypt(
 dek,
 padding.OAEP(mgf=padding.MGF1(hashes.SHA256),
 algorithm=hashes.SHA256, label=None),
)).decode)
PY
```

`RSA-OAEP-256` on the Azure side corresponds to OAEP with SHA-256 for both the
digest and MGF1, which is what the snippet above uses — they must match or the
in-TEE unwrap fails with a padding error that says nothing about why.

Put the result in `.env` as `TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK`, and set
`TEE_CRAFTER_BYOK=azure-skr` plus the key URL. `AzureAttestSKR` unwraps it
in-TEE using the released key; see the `azure-skr` block in `.env.example`
section 26.

#### Network path

The TD must reach both MAA and Key Vault under the template's deny-all egress.
The deploy opens both automatically — `TF_VAR_attest_maa_egress` for the
`AzureAttestation` tag and `TF_VAR_byok_azure_kv` for `AzureKeyVault`.

The two scope differently, and the asymmetry is Azure's, not ours:

- **Key Vault** publishes regional tags (`AzureKeyVault.WestUS`, and dozens
 more), so narrow it with `byok_kv_service_tag_region` — or better,
 `byok_kv_private_endpoint_cidr`. The global tag covers every vault in every
 Azure tenant, which turns a rule meant to reach *your* vault into an
 exfiltration path.
- **Attestation** publishes **only** the flat `AzureAttestation` tag. Verify for
 yourself:

 ```bash
 az network list-service-tags --location westus \
 --query "values[?contains(name,'Attestation')].name" -o tsv # -> AzureAttestation
 ```

 So there is no regional middle ground: either accept the flat tag or point
 `maa_endpoint_cidr` at a Private Endpoint for your own provider. An earlier
 revision of TEE-Crafter derived `AzureAttestation.WestUS` by analogy with Key
 Vault; Azure rejects that tag at apply time, *after* the VM has been created.

#### What is verified, and what is not

| Step | Status |
|---|---|
| A, B — vault + exportable key, policy attaches | **Run against a real subscription** |
| RBAC-mode dead end, and the `releasePolicy` casing | **Reproduced.** Both cost time here |
| D — local OAEP-SHA256 wrap against the downloaded public half | **Run.** Produces the expected 384-byte RSA-3072 ciphertext |
| C — granting the VM identity `release` | **Not exercised.** The `identity` block has never been applied on any of the three platforms |
| The MAA egress rule and the shared `AzureAttestSKR` bake | **Not exercised.** `terraform validate` passes 10/10 and the three rendered setup scripts pass `bash -n`, which is not the same as a bake or an apply |
| The in-TEE release and unwrap | **Exercised on hardware** — a live `snp-azure` CVM released the exportable key and unwrapped the DEK to bytes hashing to the pre-wrap value, both by hand and via `tee-crafter-secrets.service`. `tdx-azure` and `gpu-cc-azure` take the same code path and have not run it ([byok.md](byok.md), [pending.md](pending.md)) |

Treat C and D as untested until that run lands. Everything above is a
prerequisite for it, not evidence that it works.

Note the ordering that follows from this: `snp-azure` and `gpu-cc-azure` now have
the same SKR mechanism as `tdx-azure`, but proving the mechanism once on
`tdx-azure` should come first — it is the platform where the MAA path is already
under active debugging, so a failure there is cheaper to attribute.

### Rotating BYOK material without redeploying — `tee-crafter byok-stage`

For `snp-azure`, `tdx-azure`, and `gpu-cc-azure`, rotate the wrapped DEK (or HSM bearer) without rebuilding:

> `apps/cli/byok-sandbox/configs/` is created by the sandbox helper
> scripts; the JSON below does not exist until you run
> `wrap_dek.py` (or `generate_byok_config.py`) to produce it.

```bash
tee-crafter byok-stage \
    --platform tdx-azure \
    --byok-config apps/cli/byok-sandbox/configs/tdx-azure-rotated.json \
    --ssh-host <bastion-or-pip> --ssh-key ~/.ssh/tee-crafter-azure \
    --ssh-user azureuser
```

The new `byok.env` lands on **tmpfs** at `/run/tee-crafter-<platform>/byok.env` (mode 0600), the non-secret half goes to `byok.env.public` on disk, any stale on-disk `byok.env` is shredded, and the workload `try-restart`s. Required RBAC on the **deploy SP**: same as deploy time (Contributor on the RG for Bastion / SSH); nothing new on the **Key Vault** for rotation alone since release authorization comes from the VM's Managed Identity + SKR policy, not the deploy SP.

> **SGX-Azure** is intentionally not in the `byok-stage` list: SGX workloads consume BYOK config inside the Gramine manifest at build time, not from an env-file on the host. Rotate by re-baking instead.

---

### Step 6 (advanced). Use a minimal custom role

> **Important:** Terraform (and the AzureRM provider) **must** be able to call
> `Microsoft.Resources/subscriptions/providers/read` at the **subscription**
> scope to enumerate resource providers. If your service principal only has a
> resource‑group–scoped custom role, you will see errors like:
>
> `AuthorizationFailed: The client '<APP_ID>' does not have authorization to perform action 'Microsoft.Resources/subscriptions/providers/read' over scope '/subscriptions/<SUBSCRIPTION_ID>'`
>
> For most users, **sticking with subscription‑level
> Contributor from Step 5 is strongly recommended.**
>
> Only use this step if you are comfortable managing custom roles and you
> understand that you still need **some** subscription‑level role that includes
> `Microsoft.Resources/subscriptions/providers/read` (for example, a small
> subscription‑scoped custom role in addition to the resource‑group‑scoped one
> below).

For tighter permissions on the actual workload resources, you can create a
custom role scoped to the TEE-Crafter resource group:

```json
{
  "Name": "tee-crafter-sgx-operator",
  "IsCustom": true,
  "Description": "Minimal permissions for TEE-Crafter SGX deployments.",
  "Actions": [
    "Microsoft.Resources/subscriptions/providers/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Resources/subscriptions/resourceGroups/write",
    "Microsoft.Resources/deployments/*",
    "Microsoft.Compute/virtualMachines/*",
    "Microsoft.Compute/images/*",
    "Microsoft.Compute/disks/*",
    "Microsoft.Network/virtualNetworks/*",
    "Microsoft.Network/networkInterfaces/*",
    "Microsoft.Network/publicIPAddresses/*",
    "Microsoft.Network/bastionHosts/*",
    "Microsoft.Network/networkSecurityGroups/*",
    "Microsoft.Storage/storageAccounts/*",
    "Microsoft.KeyVault/vaults/*",
    "Microsoft.KeyVault/managedHSMs/*"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/tee-crafter-sgx-rg"
  ]
}
```

Create and assign:

```bash
az role definition create --role-definition @tee-crafter-sgx-role.json

# To edit later:
az role definition update --role-definition @tee-crafter-sgx-role.json

# Assign to SP:
az role assignment create \
  --assignee <APP_ID> \
  --role tee-crafter-sgx-operator \
  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/tee-crafter-sgx-rg
```

No additional Azure RBAC changes are needed for GPU CC: the existing **Contributor** role from Step 5 covers NCC H100 v5 VMs and the **NvidiaGpuDriverLinux** VM extension. The custom role in Step 6 already includes `Microsoft.Compute/virtualMachines/*`, which covers extensions.

### Step 7 (recommended). Read-only audit role for `verify-provenance`

`tee-crafter verify-provenance` emits a `CT-005` row by reading the
**Azure Activity Log** for Key Vault SKR (`release`) operations. The
deploy service principal needs read access to the Activity Log for the
target subscription:

```bash
az role assignment create \
  --assignee <DEPLOY_SP_OBJECT_ID> \
  --role "Monitoring Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

This is read-only and safe. Skipping it downgrades the matrix to a
`warn` row instead of blocking the deploy.

> **Not needed if you kept subscription-scoped Contributor from Step 5.**
> Contributor already grants `*/read`, which covers the Activity Log. Verified
> by having a Contributor-only SP run
> `az monitor activity-log list --offset 1h --max-events 1`, which succeeded
> with no `Monitoring Reader` assignment. This step matters only if you
> tightened to the Step 6 custom role, whose `Actions` list does not include
> the Activity Log.

---

### Quick reference

| What | Who creates it | When |
|---|---|---|
| Resource group (`tee-crafter-bake-sgx-rg`) | `bake-ami` (auto) | During SGX bake, deleted after |
| Resource group (`tee-crafter-bake-tdx-rg`) | `bake-ami` (auto) | During TDX bake, deleted after |
| Resource group (`tee-crafter-bake-snp-rg`) | `bake-ami` (auto) | During SNP bake, deleted after |
| Resource group (`tee-crafter-bake-gpu-cc-rg`) | `bake-ami` (auto) | During GPU CC bake, deleted after |
| Resource group (`tee-crafter-images-sgx-rg`) | `bake-ami` (auto) | Persistent — SGX captured images |
| Resource group (`tee-crafter-images-tdx-rg`) | `bake-ami` (auto) | Persistent — TDX captured images |
| Resource group (`tee-crafter-images-snp-rg`) | `bake-ami` (auto) | Persistent — SNP captured images |
| Resource group (`tee-crafter-images-gpu-cc-rg`) | `bake-ami` (auto) | Persistent — GPU CC captured images |
| Resource group (`tee-crafter-sgx-rg`) | Terraform (auto) | During SGX deploy |
| Resource group (`tee-crafter-tdx-rg`) | Terraform (auto) | During TDX deploy |
| Resource group (`tee-crafter-snp-rg`) | Terraform (auto) | During SNP-Azure deploy |
| Resource group (`tee-crafter-gpu-cc-rg`) | Terraform (auto) | During GPU CC deploy |
| VNet, NSG, Bastion, NIC, VM, Storage, VNet Flow Logs, Log Analytics | Terraform (auto) | During deploy |
| Key Vault + exportable key (`tee-crafter-skr-rg`) | **You** (once) | Only for BYOK — see [Secure Key Release](#secure-key-release-on-azure----byok-azure-skr). Persistent, and **not** created by Terraform: the vault may live in a different subscription than the deploy, and it outlives any single VM. |
| Service principal + `.env` | **You** (once) | Before first run |
| VM family quotas (see Step 4: DCSv3, DCEV6, DCASv5, NCCads2023) + Spot quota | **You** (once) | Before first run |
| Resource provider registration | **You** (once) | Before first run |

### Troubleshooting

| Issue | Fix |
|-------|-----|
| `kex_exchange_identification: read: Connection reset by peer` over Azure Bastion | Transient Bastion local-listener flake. TEE-Crafter retries every SSH / SCP call up to 4 times with exponential backoff (base 2). Tune with `TEE_CRAFTER_SSH_RETRIES` (default `4`) and `TEE_CRAFTER_SSH_RETRY_BACKOFF` (default `2.0`) in `.env`. The same retry wrapper applies to GCP IAP tunnels. |
| `OperationNotAllowed: Creation of managed images are not supported for virtual machine with TrustedLaunch security type` during `bake-ami` | TEE-Crafter never calls `az image create` on Azure. Every Azure bake (SGX-Azure, TDX-Azure, SNP-Azure, GPU-CC-Azure) publishes a gallery image version via the shared `capture_vhd_to_gallery` helper. Seeing this message means you are running a stale `tee-crafter` build — upgrade the package and re-run the bake. |
| `sgx-azure` bake VM has `--security-type TrustedLaunch` but Terraform demands the same | Intentional — the bake VM matches the deploy template's `secure_boot_enabled = true` / `vtpm_enabled = true` so the firmware path is identical. The image definition is tagged `SecurityType=TrustedLaunchSupported`. |
