## GCP Setup for TEE-Crafter (AMD SEV-SNP & Intel TDX)

TEE-Crafter uses **GCP Confidential VMs** (and NVIDIA Confidential GPU on A3 with `--tee-platform gpu-cc-gcp`) for:


- `--tee-platform snp-gcp` — AMD SEV-SNP on **N2D** machines
- `--tee-platform tdx-gcp` — Intel TDX on **C3** machines
- `--tee-platform gpu-cc-gcp` — NVIDIA Confidential GPU on **A3** machines (Intel TDX + NVIDIA CC)

All infrastructure (VPC, firewall, GCS, KMS, VMs, VPC subnet flow logs) is created automatically by Terraform. Each deployment creates a dedicated VPC with subnet flow logs enabled (5-second aggregation, 100% sampling, full metadata).

---

### Step 1. Enable APIs (once, from your host machine)

```bash
gcloud auth login
gcloud config set project <PROJECT_ID>
gcloud services enable --quiet \
  compute.googleapis.com \
  iap.googleapis.com \
  storage.googleapis.com \
  cloudkms.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  cloudresourcemanager.googleapis.com \
  dns.googleapis.com
```

> **`dns.googleapis.com` is required for `--byok gcp-kms`** and was missing from
> this list previously. Under deny-all egress the deploy publishes a
> private Cloud DNS zone so `cloudkms.googleapis.com` resolves to the
> restricted Google APIs VIP, so Terraform creates a
> `google_dns_managed_zone`. Without the API the apply fails with
> `SERVICE_DISABLED` on `google_dns_managed_zone.googleapis` — and it fails
> *after* the container build and vulnerability scan, so you lose several
> minutes to a missing one-line prerequisite. Non-BYOK deploys never create the
> zone and do not need it.

> Run this as a principal that holds `serviceusage.services.enable` — your own
> Owner account. The least-privilege deployer service account in
> [Least-Privilege IAM](#least-privilege-iam-optional-recommended-for-production--ci)
> deliberately lacks it, so if you have already configured impersonation this
> command fails with `AUTH_PERMISSION_DENIED`. Unset
> `auth/impersonate_service_account`, enable the APIs, then set it back.

**GPU CC (`gpu-cc-gcp`):** No additional APIs are needed; the existing Compute, IAP, Storage, and KMS APIs above are sufficient. Deployed A3 VMs use **shielded instance `enable_secure_boot = false`** so the NVIDIA open DKMS module loads (Secure Boot on would enforce lockdown on unsigned modules). CPU TDX, vTPM, and dual attestation are unchanged. Details: [gpu_flow.md](gpu_flow.md#secure-boot-on-gpu-cc-azure-and-gpu-cc-gcp).

### Step 2. Authenticate (choose one)

> **If your project belongs to an organization, start with Option A.** Many
> organizations enforce `constraints/iam.disableServiceAccountKeyCreation`, which
> makes `gcloud iam service-accounts keys create` fail with
> `FAILED_PRECONDITION: Key creation is not allowed on this service account`.
> Options B and C below both need a key file and are simply unavailable to you in
> that case. Check with:
>
> ```bash
> gcloud resource-manager org-policies describe \
> constraints/iam.disableServiceAccountKeyCreation --effective \
> --project=$(gcloud config get-value project)
> ```

**Option A — User ADC + impersonation (no key file; works under the org policy above):**

Your own login is the base credential, and Terraform then impersonates the
least-privilege deployer service account. Requires
`roles/iam.serviceAccountTokenCreator` on that SA — granted in
[Least-Privilege IAM](#least-privilege-iam-optional-recommended-for-production--ci)
step 3 below.

```bash
gcloud auth login # if not already logged in
gcloud auth application-default login # creates ADC — Terraform needs this
```

`gcloud auth login` alone is **not** enough: it authenticates the `gcloud` CLI
but writes no Application Default Credentials, and the Terraform `google`
provider reads ADC. Add to `.env`:

```ini
TF_VAR_gcp_project=<PROJECT_ID>
TF_VAR_gcp_region=us-central1
TF_VAR_gcp_zone=us-central1-a
GOOGLE_IMPERSONATE_SERVICE_ACCOUNT=tee-crafter-deployer@<PROJECT_ID>.iam.gserviceaccount.com
```

Leave `GOOGLE_APPLICATION_CREDENTIALS` **unset or commented out**. Pointing it at
a `gcp-key.json` that does not exist is worse than leaving it blank: both the
Terraform provider and `google-auth` read that variable and fail outright on a
missing file rather than falling back to ADC.

Verify which identity Terraform will actually use — the provider blocks in our
templates do not set `impersonate_service_account`, so this is worth confirming
rather than assuming:

```bash
gcloud auth print-access-token --quiet >/dev/null && echo "base credential OK"
gcloud auth print-access-token \
  --impersonate-service-account=tee-crafter-deployer@<PROJECT_ID>.iam.gserviceaccount.com \
  --quiet >/dev/null && echo "impersonation OK"
```

Verified against `hashicorp/google v5.45.2`, and re-checked on
Observed after the provider moved to `~> 7.0` (v7.45.0): with `GOOGLE_IMPERSONATE_SERVICE_ACCOUNT` set, a
`google_client_openid_userinfo` data source reports the deployer SA; unset, it
reports the human user. So the variable alone is what moves Terraform off your
Owner account and onto the scoped SA.

**Option B — JSON key file (only if key creation is permitted; never expires):**

```bash
SA_EMAIL="tee-crafter-deployer@<PROJECT_ID>.iam.gserviceaccount.com"
gcloud iam service-accounts keys create gcp-key.json --iam-account=$SA_EMAIL
chmod 600 gcp-key.json
```

Add to `.env`:

```ini
TF_VAR_gcp_project=<PROJECT_ID>
TF_VAR_gcp_region=us-central1
TF_VAR_gcp_zone=us-central1-a
GOOGLE_APPLICATION_CREDENTIALS=./gcp-key.json
```

The CLI auto-activates gcloud from this key at startup — but only inside the
container, where `TEE_CRAFTER_IN_DOCKER=1` is set. On the host, `gcloud` config
is left alone.

You can also add `GOOGLE_IMPERSONATE_SERVICE_ACCOUNT` on top of this to use the
key purely as a base credential for the SA.

**Option C — Interactive login in the container (tokens expire, need periodic refresh):**

TEE-Crafter stores gcloud config at `/workspace/.gcloud` (gitignored). Run once:

```bash
docker run --rm -it \
  -v "$(pwd):/workspace" -w /workspace \
  -e CLOUDSDK_CONFIG=/workspace/.gcloud \
  tee-crafter bash -c "\
    gcloud auth login && \
    gcloud auth application-default login && \
    gcloud auth application-default set-quota-project <PROJECT_ID>"
```

Add to `.env`:

```ini
TF_VAR_gcp_project=<PROJECT_ID>
TF_VAR_gcp_region=us-central1
TF_VAR_gcp_zone=us-central1-a
GOOGLE_IMPERSONATE_SERVICE_ACCOUNT=tee-crafter-deployer@<PROJECT_ID>.iam.gserviceaccount.com
```

> **Warning:** Option C tokens expire. If you see `invalid_grant: Bad Request`, re-run
> the `docker run... gcloud auth login` command above. Options A/B avoid this entirely.

**Done.** You can run `tee-crafter deploy --tee-platform snp-gcp...` or `tdx-gcp`.

> **Cloud isolation — GCP-only deploys do NOT need AWS or Azure credentials.**
> When `--tee-platform` is `snp-gcp`, `tdx-gcp`, or `gpu-cc-gcp`, the CLI
> validates `gcloud` credentials only. `boto3` and `az` are never
> invoked, and any stale `AWS_*` / `AZURE_*` entries in your `.env` are
> ignored for that run. If GCP creds are missing, the CLI fails fast
> with an error pointing back to this document. Sandbox helpers under
> `apps/cli/byok-sandbox/gcp/` follow the same rule (only need GCP creds).

---

### Quota Requirements (All GCP Platforms)

GCP instance launches are gated by **regional quotas** (CPU and GPU limits).
TEE-Crafter uses **On-Demand instances by default**. Pass **`--spot`** (or set `TEE_CRAFTER_SPOT=1`) on `deploy` to use preemptible/Spot (requires `PREEMPTIBLE_CPUS` and related quotas). The internal `tee-crafter internal bake-ami` also accepts a `--spot` flag for the bake VM.
Default region/zone: **`us-central1`** / **`us-central1-a`**.

> **Quota is not capacity, and zonal capacity is a live constraint.** Having
> `N2D_CPUS` headroom does not mean the zone can place the instance. On
> A `snp-gcp` apply in `us-central1-a` failed with *"The zone … does
> not have enough resources available to fulfill the request"* while quota was
> fine; the same plan came up in `us-central1-b`. Google's own advice is to try
> another zone, so the CLI now reports this as a capacity limit and names the
> variable to change rather than retrying into the same wall:
>
> ```bash
> TF_VAR_gcp_zone=us-central1-b tee-crafter deploy --tee-platform snp-gcp...
> ```
>
> Confirm the machine type is offered there first — all four `us-central1`
> zones offer `n2d-standard-2`, but that is not true of every family:
>
> ```bash
> gcloud compute machine-types describe n2d-standard-2 --zone us-central1-b
> ```

#### Quota summary per platform

| Platform | Default Instance | vCPUs | GPUs | CPU Quota Metric | GPU Quota Metric |
|---|---|---|---|---|---|
| `snp-gcp` | `n2d-standard-2` | 2 | 0 | `N2D_CPUS` | N/A |
| `tdx-gcp` | `c3-standard-4` | 4 | 0 | `C3_CPUS` | N/A |
| `gpu-cc-gcp` | `a3-highgpu-1g` | 26 | 1 H100 | `CPUS` (or A3 family) | `NVIDIA_H100_80GB_GPUS` |

#### Minimum quotas needed (one VM at a time)

**On-Demand:**

| Quota Metric | Minimum | For |
|---|---|---|
| `N2D_CPUS` | **2** | SNP-GCP |
| `C3_CPUS` | **4** | TDX-GCP |
| `CPUS` (general) | **26** | GPU-CC-GCP (if no A3 family quota) |
| `NVIDIA_H100_80GB_GPUS` | **1** | GPU-CC-GCP |

**Spot (preemptible):**

| Quota Metric | Minimum | For |
|---|---|---|
| `PREEMPTIBLE_CPUS` | **4** | Any Spot CPU TEE VM |
| `PREEMPTIBLE_CPUS` | **26** | Spot GPU CC VM |
| `PREEMPTIBLE_NVIDIA_H100_80GB_GPUS` | **1** | Spot GPU CC VM |

> **Note:** `PREEMPTIBLE_CPUS` defaults to **0** in many GCP projects and must be explicitly requested.

#### How to check your quotas

```bash
# All regional quotas for us-central1
gcloud compute regions describe us-central1 --format='json(quotas)' | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
[print(f\"{q['metric']:45s} limit={q['limit']:6.0f} used={q['usage']:6.0f}\") \
 for q in d.get('quotas',[]) \
 if 'GPU' in q['metric'] or 'CPU' in q['metric'] or 'PREEMPT' in q['metric']]"
```

#### How to request increases

**Option 1: GCP Console (recommended)**

1. Open **[GCP Console > IAM & Admin > Quotas](https://console.cloud.google.com/iam-admin/quotas)**
2. Filter by metric name (e.g., `PREEMPTIBLE_CPUS`, `NVIDIA_H100`)
3. Select the row for your region (`us-central1`)
4. Click **Edit quotas** and request the minimum values above

**Option 2: gcloud CLI**

```bash
PROJECT=$(gcloud config get-value project)

# Request preemptible CPUs for Spot
gcloud alpha quotas preferences create \
  --project="$PROJECT" \
  --service=compute.googleapis.com \
  --quota-id=PREEMPTIBLE-CPUS-per-project-region \
  --preferred-value=32 \
  --dimensions=region=us-central1 \
  --justification="TEE-Crafter Spot instances" \
  --email=$(gcloud config get-value account) \
  --preference-id=preemptible-cpus-us-central1
```

> **Warning:** CLI quota requests are often **not auto-approved** for GPU and Spot quotas. They go to manual review. The Console UI is usually faster for approval.

#### GPU CC specific: A3 + H100 access

A3 machines with H100 GPUs may require **explicit enablement** for your project before quota metrics even appear. If `NVIDIA_H100_80GB_GPUS` does not show in your regional quotas:

1. Request A3/H100 access through the [GCP GPU access request form](https://cloud.google.com/compute/docs/gpus#access)
2. Or contact GCP support and ask them to enable A3 capacity for your project in `us-central1`

Common A3/H100 regions: `us-central1`, `us-east4`, `europe-west4`.

```bash
# Check A3 (H100 GPU) availability
gcloud compute machine-types list --filter="name:a3-highgpu" --zones=us-central1-a
```

#### GPU CC quota: the right metric (new quota model)

GCP has multiple GPU quota types. For A3/H100, the one that gates VM creation is:

- **Name**: `GPUs per GPU family`
- **Metric**: `compute.googleapis.com/gpus_per_gpu_family`
- **Dimensions**: `gpu_family: NVIDIA_H100` **and** `region: <your region>`
- **Type**: **Quota** (not "System limit")

You may also see **Committed H100 GPUs** quotas in the UI. Those are for **committed-use / reservations** and do **not** enable on-demand VM creation.

#### Request quota in the GCP Console (recommended for GPU)

1. Open **GCP Console > IAM & Admin > Quotas & System Limits**
2. Filter: `gpus_per_gpu_family`
3. Select the row matching: Service=Compute Engine, Dimensions=`gpu_family: NVIDIA_H100`, region=`us-central1`, Type=**Quota**, Adjustable=**Yes**
4. Click **Edit quotas** and request **1** (single GPU) or **2** (2-GPU testing)

> If you request quota in one region but deploy in another, Terraform will fail with `GPUS_PER_GPU_FAMILY exceeded`.

For GPU CC (`--tee-platform gpu-cc-gcp`), **`NVIDIA_NRAS_API_KEY`** must be **non-empty** in `.env` for `tee-crafter deploy` / setup to run. The NRAS endpoint (v4) does not use it as an HTTP service key; an NGC API key is not interchangeable. **Do not pass secrets via CLI flags or shell history.**

---

### Least-Privilege IAM (optional, recommended for production / CI)

The steps above use your **Owner** account (full permissions). For production or shared environments, create a **dedicated service account** with only the roles TEE-Crafter needs — similar to how [docs/aws_setup.md](aws_setup.md) creates a scoped IAM user.

#### 1. Create the service account

```bash
PROJECT_ID=$(gcloud config get-value project)

gcloud iam service-accounts create tee-crafter-deployer \
  --display-name="TEE-Crafter Deployer" \
  --description="Least-privilege SA for TEE-Crafter GCP deployments"

SA_EMAIL="tee-crafter-deployer@${PROJECT_ID}.iam.gserviceaccount.com"
```

#### 2. Assign roles

```bash
for ROLE in \
  roles/compute.instanceAdmin.v1 \
  roles/compute.networkAdmin \
  roles/compute.securityAdmin \
  roles/storage.admin \
  roles/cloudkms.admin \
  roles/iam.serviceAccountAdmin \
  roles/iam.serviceAccountUser \
  roles/iap.tunnelResourceAccessor \
  roles/dns.admin \
  roles/logging.viewer; do
  gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="$ROLE" --condition=None --quiet
done
```

| Role | Why TEE-Crafter needs it |
|------|--------------------------|
| `compute.instanceAdmin.v1` | Create / start / stop / delete Confidential VMs |
| `compute.networkAdmin` | Create VPC, subnets, Cloud Router, Cloud NAT |
| `compute.securityAdmin` | Create firewall rules (IAP-only ingress) |
| `storage.admin` | Create GCS bucket for artifacts, upload/download objects |
| `cloudkms.admin` | Create KMS keyring + key for CMEK disk/bucket encryption. Note that this role cannot *delete* them either — nobody can; see [Keyrings and keys are permanent](#keyrings-and-keys-are-permanent) below |
| `iam.serviceAccountAdmin` | Create the **VM-level** service account (Terraform does this) |
| `iam.serviceAccountUser` | Attach a service account to VMs at launch |
| `iap.tunnelResourceAccessor` | SSH into VMs via IAP TCP tunnel (zero public IP) |
| `dns.admin` | Create the private `googleapis.com` Cloud DNS zone that `--byok gcp-kms` needs. Only that flag creates the zone, but the role is listed unconditionally because the failure is otherwise a `403 Forbidden` on `google_dns_managed_zone.googleapis` *during* `terraform apply`, after the container build. Enabling `dns.googleapis.com` (Step 1) is necessary but not sufficient — the API and the permission are separate gates and this project hit them one after the other |
| `logging.viewer` | Read GCP audit logs for the audit-evidence matrix (`CT-006`). Read-only; without it the row downgrades to `warn`. |

**CT-006 (BYOK decrypt in audit logs):** `logging.viewer` alone is not
enough — the project must also have **Cloud KMS Data Access** audit
logging enabled so `Decrypt` calls on the customer key appear in Cloud
Logging. In the console: **IAM & Admin → Audit Logs → Cloud KMS** →
enable **Admin Read**, **Data Read**, and **Data Write** (or run
`gcloud logging sinks` / audit-config for `cloudkms.googleapis.com`).
Without this, `CT-006` is emitted as `warn` with `events=0` even when
BYOK unwrap succeeded in the VM (`BYOK-007` pass).

**GPU CC:** No additional GCP IAM roles are needed for GPU CC. The existing `compute.instanceAdmin.v1` role covers A3 machine types.

**BYOK (`--byok gcp-kms`):** No additional GCP IAM roles are needed. The recommended `roles/cloudkms.admin` above already covers the operator-side helpers under [`apps/cli/byok-sandbox/gcp/`](../apps/cli/byok-sandbox/gcp/):

| What you do | Covered by |
|---|---|
| Create a keyring + symmetric key (`create_kms_key.py`) | `roles/cloudkms.admin` (`cloudkms.keyRings.create`, `cloudkms.cryptoKeys.create`, `cloudkms.cryptoKeys.setIamPolicy`) |
| Wrap a DEK (`wrap_dek.py` -> `KeyManagementServiceClient.encrypt`) | `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key — the helper adds this binding automatically to the current `gcloud auth` account and the ADC impersonation SA |
| In-CVM decrypt at runtime | `roles/cloudkms.cryptoKeyDecrypter` on **the BYOK key**, granted to the CVM's own service account by the Terraform that ships with TEE-Crafter — but only because the CLI exports `TF_VAR_byok_gcp_kms_key_id` from your `--byok-config`. Decrypt only: the TEE unwraps a DEK, it never wraps one |

When the deployer SA uses **impersonation** (Step 2, Option A or B) the ADC principal is the *impersonated* SA, not your user. `create_kms_key.py` autodetects that and grants `cryptoKeyEncrypterDecrypter` to the impersonated SA so `wrap_dek.py` succeeds on the first run.

> **Cross-project BYOK key?** The Terraform grants the CVM service account
> `roles/cloudkms.cryptoKeyDecrypter` on whatever key id
> `TF_VAR_byok_gcp_kms_key_id` names, so a key in another project works *if the
> deployer principal may set IAM policy on it there* — `roles/cloudkms.admin`
> in the key's project, not the deploy's. Without that the apply fails on the
> binding rather than at runtime, which is the better of the two failures.
> The CVM service account is named `tc-<platform>-<random>` and its suffix is a
> Terraform `random_id`, so you cannot pre-grant it by hand — that is exactly
> why the binding has to be created by the deploy.

> **Reachability is not authorization.** `--byok gcp-kms` sets two Terraform
> variables and they do different jobs: `byok_gcp_kms` (bool) publishes the
> private `googleapis.com` DNS zone so Cloud KMS is *reachable* under deny-all
> egress, and `byok_gcp_kms_key_id` *authorizes* the CVM against your key.
> Previously only the first was exported, so an in-TEE unwrap reached
> Cloud KMS and was refused `PERMISSION_DENIED` with BYOK fully configured.
> `DH-019` now fails the deploy when the key id is missing.

> **Confidential Space + WIF (advanced).** If you want true attestation-gated decrypt (Workload Identity Federation evaluating Confidential Space token claims like `submods.confidential_space.support_attributes`), follow Google's CS quickstart and grant `roles/iam.workloadIdentityUser` to the WIF principal-set on the customer's key. The TEE-Crafter Terraform does **not** auto-configure WIF — that's a customer-policy decision (which CS image, which claims to gate on). See [`docs/byok.md`](byok.md) §"GCP Confidential Space" for the wiring details.

### Rotating BYOK material without redeploying — `tee-crafter byok-stage`

For `snp-gcp`, `tdx-gcp`, and `gpu-cc-gcp`, you can rotate the wrapped DEK (or HSM bearer for `--byok external-hsm`) without rebuilding artifacts:

> `apps/cli/byok-sandbox/configs/` is created by the sandbox helper
> scripts; the JSON below does not exist until you run
> `wrap_dek.py` (or `generate_byok_config.py`) to produce it.

```bash
tee-crafter byok-stage \
    --platform tdx-gcp \
    --byok-config apps/cli/byok-sandbox/configs/tdx-gcp-rotated.json \
    --ssh-host 35.x.x.x --ssh-key ~/.ssh/tee-crafter-gcp \
    --ssh-user $(whoami)
```

It pushes the new `byok.env` to **tmpfs** at `/run/tee-crafter-<platform>/byok.env` (mode 0600), writes the non-secret half to `byok.env.public` on disk, scrubs any stale on-disk `byok.env`, and `try-restart`s the workload. IAP-tunnelled SSH is the typical path on GCP since deploys put the VM on a private subnet by default. Required IAM: same as deploy (`iap.tunnelResourceAccessor` to open the tunnel, `compute.instanceAdmin.v1` to SSH). No new bindings on the customer's KMS key needed — rotation just changes the *ciphertext*, not the access posture.

#### 3. Allow your user to impersonate the service account

Your Owner account needs `serviceAccountTokenCreator` on the SA (IAM propagation can take up to 60 seconds):

```bash
USER_EMAIL=$(gcloud config get-value core/account)

gcloud iam service-accounts add-iam-policy-binding $SA_EMAIL \
  --member="user:${USER_EMAIL}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project $PROJECT_ID --quiet
```

#### 4. Add to `.env`

**Recommended — impersonation on top of your own ADC (no key file):**

```bash
gcloud auth application-default login
```

```ini
GOOGLE_IMPERSONATE_SERVICE_ACCOUNT=tee-crafter-deployer@<PROJECT_ID>.iam.gserviceaccount.com
```

This is the only one of the two that works when the organization enforces
`constraints/iam.disableServiceAccountKeyCreation`, and it keeps no long-lived
secret on disk. The base credential is your user login, so tokens expire and
need a periodic `gcloud auth application-default login`. Leave
`GOOGLE_APPLICATION_CREDENTIALS` unset — see Step 2, Option A.

**Alternative — JSON key file (never expires; blocked by some org policies):**

```bash
gcloud iam service-accounts keys create gcp-key.json \
  --iam-account=$SA_EMAIL
chmod 600 gcp-key.json
```

```ini
GOOGLE_APPLICATION_CREDENTIALS=./gcp-key.json
```

The CLI auto-activates the service account from this file at startup, inside the
container. A key file is a long-lived credential in your working tree: keep it
`chmod 600`, keep it out of git, and rotate it on the same cadence as any other
static secret.

> If key creation fails with `constraints/iam.disableServiceAccountKeyCreation`,
> your organization forbids key files entirely. Use impersonation above
> (Step 2, Option A) — no amount of IAM grants will change this, since the
> constraint is evaluated before permissions.

#### 5. Verify (inside the container)

```bash
gcloud auth print-access-token --quiet >/dev/null && echo "OK"
```

If this fails with `PERMISSION_DENIED`, wait 60 seconds for IAM propagation and retry.

#### What the VM itself gets (created by Terraform, not you)

Terraform creates a **separate** service account for the Confidential VM with minimal permissions:

| Role | Scope | Purpose |
|------|-------|---------|
| `storage.objectViewer` | the deployment bucket | Pull artifacts from GCS |
| `logging.logWriter` | project | Write to Cloud Logging |
| `monitoring.metricWriter` | project | Write to Cloud Monitoring |
| `cloudkms.cryptoKeyDecrypter` | **only the `--byok` key** | Unwrap the customer DEK in-TEE. Absent unless `--byok gcp-kms` is used |

Note the scope of that last row: `cloudkms.cryptoKeyDecrypter` on **one named
key**, granted only when BYOK is requested. It is deliberately not the
project-wide `cloudkms.cryptoKeyEncrypterDecrypter` that a quick reading of the
BYOK flow might suggest — the workload needs to unwrap one DEK, not to act on
every key in the project.

---

### Troubleshooting

| Issue | Fix |
|-------|-----|
| `Confidential Computing is not supported` | Use N2D for SNP, C3 for TDX. Check zone availability. |
| `Quota exceeded for resource: CPUS` | Request quota increase in [GCP Console](https://console.cloud.google.com/iam-admin/quotas). |
| `The zone … does not have enough resources available` | Zonal **capacity**, not quota — nothing to request. Set `TF_VAR_gcp_zone` to another zone in the region and re-run. The CLI stops rather than retrying, because a second apply in the same zone cannot help. |
| `Error 409: KeyRing … already exists` on a retry | Was a bug in the retry, since fixed. Cloud KMS key rings **cannot be deleted**, and the Terraform google provider handles a keyring destroy by dropping it from state and leaving it in place — so cleaning up partial state before a retry guaranteed the retry would fail. GCP retries now re-apply without destroying (`terraform apply` is convergent). If you see this on an older build directory, delete the build dir and start a fresh deploy so the suffix — and the ring name — change. |
| IAP tunnel timeout | Verify `iap.googleapis.com` is enabled. |
| `kex_exchange_identification: read: Connection reset by peer` over IAP | Transient IAP local-listener flake. TEE-Crafter retries every SSH/SCP call up to 4 times with exponential backoff (base 2); tune with `TEE_CRAFTER_SSH_RETRIES` (default `4`) and `TEE_CRAFTER_SSH_RETRY_BACKOFF` (default `2.0`) in `.env`. The same retry wrapper applies to Azure Bastion tunnels. |
| `API not enabled` | `gcloud services enable <API>` |
| `SEV_GUEST_DEVICE=MISSING` | VM not launched with `--confidential-compute-type=SEV_SNP`. |
| `PERMISSION_DENIED: Failed to impersonate` | Wait 60s for IAM propagation. Ensure step 3 (`serviceAccountTokenCreator` grant) was completed. |
| `invalid_grant: Bad Request` | Your login tokens expired. Re-run `gcloud auth login` **and** `gcloud auth application-default login` (Step 2, Option A), or switch to a JSON key file (Option B) to avoid expiry entirely. |
| `constraints/iam.disableServiceAccountKeyCreation` | Org policy forbids key files; no IAM grant overrides it. Use user ADC + impersonation (Step 2, Option A). |
| `Could not automatically determine credentials` / provider authenticates as the wrong identity | You ran `gcloud auth login` but not `gcloud auth application-default login`. The former configures the CLI; only the latter writes the ADC that the Terraform `google` provider reads. |
| `GOOGLE_APPLICATION_CREDENTIALS` set to a file that does not exist | Both Terraform and `google-auth` fail hard rather than falling back to ADC. Comment the variable out. |
| `machineTypes` calls return `Internal error... backendError` (HTTP 503) | Google-side outage, not your zone or your permissions — other Compute endpoints keep working. Preflight reports the machine-type check as "skipped, not passed" and still runs the CPU quota check. Retry later. |
| `tdx-gcp`: `TcbInfoUnavailable: the collateral bundle... carries no 'tdx_tcb_info'` | Expected on a **first** deploy to a new CPU model, and the error prints the fix. Intel's `/tcb` endpoint is keyed by FMSPC, the FMSPC identifies the CPU model, and it only exists inside a real quote — so the build host cannot know it in advance. Re-run with `TEE_CRAFTER_FMSPC=<value from the error>`; on GCP C3 in `us-central1` that is `00806F050000`. The refusal is the TCB gate working: an unresolvable `tcbStatus` means the quote is not evaluated, so it is not accepted. |
| `snp-gcp`: `ZONE_RESOURCE_POOL_EXHAUSTED` for `n2d-standard-2` | N2D SEV-SNP capacity is genuinely scarce. It has been observed exhausted in **all four** `us-central1` zones and in `us-east1`/`us-west1`/`us-east4`; `europe-west4-a` had it. Probe with a throwaway `gcloud compute instances create --confidential-compute-type=SEV_SNP... --no-address` before deploying — each failed deploy otherwise costs a full container build. Check `cpuPlatform` on the probe: the pinned measurement is per CPU generation, so you want `AMD Milan` to match a Milan bake. |
| `GPU quota exceeded` | Request NVIDIA_H100_GPUS quota increase in GCP Console. |
| `nvidia-smi not found` | GPU driver installation may still be in progress. Wait for cloud-init to complete. |

---

## Keyrings and keys are permanent

Cloud KMS has **no delete operation for a keyring or a CryptoKey**. The
[resource-hierarchy documentation](https://cloud.google.com/kms/docs/resource-hierarchy)
states it directly: "Key rings and keys cannot be deleted." Only individual
key *versions* can be destroyed.

Every GCP deploy creates one keyring and one key for CMEK disk encryption,
named after the deploy's random suffix (`tee-crafter-snp-kr-<hex8>` and so on).
`terraform destroy` removes the VM, disks, network and bucket; the keyring and
key stay behind forever. Measured in this project's test account on
with no instances, disks, networks or buckets left in it:

| | count |
|---|---|
| keyrings in `us-central1` | 100 |
| keys across those keyrings | 113 |
| keys whose primary version is `DESTROYED` | 81 |
| keys whose primary version is `DESTROY_SCHEDULED` | 29 |
| keys whose primary version is `ENABLED` | 3 |

So a rising keyring count in a long-lived project is expected, and is not
evidence that teardown is failing.

**Cost is a separate question, and it is handled.** Billing is per *active key
version*, not per key or keyring, so destroying the version stops the charge.
The three still `ENABLED` above are the deliberately long-lived
`tee-crafter-byok` keys used by the BYOK end-to-end tests, not deploy
leftovers.

Per-deploy keys also carry **no `rotation_period`**. They used to: a 90-day
schedule that, on a key belonging to a deploy that lasts an hour, could only
ever fire long after the deploy was abandoned — minting a fresh billable
version every quarter, indefinitely. Seven abandoned keyrings in this project
had picked up a second `ENABLED` version exactly 90 days after their first,
with the next rotation still scheduled. Rotation protects long-lived keys;
on an ephemeral one it was dead configuration with a recurring bill attached.

To reclaim a version by hand:

```bash
gcloud kms keys versions list --key=<key> --keyring=<ring> --location=us-central1
gcloud kms keys versions destroy <n> --key=<key> --keyring=<ring> --location=us-central1
```
