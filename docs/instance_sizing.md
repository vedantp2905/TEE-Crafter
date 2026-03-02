## Instance Sizing: CPU, RAM, and Host Instance Type

This guide explains how to choose values for:

- **`--enclave-cpu`**: vCPUs reserved for the enclave.
- **`--enclave-ram`**: RAM (in MB) reserved for the enclave.
- **`--instance-type`**: The Nitro Enclave-capable EC2 instance that will host the enclave.

Nitro-Agent uses these values to:

- Generate Terraform configuration that provisions an EC2 host (`llm/iac.py`).
- Configure the Nitro Enclaves **memory allocator** on the host (via `remote_setup_script.sh`).
- Start the enclave with `nitro-cli run-enclave --cpu-count <enclave-cpu> --memory <enclave-ram>`.

---

## Key Constraints

When picking values, keep the following in mind:

- **The enclave runs _inside_ a single EC2 instance.**
  - The host instance must be **Nitro Enclave-capable** (e.g., `c6g.*`, `m6g.*`, `r6g.*` families). Nitro-Agent defaults to `c6g.xlarge` in examples.
- **Enclave CPU and RAM are carved out of the host.**
  - `--enclave-cpu` must be less than or equal to the host vCPU count.
  - `--enclave-ram` (in MB) should leave headroom for the base OS, Nitro Enclaves allocator, Docker, `nitro-cli`, and the host proxy process.
- **Nitro-Agent adds allocator headroom automatically.**
  - In `llm/iac.py`, the allocator memory is calculated as:
    - `allocator_mb = min(host_ram_mb - 1024, enclave_memory_mb + 1024)`
    - `allocator_mb = max(allocator_mb, enclave_memory_mb)`
  - In `remote_setup_script.sh`, the allocator YAML is configured with this value.
  - This reserves `enclave_ram` MB for the enclave plus additional headroom while keeping at least 1 GiB for the host.

As a rule of thumb:

- **Do not allocate more than ~70-75% of the host's total RAM to enclaves.**
- Always leave **at least 1-2 GiB** for the host OS and supporting services.

---

## Recommended Starting Values

For most proof-of-concept and small-to-medium workloads:

- **Host instance type**: `c6g.xlarge` (4 vCPUs, 8 GiB RAM, Nitro Enclave-capable, cost-effective)
- **Enclave CPU**: `--enclave-cpu 2` (leaves 2 vCPUs for the host)
- **Enclave RAM**: `--enclave-ram 4096` (4 GiB; allocator configured to ~5 GiB, leaving ~3 GiB for host)

Example command:

```bash
nitro-agent deploy \
  --source ./examples/hr_salary_analytics \
  --enclave-cpu 2 \
  --enclave-ram 4096 \
  --instance-type c6g.xlarge \
  --deploy \
  --auto-approve \
  --teardown
```

---

## How to Choose `--enclave-cpu`

Think about how compute-heavy your `app.py` workload is:

- **Lightweight / I/O-bound workloads** (simple transformations, light aggregation):
  - Start with **1-2 vCPUs**.
- **Moderate CPU workloads** (vector math, small ML models, complex aggregations):
  - Start with **2-4 vCPUs**.
- **Heavy CPU workloads** (large ML inference, crypto-heavy workloads):
  - Consider **4+ vCPUs** and a correspondingly larger host instance.

Practical rule: give the enclave **50-75% of the host's vCPUs**, reserving the rest for the host.

---

## How to Choose `--enclave-ram`

Memory sizing depends on:

- The size of your **Python dependencies** and model weights.
- The maximum size of your **input payloads** (`data.json`).
- Whether your app processes **batches** of items in memory.

Guidelines:

- **Lightweight apps** (small JSON payloads, no large ML models): Start at **2048-4096 MB**.
- **Apps with medium-sized models or batch processing**: Start at **4096-8192 MB**.
- **Large models / very large batch workloads**: Consider **8192 MB+** and a larger host instance.

---

## How to Choose `--instance-type`

The `--instance-type` flag controls which EC2 instance hosts your enclave. Consider:

- **Nitro Enclave support**: Only certain instance families/sizes support Nitro Enclaves.
- **vCPU and RAM capacity**: Must be sufficient for both the host OS and the enclave allocator.
- **Cost vs. performance**: Start small for development, scale up as needed.

Nitro-Agent's instance selector (`llm/iac.py`) knows the following Graviton instances:

| Instance Type | vCPUs | RAM (GiB) |
|---------------|-------|-----------|
| `c6g.xlarge` | 4 | 8 |
| `c6g.2xlarge` | 8 | 16 |
| `c6g.4xlarge` | 16 | 32 |
| `c6g.8xlarge` | 32 | 64 |
| `m6g.xlarge` | 4 | 16 |
| `m6g.2xlarge` | 8 | 32 |
| `m6g.4xlarge` | 16 | 64 |
| `m6g.8xlarge` | 32 | 128 |
| `r6g.xlarge` | 4 | 32 |
| `r6g.2xlarge` | 8 | 64 |

If you pass `--instance-type` on the CLI, it is set as a Terraform variable (`TF_VAR_instance_type`). If omitted, `llm/iac.py` automatically selects the smallest Graviton instance that fits your CPU and RAM requirements with headroom.

---

## Example Scenarios

- **Scenario 1: Simple analytics / data masking**
  - Workload: small JSON payloads, basic aggregation, no ML models.
  - Config: `--instance-type c6g.xlarge --enclave-cpu 2 --enclave-ram 4096`

- **Scenario 2: Medium ML inference**
  - Workload: modest model (tens to hundreds of MB), moderate batch sizes.
  - Config: `--instance-type c6g.2xlarge --enclave-cpu 4 --enclave-ram 8192`

- **Scenario 3: Heavy analytics or large batches**
  - Workload: heavy numerical processing, large per-batch memory footprint.
  - Config: `--instance-type c6g.4xlarge --enclave-cpu 8 --enclave-ram 16384`

In all cases, start conservative and inspect:

- **Client output** in `builds/.../client_output.json` or `.txt`.
- **Host proxy logs** (fetched automatically on failure via SSM).
- **Enclave console logs** (fetched automatically on failure via SSM).
- **Nitro/allocator logs** for OOM or resource exhaustion.

Then iteratively adjust until you get the desired performance and reliability.
