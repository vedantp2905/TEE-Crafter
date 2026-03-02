## Nitro-Agent Example Applications

This document explains how the example applications under `examples/` are structured and how you can build and test your own apps in the same way.

---

### 1. Directory Layout

Each example lives in its own subdirectory under `examples/` and contains:

- **`app.py`**: Main entrypoint with your business logic. Must read JSON from `stdin` and write JSON to `stdout`.
- **`requirements.txt`**: Optional extra Python dependencies specific to this app (installed inside the enclave image alongside the base attestation dependencies).
- **`data.json`**: Sample input payload used by Nitro-Agent for the end-to-end test.
- **Additional modules/packages** (e.g., `domain/`, `core/`, `analytics/`, `auction/`): Regular Python packages imported by `app.py`.

These apps are ordinary Python programs; they do **not** import Nitro-specific code. Nitro-Agent reads this directory and generates the secure `app_vsock.py`, `client.py`, `host_proxy.py`, `Dockerfile`, and Terraform configuration around your code.

---

### 2. Built-in Examples

#### `hr_salary_analytics`
- **Purpose:** Confidential HR pay equity analysis.
- **Files:** `app.py`, `data.json`, `requirements.txt`, `analytics/statistics.py`, `models/employee.py`
- **Dependencies:** `pydantic`, `numpy`, `pandas`
- **Logic:** Reads a JSON list of employee records, validates them via Pydantic, computes gender pay gaps, departmental statistics, role distributions, and outlier counts using pandas/numpy. Returns aggregated statistics (no individual records leave the enclave).

#### `fintech_fraud_detection`
- **Purpose:** Transaction fraud scoring with confidential rule sets.
- **Files:** `app.py`, `data.json`, `requirements.txt`, `core/rules.py`, `core/scoring.py`, `schemas/transaction.py`
- **Dependencies:** `pydantic`
- **Logic:** Reads transactions, validates via Pydantic, applies proprietary fraud scoring rules, and returns per-transaction risk scores.

#### `health_risk`
- **Purpose:** Patient health risk assessment on protected health information (PHI).
- **Files:** `app.py`, `data.json`, `requirements.txt`, `domain/__init__.py`, `domain/logic.py`, `domain/models.py`, `io/__init__.py`, `io/serializers.py`
- **Dependencies:** `pydantic`
- **Logic:** Parses patient vitals, computes multi-factor risk scores, returns risk assessments without exposing raw PHI.

#### `private_bidding_engine`
- **Purpose:** Sealed-bid Vickrey auction engine.
- **Files:** `app.py`, `data.json`, `requirements.txt`, `auction/types.py`, `auction/engine.py`
- **Dependencies:** `pydantic`
- **Logic:** Groups bids by auction ID, runs a Vickrey (second-price) auction engine, returns winners and prices without revealing other bids.

#### `secure_ml_inference`
- **Purpose:** Confidential ML inference (brain health scoring).
- **Files:** `app.py`, `data.json`, `requirements.txt`, `domain/models.py`, `domain/inference.py`
- **Dependencies:** `pydantic`, `numpy`
- **Logic:** Runs a brain health model inference on patient scan data, returns predictions without exposing model weights or input data.

---

### 3. Application Contract (I/O)

Nitro-Agent expects your app to follow a simple input/output contract:

- **Input**: Read a JSON payload from `stdin` (single object or list of objects).
- **Output**: Write a JSON payload to `stdout` (single object or list).
- **Errors**: Catch exceptions and print a JSON object with an `"error"` field.

A minimal compatible pattern:

```python
import sys
import json


def run_app():
    raw = sys.stdin.read()
    data = json.loads(raw)

    result = {"echo": data}

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    run_app()
```

The AI translation layer reads your `app.py` and generates a `process_request(data)` function that bridges your logic into the vsock server template. Both single-object and list/batch inputs are supported.

---

### 4. Running the Built-in Examples

Point `--source` at the example directory:

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

Nitro-Agent will:

1. Read your app code and `requirements.txt`.
2. Generate `app_vsock.py` (vsock wrapper), `client.py` (attestation client), `host_proxy.py` (HTTPS proxy), `Dockerfile`, and `main.tf` (Terraform).
3. Build the `.eif` enclave image and extract PCR hashes.
4. Deploy infrastructure, boot the enclave, run the client against `data.json`, and save results to `builds/<app>_build_<timestamp>/client_output.json`.

---

### 5. Creating Your Own Example

1. **Create a directory:** `examples/my_app/`
2. **Add `app.py`:** Read JSON from `stdin`, process it, print JSON to `stdout`.
3. **Add `requirements.txt`:** List any extra Python packages (leave empty if none).
4. **Add `data.json`:** Representative input payload for end-to-end testing.
5. **Deploy and test:**

```bash
nitro-agent deploy \
  --source ./examples/my_app \
  --enclave-cpu 2 \
  --enclave-ram 4096 \
  --instance-type c6g.xlarge \
  --deploy \
  --auto-approve \
  --teardown
```

Nitro-Agent treats `examples/my_app` the same as the built-in examples: it builds a new enclave image around your `app.py`, runs it against `data.json`, and stores output in a new `builds/my_app_build_*` directory.

---

### 6. What Gets Generated

For each deploy, Nitro-Agent creates a timestamped build directory under `builds/` containing:

| File | Description |
|------|-------------|
| `app_vsock.py` | Your business logic wrapped in the vsock server template (KMS decrypt, CMS unwrap, attestation) |
| `client.py` | Attestation client with embedded PCR hashes and Root CA |
| `host_proxy.py` | FastAPI HTTPS blind proxy with IAM credential injection |
| `Dockerfile` | Multi-stage build (Rust nsm-cli + Alpine Python + your code) |
| `main.tf` | Terraform configuration with PCR-locked KMS key policy |
| `remote_setup_script.sh` | Host setup script for SSM |
| `app.eif` | Compiled Enclave Image File |
| `data.json` | Copy of your input data |
| `client_output.json` | Results from the end-to-end test (on success) |
| `terraform.tfstate` | Terraform state (during deployment) |
| Your source files | Copies of `app.py`, modules, `requirements.txt` |
