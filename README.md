# Nitro-Agent

Nitro-Agent is an AI-powered compiler and deployment orchestrator that translates standard Python scripts into secure **AWS Nitro Enclaves**.

It handles the entire lifecycle:
1.  **Translates** your code to use the secure `vsock` protocol.
2.  **Builds** a cryptographically signed Enclave Image File (`.eif`).
3.  **Provisions** AWS infrastructure (EC2, KMS, S3, VPC Endpoints) using Terraform.
4.  **Deploys** and **Verifies** the enclave end-to-end via AWS Systems Manager (SSM) and an HTTPS Host Proxy.

> **Zero-Trust Architecture:** SSH (Port 22) is completely disabled. All host management is routed via AWS SSM. The EC2 host acts purely as a blind HTTPS proxy, forwarding KMS-encrypted payloads to the enclave over vsock. Data is only decrypted inside the enclave using KMS with hardware-backed attestation, ensuring the host never sees plaintext.

For the full technical architecture and 5-phase pipeline, see [docs/project.md](docs/project.md).
For a walkthrough of example applications, see [docs/examples.md](docs/examples.md).
For guidance on choosing instance sizes, see [docs/instance_sizing.md](docs/instance_sizing.md).
For the required AWS IAM permissions, see [docs/iam_permissions.md](docs/iam_permissions.md).

## Prerequisites (macOS Guide)

**Setup checklist:** Homebrew → Python 3.11 → LLM (llama.cpp) → Docker → Terraform → AWS credentials + `.env` → `make install` → `source venv/bin/activate`

**Tested on:** macOS 26.3, Apple MacBook Pro 16‑inch, M4 Pro, 48 GB RAM.  
Lighter machines may work, but enclave builds (Docker-in-Docker + Nitro CLI) **and running local LLMs** are CPU/RAM intensive.

### 1. Install Homebrew
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Install Python 3.11
Nitro-Agent requires Python 3.11 for reproducible builds and compatible cryptography dependencies.
```bash
brew install python@3.11
```

### 3. LLM Setup

Nitro-Agent supports **four LLM providers**. Choose one via the `--llm-provider` flag:

| Provider | Flag | Model (default) | API Key Env Var |
|----------|------|-----------------|-----------------|
| **Local** (default) | `--llm-provider local` | Qwen2.5-Coder-7B via llama.cpp | *None (runs locally)* |
| **OpenAI** | `--llm-provider openai` | `gpt-4o` | `OPENAI_API_KEY` |
| **Anthropic** | `--llm-provider anthropic` | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` |
| **Google Gemini** | `--llm-provider gemini` | `gemini-2.5-flash` | `GEMINI_API_KEY` |

**Option A: Local LLM (default, code never leaves your machine)**

```bash
brew install llama.cpp
```

Run the server (keep running in a separate terminal):
```bash
llama-server -hf bartowski/Qwen2.5-Coder-7B-Instruct-GGUF:Q8_0 \
  --port 8080 \
  -c 65851
```

**Option B: Cloud LLM provider**

All providers (OpenAI, Anthropic, Gemini) are included by default. Add your API key to `.env`:
```ini
OPENAI_API_KEY=sk-...
# or
ANTHROPIC_API_KEY=sk-ant-...
# or
GEMINI_API_KEY=...
```

You can override the default model with `OPENAI_MODEL`, `ANTHROPIC_MODEL`, or `GEMINI_MODEL` in `.env`.

> **Note:** When using cloud providers, your source code is sent to the provider's API for code generation. The local provider keeps all code on your machine.

### 4. Install and Start Docker
Docker is required to build the Enclave Image File (.eif).
```bash
brew install --cask docker
```
Open **Docker Desktop** from Applications and ensure the engine is running.

### 5. Install Terraform
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
```

### 6. Configure AWS Access
You need an AWS IAM User with permissions to provision infrastructure and execute SSM commands.

1.  **Get Credentials:** AWS Console → IAM → Users → Security credentials → Create access key.
2.  **Required IAM Permissions:** Attach the policy from [docs/iam_permissions.md](docs/iam_permissions.md) to your IAM User.
3.  **Configure Environment:**
    ```bash
    cp .env.example .env
    ```
    Edit `.env` and add your keys:
    ```ini
    LLAMA_SERVER_BASE_URL=http://127.0.0.1:8080/v1
    AWS_ACCESS_KEY_ID=your_access_key
    AWS_SECRET_ACCESS_KEY=your_secret_key
    TF_VAR_aws_region=us-east-2
    ```

## Installation

```bash
make install
source venv/bin/activate
```

## Quick Start

1.  **Start your LLM** (skip this step if using a cloud provider):
    ```bash
    llama-server -hf bartowski/Qwen2.5-Coder-7B-Instruct-GGUF:Q8_0 --port 8080 -c 65851
    ```

2.  **Prepare your app:** Place Python code and a `data.json` file in a directory. Examples are in `examples/`.

3.  **Run the agent** (with venv activated):
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

    **What happens:**
    *   The agent generates `app_vsock.py`, `client.py`, `host_proxy.py`, and `Dockerfile`.
    *   It builds the enclave image and extracts **PCR hashes** (PCR0, PCR1, PCR2).
    *   It generates and applies Terraform to provision a Graviton EC2 instance with a **PCR-locked KMS key**, an S3 deployment bucket, VPC Endpoints for KMS, and hardened security groups.
    *   It uses **AWS SSM** (no SSH) to install dependencies, configure the host's `vsock-proxy`, boot the enclave, and start the secure HTTPS proxy.
    *   The local client performs **remote attestation** -- verifying the COSE_Sign1 signature, PCR hashes, and the full certificate chain against the AWS Nitro hardware root of trust -- before encrypting and sending data.
    *   Inside the enclave, the data is decrypted via KMS using the `Recipient` attestation parameter. The **CMS envelope** returned by KMS is unwrapped locally (RSA + AES), routed through a VPC Interface Endpoint and a pure-Python TCP-to-VSOCK proxy. The host never sees plaintext.
    *   Output is saved to `builds/.../client_output.json`.

## Project Structure

```
nitro-agent/
├── src/nitro_agent/
│   ├── cli/main.py              # CLI entrypoint and deploy orchestration
│   ├── core/
│   │   ├── ingestion.py         # Source directory scanner
│   │   ├── builder.py           # Template rendering and artifact staging
│   │   ├── enclave.py           # EIF build, PCR extraction (Docker-in-Docker)
│   │   ├── iac.py               # Terraform stage/validate/apply/destroy
│   │   ├── ssm.py               # AWS SSM commands and S3 file transfer
│   │   └── verification.py      # pyflakes validation, Docker build checks
│   ├── llm/
│   │   ├── engine.py            # LangChain ChatOpenAI engine (local llama-server)
│   │   ├── chains.py            # AI vsock wrapper generation with self-healing
│   │   ├── iac.py               # Deterministic Terraform generation from template
│   │   └── prompts/             # LLM system prompts and templates
│   ├── templates/
│   │   ├── app_vsock.template.py       # Enclave vsock server (KMS decrypt, CMS unwrap, attestation)
│   │   ├── client.template.py          # Attestation client (COSE_Sign1, cert chain, PCR verify)
│   │   ├── host_proxy.template.py      # FastAPI HTTPS blind proxy
│   │   ├── Dockerfile.template         # Multi-stage: Rust nsm-cli + Alpine Python
│   │   ├── main.template.tf            # Terraform (EC2, KMS, S3, IAM, VPC Endpoints)
│   │   └── remote_setup_script.sh      # SSM remote setup script
│   └── resources/
│       └── root.pem                    # AWS Nitro Root CA certificate
├── examples/                    # Ready-to-deploy example applications
│   ├── hr_salary_analytics/     # Pay equity analysis
│   ├── fintech_fraud_detection/ # Transaction fraud scoring
│   ├── health_risk/             # Patient risk assessment
│   ├── private_bidding_engine/  # Vickrey sealed-bid auction
│   └── secure_ml_inference/     # Brain health ML inference
├── docs/                        # Documentation (project.md, examples.md, instance_sizing.md, iam_permissions.md)
├── builds/                      # Generated build output directories (timestamped)
├── pyproject.toml               # Package definition and dependencies
├── requirements.txt             # Pinned runtime + dev dependencies
├── Makefile                     # install, clean targets
└── .env.example                 # Environment variable template
```

## Features

*   **Zero-Trust Security Model:** SSH is completely disabled. The EC2 host enforces IMDSv2, restricts egress to HTTPS-only (port 443), and acts as a blind proxy. All data is KMS-encrypted until it reaches isolated enclave memory.
*   **Hybrid AI/Template Architecture:** Robust static templates handle networking, attestation, KMS integration (including CMS envelope unwrapping), and the TCP-to-VSOCK proxy. The LLM focuses purely on bridging your application logic into the `process_request` function.
*   **CMS Envelope Decryption:** When KMS returns data via the `Recipient` attestation parameter, the response is a CMS (RFC 5652) enveloped data structure. The enclave automatically parses this using `asn1crypto`, RSA-unwraps the content-encryption key, and AES-decrypts the payload (supporting both GCM and CBC modes).
*   **Self-Healing Code Generation:** Detects and fixes syntax errors in AI-generated Python code automatically via pyflakes validation with retry loops.
*   **Cryptographic Security:** KMS keys are locked to the enclave's PCR measurements. KMS traffic is routed through a VPC Interface Endpoint, staying entirely within the AWS network.
*   **Remote Attestation:** Full hardware-backed verification: COSE_Sign1 signature (ECDSA P-384), certificate chain back to the AWS Nitro Root CA, and PCR hash matching -- all using verified static implementations.
*   **Enclave Entropy:** Supplements the NSM hardware RNG with 256 bytes from KMS `GenerateRandom` on first use.
*   **Comprehensive Debug Logging:** On failure, the CLI automatically fetches host-proxy service logs, vsock-proxy logs, and enclave console output. Error responses from the enclave include the full exception type and traceback.
*   **Full Automation:** From source code to live enclave in one command via AWS SSM.

## Troubleshooting

*   **Logs:** On failure, the CLI automatically fetches `host-proxy.service`, `nitro-enclaves-vsock-proxy.service`, and enclave console logs from the host via SSM.
*   **Enclave Errors:** Error responses now include `exception`, `exception_type`, and `traceback` fields for precise debugging.
*   **Artifacts:** Inspect `builds/` for generated code (`app_vsock.py`, `client.py`, `host_proxy.py`, `main.tf`, `Dockerfile`) and Terraform state.
*   **KMS Read Timeout:** Verify the VPC endpoint is healthy (`aws ec2 describe-vpc-endpoints`) and the `vsock-proxy` is running (`journalctl -u nitro-enclaves-vsock-proxy`).
*   **SSM & AWS Keys:** Ensure your credentials have the permissions listed in [docs/iam_permissions.md](docs/iam_permissions.md).
