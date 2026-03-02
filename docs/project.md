# Nitro-Agent: AI-Powered Secure Enclave Orchestrator

## The Core Concept

**Nitro-Agent** is an AI-powered compiler and deployment orchestrator that transforms standard Python scripts into secure **AWS Nitro Enclaves**.

Normally, deploying to a Trusted Execution Environment (TEE) like AWS Nitro Enclaves requires deep expertise in low-level socket programming (`vsock`), cryptographic attestation (PCRs), CMS envelope decryption, Docker optimization, and infrastructure-as-code. Nitro-Agent automates this entire engineering pipeline using a local Large Language Model (LLM).

It takes a standard, non-networked Python script (e.g., a machine learning inference function) and:
1.  **Rewrites it** to communicate over the secure `vsock` channel.
2.  **Containerizes it** into a minimal, secure Docker image.
3.  **Builds it** into a cryptographically signed Enclave Image File (`.eif`).
4.  **Provisions** the necessary AWS infrastructure (EC2, KMS, IAM, VPC Endpoints) with correct security policies.
5.  **Deploys and Tests** the enclave end-to-end.

---

## Architecture Overview

```
┌──────────────┐      HTTPS (443)       ┌───────────────────────────────────────────────────┐
│  Local Client │  ◄──────────────────►  │  EC2 Host (Graviton, IMDSv2, No SSH)              │
│  (client.py)  │                        │  ┌─────────────────────┐  vsock   ┌─────────────┐ │
│               │                        │  │  host_proxy.py      │ ◄──────► │  Nitro      │ │
│  1. Attest    │                        │  │  (FastAPI, HTTPS)   │  :5005   │  Enclave    │ │
│  2. KMS Encrypt                        │  │  Blind proxy -      │          │             │ │
│  3. Send data │                        │  │  injects IAM creds  │          │ app_vsock.py│ │
│  4. Get result│                        │  └─────────────────────┘          │ (user code) │ │
└──────────────┘                        │                                    │             │ │
                                        │  ┌─────────────────────┐  vsock   │ KMS Decrypt │ │
                                        │  │  vsock-proxy        │ ◄──────► │ w/ Recipient│ │
                                        │  │  (AWS provided)     │  :8000   │ + CMS unwrap│ │
                                        │  └────────┬────────────┘          └─────────────┘ │
                                        │           │                                       │
                                        │  ┌────────▼────────────┐                          │
                                        │  │  VPC Interface      │                          │
                                        │  │  Endpoint for KMS   │                          │
                                        │  │  (private DNS)      │                          │
                                        │  └─────────────────────┘                          │
                                        └───────────────────────────────────────────────────┘
```

---

## The 5-Phase Technical Pipeline

### Phase 1: Code Ingestion & AI Translation

**Module:** `core/ingestion.py`, `llm/chains.py`, `core/builder.py`, `core/verification.py`

The agent scans your source directory for Python files and dependencies.

*   **Code Ingestion** (`core/ingestion.py`): Recursively reads all `.py` files and `requirements.txt` from the source directory, skipping virtual environments and hidden directories.
*   **App Validation** (`core/verification.py`): Checks that the user's code is a batch-style script (has `if __name__ == "__main__"`) and is not a server framework (FastAPI, Flask, etc.).
*   **Vsock Logic Bridging** (`llm/chains.py`): The LLM analyzes your code and generates *only* the necessary imports and a `process_request` function body. These are injected into the pre-validated `app_vsock.template.py` template:
    *   **Template-Based Stability:** The networking, attestation, KMS decryption, and CMS envelope unwrapping logic are static and guaranteed correct. The AI focuses purely on your business logic.
    *   **CMS Envelope Decryption:** When KMS returns data via the `Recipient` attestation parameter, the `CiphertextForRecipient` is a CMS (RFC 5652) EnvelopedData structure. The template uses `asn1crypto` to parse it, RSA-OAEP-unwraps the content-encryption key, determines the content algorithm via `EncryptionAlgorithm.encryption_mode` (supporting both AES-GCM and AES-CBC), and AES-decrypts the payload.
    *   **Pure-Python KMS Proxy:** The enclave uses a built-in TCP-to-VSOCK proxy with DNS patching (no external tools like `socat`). It redirects `kms.<region>.amazonaws.com` to `127.0.0.1:443`, which tunnels through vsock CID 3 port 8000 to the host's `vsock-proxy`.
    *   **Entropy Seeding:** On first data request, the enclave supplements its NSM hardware RNG by fetching 256 bytes from KMS `GenerateRandom` via the vsock proxy.
    *   **Self-Healing:** Generated code segments are validated with `pyflakes`. Syntax errors or undefined name errors trigger an automatic retry with error feedback to the LLM.
*   **Client Configuration** (`core/builder.py`): Uses the static `client.template.py` template. The specific **PCR hashes** and **Root CA** are injected at build time.
    *   **Zero Hallucination:** The cryptographic verification logic (nonce check, certificate chain validation, COSE_Sign1 signature verification, PCR matching) is hardcoded and reviewed.
    *   **Remote Attestation:** Before sending data, the client requests a cryptographic attestation document and verifies the COSE_Sign1 signature (ECDSA P-384) against the leaf certificate's public key, validates the nonce, PCR hashes, and the full certificate chain back to the AWS Nitro Root CA.
*   **Dockerfile Generation** (`core/builder.py`): Uses the static multi-stage `Dockerfile.template`:
    *   *Stage 1:* Compiles a custom Rust binary (`nsm-cli`) from the official `aws-nitro-enclaves-nsm-api` (v0.4) sources.
    *   *Stage 2:* Copies the binary into a minimal `python:3.11-alpine` image along with your application code, user dependencies, and the attestation dependencies (`cbor2`, `cryptography`, `pydantic`, `boto3`, `requests`, `fastapi`, `uvicorn`, `asn1crypto`).
*   **Host Proxy** (`core/builder.py`): Renders `host_proxy.template.py`, a FastAPI HTTPS service that acts as a blind proxy between the client and the enclave. It injects the host's IAM role credentials into each request so the enclave can call KMS.
*   **Artifact Staging** (`core/builder.py`): All generated files are written to a timestamped `builds/<app>_build_<timestamp>/` directory alongside a copy of the user's source files.

### Phase 2: Cryptographic Packaging (EIF Build)

**Module:** `core/enclave.py`

Nitro-Agent builds the enclave image locally using a "Docker-in-Docker" approach, making it compatible with macOS and Windows.
*   It builds the Docker image for `linux/arm64` (Graviton native) using Docker's multi-architecture support.
*   It runs `nitro-cli build-enclave` inside a helper container (`nitro-cli-builder`) built from `amazonlinux:2023` with `aws-nitro-enclaves-cli` installed.
*   **PCR Extraction:** Captures **Platform Configuration Register (PCR)** hashes (PCR0, PCR1, PCR2) from the build output. These are the cryptographic fingerprints of your enclave code.

### Phase 3: Infrastructure-as-Code (Terraform)

**Module:** `llm/iac.py`, `core/iac.py`

The agent generates deterministic Terraform configuration using a static template (`main.template.tf`).
*   **Deterministic Generation** (`llm/iac.py`): No LLM is used. Instance type is selected from a table of Graviton instances (`c6g`, `m6g`, `r6g` families) based on CPU/RAM requirements. The template is filled with concrete values.
*   **PCR Injection** (`core/iac.py`): PCR hashes are injected directly into the KMS Key Policy as `kms:RecipientAttestation:PCR0/1/2` conditions, ensuring only the specific enclave code can decrypt data.
*   **Provisioned Resources:**
    *   **EC2 Instance:** Graviton-based (e.g., `c6g.xlarge`) with Nitro Enclaves enabled, IMDSv2 enforced, encrypted root volume. Supports both Spot and On-Demand instances.
    *   **IAM Role:** Least-privilege -- S3 read for the deployment bucket, `kms:GenerateRandom` for entropy seeding, SSM Core for remote management. `kms:Decrypt` is granted only via the KMS key policy with PCR conditions.
    *   **KMS Key:** Auto-rotating symmetric key with a policy that grants `kms:Decrypt` and `kms:GenerateDataKey` only to the enclave role, contingent on valid PCR attestation. The deploying IAM user gets `kms:Encrypt` for client-side encryption.
    *   **Security Groups:** HTTPS-only (port 443) for both ingress and egress. SSH (port 22) is never opened.
    *   **VPC Interface Endpoint for KMS:** Private-DNS-enabled endpoint that routes all KMS traffic through the AWS backbone, never traversing the public internet.
    *   **VPC Gateway Endpoint for S3:** Free gateway endpoint for S3 traffic.
    *   **S3 Deployment Bucket:** Force-destroy enabled, public access blocked, SSE-AES256 encryption, SSL-only policy.
*   **Validation** (`core/iac.py`): Runs `terraform init` and `terraform validate` on the generated `main.tf`.

### Phase 4: Infrastructure Deployment

**Module:** `core/iac.py`

The agent executes `terraform apply` to create all resources:
*   Returns structured outputs: `instance_id`, `public_ip`, `kms_key_arn`, `deployment_bucket`.
*   Supports `--auto-approve` for non-interactive deployment.
*   Timeout configurable (default 600 seconds).

### Phase 5: Post-Deployment Automation

**Module:** `core/ssm.py`, `cli/main.py`

Once the instance is running, Nitro-Agent performs the final setup and verification using **AWS Systems Manager (SSM)**:

1.  **SSM Wait** (`core/ssm.py`): Polls `describe-instance-information` until the instance registers with SSM (up to 5 minutes).
2.  **Cloud-Init Wait:** Polls via SSM for `cloud-init status --wait` to ensure the base OS setup is complete.
3.  **Remote Setup:** Uploads the `.eif`, `host_proxy.py`, `remote_setup_script.sh`, and a self-signed TLS certificate to the S3 deployment bucket. Runs the setup script via SSM which:
    *   Installs Docker, `aws-nitro-enclaves-cli`, Python, and FastAPI/Uvicorn.
    *   Configures the Nitro Enclaves allocator with appropriate memory.
    *   Configures the `vsock-proxy` systemd unit for the correct AWS region.
    *   Creates systemd services for the host proxy.
4.  **Enclave Boot:** Starts the enclave via `nitro-cli run-enclave` with the specified CPU and RAM.
5.  **Host Proxy Start:** Starts the `host-proxy.service` systemd unit.
6.  **End-to-End Test:** Runs `client.py` locally, which:
    *   Requests an attestation document from the enclave (via the host proxy).
    *   Verifies COSE_Sign1 signature, certificate chain, nonce, and PCR hashes.
    *   Encrypts `data.json` with the PCR-locked KMS key.
    *   Sends the ciphertext to the enclave via the host proxy.
    *   The enclave decrypts using KMS with `Recipient` attestation, unwraps the CMS envelope, processes the data, and returns results.
7.  **Result Capture:** Output is saved to `client_output.json` (or `.txt`) in the build directory.
8.  **Error Debugging:** On failure, the CLI fetches `host-proxy.service` logs, `nitro-enclaves-vsock-proxy.service` logs, and the enclave console output via SSM. Enclave error responses include the full exception type, message, and traceback.
9.  **Teardown (Optional):** If `--teardown` is specified, runs `terraform destroy` to remove all AWS resources.

---

## Security Model

*   **Zero-Trust Host:** The EC2 host is treated as untrusted. It acts as a blind HTTPS proxy, injecting IAM credentials but never seeing plaintext data. SSH is completely disabled.
*   **Hardware-Backed Attestation:** The client verifies the enclave's identity via COSE_Sign1 signature (ECDSA P-384), full X.509 certificate chain validation back to the AWS Nitro Root CA, and PCR hash matching.
*   **KMS Key Policy:** `kms:Decrypt` is only permitted when the caller provides a valid attestation document matching the exact PCR0, PCR1, and PCR2 values of the deployed enclave image. This prevents even the host from decrypting data.
*   **CMS Envelope:** KMS returns decrypted data in a CMS (RFC 5652) EnvelopedData structure when the `Recipient` parameter is used. The enclave RSA-OAEP-unwraps the content-encryption key and AES-decrypts the payload using `asn1crypto`'s built-in algorithm helpers.
*   **Network Isolation:** Enclaves have no external networking except KMS traffic tunneled through the host's `vsock-proxy` via a VPC Interface Endpoint (private DNS enabled). Egress from the host is restricted to HTTPS-only (port 443).
*   **Encryption At Rest:** S3 buckets use SSE-AES256 and enforce SSL-only access. EC2 root volumes are encrypted.
*   **Enclave Entropy:** The NSM hardware RNG is supplemented with 256 bytes from KMS `GenerateRandom` on first use.

---

## Module Reference

| Module | File | Purpose |
|--------|------|---------|
| **CLI** | `cli/main.py` | Click-based CLI entrypoint, full deploy orchestration with Rich progress |
| **Core** | `core/ingestion.py` | Recursive Python file scanner with dependency detection |
| | `core/builder.py` | Template rendering (`app_vsock`, `client`, `host_proxy`, `Dockerfile`), artifact staging |
| | `core/enclave.py` | Docker-in-Docker EIF build, PCR extraction, builder image management |
| | `core/iac.py` | Terraform staging with PCR injection, init/validate/apply/destroy/output |
| | `core/ssm.py` | SSM command execution, S3 file upload, SSM readiness polling |
| | `core/verification.py` | pyflakes code validation, Docker build verification, server detection |
| **LLM** | `llm/engine.py` | LangChain `ChatOpenAI` engine targeting local `llama-server` |
| | `llm/chains.py` | AI-powered vsock wrapper generation with self-healing retry |
| | `llm/iac.py` | Deterministic Terraform generation from template, instance type selection |
| | `llm/prompts/` | System prompts and prompt templates for the LLM |
| **Templates** | `templates/app_vsock.template.py` | Enclave vsock server: KMS decrypt, CMS unwrap, attestation, entropy seeding |
| | `templates/client.template.py` | Client: attestation verification, KMS encrypt, result retrieval |
| | `templates/host_proxy.template.py` | Host: FastAPI blind HTTPS proxy with credential injection |
| | `templates/Dockerfile.template` | Multi-stage: Rust nsm-cli build + Alpine Python runtime |
| | `templates/main.template.tf` | Terraform: EC2, KMS, IAM, S3, SG, VPC Endpoints |
| | `templates/remote_setup_script.sh` | Host setup: packages, allocator, vsock-proxy, systemd services |
| **Resources** | `resources/root.pem` | AWS Nitro Enclaves Root CA certificate |

---

## Instance Sizing

Nitro-Agent exposes three key sizing flags:

*   `--enclave-cpu`: vCPUs reserved for the enclave.
*   `--enclave-ram`: RAM in MB reserved for the enclave.
*   `--instance-type`: The Nitro Enclave-capable EC2 instance type.

For a detailed guide with example configurations and trade-offs, see [instance_sizing.md](instance_sizing.md).

---

## Required AWS IAM Permissions

See [iam_permissions.md](iam_permissions.md) for the full least-privilege policy JSON covering EC2, IAM, KMS, S3, SSM, and STS permissions.

For a walkthrough of the example applications and how to build your own, see [examples.md](examples.md).
