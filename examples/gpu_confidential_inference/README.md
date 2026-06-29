# Confidential Radiology AI — Single-GPU Inference

End-to-end medical imaging analysis pipeline running inside a Trusted
Execution Environment with NVIDIA Confidential Computing on a single H100.

## What It Does

This example demonstrates a **production-grade radiology AI pipeline** that
processes patient imaging data with full hardware-level encryption:

| Stage | Description |
|-------|-------------|
| **Input validation** | DICOM-style metadata extraction, tensor shape normalization |
| **Preprocessing** | Scan-type-aware normalization (MRI / CT / X-ray), multi-scale interpolation |
| **Feature extraction** | EfficientNet-B0 backbone with spatial + channel attention gates |
| **Classification** | 8-class diagnosis (normal, benign nodule, malignant tumor, hemorrhage, ischemic stroke, pneumonia, pleural effusion, cardiomegaly) |
| **Severity scoring** | 4-level severity (none / mild / moderate / severe) with learned uncertainty weighting |
| **Risk assessment** | Composite risk score adjusted by clinical context (age, prior conditions), urgency recommendation |
| **Explainability** | Grad-CAM saliency maps highlighting regions driving the prediction |
| **Calibration** | Temperature-scaled confidence for reliable clinical decision support |

## Architecture

```
Patient Image Tensor
        │
        ▼
┌─────────────────────┐
│   _Preprocessor     │  scan-type normalization, 224×224 resize
│   (MRI/CT/X-ray)    │
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  EfficientNet-B0    │  pretrained backbone (1280-dim features)
│  Feature Extractor  │
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  Dual Attention     │  SpatialAttention + ChannelAttention (SE)
└────────┬────────────┘
         ▼
    ┌────┴────┬──────────────┐
    ▼         ▼              ▼
┌────────┐ ┌──────────┐ ┌──────────┐
│Classify│ │ Region   │ │  Risk    │
│ Head   │ │ Analysis │ │  Head    │
│(8-cls) │ │(heatmap) │ │(sigmoid) │
└────────┘ └──────────┘ └──────────┘
```

## Security Model

- **GPU memory encryption**: All tensors (weights, activations, patient data) encrypted via H100 CC mode
- **CPU-TEE boundary**: Runs inside Intel TDX (GCP) or AMD SEV-SNP (Azure) confidential VM
- **Dual attestation**: CPU TEE report + NVIDIA NRAS GPU attestation token
- **Secure Boot (Azure/GCP GPU deploy)**: TEE-Crafter turns **UEFI Secure Boot off** on `gpu-cc-azure` and `gpu-cc-gcp` so the NVIDIA open DKMS driver is allowed to load; SEV-SNP / TDX memory encryption and attestation are unchanged ([docs/gpu_flow.md](../../docs/gpu_flow.md#secure-boot-on-gpu-cc-azure-and-gpu-cc-gcp))
- **Input hashing**: SHA-256 fingerprint of every input for audit trail
- **No data exfiltration**: Cloud provider cannot observe inputs, weights, or predictions

## Deploy

> **Prerequisite:** a non-empty `NVIDIA_NRAS_API_KEY` in `.env`. This satisfies a
> CLI gate; the NRAS endpoint does not use it as a Bearer token. See
> [docs/gpu_flow.md](../../docs/gpu_flow.md#nvidia-remote-attestation-service-nras).

```bash
# bake once per cloud
tee-crafter internal bake-ami --tee-platform gpu-cc-gcp    --region us-central1-a
# tee-crafter internal bake-ami --tee-platform gpu-cc-azure --region eastus2

tee-crafter deploy \
  --source ./examples/gpu_confidential_inference \
  --tee-platform gpu-cc-gcp \
  --ami-id <GPU_IMAGE_ID> \
  --persistent \
  --deploy --auto-approve
```

Swap `--tee-platform gpu-cc-azure` (+ that cloud's image id) for the SEV-SNP
variant. Both run the container behind the RA-TLS proxy, which forwards to
**`POST http://127.0.0.1:8080/`** — the same JSON body `app.py` reads on stdin.
The CUDA + PyTorch image is large; expect a long first upload.

### Full fail-closed shape — sealed `.env` + SIEM + BYOK

Seals this example's [`.env`](./.env) with a customer-managed key, streams
continuous-attestation events to a SIEM, and gates key release on the **dual**
CPU-TEE + NVIDIA GPU attestation, bound to the bake-time pinned measurement:

```bash
tee-crafter deploy \
  --source ./examples/gpu_confidential_inference \
  --tee-platform gpu-cc-gcp \
  --ami-id <GCP_GPU_IMAGE_URI> \
  --persistent --service-profile long-lived \
  --secrets-env ./examples/gpu_confidential_inference/.env \
  --siem syslog-cef --siem-config ./apps/cli/siem-sandbox/configs/syslog-via-ngrok.json \
  --byok gcp-kms     --byok-config ./apps/cli/byok-sandbox/configs/byok-gcp.json \
  --deploy --auto-approve
```

> `syslog-via-ngrok.json` is **generated**, not checked in — create it with
> `python apps/cli/siem-sandbox/scripts/make_remote_syslog_siem_config.py`
> (see [docs/siem.md](../../docs/siem.md)).
>
> On `gpu-cc-azure` use `--byok azure-skr`, not `azure-kv`: Key Vault wraps the
> released key to a vTPM-sealed key no Python process can unwrap. It needs
> `TEE_CRAFTER_MAA_ENDPOINT` and a hand-provisioned vault
> ([azure_setup.md](../../docs/azure_setup.md#secure-key-release-on-azure----byok-azure-skr)),
> and no Azure platform has completed a release on hardware yet. `gpu-cc-gcp` is
> the BYOK shape that has.

### Verify `.env` injection

`server.py`'s **GET** `/health` echoes the injected config so you can prove
`--secrets-env` delivery (non-secret proof only):

```bash
curl https://<attested-endpoint>/health
# {"status":"ok","env_injection":{"environment":"production",
#  "model_version":"radiology-efn-b0-v1","nras_key_loaded":true,
#  "env_injection_ok":true}}
```

`env_injection_ok` is `false` (and `model_version` is `"<.env NOT injected>"`)
if the `.env` never arrived.

## Test Locally

```bash
cat input/data.json | python app.py
```

## Input Format

```json
{
  "patient_id": "PT-7291",
  "scan_type": "mri_brain",
  "clinical_context": {
    "age": 72,
    "sex": "M",
    "prior_conditions": ["hypertension", "diabetes"],
    "urgency": "stat"
  },
  "options": {
    "generate_heatmap": true,
    "generate_gradcam": true,
    "temperature": 1.5
  },
  "tensor": [[0.12, 0.34, ...], ...]
}
```

## Output Format

```json
{
  "patient_id": "PT-7291",
  "diagnosis":  { "primary_finding": "hemorrhage", "confidence": 0.87,
                  "calibrated_confidence": 0.79, "differential": [ ... ] },
  "severity":   { "level": "severe", "scores": { ... } },
  "risk_assessment": { "composite_risk": 0.94, "urgency_recommendation": "immediate_review" },
  "anomaly_heatmap": [[ ... ]],
  "gradcam_saliency": [[ ... ]],
  "metadata":   { "model_version": "radiology-efn-b0-v1", "gpu_name": "NVIDIA H100 80GB HBM3",
                  "inference_ms": 23.4, "input_hash": "sha256:..." }
}
```

## Files

| File | Description |
|------|-------------|
| `app.py` | CLI entry point, batch processing, timing |
| `server.py` | FastAPI server for **container** deploy (`POST /`, `POST /infer`, `GET /health`) |
| `Dockerfile` | CUDA + PyTorch runtime image for `tee-crafter deploy` |
| `handler.py` | Full radiology pipeline (model, preprocessing, attention, Grad-CAM, calibration) |
| `input/data.json` | 3 synthetic 16x16 scans (MRI, CT, X-ray) with clinical context — generated placeholder pixel data, not real imaging |
| `requirements.txt` | PyTorch + torchvision dependencies |
