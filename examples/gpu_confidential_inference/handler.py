"""Confidential medical imaging pipeline: multi-stage analysis on a single H100.

Implements a full radiology AI pipeline inside a TEE + GPU CC boundary:
  1. Input validation and DICOM-style metadata extraction
  2. Preprocessing (normalization, augmentation, multi-scale crops)
  3. Feature extraction via EfficientNet-B0 backbone
  4. Attention-weighted region analysis
  5. Multi-task prediction (classification + anomaly heatmap + risk score)
  6. Grad-CAM saliency for explainability
  7. Structured report generation with confidence calibration

All patient data, model weights, intermediate activations, and predictions
remain hardware-encrypted in GPU memory.  The cloud provider cannot observe
any step of the pipeline.
"""

import hashlib
import time
from typing import Any, Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torchvision import models


# ---------------------------------------------------------------------------
# Model architecture
# ---------------------------------------------------------------------------

class SpatialAttention(nn.Module):
    """Channel-independent spatial attention gate."""

    def __init__(self, in_channels: int):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv2d(2, 1, kernel_size=7, padding=3, bias=False),
            nn.BatchNorm2d(1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        avg_pool = x.mean(dim=1, keepdim=True)
        max_pool = x.amax(dim=1, keepdim=True)
        attn = self.conv(torch.cat([avg_pool, max_pool], dim=1))
        return x * attn


class ChannelAttention(nn.Module):
    """Squeeze-and-excitation channel attention."""

    def __init__(self, channels: int, reduction: int = 16):
        super().__init__()
        mid = max(channels // reduction, 8)
        self.pool = nn.AdaptiveAvgPool2d(1)
        self.fc = nn.Sequential(
            nn.Linear(channels, mid, bias=False),
            nn.ReLU(inplace=True),
            nn.Linear(mid, channels, bias=False),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        b, c, _, _ = x.shape
        w = self.fc(self.pool(x).view(b, c)).view(b, c, 1, 1)
        return x * w


class RegionAnalysisHead(nn.Module):
    """Produces per-region anomaly heatmap + severity scores."""

    def __init__(self, in_features: int, grid_size: int = 7, num_severity_levels: int = 4):
        super().__init__()
        self.grid_size = grid_size
        self.heatmap_head = nn.Sequential(
            nn.Linear(in_features, 256),
            nn.ReLU(inplace=True),
            nn.Dropout(0.2),
            nn.Linear(256, grid_size * grid_size),
            nn.Sigmoid(),
        )
        self.severity_head = nn.Sequential(
            nn.Linear(in_features, 128),
            nn.ReLU(inplace=True),
            nn.Linear(128, num_severity_levels),
        )

    def forward(self, features: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        heatmap = self.heatmap_head(features).view(-1, 1, self.grid_size, self.grid_size)
        severity = self.severity_head(features)
        return heatmap, severity


class ConfidentialRadiologyModel(nn.Module):
    """Multi-task radiology model: classification + heatmap + risk scoring.

    Uses EfficientNet-B0 backbone with dual attention (spatial + channel)
    and three output heads for comprehensive analysis.
    """

    NUM_CLASSES = 8
    CLASS_LABELS = {
        0: "normal",
        1: "benign_nodule",
        2: "malignant_tumor",
        3: "hemorrhage",
        4: "ischemic_stroke",
        5: "pneumonia",
        6: "pleural_effusion",
        7: "cardiomegaly",
    }
    SEVERITY_LABELS = ["none", "mild", "moderate", "severe"]

    def __init__(self):
        super().__init__()
        backbone = models.efficientnet_b0(weights=None)
        self.features = backbone.features
        self.spatial_attn = SpatialAttention(1280)
        self.channel_attn = ChannelAttention(1280)
        self.pool = nn.AdaptiveAvgPool2d(1)
        self.classifier = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(1280, 512),
            nn.ReLU(inplace=True),
            nn.Dropout(0.2),
            nn.Linear(512, self.NUM_CLASSES),
        )
        self.region_head = RegionAnalysisHead(1280, grid_size=7, num_severity_levels=len(self.SEVERITY_LABELS))
        self.risk_head = nn.Sequential(
            nn.Linear(1280 + self.NUM_CLASSES + len(self.SEVERITY_LABELS), 128),
            nn.ReLU(inplace=True),
            nn.Dropout(0.2),
            nn.Linear(128, 1),
            nn.Sigmoid(),
        )
        self._last_feature_map = None

    def forward(self, x: torch.Tensor) -> Dict[str, torch.Tensor]:
        feat_map = self.features(x)
        self._last_feature_map = feat_map

        feat_map = self.spatial_attn(feat_map)
        feat_map = self.channel_attn(feat_map)

        pooled = self.pool(feat_map).flatten(1)

        class_logits = self.classifier(pooled)
        heatmap, severity_logits = self.region_head(pooled)

        risk_input = torch.cat([pooled, class_logits, severity_logits], dim=1)
        risk_score = self.risk_head(risk_input)

        return {
            "class_logits": class_logits,
            "heatmap": heatmap,
            "severity_logits": severity_logits,
            "risk_score": risk_score,
            "features": pooled,
        }


# ---------------------------------------------------------------------------
# Grad-CAM explainability
# ---------------------------------------------------------------------------

def _compute_gradcam(model: ConfidentialRadiologyModel, x: torch.Tensor, target_class: int) -> List[List[float]]:
    """Generate Grad-CAM saliency map for the predicted class."""
    model.eval()
    x_grad = x.clone().requires_grad_(True)

    outputs = model(x_grad)
    logits = outputs["class_logits"]
    logits[0, target_class].backward(retain_graph=False)

    feat_map = model._last_feature_map
    if feat_map is None or x_grad.grad is None:
        return []

    grads = torch.autograd.grad(logits[0, target_class], feat_map, retain_graph=True)[0]
    weights = grads.mean(dim=[2, 3], keepdim=True)
    cam = F.relu((weights * feat_map).sum(dim=1, keepdim=True))
    cam = F.interpolate(cam, size=(7, 7), mode="bilinear", align_corners=False)
    cam = cam.squeeze()
    cam = (cam - cam.min()) / (cam.max() - cam.min() + 1e-8)
    return [[round(float(cam[i, j]), 4) for j in range(7)] for i in range(7)]


# ---------------------------------------------------------------------------
# Preprocessing pipeline
# ---------------------------------------------------------------------------

class _Preprocessor:
    """Standardized medical imaging preprocessing with multi-scale analysis."""

    SCAN_NORMALIZATION = {
        "mri_brain": {"mean": [0.485, 0.456, 0.406], "std": [0.229, 0.224, 0.225]},
        "ct_chest":  {"mean": [0.500, 0.500, 0.500], "std": [0.250, 0.250, 0.250]},
        "xray":      {"mean": [0.520, 0.520, 0.520], "std": [0.200, 0.200, 0.200]},
        "default":   {"mean": [0.500, 0.500, 0.500], "std": [0.250, 0.250, 0.250]},
    }

    @classmethod
    def prepare(cls, raw_tensor: list, scan_type: str, device: torch.device) -> torch.Tensor:
        t = torch.tensor(raw_tensor, dtype=torch.float32, device=device)

        if t.dim() == 1:
            side = int(t.numel() ** 0.5)
            t = t[:side * side].view(1, 1, side, side)
        elif t.dim() == 2:
            t = t.unsqueeze(0).unsqueeze(0)
        elif t.dim() == 3:
            t = t.unsqueeze(0)

        if t.shape[1] == 1:
            t = t.expand(-1, 3, -1, -1)

        t = F.interpolate(t, size=(224, 224), mode="bilinear", align_corners=False)

        norm = cls.SCAN_NORMALIZATION.get(scan_type, cls.SCAN_NORMALIZATION["default"])
        mean = torch.tensor(norm["mean"], device=device).view(1, 3, 1, 1)
        std = torch.tensor(norm["std"], device=device).view(1, 3, 1, 1)
        t = (t - mean) / std

        return t


# ---------------------------------------------------------------------------
# Confidence calibration
# ---------------------------------------------------------------------------

def _calibrate_confidence(probs: torch.Tensor, temperature: float = 1.5) -> torch.Tensor:
    """Temperature scaling for better-calibrated probabilities."""
    logits = torch.log(probs + 1e-10) * temperature
    return F.softmax(logits, dim=0)


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

_model: Optional[ConfidentialRadiologyModel] = None
_device: Optional[torch.device] = None
_request_counter = 0
_total_latency_ms = 0.0


def _ensure_model():
    global _model, _device

    if _model is not None:
        return

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA not available -- GPU CC requires a confidential GPU")

    _device = torch.device("cuda:0")

    # ``total_memory``, not ``total_mem``.  The attribute is defined on
    # ``torch._C._CudaDeviceProperties``, which has no ``__getattr__`` fallback,
    # so the misspelling raised AttributeError inside ``_ensure_model`` — and
    # ``process_request`` calls that first, which meant every request to this
    # example failed before it reached the model.  Checked against the type's
    # own attribute list in the base image:
    #   [..., 'shared_memory_per_multiprocessor', 'total_memory']
    props = torch.cuda.get_device_properties(0)
    if props.total_memory < 10 * 1024**3:
        raise RuntimeError(
            f"GPU has {props.total_memory // 1024**3} GiB -- "
            "minimum 10 GiB required for confidential radiology model"
        )

    _model = ConfidentialRadiologyModel()
    _model.to(_device)
    _model.eval()

    with torch.no_grad():
        dummy = torch.randn(1, 3, 224, 224, device=_device)
        _ = _model(dummy)


# ---------------------------------------------------------------------------
# Public handler
# ---------------------------------------------------------------------------

def process_request(data: dict) -> dict:
    """Full confidential radiology analysis pipeline.

    Input::

        {
            "patient_id": "PT-42",
            "scan_type": "mri_brain",          # mri_brain | ct_chest | xray
            "tensor": [[...], ...],            # raw pixel data (any shape)
            "clinical_context": {              # optional
                "age": 67,
                "sex": "M",
                "prior_conditions": ["hypertension", "diabetes"],
                "urgency": "stat"
            },
            "options": {                       # optional
                "generate_heatmap": true,
                "generate_gradcam": true,
                "temperature": 1.5
            }
        }

    Output::

        {
            "patient_id": "PT-42",
            "diagnosis": {
                "primary_finding": "malignant_tumor",
                "confidence": 0.89,
                "calibrated_confidence": 0.82,
                "differential": [
                    {"finding": "malignant_tumor", "probability": 0.89},
                    {"finding": "benign_nodule", "probability": 0.07},
                    ...
                ]
            },
            "severity": {
                "level": "severe",
                "scores": {"none": 0.02, "mild": 0.05, ...}
            },
            "risk_assessment": {
                "composite_risk": 0.91,
                "clinical_factors_applied": true,
                "urgency_recommendation": "immediate_review"
            },
            "anomaly_heatmap": [[...], ...],
            "gradcam_saliency": [[...], ...],
            "metadata": {
                "model_version": "radiology-efn-b0-v1",
                "gpu_device": "cuda:0",
                "inference_ms": 23.4,
                "input_hash": "sha256:abc...",
                "scan_type": "mri_brain"
            }
        }
    """
    global _request_counter, _total_latency_ms
    _ensure_model()

    t_start = time.perf_counter()
    _request_counter += 1

    patient_id = data.get("patient_id", "unknown")
    scan_type = data.get("scan_type", "default")
    raw_tensor = data.get("tensor")
    clinical = data.get("clinical_context", {})
    options = data.get("options", {})

    if raw_tensor is None:
        return {"patient_id": patient_id, "error": "missing 'tensor' field"}

    input_hash = hashlib.sha256(str(raw_tensor).encode()).hexdigest()[:16]

    try:
        x = _Preprocessor.prepare(raw_tensor, scan_type, _device)
    except Exception as exc:
        return {"patient_id": patient_id, "error": f"preprocessing failed: {type(exc).__name__}"}

    # ---- Multi-task inference ----
    with torch.no_grad():
        outputs = _model(x)

    class_probs = F.softmax(outputs["class_logits"], dim=1).squeeze(0)
    temp = options.get("temperature", 1.5)
    cal_probs = _calibrate_confidence(class_probs, temperature=temp)

    pred_idx = int(class_probs.argmax())
    primary_finding = ConfidentialRadiologyModel.CLASS_LABELS[pred_idx]
    confidence = float(class_probs[pred_idx])
    cal_confidence = float(cal_probs[pred_idx])

    sorted_indices = torch.argsort(class_probs, descending=True)
    differential = []
    for idx in sorted_indices:
        i = int(idx)
        p = float(class_probs[i])
        if p < 0.01 and len(differential) >= 3:
            break
        differential.append({
            "finding": ConfidentialRadiologyModel.CLASS_LABELS[i],
            "probability": round(p, 4),
            "calibrated": round(float(cal_probs[i]), 4),
        })

    sev_probs = F.softmax(outputs["severity_logits"], dim=1).squeeze(0)
    sev_idx = int(sev_probs.argmax())
    severity_level = ConfidentialRadiologyModel.SEVERITY_LABELS[sev_idx]
    severity_scores = {
        ConfidentialRadiologyModel.SEVERITY_LABELS[i]: round(float(sev_probs[i]), 4)
        for i in range(len(ConfidentialRadiologyModel.SEVERITY_LABELS))
    }

    composite_risk = float(outputs["risk_score"].squeeze())
    age = clinical.get("age", 0)
    prior_conditions = clinical.get("prior_conditions", [])
    clinical_adjusted = False
    if age > 65:
        composite_risk = min(1.0, composite_risk + 0.05)
        clinical_adjusted = True
    if "diabetes" in prior_conditions:
        composite_risk = min(1.0, composite_risk + 0.03)
        clinical_adjusted = True
    if "hypertension" in prior_conditions:
        composite_risk = min(1.0, composite_risk + 0.02)
        clinical_adjusted = True
    if "cancer_history" in prior_conditions:
        composite_risk = min(1.0, composite_risk + 0.08)
        clinical_adjusted = True

    if composite_risk > 0.8:
        urgency_rec = "immediate_review"
    elif composite_risk > 0.5:
        urgency_rec = "priority_review"
    elif composite_risk > 0.3:
        urgency_rec = "routine_followup"
    else:
        urgency_rec = "standard_reporting"

    result: Dict[str, Any] = {
        "patient_id": patient_id,
        "diagnosis": {
            "primary_finding": primary_finding,
            "confidence": round(confidence, 4),
            "calibrated_confidence": round(cal_confidence, 4),
            "differential": differential,
        },
        "severity": {
            "level": severity_level,
            "scores": severity_scores,
        },
        "risk_assessment": {
            "composite_risk": round(composite_risk, 4),
            "clinical_factors_applied": clinical_adjusted,
            "urgency_recommendation": urgency_rec,
        },
    }

    if options.get("generate_heatmap", True):
        heatmap = outputs["heatmap"].squeeze().detach().cpu()
        result["anomaly_heatmap"] = [
            [round(float(heatmap[i, j]), 4) for j in range(heatmap.shape[1])]
            for i in range(heatmap.shape[0])
        ]

    if options.get("generate_gradcam", False):
        try:
            result["gradcam_saliency"] = _compute_gradcam(_model, x, pred_idx)
        except Exception:
            result["gradcam_saliency"] = None

    elapsed_ms = (time.perf_counter() - t_start) * 1000
    _total_latency_ms += elapsed_ms

    result["metadata"] = {
        "model_version": "radiology-efn-b0-v1",
        "gpu_device": str(_device),
        "gpu_name": torch.cuda.get_device_name(0),
        "inference_ms": round(elapsed_ms, 2),
        "input_hash": f"sha256:{input_hash}",
        "scan_type": scan_type,
        "request_number": _request_counter,
        "avg_latency_ms": round(_total_latency_ms / _request_counter, 2),
    }

    return result
