"""Confidential radiology AI: multi-task medical image analysis inside a TEE.

Runs on a single NVIDIA H100 with Confidential Computing enabled.
All model weights, patient imaging data, clinical context, predictions,
saliency maps, and risk assessments remain hardware-encrypted in GPU
memory -- the cloud provider cannot observe any stage of the pipeline.

Pipeline stages:
  1. Input validation with DICOM-style metadata
  2. Scan-type-aware normalization (MRI/CT/X-ray)
  3. EfficientNet-B0 feature extraction with dual attention
  4. Multi-task prediction (8-class diagnosis + severity + risk)
  5. Grad-CAM saliency map generation
  6. Confidence calibration and structured report

Deploy with:
    tee-crafter deploy \\
      --source ./examples/gpu_confidential_inference \\
      --tee-platform gpu-cc-gcp \\
      --ami-id <GCP_GPU_IMAGE_URI> \\
      --instance-type a3-highgpu-1g \\
      --persistent \\
      --deploy --auto-approve

The GPU model and count come from --instance-type via the instance catalog;
there are no separate --gpu-model / --gpu-count flags. Exactly one of --batch
or --persistent is required.
"""

import json
import sys
import time

from handler import process_request


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print(json.dumps({"error": "empty input"}))
        return

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"invalid JSON: {exc}"}))
        return

    t0 = time.perf_counter()

    if isinstance(data, list):
        results = []
        for i, item in enumerate(data):
            result = process_request(item)
            result["batch_index"] = i
            results.append(result)
        output = {
            "batch_size": len(results),
            "total_ms": round((time.perf_counter() - t0) * 1000, 2),
            "results": results,
        }
    else:
        output = process_request(data)
        output["total_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
