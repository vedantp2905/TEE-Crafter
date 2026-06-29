"""HTTP server for `tee-crafter deploy` on GPU-CC / other CVMs.

The TEE-Crafter host proxy forwards RA-TLS requests to the user container with:

    POST http://127.0.0.1:<port>/  (JSON body: one object or a list)

This mirrors the stdin/stdout contract of ``app.py`` but over HTTP.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

from handler import process_request

app = FastAPI(title="Confidential Radiology AI (container)")

_LISTEN_HOST = "0.0.0.0"
_LISTEN_PORT = int(os.environ.get("PORT", "8080"))

# Config + secrets delivered by TEE-Crafter via `--secrets-env .env` (sealed
# with --byok). MODEL_VERSION is a non-secret marker that proves end-to-end
# .env delivery; nras_key_loaded confirms the sealed secret arrived.
_MODEL_VERSION = os.environ.get("MODEL_VERSION", "<.env NOT injected>")
print(
    f"[gpu_confidential_inference] env injection: model_version={_MODEL_VERSION!r} "
    f"nras_key_loaded={bool(os.environ.get('NVIDIA_NRAS_API_KEY'))}",
    flush=True,
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "env_injection": {
            "environment": os.environ.get("ENVIRONMENT", "development"),
            "model_version": _MODEL_VERSION,
            "nras_key_loaded": bool(os.environ.get("NVIDIA_NRAS_API_KEY")),
            "env_injection_ok": _MODEL_VERSION != "<.env NOT injected>",
        },
    }


@app.post("/")
@app.post("/infer")
def infer(payload: Any = Body(...)):
    """Accept the same JSON as ``app.py`` (single object or batch list)."""
    t0 = time.perf_counter()
    try:
        if isinstance(payload, list):
            results = []
            for i, item in enumerate(payload):
                if not isinstance(item, dict):
                    raise HTTPException(
                        status_code=400,
                        detail="Batch items must be JSON objects",
                    )
                result = process_request(item)
                result["batch_index"] = i
                results.append(result)
            out = {
                "batch_size": len(results),
                "total_ms": round((time.perf_counter() - t0) * 1000, 2),
                "results": results,
            }
        elif isinstance(payload, dict):
            out = process_request(payload)
            out["total_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        else:
            raise HTTPException(
                status_code=400,
                detail="Body must be a JSON object or array of objects",
            )
        return JSONResponse(content=out)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


if __name__ == "__main__":
    uvicorn.run(app, host=_LISTEN_HOST, port=_LISTEN_PORT, log_level="info")
