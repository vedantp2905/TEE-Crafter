"""Small FastAPI HTTP app for local runs and TEE-Crafter deploy.

No TEE-specific code — attestation and RA-TLS are handled by the platform
ingress proxy when you deploy with ``tee-crafter deploy --persistent``.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from fastapi import Body, FastAPI, Header, HTTPException
import uvicorn

app = FastAPI(title="Hello HTTP", version="1.0.0")

PORT = int(os.environ.get("PORT", "8080"))
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
API_TOKEN = os.environ.get("API_TOKEN", "")
APP_BANNER = os.environ.get("APP_BANNER", "<.env NOT injected>")

print(
    f"[hello_http] env injection: banner={APP_BANNER!r} "
    f"environment={ENVIRONMENT!r} api_token_loaded={bool(API_TOKEN)}",
    flush=True,
)


def _env_proof() -> dict[str, Any]:
    return {
        "banner": APP_BANNER,
        "environment": ENVIRONMENT,
        "api_token_loaded": bool(API_TOKEN),
        "env_injection_ok": APP_BANNER != "<.env NOT injected>",
    }


def _require_auth(authorization: str | None) -> None:
    if not API_TOKEN:
        return
    if authorization != f"Bearer {API_TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/health")
@app.get("/")
def health() -> dict[str, Any]:
    return {"status": "ok", **_env_proof()}


@app.get("/time")
def time() -> dict[str, str]:
    return {"utc": datetime.now(timezone.utc).isoformat()}


@app.post("/echo")
def echo(
    payload: Any = Body(...),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(authorization)
    return {
        "env_injection": _env_proof(),
        "echo": payload,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
