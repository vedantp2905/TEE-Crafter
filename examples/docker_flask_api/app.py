"""Minimal Flask JSON API for Docker-in-TEE demonstration.

Accepts POST requests with JSON payloads on ``/`` and ``/process``,
returns the processed result.  This is a standard Flask app — it has
no TEE-specific code.  TEE-Crafter wraps it with attestation + crypto.
"""
import os

from flask import Flask, request, jsonify

app = Flask(__name__)

# Config + secrets delivered by TEE-Crafter via `--secrets-env .env`.
# With --byok the .env is attestation-sealed; without it, the values are
# baked into the measured image.  They surface here as ordinary env vars.
PORT = int(os.environ.get("PORT", "8080"))
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
API_TOKEN = os.environ.get("API_TOKEN", "")
# Distinctive, non-secret marker that ONLY comes from the injected .env, so a
# deployer can prove `--secrets-env` delivery end-to-end (GET /health below).
APP_BANNER = os.environ.get("APP_BANNER", "<.env NOT injected>")

# Make .env delivery obvious in the container/boot logs too.
print(
    f"[docker_flask_api] env injection: banner={APP_BANNER!r} "
    f"environment={ENVIRONMENT!r} api_token_loaded={bool(API_TOKEN)}",
    flush=True,
)


def _env_proof():
    """Non-secret proof that the injected .env reached the app."""
    return {
        "banner": APP_BANNER,
        "environment": ENVIRONMENT,
        "api_token_loaded": bool(API_TOKEN),
        "env_injection_ok": APP_BANNER != "<.env NOT injected>",
    }


@app.route("/health", methods=["GET"])
@app.route("/", methods=["GET"])
def health():
    # GET is unauthenticated on purpose: it leaks no secret values, only
    # presence booleans + the non-secret banner from the .env.
    return jsonify({"status": "ok", **_env_proof()})


def _process(data):
    """Core processing logic (runs inside a TEE at deployment time)."""
    if isinstance(data, list):
        return [{"received": item, "status": "ok"} for item in data]
    return {"received": data, "status": "ok"}


@app.route("/", methods=["POST"])
@app.route("/process", methods=["POST"])
def handle():
    # Optional bearer-token gate, demonstrating a secret sourced from .env.
    if API_TOKEN:
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {API_TOKEN}":
            return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(force=True)
    result = _process(payload)
    return jsonify({"env_injection": _env_proof(), "result": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
