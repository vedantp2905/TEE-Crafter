import os
import sys
import json
from schemas.transaction import Transaction
from core.scoring import score_transaction


def _env_injection():
    """Config + secrets delivered by TEE-Crafter via `--secrets-env .env`.

    BLOCK_THRESHOLD is a non-secret value sourced from the injected .env, so
    its presence in the output proves end-to-end delivery; the *_loaded flags
    confirm the sealed secrets arrived without leaking their values.
    """
    threshold = int(os.environ.get("SCORE_THRESHOLD", "80"))
    return {
        "environment": os.environ.get("ENVIRONMENT", "development"),
        "score_threshold": threshold,
        "database_url_loaded": bool(os.environ.get("DATABASE_URL")),
        "risk_api_token_loaded": bool(os.environ.get("RISK_API_TOKEN")),
        "env_injection_ok": "SCORE_THRESHOLD" in os.environ,
    }


def run_app():
    input_str = sys.stdin.read()
    env = _env_injection()
    print(f"[fintech] env injection: {env}", file=sys.stderr, flush=True)
    threshold = env["score_threshold"]
    try:
        data = json.loads(input_str)

        if isinstance(data, list):
            scored = [score_transaction(Transaction(**item), threshold).model_dump()
                      for item in data]
        else:
            scored = score_transaction(Transaction(**data), threshold).model_dump()

        print(json.dumps({"env_injection": env, "results": scored},
                         indent=2, default=str))

    except Exception as e:
        # Return generic error structure
        print(json.dumps({"env_injection": env, "error": str(e)}))

if __name__ == "__main__":
    run_app()
