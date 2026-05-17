#!/usr/bin/env python3
"""CVM host secret bootstrap (runs in ``tee-crafter-secrets.service``, oneshot).

This is the missing runtime caller that makes ``--secrets-env`` and BYOK
actually reach the workload.  It runs on the CVM host *before* the user
container starts (the container unit ``Requires=`` + ``After=`` this oneshot),
with the platform report device available, and:

1. **Sealed ``.env``** (``TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64`` present):
   attested-decrypt the envelope through the BYOK orchestrator and write the
   cleartext to ``/run/tee_crafter/app.env`` (tmpfs, 0600).
2. **Baked ``.env``** (no bundle, but a non-empty ``app.env`` was staged next
   to this script): copy it to ``/run/tee_crafter/app.env``.
3. **BYOK DEK** (``TEE_CRAFTER_BYOK_ENABLED=1``): attested-release the
   customer DEK to ``$TEE_CRAFTER_BYOK_DEK_PATH`` for the app to read.

**Fail-closed by default**: if a *requested* step fails (sealed unseal or BYOK
release), the process exits non-zero so the dependent container unit never
starts (``Requires=`` propagates the failure).  Set
``TEE_CRAFTER_SECRETS_FAIL_OPEN=1`` to downgrade failures to warnings for
dev/prototyping — mirrors the SIEM ``*_FAIL_OPEN`` hatch.

The script is staged into the app bundle and executed by the platform venv so
``tee_crafter.core`` is importable; it never raises uncaught (it translates to
a clean exit code).
"""
from __future__ import annotations

import os
import shutil
import sys

APP_ENV_PATH = "/run/tee_crafter/app.env"


def _log(msg: str) -> None:
    sys.stderr.write(f"[tee-crafter-secrets] {msg}\n")
    sys.stderr.flush()


def _fail_open() -> bool:
    return os.environ.get("TEE_CRAFTER_SECRETS_FAIL_OPEN", "").strip().lower() in (
        "1", "true", "yes", "on")


def _platform() -> str:
    # The deploy installer exports this into the oneshot environment; fall back
    # to argv for manual invocation/tests.
    p = os.environ.get("TEE_CRAFTER_TEE_PLATFORM", "").strip()
    if not p and len(sys.argv) > 1:
        p = sys.argv[1].strip()
    return p


def _ensure_app_env() -> None:
    os.makedirs(os.path.dirname(APP_ENV_PATH), exist_ok=True, mode=0o700)
    if not os.path.exists(APP_ENV_PATH):
        with open(APP_ENV_PATH, "w", encoding="utf-8") as fh:
            fh.write("# tee-crafter app env\n")
    os.chmod(APP_ENV_PATH, 0o600)


def _staged_app_env() -> str:
    """Path of the baked plaintext app.env staged beside this script."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.env")


def _has_content(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith(b"#"):
                    return True
    except OSError:
        return False
    return False


def main() -> int:
    _ensure_app_env()
    platform = _platform()
    fail_open = _fail_open()
    failures = []

    sealed_bundle = os.environ.get("TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64", "")
    byok_enabled = os.environ.get("TEE_CRAFTER_BYOK_ENABLED", "0").strip().lower() in (
        "1", "true", "yes", "on")

    provider = None
    if sealed_bundle or byok_enabled:
        try:
            from tee_crafter.core.keys.attestation_providers import build_for_platform
            provider = build_for_platform(platform)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"attestation provider for {platform!r}: {exc!r}")

    # 1/2: sealed .env (attested) takes precedence; else baked plaintext copy.
    if sealed_bundle:
        if provider is None:
            failures.append("sealed .env present but no attestation provider")
        else:
            try:
                from tee_crafter.templates.common.tee_crafter_runtime_bootstrap import (
                    bootstrap_secret_env_release,
                )
            except Exception:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from tee_crafter_runtime_bootstrap import (  # type: ignore
                    bootstrap_secret_env_release,
                )
            result = bootstrap_secret_env_release(
                attestation_provider=provider, env_path=APP_ENV_PATH,
                inject_environ=False)
            if result is None:
                failures.append("sealed .env attested release failed")
            else:
                _log(f"sealed .env released: {len(result)} var(s) -> {APP_ENV_PATH}")
    else:
        staged = _staged_app_env()
        if _has_content(staged):
            try:
                shutil.copyfile(staged, APP_ENV_PATH)
                os.chmod(APP_ENV_PATH, 0o600)
                _log(f"baked .env staged -> {APP_ENV_PATH}")
            except OSError as exc:
                failures.append(f"baked .env copy failed: {exc!r}")

    # 3: BYOK DEK release for the app.
    if byok_enabled:
        if provider is None:
            failures.append("BYOK enabled but no attestation provider")
        else:
            try:
                from tee_crafter.templates.common.tee_crafter_runtime_bootstrap import (
                    bootstrap_byok_release,
                )
            except Exception:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from tee_crafter_runtime_bootstrap import (  # type: ignore
                    bootstrap_byok_release,
                )
            out = bootstrap_byok_release(attestation_provider=provider)
            if out is None:
                failures.append("BYOK attested release failed")
            else:
                _log("BYOK DEK released for the app")

    if failures:
        for f in failures:
            _log(("WARN " if fail_open else "FATAL ") + f)
        if not fail_open:
            _log("refusing to start the workload (fail-closed). "
                 "Set TEE_CRAFTER_SECRETS_FAIL_OPEN=1 to override for dev.")
            return 1
        _log("TEE_CRAFTER_SECRETS_FAIL_OPEN=1: continuing despite failures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
