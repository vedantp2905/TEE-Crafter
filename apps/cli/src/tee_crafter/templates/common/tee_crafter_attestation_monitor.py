"""Continuous attestation monitor for TEE workloads.

Runs a background daemon thread that periodically re-requests hardware
attestation and compares the measurement against the baseline captured
at boot.  Detects measurement drift, platform tampering, or unexpected
changes to the runtime environment.

Known limitation — where these logs live
----------------------------------------
``TEE_AUDIT_LOG_DIR`` defaults to ``/var/log/tee_crafter``, which on the
CVM platforms is the guest's persistent OS disk: outside the launch
measurement, outside TEE memory encryption, and reachable by anyone with
root on the guest or with volume/cloud-plane access.

Be blunt about what that means for *this* file specifically: unlike
``tee_crafter_audit_logger``, the monitor's JSONL has **no hash chain and
no HMAC at all**.  It is an append-only diagnostic record, not tamper
evidence.  Someone who can write the file can rewrite drift history
without leaving a trace here.

The detection this module provides that is *not* forgeable that way is
its live behaviour: on persistent drift it calls ``halt_fn`` and the
workload stops serving (see the drift-kill note below), and each cycle
is exported to
the SIEM by the sidecar.  Treat the SIEM copy — not this file — as the
audit record.

This file is copied into the TEE image at build time and imported by the
platform template app.  Platform-specific attestation functions are
injected via ``configure()``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

_logger = logging.getLogger("tee_crafter.attestation_monitor")

_LOG_DIR = os.environ.get("TEE_AUDIT_LOG_DIR", "/var/log/tee_crafter")
_LOG_FILE = os.path.join(_LOG_DIR, "attestation_monitor.jsonl")

_DEFAULT_INTERVAL = int(os.environ.get("TEE_ATTESTATION_INTERVAL_SECS", "300"))

# Drift-kill (audit catalogue ``ATT-008``, "Continuous-attestation pulses
# observed" — see core/audit/checks.py; the ``MON-1`` tag this used to
# carry is not defined anywhere, so an operator could not look it up):
# production posture is **auto-shutdown on persistent drift**.
# When ``TEE_ATTESTATION_DRIFT_KILL=N`` (N >= 1) samples disagree with
# the boot-time baseline (or fail outright), the monitor calls
# ``halt_fn`` (default: ``os._exit(99)``) — the orchestrator then
# detects the missing health check, tears the VM down, and surfaces
# the drift to the operator.
#
# Default is ``3``: at the default 5-minute interval that gives ~15
# minutes for transient kernel TPM hiccups to resolve before we treat
# them as a genuine integrity breach.  Dev hatch: set to ``0`` for
# "log only" behaviour (regression tests / inspection-only deploys).
_DRIFT_KILL_THRESHOLD = int(os.environ.get("TEE_ATTESTATION_DRIFT_KILL", "3"))

_lock = threading.Lock()
_running = False
_thread: Optional[threading.Thread] = None
_baseline: Optional[str] = None
_attest_fn: Optional[Callable[[], Dict[str, Any]]] = None
_gpu_attest_fn: Optional[Callable[[], Dict[str, Any]]] = None
_halt_fn: Callable[[], None] = lambda: os._exit(99)
_interval: int = _DEFAULT_INTERVAL
_drift_kill_threshold: int = _DRIFT_KILL_THRESHOLD
_results: List[Dict[str, Any]] = []
_gpu_results: List[Dict[str, Any]] = []
_gpu_baseline_nonce: Optional[str] = None


def configure(
    attest_fn: Callable[[], Dict[str, Any]],
    interval_secs: int = _DEFAULT_INTERVAL,
    gpu_attest_fn: Optional[Callable[[], Dict[str, Any]]] = None,
    drift_kill_threshold: Optional[int] = None,
    halt_fn: Optional[Callable[[], None]] = None,
) -> None:
    """Set the platform-specific attestation callback.

    ``attest_fn`` must return a dict with at least ``{"measurement": "<hex>"}``.
    It may also include ``report_hex``, ``policy``, or other platform data.

    ``gpu_attest_fn``, when provided, is called each cycle to check GPU CC
    mode, driver health, and NRAS token validity.  It must return a dict with
    ``{"cc_mode": "on"|"devtools"|"off", "gpu_healthy": bool, ...}``.

    Only ``cc_mode == "on"`` is considered safe for production: ``devtools``
    disables GPU memory encryption, and ``off`` means no confidential
    computing at all.  Both are treated as drift.
    """
    global _attest_fn, _gpu_attest_fn, _interval, _drift_kill_threshold, _halt_fn
    _attest_fn = attest_fn
    _gpu_attest_fn = gpu_attest_fn
    _interval = interval_secs
    if drift_kill_threshold is not None:
        _drift_kill_threshold = int(drift_kill_threshold)
    if halt_fn is not None:
        _halt_fn = halt_fn


def start(baseline_measurement: Optional[str] = None) -> None:
    """Start the attestation monitor background thread.

    If *baseline_measurement* is ``None``, the first attestation result
    becomes the baseline.
    """
    global _running, _thread, _baseline
    if _attest_fn is None:
        _logger.warning("Attestation monitor not configured; skipping start")
        return
    _baseline = baseline_measurement
    _running = True
    _thread = threading.Thread(target=_monitor_loop, daemon=True, name="attest-monitor")
    _thread.start()
    _logger.info(
        "Attestation monitor started (interval=%ds, baseline=%s)",
        _interval,
        _baseline or "auto-detect",
    )


def stop() -> None:
    """Stop the monitor thread."""
    global _running
    _running = False
    if _thread and _thread.is_alive():
        _thread.join(timeout=_interval + 5)


def get_status() -> Dict[str, Any]:
    """Return current monitor status and recent results."""
    with _lock:
        status: Dict[str, Any] = {
            "running": _running,
            "baseline_measurement": _baseline,
            "interval_secs": _interval,
            "total_checks": len(_results),
            "last_check": _results[-1] if _results else None,
            "drift_detected": any(r.get("drift") for r in _results),
            "consecutive_failures": _consecutive_failures(),
        }
        if _gpu_attest_fn is not None:
            status["gpu_monitoring"] = True
            status["gpu_total_checks"] = len(_gpu_results)
            status["gpu_last_check"] = _gpu_results[-1] if _gpu_results else None
            status["gpu_cc_drift"] = any(r.get("cc_mode_drift") for r in _gpu_results)
            status["gpu_unhealthy_count"] = sum(
                1 for r in _gpu_results if not r.get("gpu_healthy", True)
            )
        return status


def _consecutive_failures() -> int:
    count = 0
    for r in reversed(_results):
        if r.get("status") != "ok" or r.get("drift"):
            count += 1
        else:
            break
    return count


def _gpu_consecutive_failures() -> int:
    count = 0
    for r in reversed(_gpu_results):
        if (
            r.get("status") != "ok"
            or r.get("cc_mode_drift")
            or r.get("attestation_drift")
            or not r.get("gpu_healthy", True)
        ):
            count += 1
        else:
            break
    return count


def _monitor_loop() -> None:
    global _baseline, _gpu_baseline_nonce
    _ensure_log_dir()

    while _running:
        result = _perform_check()

        if _baseline is None and result.get("measurement"):
            _baseline = result["measurement"]
            result["baseline_set"] = True
            _logger.info("Baseline measurement set: %s", _baseline)

        with _lock:
            _results.append(result)
            if len(_results) > 1000:
                _results[:] = _results[-500:]

        _write_result(result)

        if result.get("drift"):
            _logger.error(
                "ATTESTATION DRIFT DETECTED: expected=%s got=%s",
                _baseline,
                result.get("measurement"),
            )

        if _drift_kill_threshold > 0:
            failures = _consecutive_failures()
            if failures >= _drift_kill_threshold:
                _logger.critical(
                    "ATT-008: %d consecutive attestation drift/failure samples "
                    "(threshold=%d) — halting enclave to fail closed.",
                    failures,
                    _drift_kill_threshold,
                )
                _write_result({
                    "ts": time.time(),
                    "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "status": "halt",
                    "reason": "drift_kill_threshold_exceeded",
                    "consecutive_failures": failures,
                    "threshold": _drift_kill_threshold,
                })
                try:
                    _halt_fn()
                except Exception:
                    os._exit(99)
                return

        if _gpu_attest_fn is not None:
            gpu_result = _perform_gpu_check()
            with _lock:
                _gpu_results.append(gpu_result)
                if len(_gpu_results) > 1000:
                    _gpu_results[:] = _gpu_results[-500:]
            _write_result(gpu_result)

            if gpu_result.get("cc_mode_drift"):
                _logger.critical(
                    "GPU CC MODE DRIFT: expected=on got=%s — this is a security "
                    "event, GPU memory encryption may be disabled.",
                    gpu_result.get("cc_mode"),
                )
            if gpu_result.get("attestation_drift") and not gpu_result.get("cc_mode_drift"):
                _logger.critical(
                    "GPU NRAS re-attestation failed (token invalid) — treating as drift."
                )
            if not gpu_result.get("gpu_healthy", True):
                _logger.error("GPU HEALTH CHECK FAILED: %s", gpu_result.get("error", "unknown"))

            if _drift_kill_threshold > 0:
                gpu_failures = _gpu_consecutive_failures()
                if gpu_failures >= _drift_kill_threshold:
                    _logger.critical(
                        "ATT-008: %d consecutive GPU CC drift/failure samples "
                        "(threshold=%d) — halting enclave to fail closed.",
                        gpu_failures,
                        _drift_kill_threshold,
                    )
                    _write_result({
                        "ts": time.time(),
                        "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "check_type": "gpu_cc",
                        "status": "halt",
                        "reason": "gpu_drift_kill_threshold_exceeded",
                        "consecutive_failures": gpu_failures,
                        "threshold": _drift_kill_threshold,
                    })
                    try:
                        _halt_fn()
                    except Exception:
                        os._exit(99)
                    return

        for _ in range(int(_interval)):
            if not _running:
                return
            time.sleep(1)


def _perform_check() -> Dict[str, Any]:
    ts = time.time()
    try:
        report = _attest_fn()
        measurement = report.get("measurement", "")
        drift = bool(_baseline and measurement and measurement != _baseline)
        return {
            "ts": ts,
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
            "status": "ok",
            "measurement": measurement,
            "baseline": _baseline or "",
            "drift": drift,
            "report_hash": hashlib.sha256(
                json.dumps(report, sort_keys=True, default=str).encode()
            ).hexdigest(),
            "latency_ms": round((time.time() - ts) * 1000, 2),
        }
    except Exception as exc:
        return {
            "ts": ts,
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
            "status": "error",
            "error": str(exc)[:500],
            "measurement": "",
            "baseline": _baseline or "",
            "drift": False,
            "latency_ms": round((time.time() - ts) * 1000, 2),
        }


def _perform_gpu_check() -> Dict[str, Any]:
    """Run GPU CC health check: CC mode status, driver health, NRAS re-attestation."""
    ts = time.time()
    try:
        report = _gpu_attest_fn()
        cc_mode = report.get("cc_mode", "unknown")
        gpu_healthy = report.get("gpu_healthy", False)
        nras_token_valid = bool(report.get("nras_token_valid", False))
        # NVIDIA CC: only "on" is production-safe.  "devtools" disables
        # memory encryption and "off" means no CC at all.  Either is drift.
        cc_mode_normalised = str(cc_mode).strip().lower()
        cc_mode_drift = cc_mode_normalised != "on"
        # A failed NRAS re-attestation is also drift (key material or firmware
        # may have changed since baseline).
        attestation_drift = (not nras_token_valid) or cc_mode_drift
        status = (
            "ok"
            if (gpu_healthy and not attestation_drift)
            else "failed"
        )
        return {
            "ts": ts,
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
            "check_type": "gpu_cc",
            "status": status,
            "cc_mode": cc_mode,
            "cc_mode_drift": cc_mode_drift,
            "attestation_drift": attestation_drift,
            "gpu_healthy": gpu_healthy,
            "gpu_count": report.get("gpu_count", 0),
            "nras_token_valid": nras_token_valid,
            "driver_version": report.get("driver_version", ""),
            "latency_ms": round((time.time() - ts) * 1000, 2),
        }
    except Exception as exc:
        return {
            "ts": ts,
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
            "check_type": "gpu_cc",
            "status": "error",
            "error": str(exc)[:500],
            "cc_mode": "unknown",
            "cc_mode_drift": True,
            "gpu_healthy": False,
            "latency_ms": round((time.time() - ts) * 1000, 2),
        }


def _ensure_log_dir() -> None:
    try:
        os.makedirs(_LOG_DIR, mode=0o700, exist_ok=True)
    except OSError:
        pass


def _write_result(result: Dict[str, Any]) -> None:
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
    except OSError as exc:
        _logger.warning("Attestation monitor log write failed: %s", exc)
