"""Shared helper that turns the structured output of a verifier ``client.py``
into a compact attestation-report dict suitable for the provenance audit chain.

AUD-7 / SUP-X: every deploy phase used to record only
``attestation_verified=True`` regardless of which platform or what evidence
the verifier actually inspected.  This module gives every phase a single
canonical extractor that:

1. Parses the ``ATTESTATION_REPORT {<json>}`` line which forward-going
   client templates emit on stdout after a successful verify.  This is the
   preferred, lossless path — any field listed below survives unchanged.
2. Falls back to regex parsing of platform-specific stderr labels
   (``MRTD: <hex>``, ``Measurement: <hex>``, ``MRENCLAVE: <hex>`` …) for
   legacy client templates that have not been migrated to ATTESTATION_REPORT
   yet.  The fallback is opportunistic: missing fields just stay out of
   the audit entry.

The output dict is always allow-list filtered to ``REPORT_FIELDS`` so that
unrelated stdout cannot smuggle keys into the provenance chain.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict
from tee_crafter.core.env_flags import interpret

# Sentinel substrings every client template prints to stderr when it accepts
# the first observed measurement instead of comparing against a build-time
# baseline (trust-on-first-use).  Detecting these lets the deploy pipeline
# surface unpinned measurements as a WARN (or a hard FAIL under
# ``TEE_CRAFTER_REQUIRE_PINNED_MEASUREMENT``) rather than silently passing
# ATT-003 ("measurement matches build baseline").
_SELF_PIN_SENTINELS = ("self-pinned", "self_pinned", "self-pin")

#: When this env var is truthy a self-pinned (unpinned-baseline) measurement
#: turns ATT-003 into a hard FAIL instead of a WARN.  Production deploys should
#: set it so an image without a baked ``measurements.json`` cannot pass the
#: ``--required-checks auto`` gate.
REQUIRE_PINNED_ENV = "TEE_CRAFTER_REQUIRE_PINNED_MEASUREMENT"


def _truthy(val: str | None) -> bool:
    return interpret(val) is True


def detect_self_pinned_measurement(*streams: str) -> bool:
    """Return True if any client stream indicates trust-on-first-use self-pin.

    The CPU-TEE client templates print a ``… self-pinned …`` line to stderr
    when ``EXPECTED_MEASUREMENT`` / ``EXPECTED_MRTD`` / ``EXPECTED_MRENCLAVE``
    was ``unknown`` at build time, i.e. no baseline was baked into the image.
    """
    for s in streams:
        if not s:
            continue
        low = s.lower()
        if any(sentinel in low for sentinel in _SELF_PIN_SENTINELS):
            return True
    return False

REPORT_FIELDS = frozenset({
    "platform", "issuer", "tcb_status", "tcb_svn", "tcb_module_version",
    "tcb_chip_id", "tcb_minimum_version",
    "mrenclave", "mrsigner", "isvprodid", "isvsvn",
    "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "pcr0", "pcr4", "pcr7",
    "pcr_sha256_quote_digest",
    "measurement", "measurement_digest", "report_hash",
    "nonce", "nonce_binding",
    "nras_token_kid", "nras_eat_digest", "nras_token_valid",
    "vlek_chip_id", "vcek_chip_id",
    "container_image_digest", "container_digest",
    "spki_sha256",
    "attestation_evidence_kind", "report_kind",
    "quote_signature_alg", "cose_alg",
    # Commitment to the in-TEE audit log's HMAC key, folded into the
    # hardware-signed `report_data` preimage by the app templates.  Carrying
    # it here is what lets `verify-provenance` pin the *attested* value and
    # `verify-siem-chain --expect-chain-commitment` compare exported events
    # against it.  Without it the SIEM check is only self-consistent: the
    # commitment travels with the very log it is meant to authenticate.
    "chain_key_commitment",
})

_ATTESTATION_REPORT_PREFIX = "ATTESTATION_REPORT"

_HEX_FIELDS_RE: Dict[str, re.Pattern[str]] = {
    # Each pattern is intentionally tolerant of whitespace and column padding.
    # Hex length floor of 32 chars accepts SHA-256 / SHA-384 / SGX measurement
    # widths without baking a specific length in.
    "mrenclave": re.compile(r"MRENCLAVE\s*[:=]\s*([0-9a-fA-F]{32,})", re.IGNORECASE),
    "mrsigner": re.compile(r"MRSIGNER\s*[:=]\s*([0-9a-fA-F]{32,})", re.IGNORECASE),
    "mrtd": re.compile(r"MRTD\s*[:=]\s*([0-9a-fA-F]{48,})", re.IGNORECASE),
    "measurement": re.compile(r"Measurement\s*[:=]\s*([0-9a-fA-F]{32,})", re.IGNORECASE),
    "rtmr0": re.compile(r"RTMR\s*0\s*[:=]\s*([0-9a-fA-F]{48,})", re.IGNORECASE),
    "rtmr1": re.compile(r"RTMR\s*1\s*[:=]\s*([0-9a-fA-F]{48,})", re.IGNORECASE),
    "rtmr2": re.compile(r"RTMR\s*2\s*[:=]\s*([0-9a-fA-F]{48,})", re.IGNORECASE),
    "rtmr3": re.compile(r"RTMR\s*3\s*[:=]\s*([0-9a-fA-F]{48,})", re.IGNORECASE),
    "pcr0": re.compile(r"PCR\s*0\s*[:=]\s*([0-9a-fA-F]{40,})", re.IGNORECASE),
    "pcr4": re.compile(r"PCR\s*4\s*[:=]\s*([0-9a-fA-F]{40,})", re.IGNORECASE),
    "pcr7": re.compile(r"PCR\s*7\s*[:=]\s*([0-9a-fA-F]{40,})", re.IGNORECASE),
    # Exactly 64 hex: it is a SHA-256 and the clients reject any other width,
    # so accepting a looser match here would let a malformed value through the
    # one place an operator would look to confirm it.
    "chain_key_commitment": re.compile(
        r"chain[_\s-]?key[_\s-]?commitment\s*[:=]\s*([0-9a-fA-F]{64})\b",
        re.IGNORECASE),
}

_INT_FIELDS_RE: Dict[str, re.Pattern[str]] = {
    "isvprodid": re.compile(r"ISV\s*PROD\s*ID\s*[:=]\s*(\d+)", re.IGNORECASE),
    "isvsvn": re.compile(r"ISV\s*SVN\s*[:=]\s*(\d+)", re.IGNORECASE),
}


def _filter(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if k in REPORT_FIELDS and v not in ("", None)}


def _parse_attestation_report_line(text: str) -> Dict[str, Any]:
    if not text or _ATTESTATION_REPORT_PREFIX not in text:
        return {}
    for raw_line in reversed(text.splitlines()):
        line = raw_line.strip()
        if not line.startswith(_ATTESTATION_REPORT_PREFIX):
            continue
        try:
            payload = line.split(_ATTESTATION_REPORT_PREFIX, 1)[1].strip()
            obj = json.loads(payload)
        except (json.JSONDecodeError, IndexError, ValueError):
            return {}
        if isinstance(obj, dict):
            return _filter(obj)
    return {}


def _parse_legacy_labels(text: str) -> Dict[str, Any]:
    if not text:
        return {}
    out: Dict[str, Any] = {}
    for field, pattern in _HEX_FIELDS_RE.items():
        m = pattern.search(text)
        if m:
            out[field] = m.group(1).lower()
    for field, pattern in _INT_FIELDS_RE.items():
        m = pattern.search(text)
        if m:
            try:
                out[field] = int(m.group(1))
            except ValueError:
                pass
    return _filter(out)


def extract_attestation_report(*streams: str) -> Dict[str, Any]:
    """Best-effort extraction of structured attestation fields.

    Accepts an arbitrary number of text streams (typically stdout + stderr
    from the verifier).  The ATTESTATION_REPORT JSON line wins; legacy
    label regexes fill in any gaps when the client has not been migrated
    yet.  Always returns an allow-list filtered dict and never raises.
    """
    out: Dict[str, Any] = {}
    for s in streams:
        out.update(_parse_legacy_labels(s or ""))
    # ATTESTATION_REPORT JSON has the last word — overwrite legacy fields
    # because it is structured and signed against by the platform-specific
    # verifier path.
    for s in streams:
        out.update(_parse_attestation_report_line(s or ""))
    return out


def emit_att_verdicts(
    audit: Any,
    *,
    success: bool,
    evidence_pointer: str = "client_output.json",
    note: str = "",
    measurement_fields: Dict[str, Any] | None = None,
    pulses_seen: bool = True,
    tee_platform: str = "",
    baseline_pinned: bool | None = None,
) -> None:
    """Emit the ATT-001..010 verdict family from a per-platform client phase.

    Centralised so every platform's client wrapper records the same
    structured rows for the audit matrix.  Callers should pass
    ``success=True`` only after they have actually verified the
    attestation report (signature + measurement + nonce + issuer
    allowlist).  ATT-009 / ATT-010 only fire on GPU-CC platforms;
    they're derived from the NVIDIA NRAS evidence fields the GPU
    client embeds into the ATTESTATION_REPORT JSON.
    """
    if audit is None:
        return
    fields = measurement_fields or {}
    mp = fields.get("measurement_summary") or ", ".join(
        f"{k}={str(v)[:24]}" for k, v in fields.items() if isinstance(v, str)
    )
    if not tee_platform:
        # Read the BuildAuditTrail's tee_platform so the GPU-only
        # ATT-009 / ATT-010 rows fire even when the caller didn't
        # plumb the platform explicitly.
        tee_platform = (
            getattr(audit, "_tee_platform", "")
            or getattr(getattr(audit, "ledger", None), "tee_platform", "")
            or ""
        )
    issuer = fields.get("issuer") or ""
    spki = fields.get("spki_sha256") or ""
    nonce_bound = bool(fields.get("nonce") or fields.get("nonce_binding"))
    nras_kid = fields.get("nras_token_kid") or ""
    nras_eat = fields.get("nras_eat_digest") or ""
    nras_valid = fields.get("nras_token_valid")
    dual_cpu_gpu = nras_kid and (
        fields.get("measurement") or fields.get("mrtd")
        or fields.get("pcr0") or fields.get("rtmr0")
    )
    # Either the operator-supplied platform tag (BuildAuditTrail) or
    # the ``platform`` field the per-platform client wrote into the
    # ATTESTATION_REPORT can identify GPU-CC.
    is_gpu = (
        (tee_platform or "").startswith("gpu-cc")
        or str(fields.get("platform") or "").startswith("gpu-cc")
    )

    audit.record_check(
        "Phase 5: Post-Deploy", "Client received attestation report",
        "ATT-001",
        observed=bool(success), evidence_pointer=evidence_pointer,
        note=mp or note or "",
    )
    audit.record_check(
        "Phase 5: Post-Deploy", "Attestation signature / cert chain valid",
        "ATT-002",
        observed=bool(success), evidence_pointer=evidence_pointer,
    )
    # ATT-003 — measurement matches build baseline.  A successful client run
    # only proves the *runtime* measurement is internally consistent; it does
    # NOT prove it matched a pinned baseline if the client self-pinned (TOFU)
    # because the image shipped without a baked ``measurements.json``.  Surface
    # that honestly: WARN normally, hard FAIL when REQUIRE_PINNED_ENV is set.
    if success and baseline_pinned is False:
        from tee_crafter.core.audit import Verdict
        require_pinned = _truthy(os.environ.get(REQUIRE_PINNED_ENV))
        audit.record_check(
            "Phase 5: Post-Deploy", "Measurement matches build baseline",
            "ATT-003",
            verdict=Verdict.FAIL if require_pinned else Verdict.WARN,
            observed=False,
            evidence_pointer="measurements.json",
            note=(
                "client self-pinned the measurement (trust-on-first-use): no "
                "baseline was baked into the image at build time. Production "
                "deploys must ship a pinned measurements.json "
                f"(MRTD/MRENCLAVE/PCR/SNP-measurement); set {REQUIRE_PINNED_ENV}=1 "
                "to make this a hard failure."
            ),
        )
    else:
        audit.record_check(
            "Phase 5: Post-Deploy", "Measurement matches build baseline",
            "ATT-003",
            observed=bool(success), evidence_pointer="measurements.json",
            note="PCR / MRENCLAVE / MRTD / RTMR compared to baseline in measurements.json",
        )
    # ATT-004 — issuer in pinned allowlist.  When the client.py
    # validated the chain successfully and emitted an ``issuer``
    # field, we trust the verifier.  When success is True but the
    # field is absent (older client templates), we still record
    # PASS because the chain itself was verified — but with a note
    # so the auditor knows the issuer string was not surfaced.
    audit.record_check(
        "Phase 5: Post-Deploy", "Issuer in pinned allowlist", "ATT-004",
        observed=bool(success),
        evidence_pointer=evidence_pointer,
        note=(f"issuer={issuer}" if issuer
              else "verifier did not surface issuer string"),
    )
    audit.record_check(
        "Phase 5: Post-Deploy", "TCB / SVN >= floor (freshness)",
        "ATT-005",
        observed=bool(success), evidence_pointer=evidence_pointer,
    )
    audit.record_check(
        "Phase 5: Post-Deploy", "Nonce binding present in report",
        "ATT-006",
        observed=bool(success and nonce_bound) if success else False,
        evidence_pointer=evidence_pointer,
        note=("nonce field present in ATTESTATION_REPORT"
              if (success and nonce_bound)
              else "no nonce field in ATTESTATION_REPORT"),
    )
    audit.record_check(
        "Phase 5: Post-Deploy", "TLS SPKI sha256 captured", "ATT-007",
        observed=bool(spki) if success else False,
        evidence_pointer=evidence_pointer,
        note=(f"spki_sha256={spki[:16]}…" if spki else ""),
    )
    audit.record_check(
        "Phase 5: Post-Deploy", "Continuous-attestation pulses observed",
        "ATT-008",
        observed=bool(success and pulses_seen),
        evidence_pointer=evidence_pointer,
    )
    if is_gpu:
        # ATT-009 / ATT-010 only fire on GPU-CC platforms.  The
        # catalogue itself enforces ``platform_filter``; we still
        # gate the emission so non-GPU runs don't carry confusing
        # NRAS rows.
        from tee_crafter.core.audit import Verdict
        if nras_valid is False:
            verdict_nras = Verdict.FAIL
        elif nras_valid is True or (success and (nras_kid or nras_eat)):
            verdict_nras = Verdict.PASS
        else:
            verdict_nras = Verdict.WARN
        audit.record_check(
            "Phase 5: Post-Deploy", "nvAttest (NRAS) verdict valid",
            "ATT-009",
            verdict=verdict_nras,
            observed=bool(nras_valid is True
                          or (success and (nras_kid or nras_eat))),
            evidence_pointer=evidence_pointer,
            note=(f"kid={nras_kid[:12]}… eat={nras_eat[:12]}…"
                  if (nras_kid or nras_eat)
                  else "no NRAS fields in ATTESTATION_REPORT"),
        )
        audit.record_check(
            "Phase 5: Post-Deploy", "Dual-attestation CPU+GPU bound",
            "ATT-010",
            observed=bool(dual_cpu_gpu and success),
            evidence_pointer=evidence_pointer,
            note=("CPU measurement + NRAS token both present in report"
                  if dual_cpu_gpu else
                  "CPU TEE measurement and NRAS token not both surfaced"),
        )
