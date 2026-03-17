"""Build Provenance Audit Trail for TEE-Crafter.

Produces a hash-chained, tamper-evident record of every security-relevant
action taken during the build/deploy pipeline.  The trail is saved to the
build directory so the client can independently verify that every signature,
hash, and security mechanism was in place for their enclave.
"""
from __future__ import annotations

import datetime
import json
import os
import platform
from dataclasses import asdict
from typing import Any, Dict, List, Optional  # noqa: F401 — Optional used in verify_signature

from tee_crafter.core.audit.helpers import (  # noqa: F401 – re-exports
    sha256_hex, sha256_file, _sanitize_details, ENCLAVE_TCB_SUBSTEPS, AuditEntry,
)
from tee_crafter.core.audit.report import (
    write_summary as _write_summary,
    parse_enclave_startup_report as _parse_enclave_startup_report,
    verify_chain as _verify_chain,
)
from tee_crafter.core.audit.checks import (
    CHECKS as _CHECKS,
    Verdict as _Verdict,
    derive_verdict as _derive_verdict,
)
from tee_crafter.core.audit.ledger import AuditEvidenceLedger


class BuildAuditTrail:
    """Accumulates a hash-chained sequence of :class:`AuditEntry` records."""

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._head_hash: str = "0" * 64
        self._start_time = datetime.datetime.utcnow().isoformat() + "Z"
        self._pipeline_version: str = ""
        self._build_dir: str = ""
        self._ledger: AuditEvidenceLedger = AuditEvidenceLedger()
        self._tee_platform: str = ""

    def set_metadata(self, pipeline_version: str, build_dir: str) -> None:
        self._pipeline_version = pipeline_version
        self._build_dir = build_dir
        # PC-003 / PC-004 — emit two cheap "the pipeline is up"
        # evidence rows so the catalogue's PC bucket always has
        # something visible even on flows that fail early (e.g.
        # invalid args).  build_dir of "(pending)" is the deploy
        # sentinel — skip the writable probe for it.
        try:
            from tee_crafter.core.audit.checks import (
                CHECKS as _CHECKS,
                Verdict as _Verdict,
            )
            writable = False
            note = ""
            if build_dir and build_dir != "(pending)":
                try:
                    import os as _os
                    _os.makedirs(build_dir, exist_ok=True)
                    writable = _os.access(build_dir, _os.W_OK)
                    note = f"path={build_dir}"
                except Exception as exc:
                    note = f"{type(exc).__name__}: {exc}"
            if "PC-003" in _CHECKS:
                self.record_check(
                    "Pipeline Config", "build_dir writable", "PC-003",
                    observed=bool(writable) if build_dir != "(pending)" else None,
                    verdict=(
                        _Verdict.PASS if writable
                        else (_Verdict.INFO if build_dir == "(pending)"
                              else _Verdict.FAIL)
                    ),
                    note=note,
                )
            if "PC-004" in _CHECKS:
                cli_version = pipeline_version or "unknown"
                self.record_check(
                    "Pipeline Config", "cli version recorded", "PC-004",
                    observed=cli_version,
                    verdict=_Verdict.INFO,
                )
        except Exception:
            # Never let an audit helper abort pipeline initialisation.
            pass

    def set_tee_platform(self, tee_platform: str) -> None:
        """Tag every subsequent ledger row with *tee_platform*."""
        self._tee_platform = tee_platform or ""
        self._ledger.set_tee_platform(self._tee_platform)

    @property
    def ledger(self) -> AuditEvidenceLedger:
        """Return the structured pass/fail evidence ledger sibling."""
        return self._ledger

    def record(
        self,
        phase: str,
        step: str,
        status: str,
        **details: Any,
    ) -> AuditEntry:
        """Append a new entry to the chain and return it.

        Recognised "audit-aware" keyword arguments — ``check_id``,
        ``expected``, ``observed``, ``evidence_pointer`` — are *also*
        stored verbatim in the entry's details (so the trail's TXT
        renderer continues to surface them) AND, when ``check_id`` is
        provided, paired into the embedded :class:`AuditEvidenceLedger`
        as a structured verdict row.

        The verdict is derived from ``expected``/``observed`` unless
        ``status`` itself is already an authoritative verdict label
        (``fail`` / ``warn`` are always honoured as-is so phases can
        emit early-failure rows without a paired observation).
        """
        check_id = details.pop("check_id", None)
        expected = details.pop("expected", None) if "expected" in details else None
        observed = details.pop("observed", None) if "observed" in details else None
        evidence_pointer = details.pop("evidence_pointer", "") if "evidence_pointer" in details else ""

        trail_details: Dict[str, Any] = dict(details)
        if check_id:
            trail_details.setdefault("check_id", check_id)
        if expected is not None:
            trail_details.setdefault("expected", expected)
        if observed is not None:
            trail_details.setdefault("observed", observed)
        if evidence_pointer:
            trail_details.setdefault("evidence_pointer", evidence_pointer)

        entry = AuditEntry(
            seq=len(self._entries),
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            phase=phase, step=step, status=status,
            details=_sanitize_details(trail_details),
            prev_hash=self._head_hash,
        )
        self._head_hash = entry.digest()
        self._entries.append(entry)

        if check_id:
            mapped = _Verdict.from_status(status)
            # Only auto-derive when caller did NOT already pin an
            # authoritative verdict.  ``fail`` / ``warn`` / ``skip``
            # (``not_applicable``) / ``info`` are explicit operator
            # statements and must not be silently flipped by the
            # expected/observed pair (which the caller may only have
            # supplied for the trail row's display).  ``pass`` is the
            # default fall-through used by older call-sites that
            # rely on derivation, so we still honour the derivation
            # in that case.
            if (
                (expected is not None or observed is not None)
                and status == "pass"
            ):
                mapped = _derive_verdict(expected, observed)
            ledger_extra = {
                k: v for k, v in entry.details.items()
                if k not in {"check_id", "expected", "observed",
                             "evidence_pointer", "note"}
            }
            self._ledger.record_check(
                check_id,
                verdict=mapped,
                expected=expected,
                observed=observed,
                source_seq=entry.seq,
                evidence_pointer=evidence_pointer,
                note=details.get("note", ""),
                **ledger_extra,
            )
        return entry

    def record_check(
        self,
        phase: str,
        step: str,
        check_id: str,
        *,
        expected: Any = None,
        observed: Any = None,
        evidence_pointer: str = "",
        note: str = "",
        verdict: Optional[_Verdict] = None,
        **details: Any,
    ) -> AuditEntry:
        """Atomically record one chain entry *and* one ledger row.

        The chain status is derived from the verdict so the existing
        ``[✓]/[✗]/[!]/[○]`` rendering in ``build_provenance.txt`` stays
        meaningful.  ``record_check`` is the preferred call site for
        every production gate.
        """
        spec = _CHECKS.get(check_id)
        if spec is not None and expected is None:
            expected = spec.default_expected
        if verdict is None:
            v = _derive_verdict(expected, observed)
        elif isinstance(verdict, _Verdict):
            v = verdict
        else:
            v = _Verdict.from_status(str(verdict))
        status_map = {
            _Verdict.PASS: "pass",
            _Verdict.FAIL: "fail",
            _Verdict.WARN: "warn",
            _Verdict.NOT_APPLICABLE: "skip",
            _Verdict.INFO: "info",
        }
        status = status_map[v]
        return self.record(
            phase, step, status,
            check_id=check_id,
            expected=expected,
            observed=observed,
            evidence_pointer=evidence_pointer,
            note=note,
            **details,
        )

    def record_file_hash(self, phase: str, step: str, filepath: str, *, label: str = "") -> AuditEntry:
        """Record the SHA-256 digest of *filepath*."""
        digest = sha256_file(filepath)
        return self.record(phase, step, "pass" if digest else "fail",
                           file=os.path.basename(filepath), sha256=digest,
                           label=label or os.path.basename(filepath))

    def record_hash_value(self, phase: str, step: str, content: str, *, label: str = "") -> AuditEntry:
        """Record the SHA-256 digest of an in-memory string."""
        return self.record(phase, step, "pass", sha256=sha256_hex(content), label=label)

    def record_enclave_tcb_substeps(self, template_sha256: str, *,
                                     phase: str = "Enclave TCB") -> None:
        """Record all template-guaranteed enclave security substeps."""
        for sub in ENCLAVE_TCB_SUBSTEPS:
            self.record(phase, sub["name"], "pass",
                        substep_id=sub["id"], category=sub["category"],
                        template_sha256=template_sha256)

    def record_enclave_runtime_startup(self, steps: List[str], *,
                                        phase: str = "Enclave Runtime",
                                        status: str = "pass") -> AuditEntry:
        """Record the enclave-reported startup steps."""
        return self.record(phase, "Enclave startup report (from console)", status,
                           reported_steps=steps, step_count=len(steps))

    def record_batch_run(
        self,
        *,
        mode: str,
        platform: str,
        input_bundle_sha256: str = "",
        output_bundle_sha256: str = "",
        exit_code: int = 0,
        duration_sec: float = 0.0,
        captured_file_count: int = 0,
        captured_bytes: int = 0,
        boot_attestation_sha256: str = "",
        batch_entrypoint: str = "",
        status: str = "pass",
        **extra: Any,
    ) -> AuditEntry:
        """Record one batch-mode run (mode A 'container' or mode B 'entrypoint').

        Batch mode replaces per-request RA-TLS with a deterministic build/run
        provenance: SHA-256 over the uploaded input bundle, SHA-256 over the
        captured output bundle, the user command's exit code, and how much
        data the runner actually managed to capture.  The verifier of
        ``build_provenance.json`` can re-derive the same SHAs from the local
        copies and prove the bundle they have matches the one the TEE produced.
        """
        return self.record(
            "Batch Run", f"batch_{mode}", status,
            platform=platform,
            input_bundle_sha256=input_bundle_sha256,
            output_bundle_sha256=output_bundle_sha256,
            exit_code=int(exit_code),
            duration_sec=round(float(duration_sec), 3),
            captured_file_count=int(captured_file_count),
            captured_bytes=int(captured_bytes),
            boot_attestation_sha256=boot_attestation_sha256,
            batch_entrypoint=batch_entrypoint,
            **extra,
        )

    def _build_document(self) -> Dict[str, Any]:
        # Resolve the tee_platform tag from the embedded ledger (set
        # via ``set_tee_platform``) so downstream verifiers (e.g.
        # ``verify-provenance --required-checks auto``) can determine
        # which per-platform required-check list to apply WITHOUT
        # having to also load the sibling audit_evidence.json.
        tee_platform = self._tee_platform or ""
        if not tee_platform:
            # Best-effort fallback: an early ``Pipeline initialized``
            # entry usually carries ``tee_platform=...`` in details.
            for entry in self._entries:
                d = entry.details if isinstance(entry.details, dict) else {}
                tp = d.get("tee_platform") or d.get("platform")
                if isinstance(tp, str) and tp:
                    tee_platform = tp
                    break
        return {
            "audit_trail_version": "1.0",
            "pipeline_version": self._pipeline_version,
            "tee_platform": tee_platform,
            "build_dir": self._build_dir,
            "started_at": self._start_time,
            "finished_at": datetime.datetime.utcnow().isoformat() + "Z",
            "host_platform": platform.platform(),
            "python_version": platform.python_version(),
            "total_entries": len(self._entries),
            "chain_head_hash": self._head_hash,
            "entries": [asdict(e) for e in self._entries],
        }

    def save(self, build_dir: str) -> str:
        """Write ``build_provenance.json`` and its Ed25519 signature.

        Signing uses :func:`tee_crafter.core.audit.signing.load_signing_key`,
        which honours operator-controlled long-lived keys (env var, file,
        or OS keyring) and only falls back to an ephemeral per-build
        keypair when ``TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL=1`` is set.

        Emits four files alongside the JSON trail:
          * ``build_provenance.sig``           — hex-encoded Ed25519 sig
          * ``build_provenance.pub``           — PEM-encoded public key
          * ``build_provenance.pub.sha256``    — SPKI-SHA256 fingerprint
          * ``build_provenance.key_kind.txt``  — ``longlived`` or ``ephemeral``
            plus the resolved source (env / keyring / file / generated).

        Production verifiers pass ``--pinned-pubkey-sha256 <hex>`` to
        ``tee-crafter verify-provenance`` to require the fingerprint they
        committed to in their audit policy.
        """
        self._build_dir = build_dir
        from tee_crafter.core.audit import build_layout as _layout
        _layout.ensure_dirs(build_dir)
        doc = self._build_document()
        path = _layout.provenance_json(build_dir)

        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")

        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)

        signing_ok = False
        signing_error: Optional[str] = None
        try:
            from tee_crafter.core.audit.signing import (
                load_signing_key,
                public_key_fingerprint,
                public_key_pem,
            )

            loaded = load_signing_key()
            signature = loaded.key.sign(canonical)
            pub_key = loaded.key.public_key()
            pub_pem = public_key_pem(pub_key)
            fingerprint = public_key_fingerprint(pub_key)

            sig_path = _layout.provenance_sig(build_dir)
            pub_path = _layout.provenance_pub(build_dir)
            fpr_path = _layout.provenance_pub_fpr(build_dir)
            kind_path = _layout.provenance_key_kind(build_dir)
            with open(sig_path, "w", encoding="utf-8") as f:
                f.write(signature.hex())
            with open(pub_path, "wb") as f:
                f.write(pub_pem)
            with open(fpr_path, "w", encoding="utf-8") as f:
                f.write(fingerprint + "\n")
            with open(kind_path, "w", encoding="utf-8") as f:
                f.write(f"{loaded.kind}\nsource={loaded.source}\n")
            signing_ok = True
        except Exception as exc:
            # Surface the failure loudly: provenance is intentionally
            # signed by default and a silent fallback to an unsigned
            # JSON would defeat the whole audit trail.  We write
            # ``build_provenance.signing_error.txt`` so the operator
            # sees what to do and the SaaS / CI orchestrator can
            # surface a structured warning in the deploy summary.
            signing_error = f"{type(exc).__name__}: {exc}"
            try:
                err_path = _layout.provenance_signing_error(build_dir)
                with open(err_path, "w", encoding="utf-8") as f:
                    f.write(
                        "TEE-Crafter provenance signing FAILED.\n\n"
                        f"Reason: {signing_error}\n\n"
                        "Remediation (pick one):\n"
                        "  • tee-crafter audit-gen-signing-key   # bootstrap\n"
                        "    a long-lived Ed25519 key at\n"
                        "    ~/.tee-crafter/provenance-signing-key.pem (0600).\n"
                        "  • export TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE=\n"
                        "      /path/to/provenance-signing-key.pem\n"
                        "  • export TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL=1\n"
                        "      (development only; ephemeral keys are\n"
                        "       refused by --require-longlived).\n\n"
                        "Until this is fixed, every build emits an\n"
                        "UNSIGNED build_provenance.json and skips SLSA\n"
                        "(SIEM-SEC-6) emission entirely.\n")
            except OSError:
                pass
            try:
                import logging
                logging.getLogger("tee_crafter.audit").error(
                    "Provenance signing failed (%s) — build provenance was "
                    "written UNSIGNED to %s.  See "
                    "build_provenance.signing_error.txt for remediation.",
                    signing_error, path)
            except Exception:
                pass
            # Best-effort echo to the CLI console used by the deploy
            # pipeline — surfaces above the spinner-driven status lines.
            try:
                from tee_crafter.cli.constants import console
                console.print(
                    "[bold red]Provenance signing FAILED[/bold red]: "
                    f"{signing_error}\n"
                    "[yellow]→ Run `tee-crafter audit-gen-signing-key`, "
                    "or export "
                    "`TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE=...`, "
                    "or set `TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL=1` "
                    "for dev runs.[/yellow]\n"
                    "[dim]Until then SLSA Provenance v1 (SIEM-SEC-6) is "
                    "skipped and `build_provenance.json` is unsigned.[/dim]")
            except Exception:
                pass

        # SIEM-SEC-6: emit a parallel SLSA Provenance v1 (in-toto +
        # DSSE) artifact so downstream `slsa-verifier` / `cosign
        # attest --type slsaprovenance` / Kyverno / Sigstore
        # policy-controller can ingest the build provenance in the
        # standard format.  Best-effort: never fail the build if the
        # SLSA emission cannot complete.  Skipped entirely when
        # provenance signing already failed — emitting an unsigned
        # SLSA statement would be misleading to verifiers.
        if signing_ok:
            try:
                from tee_crafter.core.audit.slsa import (
                    emit_attestation as _emit_slsa,
                )
                tee_platform = ""
                for entry in self._entries:
                    d = entry.details if isinstance(entry.details, dict) else {}
                    tp = d.get("tee_platform") or d.get("platform")
                    if isinstance(tp, str) and tp:
                        tee_platform = tp
                        break
                _emit_slsa(
                    build_dir=build_dir,
                    tee_platform=tee_platform or "unknown",
                    build_config={
                        "pipeline_version": self._pipeline_version,
                        "chain_head_hash": self._head_hash,
                        "total_entries": len(self._entries),
                    },
                    started_at=self._start_time,
                )
            except Exception as exc:
                # SLSA-specific failure (e.g. cryptography backend
                # missing).  Native provenance is already signed, so
                # surface but don't tear the build down.
                try:
                    from tee_crafter.cli.constants import console
                    console.print(
                        "[yellow]SLSA Provenance v1 emission skipped: "
                        f"{type(exc).__name__}: {exc}[/yellow]")
                except Exception:
                    pass

        return os.path.abspath(path)

    def save_summary(self, build_dir: str) -> str:
        """Write a human-readable summary alongside the JSON trail."""
        doc = self._build_document()
        ledger_doc = self._ledger.build_document() if self._ledger.rows else None
        return _write_summary(self._entries, doc, build_dir, ledger_doc)

    @staticmethod
    def parse_enclave_startup_report(console_output: str) -> Optional[List[str]]:
        """Parse enclave stdout for startup report JSON line."""
        return _parse_enclave_startup_report(console_output)

    @staticmethod
    def verify_chain(provenance_path: str) -> tuple[bool, str]:
        """Re-compute every hash in a saved provenance file and confirm chain integrity."""
        return _verify_chain(provenance_path)

    @staticmethod
    def verify_signature(
        provenance_path: str,
        *,
        pinned_pubkey_sha256: Optional[str] = None,
        require_longlived: bool = False,
    ) -> tuple[bool, str]:
        """Verify the Ed25519 signature of a provenance file.

        Expects ``build_provenance.sig`` and ``build_provenance.pub`` next
        to the JSON file.  When *pinned_pubkey_sha256* is provided, also
        require the SHA-256 of the public key's SPKI-DER encoding to match
        the pinned value — this is what production verifiers use to prove
        the build was signed by the operator's audit key, not a forgery.

        When *require_longlived* is True, refuse signatures emitted by an
        ephemeral per-build keypair (i.e. ``build_provenance.key_kind.txt``
        must read ``longlived``).  Production CI should set both.
        """
        from tee_crafter.core.audit import build_layout as _layout
        # ``provenance_path`` may live in either layout — fall back to the
        # parent dir of the JSON file so both the new ``provenance/`` subdir
        # and legacy top-level layouts resolve identically.
        prov_dir = os.path.dirname(provenance_path)
        build_dir = (os.path.dirname(prov_dir)
                     if os.path.basename(prov_dir) == _layout.PROVENANCE_DIR
                     else prov_dir)
        sig_path = _layout.resolve_provenance_sig(build_dir)
        pub_path = _layout.resolve_provenance_pub(build_dir)

        if not os.path.isfile(sig_path) or not os.path.isfile(pub_path):
            return False, "Signature or public key file not found"

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives import serialization
            from tee_crafter.core.audit.signing import public_key_fingerprint

            with open(provenance_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")

            with open(sig_path, "r", encoding="utf-8") as f:
                signature = bytes.fromhex(f.read().strip())
            with open(pub_path, "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())

            if not isinstance(pub_key, Ed25519PublicKey):
                return False, "Public key is not Ed25519"
            pub_key.verify(signature, canonical)

            if pinned_pubkey_sha256:
                actual = public_key_fingerprint(pub_key)
                if actual.lower() != pinned_pubkey_sha256.strip().lower():
                    return False, (
                        f"Public-key fingerprint mismatch: "
                        f"build={actual}, pinned={pinned_pubkey_sha256}. "
                        f"This build was signed by a different key than the "
                        f"one pinned in your audit policy."
                    )

            if require_longlived:
                kind_path = _layout.resolve_provenance_key_kind(build_dir)
                kind_label = ""
                if os.path.isfile(kind_path):
                    try:
                        with open(kind_path, "r", encoding="utf-8") as f:
                            kind_label = f.readline().strip().lower()
                    except OSError:
                        kind_label = ""
                if kind_label != "longlived":
                    return False, (
                        f"Signature key kind is '{kind_label or 'unknown'}'; "
                        f"production verifiers require 'longlived'. Configure "
                        f"a persistent signing key (TEE_CRAFTER_PROVENANCE_"
                        f"SIGNING_KEY / _FILE / keyring) before signing."
                    )

            return True, ""
        except Exception as exc:
            return False, str(exc)
