"""Audit trail persistence helpers."""

import logging
import os
from typing import Tuple


from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.constants import Console, Panel

logger = logging.getLogger("tee_crafter.audit_helpers")


def _generate_compliance_reports(json_path: str, build_dir: str) -> str | None:
    """Generate the compliance/ directory from a provenance file.

    Returns the compliance directory path, or None on failure.
    """
    try:
        from tee_crafter.core.compliance.engine import ComplianceEngine
        engine = ComplianceEngine(provenance_path=json_path)
        return engine.generate_report(build_dir)
    except Exception as exc:
        logger.warning("Compliance report generation failed: %s", exc)
        return None


def _signing_status(build_dir: str) -> tuple[str, str]:
    """Return ``(headline, detail)`` describing the provenance signing state.

    Inspects sidecars written by :meth:`BuildAuditTrail.save` to tell the
    operator which artefacts landed and which (if any) failed.  Output
    is rendered into the CLI panel so a missing SLSA file no longer
    looks like a no-op.
    """
    from tee_crafter.core.audit import build_layout as _layout
    sig_present = os.path.isfile(_layout.resolve_provenance_sig(build_dir))
    err_path = _layout.provenance_signing_error(build_dir)
    err_path_legacy = os.path.join(
        build_dir, "build_provenance.signing_error.txt")
    err_present = os.path.isfile(err_path) or os.path.isfile(err_path_legacy)
    slsa_present = os.path.isfile(_layout.resolve_slsa_intoto(build_dir))
    if sig_present and slsa_present:
        fpr_path = _layout.resolve_provenance_pub_fpr(build_dir)
        fpr = ""
        try:
            with open(fpr_path, "r", encoding="utf-8") as f:
                fpr = f.read().strip()[:16] + "…"
        except OSError:
            fpr = "(fingerprint sidecar missing)"
        return (
            "[green]Signed (Ed25519) + SLSA Provenance v1 emitted[/green]",
            f"  Key fingerprint: {fpr}\n"
            f"  SLSA: {_layout.EVIDENCE_SLSA_INTOTO} + "
            f"{_layout.EVIDENCE_SLSA_DSSE}",
        )
    if sig_present and not slsa_present:
        return (
            "[yellow]Signed but SLSA emission skipped[/yellow]",
            "  See deploy log for the SLSA-specific reason "
            "(usually a missing cryptography backend).",
        )
    if err_present:
        shown = err_path if os.path.isfile(err_path) else err_path_legacy
        return (
            "[bold red]UNSIGNED provenance — signing FAILED[/bold red]",
            f"  See {shown} for remediation\n"
            "  → `tee-crafter audit-gen-signing-key` is the usual fix.",
        )
    return (
        "[bold red]UNSIGNED provenance[/bold red]",
        "  No signing sidecars were produced and no error file is "
        "present;\n  the audit module silently lost the signing key. "
        "Investigate.",
    )


def _record_provenance_self_checks(audit: BuildAuditTrail, build_dir: str) -> None:
    """Add the PROV-* / PC-008 / PC-009 ledger rows describing the artefacts
    that ``audit.save()`` just produced."""
    from tee_crafter.core.audit import build_layout as _layout

    sig_path = _layout.resolve_provenance_sig(build_dir)
    pub_path = _layout.resolve_provenance_pub(build_dir)
    sig_present = os.path.isfile(sig_path)
    pub_present = os.path.isfile(pub_path)
    kind_path = _layout.resolve_provenance_key_kind(build_dir)
    kind = ""
    if os.path.isfile(kind_path):
        try:
            with open(kind_path, "r", encoding="utf-8") as f:
                kind = f.readline().strip().lower()
        except OSError:
            kind = ""

    audit.record_check(
        "Phase 6: Provenance", "Provenance signing key kind",
        "PROV-001",
        observed=kind or "missing",
        evidence_pointer=_layout.EVIDENCE_PROVENANCE_KEY_KIND,
    )
    audit.record_check(
        "Phase 6: Provenance", "build_provenance.sig present",
        "PROV-002",
        observed=bool(sig_present and pub_present),
        evidence_pointer=_layout.EVIDENCE_PROVENANCE_SIG,
    )
    audit.record_check(
        "Phase 6: Provenance", "Signing key kind == longlived",
        "PC-006",
        observed=kind or "missing",
        evidence_pointer=_layout.EVIDENCE_PROVENANCE_KEY_KIND,
    )
    audit.record_check(
        "Phase 6: Provenance", "Provenance signing succeeded",
        "PC-007",
        observed=bool(sig_present),
        evidence_pointer=_layout.EVIDENCE_PROVENANCE_SIG,
    )

    slsa_present = os.path.isfile(_layout.resolve_slsa_intoto(build_dir))
    dsse_present = os.path.isfile(_layout.resolve_slsa_dsse(build_dir))
    audit.record_check(
        "Phase 6: Provenance", "SLSA in-toto attestation present",
        "PROV-004",
        observed=bool(slsa_present),
        evidence_pointer=_layout.EVIDENCE_SLSA_INTOTO,
    )
    audit.record_check(
        "Phase 6: Provenance", "DSSE envelope present",
        "PROV-005",
        observed=bool(dsse_present),
        evidence_pointer=_layout.EVIDENCE_SLSA_DSSE,
    )

    json_path = _layout.resolve_provenance_json(build_dir)
    chain_ok, _ = (
        BuildAuditTrail.verify_chain(json_path)
        if os.path.isfile(json_path) else (False, "")
    )
    audit.record_check(
        "Phase 6: Provenance", "Hash chain verifies",
        "PROV-006",
        observed=bool(chain_ok),
        evidence_pointer=_layout.EVIDENCE_PROVENANCE_JSON,
    )
    audit.record_check(
        "Phase 6: Provenance", "Hash chain integrity",
        "PC-008",
        observed=bool(chain_ok),
        evidence_pointer=_layout.EVIDENCE_PROVENANCE_JSON,
    )


def _sweep_missing_required_checks(audit: BuildAuditTrail) -> None:
    """Emit a ``WARN`` row for every required-check the build did not
    produce.

    Without this sweep, ``verify-provenance --required-checks auto``
    would silently degrade to "all required rows missing → fail" with
    no per-row evidence pointer.  The sweep guarantees that the audit
    matrix always tells the operator exactly which gates were skipped
    (probe couldn't run, cloud-audit call lacked IAM permission, …)
    so the remediation hint in the CheckSpec is surfaced.
    """
    if audit is None:
        return
    try:
        from tee_crafter.core.audit.checks import (
            CHECKS, Verdict, required_checks_for,
        )
    except Exception:
        return
    tee_platform = getattr(audit, "_tee_platform", "") or ""
    required = required_checks_for(tee_platform)
    for cid in required:
        if audit.ledger.has(cid):
            continue
        spec = CHECKS.get(cid)
        if spec is None:
            continue
        audit.record_check(
            "Phase 6: Provenance",
            spec.title,
            cid,
            verdict=Verdict.WARN,
            observed=None,
            note=("evidence not collected during this build — "
                  f"source={spec.source_kind.value}; "
                  f"remediation={spec.remediation or 'see docs/audit_matrix.md'}"),
        )


def _save_ledger(audit: BuildAuditTrail, build_dir: str) -> Tuple[bool, str]:
    """Persist + sign ``audit_evidence.{json,txt,md,html,sig}``.

    Returns ``(signed_ok, json_path_or_empty)``.
    """
    if not audit.ledger.rows:
        return False, ""
    # Surface gaps in the required-check coverage BEFORE we persist
    # so the rendered matrix tells the operator which gates were
    # skipped instead of silently dropping them.
    _sweep_missing_required_checks(audit)
    paths = audit.ledger.save(build_dir)
    sig_path = audit.ledger.sign(build_dir)
    # PC-009 / PROV-007 are emitted post-save so we can prove they
    # actually landed.  These are appended to the trail *and* the
    # ledger but won't appear in the rendered audit_evidence.json we
    # just wrote — that's the trade-off of "self-attesting" rows.
    # The next save() rewrites with both visible.
    audit.record_check(
        "Phase 6: Provenance", "Audit ledger emitted",
        "PC-009",
        observed=True,
        evidence_pointer=os.path.basename(paths.get("json", "")),
    )
    audit.record_check(
        "Phase 6: Provenance", "Ledger emitted + signed",
        "PROV-007",
        observed=bool(sig_path),
        evidence_pointer=os.path.basename(paths.get("json", "")),
    )
    # Re-save so PC-009 / PROV-007 are visible in the final artefact.
    audit.ledger.save(build_dir)
    audit.ledger.sign(build_dir)
    return bool(sig_path), paths.get("json", "")


def _emit_pipeline_teardown_verdicts(
    audit: BuildAuditTrail, *, build_dir: str, teardown_ok: bool | None,
) -> None:
    """Emit TEAR-002 / TEAR-005 / TEAR-006 from pipeline-side evidence."""
    if audit is None or not build_dir:
        return
    from tee_crafter.core.audit import Verdict

    shred_manifest = os.path.join(build_dir, "post_destroy_shred_manifest.txt")
    if teardown_ok is True:
        audit.record_check(
            "Phase 5: Post-Deploy",
            "Post-destroy shred manifest present",
            "TEAR-002",
            observed=os.path.isfile(shred_manifest),
            evidence_pointer="post_destroy_shred_manifest.txt",
            note="suppressed via TEE_CRAFTER_SKIP_POST_DESTROY_SHRED"
                 if not os.path.isfile(shred_manifest) else "",
        )
    else:
        audit.record_check(
            "Phase 5: Post-Deploy", "Post-destroy shred manifest present",
            "TEAR-002",
            verdict=Verdict.NOT_APPLICABLE, observed=False,
            note="teardown not run or failed; no shred performed",
        )

    docker_prune = os.path.join(build_dir, "docker_prune_summary.txt")
    if teardown_ok is True:
        audit.record_check(
            "Phase 5: Post-Deploy", "Local docker prune ran", "TEAR-005",
            observed=os.path.isfile(docker_prune),
            evidence_pointer="docker_prune_summary.txt",
        )
    else:
        audit.record_check(
            "Phase 5: Post-Deploy", "Local docker prune ran", "TEAR-005",
            verdict=Verdict.NOT_APPLICABLE, observed=False,
            note="teardown not requested or failed",
        )

    secret_hits: list[str] = []
    try:
        suspicious = (
            "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
        )
        for root, _, files in os.walk(build_dir):
            if any(
                p in root for p in ("/post_destroy_shred", "/__pycache__")
            ):
                continue
            for fn in files:
                p = os.path.join(root, fn)
                if any(s in fn.lower() for s in (
                    ".pem", "_rsa", "_ed25519", "id_dsa",
                )):
                    secret_hits.append(os.path.relpath(p, build_dir))
                    continue
                try:
                    if os.path.getsize(p) > 256 * 1024:
                        continue
                    with open(p, "rb") as fh:
                        chunk = fh.read(8192)
                    text = chunk.decode("utf-8", "ignore")
                    if any(needle in text for needle in suspicious):
                        secret_hits.append(os.path.relpath(p, build_dir))
                except Exception:
                    continue
            if len(secret_hits) > 20:
                break
    except Exception:
        pass
    audit.record_check(
        "Phase 5: Post-Deploy",
        "Build dir contains no key material",
        "TEAR-006",
        observed=not secret_hits,
        evidence_pointer=", ".join(secret_hits[:5]) if secret_hits else "",
        note=(
            f"{len(secret_hits)} suspicious file(s) found"
            if secret_hits else "no PEM / OpenSSH markers detected"
        ),
    )


def _tear_sweep_commands(tee_platform: str) -> tuple[str, str]:
    """Return ``(kms_cmd, firewall_cmd)`` for the operator to verify.

    Each TEE-Crafter deployment lives in exactly one cloud, so the
    follow-up sweep commands must reflect that cloud's CLI — not AWS's
    in every case.  Used by TEAR-003 / TEAR-004 row notes.
    """
    plat = (tee_platform or "").lower()
    if plat.endswith("-azure"):
        return (
            "az keyvault list -o table",
            "az network nsg list -o table",
        )
    if plat.endswith("-gcp"):
        return (
            "gcloud kms keys list --location=<region> --keyring=<kr>",
            "gcloud compute firewall-rules list",
        )
    return (
        "aws kms list-aliases",
        "aws ec2 describe-security-groups",
    )


def emit_teardown_and_cloud_audit(
    audit: BuildAuditTrail,
    *,
    tee_platform: str,
    teardown_ok: bool | None,
    teardown_msg: str = "",
    outputs: dict | None = None,
    build_dir: str | None = None,
) -> None:
    """Emit TEAR-001 + CT-* verdicts in one call.

    Called from each per-platform phase right before
    :func:`save_audit_trail`.  Safe to call with ``teardown_ok=None``
    (meaning "no teardown was performed in this build"); the TEAR-001
    row is then emitted as ``not_applicable``.
    """
    if audit is None:
        return
    from tee_crafter.core.audit import Verdict
    if teardown_ok is None:
        audit.record_check(
            "Phase 5: Post-Deploy", "terraform destroy success", "TEAR-001",
            verdict=Verdict.NOT_APPLICABLE,
            observed=False,
            note="--teardown not requested",
        )
    else:
        audit.record_check(
            "Phase 5: Post-Deploy", "terraform destroy success", "TEAR-001",
            observed=bool(teardown_ok),
            note=teardown_msg[:200],
        )
    if build_dir:
        _emit_pipeline_teardown_verdicts(
            audit, build_dir=build_dir, teardown_ok=teardown_ok,
        )
    kms_sweep_cmd, fw_sweep_cmd = _tear_sweep_commands(tee_platform)
    audit.record_check(
        "Phase 6: Cloud audit",
        "No orphaned KMS aliases (cloud sweep)",
        "TEAR-003",
        verdict=Verdict.WARN, observed=False,
        note=("Operator must run platform-specific resource sweep "
              f"({kms_sweep_cmd}) to confirm."),
    )
    audit.record_check(
        "Phase 6: Cloud audit",
        "No orphaned security groups (cloud sweep)",
        "TEAR-004",
        verdict=Verdict.WARN, observed=False,
        note=("Operator must run platform-specific resource sweep "
              f"({fw_sweep_cmd}) to confirm."),
    )
    try:
        from tee_crafter.cli.deployment.common.cloud_audit import (
            record_cloud_audit_verdicts,
        )
        outputs = outputs or {}
        record_cloud_audit_verdicts(
            audit, tee_platform=tee_platform,
            aws_instance_id=outputs.get("instance_id", "") or "",
            azure_resource_group=outputs.get("resource_group", "") or "",
            gcp_project=outputs.get("project", "") or "",
            build_dir=build_dir or "",
            terraform_outputs=outputs,
        )
    except Exception:
        pass


def save_audit_trail(audit: BuildAuditTrail, build_dir: str, console: Console) -> None:
    """Persist the audit trail as JSON + human-readable summary + compliance reports."""
    json_path = audit.save(build_dir)
    _record_provenance_self_checks(audit, build_dir)
    ledger_signed, ledger_path = _save_ledger(audit, build_dir)
    txt_path = audit.save_summary(build_dir)
    # Re-save the JSON trail one final time so the ledger self-checks
    # (PROV-001..007 + PC-006..009) and any caller-deferred records
    # land in build_provenance.json too.  This second save also
    # recomputes the Ed25519 signature, so the txt / json pair stay
    # consistent.
    json_path = audit.save(build_dir)
    audit.save_summary(build_dir)
    compliance_dir = _generate_compliance_reports(json_path, build_dir)
    compliance_line = (
        f"\n[cyan]Compliance:[/cyan]  {compliance_dir}/"
        if compliance_dir else ""
    )
    headline, detail = _signing_status(build_dir)
    ledger_line = ""
    if ledger_path:
        ledger_state = (
            "[green]signed[/green]" if ledger_signed
            else "[yellow]unsigned (see audit_evidence.signing_error.txt)[/yellow]"
        )
        ledger_line = (
            f"\n[cyan]Audit ledger:[/cyan]  {ledger_path}  ({ledger_state})"
        )
    console.print(Panel(
        f"[cyan]JSON:[/cyan]  {json_path}\n"
        f"[cyan]Text:[/cyan]  {txt_path}"
        f"{ledger_line}"
        f"{compliance_line}\n"
        f"[cyan]Signing:[/cyan]  {headline}\n{detail}\n\n"
        "Verify chain integrity:\n"
        f"  [bold]tee-crafter verify-provenance --file {json_path}[/bold]",
        title="[bold green]Build Provenance Audit Trail[/bold green]",
        border_style="green",
    ))
