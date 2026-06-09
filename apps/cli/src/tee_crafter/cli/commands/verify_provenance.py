"""Verify-provenance command: check both the hash-chain AND the Ed25519 signature."""

import json
import os
import click
from tee_crafter.cli.constants import Panel

from tee_crafter.core.audit import BuildAuditTrail
from tee_crafter.cli.constants import console


def register(cli):
    @cli.command("verify-provenance")
    @click.option(
        "--file",
        "provenance_file",
        required=True,
        type=click.Path(exists=True, dir_okay=False),
        help="Path to build_provenance.json (build_provenance.sig + .pub must sit next to it)",
    )
    @click.option(
        "--skip-signature",
        is_flag=True,
        default=False,
        help="Only verify the hash chain — DO NOT use in production. Audit-only escape hatch "
             "for legacy artefacts captured before per-build Ed25519 signing was enabled. "
             "Also skips the audit-ledger signature check.",
    )
    @click.option(
        "--pinned-pubkey-sha256",
        "pinned_pubkey_sha256",
        default=None,
        help="Require build_provenance.pub to match this SHA-256 fingerprint "
             "(hex, lowercase, 64 chars). Production verifiers should always set "
             "this to the fingerprint of their long-lived audit signing key.",
    )
    @click.option(
        "--require-longlived",
        is_flag=True,
        default=False,
        help="Refuse provenance files signed by an ephemeral per-build keypair "
             "(build_provenance.key_kind.txt must read 'longlived'). Use this in "
             "CI / production audit pipelines.",
    )
    @click.option(
        "--ledger",
        "ledger_file",
        default=None,
        type=click.Path(exists=False, dir_okay=False),
        help="Path to audit_evidence.json (defaults to alongside --file). "
             "When present, also verify the ledger's Ed25519 signature "
             "(exit 5 on failure) and print a colourised matrix.",
    )
    @click.option(
        "--required-checks",
        "required_checks",
        default=None,
        help="Comma-separated list of check_ids that MUST pass for the "
             "verify command to exit 0 (e.g. 'BYOK-001,SIEM-001,ATT-002'). "
             "Pass 'auto' to use the catalogue's per-platform required set.",
    )
    @click.option(
        "--allow-warn",
        is_flag=True,
        default=False,
        help="Treat warn rows in required-checks as acceptable. Defaults "
             "to off (warn rows fail the gate).",
    )
    def verify_provenance(
        provenance_file, skip_signature, pinned_pubkey_sha256, require_longlived,
        ledger_file, required_checks, allow_warn,
    ):
        """Verify a build provenance audit trail (hash chain + Ed25519 signature)."""
        provenance_file = os.path.abspath(provenance_file)
        console.print(f"[cyan]Verifying:[/cyan] {provenance_file}")

        chain_ok, chain_reason = BuildAuditTrail.verify_chain(provenance_file)
        if not chain_ok:
            console.print(
                Panel(
                    f"[bold red]Hash-chain verification FAILED[/bold red]\n\n{chain_reason}",
                    title="[bold red]Provenance Tampered[/bold red]",
                    border_style="red",
                )
            )
            raise SystemExit(1)

        sig_ok, sig_reason = (True, "")
        if skip_signature:
            console.print(
                "[yellow]WARNING:[/yellow] --skip-signature set; Ed25519 signature "
                "was NOT checked. Production verifiers MUST omit this flag."
            )
            if pinned_pubkey_sha256 or require_longlived:
                console.print(
                    "[red]ERROR:[/red] --skip-signature is incompatible with "
                    "--pinned-pubkey-sha256 / --require-longlived; refusing."
                )
                raise SystemExit(3)
        else:
            sig_ok, sig_reason = BuildAuditTrail.verify_signature(
                provenance_file,
                pinned_pubkey_sha256=pinned_pubkey_sha256,
                require_longlived=require_longlived,
            )

        if not sig_ok:
            console.print(
                Panel(
                    f"[bold red]Ed25519 signature verification FAILED[/bold red]\n\n"
                    f"{sig_reason}\n\n"
                    f"The hash chain is intact, but the per-build signature does not "
                    f"match. Either the document was re-saved after signing, the "
                    f"public key file (`build_provenance.pub`) belongs to a different "
                    f"build, or the pinned fingerprint does not match. Treat this "
                    f"artefact as untrusted.",
                    title="[bold red]Provenance Signature Invalid[/bold red]",
                    border_style="red",
                )
            )
            raise SystemExit(2)

        with open(provenance_file, "r", encoding="utf-8") as f:
            doc = json.load(f)
        n = doc.get("total_entries", 0)
        head = doc.get("chain_head_hash", "")
        sig_line = (
            "  Ed25519 signature : [yellow]SKIPPED[/yellow]"
            if skip_signature
            else "  Ed25519 signature : [green]VALID[/green]"
        )
        from tee_crafter.core.audit import build_layout as _layout
        kind_line = ""
        # *provenance_file* may live in either layout — walk back to
        # the per-build root before resolving sidecars.
        prov_dir = os.path.dirname(provenance_file)
        build_dir = (os.path.dirname(prov_dir)
                     if os.path.basename(prov_dir) == _layout.PROVENANCE_DIR
                     else prov_dir)
        kind_path = _layout.resolve_provenance_key_kind(build_dir)
        if os.path.isfile(kind_path):
            try:
                with open(kind_path, "r", encoding="utf-8") as f:
                    kind = f.readline().strip()
                colour = "green" if kind == "longlived" else "yellow"
                kind_line = f"\n  Key kind          : [{colour}]{kind}[/{colour}]"
            except OSError:
                pass
        fpr_line = ""
        fpr_path = _layout.resolve_provenance_pub_fpr(build_dir)
        if os.path.isfile(fpr_path):
            try:
                with open(fpr_path, "r", encoding="utf-8") as f:
                    fpr = f.read().strip()
                fpr_line = f"\n  Pubkey SHA-256    : [cyan]{fpr}[/cyan]"
            except OSError:
                pass
        console.print(
            Panel(
                f"[green]Chain is intact.[/green]\n"
                f"  Entries verified : {n}\n"
                f"  Chain head hash  : {head}\n"
                f"{sig_line}{kind_line}{fpr_line}",
                title="[bold green]Provenance Verified[/bold green]",
                border_style="green",
            )
        )

        ledger_path = ledger_file or _layout.resolve_audit_evidence_json(
            build_dir)
        if os.path.isfile(ledger_path):
            _verify_and_print_ledger(
                ledger_path,
                required_checks=required_checks,
                allow_warn=allow_warn,
                # tee_platform is now persisted in the provenance JSON
                # itself; fall back to the ledger's own field for
                # backward-compat with pre-fix builds.
                tee_platform=doc.get("tee_platform"),
                skip_signature=skip_signature,
                pinned_pubkey_sha256=pinned_pubkey_sha256,
                require_longlived=require_longlived,
            )
        elif required_checks:
            console.print(
                "[bold red]ERROR:[/bold red] --required-checks was set but "
                f"no audit_evidence.json was found at {ledger_path}."
            )
            raise SystemExit(4)


def _verify_and_print_ledger(
    ledger_path: str,
    *,
    required_checks: str | None,
    allow_warn: bool,
    tee_platform: str | None,
    skip_signature: bool = False,
    pinned_pubkey_sha256: str | None = None,
    require_longlived: bool = False,
) -> None:
    """Load *ledger_path*, verify its Ed25519 signature, print a matrix.

    Exits with code 5 when the ledger's Ed25519 signature does not verify
    (``docs/audit_matrix.md`` tells auditors to check this signature, so a
    bad one has to break the build, not just print red text), and with
    code 4 when any required-check row is missing or in a non-passing
    verdict, so CI gates can rely on the exit status.
    """
    with open(ledger_path, "r", encoding="utf-8") as f:
        ledger = json.load(f)
    rows = ledger.get("rows") or []
    # Fall back to the ledger's own tee_platform tag when the
    # provenance JSON didn't carry one (pre-fix builds).
    if not tee_platform:
        tee_platform = ledger.get("tee_platform") or None

    # The signature is produced by ``AuditEvidenceLedger.sign`` over the
    # *canonical JSON* of the document and stored hex-encoded, so it must
    # be checked with the matching helper — verifying raw file bytes
    # against raw signature bytes (as this command used to do) can never
    # succeed.
    ledger_sig_reason = ""
    if skip_signature:
        sig_state = "[yellow]SKIPPED[/yellow]"
        ledger_sig_ok = True
    else:
        from tee_crafter.core.audit.ledger import verify_ledger_signature
        ledger_sig_ok, ledger_sig_reason = verify_ledger_signature(
            ledger_path,
            pinned_pubkey_sha256=pinned_pubkey_sha256,
            require_longlived=require_longlived,
        )
        sig_state = ("[green]VALID[/green]" if ledger_sig_ok
                     else "[bold red]INVALID[/bold red]")

    totals = ledger.get("totals") or {}
    pass_n = totals.get("pass", 0)
    fail_n = totals.get("fail", 0)
    warn_n = totals.get("warn", 0)
    na_n = totals.get("not_applicable", 0)
    info_n = totals.get("info", 0)
    ne_n = totals.get("not_evaluated", 0)

    matrix_lines = [
        f"  Ledger signature : {sig_state}",
        f"  Rows total       : {len(rows)}",
        f"  Pass             : [green]{pass_n}[/green]",
        f"  Fail             : [red]{fail_n}[/red]",
        f"  Warn             : [yellow]{warn_n}[/yellow]",
        f"  Not evaluated    : [yellow]{ne_n}[/yellow]",
        f"  N/A              : [dim]{na_n}[/dim]",
        f"  Info             : [dim]{info_n}[/dim]",
    ]
    failing = [r for r in rows if r.get("verdict") == "fail"]
    warning = [r for r in rows if r.get("verdict") == "warn"]
    for r in failing[:20]:
        matrix_lines.append(
            f"    [red]✗[/red] {r.get('check_id')}: {r.get('title')}"
        )
    for r in warning[:20]:
        matrix_lines.append(
            f"    [yellow]![/yellow] {r.get('check_id')}: {r.get('title')}"
        )
    console.print(
        Panel(
            "\n".join(matrix_lines),
            title="[bold cyan]Audit Matrix[/bold cyan]",
            border_style="cyan",
        )
    )

    if not ledger_sig_ok:
        console.print(
            Panel(
                f"[bold red]Audit-ledger Ed25519 signature verification "
                f"FAILED[/bold red]\n\n{ledger_sig_reason}\n\n"
                f"`audit_evidence.json` is the machine-readable evidence "
                f"matrix auditors are told to check (docs/audit_matrix.md). "
                f"An unverifiable signature means the rows below prove "
                f"nothing — treat the whole build as untrusted.",
                title="[bold red]Ledger Signature Invalid[/bold red]",
                border_style="red",
            )
        )
        raise SystemExit(5)

    if not required_checks:
        return

    required = _resolve_required_checks(required_checks, tee_platform)
    by_id = {r.get("check_id"): r for r in rows}
    missing: list[str] = []
    not_passing: list[tuple[str, str]] = []
    for cid in required:
        row = by_id.get(cid)
        if row is None:
            missing.append(cid)
            continue
        verdict = row.get("verdict") or ""
        if verdict == "pass":
            continue
        if verdict == "warn" and allow_warn:
            continue
        if verdict == "not_applicable":
            continue
        not_passing.append((cid, verdict))

    if missing or not_passing:
        lines = []
        if missing:
            lines.append("[bold red]Missing required check_ids:[/bold red]")
            lines.extend(f"  - {c}" for c in missing)
        if not_passing:
            lines.append("[bold red]Required checks not passing:[/bold red]")
            lines.extend(f"  - {c} (verdict={v})" for c, v in not_passing)
        console.print(
            Panel(
                "\n".join(lines),
                title="[bold red]Required-Check Gate FAILED[/bold red]",
                border_style="red",
            )
        )
        raise SystemExit(4)

    console.print(
        f"[green]Required-check gate passed[/green] "
        f"({len(required)} checks)."
    )


def _resolve_required_checks(
    spec: str | None, tee_platform: str | None,
) -> list[str]:
    """Resolve 'auto' or a comma list into a list of check_ids."""
    if not spec:
        return []
    if spec.strip().lower() == "auto":
        try:
            from tee_crafter.core.audit.checks import required_checks_for
            return required_checks_for(tee_platform or "")
        except Exception:
            return []
    return [c.strip() for c in spec.split(",") if c.strip()]
