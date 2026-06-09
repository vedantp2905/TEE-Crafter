"""Operator key management for build provenance signing.

Adds ``tee-crafter audit-gen-signing-key`` which bootstraps a long-lived
Ed25519 keypair and prints the public-key fingerprint operators are
expected to pin in CI / verifier policy.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from tee_crafter.cli.constants import Panel, console
from tee_crafter.core.audit.signing import (
    generate_keypair_pem,
    install_default_key,
)


def register(cli):
    @cli.command("audit-gen-signing-key")
    @click.option(
        "--out-dir",
        type=click.Path(file_okay=False, dir_okay=True),
        default=None,
        help="Write the keypair to this directory as provenance-signing-key.pem "
             "(private) and provenance-signing-key.pub.pem (public). Defaults to "
             "~/.tee-crafter/ for the private key (installed at mode 0600) and "
             "the working directory for the public key.",
    )
    @click.option(
        "--print-private",
        is_flag=True,
        default=False,
        help="Print the private key PEM to stdout (DO NOT use in shared shells; "
             "intended for piping into a CI secrets manager).",
    )
    def audit_gen_signing_key(out_dir, print_private):
        """Generate a long-lived Ed25519 provenance signing key.

        After running this command, every subsequent build signs its
        build_provenance.json with the same key. Verifiers then pin the
        fingerprint via ``tee-crafter verify-provenance --pinned-pubkey-sha256``.
        """
        priv_pem, pub_pem, fingerprint = generate_keypair_pem()

        if out_dir:
            target_dir = Path(out_dir).expanduser()
            target_dir.mkdir(parents=True, exist_ok=True)
            priv_path = target_dir / "provenance-signing-key.pem"
            pub_path = target_dir / "provenance-signing-key.pub.pem"
            if priv_path.exists():
                console.print(
                    f"[red]Refusing to overwrite[/red] existing private key at {priv_path}. "
                    f"Remove it explicitly to regenerate."
                )
                sys.exit(1)
            priv_path.write_bytes(priv_pem)
            try:
                os.chmod(priv_path, 0o600)
            except OSError:
                pass
            pub_path.write_bytes(pub_pem)
            installed_at = priv_path
            public_at = pub_path
        else:
            try:
                installed_at = install_default_key(priv_pem)
            except FileExistsError as exc:
                console.print(f"[red]{exc}[/red]")
                sys.exit(1)
            public_at = Path.cwd() / "provenance-signing-key.pub.pem"
            public_at.write_bytes(pub_pem)

        console.print(
            Panel(
                f"[green]Provenance signing key generated.[/green]\n\n"
                f"  Private key (0600) : {installed_at}\n"
                f"  Public key         : {public_at}\n"
                f"  SHA-256 fingerprint: [cyan]{fingerprint}[/cyan]\n\n"
                f"[bold]Next steps[/bold]\n"
                f"  1. Commit the fingerprint to your audit policy.\n"
                f"  2. Pin it on every verifier:\n"
                f"     tee-crafter verify-provenance --file build_provenance.json \\\n"
                f"       --pinned-pubkey-sha256 {fingerprint} --require-longlived\n"
                f"  3. For CI runners, export the private key PEM via\n"
                f"     TEE_CRAFTER_PROVENANCE_SIGNING_KEY=<pem>  or\n"
                f"     TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE=<path>.",
                title="[bold green]Audit Signing Key Ready[/bold green]",
                border_style="green",
            )
        )

        if print_private:
            sys.stdout.write(priv_pem.decode("ascii"))
            sys.stdout.flush()
