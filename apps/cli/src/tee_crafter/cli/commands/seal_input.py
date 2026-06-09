"""``tee-crafter seal-input`` — wrap an input directory to an enclave key."""
from __future__ import annotations

import json
import os
import sys

import click

from tee_crafter.cli.constants import console, Panel
from tee_crafter.core.sealing import seal_input_directory


def register(cli):
    @cli.command(name="seal-input")
    @click.option("--input-dir", required=True,
                  type=click.Path(exists=True, file_okay=False, dir_okay=True),
                  help="Directory whose contents will be sealed to the enclave.")
    @click.option("--target-pub", "target_pub_path", required=True,
                  type=click.Path(exists=True, file_okay=True, dir_okay=False),
                  help="PEM-encoded RSA public key of the target enclave "
                       "(usually <build_dir>/seal_pub.pem).")
    @click.option("--out", "out_path", required=True,
                  type=click.Path(file_okay=True, dir_okay=False),
                  help="Path for the sealed bundle (the manifest goes to "
                       "<out>.manifest.json).")
    @click.option("--build-id", default="", type=str,
                  help="SHA-256 of the build directory; the enclave will "
                       "refuse to unseal a bundle whose build_id does not match.")
    @click.option("--aad", "aad_pairs", multiple=True, metavar="KEY=VALUE",
                  help="Extra key=value AAD entries copied into the manifest "
                       "and bound by the GCM tag.")
    def seal_input(input_dir, target_pub_path, out_path, build_id, aad_pairs):
        """Seal an input directory to a target enclave's public key."""
        try:
            with open(target_pub_path, "rb") as f:
                target_pem = f.read()
        except OSError as exc:
            console.print(Panel.fit(
                f"[bold red]Could not read --target-pub[/bold red]\n\n{exc}",
                border_style="red"))
            sys.exit(1)

        extra = {}
        for raw in aad_pairs:
            if "=" not in raw:
                console.print(Panel.fit(
                    f"[bold red]--aad must be KEY=VALUE[/bold red]\n\nGot: {raw}",
                    border_style="red"))
                sys.exit(2)
            k, _, v = raw.partition("=")
            extra[k] = v

        try:
            sealed = seal_input_directory(
                input_dir=os.path.abspath(input_dir),
                target_pub_pem=target_pem,
                out_path=os.path.abspath(out_path),
                build_id=build_id,
                additional_aad=extra or None,
            )
        except Exception as exc:
            console.print(Panel.fit(
                f"[bold red]Seal failed[/bold red]\n\n{exc}", border_style="red"))
            sys.exit(3)

        console.print(Panel.fit(
            f"[bold green]Sealed input bundle written[/bold green]\n\n"
            f"Sealed:    [yellow]{sealed.sealed_path}[/yellow]\n"
            f"Manifest:  [yellow]{sealed.manifest_path}[/yellow]\n"
            f"Plaintext: [magenta]{sealed.size_bytes:,}[/magenta] bytes "
            f"(sha256 [cyan]{sealed.plaintext_sha256[:16]}…[/cyan])\n"
            f"SPKI:      [cyan]{sealed.target_spki_sha256[:16]}…[/cyan]\n"
            f"Build ID:  [magenta]{sealed.build_id or '(none)'}[/magenta]\n"
            f"Algorithm: [white]RSA-OAEP-SHA256 + AES-256-GCM[/white]",
            border_style="green"))

        # Also print the manifest so it can be piped/copied around.
        console.print_json(json.dumps(sealed.to_dict()))
