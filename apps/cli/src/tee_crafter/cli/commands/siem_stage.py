"""``tee-crafter siem-stage`` — push a fresh SIEM token to a running TEE.

Used in two scenarios:

1. **Token rotation.**  Generate a new HEC token / Datadog API key /
   bearer credential, drop it into a JSON config, and push it without
   redeploying.  The sidecar is reloaded (``systemctl reload-or-restart
   tee-crafter-siem.service``) and starts using the new token on the
   next tick.  The chain head signature changes (per-boot key), so the
   SIEM-side ``verify-siem-chain`` operator sees a clean cut-over.
2. **Post-reboot re-staging.**  The tmpfs location of ``siem.env``
   means the token vanishes on VM reboot (SIEM-SEC-2).  This command
   re-stages it without rebuilding artifacts.

Supports both SSM (AWS/Nitro/GPU-CC AWS) and SSH-via-Bastion (Azure)
and IAP-tunneled SSH (GCP) — the same transport the deploy phase
used.  ``--instance-id`` / ``--vm`` plus ``--platform`` is enough to
route correctly.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from typing import Tuple

import click

from tee_crafter.cli.constants import Panel, console
from tee_crafter.cli.commands.deploy.siem_mode import (
    SECRET_ENV_KEYS,
    SiemConfig,
    build_siem_config,
    split_env_secrets,
)
from tee_crafter.cli.deployment.common.siem_sidecar import (
    SUPPORTED_PLATFORMS,
    runtime_dir_for,
)


def _build_remote_command(*, tee_platform: str, secret_env: dict,
                          public_env: dict) -> str:
    """Render the bash one-liner that re-stages the env files.

    The secret half lands on tmpfs under ``/run/tee-crafter-{platform}/``;
    the public half lands on disk so a reboot still has provider+endpoint
    config available.  The sidecar service is reloaded at the end.
    """
    secret_lines = "\n".join(f"{k}={v}" for k, v in sorted(secret_env.items()))
    public_lines = "\n".join(f"{k}={v}" for k, v in sorted(public_env.items()))
    sec_b64 = base64.b64encode(secret_lines.encode("utf-8")).decode("ascii")
    pub_b64 = base64.b64encode(public_lines.encode("utf-8")).decode("ascii")

    runtime_dir = runtime_dir_for(tee_platform)
    # We can't know the on-disk app dir for the public half from
    # tee_platform alone (the LAYOUT mapping in siem_sidecar.py owns
    # that).  Reuse the layout.
    from tee_crafter.cli.deployment.common.siem_sidecar import _LAYOUT
    base, sub = _LAYOUT[tee_platform]
    on_disk_dir = (f"{base}/{sub}".rstrip("/") if sub else base)

    return (
        "set -eu;\n"
        f"sudo install -d -m 0700 -o tee_enclave -g tee_enclave {runtime_dir};\n"
        f"echo {sec_b64} | base64 -d | sudo tee {runtime_dir}/siem.env >/dev/null;\n"
        f"sudo chmod 0600 {runtime_dir}/siem.env;\n"
        f"sudo chown tee_enclave:tee_enclave {runtime_dir}/siem.env;\n"
        f"echo {pub_b64} | base64 -d | sudo tee {on_disk_dir}/siem.env.public >/dev/null;\n"
        f"sudo chmod 0640 {on_disk_dir}/siem.env.public;\n"
        f"sudo chown tee_enclave:tee_enclave {on_disk_dir}/siem.env.public;\n"
        "sudo systemctl reload-or-restart tee-crafter-siem.service 2>&1 || true;\n"
        "sleep 2;\n"
        "systemctl is-active tee-crafter-siem.service 2>&1;\n"
        "journalctl -u tee-crafter-siem.service --no-pager -n 15 2>&1 || true;\n"
    )


def _run_via_ssm(instance_id: str, region: str, script: str) -> Tuple[bool, str, str]:
    from tee_crafter.core.remote.ssm import run_ssm_command
    return run_ssm_command(instance_id, script, region, timeout=120)


def _run_via_ssh(host: str, ssh_key_path: str, port: int, user: str,
                 script: str) -> Tuple[bool, str, str]:
    """Fall-back for Azure Bastion / GCP IAP tunnels."""
    from tee_crafter.core.remote.azure_ssh import run_ssh_command
    return run_ssh_command(script, ssh_key_path, user=user, port=port,
                           timeout=120, host=host)


def register(cli):
    @cli.command("siem-stage")
    @click.option("--platform", "tee_platform", required=True,
                  type=click.Choice(SUPPORTED_PLATFORMS),
                  help="Target TEE platform slug.")
    @click.option("--siem-config", "siem_config_path", required=True,
                  type=click.Path(exists=True, dir_okay=False),
                  help="New SIEM JSON config (same schema as `--siem-config` "
                       "at deploy time).  Must include the rotated token.")
    @click.option("--instance-id", default=None,
                  help="EC2 instance id, reached over SSM (nitro-aws, snp-aws, "
                       "gpu-cc-aws). Pass this OR --ssh-host + --ssh-key; when "
                       "both are given, --instance-id wins.")
    @click.option("--region", default=lambda: os.getenv("AWS_REGION", "us-east-2"),
                  help="AWS region for the SSM call. Only used with "
                       "--instance-id. Defaults to $AWS_REGION, else us-east-2.")
    @click.option("--ssh-host", default=None,
                  help="SSH host for the Azure Bastion / GCP IAP path. Use with "
                       "--ssh-key. Ignored when --instance-id is given.")
    @click.option("--ssh-key", default=None, type=click.Path(),
                  help="SSH private key path. Required alongside --ssh-host.")
    @click.option("--ssh-port", default=22, type=int,
                  help="SSH port (default 22). Point this at the local end of "
                       "an already-open Bastion / IAP tunnel if you have one.")
    @click.option("--ssh-user", default="azureuser",
                  help="SSH username (default 'azureuser', the Azure bake "
                       "default). GCP images use 'tee_admin'.")
    @click.option("--dry-run", is_flag=True, default=False,
                  help="Print the remote script instead of executing it. "
                       "Includes the rotated token — handle with care.")
    def siem_stage(tee_platform, siem_config_path, instance_id, region,
                   ssh_host, ssh_key, ssh_port, ssh_user, dry_run):
        """Re-stage SIEM env (token rotation / post-reboot recovery).

        The token-bearing half of the SIEM config lives on tmpfs, so it does
        not survive a reboot; this pushes a fresh copy without rebuilding or
        redeploying. `tee-crafter byok-stage` does the same for BYOK keys.
        See docs/siem.md.
        """
        # Reuse the deploy-time loader so validation behaviour is
        # identical to ``--siem-config`` at deploy time.
        with open(siem_config_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        provider = (doc.get("provider") or "none").lower()
        if provider == "none":
            raise click.ClickException(
                "--siem-config has provider=none; nothing to stage.")
        cfg: SiemConfig = build_siem_config(
            provider=provider, raw_config_path=siem_config_path)
        errs = cfg.validate()
        if errs:
            raise click.ClickException(
                "siem-config invalid:\n" + "\n".join(f" - {e}" for e in errs))
        env_data = cfg.to_env()
        env_data["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        secret_env, public_env = split_env_secrets(env_data)
        if not any(k in secret_env for k in SECRET_ENV_KEYS):
            raise click.ClickException(
                "siem-config produced no secret keys; refusing to push (would "
                "leak nothing).  Did you forget the token / api_key field?")

        script = _build_remote_command(
            tee_platform=tee_platform,
            secret_env=secret_env, public_env=public_env)

        if dry_run:
            console.print(Panel(script, title="[bold cyan]Remote script (DRY RUN)[/bold cyan]",
                                border_style="cyan"))
            return

        if instance_id:
            console.print(f"[cyan]siem-stage[/cyan]: via SSM -> {instance_id} ({region})")
            ok, out, err = _run_via_ssm(instance_id, region, script)
        elif ssh_host and ssh_key:
            console.print(f"[cyan]siem-stage[/cyan]: via SSH -> {ssh_user}@{ssh_host}:{ssh_port}")
            ok, out, err = _run_via_ssh(ssh_host, ssh_key, ssh_port, ssh_user, script)
        else:
            raise click.ClickException(
                "Provide either --instance-id (SSM) or "
                "--ssh-host + --ssh-key (SSH path).")

        text = (out or "") + ("\n" + err if err else "")
        last_line = text.strip().splitlines()[-1] if text.strip() else ""
        if ok and "active" in last_line.lower():
            console.print("[green]✓ Sidecar reloaded with rotated SIEM token.[/green]")
            console.print(f"[dim]{text[-400:]}[/dim]")
        else:
            console.print(Panel(
                text[-2000:] or "(no output)",
                title="[bold yellow]Stage result[/bold yellow]",
                border_style="yellow",
            ))
            sys.exit(1)
