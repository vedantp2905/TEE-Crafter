"""``tee-crafter byok-stage`` — push a fresh BYOK config to a running TEE.

Sister command to ``siem-stage``.  Used in two scenarios:

1. **Key / wrapped-DEK rotation.**  Re-wrap a fresh DEK with the
   customer's KMS key (``byok-sandbox/aws/wrap_dek.py`` or equivalent),
   drop the resulting ``byok-config.json`` somewhere, and push it
   without redeploying.  The running workload's ``EnvironmentFile=``
   line points at ``/run/tee-crafter-<platform>/byok.env``, so the
   refreshed bearer / wrapped-DEK is consumed on the next service
   restart.

2. **Post-reboot re-staging.**  ``byok.env`` lives on tmpfs
   (BYOK-SEC-1) — it vanishes on reboot.  This command re-stages it
   without rebuilding artifacts.

Supports both SSM (AWS / Nitro / GPU-CC AWS) and SSH-via-Bastion
(Azure) / IAP-tunneled SSH (GCP), the same transports the deploy
phase uses.

Security:
  * The wrapped DEK ciphertext and any ``hsm_bearer_token`` are
    base64-encoded into the remote bash one-liner, sent over the
    SSM/SSH channel, written to tmpfs with mode 0600 owned by
    ``tee_enclave``, and the local-side script is **never** printed
    in full unless ``--dry-run`` is passed.
  * The non-secret half (``byok.env.public``) lands on disk at the
    standard ``app/`` directory and survives reboots so the workload
    keeps non-sensitive config (provider, key_id, region, policy
    knobs) even when the secret half is missing.
  * Refuses to push when the rendered config emits zero secret keys —
    that would be a misconfigured rotation that silently wipes the
    live key out without replacing it.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from typing import Tuple

import click

from tee_crafter.cli.constants import Panel, console
from tee_crafter.cli.commands.deploy.byok_mode import (
    ByokConfig,
    build_byok_config,
    split_byok_env_secrets,
)
from tee_crafter.cli.deployment.common.byok_sidecar import (
    SUPPORTED_PLATFORMS,
    _LAYOUT,
    runtime_dir_for,
)


def _build_remote_command(*, tee_platform: str, secret_env: dict,
                          public_env: dict, restart_workload: bool) -> str:
    """Render the bash one-liner that re-stages the env files.

    The secret half lands on tmpfs under ``/run/tee-crafter-{platform}/``;
    the public half lands on disk under ``app/`` so a reboot still has
    provider/key/region/policy info available.  When *restart_workload*
    is True, ``systemctl try-restart`` cycles the unit so the new env
    is consumed; otherwise the operator is expected to time the
    restart themselves (useful for blue/green rotations).
    """
    secret_lines = "\n".join(f"{k}={v}" for k, v in sorted(secret_env.items()))
    public_lines = "\n".join(f"{k}={v}" for k, v in sorted(public_env.items()))
    sec_b64 = base64.b64encode(secret_lines.encode("utf-8")).decode("ascii")
    pub_b64 = base64.b64encode(public_lines.encode("utf-8")).decode("ascii")

    runtime_dir = runtime_dir_for(tee_platform)
    if tee_platform not in _LAYOUT:
        # Nitro + SGX: byok.env is not loaded from disk by the
        # workload (BYOK ships through the EIF / Gramine manifest).
        # Refuse loudly rather than pretend to succeed.
        raise click.ClickException(
            f"byok-stage is not applicable for --platform {tee_platform}; "
            f"BYOK on this platform ships inside the build artifact, not "
            f"via a runtime env-file.  Re-bake / re-deploy to rotate.")
    base, sub = _LAYOUT[tee_platform]
    on_disk_dir = (f"{base}/{sub}".rstrip("/") if sub else base)

    # Restart logic: try-restart only the units that actually exist,
    # so an SNP-AWS host doesn't spuriously fail to find a "container.service"
    # while a container-mode deploy doesn't trip on a missing per-platform
    # service.  This matches the install_byok_sidecar pattern.
    restart_block = (
        "for U in tee-crafter-{0}.service container.service container.batch.service; do\n"
        "  if systemctl list-unit-files \"$U\" >/dev/null 2>&1; then\n"
        "    sudo systemctl try-restart \"$U\" 2>/dev/null || true;\n"
        "  fi;\n"
        "done;\n"
    ).format(tee_platform) if restart_workload else ""

    return (
        "set -eu;\n"
        # 1. tmpfs dir (idempotent — SIEM may have already created it).
        f"sudo install -d -m 0700 -o tee_enclave -g tee_enclave {runtime_dir};\n"
        # 2. Secret half -> tmpfs.
        f"echo {sec_b64} | base64 -d | sudo tee {runtime_dir}/byok.env >/dev/null;\n"
        f"sudo chmod 0600 {runtime_dir}/byok.env;\n"
        f"sudo chown tee_enclave:tee_enclave {runtime_dir}/byok.env;\n"
        # 3. Public half -> disk.
        f"sudo install -d -m 0750 -o tee_enclave -g tee_enclave {on_disk_dir};\n"
        f"echo {pub_b64} | base64 -d | sudo tee {on_disk_dir}/byok.env.public >/dev/null;\n"
        f"sudo chmod 0640 {on_disk_dir}/byok.env.public;\n"
        f"sudo chown tee_enclave:tee_enclave {on_disk_dir}/byok.env.public;\n"
        # 4. If a stale byok.env from a previous full-deploy run is on
        #    disk, scrub it (BYOK-SEC-1: secret half must never persist).
        f"if [ -f {on_disk_dir}/byok.env ]; then "
        f"sudo shred -u {on_disk_dir}/byok.env 2>/dev/null || "
        f"sudo rm -f {on_disk_dir}/byok.env; fi;\n"
        # 5. Workload restart (optional).
        f"{restart_block}"
        # 6. Stable marker so the caller can grep.
        "echo 'BYOK-SEC-1: byok.env re-staged (tmpfs); public half on disk.';\n"
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
    @cli.command("byok-stage")
    @click.option("--platform", "tee_platform", required=True,
                  type=click.Choice(SUPPORTED_PLATFORMS),
                  help="Target TEE platform slug.  Nitro / SGX raise "
                       "because BYOK on those platforms ships inside the "
                       "build artifact, not via a runtime env-file.")
    @click.option("--byok-config", "byok_config_path", required=True,
                  type=click.Path(exists=True, dir_okay=False),
                  help="New BYOK JSON config (same schema as --byok-config "
                       "at deploy time).  Must include the rotated wrapped "
                       "DEK (extra.ciphertext_b64) or HSM bearer.")
    @click.option("--instance-id", default=None,
                  help="EC2 instance id, reached over SSM (snp-aws / "
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
    @click.option("--no-restart", is_flag=True, default=False,
                  help="Skip the workload restart after staging.  The new "
                       "env is in place but won't take effect until the "
                       "operator restarts the unit manually (useful for "
                       "blue/green or scheduled cutovers).")
    @click.option("--dry-run", is_flag=True, default=False,
                  help="Print the remote script instead of executing it. "
                       "Includes secret material — handle with care.")
    def byok_stage(tee_platform, byok_config_path, instance_id, region,
                   ssh_host, ssh_key, ssh_port, ssh_user, no_restart,
                   dry_run):
        """Push a new BYOK config to an already-running TEE.

        \b
        Two uses:
          1. Key rotation. Re-wrap a fresh DEK with your KMS key, then push the
             new --byok-config without redeploying the workload.
          2. Post-reboot recovery. byok.env lives on tmpfs, so a VM reboot loses
             it; this re-stages it from the same config.

        \b
        Where the config lands:
          secret half     /run/tee-crafter-<platform>/byok.env
                          (tmpfs, mode 0600, owned by tee_enclave)
          non-secret half /opt/tee-crafter-<snp|tdx|gpu-cc>/app/byok.env.public
                          (on disk, survives the next reboot)

        \b
        Reach the host one of two ways:
          --instance-id <id> [--region <r>]      SSM (snp-aws, gpu-cc-aws)
          --ssh-host <h> --ssh-key <path>        SSH (Azure Bastion, GCP IAP)

        --platform nitro-aws and --platform sgx-azure are rejected: BYOK on
        those platforms ships inside the build artifact (EIF / Gramine
        manifest), so rotation means a re-bake and re-deploy.

        Run `tee-crafter siem-stage` for the equivalent SIEM token rotation.
        See docs/byok.md, plus docs/aws_setup.md, docs/azure_setup.md and
        docs/gcp_setup.md for the per-cloud prerequisites.
        """
        # Reuse the deploy-time loader so validation behaviour matches
        # --byok-config at deploy time.
        with open(byok_config_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        provider = (doc.get("provider") or "none").lower()
        if provider == "none":
            raise click.ClickException(
                "--byok-config has provider=none; nothing to stage.")
        cfg: ByokConfig = build_byok_config(
            provider=provider, raw_policy_path=byok_config_path)
        errs = cfg.validate()
        if errs:
            raise click.ClickException(
                "byok-config invalid:\n" + "\n".join(f" - {e}" for e in errs))
        env_data = cfg.to_env()
        env_data["TEE_CRAFTER_BYOK_ENABLED"] = "1"
        secret_env, public_env = split_byok_env_secrets(env_data)

        # We expect AT LEAST one of: a wrapped DEK ciphertext, or an HSM
        # bearer token.  A staging call with no secret material is
        # almost certainly an operator mistake (forgot to wrap a fresh
        # DEK before pushing), and silently succeeding would leave the
        # workload running with whatever it had before.
        if not secret_env:
            raise click.ClickException(
                "byok-config produced no secret keys (no wrapped DEK and "
                "no HSM bearer).  Refusing to push — did you forget to "
                "run wrap_dek.py before --byok-config?")

        script = _build_remote_command(
            tee_platform=tee_platform,
            secret_env=secret_env, public_env=public_env,
            restart_workload=not no_restart,
        )

        if dry_run:
            console.print(Panel(
                script,
                title="[bold cyan]Remote script (DRY RUN — contains secrets)[/bold cyan]",
                border_style="cyan",
            ))
            return

        if instance_id:
            console.print(
                f"[cyan]byok-stage[/cyan]: via SSM -> {instance_id} ({region})")
            ok, out, err = _run_via_ssm(instance_id, region, script)
        elif ssh_host and ssh_key:
            console.print(
                f"[cyan]byok-stage[/cyan]: via SSH -> {ssh_user}@{ssh_host}:{ssh_port}")
            ok, out, err = _run_via_ssh(ssh_host, ssh_key, ssh_port,
                                         ssh_user, script)
        else:
            raise click.ClickException(
                "Provide either --instance-id (SSM) or "
                "--ssh-host + --ssh-key (SSH path).")

        text = (out or "") + ("\n" + err if err else "")
        # Stable marker; same shape as install_byok_sidecar so log
        # scrapers can correlate.
        marker = "BYOK-SEC-1: byok.env re-staged"
        if ok and marker in text:
            extra = (" (workload restarted)" if not no_restart
                     else " (no restart; operator-driven cutover)")
            console.print(
                f"[green]✓ BYOK env re-staged on tmpfs{extra}.[/green]")
            # Show only the last ~6 lines — never include the full
            # script (it carries the wrapped DEK base64).
            tail = "\n".join(text.strip().splitlines()[-6:])
            console.print(f"[dim]{tail}[/dim]")
        else:
            console.print(Panel(
                text[-2000:] or "(no output)",
                title="[bold yellow]Stage result[/bold yellow]",
                border_style="yellow",
            ))
            sys.exit(1)
