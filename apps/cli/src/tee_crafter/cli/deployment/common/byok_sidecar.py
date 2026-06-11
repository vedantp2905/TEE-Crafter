"""Deploy-time relocation of the BYOK secret env to tmpfs (BYOK-SEC-1).

Counterpart to :mod:`siem_sidecar` but for ``byok.env``.  Unlike SIEM,
BYOK does not need its own systemd unit — the workload service itself
loads ``byok.env`` via ``EnvironmentFile=`` (see
``resources/systemd/{snp,tdx,gpu-cc}-*.service``).  All we have to do
post-deploy is:

1. Create the tmpfs directory (``/run/tee-crafter-<platform>``, 0700,
   owned by ``tee_enclave``) — the SIEM sidecar will normally do this
   already, but we re-run idempotently to handle a "BYOK without SIEM"
   deployment.
2. Move the staged ``app/byok.env`` (the secret half — wrapped DEK +
   HSM bearer) into that tmpfs directory with mode 0600.
3. ``shred -u`` the disk copy so a later EBS snapshot / image export
   does not surface the wrapped key material.

The non-secret half lives at ``app/byok.env.public`` and stays on
disk: it carries only provider name, KMS ARN, region, policy
thresholds, encryption-context keys — nothing that hurts to leak via
a snapshot.

Like SIEM-SEC-2, this is silently bypassed when
``TEE_CRAFTER_BYOK_PERSIST=1`` is set (development workflows that
re-deploy without re-staging).
"""
from __future__ import annotations

import os
from typing import Callable, Tuple

from tee_crafter.cli.constants import Panel
from tee_crafter.core.audit import Verdict as _Verdict
from tee_crafter.core.env_flags import interpret


# Mirror the SIEM sidecar's set so callers can route by platform name.
SUPPORTED_PLATFORMS = (
    "snp-aws", "snp-azure", "snp-gcp",
    "tdx-azure", "tdx-gcp",
    "gpu-cc-aws", "gpu-cc-azure", "gpu-cc-gcp",
    # Nitro + SGX don't load byok.env from disk (their workloads run
    # inside the enclave/Gramine and receive BYOK config another way),
    # so the sidecar is a no-op for them.  Listed so callers don't
    # explode when they pass the platform name.
    "nitro-aws", "sgx-azure",
)

_LAYOUT = {
    "snp-aws":      ("/opt/tee-crafter-snp",    "app"),
    "snp-azure":    ("/opt/tee-crafter-snp",    "app"),
    "snp-gcp":      ("/opt/tee-crafter-snp",    "app"),
    "tdx-azure":    ("/opt/tee-crafter-tdx",    "app"),
    "tdx-gcp":      ("/opt/tee-crafter-tdx",    "app"),
    "gpu-cc-aws":   ("/opt/tee-crafter-gpu-cc", "app"),
    "gpu-cc-azure": ("/opt/tee-crafter-gpu-cc", "app"),
    "gpu-cc-gcp":   ("/opt/tee-crafter-gpu-cc", "app"),
}


def runtime_dir_for(tee_platform: str) -> str:
    """Per-platform tmpfs path holding the wrapped-DEK / HSM-bearer
    byok.env.  Public so other modules (tests, audit-trail emitters and
    ``tee-crafter byok-stage``) resolve the same file the install script
    writes to."""
    return f"/run/tee-crafter-{tee_platform}"


def is_byok_enabled(build_dir: str) -> bool:
    """Return True iff ``byok.env`` (or ``byok.env.public``) in the
    build dir reports BYOK is on."""
    from tee_crafter.core.audit import build_layout as _layout
    for candidate in (
        _layout.byok_env(build_dir),         # new layout
        _layout.byok_env_public(build_dir),  # new layout
        os.path.join(build_dir, "byok.env"),       # legacy top-level
        os.path.join(build_dir, "byok.env.public"),
        os.path.join(build_dir, "app", "byok.env"),       # in-TEE staging
        os.path.join(build_dir, "app", "byok.env.public"),
    ):
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("TEE_CRAFTER_BYOK_ENABLED="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        return interpret(val) is True
        except OSError:
            continue
    return False


# Install script.  Mirrors ``siem_sidecar._INSTALL_SCRIPT`` but only
# does the relocate-and-shred dance — there is no service to enable.
_INSTALL_SCRIPT = (
    "set -u;\n"
    # Idempotent: SIEM sidecar may have created the tmpfs dir already.
    "sudo install -d -m 0700 -o tee_enclave -g tee_enclave {runtime_dir} || "
    "{{ echo 'BYOK-SEC-1: tmpfs mkdir failed'; exit 12; }};\n"
    "if [ -f {remote_app_dir}/byok.env ]; then\n"
    "  sudo install -m 0600 -o tee_enclave -g tee_enclave "
    "{remote_app_dir}/byok.env {runtime_dir}/byok.env || "
    "{{ echo 'BYOK-SEC-1: tmpfs install failed'; exit 13; }};\n"
    "  if [ \"${{TEE_CRAFTER_BYOK_PERSIST:-0}}\" = \"1\" ]; then\n"
    "    sudo chmod 0600 {remote_app_dir}/byok.env || true;\n"
    "    sudo chown tee_enclave:tee_enclave {remote_app_dir}/byok.env || true;\n"
    "    echo 'BYOK-SEC-1: TEE_CRAFTER_BYOK_PERSIST=1; leaving byok.env on disk (user-accepted snapshot risk).';\n"
    "  else\n"
    "    sudo shred -u {remote_app_dir}/byok.env 2>/dev/null || sudo rm -f {remote_app_dir}/byok.env;\n"
    "  fi;\n"
    "fi;\n"
    # The secrets oneshot has to be re-run first, and with `restart` rather than
    # `try-restart`.
    #
    # It reads TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK from the very file this script
    # has just moved into place, so on a fresh deploy it has *already* run and
    # failed -- there was nothing to unwrap when it started.  Observed on
    # snp-azure on 2026-08-23: the unit failed at 21:27:49 with "no wrapped DEK
    # supplied", and the tmpfs byok.env it needed was not written until 21:28.
    #
    # `try-restart` cannot fix that: it only acts on units that are *running*,
    # and a oneshot that exited non-zero is `failed`, not running -- so the
    # previous version of this loop silently skipped the one unit that mattered.
    # `reset-failed` first, because a unit that has hit its start-limit will
    # refuse to start again otherwise.
    "if systemctl list-unit-files tee-crafter-secrets.service 2>/dev/null \\\n"
    "     | grep -q tee-crafter-secrets; then\n"
    "  sudo systemctl reset-failed tee-crafter-secrets.service 2>/dev/null || true;\n"
    "  if sudo systemctl restart tee-crafter-secrets.service 2>/dev/null; then\n"
    "    echo 'BYOK-SEC-1: secrets oneshot re-ran successfully.';\n"
    "  else\n"
    "    echo 'BYOK-SEC-1: secrets oneshot still failing after relocation'"
    " \"(see: journalctl -u tee-crafter-secrets)\";\n"
    "  fi;\n"
    "fi;\n"
    # Then every other tee-crafter unit, so they pick up the relocated
    # env-file path.  **Discovered, not hardcoded**, because both hardcoded
    # lists here were wrong:
    #
    #   * `tee-crafter-{{tee_platform}}.service` renders
    #     `tee-crafter-snp-azure.service`, but the real unit is
    #     `tee-crafter-snp.service` (see `service_name=` in each
    #     cli/deployment/*/phase.py).  It matched nothing on any CVM platform.
    #   * `container.service` / `container.batch.service` are likewise wrong;
    #     the real name is `tee-crafter-container.service`.
    #
    # Both failed silently, so the restart step had never actually restarted
    # anything.  Globbing the installed units cannot drift as unit names change.
    # The secrets oneshot is skipped because it was already handled above, in
    # the right order and with `restart` rather than `try-restart`.
    "for U in $(systemctl list-unit-files 'tee-crafter-*.service' "
    "--no-legend 2>/dev/null | awk '{{print $1}}'); do\n"
    "  case \"$U\" in *secrets*) continue;; esac;\n"
    "  sudo systemctl try-restart \"$U\" 2>/dev/null || true;\n"
    "done;\n"
    # Always print a stable marker so the caller can grep for it.
    "echo 'BYOK-SEC-1: byok.env relocated to tmpfs (or absent).';\n"
    "exit 0;\n"
)


def _install_script(tee_platform: str) -> str:
    if tee_platform not in _LAYOUT:
        # Nitro / SGX no-op.
        return "echo 'BYOK-SEC-1: no-op for {0}'; exit 0;".format(tee_platform)
    remote_base, app_subdir = _LAYOUT[tee_platform]
    remote_app_dir = (f"{remote_base}/{app_subdir}".rstrip("/")
                      if app_subdir else remote_base)
    return _INSTALL_SCRIPT.format(
        remote_app_dir=remote_app_dir,
        runtime_dir=runtime_dir_for(tee_platform),
        tee_platform=tee_platform,
    )


def install_byok_sidecar(
    *,
    console,
    build_dir: str,
    tee_platform: str,
    run_remote: Callable[[str], Tuple[bool, str, str]],
    audit=None,
) -> bool:
    """Relocate the wrapped-DEK / HSM-bearer env file to tmpfs.

    Args:
        console: CLI console for user-visible output.
        build_dir: path to the local build directory (used to gate on
            ``byok.env`` presence).
        tee_platform: one of :data:`SUPPORTED_PLATFORMS`.
        run_remote: callable ``(cmd) -> (ok, stdout, stderr)``.
        audit: optional ``BuildAuditTrail`` for provenance.

    Returns ``True`` if relocation succeeded (or BYOK was disabled —
    nothing to do).  Returns ``False`` on a real failure.
    """
    if not is_byok_enabled(build_dir):
        return True
    if tee_platform not in _LAYOUT:
        # Nitro / SGX: BYOK config is delivered through the EIF/manifest,
        # not via a disk env file, so there is nothing to shred.  Emit
        # an explicit ``not_applicable`` ledger row instead of a silent
        # skip.
        if audit:
            audit.record_check(
                "Phase 5: Post-Deploy", "BYOK env relocation", "BYOK-007",
                verdict=_Verdict.NOT_APPLICABLE,
                observed=False,
                note=f"no-op for {tee_platform} (EIF/manifest-delivered)",
            )
        return True
    script = _install_script(tee_platform)
    console.print(f"[dim]BYOK-SEC-1: relocating byok.env to tmpfs "
                  f"({tee_platform})[/dim]")
    ok, out, err = run_remote(script)
    text = (out or "") + ("\n" + err if err else "")
    marker = "BYOK-SEC-1: byok.env relocated to tmpfs"
    if ok and marker in text:
        console.print("[green]✓ BYOK secret env on tmpfs; disk copy shredded.[/green]")
        if audit:
            audit.record_check(
                "Phase 5: Post-Deploy", "BYOK env relocation", "BYOK-007",
                observed=True,
                tee_platform=tee_platform,
                runtime_dir=runtime_dir_for(tee_platform),
            )
        return True
    console.print(Panel(
        text[-2000:] or "(no output)",
        title="[bold yellow]BYOK env relocation output[/bold yellow]",
        border_style="yellow",
    ))
    if audit:
        audit.record_check(
            "Phase 5: Post-Deploy", "BYOK env relocation", "BYOK-007",
            verdict=_Verdict.WARN,
            observed=False,
            tee_platform=tee_platform,
            last_output=text[-200:],
        )
    # Same fail-open posture as SIEM: a relocation failure is logged
    # but does not abort the deploy.  The workload still has the
    # public env half; only attestation-gated key release will be
    # unavailable.
    return False
