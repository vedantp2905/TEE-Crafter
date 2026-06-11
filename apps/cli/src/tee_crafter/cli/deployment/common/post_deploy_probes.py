"""On-instance post-deploy probes — PDR-001 .. PDR-011.

This module is the cross-cloud, cross-TEE harness for the structured
post-deploy verification rows in the audit evidence matrix.  Each
probe runs a small, JSON-emitting shell snippet on the deployed
instance via the cloud's management plane:

* AWS — SSM ``RunCommand`` (``tee_crafter.core.remote.ssm``)
* Azure — Bastion exec
* GCP — IAP-tunnelled SSH

The probes are intentionally tiny and read-only.  When the management
plane is unreachable the harness emits a single PDR-001 ``warn`` row
and short-circuits — we never want a probe failure to abort a deploy
that otherwise succeeded.

Outputs land under ``builds/<id>/probes/<check_id>.txt`` so an
auditor can re-read the raw text for each verdict.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from tee_crafter.core.audit import BuildAuditTrail


logger = logging.getLogger("tee_crafter.post_deploy_probes")


# ----------------------------- API --------------------------------------

@dataclass
class ProbeResult:
    """Outcome of a single shell probe run on the instance."""

    check_id: str
    ok: bool
    observed: Optional[object]
    raw_output: str
    note: str = ""

    def evidence_path(self) -> str:
        return f"probes/{self.check_id}.txt"


RunRemoteFn = Callable[[str], Tuple[bool, str, str]]
"""Callable signature: ``(script) -> (ok, stdout, stderr)``."""


# Shell snippets for each PDR check.  Each snippet must print a single
# line of the form ``PDR-<id>: observed=<value>`` so the harness can
# parse it back into a structured verdict.  Anything else (banners,
# stderr) is captured but ignored by the parser.
_PROBES: Dict[str, Tuple[str, str]] = {
    "PDR-002": (
        "cloud-init completed",
        "if command -v cloud-init >/dev/null 2>&1; then "
        "  s=$(cloud-init status 2>/dev/null | awk -F: 'NR==1{gsub(/ /,\"\",$2); print $2}'); "
        "  echo \"PDR-002: observed=$s\"; "
        "else echo 'PDR-002: observed=no-cloud-init'; fi"
    ),
    "PDR-003": (
        "Host TEE service active",
        # Every platform/setup script we ship installs one of these unit
        # names — when the user runs `deploy-container` the unit on the
        # host is ``tee-crafter-container.service``; when they run plain
        # `deploy` it is ``tee-crafter-{snp,tdx,sgx,gpu-cc}.service`` or
        # the Nitro host-proxy.  We probe every known unit and report
        # the first that is ``active``.
        "for u in nitro-enclaves-allocator.service host-proxy.service "
        "tee-crafter-host-proxy.service "
        "tee-crafter-snp.service tee-crafter-tdx.service "
        "tee-crafter-sgx.service sgx-enclave.service "
        "tee-crafter-gpu-cc.service tee-crafter-container.service "
        "tee-crafter-siem.service tee-crafter-service.service; do "
        "  if systemctl is-active --quiet \"$u\" 2>/dev/null; then "
        "    echo \"PDR-003: observed=active unit=$u\"; exit 0; fi; "
        "done; "
        "echo 'PDR-003: observed=none'"
    ),
    "PDR-004": (
        "IMDSv2-only on host",
        "if curl -fs --max-time 2 http://169.254.169.254/latest/meta-data/ "
        ">/dev/null 2>&1; then "
        "  echo 'PDR-004: observed=insecure'; "
        "else "
        "  if curl -fs --max-time 2 -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' "
        "    -X PUT http://169.254.169.254/latest/api/token >/dev/null 2>&1; then "
        "    echo 'PDR-004: observed=imdsv2'; "
        "  else "
        "    echo 'PDR-004: observed=unknown'; "
        "  fi; "
        "fi"
    ),
    "PDR-005": (
        "Enclave / CVM started",
        "if command -v nitro-cli >/dev/null 2>&1; then "
        "  n=$(nitro-cli describe-enclaves 2>/dev/null | grep -c '\"EnclaveID\"'); "
        "  echo \"PDR-005: observed=$n\"; "
        "elif [ -e /sys/firmware/efi/efivars ] && [ -e /dev/sev-guest ]; then "
        "  echo 'PDR-005: observed=snp-guest'; "
        "elif [ -e /dev/tdx_guest ] || [ -e /dev/tdx-guest ]; then "
        "  echo 'PDR-005: observed=tdx-guest'; "
        "elif [ -e /dev/sgx_enclave ]; then "
        "  echo 'PDR-005: observed=sgx-enclave'; "
        "else echo 'PDR-005: observed=missing'; fi"
    ),
    "PDR-006": (
        "Host proxy systemd unit active",
        "if systemctl is-active --quiet host-proxy.service 2>/dev/null; then "
        "  echo 'PDR-006: observed=active'; "
        "elif systemctl is-active --quiet tee-crafter-host-proxy.service 2>/dev/null; then "
        "  echo 'PDR-006: observed=active'; "
        "else echo 'PDR-006: observed=inactive'; fi"
    ),
    "PDR-007": (
        "vsock-proxy allowlist count",
        # The setup script writes
        #   allowlist:
        #     - {address: kms.<region>.amazonaws.com, port: 443}
        # so allowlist entries are indented with two spaces.  Match the
        # same shape the setup script itself uses to gate the install
        # (``grep -c '^[[:space:]]*-[[:space:]]*{address'``).  ``sudo`` is
        # required when SSM runs as ``ssm-user``: the file is mode 0644
        # but the parent dir is 0750 on AL2023 hardened images.
        "f=/etc/nitro_enclaves/vsock-proxy.yaml; "
        "if sudo test -f \"$f\" 2>/dev/null || [ -f \"$f\" ]; then "
        "  if [ -r \"$f\" ]; then "
        "    n=$(grep -cE '^[[:space:]]*-[[:space:]]*\\{' \"$f\" 2>/dev/null | tr -d ' '); "
        "  else "
        "    n=$(sudo grep -cE '^[[:space:]]*-[[:space:]]*\\{' \"$f\" 2>/dev/null | tr -d ' '); "
        "  fi; "
        "  echo \"PDR-007: observed=${n:-0}\"; "
        "else echo 'PDR-007: observed=missing'; fi"
    ),
    "PDR-008": (
        "No SSH authorized_keys on host",
        "n=0; for u in $(awk -F: '$3>=1000{print $1}' /etc/passwd 2>/dev/null); do "
        "  d=$(getent passwd \"$u\" | cut -d: -f6); "
        "  if [ -s \"$d/.ssh/authorized_keys\" ]; then n=$((n+1)); fi; "
        "done; echo \"PDR-008: observed=$n\""
    ),
    "PDR-009": (
        "Systemd hardening flags loaded",
        # PDR-009 has two valid evidence shapes depending on the flow:
        #
        #   (a) "deploy" — the platform service (tee-crafter-snp /
        #       tdx / sgx / gpu-cc / nitro-enclaves-vsock-proxy) is
        #       the runtime, and ships a systemd hardening cocktail
        #       (ProtectSystem=strict, PrivateTmp=yes, IPAddressDeny,
        #       RestrictAddressFamilies, etc).
        #
        #   (b) "deploy-container" — the visible unit is
        #       tee-crafter-container.service, which intentionally
        #       has *no* systemd hardening because its ExecStart is
        #       `docker run --security-opt seccomp=... --security-opt
        #       apparmor=... --cap-drop ALL --read-only ...`.  The
        #       hardening lives at the docker layer.
        #
        # We scan every candidate unit, pick the one with the
        # strongest evidence, and *also* inspect ``systemctl cat
        # tee-crafter-container.service`` so the container-layer
        # confinement is visible.  Output:
        #   observed=<systemd-line>;CONTAINER_FLAGS=<docker-flags>;
        #     UNIT=<picked-unit>
        "best_unit=''; best_score=-1; best_props=''; "
        "for cand in host-proxy.service tee-crafter-host-proxy.service "
        "nitro-enclaves-vsock-proxy.service "
        "tee-crafter-snp.service tee-crafter-tdx.service "
        "tee-crafter-sgx.service sgx-enclave.service "
        "tee-crafter-gpu-cc.service tee-crafter-container.service "
        "tee-crafter-siem.service; do "
        "  if ! systemctl show \"$cand\" -p FragmentPath 2>/dev/null "
        "    | grep -q '/etc/systemd/system'; then continue; fi; "
        # IMPORTANT: do NOT request -p SystemCallFilter here.  Our
        # platform units ship a 3-4 kB seccomp allowlist via
        # SystemCallFilter and the SSM RunCommand stdout buffer
        # truncates at ~24 kB across all probes, which would
        # silently lose every property listed after it (including
        # the ones we score below).  Skip it.  We instead capture a
        # one-bit "filter present" flag with a separate query.
        "  p=$(systemctl show \"$cand\" "
        "    -p IPAddressDeny -p IPAddressAllow "
        "    -p MemoryDenyWriteExecute "
        "    -p ProtectSystem -p ProtectHome -p PrivateTmp "
        "    -p NoNewPrivileges -p RestrictAddressFamilies "
        "    -p LockPersonality -p RestrictRealtime -p RestrictSUIDSGID "
        "    -p RestrictNamespaces -p ProtectKernelModules "
        "    -p ProtectControlGroups -p ProtectKernelLogs "
        "    -p ProtectHostname -p UMask -p RemoveIPC "
        "    -p PrivateDevices -p ProtectClock -p KeyringMode "
        "    2>/dev/null | tr '\\n' ';'); "
        "  scf=$(systemctl show \"$cand\" -p SystemCallFilter 2>/dev/null "
        "    | head -c 30); "
        "  [ -n \"$scf\" ] && [ \"$scf\" != 'SystemCallFilter=' ] "
        "    && p=\"${p}SystemCallFilter=present;\"; "
        "  score=0; "
        "  echo \"$p\" | grep -q 'IPAddressDeny=' && [ \"$(echo \\\"$p\\\" | grep -o 'IPAddressDeny=[^;]*')\" != 'IPAddressDeny=' ] && score=$((score+2)); "
        "  echo \"$p\" | grep -q 'ProtectSystem=strict' && score=$((score+2)); "
        "  echo \"$p\" | grep -q 'PrivateTmp=yes' && score=$((score+1)); "
        "  echo \"$p\" | grep -q 'RestrictAddressFamilies=AF_' && score=$((score+1)); "
        "  echo \"$p\" | grep -q 'NoNewPrivileges=yes' && score=$((score+1)); "
        "  echo \"$p\" | grep -q 'LockPersonality=yes' && score=$((score+1)); "
        "  echo \"$p\" | grep -q 'MemoryDenyWriteExecute=yes' && score=$((score+2)); "
        "  echo \"$p\" | grep -q 'RestrictNamespaces=yes' && score=$((score+1)); "
        "  if [ \"$score\" -gt \"$best_score\" ]; then "
        "    best_score=$score; best_unit=$cand; best_props=$p; "
        "  fi; "
        "done; "
        "if [ -z \"$best_unit\" ]; then echo 'PDR-009: observed=no-tee-unit'; exit 0; fi; "
        # Container-layer confinement (docker --security-opt flags).
        # Even when the platform unit was picked, we still surface
        # the container layer so an auditor sees the full stack.
        "cflags=''; "
        "if [ -f /etc/systemd/system/tee-crafter-container.service ] "
        "  || [ -f /etc/systemd/system/tee-crafter-container-batch.service ]; then "
        "  cunit=tee-crafter-container.service; "
        "  [ -f /etc/systemd/system/tee-crafter-container-batch.service ] "
        "    && cunit=tee-crafter-container-batch.service; "
        "  ec=$(systemctl cat \"$cunit\" 2>/dev/null "
        "    | tr -d '\\\\' | tr '\\n' ' '); "
        "  echo \"$ec\" | grep -q 'security-opt no-new-privileges' "
        "    && cflags=\"${cflags}no-new-privileges \"; "
        "  echo \"$ec\" | grep -q 'security-opt seccomp=' "
        "    && cflags=\"${cflags}seccomp \"; "
        "  echo \"$ec\" | grep -q 'security-opt apparmor=' "
        "    && cflags=\"${cflags}apparmor \"; "
        "  echo \"$ec\" | grep -q 'cap-drop ALL' "
        "    && cflags=\"${cflags}cap-drop-all \"; "
        "  echo \"$ec\" | grep -q 'read-only' && cflags=\"${cflags}read-only \"; "
        "  echo \"$ec\" | grep -q 'pids-limit' && cflags=\"${cflags}pids-limit \"; "
        "fi; "
        "echo \"PDR-009: observed=${best_props}CONTAINER_FLAGS=${cflags};UNIT=${best_unit}\""
    ),
    "PDR-010": (
        "No tee_enclave SUDO escape in logs",
        "n=$(journalctl -u sudo --no-pager 2>/dev/null | "
        "grep -ciE 'tee_enclave.*COMMAND' || true); "
        "echo \"PDR-010: observed=$n\""
    ),
    "PDR-011": (
        "Time sync OK",
        "if command -v chronyc >/dev/null 2>&1; then "
        "  s=$(chronyc tracking 2>/dev/null | "
        "    awk -F: '/Leap status/{gsub(/ /,\"\",$2); print $2}'); "
        "  echo \"PDR-011: observed=$s\"; "
        "elif command -v timedatectl >/dev/null 2>&1; then "
        "  s=$(timedatectl show -p NTPSynchronized --value 2>/dev/null); "
        "  echo \"PDR-011: observed=$s\"; "
        "else echo 'PDR-011: observed=unknown'; fi"
    ),
}


def run_post_deploy_probes(
    audit: BuildAuditTrail,
    *,
    tee_platform: str,
    build_dir: str,
    run_remote: Optional[RunRemoteFn],
    only: Optional[List[str]] = None,
) -> Dict[str, ProbeResult]:
    """Execute the post-deploy probe batch on the instance.

    *audit* receives a single ``PDR-001`` row (management plane reachable?)
    plus one row per executed probe.  When *run_remote* is ``None`` we
    emit ``PDR-001=warn`` and short-circuit — the cloud management
    plane was unreachable.

    Returns a dict of ``check_id -> ProbeResult`` so callers can chain
    further conditional behaviour (e.g. skip a follow-up step when a
    probe reports a fail).
    """
    results: Dict[str, ProbeResult] = {}
    probe_dir = os.path.join(build_dir, "probes")
    os.makedirs(probe_dir, exist_ok=True)

    if run_remote is None:
        audit.record_check(
            "Phase 5: Post-Deploy",
            "Management plane reachable (SSM/Bastion/IAP)",
            "PDR-001",
            verdict=None,
            observed=False,
            note="run_remote handle unavailable",
        )
        return results

    # PDR-001 — minimal connectivity check.  Just ask for an echo.
    ok, out, err = _try_run(run_remote, "echo PDR-001: observed=ok")
    _write_probe_log(probe_dir, "PDR-001", out, err)
    if ok and "PDR-001: observed=ok" in (out or ""):
        audit.record_check(
            "Phase 5: Post-Deploy",
            "Management plane reachable (SSM/Bastion/IAP)",
            "PDR-001",
            observed=True,
            evidence_pointer="probes/PDR-001.txt",
        )
        results["PDR-001"] = ProbeResult("PDR-001", True, True, out)
    else:
        audit.record_check(
            "Phase 5: Post-Deploy",
            "Management plane reachable (SSM/Bastion/IAP)",
            "PDR-001",
            observed=False,
            note=(err or out or "no output")[:200],
            evidence_pointer="probes/PDR-001.txt",
        )
        results["PDR-001"] = ProbeResult(
            "PDR-001", False, False, out, note=err[:200])
        return results

    # Run the remaining probes.
    for cid, (title, script) in _PROBES.items():
        if only and cid not in only:
            continue
        if not _platform_applies(cid, tee_platform):
            continue
        ok, out, err = _try_run(run_remote, script)
        _write_probe_log(probe_dir, cid, out, err)
        observed = _parse_observed(out, cid)
        verdict, note_suffix = _interpret_probe(cid, observed, tee_platform)
        note = f"raw={(out or err).strip()[-180:]}"
        if note_suffix:
            note = f"{note_suffix}; {note}"
        audit.record_check(
            "Phase 5: Post-Deploy", title, cid,
            observed=observed,
            verdict=verdict,
            evidence_pointer=f"probes/{cid}.txt",
            note=note,
        )
        results[cid] = ProbeResult(
            cid, ok=bool(ok), observed=observed,
            raw_output=out, note=err[:200],
        )
    return results


# --------------------------- internals ----------------------------------

def _platform_applies(check_id: str, tee_platform: str) -> bool:
    """Quick filter so e.g. PDR-007 only runs on nitro-aws."""
    if check_id == "PDR-006" and tee_platform != "nitro-aws":
        return False
    if check_id == "PDR-007" and tee_platform != "nitro-aws":
        return False
    if check_id == "PDR-004" and not tee_platform.endswith("-aws"):
        return False
    return True


def _try_run(run_remote: RunRemoteFn, script: str) -> Tuple[bool, str, str]:
    try:
        ok, out, err = run_remote(script)
        return bool(ok), (out or ""), (err or "")
    except Exception as exc:
        logger.warning("probe run_remote failed: %s", exc)
        return False, "", f"{type(exc).__name__}: {exc}"


def _parse_observed(text: str, check_id: str) -> Optional[str]:
    if not text:
        return None
    for line in text.splitlines():
        s = line.strip()
        prefix = f"{check_id}: observed="
        if s.startswith(prefix):
            return s[len(prefix):].strip()
    return None


def _interpret_probe(
    check_id: str,
    observed: Optional[str],
    tee_platform: str = "",
):
    """Turn a parsed observed value into a Verdict for the ledger.

    Returns ``(Verdict | None, note_suffix)`` — the Verdict overrides
    default derivation when not ``None``; ``note_suffix`` is prepended
    to the ledger row's ``raw=…`` note so operators can see why a
    platform-specific verdict was chosen (e.g. *expected GCP IAP-tunnel
    SSH key*).
    """
    from tee_crafter.core.audit import Verdict
    if observed is None:
        return Verdict.WARN, ""

    if check_id == "PDR-002":
        return ((Verdict.PASS if observed.lower() == "done" else Verdict.FAIL), "")
    if check_id == "PDR-003":
        return ((Verdict.PASS if observed.startswith("active") else Verdict.FAIL), "")
    if check_id == "PDR-004":
        return ((Verdict.PASS if observed == "imdsv2" else Verdict.FAIL), "")
    if check_id == "PDR-005":
        return ((Verdict.PASS
                 if observed and observed not in {"missing", "0"}
                 else Verdict.FAIL), "")
    if check_id == "PDR-006":
        return ((Verdict.PASS if observed == "active" else Verdict.FAIL), "")
    if check_id == "PDR-007":
        try:
            return ((Verdict.PASS if int(observed) == 1 else Verdict.FAIL), "")
        except ValueError:
            return (Verdict.WARN, "")
    if check_id == "PDR-008":
        # Platform-aware: AWS uses SSM with no SSH on the host so 0 is
        # the only safe value.  GCP propagates the deployer's SSH key
        # via OS Login / metadata when we use IAP tunnel — a single
        # authorized_keys file for the deployment user is expected,
        # not an indicator of compromise.  Azure Bastion's "ssh via
        # browser" mode may also drop a transient key.  We accept ≤ 1
        # on GCP/Azure and WARN on more, FAIL only when AWS sees any.
        try:
            n = int(observed)
        except ValueError:
            return (Verdict.WARN, "")
        if tee_platform.endswith("-aws") or tee_platform == "nitro-aws":
            return ((Verdict.PASS if n == 0 else Verdict.FAIL), "")
        if tee_platform.endswith("-gcp"):
            if n <= 1:
                return (Verdict.PASS,
                        "GCP IAP-tunnel / OS Login propagates the "
                        "deployer SSH key to ~/.ssh/authorized_keys; "
                        "one key is expected")
            return (Verdict.WARN, "more than one user has SSH keys")
        if tee_platform.endswith("-azure"):
            if n <= 1:
                return (Verdict.PASS,
                        "Azure Bastion may transiently provision an "
                        "SSH key; one is expected")
            return (Verdict.WARN, "more than one user has SSH keys")
        return ((Verdict.PASS if n == 0 else Verdict.WARN), "")
    if check_id == "PDR-009":
        # PDR-009 accepts evidence at either layer of the stack:
        #
        #   (1) systemd hardening on the platform unit — the cocktail
        #       our snp/tdx/sgx/gpu-cc/nitro-host-proxy unit files all
        #       ship (ProtectSystem=strict + PrivateTmp + IPAddressDeny
        #       + RestrictAddressFamilies + LockPersonality, etc).
        #
        #   (2) container-layer hardening for the deploy-container
        #       flow — the docker `--security-opt` flags installed by
        #       container.service.template (seccomp + AppArmor +
        #       no-new-privileges + cap-drop ALL + read-only + pids-
        #       limit).  When the platform unit isn't present (pure
        #       container deploy) this is the entire trust surface
        #       and we accept it on its own.
        #
        # WARN is only emitted when NEITHER layer is detectable.
        if "no-tee-unit" in observed:
            return (Verdict.WARN, "no TEE-Crafter systemd unit found")
        has_protect_strict = "ProtectSystem=strict" in observed
        has_private_tmp = "PrivateTmp=yes" in observed
        # RestrictAddressFamilies — accept any AF_* allowlist or
        # ``none``.  Empty ``RestrictAddressFamilies=`` means the
        # unit allows everything (so we do NOT count it).
        has_af_restrict = (
            "RestrictAddressFamilies=AF_" in observed
            or "RestrictAddressFamilies=none" in observed
        )
        # IPAddressDeny — accept ANY non-empty deny value.  Our
        # snp/tdx/sgx units ship ``IPAddressDeny=link-local
        # multicast`` (denies 169.254/16 + ff00::/8) while our
        # Nitro host-proxy ships ``IPAddressDeny=any``, and our
        # platform units may also expand it to explicit CIDRs
        # (``IPAddressDeny=::/0 0.0.0.0/0``, or
        # ``IPAddressDeny=169.254.0.0/16 fe80::/64 224.0.0.0/4
        # ff00::/8``).  Anything other than the empty value is
        # evidence of intentional network confinement; the empty
        # value would mean "allow everything".
        import re as _re
        ipd_m = _re.search(r"IPAddressDeny=([^;]*)", observed)
        ipd_value = (ipd_m.group(1) if ipd_m else "").strip()
        has_ip_deny = bool(ipd_value)
        has_mdwx = "MemoryDenyWriteExecute=yes" in observed
        has_nnp = "NoNewPrivileges=yes" in observed
        has_lockp = "LockPersonality=yes" in observed
        has_rnsp = "RestrictNamespaces=yes" in observed
        has_pkm = "ProtectKernelModules=yes" in observed
        has_pkl = "ProtectKernelLogs=yes" in observed
        has_pcg = "ProtectControlGroups=yes" in observed
        has_pcl = "ProtectClock=yes" in observed
        has_scf = "SystemCallFilter=present" in observed
        # Layer 1: platform-unit systemd cocktail.  ProtectSystem +
        # PrivateTmp + IPAddressDeny is the minimum; any of the
        # additional kernel-protect / personality / namespace bits
        # confirms intentional hardening.
        extras = sum(
            1 for x in (has_nnp, has_lockp, has_rnsp, has_pkm, has_pkl,
                        has_pcg, has_pcl, has_scf, has_mdwx)
            if x
        )
        systemd_cocktail = (
            has_protect_strict and has_private_tmp and has_ip_deny
            and (has_af_restrict or extras >= 3)
        )
        # Standalone-strong unit (e.g. Nitro vsock-proxy with
        # MemoryDenyWriteExecute=yes + IPAddressDeny=any).
        systemd_strong = ipd_value == "any" or has_mdwx
        # Layer 2: container-layer (docker --security-opt) cocktail.
        c_seccomp = "seccomp" in observed
        c_apparmor = "apparmor" in observed
        c_nnp = "no-new-privileges" in observed
        c_capdrop = "cap-drop-all" in observed
        # `--read-only` is deliberately NOT part of the required cocktail: the
        # batch unit lifts it so the runner can capture an output diff
        # (resources/systemd/container.batch.service.template).  It is still
        # reported, because the PASS note used to assert "+ read-only"
        # unconditionally — naming a control the predicate never checked.
        c_readonly = "read-only" in observed
        container_cocktail = (
            c_seccomp and c_apparmor and c_nnp and c_capdrop
        )
        if systemd_cocktail or systemd_strong:
            note = (
                f"systemd hardening cocktail present "
                f"(protect_strict={has_protect_strict}, "
                f"private_tmp={has_private_tmp}, "
                f"af_restrict={has_af_restrict}, "
                f"ip_deny={ipd_value[:40]!r}, mdwx={has_mdwx}, "
                f"nnp={has_nnp}, lockp={has_lockp}, rnsp={has_rnsp}, "
                f"pkm={has_pkm}, pkl={has_pkl}, scf={has_scf})"
            )
            return (Verdict.PASS, note)
        if container_cocktail:
            return (
                Verdict.PASS,
                "container-layer hardening present "
                "(docker seccomp + AppArmor + no-new-privileges + "
                f"cap-drop ALL; read_only={c_readonly})",
            )
        return (Verdict.WARN, "expected hardening cocktail not detected")
    if check_id == "PDR-010":
        try:
            return ((Verdict.PASS if int(observed) == 0 else Verdict.FAIL), "")
        except ValueError:
            return (Verdict.WARN, "")
    if check_id == "PDR-011":
        lower = observed.lower()
        return ((Verdict.PASS
                 if lower in {"normal", "yes", "true", "1"}
                 else Verdict.WARN), "")
    return (None, "")


def _write_probe_log(probe_dir: str, check_id: str, out: str, err: str) -> None:
    try:
        path = os.path.join(probe_dir, f"{check_id}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("# stdout\n")
            f.write(out or "")
            if err:
                f.write("\n# stderr\n")
                f.write(err)
    except OSError:
        pass


__all__ = ["ProbeResult", "run_post_deploy_probes"]
