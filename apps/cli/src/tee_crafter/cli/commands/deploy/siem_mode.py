"""CLI plumbing for SIEM / continuous-attestation export.

Public CLI surface is just ``--siem <provider>`` + ``--siem-config
<path/to/config.json>``.  This module loads the JSON document into a
:class:`SiemConfig`, validates it, writes ``siem.json`` + ``siem.env``
to the staged build directory (and mirrors into ``build_dir/app/`` when
present so CVM/SNP S3 bundles still ship the policy), and records an
audit entry.

In-TEE, ``tee_crafter.templates.common.tee_crafter_runtime_bootstrap``
reads the same env at startup and constructs the appropriate
:class:`AuditEventExporter` plus a background
:class:`ContinuousAttestor` thread.  The user's app does not need to
import or wire anything: the bootstrap module is staged automatically
into every build.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from tee_crafter.core.env_flags import interpret


#: Selectable ``--siem`` providers.  Must stay in step with the exporter
#: factory the sidecar actually runs,
#: ``templates/common/siem_export.py::_build_exporter``, which raises
#: ``RuntimeError("unsupported SIEM provider for sidecar: ...")`` for anything
#: it cannot build.
#:
#: ``cloudwatch`` and ``azure-monitor`` were removed after a live nitro-aws
#: deploy showed what offering an unbuildable provider costs: the sidecar
#: raised on every start and crash-looped 28 times while the deploy reported
#: "SIEM sidecar active - events streaming", no log group was ever created, and
#: the operator's only clue was a bare "RuntimeError" with the message
#: discarded.  Terraform had meanwhile provisioned a CloudWatch Logs interface
#: endpoint and a ``logs:PutLogEvents`` grant for a stream nothing wrote to.
#:
#: Exporter classes for both do exist under ``core/audit/exporters/`` and are
#: wired into ``tee_crafter_runtime_bootstrap._build_exporter_from_env``, so
#: adding either back is a matter of teaching the *sidecar* factory about it --
#: not new protocol work.  Until then they are not offered.
SIEM_PROVIDERS = (
    "none",
    "syslog-cef",
    "splunk-hec",
    "datadog",
)

#: The subset of :data:`SIEM_PROVIDERS` the in-TEE sidecar can actually build an
#: exporter for.  Must stay in step with
#: ``templates/common/siem_export.py::_build_exporter``, which raises
#: ``RuntimeError("unsupported SIEM provider for sidecar: ...")`` for anything
#: else.
#:
#: ``cloudwatch`` and ``azure-monitor`` are deliberately absent: they are
#: accepted by ``--siem``, documented in ``docs/siem.md``'s provider table, and
#: fully provisioned by Terraform (``cloudwatch`` even gets a CloudWatch Logs
#: interface endpoint and a ``logs:PutLogEvents`` grant) — but no exporter class
#: exists, so the sidecar raised on every start and crash-looped while the
#: deploy reported "SIEM sidecar active — events streaming". Observed on a live
#: nitro-aws deploy (2026-08-20): 28 restarts, zero events, no log group
#: created. ``byok-sandbox``'s own provider matrix lists both as "planned".
#:
#: Validation refuses them here rather than at first export so the operator
#: learns before a 20-minute deploy, not after.
SIDECAR_IMPLEMENTED_PROVIDERS = frozenset({
    "syslog-cef",
    "splunk-hec",
    "datadog",
})

# How outbound traffic from the TEE to the SIEM should be provisioned.
#
#   ``auto``                Pick the right thing for the provider:
#                             - cloudwatch  -> private (Interface VPC Endpoint)
#                             - syslog-cef  -> none    (assume in-VPC collector)
#                             - others      -> public  (NAT, optionally
#                                                       restricted by
#                                                       ``egress_allowlist_cidrs``)
#   ``private``             Force private connectivity only.  Fails closed
#                           if the provider needs the public internet.
#   ``public``              Force NAT egress.  When
#                           ``egress_allowlist_cidrs`` is non-empty, the
#                           host SG / NSG / GCP firewall is locked down
#                           so the only public destinations on 443/tcp
#                           are those CIDRs.
#   ``none``                Don't touch any network plumbing.  The
#                           operator owns the egress story (e.g. a
#                           pre-existing forward proxy, transit gateway,
#                           or third-party SASE).
SIEM_EGRESS_MODES = ("auto", "private", "public", "none")


@dataclass
class SiemConfig:
    """Serializable SIEM exporter configuration.

    Only fields relevant to *provider* are populated; everything else is
    left blank.  The dataclass is deliberately permissive at construction
    time and validated by :meth:`validate` so that
    ``--siem none`` always succeeds (no-op).
    """

    provider: str = "none"
    interval_seconds: int = 60
    sign_events: bool = True
    # Production posture: SIEM is fail-CLOSED by default — if the
    # continuous-attestation exporter goes dark, the workload refuses
    # new requests rather than serve traffic with no audit trail.
    # Set ``fail_open: true`` in siem.json (dev hatch) to revert to
    # log-and-keep-serving behaviour for prototyping / eval workloads.
    fail_open: bool = False

    # syslog-cef
    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    facility: int = 13
    hostname: str = ""

    # splunk-hec
    endpoint: str = ""
    token: str = ""
    index: str = "main"
    sourcetype: str = "tee_crafter:attestation"
    source: str = "tee-crafter"

    # datadog
    api_key: str = ""
    site: str = "datadoghq.com"
    service: str = "tee-crafter"
    ddsource: str = "tee-crafter"
    env: str = "prod"

    # azure-monitor
    dce_url: str = ""
    dcr_immutable_id: str = ""
    stream_name: str = ""

    # cloudwatch
    log_group: str = ""
    log_stream: str = ""
    region: str = ""

    # Egress / network-plumbing fields.  These do not change exporter
    # behaviour at runtime; they're consumed by
    # ``siem_egress_terraform.translate_to_terraform`` to set TF_VAR_*
    # variables and emit the right resources alongside the platform's
    # main.tf.
    egress_mode: str = "auto"
    egress_allowlist_cidrs: List[str] = field(default_factory=list)
    egress_ports: List[int] = field(default_factory=lambda: [443])

    extra: Dict[str, str] = field(default_factory=dict)
    """Arbitrary additional knobs passed verbatim into the exporter."""

    def validate(self) -> List[str]:
        """Validate the loaded ``--siem-config`` JSON.

        Error messages name the JSON keys that the config file should
        contain (the per-field CLI flags ``--siem-host`` / ``--siem-token``
        / ``--siem-egress`` / ... are no longer part of the public CLI).
        """
        errs: List[str] = []
        if self.provider == "none":
            return errs
        if self.provider not in SIEM_PROVIDERS:
            errs.append(f"--siem must be one of {SIEM_PROVIDERS}")
            return errs
        if self.interval_seconds <= 0:
            errs.append("siem-config: 'interval_seconds' must be > 0")
        if self.provider == "syslog-cef":
            if not self.host:
                errs.append("siem-config: 'host' is required for syslog-cef")
            if self.port <= 0 or self.port > 65535:
                errs.append("siem-config: 'port' must be a valid TCP/UDP port for syslog-cef")
            if self.protocol not in ("udp", "tcp"):
                errs.append("siem-config: 'protocol' must be 'udp' or 'tcp' for syslog-cef")
        elif self.provider == "splunk-hec":
            if not (self.endpoint.startswith("http://") or self.endpoint.startswith("https://")):
                errs.append("siem-config: 'endpoint' must be http(s):// for splunk-hec")
            if not self.token:
                errs.append("siem-config: 'token' is required for splunk-hec")
        elif self.provider == "datadog":
            if not self.api_key:
                errs.append("siem-config: 'api_key' is required for datadog")
        # No azure-monitor / cloudwatch branches: both were removed from
        # SIEM_PROVIDERS above, so the earlier membership check rejects them
        # before reaching here.  Their per-provider config fields are kept on
        # the dataclass (dce_url, dcr_immutable_id, stream_name, log_group,
        # log_stream) so an operator's existing --siem-config JSON still parses
        # rather than blowing up on unknown keys, but nothing consumes them.
        if self.egress_mode not in SIEM_EGRESS_MODES:
            errs.append(
                f"siem-config: 'egress_mode' must be one of {SIEM_EGRESS_MODES}; got {self.egress_mode!r}"
            )
        for cidr in self.egress_allowlist_cidrs:
            if "/" not in cidr or " " in cidr:
                errs.append(f"siem-config: 'egress_allowlist_cidrs' entry {cidr!r} is not a valid CIDR")
        for p in self.egress_ports:
            if not (0 < int(p) <= 65535):
                errs.append(f"siem-config: 'egress_ports' entry {p!r} is not a valid TCP port")
        return errs

    def to_env(self) -> Dict[str, str]:
        """Render the config as systemd-EnvironmentFile-compatible vars.

        Empty/zero values are omitted so the runtime can rely on
        ``os.environ.get`` defaults.
        """
        e: Dict[str, str] = {
            "TEE_CRAFTER_SIEM": self.provider,
            "TEE_CRAFTER_SIEM_INTERVAL_SECONDS": str(self.interval_seconds),
            "TEE_CRAFTER_SIEM_SIGN_EVENTS": "1" if self.sign_events else "0",
            "TEE_CRAFTER_SIEM_FAIL_OPEN": "1" if self.fail_open else "0",
        }
        # Provider-specific fields.
        if self.host:
            e["TEE_CRAFTER_SIEM_HOST"] = self.host
        if self.port:
            e["TEE_CRAFTER_SIEM_PORT"] = str(self.port)
        if self.protocol and self.provider == "syslog-cef":
            e["TEE_CRAFTER_SIEM_PROTOCOL"] = self.protocol
        if self.facility and self.provider == "syslog-cef":
            e["TEE_CRAFTER_SIEM_FACILITY"] = str(self.facility)
        if self.hostname:
            e["TEE_CRAFTER_SIEM_HOSTNAME"] = self.hostname

        if self.endpoint:
            e["TEE_CRAFTER_SIEM_ENDPOINT"] = self.endpoint
        if self.token:
            e["TEE_CRAFTER_SIEM_TOKEN"] = self.token
        if self.index and self.provider == "splunk-hec":
            e["TEE_CRAFTER_SIEM_INDEX"] = self.index
        if self.sourcetype and self.provider == "splunk-hec":
            e["TEE_CRAFTER_SIEM_SOURCETYPE"] = self.sourcetype
        if self.source and self.provider in ("splunk-hec",):
            e["TEE_CRAFTER_SIEM_SOURCE"] = self.source

        if self.api_key:
            e["TEE_CRAFTER_SIEM_API_KEY"] = self.api_key
        if self.site and self.provider == "datadog":
            e["TEE_CRAFTER_SIEM_SITE"] = self.site
        if self.service and self.provider == "datadog":
            e["TEE_CRAFTER_SIEM_SERVICE"] = self.service
        if self.ddsource and self.provider == "datadog":
            e["TEE_CRAFTER_SIEM_DDSOURCE"] = self.ddsource
        if self.env and self.provider == "datadog":
            e["TEE_CRAFTER_SIEM_ENV"] = self.env

        if self.dce_url:
            e["TEE_CRAFTER_SIEM_DCE_URL"] = self.dce_url
        if self.dcr_immutable_id:
            e["TEE_CRAFTER_SIEM_DCR_IMMUTABLE_ID"] = self.dcr_immutable_id
        if self.stream_name:
            e["TEE_CRAFTER_SIEM_STREAM_NAME"] = self.stream_name

        if self.log_group:
            e["TEE_CRAFTER_SIEM_LOG_GROUP"] = self.log_group
        if self.log_stream:
            e["TEE_CRAFTER_SIEM_LOG_STREAM"] = self.log_stream
        if self.region:
            e["TEE_CRAFTER_SIEM_REGION"] = self.region

        for k, v in (self.extra or {}).items():
            e[f"TEE_CRAFTER_SIEM_X_{k.upper()}"] = str(v)
        return e

    def describe(self) -> str:
        if self.provider == "none":
            return "SIEM export disabled."
        if self.provider == "syslog-cef":
            return f"syslog-cef -> {self.host}:{self.port}/{self.protocol} every {self.interval_seconds}s"
        if self.provider == "splunk-hec":
            return f"splunk-hec -> {self.endpoint} index={self.index} every {self.interval_seconds}s"
        if self.provider == "datadog":
            return f"datadog -> site={self.site} service={self.service} every {self.interval_seconds}s"
        if self.provider == "azure-monitor":
            return (f"azure-monitor -> {self.dce_url} dcr={self.dcr_immutable_id} "
                    f"stream={self.stream_name} every {self.interval_seconds}s")
        if self.provider == "cloudwatch":
            return (f"cloudwatch -> group={self.log_group} stream={self.log_stream} "
                    f"region={self.region} every {self.interval_seconds}s")
        return f"{self.provider} (unknown)"


def build_siem_config(*, provider: str,
                      raw_config_path: Optional[str] = None) -> SiemConfig:
    """Construct a :class:`SiemConfig` from the slim public CLI surface.

    The public CLI only exposes ``--siem <provider>`` + ``--siem-config
    <path>``.  When ``provider`` is anything other than ``"none"`` and
    ``raw_config_path`` is given, every field is loaded from that JSON
    file.  When ``provider == "none"`` a no-op config is returned.

    Programmatic callers (tests, the SaaS orchestrator) may still pass a
    JSON document directly via ``raw_config_path``.
    """
    p = (provider or "none").lower()
    if p == "none":
        return SiemConfig(provider="none")

    if not raw_config_path:
        raise ValueError(
            f"--siem={p} requires --siem-config <path/to/config.json> "
            "(provider, endpoint, token, egress, etc.)"
        )

    with open(raw_config_path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError(f"--siem-config {raw_config_path}: must be a JSON object")
    # CLI provider wins over any value embedded in the JSON.
    doc.setdefault("provider", p)
    if doc.get("provider", "none").lower() != p:
        raise ValueError(
            f"--siem-config provider {doc['provider']!r} does not match "
            f"--siem {p!r}"
        )
    cfg = SiemConfig(**{k: v for k, v in doc.items()
                        if k in SiemConfig.__dataclass_fields__})
    if "extra" in doc and isinstance(doc["extra"], dict):
        cfg.extra = {str(k): str(v) for k, v in doc["extra"].items()}
    if cfg.provider == "syslog-cef" and not cfg.port:
        cfg.port = 514

    # syslog-cef speaks to its collector on `port`, not on 443.  `egress_ports`
    # defaults to [443] (right for the HTTPS providers), so leaving it alone
    # produced an egress security group that allowed 443 outbound while the
    # exporter dialled 514 — i.e. the *default* syslog-cef configuration
    # blocked its own traffic.
    #
    # Measured on a real nitro-aws deploy (2026-08-20) with a collector on
    # 6514: SG allowed only 443, the sidecar logged
    #   "syslog TCP socket to <ip>:6514 died (timeout); reconnecting"
    #   "exporter.emit failed: timeout"
    #   "emitted seq=-1 status=pass size=0 export=fail"
    # and the collector received zero bytes — while the deploy reported
    # "SIEM sidecar active — events streaming".
    #
    # Only fill it in when the operator did not say otherwise, so an explicit
    # egress_ports (e.g. a collector behind a proxy on 443) still wins.
    if cfg.provider == "syslog-cef" and "egress_ports" not in doc:
        cfg.egress_ports = [cfg.port]

    # Operator-side override.  ``TEE_CRAFTER_SIEM_FAIL_OPEN`` (set in
    # ``.env`` or the shell) lets a deployer force fail-closed posture
    # without editing the JSON config — this is the recommended way to
    # take a sandbox config (which ships ``fail_open: true`` for
    # prototyping) into production: leave the JSON untouched and set
    # ``TEE_CRAFTER_SIEM_FAIL_OPEN=0`` in ``.env``.  Setting the env
    # var to ``1`` similarly forces fail-open and is recorded as a
    # dev-hatch override on the SIEM-002 audit row.
    env_val = os.environ.get("TEE_CRAFTER_SIEM_FAIL_OPEN")
    if env_val is not None:
        env_val = env_val.strip().lower()
        _want = interpret(env_val)
        if _want is not None:
            cfg.fail_open = _want
    return cfg


# SIEM-SEC-2: a deny-list of env-var names whose *values* are treated
# as bearer secrets and stripped from the public (disk-resident) env
# file.  Anything matching this list lives only in ``siem.env`` (the
# tmpfs-relocated file) and NEVER in ``siem.env.public``.
SECRET_ENV_KEYS = frozenset({
    "TEE_CRAFTER_SIEM_TOKEN",       # splunk HEC
    "TEE_CRAFTER_SIEM_API_KEY",     # datadog
    "TEE_CRAFTER_SIEM_BEARER",      # azure-monitor static bearer
    "TEE_CRAFTER_SIEM_X_BEARER",
    "TEE_CRAFTER_SIEM_X_PASSWORD",
    "TEE_CRAFTER_SIEM_X_HMAC_KEY",
})


#: SIEM-SEC-2: the ONLY :class:`SiemConfig` fields allowed into ``siem.json``.
#: ``siem.json`` is written to the build dir, mirrored into ``app/``, shipped to
#: S3 inside ``app_bundle.tar.gz`` and never shredded — so it is an allowlist,
#: not a deny-list.  Adding a field to the dataclass must not silently publish
#: it; a new bearer credential is inert here until someone lists it.
#: ``token`` / ``api_key`` are deliberately absent.  Mirrors the redaction
#: :func:`byok_mode.write_byok_config` already applies to ``byok.json``.
NON_SECRET_CONFIG_KEYS = (
    "provider",
    "interval_seconds",
    "sign_events",
    "fail_open",
    # syslog-cef
    "host", "port", "protocol", "facility", "hostname",
    # splunk-hec
    "endpoint", "index", "sourcetype", "source",
    # datadog
    "site", "service", "ddsource", "env",
    # azure-monitor
    "dce_url", "dcr_immutable_id", "stream_name",
    # cloudwatch
    "log_group", "log_stream", "region",
    # egress plumbing
    "egress_mode", "egress_allowlist_cidrs", "egress_ports",
)


def public_config_view(cfg: "SiemConfig") -> Dict[str, Any]:
    """Serialisable, secret-free view of *cfg* for ``siem.json``.

    Secret-bearing fields are represented by presence only (``token_set``,
    ``api_key_set``) so an auditor can still tell a credential was configured
    without the credential leaving the tmpfs ``siem.env``.  Entries in
    ``extra`` are kept unless their env-var name is in
    :data:`SECRET_ENV_KEYS`.
    """
    doc: Dict[str, Any] = {}
    for key in NON_SECRET_CONFIG_KEYS:
        value = getattr(cfg, key, None)
        doc[key] = list(value) if isinstance(value, list) else value
    doc["token_set"] = bool(cfg.token)
    doc["api_key_set"] = bool(cfg.api_key)
    extra: Dict[str, str] = {}
    for k, v in (cfg.extra or {}).items():
        if f"TEE_CRAFTER_SIEM_X_{k.upper()}" in SECRET_ENV_KEYS:
            extra[k] = f"<redacted:{len(str(v))}b>"
        else:
            extra[k] = str(v)
    doc["extra"] = extra
    return doc


def split_env_secrets(env_data: Dict[str, str]) -> tuple[Dict[str, str], Dict[str, str]]:
    """Partition ``env_data`` into (secret, public) halves for SIEM-SEC-2.

    Public-half keys carry config that is innocuous if it leaks via a
    disk snapshot (provider name, endpoint URL, index, sourcetype, the
    fail-closed flag, the verify-ssl flag).  Secret-half keys carry
    bearer credentials and only ever land in
    ``/run/tee-crafter-{platform}/siem.env`` (tmpfs).
    """
    secrets_env: Dict[str, str] = {}
    public_env: Dict[str, str] = {}
    for k, v in env_data.items():
        if k in SECRET_ENV_KEYS:
            secrets_env[k] = v
        else:
            public_env[k] = v
    return secrets_env, public_env


def write_siem_config(build_dir: str, cfg: SiemConfig, *, enabled: bool) -> str:
    """Persist the SIEM config to *build_dir* and mirror into ``app/``.

    Emits THREE files per location:

    * ``siem.env``         — full env, **contains the bearer secret**.
                              Deploy-time installer relocates this to
                              ``/run/tee-crafter-{platform}/siem.env``
                              (tmpfs) and shreds the disk copy.  Mode
                              0600.
    * ``siem.env.public``  — same env *minus* the keys named in
                              :data:`SECRET_ENV_KEYS`.  Stays on disk;
                              survives reboot; pointing the systemd
                              unit at this file means non-secret SIEM
                              config remains available after a reboot
                              wipes /run.  Mode 0640.
    * ``siem.json``        — human-readable manifest built from the
                              :data:`NON_SECRET_CONFIG_KEYS` allowlist
                              (:func:`public_config_view`); 0600.  This file
                              rides ``app_bundle.tar.gz`` to S3 and is never
                              shredded, so it must not carry the bearer token.

    Returns the path to ``siem.json`` at the build_dir root.
    """
    os.makedirs(build_dir, exist_ok=True)
    doc: Dict[str, Any] = {
        "enabled": bool(enabled and cfg.provider != "none"),
        "provider": cfg.provider,
        "describe": cfg.describe(),
        "config": public_config_view(cfg),
    }
    env_data = cfg.to_env()
    env_data["TEE_CRAFTER_SIEM_ENABLED"] = "1" if doc["enabled"] else "0"

    # The collector's host and port, resolved once here rather than re-derived
    # by each consumer.  The Nitro enclave needs them explicitly: its egress is
    # a fixed vsock tunnel per destination, so it has to know which hostname to
    # redirect onto its collector loopback address, and it cannot parse a
    # Splunk URL or a Datadog site name for itself without duplicating this
    # logic inside the measured image.  Neither value is a secret, so both stay
    # in the public half.
    if doc["enabled"]:
        from tee_crafter.cli.deployment.common.siem_sidecar import collector_endpoint
        _host, _port = collector_endpoint(env_data)
        if _host:
            env_data["TEE_CRAFTER_SIEM_COLLECTOR_HOST"] = _host
            env_data["TEE_CRAFTER_SIEM_COLLECTOR_PORT"] = str(_port)

    secrets_env, public_env = split_env_secrets(env_data)

    def _write_triple(base: str) -> None:
        os.makedirs(base, exist_ok=True)
        jp = os.path.join(base, "siem.json")
        ep = os.path.join(base, "siem.env")
        ep_pub = os.path.join(base, "siem.env.public")
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, default=str)
        with open(ep, "w", encoding="utf-8") as f:
            for k, v in sorted(env_data.items()):
                f.write(f"{k}={v}\n")
        with open(ep_pub, "w", encoding="utf-8") as f:
            f.write(
                "# SIEM-SEC-2: non-secret SIEM config (provider, endpoint,\n"
                "# index, fail-closed/verify-ssl gates).  The token-bearing\n"
                "# half lives on tmpfs at /run/tee-crafter-<platform>/siem.env\n"
                "# and is never written to persistent disk after deploy.\n"
            )
            for k, v in sorted(public_env.items()):
                f.write(f"{k}={v}\n")
        try:
            os.chmod(ep, 0o600)
            os.chmod(jp, 0o600)
            os.chmod(ep_pub, 0o640)
        except Exception:
            pass

    # Build-dir copy lives in the new ``siem/`` subdir; the in-TEE bundle
    # staging copy under ``app/`` keeps its flat layout (uploader scripts
    # and the in-TEE runtime read from a flat directory).
    from tee_crafter.core.audit import build_layout as _layout
    _write_triple(_layout.siem_dir(build_dir))
    app_dir = os.path.join(build_dir, "app")
    if os.path.isdir(app_dir):
        _write_triple(app_dir)
    return _layout.siem_json(build_dir)


def record_siem_audit(audit, cfg: SiemConfig, *, enabled: bool) -> None:
    """Record the SIEM* verdict rows for the resolved exporter config."""
    if audit is None:
        return
    active = bool(enabled and cfg.provider != "none")
    try:
        audit.record(
            "SIEM Export",
            "Continuous-attestation exporter resolved",
            "info" if active else "skip",
            enabled=active,
            provider=cfg.provider,
            interval_seconds=cfg.interval_seconds,
            sign_events=cfg.sign_events,
            describe=cfg.describe(),
        )
    except Exception:
        return
    if not active:
        return
    try:
        audit.record_check(
            "SIEM Export", "SIEM provider resolved", "SIEM-001",
            expected=True,
            observed=cfg.provider in SIEM_PROVIDERS and cfg.provider != "none",
            note=f"provider={cfg.provider}",
        )
        env_override = os.environ.get("TEE_CRAFTER_SIEM_FAIL_OPEN")
        env_suffix = (
            f" [TEE_CRAFTER_SIEM_FAIL_OPEN={env_override!r}]"
            if env_override is not None else ""
        )
        audit.record_check(
            "SIEM Export", "fail_open observed value", "SIEM-002",
            expected=False, observed=bool(cfg.fail_open),
            note=(("fail-open posture (dev hatch)" if cfg.fail_open
                   else "fail-closed (production)") + env_suffix),
        )
        audit.record_check(
            "SIEM Export", "interval_seconds <= 60", "SIEM-005",
            expected=True,
            observed=(0 < int(cfg.interval_seconds) <= 60),
            note=f"{cfg.interval_seconds}s",
        )
        audit.record_check(
            "SIEM Export", "Events signed (sign_events=True)", "SIEM-006",
            expected=True, observed=bool(cfg.sign_events),
        )
        # SIEM-007 — egress narrow.  Lazily inspect the configured egress
        # CIDR list; the SiemConfig may not have it populated until
        # build_siem_egress_terraform() runs, so missing list → warn.
        cidrs = list(getattr(cfg, "egress_allowlist_cidrs", []) or [])
        broad = any(str(c).strip() in {"0.0.0.0/0", "::/0"} for c in cidrs)
        # An empty list is a "warn" rather than "fail" — the egress
        # plumbing may fill it later from --siem-egress-cidr.
        if not cidrs:
            audit.record_check(
                "SIEM Export", "Egress CIDRs narrow (no 0.0.0.0/0)", "SIEM-007",
                expected=True, observed=None,
                note="egress_allowlist_cidrs empty at audit time",
            )
        else:
            audit.record_check(
                "SIEM Export", "Egress CIDRs narrow (no 0.0.0.0/0)", "SIEM-007",
                expected=True, observed=(not broad),
                note=f"cidrs={cidrs[:8]} count={len(cidrs)}",
            )
    except Exception:
        pass
