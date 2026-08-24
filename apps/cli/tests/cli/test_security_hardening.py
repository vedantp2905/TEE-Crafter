"""Regression tests for the security-hardening pass:

* SIEM-SEC-2: tmpfs siem.env + siem.env.public split
* SIEM-SEC-4: fail-closed gate + sidecar health-state contract
* SIEM-SEC-5: handler sandbox status + RLIMIT semantics
* SIEM-SEC-6: SLSA Provenance v1 + DSSE envelope round-trip
* SIEM verify-siem-chain command (chain + signature checks)
* siem-stage command (token rotation dry-run)
* Systemd units carry the right tmpfs paths
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


# ---------------------------------------------------------------------------
# SIEM-SEC-2: tmpfs siem.env split
# ---------------------------------------------------------------------------

class TestSecretEnvSplit(unittest.TestCase):
    def test_split_partitions_known_secret_keys(self):
        from tee_crafter.cli.commands.deploy.siem_mode import (
            SECRET_ENV_KEYS, split_env_secrets,
        )
        env = {
            "TEE_CRAFTER_SIEM": "splunk-hec",
            "TEE_CRAFTER_SIEM_ENDPOINT": "https://splunk.example/services/collector",
            "TEE_CRAFTER_SIEM_TOKEN": "deadbeef-token",
            "TEE_CRAFTER_SIEM_API_KEY": "datadog-key",
            "TEE_CRAFTER_SIEM_INDEX": "tee_crafter",
            "TEE_CRAFTER_SIEM_FAIL_OPEN": "0",
        }
        secret, public = split_env_secrets(env)
        # Every known secret-bearing key lands in `secret`.
        for k in env:
            if k in SECRET_ENV_KEYS:
                self.assertIn(k, secret)
                self.assertNotIn(k, public)
            else:
                self.assertIn(k, public)
                self.assertNotIn(k, secret)
        # Provider + endpoint + fail_open in public for reboot survival.
        self.assertIn("TEE_CRAFTER_SIEM_ENDPOINT", public)
        self.assertIn("TEE_CRAFTER_SIEM_FAIL_OPEN", public)

    def test_write_siem_config_emits_triple(self):
        from tee_crafter.cli.commands.deploy.siem_mode import (
            SiemConfig, write_siem_config,
        )
        cfg = SiemConfig(
            provider="splunk-hec",
            endpoint="https://splunk.example/services/collector",
            token="deadbeef-secret",
            index="t", sourcetype="t", source="t",
            interval_seconds=30,
        )
        from tee_crafter.core.audit import build_layout as _layout
        with tempfile.TemporaryDirectory() as build_dir:
            write_siem_config(build_dir, cfg, enabled=True)
            secret_env = open(_layout.siem_env(build_dir)).read()
            public_env = open(_layout.siem_env_public(build_dir)).read()
        self.assertIn("deadbeef-secret", secret_env,
                      "the bearer token must land in siem.env")
        self.assertNotIn("deadbeef-secret", public_env,
                         "SIEM-SEC-2: bearer token must NOT land in siem.env.public")
        # And conversely the public file MUST still carry the endpoint.
        self.assertIn("splunk.example", public_env)


class TestSidecarTmpfsPath(unittest.TestCase):
    """The deploy-time install script + the systemd unit template must
    agree on the same /run/tee-crafter-{platform}/ path.
    """

    def test_install_script_writes_to_tmpfs(self):
        from tee_crafter.cli.deployment.common.siem_sidecar import (
            _install_script, render_sidecar_unit, runtime_dir_for,
        )
        unit = render_sidecar_unit("snp-aws")
        rd = runtime_dir_for("snp-aws")
        self.assertEqual(rd, "/run/tee-crafter-snp-aws")
        # Unit must reference the tmpfs path.
        self.assertIn(f"EnvironmentFile=-{rd}/siem.env", unit)
        # The install script must (a) create the tmpfs dir,
        # (b) move siem.env into it, (c) shred the disk copy by default.
        script = _install_script(unit, "snp-aws")
        self.assertIn(f"install -d -m 0700 -o tee_enclave -g tee_enclave {rd}", script)
        self.assertIn(f"{rd}/siem.env", script)
        self.assertIn("shred -u", script)
        # And surface the persist override.
        self.assertIn("TEE_CRAFTER_SIEM_PERSIST", script)

    def test_every_platform_has_distinct_tmpfs(self):
        from tee_crafter.cli.deployment.common.siem_sidecar import (
            SUPPORTED_PLATFORMS, runtime_dir_for,
        )
        seen = {runtime_dir_for(p) for p in SUPPORTED_PLATFORMS}
        self.assertEqual(len(seen), len(SUPPORTED_PLATFORMS),
                         "each platform must get its own tmpfs dir")
        # Every directory must be on /run.
        for rd in seen:
            self.assertTrue(rd.startswith("/run/tee-crafter-"))


# ---------------------------------------------------------------------------
# SIEM-SEC-4: fail-closed gate
# ---------------------------------------------------------------------------

class TestFailClosedGate(unittest.TestCase):
    def setUp(self):
        self._snap = dict(os.environ)
        # Import under controlled env.
        for k in list(os.environ):
            if k.startswith("TEE_CRAFTER_SIEM"):
                del os.environ[k]
        # Defer the import so module-level cache picks up our env each test.
        from tee_crafter.templates.common import siem_health
        self.mod = siem_health
        # Reset the process start anchor so the grace window is fresh.
        siem_health._PROCESS_START = time.monotonic()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._snap)

    def test_disabled_when_siem_not_enabled(self):
        # No envs set -> SIEM not enabled -> fail-closed not engaged.
        self.assertFalse(self.mod.is_fail_closed())
        # And `assert` must not raise.
        self.mod.assert_siem_healthy()

    def test_production_default_is_fail_closed(self):
        """Production posture: enabling SIEM (no FAIL_OPEN knob set)
        engages the gate by default — fail-closed."""
        os.environ["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        # No TEE_CRAFTER_SIEM_FAIL_OPEN at all -> defaults to 0 (fail closed).
        self.assertTrue(self.mod.is_fail_closed())

    def test_dev_hatch_disables_gate(self):
        """Dev hatch TEE_CRAFTER_SIEM_FAIL_OPEN=1 reverts to
        log-and-keep-serving."""
        os.environ["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        os.environ["TEE_CRAFTER_SIEM_FAIL_OPEN"] = "1"
        self.assertFalse(self.mod.is_fail_closed())
        # Explicit "0" should also be fail-closed.
        os.environ["TEE_CRAFTER_SIEM_FAIL_OPEN"] = "0"
        self.assertTrue(self.mod.is_fail_closed())

    def test_unrecognised_fail_open_value_fails_closed(self):
        """A typo must not silently disable the gate.

        The predicate used to test the *falsy* set, so anything outside
        ``0/false/no/off/""`` — ``2``, ``ture``, ``TRUE!`` — read as
        "fail open".  Only an explicit recognised truthy value may
        disable it.
        """
        os.environ["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        for bogus in ("2", "ture", "yes please", "-1", "off "):
            with self.subTest(value=bogus):
                os.environ["TEE_CRAFTER_SIEM_FAIL_OPEN"] = bogus
                self.assertTrue(self.mod.is_fail_closed())

    def test_byok_unrecognised_fail_open_value_fails_closed(self):
        from tee_crafter.templates.common import byok_health
        os.environ["TEE_CRAFTER_BYOK_ENABLED"] = "1"
        try:
            for bogus in ("2", "ture", "yes please", "-1"):
                with self.subTest(value=bogus):
                    os.environ["TEE_CRAFTER_BYOK_FAIL_OPEN"] = bogus
                    self.assertTrue(byok_health.is_fail_closed())
            os.environ["TEE_CRAFTER_BYOK_FAIL_OPEN"] = "1"
            self.assertFalse(byok_health.is_fail_closed())
        finally:
            os.environ.pop("TEE_CRAFTER_BYOK_ENABLED", None)
            os.environ.pop("TEE_CRAFTER_BYOK_FAIL_OPEN", None)

    def test_both_gates_recognise_the_same_truthy_values(self):
        """The SIEM and BYOK gates must answer the same env value alike.

        ``siem_health`` recognised ``1/true/yes`` while ``byok_health``
        also recognised ``on``, so ``TEE_CRAFTER_SIEM_ENABLED=on`` left
        the SIEM gate disarmed while ``TEE_CRAFTER_BYOK_ENABLED=on``
        armed the BYOK one.
        """
        from tee_crafter.templates.common import byok_health
        self.assertEqual(self.mod._TRUE_SET, byok_health._TRUE_SET)
        os.environ.pop("TEE_CRAFTER_SIEM_FAIL_OPEN", None)
        os.environ.pop("TEE_CRAFTER_BYOK_FAIL_OPEN", None)
        try:
            for value in self.mod._TRUE_SET:
                with self.subTest(value=value):
                    os.environ["TEE_CRAFTER_SIEM_ENABLED"] = value
                    os.environ["TEE_CRAFTER_BYOK_ENABLED"] = value
                    self.assertTrue(self.mod.is_fail_closed())
                    self.assertTrue(byok_health.is_fail_closed())
        finally:
            os.environ.pop("TEE_CRAFTER_BYOK_ENABLED", None)

    def test_grace_window_tolerates_missing_health(self):
        os.environ["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        os.environ["TEE_CRAFTER_SIEM_FAIL_OPEN"] = "0"
        os.environ["TEE_CRAFTER_TEE_PLATFORM"] = "snp-aws"
        os.environ["TEE_CRAFTER_SIEM_GRACE_SECONDS"] = "60"
        # Health file missing but we're inside the grace window -> pass.
        self.mod.assert_siem_healthy()

    def test_blackout_after_grace(self):
        os.environ["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        os.environ["TEE_CRAFTER_SIEM_FAIL_OPEN"] = "0"
        os.environ["TEE_CRAFTER_TEE_PLATFORM"] = "snp-aws"
        os.environ["TEE_CRAFTER_SIEM_GRACE_SECONDS"] = "0"
        # Health file missing AND past grace -> raise.
        with self.assertRaises(self.mod.SiemBlackoutError):
            self.mod.assert_siem_healthy()

    def test_stale_health_file_triggers_blackout(self):
        os.environ["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        os.environ["TEE_CRAFTER_SIEM_FAIL_OPEN"] = "0"
        os.environ["TEE_CRAFTER_TEE_PLATFORM"] = "snp-aws"
        os.environ["TEE_CRAFTER_SIEM_GRACE_SECONDS"] = "0"
        os.environ["TEE_CRAFTER_SIEM_MAX_LAG_SECONDS"] = "5"
        # Patch the read to return a very stale snapshot.
        with mock.patch.object(self.mod, "_read_state", return_value={
            "ts": int(time.time()) - 3600,
            "last_seq": 1,
            "last_status": "pass",
            "last_export_status": "pass",
        }):
            with self.assertRaises(self.mod.SiemBlackoutError):
                self.mod.assert_siem_healthy()

    def test_export_fail_triggers_blackout(self):
        os.environ["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        os.environ["TEE_CRAFTER_SIEM_FAIL_OPEN"] = "0"
        os.environ["TEE_CRAFTER_TEE_PLATFORM"] = "snp-aws"
        os.environ["TEE_CRAFTER_SIEM_MAX_LAG_SECONDS"] = "9999"
        with mock.patch.object(self.mod, "_read_state", return_value={
            "ts": int(time.time()),
            "last_seq": 5,
            "last_status": "pass",
            "last_export_status": "fail",  # SIEM rejecting events
        }):
            with self.assertRaises(self.mod.SiemBlackoutError):
                self.mod.assert_siem_healthy()

    def test_fail_closed_wrap_returns_refusal_payload(self):
        os.environ["TEE_CRAFTER_SIEM_ENABLED"] = "1"
        os.environ["TEE_CRAFTER_SIEM_FAIL_OPEN"] = "0"
        os.environ["TEE_CRAFTER_TEE_PLATFORM"] = "snp-aws"
        os.environ["TEE_CRAFTER_SIEM_GRACE_SECONDS"] = "0"
        called = {"n": 0}
        def handler(data):
            called["n"] += 1
            return {"ok": True}
        wrapped = self.mod.fail_closed_wrap(handler)
        out = wrapped({"req": "x"})
        # Handler must NOT have been invoked when SIEM is dark.
        self.assertEqual(called["n"], 0)
        self.assertEqual(out["error"], "siem_blackout")
        self.assertEqual(out["policy"], "fail_closed")


# ---------------------------------------------------------------------------
# SIEM-SEC-5: handler sandbox
# ---------------------------------------------------------------------------

class TestHandlerSandbox(unittest.TestCase):
    def test_status_snapshot_includes_required_fields(self):
        sys.path.insert(0, os.path.join(SRC, "tee_crafter", "templates", "common"))
        try:
            import tee_crafter_handler_sandbox as hs
        finally:
            sys.path.pop(0)
        snap = hs.status_snapshot()
        for k in ("enabled", "install_attempted",
                  "have_prctl_no_new_privs", "have_seccomp",
                  "parent_seccomp_filter", "seccomp_source",
                  "rlimit_cpu_sec", "denied_syscalls", "platform"):
            self.assertIn(k, snap)
        # The denied-syscall list must include the dangerous primitives.
        for syscall in ("fork", "execve", "ptrace", "bpf", "userfaultfd"):
            self.assertIn(syscall, snap["denied_syscalls"])
        # The seccomp source must be one of the three known states.
        self.assertIn(snap["seccomp_source"], ("in-app", "parent", "none"))

    def test_status_snapshot_survives_a_mistyped_rlimit_knob(self):
        """``/healthz`` must not 500 because a knob has a typo.

        ``status_snapshot`` used a bare ``int(os.environ.get(...))`` on the
        RLIMIT knobs, so ``RLIMIT_CPU_SEC=thirty`` raised ValueError out of
        the health endpoint.  It now uses the same "unset / unparseable ->
        default" rule the fence itself applies.
        """
        sys.path.insert(0, os.path.join(SRC, "tee_crafter", "templates", "common"))
        try:
            import tee_crafter_handler_sandbox as hs
        finally:
            sys.path.pop(0)
        os.environ["TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_CPU_SEC"] = "thirty"
        os.environ["TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_AS_MB"] = "-5"
        os.environ["TEE_CRAFTER_HANDLER_SANDBOX_RLIMIT_FSIZE_MB"] = "0"
        try:
            snap = hs.status_snapshot()
            self.assertEqual(snap["rlimit_cpu_sec"], hs.DEFAULT_CPU_SEC)
            self.assertIsNone(snap["rlimit_as_mb"])
            # An explicit 0 is a real zero-byte limit, not "unset".
            self.assertEqual(snap["rlimit_fsize_mb"], 0)
        finally:
            for k in ("RLIMIT_CPU_SEC", "RLIMIT_AS_MB", "RLIMIT_FSIZE_MB"):
                os.environ.pop("TEE_CRAFTER_HANDLER_SANDBOX_" + k, None)

    def test_no_install_at_import_time(self):
        """Importing the module must not call ``seccomp(2)`` —
        otherwise systemd's ``SystemCallFilter=`` (which excludes
        ``seccomp``) SIGSYS's the whole service.  Regression test for
        the SNP/SIEM core-dump observed during the first deploy with
        SIEM-SEC-5 enabled.
        """
        sys.path.insert(0, os.path.join(SRC, "tee_crafter", "templates", "common"))
        try:
            if "tee_crafter_handler_sandbox" in sys.modules:
                del sys.modules["tee_crafter_handler_sandbox"]
            import tee_crafter_handler_sandbox as hs
        finally:
            sys.path.pop(0)
        # Fresh import must NOT have attempted install yet.
        self.assertFalse(hs._INSTALL_ATTEMPTED)
        self.assertFalse(hs._HAVE_SECCOMP)

    def test_parent_seccomp_probe_skips_install(self):
        """When ``/proc/self/status`` reports an active parent filter,
        the lazy installer must record ``parent_seccomp_filter=True``
        and skip the in-app install instead of calling
        ``seccomp_load()`` (which would SIGSYS under systemd).
        """
        sys.path.insert(0, os.path.join(SRC, "tee_crafter", "templates", "common"))
        try:
            if "tee_crafter_handler_sandbox" in sys.modules:
                del sys.modules["tee_crafter_handler_sandbox"]
            import tee_crafter_handler_sandbox as hs
        finally:
            sys.path.pop(0)
        hs._PARENT_SECCOMP = False
        hs._HAVE_SECCOMP = False
        hs._INSTALL_ATTEMPTED = False
        original = hs._detect_parent_seccomp_filter
        original_probe = hs._probe_seccomp_load_permitted
        hs._detect_parent_seccomp_filter = lambda: True
        # The probe has to be stubbed too, and not only for determinism.  Left
        # live it returns False on macOS (no seccomp) but True on Linux, so the
        # installer went on to load a filter *into the pytest process itself* --
        # and a seccomp filter cannot be removed.  Every later test that spawned
        # a subprocess then died with EPERM at exec: 34 failures and 58 errors on
        # Linux CI, none of them reproducible on a developer's Mac.  The scenario
        # under test is a parent filter that would SIGSYS under systemd, i.e. one
        # we must not load under, so False is also the correct value here.
        hs._probe_seccomp_load_permitted = lambda: False
        try:
            # FORCE_SECCOMP short-circuits the probe entirely, so a stray value
            # in the environment would put the real load back in play.
            with mock.patch.dict(
                    os.environ,
                    {"TEE_CRAFTER_HANDLER_SANDBOX_FORCE_SECCOMP": "0"}):
                ok = hs._try_install_seccomp_once()
        finally:
            hs._detect_parent_seccomp_filter = original
            hs._probe_seccomp_load_permitted = original_probe
        self.assertTrue(ok)
        self.assertTrue(hs._PARENT_SECCOMP)
        self.assertFalse(hs._HAVE_SECCOMP)
        snap = hs.status_snapshot()
        self.assertEqual(snap["seccomp_source"], "parent")

    def test_sandbox_wrap_invokes_handler(self):
        sys.path.insert(0, os.path.join(SRC, "tee_crafter", "templates", "common"))
        try:
            import tee_crafter_handler_sandbox as hs
        finally:
            sys.path.pop(0)
        def handler(data):
            return {"got": data}
        wrapped = hs.sandbox_wrap(handler)
        self.assertEqual(wrapped({"x": 1}), {"got": {"x": 1}})

    def test_disable_env_returns_unwrapped_fn(self):
        sys.path.insert(0, os.path.join(SRC, "tee_crafter", "templates", "common"))
        try:
            import tee_crafter_handler_sandbox as hs
        finally:
            sys.path.pop(0)
        os.environ["TEE_CRAFTER_HANDLER_SANDBOX"] = "0"
        try:
            def handler(data): return data
            self.assertIs(hs.sandbox_wrap(handler), handler)
        finally:
            del os.environ["TEE_CRAFTER_HANDLER_SANDBOX"]

    def _hs(self):
        sys.path.insert(0, os.path.join(SRC, "tee_crafter", "templates", "common"))
        try:
            import tee_crafter_handler_sandbox as hs
        finally:
            sys.path.pop(0)
        return hs

    def test_clone_is_denied(self):
        """glibc implements fork() via clone(2) on x86-64.

        A filter that lists ``clone3`` but not ``clone`` blocks nothing.
        ``clone`` is denied by a masked-argument rule (CLONE_THREAD
        clear) so pthread_create keeps working.
        """
        hs = self._hs()
        snap = hs.status_snapshot()
        self.assertIn("clone", snap["denied_syscalls"])
        masked = {m["syscall"]: m for m in snap["masked_denied_syscalls"]}
        self.assertIn("clone", masked)
        self.assertEqual(masked["clone"]["mask"], hex(hs._CLONE_THREAD))
        self.assertEqual(masked["clone"]["value"], 0)

    def test_cpu_rlimit_is_rebased_per_request(self):
        """RLIMIT_CPU counts process-lifetime CPU, so a flat ceiling
        SIGXCPUs a persistent service after ~30 s of aggregate CPU."""
        import resource as _res
        hs = self._hs()
        applied = []

        def _fake_setrlimit(r, pair):
            applied.append((r, pair))

        with mock.patch.object(_res, "setrlimit", _fake_setrlimit), \
                mock.patch.object(_res, "getrlimit",
                                  return_value=(_res.RLIM_INFINITY,
                                                _res.RLIM_INFINITY)), \
                mock.patch.object(hs, "_cpu_seconds_used", return_value=900.0):
            hs._resource_fence(cpu_seconds=30, as_bytes=None, fsize_bytes=None)
        cpu = [pair for r, pair in applied if r == _res.RLIMIT_CPU]
        self.assertEqual(len(cpu), 1)
        # 900 s already burned + a fresh 30 s budget for this request.
        self.assertEqual(cpu[0][0], 930)

    def test_explicit_zero_fsize_is_applied(self):
        """0 used to mean 'unset', so ``RLIMIT_FSIZE=0`` was skipped."""
        import resource as _res
        hs = self._hs()
        applied = []
        with mock.patch.object(_res, "setrlimit",
                               lambda r, pair: applied.append((r, pair))), \
                mock.patch.object(_res, "getrlimit",
                                  return_value=(_res.RLIM_INFINITY,
                                                _res.RLIM_INFINITY)):
            hs._resource_fence(cpu_seconds=None, as_bytes=None, fsize_bytes=0)
        self.assertEqual([r for r, _ in applied], [_res.RLIMIT_FSIZE])
        self.assertEqual(applied[0][1][0], 0)

    def test_unset_limits_are_left_alone(self):
        import resource as _res
        hs = self._hs()
        applied = []
        with mock.patch.object(_res, "setrlimit",
                               lambda r, pair: applied.append((r, pair))), \
                mock.patch.object(_res, "getrlimit",
                                  return_value=(_res.RLIM_INFINITY,
                                                _res.RLIM_INFINITY)):
            hs._resource_fence(cpu_seconds=None, as_bytes=None,
                               fsize_bytes=None)
        self.assertEqual(applied, [])


# ---------------------------------------------------------------------------
# Batch mode gates
# ---------------------------------------------------------------------------


class TestSlsaProvenance(unittest.TestCase):
    def setUp(self):
        # SIEM-SEC-6 emit_attestation reuses the BuildAuditTrail signing
        # key.  In CI / unit tests we deliberately use an ephemeral
        # keypair — production deployments are expected to pin a
        # long-lived key via TEE_CRAFTER_PROVENANCE_SIGNING_KEY_FILE
        # / OS keyring, but tests don't have that.
        self._snap = dict(os.environ)
        os.environ["TEE_CRAFTER_PROVENANCE_ALLOW_EPHEMERAL"] = "1"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._snap)

    def test_emit_and_verify(self):
        from tee_crafter.core.audit import slsa
        with tempfile.TemporaryDirectory() as build_dir:
            # Place a couple of subject files so collect_subjects has work.
            tar = os.path.join(build_dir, "tee-crafter.tar")
            with open(tar, "wb") as f:
                f.write(b"hello")
            out = slsa.emit_attestation(
                build_dir=build_dir,
                tee_platform="snp-aws",
                build_config={"pipeline_version": "test"},
            )
            self.assertTrue(os.path.isfile(out["statement"]))
            self.assertTrue(os.path.isfile(out["envelope"]))
            with open(out["envelope"]) as f:
                env = json.load(f)
            # DSSE envelope shape.
            self.assertEqual(env["payloadType"], slsa.DSSE_PAYLOAD_TYPE)
            self.assertEqual(len(env["signatures"]), 1)
            self.assertTrue(env["signatures"][0]["keyid"].startswith("sha256:"))
            # Payload decodes to a valid in-toto Statement v1 with our predicate.
            payload = json.loads(base64.b64decode(env["payload"]))
            self.assertEqual(payload["_type"], slsa.SLSA_STATEMENT_TYPE)
            self.assertEqual(payload["predicateType"], slsa.SLSA_PREDICATE_TYPE)
            self.assertEqual(
                payload["predicate"]["buildDefinition"]["buildType"],
                slsa.TEE_CRAFTER_BUILD_TYPE)
            self.assertEqual(
                payload["predicate"]["buildDefinition"]
                ["externalParameters"]["tee_platform"],
                "snp-aws")
            # And the subject SHA matches the file we wrote.
            subjects = payload["subject"]
            expected_sha = hashlib.sha256(b"hello").hexdigest()
            self.assertTrue(
                any(s["digest"].get("sha256") == expected_sha for s in subjects),
                "subject digest must match the file SHA",
            )
            # Verify round-trip.
            ok, msg = slsa.verify_envelope(out["envelope"])
            self.assertTrue(ok, msg)

    def test_verify_fails_on_tamper(self):
        from tee_crafter.core.audit import slsa
        with tempfile.TemporaryDirectory() as build_dir:
            with open(os.path.join(build_dir, "tee-crafter.tar"), "wb") as f:
                f.write(b"x")
            out = slsa.emit_attestation(
                build_dir=build_dir,
                tee_platform="tdx-azure",
                build_config={},
            )
            # Flip a bit in the payload — verification must fail.
            with open(out["envelope"], "r") as f:
                env = json.load(f)
            payload = bytearray(base64.b64decode(env["payload"]))
            payload[0] ^= 0xFF
            env["payload"] = base64.b64encode(bytes(payload)).decode("ascii")
            with open(out["envelope"], "w") as f:
                json.dump(env, f)
            ok, msg = slsa.verify_envelope(out["envelope"])
            self.assertFalse(ok)


# ---------------------------------------------------------------------------
# verify-siem-chain
# ---------------------------------------------------------------------------

class _CaptureExporter:
    """Collects the events the real producer hands to an exporter."""

    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class TestVerifySiemChain(unittest.TestCase):
    """The fixture drives the REAL producer, not a hand-rolled imitation.

    The previous version of this class built events itself, in the
    *verifier's* convention, and never imported ``siem_export``.  It
    therefore passed for months while no event a deployed TEE emitted
    could verify at all: the producer hashed a payload containing
    ``"digest": ""`` and the verifier hashed one without it.  Any fixture
    that re-implements the thing under test can only prove the test
    agrees with itself.
    """

    def setUp(self):
        self._snap = dict(os.environ)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # Publish a real chain-key commitment through the real audit
        # logger so the producer picks it up the way it would in a TEE.
        commitment_path = os.path.join(self._tmp.name, "chain_key_commitment")
        os.environ["TEE_CRAFTER_CHAIN_COMMITMENT_PATH"] = commitment_path
        from tee_crafter.templates.common import tee_crafter_audit_logger as al
        self.commitment = al.publish_chain_key_commitment(commitment_path)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._snap)

    # ------------------------------------------------------------------
    def _make_events(self, n: int = 3, *, measurement: str = "ab" * 32):
        """Run the real ``siem_export.AttestationLoop`` for *n* ticks.

        Returns ``(event_dicts, public_key_pem)``.  Only two things are
        stubbed: the exporter (so nothing leaves the box) and the health
        -state writer (which targets ``/run``, unavailable in CI).
        """
        from dataclasses import asdict
        from tee_crafter.templates.common import siem_export

        exporter = _CaptureExporter()
        loop = siem_export.AttestationLoop(
            exporter=exporter,
            interval_seconds=1,
            instance_id="i-test",
            tee_platform="snp-aws",
            pipeline_version="v1",
            attest_provider=lambda: (b"attestation-blob", measurement),
        )
        with mock.patch.object(siem_export, "_write_health_state"):
            for _ in range(n):
                loop.tick()
        self.assertEqual(len(exporter.events), n)
        return [asdict(ev) for ev in exporter.events], loop.public_pem

    def _write_events(self, events) -> str:
        path = os.path.join(self._tmp.name, f"events-{len(os.listdir(self._tmp.name))}.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")
        return path

    def _write_pubkey(self, pem: str) -> str:
        path = os.path.join(self._tmp.name, "signing.pub")
        with open(path, "w", encoding="utf-8") as f:
            f.write(pem)
        return path

    def _run_cli(self, events, pem, *extra_args):
        """Invoke the real Click command; returns the CliRunner result."""
        import click
        from click.testing import CliRunner
        from tee_crafter.cli.commands.verify_siem_chain import register

        @click.group()
        def cli():
            pass

        register(cli)
        args = ["verify-siem-chain",
                "--file", self._write_events(events)]
        if pem is not None:
            args += ["--pubkey", self._write_pubkey(pem)]
        args += list(extra_args)
        return CliRunner().invoke(cli, args)

    # ---- producer/verifier agreement --------------------------------
    def test_clean_chain_from_real_producer_verifies(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(5)
        ok, problems = verify_chain(events, trusted_pubkey_pem=pem)
        self.assertTrue(ok, problems)

    def test_producer_genesis_matches_documented_value(self):
        from tee_crafter.templates.common.siem_export import GENESIS_PREV_DIGEST
        events, _ = self._make_events(2)
        self.assertEqual(events[0]["seq"], 0)
        self.assertEqual(events[0]["prev_digest"], GENESIS_PREV_DIGEST)
        self.assertEqual(events[1]["prev_digest"], events[0]["digest"])

    def test_producer_publishes_chain_key_commitment(self):
        events, _ = self._make_events(2)
        for ev in events:
            self.assertEqual(
                ev["extra"]["chain_key_commitment"], self.commitment)

    def test_core_producer_and_sidecar_share_canonicalisation(self):
        """``core.audit.continuous`` events must verify under the CLI verifier."""
        from dataclasses import asdict
        from tee_crafter.core.audit.continuous import (
            ContinuousAttestor, InMemoryExporter,
        )
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        exporter = InMemoryExporter()
        attestor = ContinuousAttestor(
            attest=lambda nonce: b"blob", exporters=[exporter],
            interval_seconds=60, instance_id="i-core", tee_platform="snp-aws",
        )
        attestor.emit_now(event_type="attestation_boot")
        attestor.emit_now()
        events = [asdict(ev) for ev in exporter.events]
        ok, problems = verify_chain(
            events,
            trusted_pubkey_pem=events[0]["public_key_pem"],
            require_chain_commitment=False,
        )
        self.assertTrue(ok, problems)

    # ---- rejection cases --------------------------------------------
    def test_unknown_schema_version_rejected(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(2)
        events[1]["schema_version"] = 99
        ok, problems = verify_chain(events, trusted_pubkey_pem=pem)
        self.assertFalse(ok)
        self.assertTrue(any("unsupported schema_version" in p for p in problems))

    def test_missing_trust_anchor_refused(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, _ = self._make_events(2)
        ok, problems = verify_chain(events)
        self.assertFalse(ok)
        self.assertTrue(any("out-of-band signing key" in p for p in problems))

    def test_broken_chain_detected(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(3)
        events[1]["prev_digest"] = "f" * 64
        ok, problems = verify_chain(events, trusted_pubkey_pem=pem)
        self.assertFalse(ok)
        self.assertTrue(any("prev_digest break" in p for p in problems))

    def test_non_genesis_first_event_detected(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(2)
        events[0]["prev_digest"] = "1" * 64
        ok, problems = verify_chain(events, trusted_pubkey_pem=pem)
        self.assertFalse(ok)
        self.assertTrue(any("genesis" in p for p in problems))

    def test_measurement_pinning(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(2, measurement="ab" * 32)
        ok, _ = verify_chain(events, trusted_pubkey_pem=pem,
                             expected_measurements=["cd" * 32])
        self.assertFalse(ok)
        ok, problems = verify_chain(events, trusted_pubkey_pem=pem,
                                    expected_measurements=["AB" * 32])
        self.assertTrue(ok, problems)

    def test_empty_measurement_fails_when_allowlist_set(self):
        """An absent measurement must not sneak past a pinned allowlist.

        Same shape as ``core.keys.release``: a policy that requires a
        measurement fails when the provider supplied none.
        """
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(1, measurement="")
        ok, problems = verify_chain(events, trusted_pubkey_pem=pem,
                                    expected_measurements=["ab" * 32])
        self.assertFalse(ok)
        self.assertTrue(any("no measurement_sha256" in p for p in problems))

    def test_missing_chain_commitment_rejected(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(2)
        for ev in events:
            ev["extra"].pop("chain_key_commitment")
        ok, problems = verify_chain(events, trusted_pubkey_pem=pem)
        self.assertFalse(ok)
        self.assertTrue(any("chain_key_commitment" in p for p in problems))

    def test_chain_commitment_pinning(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(2)
        ok, problems = verify_chain(
            events, trusted_pubkey_pem=pem,
            expected_chain_commitment=self.commitment)
        self.assertTrue(ok, problems)
        ok, problems = verify_chain(
            events, trusted_pubkey_pem=pem,
            expected_chain_commitment="0" * 64)
        self.assertFalse(ok)

    def test_signature_skip_flag(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(2)
        # Break the signature; with skip_signature it must still pass.
        events[0]["signature"] = "00" * 64
        ok, problems = verify_chain(events, skip_signature=True)
        self.assertTrue(ok, problems)
        ok, _ = verify_chain(events, trusted_pubkey_pem=pem)
        self.assertFalse(ok)

    def test_forged_chain_rejected_against_pinned_key(self):
        """A self-consistent chain signed by another key must not verify."""
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        good_events, good_pem = self._make_events(2)
        forged_events, _forged_pem = self._make_events(2)
        ok, problems = verify_chain(good_events, trusted_pubkey_pem=good_pem)
        self.assertTrue(ok, problems)
        ok, problems = verify_chain(forged_events, trusted_pubkey_pem=good_pem)
        self.assertFalse(ok)
        self.assertTrue(any("not the pinned key" in p for p in problems))

    def test_seq_gap_detected_and_optionally_allowed(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(3)
        # Drop the middle event and re-link so only `seq` reveals the gap.
        gapped = [events[0], dict(events[2])]
        gapped[1]["prev_digest"] = events[0]["digest"]
        ok, problems = verify_chain(gapped, trusted_pubkey_pem=pem,
                                    skip_signature=True)
        self.assertFalse(ok)
        self.assertTrue(any("seq jumped" in p for p in problems))

    def test_reordered_chain_detected(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(3)
        reordered = [events[0], events[2], events[1]]
        ok, problems = verify_chain(reordered, trusted_pubkey_pem=pem)
        self.assertFalse(ok)
        self.assertTrue(any("not increasing" in p or "prev_digest break" in p
                            for p in problems))

    def test_expect_first_seq_detects_head_truncation(self):
        from tee_crafter.cli.commands.verify_siem_chain import verify_chain
        events, pem = self._make_events(3)
        truncated = events[1:]  # drop genesis; window now starts at seq 1
        ok, problems = verify_chain(
            truncated, trusted_pubkey_pem=pem, expected_first_seq=0)
        self.assertFalse(ok)
        self.assertTrue(any("head truncation" in p for p in problems))

    # ---- CLI exit codes ---------------------------------------------
    def test_cli_clean_chain_exits_zero(self):
        events, pem = self._make_events(3)
        res = self._run_cli(events, pem, "--expect-first-seq", "0")
        self.assertEqual(res.exit_code, 0, res.output)

    def test_cli_empty_event_list_exits_2(self):
        """A vacuous pass is the worst outcome; an empty window must fail."""
        _events, pem = self._make_events(1)
        res = self._run_cli([], pem)
        self.assertEqual(res.exit_code, 2, res.output)

    def test_cli_tampered_chain_exits_2(self):
        events, pem = self._make_events(3)
        events[2]["status"] = "fail"
        res = self._run_cli(events, pem)
        self.assertEqual(res.exit_code, 2, res.output)

    def test_cli_reordered_chain_exits_2(self):
        events, pem = self._make_events(3)
        res = self._run_cli([events[0], events[2], events[1]], pem)
        self.assertEqual(res.exit_code, 2, res.output)

    def test_cli_truncated_chain_exits_2(self):
        events, pem = self._make_events(3)
        res = self._run_cli(events[1:], pem, "--expect-first-seq", "0")
        self.assertEqual(res.exit_code, 2, res.output)

    def test_cli_resigned_chain_exits_2(self):
        """Attacker re-signs a whole window with their own key."""
        _good, good_pem = self._make_events(3)
        forged, _forged_pem = self._make_events(3)
        res = self._run_cli(forged, good_pem)
        self.assertEqual(res.exit_code, 2, res.output)


# ---------------------------------------------------------------------------
# siem-stage CLI: dry-run shape
# ---------------------------------------------------------------------------

class TestSiemStageDryRun(unittest.TestCase):
    def test_dry_run_emits_runtime_dir(self):
        # Use the CliRunner-free pure functions to assert shape.
        from tee_crafter.cli.commands.siem_stage import _build_remote_command
        script = _build_remote_command(
            tee_platform="snp-aws",
            secret_env={"TEE_CRAFTER_SIEM_TOKEN": "deadbeef"},
            public_env={"TEE_CRAFTER_SIEM_ENABLED": "1",
                        "TEE_CRAFTER_SIEM_FAIL_OPEN": "0"},
        )
        self.assertIn("/run/tee-crafter-snp-aws", script)
        self.assertIn("tee-crafter-siem.service", script)
        # Public env on disk, secret env on tmpfs.
        self.assertIn("siem.env.public", script)
        self.assertIn("/run/tee-crafter-snp-aws/siem.env", script)


# ---------------------------------------------------------------------------
# Systemd unit consistency
# ---------------------------------------------------------------------------

class TestSystemdUnitsCarryTmpfsPath(unittest.TestCase):
    UNITS = (
        ("snp-aws.service",      "snp-aws"),
        ("snp-azure.service",    "snp-azure"),
        ("snp-gcp.service",      "snp-gcp"),
        ("tdx-azure.service",    "tdx-azure"),
        ("tdx-gcp.service",      "tdx-gcp"),
        ("gpu-cc-aws.service",   "gpu-cc-aws"),
        ("gpu-cc-azure.service", "gpu-cc-azure"),
        ("gpu-cc-gcp.service",   "gpu-cc-gcp"),
    )

    def test_every_main_unit_loads_from_tmpfs(self):
        base = os.path.join(SRC, "tee_crafter", "resources", "systemd")
        for unit, slug in self.UNITS:
            with self.subTest(unit=unit):
                content = open(os.path.join(base, unit)).read()
                self.assertIn(f"/run/tee-crafter-{slug}/siem.env", content,
                              f"{unit} must point at the tmpfs siem.env path")

    def test_main_units_set_memory_ceiling(self):
        """SBX-2: every main unit must set MemoryMax to defend
        against an OOM amplification attack from user code."""
        base = os.path.join(SRC, "tee_crafter", "resources", "systemd")
        for unit, _ in self.UNITS:
            with self.subTest(unit=unit):
                content = open(os.path.join(base, unit)).read()
                self.assertIn("MemoryMax=", content,
                              f"{unit} should declare a MemoryMax ceiling")



# ---------------------------------------------------------------------------
# SBX-3: nesting the in-app seccomp filter under a parent filter
# ---------------------------------------------------------------------------

class TestSeccompNestingDecision(unittest.TestCase):
    """A parent filter must not by itself disable the in-app filter.

    Seccomp filters are additive, and Docker's default profile permits
    ``seccomp(2)``.  Conflating "someone is filtering us" with "we may not
    nest" meant the in-app filter never installed under *any* container --
    which is now the only deployment model -- so ``fork``/``execve`` stayed
    open for user code while ``status_snapshot`` reported the reassuring
    ``seccomp_source: "parent"``.

    Verified for real on a Linux kernel (this suite runs on macOS, where
    seccomp does not exist, so the decision matrix is what is asserted here):
      * Docker default profile  -> installs, fork blocked, threads work
      * seccomp=unconfined      -> installs, fork blocked, threads work
      * profile that KILLs on seccomp(2) (the systemd @privileged case)
                                -> probe child dies, we skip, process lives
    """

    def _module(self):
        sys.path.insert(0, os.path.join(SRC, "tee_crafter", "templates", "common"))
        try:
            if "tee_crafter_handler_sandbox" in sys.modules:
                del sys.modules["tee_crafter_handler_sandbox"]
            import tee_crafter_handler_sandbox as hs
            return hs
        finally:
            sys.path.pop(0)

    def test_parent_filter_that_permits_seccomp_does_not_block_install(self):
        hs = self._module()
        with mock.patch.object(hs, "_detect_parent_seccomp_filter",
                               return_value=True), \
             mock.patch.object(hs, "_probe_seccomp_load_permitted",
                               return_value=True) as probe, \
             mock.patch.object(hs, "_load_empty_allow_filter",
                               return_value=True):
            hs._try_install_seccomp_once()
        probe.assert_called_once()
        # It must NOT have taken the "parent filter, give up" branch.
        self.assertFalse(hs._PARENT_SECCOMP,
                         "a permissive parent filter must not disable the "
                         "in-app filter")

    def test_parent_filter_that_denies_seccomp_makes_us_skip(self):
        hs = self._module()
        with mock.patch.object(hs, "_detect_parent_seccomp_filter",
                               return_value=True), \
             mock.patch.object(hs, "_probe_seccomp_load_permitted",
                               return_value=False):
            self.assertTrue(hs._try_install_seccomp_once())
        self.assertTrue(hs._PARENT_SECCOMP)
        self.assertFalse(hs._HAVE_SECCOMP)
        self.assertEqual(hs.status_snapshot()["seccomp_source"], "parent")

    def test_force_flag_skips_the_probe_entirely(self):
        hs = self._module()
        with mock.patch.object(hs, "_detect_parent_seccomp_filter",
                               return_value=True), \
             mock.patch.object(hs, "_probe_seccomp_load_permitted") as probe, \
             mock.patch.dict(
                 os.environ,
                 {"TEE_CRAFTER_HANDLER_SANDBOX_FORCE_SECCOMP": "1"}), \
             mock.patch.object(hs, "_load_empty_allow_filter",
                               return_value=True):
            hs._try_install_seccomp_once()
        probe.assert_not_called()

    def test_probe_reports_denied_when_fork_is_unavailable(self):
        """Every failure direction must read as "denied", never "permitted"."""
        hs = self._module()
        with mock.patch.object(hs.os, "fork",
                               side_effect=OSError("no fork for you")):
            self.assertFalse(hs._probe_seccomp_load_permitted())

    def test_probe_reports_denied_when_child_is_killed_by_a_signal(self):
        """The systemd case: the child dies rather than exiting."""
        hs = self._module()
        # os.fork() returning a pid means "we are the parent".
        with mock.patch.object(hs.os, "fork", return_value=4242), \
             mock.patch.object(hs.os, "waitpid",
                               return_value=(4242, 31)):  # SIGSYS, not exited
            self.assertFalse(hs._probe_seccomp_load_permitted())

    def test_probe_reports_permitted_only_on_a_clean_exit_zero(self):
        hs = self._module()
        with mock.patch.object(hs.os, "fork", return_value=4242), \
             mock.patch.object(hs.os, "waitpid", return_value=(4242, 0)):
            self.assertTrue(hs._probe_seccomp_load_permitted())
        # A non-zero exit is a failed load, not a permitted one.
        with mock.patch.object(hs.os, "fork", return_value=4242), \
             mock.patch.object(hs.os, "waitpid",
                               return_value=(4242, 1 << 8)):  # exit code 1
            self.assertFalse(hs._probe_seccomp_load_permitted())


if __name__ == "__main__":
    unittest.main()
