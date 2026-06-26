"""Unit tests for batch mode capture, staging, and bundle extraction.

These tests deliberately avoid any cloud SDKs / SSH transports — those are
covered by the existing integration suites.  Here we only exercise the parts
of batch mode that can be run end-to-end in a temp directory:

* :func:`batch_runner.snapshot` / :func:`batch_runner.changed_since` produce
  the right diff when files are added, modified, and untouched.
* :func:`batch._extract_bundle` safely unpacks a tarball produced by
  ``tee_crafter_capture_container.sh``-style layouts.
* The unified ``deploy`` CLI guards reject ``--batch`` + ``--persistent``
  together, and reject ``--persistent`` on ``sgx-azure`` (batch-only).
"""
from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest




class TestBundleExtraction:
    def _make_bundle(self, tmp_path: Path, *, with_meta: bool = True) -> Path:
        """Build a tarball mimicking tee_crafter_capture_container.sh output."""
        staging = tmp_path / "stage"
        (staging / "files" / "var" / "log").mkdir(parents=True)
        (staging / "_logs").mkdir()
        (staging / "_meta").mkdir()
        (staging / "files" / "var" / "log" / "out.txt").write_text("captured\n")
        (staging / "_logs" / "stdout.log").write_text("hello world\n")
        (staging / "_logs" / "exit_code.txt").write_text("0\n")
        if with_meta:
            (staging / "_meta.json").write_text(json.dumps({
                "command": "true",
                "exit_code": 0,
                "duration_sec": 0.42,
                "captured_files": {
                    "runtime_count": 1, "tmp_count": 0,
                    "runtime_bytes": 9, "tmp_bytes": 0,
                },
            }))
        bundle = tmp_path / "output.tar.gz"
        with tarfile.open(bundle, "w:gz") as tf:
            tf.add(staging, arcname=".")
        return bundle

    def test_extract_bundle_is_safe_and_records_meta(self, tmp_path: Path):
        from tee_crafter.cli.commands.deploy.batch import _extract_bundle
        bundle = self._make_bundle(tmp_path)
        dest = tmp_path / "extracted"
        count, total_bytes, meta = _extract_bundle(str(bundle), str(dest))
        assert (dest / "files" / "var" / "log" / "out.txt").read_text() == "captured\n"
        assert count >= 3
        assert total_bytes > 0
        assert meta["exit_code"] == 0
        assert meta["captured_files"]["runtime_count"] == 1

    def test_extract_bundle_strips_path_traversal(self, tmp_path: Path):
        from tee_crafter.cli.commands.deploy.batch import _extract_bundle
        bundle = tmp_path / "evil.tar.gz"
        good = tmp_path / "good.txt"
        good.write_text("ok")
        with tarfile.open(bundle, "w:gz") as tf:
            tf.add(good, arcname="files/inside.txt")
            info = tarfile.TarInfo(name="../escape.txt")
            info.size = 4
            import io
            tf.addfile(info, io.BytesIO(b"evil"))
            info_abs = tarfile.TarInfo(name="/abs.txt")
            info_abs.size = 4
            tf.addfile(info_abs, io.BytesIO(b"evil"))
        dest = tmp_path / "out"
        _extract_bundle(str(bundle), str(dest))
        assert (dest / "files" / "inside.txt").is_file()
        assert not (tmp_path / "escape.txt").exists()
        assert not Path("/abs.txt").exists() or Path("/abs.txt").read_text() != "evil"

    def test_extract_bundle_skips_absolute_symlinks(self, tmp_path: Path):
        """Container batch capture often produces tarballs containing
        absolute symlinks (e.g. ``./files/usr/bin/nawk -> /usr/bin/gawk``)
        because ``docker cp`` preserves the link as-is.  The extractor
        must NOT abort on those — it must skip them and continue extracting
        the rest of the bundle.  Regression test for the
        ``'./files/usr/bin/nawk' is a link to an absolute path`` failure
        that bubbled up from Python 3.12's ``tarfile.data_filter``.
        """
        from tee_crafter.cli.commands.deploy.batch import _extract_bundle
        bundle = tmp_path / "with_abs_symlink.tar.gz"
        good = tmp_path / "ok.txt"
        good.write_text("hello\n")
        with tarfile.open(bundle, "w:gz") as tf:
            tf.add(good, arcname="files/var/log/out.txt")
            link = tarfile.TarInfo(name="files/usr/bin/nawk")
            link.type = tarfile.SYMTYPE
            link.linkname = "/usr/bin/gawk"
            tf.addfile(link)
            esc = tarfile.TarInfo(name="files/var/log/up.lnk")
            esc.type = tarfile.SYMTYPE
            esc.linkname = "../../../../../../../../etc/passwd"
            tf.addfile(esc)
        dest = tmp_path / "extracted"
        count, total_bytes, meta = _extract_bundle(str(bundle), str(dest))
        assert (dest / "files" / "var" / "log" / "out.txt").is_file()
        assert not (dest / "files" / "usr" / "bin" / "nawk").exists()
        assert not (dest / "files" / "var" / "log" / "up.lnk").exists()
        assert count >= 1
        assert total_bytes > 0
        assert meta.get("captured_files", {}).get("skipped_unsafe_entries", 0) >= 2


class TestContainerImageUploadStaging:
    """Verify the container tarball is staged through ``/tmp`` and installed
    into ``/var/lib/tee_crafter`` as root.

    Previously the upload targeted ``/var/lib/tee_crafter/user_container.tar``
    directly, which is root-owned. SCP runs as the unprivileged SSH user on
    Azure/GCP transports so the upload failed with ``Permission denied``.
    The fix uploads to ``/tmp/...`` and then ``sudo install``s the file
    into place with ``root:root 0644`` — same security posture as before,
    but works on every supported transport.
    """

    def _run(self, monkeypatch, tmp_path: Path):
        import tee_crafter.cli.commands.deploy.batch as batch_mod
        from tee_crafter.cli.commands.deploy.batch import (
            BatchTransport, run_batch_container_deploy,
        )
        from unittest.mock import MagicMock

        tar = tmp_path / "user_container.tar"
        tar.write_bytes(b"FAKE_TAR_BYTES")
        # A real build dir always carries the CVM secret-bootstrap script
        # (staged by ``deploy.platform._stage_common_bootstrap``), and the batch
        # path now uploads it because the container unit's
        # ``Requires=tee-crafter-secrets.service`` cannot be satisfied without
        # it.  Without this the fixture aborts before the tarball upload.
        app = tmp_path / "app"
        app.mkdir(exist_ok=True)
        (app / "tee_crafter_secret_bootstrap.py").write_text("# stub\n")

        upload_mock = MagicMock(return_value=(True, "ok"))
        ssh_calls: list[str] = []

        def fake_run_remote(cmd, timeout=60):
            ssh_calls.append(cmd)
            return True, "", ""

        monkeypatch.setattr(batch_mod, "_scp_uploader", lambda t: upload_mock)
        monkeypatch.setattr(batch_mod, "_ssh_runner", lambda t: fake_run_remote)
        # Short-circuit downstream steps that need real transports/services.
        monkeypatch.setattr(
            batch_mod, "collect_batch_output",
            lambda **kw: batch_mod.BatchResult(True, message="stubbed"),
        )

        transport = BatchTransport(
            platform="snp-gcp",
            ssh_private_key_path="/dev/null",
            ssh_user="tee_admin",
        )
        from tee_crafter.cli.constants import Console
        run_batch_container_deploy(
            build_dir=str(tmp_path),
            transport=transport,
            container_tar_local=str(tar),
            console=Console(),
        )
        return upload_mock, ssh_calls

    def test_upload_targets_tmp_and_install_into_var_lib(
        self, tmp_path: Path, monkeypatch,
    ):
        upload_mock, ssh_calls = self._run(monkeypatch, tmp_path)
        # 1. The container tar must NOT be SCP'd directly to /var/lib/tee_crafter.
        for call in upload_mock.call_args_list:
            local, remote = call.args[0], call.args[1]
            if local.endswith("user_container.tar"):
                assert not remote.startswith("/var/lib/tee_crafter/"), (
                    "SCP must stage user_container.tar through /tmp, not write "
                    f"to root-owned /var/lib/tee_crafter directly (got remote={remote!r})"
                )
                assert remote.startswith("/tmp/"), (
                    f"Expected /tmp/ staging path, got {remote!r}"
                )
        # 2. A `sudo install` step must place the file at the final root-owned path.
        install_cmds = [c for c in ssh_calls if "sudo install" in c
                        and "/var/lib/tee_crafter/user_container.tar" in c]
        assert install_cmds, (
            "Missing `sudo install ... /var/lib/tee_crafter/user_container.tar` "
            "step; the tarball would never reach its final root-owned location.\n"
            f"ssh calls observed: {ssh_calls}"
        )
        # 3. Ownership / mode arguments preserve the prior security posture.
        install_cmd = install_cmds[0]
        assert "-m 0644" in install_cmd
        assert "-o root" in install_cmd
        assert "-g root" in install_cmd


class TestCliGuards:
    def _invoke(self, *args):
        from click.testing import CliRunner
        import click
        from tee_crafter.cli.commands.deploy.deploy import register
        cli = click.Group()
        register(cli)
        runner = CliRunner()
        return runner.invoke(cli, list(args))

    def test_batch_persistent_mutually_exclusive(self, tmp_path: Path):
        src = tmp_path / "app"
        src.mkdir()
        (src / "Dockerfile").write_text("FROM alpine\nCMD true\n")
        result = self._invoke(
            "deploy", "--source", str(src),
            "--tee-platform", "tdx-azure", "--batch", "--persistent",
        )
        assert "mutually exclusive" in result.output

    def test_sgx_requires_batch(self, tmp_path: Path):
        src = tmp_path / "app"
        src.mkdir()
        (src / "Dockerfile").write_text("FROM alpine\nCMD true\n")
        result = self._invoke(
            "deploy", "--source", str(src),
            "--tee-platform", "sgx-azure",
        )
        # No --batch/--persistent: generic run-mode guard fires first.
        assert "run mode required" in result.output.lower()

    def test_sgx_rejects_persistent_service_profile(self, tmp_path: Path):
        src = tmp_path / "app"
        src.mkdir()
        (src / "Dockerfile").write_text("FROM alpine\nCMD true\n")
        result = self._invoke(
            "deploy", "--source", str(src),
            "--tee-platform", "sgx-azure", "--persistent",
        )
        assert "batch-only" in result.output.lower()

    def test_nitro_batch_rejected_before_any_provisioning(self, tmp_path: Path):
        """``--batch --tee-platform nitro-aws`` must fail in pre-flight.

        A Nitro Enclave boots a signed EIF, not an operator-supplied OCI
        image, so ``resources._CONTAINER_CFG`` has no ``nitro-aws`` entry.
        The dispatcher routed Nitro into the container-batch branch anyway
        (``batch_dispatch._AWS_VM or _NITRO``), so ``load_container_batch_unit``
        raised ``ValueError`` *after* Terraform apply and the image upload —
        the exception was swallowed into a discarded ``BatchResult``, the CLI
        exited 0, and the instance kept billing.  ``nitro-aws`` is the default
        platform, which is how this reached the README's first example.
        """
        src = tmp_path / "app"
        src.mkdir()
        (src / "Dockerfile").write_text("FROM alpine\nCMD true\n")
        result = self._invoke(
            "deploy", "--source", str(src),
            "--tee-platform", "nitro-aws", "--batch",
        )
        assert result.exit_code != 0, result.output
        out = result.output.lower()
        assert "not supported for container workloads" in out
        assert "nitro enclaves cannot run arbitrary container images" in out
        assert "snp-" in out and "tdx-" in out, "message must name the alternatives"

    def test_nitro_batch_guard_matches_the_unit_loader(self):
        """The pre-flight allowlist is derived from the unit table itself.

        Guards against the two drifting apart again: anything
        ``load_container_batch_unit`` can render must be accepted, and
        anything it cannot must be rejected.
        """
        from tee_crafter.resources import (
            CONTAINER_PLATFORMS, load_container_batch_unit,
        )
        assert "nitro-aws" not in CONTAINER_PLATFORMS
        for platform in CONTAINER_PLATFORMS:
            assert load_container_batch_unit(platform)
        with pytest.raises(ValueError):
            load_container_batch_unit("nitro-aws")

    def test_batch_persistent_conflict_exits_non_zero(self, tmp_path: Path):
        """Validation failures must be non-zero exits, not a red panel + rc=0.

        The existing guard tests above assert only on ``result.output``, which
        is why every one of these paths could ``return`` from the Click
        callback — a *successful* exit — without any test noticing.
        """
        src = tmp_path / "app"
        src.mkdir()
        (src / "Dockerfile").write_text("FROM alpine\nCMD true\n")
        result = self._invoke(
            "deploy", "--source", str(src),
            "--tee-platform", "tdx-azure", "--batch", "--persistent",
        )
        assert result.exit_code != 0, result.output

    def test_no_run_mode_exits_non_zero(self, tmp_path: Path):
        src = tmp_path / "app"
        src.mkdir()
        (src / "Dockerfile").write_text("FROM alpine\nCMD true\n")
        result = self._invoke("deploy", "--source", str(src),
                              "--tee-platform", "tdx-azure")
        assert result.exit_code != 0, result.output

    def test_sgx_persistent_exits_non_zero(self, tmp_path: Path):
        src = tmp_path / "app"
        src.mkdir()
        (src / "Dockerfile").write_text("FROM alpine\nCMD true\n")
        result = self._invoke("deploy", "--source", str(src),
                              "--tee-platform", "sgx-azure", "--persistent")
        assert result.exit_code != 0, result.output
