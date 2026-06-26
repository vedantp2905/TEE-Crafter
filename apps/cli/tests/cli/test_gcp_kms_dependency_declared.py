"""`--byok gcp-kms` needs a Cloud KMS client that is actually installed.

Found on 2026-08-21 during the first real ``snp-gcp`` deploy.  ``boto3`` was a
pinned dependency, so ``--byok aws-kms --secrets-env ...`` worked; nothing
declared ``google-cloud-kms``, so the same flags with ``gcp-kms`` aborted with

    ModuleNotFoundError: No module named 'google'

raised from ``_kms_wrap_dek``'s lazy import -- an unhandled traceback, not a
CLI error, and only *after* the user image had been built and scanned.

Two separate defects, so two sets of assertions: the dependency must be
declared for every install path, and the import site must fail like a CLI
rather than like a crash if it is ever missing anyway (a stale editable
install or an old container image both reproduce it).
"""

import os
import re

import pytest

_CLI_ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
_PYPROJECT = os.path.join(_CLI_ROOT, "pyproject.toml")
_REQUIREMENTS = os.path.join(_CLI_ROOT, "requirements.txt")

PACKAGE = "google-cloud-kms"


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestDependencyIsDeclared:
    """Both files, because they are installed by different paths.

    ``pip install -e apps/cli`` reads ``pyproject.toml``; the container image
    also installs ``requirements.txt`` (``apps/cli/Dockerfile``).  Declaring it
    in only one leaves the other broken.
    """

    def test_declared_in_pyproject(self):
        deps = _read(_PYPROJECT).split("dependencies = [", 1)[1].split("]", 1)[0]
        assert PACKAGE in deps

    def test_declared_in_requirements(self):
        assert PACKAGE in _read(_REQUIREMENTS)

    def test_pinned_exactly_like_its_neighbours(self):
        """Every other runtime dependency is `==`-pinned; match that."""
        for path in (_PYPROJECT, _REQUIREMENTS):
            m = re.search(rf"{re.escape(PACKAGE)}==([0-9][^\"'\s]*)", _read(path))
            assert m, f"{PACKAGE} is not =='-pinned in {os.path.basename(path)}"

    def test_both_files_pin_the_same_version(self):
        """A split pin means the image and the editable install disagree."""
        versions = {
            re.search(rf"{re.escape(PACKAGE)}==([0-9][^\"'\s]*)",
                      _read(p)).group(1)
            for p in (_PYPROJECT, _REQUIREMENTS)
        }
        assert len(versions) == 1, f"version drift: {versions}"

    def test_the_client_actually_imports(self):
        """The point of the pin: the module must be importable, not just named."""
        from google.cloud import kms  # noqa: F401

    def test_aws_counterpart_still_declared(self):
        """Guards the asymmetry that caused this: one cloud pinned, one not."""
        assert "boto3" in _read(_PYPROJECT)


class TestMissingClientFailsCleanly:
    def test_import_error_becomes_a_secret_env_error(self, monkeypatch):
        """Simulate the stale-image case and assert on the surfaced error.

        `_kms_wrap_dek` is reached mid-deploy, so a raw traceback there is both
        ugly and uninformative about the fix.
        """
        import builtins

        from tee_crafter.cli.commands.deploy import secret_env

        real_import = builtins.__import__

        def _no_google(name, *args, **kwargs):
            if name == "google.cloud" or name.startswith("google.cloud"):
                raise ImportError("No module named 'google'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _no_google)

        with pytest.raises(secret_env.SecretEnvError) as exc:
            secret_env._kms_wrap_dek(
                b"0" * 32,
                provider="gcp-kms",
                key_id="projects/p/locations/l/keyRings/r/cryptoKeys/k",
                region="us-central1",
                encryption_context={},
                kms_client=None,
            )
        msg = str(exc.value)
        assert "google-cloud-kms" in msg
        # Must name a way out, not just the symptom.
        assert "docker-build-cli" in msg or "pip install" in msg

    def test_supplied_client_needs_no_import(self):
        """An injected client must not touch google.cloud at all."""
        from tee_crafter.cli.commands.deploy import secret_env

        class _Resp:
            ciphertext = b"wrapped-bytes"

        class _Client:
            def __init__(self):
                self.calls = []

            def encrypt(self, request):
                self.calls.append(request)
                return _Resp()

        client = _Client()
        out = secret_env._kms_wrap_dek(
            b"1" * 32,
            provider="gcp-kms",
            key_id="projects/p/locations/l/keyRings/r/cryptoKeys/k",
            region="us-central1",
            encryption_context={},
            kms_client=client,
        )
        import base64
        assert base64.b64decode(out) == b"wrapped-bytes"
        assert client.calls[0]["name"].endswith("cryptoKeys/k")
