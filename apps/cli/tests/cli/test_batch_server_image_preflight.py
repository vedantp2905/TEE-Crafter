"""``--batch`` must reject-shaped feedback arrive before Terraform, not after it.

Batch mode runs the user image as-is and captures what it wrote once it exits.
A server never exits, so the oneshot sits until ``TimeoutStartSec`` — an hour by
default — and then fails with nothing captured.  That is an easy mistake to
make: of the four shipped examples, ``docker_flask_api``, ``hello_http`` and
``gpu_confidential_inference`` all ``EXPOSE 8080`` and run a listener, and only
``fintech_fraud_detection`` is batch-shaped.

The check existed, but it ran on the VM after ``docker load`` — roughly twenty
minutes of Terraform and Bastion provisioning after the point where the operator
could have done anything about it.  It now runs against the freshly built local
image, before any cloud resource exists.

``ExposedPorts`` on the *built image* is the discriminator rather than a grep for
``EXPOSE`` in the Dockerfile, because a port inherited from the base image is
invisible to the latter and equally fatal.
"""
from __future__ import annotations

import pathlib

import pytest

from tee_crafter.cli.commands.deploy import flow_container

REPO = pathlib.Path(__file__).resolve().parents[4]
EXAMPLES = REPO / "examples"


@pytest.fixture
def captured(monkeypatch):
    printed: list[str] = []
    monkeypatch.setattr(
        flow_container.console, "print",
        lambda *a, **k: printed.append(" ".join(str(x) for x in a)))
    return printed


def _with_port_count(monkeypatch, count):
    monkeypatch.setattr(flow_container, "exposed_port_count", lambda _tag: count)


class TestTheHeuristic:
    def test_an_exposed_port_warns(self, monkeypatch, captured):
        _with_port_count(monkeypatch, 1)
        assert flow_container.warn_if_batch_image_looks_like_a_server(
            "img", batch_timeout=3600)
        assert "long-running server" in "\n".join(captured)
        assert "3600s" in "\n".join(captured)

    def test_no_exposed_ports_is_silent(self, monkeypatch, captured):
        _with_port_count(monkeypatch, 0)
        assert not flow_container.warn_if_batch_image_looks_like_a_server(
            "img", batch_timeout=3600)
        assert captured == []

    def test_multiple_ports_are_counted(self, monkeypatch, captured):
        _with_port_count(monkeypatch, 3)
        flow_container.warn_if_batch_image_looks_like_a_server(
            "img", batch_timeout=3600)
        assert "3 port(s)" in "\n".join(captured)

    def test_it_points_at_the_batch_shaped_example(self, monkeypatch, captured):
        _with_port_count(monkeypatch, 1)
        flow_container.warn_if_batch_image_looks_like_a_server(
            "img", batch_timeout=3600)
        assert "fintech_fraud_detection" in "\n".join(captured)

    def test_it_only_warns_and_never_blocks(self):
        """A batch job may legitimately expose a port."""
        import inspect
        src = inspect.getsource(
            flow_container.warn_if_batch_image_looks_like_a_server)
        assert "raise" not in src


class TestAnUnreadableImageIsSilent:
    """Never warn on a reading we could not make."""

    def test_a_failed_inspect_reads_zero(self, monkeypatch):
        class _Result:
            returncode = 1
            stdout = ""
        monkeypatch.setattr(flow_container.subprocess, "run",
                            lambda *a, **k: _Result())
        assert flow_container.exposed_port_count("nope") == 0

    def test_unparseable_output_reads_zero(self, monkeypatch):
        class _Result:
            returncode = 0
            stdout = "<no value>\n"
        monkeypatch.setattr(flow_container.subprocess, "run",
                            lambda *a, **k: _Result())
        assert flow_container.exposed_port_count("img") == 0

    def test_empty_output_reads_zero(self, monkeypatch):
        class _Result:
            returncode = 0
            stdout = ""
        monkeypatch.setattr(flow_container.subprocess, "run",
                            lambda *a, **k: _Result())
        assert flow_container.exposed_port_count("img") == 0


class TestItRunsBeforeAnythingIsProvisioned:
    def test_run_container_phases_accepts_the_batch_flag(self):
        import inspect
        params = inspect.signature(flow_container.run_container_phases).parameters
        assert "batch" in params and "batch_timeout" in params

    def test_it_is_called_from_the_build_step(self):
        import inspect
        src = inspect.getsource(flow_container.run_container_phases)
        assert "warn_if_batch_image_looks_like_a_server" in src

    def test_the_warning_precedes_terraform_in_the_deploy_command(self):
        """``run_container_phases`` is the build phase; Terraform comes later."""
        from tee_crafter.cli.commands.deploy import deploy_container
        import inspect
        src = inspect.getsource(deploy_container)
        assert "batch=batch_mode" in src

    def test_only_batch_mode_triggers_it(self):
        """A --persistent server is the correct shape; do not nag."""
        import inspect
        src = inspect.getsource(flow_container.run_container_phases)
        assert "if batch:" in src


class TestTheShippedExamplesStillSplitTheWayTheDocsClaim:
    """The prose names specific examples; hold it to them."""

    SERVERS = ("docker_flask_api", "hello_http", "gpu_confidential_inference")
    BATCH = "fintech_fraud_detection"

    @pytest.mark.parametrize("name", SERVERS)
    def test_the_server_examples_expose_a_port(self, name):
        dockerfile = EXAMPLES / name / "Dockerfile"
        assert dockerfile.is_file(), f"{name} example is missing"
        assert "EXPOSE" in dockerfile.read_text(encoding="utf-8")

    def test_the_batch_example_exposes_none(self):
        dockerfile = EXAMPLES / self.BATCH / "Dockerfile"
        assert dockerfile.is_file()
        assert "EXPOSE" not in dockerfile.read_text(encoding="utf-8")

    def test_the_examples_readme_names_the_only_batch_shaped_example(self):
        """An operator should not have to read Dockerfiles to find this out."""
        readme = (EXAMPLES / "README.md").read_text(encoding="utf-8")
        assert f"Only `{self.BATCH}` is batch-shaped" in readme

    def test_the_examples_readme_explains_the_hang(self):
        """The failure mode is a silent hour-long wait, not an error."""
        readme = (EXAMPLES / "README.md").read_text(encoding="utf-8")
        assert "--batch-timeout" in readme
        assert "captured nothing" in readme
