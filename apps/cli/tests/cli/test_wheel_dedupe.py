"""Tests for image-manifest-aware deploy-time wheel dedupe.

Every bake script writes ``/etc/tee_crafter/image_pip_frozen.txt`` (a
``pip freeze`` of the venv on the baked image).  At deploy time the
orchestrator reads it back over the same transport that runs the bake
script, and uses it to skip downloading wheels the image already
satisfies.  For GPU-CC this turns a ~2.9 GB upload (torch + the CUDA
wheel set) into a ~MB-scale delta.

These tests pin the dedupe contract: only **exact ``==`` pins** are
dropped, looser specs (ranges, markers, editables, VCS refs) are kept
verbatim so we never silently violate the user's spec.
"""
from __future__ import annotations

import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tee_crafter.cli.deployment.common import wheel_manager as wm  # noqa: E402


# ---------------------------------------------------------------------------
#  parse_pip_freeze
# ---------------------------------------------------------------------------

def test_parse_pip_freeze_simple_pins() -> None:
    text = textwrap.dedent(
        """
        torch==2.5.1
        numpy==1.26.4
        # comment
        nvidia-cuda-nvrtc-cu12==12.4.127

        Pillow==10.4.0
        """
    ).strip()
    out = wm.parse_pip_freeze(text)
    assert out == {
        "torch": "2.5.1",
        "numpy": "1.26.4",
        "nvidia-cuda-nvrtc-cu12": "12.4.127",
        "pillow": "10.4.0",
    }


def test_parse_pip_freeze_normalizes_names() -> None:
    text = "Some_Pkg==1.0\nUPPER==2.0\nMixed_Case_Name==3.0"
    out = wm.parse_pip_freeze(text)
    assert out == {"some-pkg": "1.0", "upper": "2.0", "mixed-case-name": "3.0"}


def test_parse_pip_freeze_skips_non_pin_lines() -> None:
    """Editables, direct URLs, VCS refs, and other non-pin lines are dropped."""
    text = textwrap.dedent(
        """
        torch==2.5.1
        -e git+https://github.com/foo/bar@deadbeef#egg=bar
        @ file:///tmp/some-wheel.whl
        git+https://example.com/proj.git
        # plain comment
        --extra-index-url https://example.com/pypi
        weirdline-without-pins
        """
    ).strip()
    out = wm.parse_pip_freeze(text)
    assert out == {"torch": "2.5.1"}


# ---------------------------------------------------------------------------
#  filter_requirements_against_image
# ---------------------------------------------------------------------------

def test_filter_drops_exact_pin_matches() -> None:
    req = textwrap.dedent(
        """
        torch==2.5.1
        torchvision==0.20.1
        nvidia-cuda-nvrtc-cu12==12.4.127
        myapp-only==9.9.9
        """
    ).lstrip()
    image = {
        "torch": "2.5.1",
        "torchvision": "0.20.1",
        "nvidia-cuda-nvrtc-cu12": "12.4.127",
    }
    filtered, skipped = wm.filter_requirements_against_image(req, image)
    assert sorted(skipped) == [
        "nvidia-cuda-nvrtc-cu12==12.4.127",
        "torch==2.5.1",
        "torchvision==0.20.1",
    ]
    assert "torch==" not in filtered
    assert "nvidia-cuda-nvrtc-cu12" not in filtered
    assert "myapp-only==9.9.9" in filtered


def test_filter_keeps_version_mismatch() -> None:
    """Image has torch==2.5.0, user wants ==2.5.1 → must NOT drop."""
    req = "torch==2.5.1\n"
    image = {"torch": "2.5.0"}
    filtered, skipped = wm.filter_requirements_against_image(req, image)
    assert "torch==2.5.1" in filtered
    assert skipped == []


def test_filter_keeps_range_specs() -> None:
    """Range / open specs must never be dropped — only exact ``==`` pins."""
    req = textwrap.dedent(
        """
        torch>=2.5,<3
        numpy~=1.26
        Pillow!=10.0.0
        bare-pkg
        """
    ).lstrip()
    image = {"torch": "2.5.1", "numpy": "1.26.4", "pillow": "10.4.0", "bare-pkg": "9.9.9"}
    filtered, skipped = wm.filter_requirements_against_image(req, image)
    assert skipped == []
    for line in ("torch>=2.5,<3", "numpy~=1.26", "Pillow!=10.0.0", "bare-pkg"):
        assert line in filtered


def test_filter_keeps_environment_markers() -> None:
    """Lines with environment markers are kept verbatim — we can't
    evaluate ``sys_platform`` etc on the deployer for the target VM, so
    let pip do it.
    """
    req = 'torch==2.5.1 ; sys_platform == "linux"\n'
    image = {"torch": "2.5.1"}
    filtered, skipped = wm.filter_requirements_against_image(req, image)
    assert skipped == []
    assert 'torch==2.5.1 ; sys_platform == "linux"' in filtered


def test_filter_preserves_comments_and_blank_lines() -> None:
    req = textwrap.dedent(
        """
        # Heavy GPU stack
        torch==2.5.1

        # Light app deps
        requests==2.31.0
        """
    ).lstrip()
    image = {"torch": "2.5.1"}
    filtered, skipped = wm.filter_requirements_against_image(req, image)
    assert skipped == ["torch==2.5.1"]
    assert "# Heavy GPU stack" in filtered
    assert "# Light app deps" in filtered
    assert "requests==2.31.0" in filtered


def test_filter_empty_image_pins_is_passthrough() -> None:
    """An unbaked deploy (missing manifest) must behave exactly like the
    pre-optimization code path: no lines filtered out.
    """
    req = "torch==2.5.1\nnumpy==1.26.4\n"
    filtered, skipped = wm.filter_requirements_against_image(req, {})
    assert skipped == []
    assert filtered == req


# ---------------------------------------------------------------------------
#  fetch_image_pip_manifest
# ---------------------------------------------------------------------------

def test_fetch_manifest_parses_remote_freeze_output() -> None:
    def fake_run(cmd, *, timeout):  # noqa: ARG001
        return True, "torch==2.5.1\ntorchvision==0.20.1\n", ""
    pins = wm.fetch_image_pip_manifest(fake_run)
    assert pins == {"torch": "2.5.1", "torchvision": "0.20.1"}


def test_fetch_manifest_missing_file_returns_empty() -> None:
    """``cat ... || true`` returns ok=True with empty stdout when the file
    doesn't exist (unbaked image / older bake).  We must treat that as
    "no manifest, full download" instead of crashing.
    """
    def fake_run(cmd, *, timeout):  # noqa: ARG001
        return True, "", ""
    assert wm.fetch_image_pip_manifest(fake_run) == {}


def test_fetch_manifest_transport_failure_returns_empty() -> None:
    """Same applies if the SSH/SSM call itself fails — never raise."""
    def fake_run(cmd, *, timeout):  # noqa: ARG001
        return False, "", "connection reset"
    assert wm.fetch_image_pip_manifest(fake_run) == {}


def test_fetch_manifest_swallows_exceptions() -> None:
    """Even a runtime exception in the transport callable is non-fatal:
    dedupe is opportunistic, the deploy must continue with a full download.
    """
    def fake_run(cmd, *, timeout):  # noqa: ARG001
        raise RuntimeError("boom")
    assert wm.fetch_image_pip_manifest(fake_run) == {}


# ---------------------------------------------------------------------------
#  download_wheels_delta integration
# ---------------------------------------------------------------------------

def test_download_wheels_delta_skips_when_all_satisfied(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """If every line in the user's requirements.txt is already pinned by
    the image, we must not run ``pip download`` at all and must return 0.
    """
    req = tmp_path / "req.txt"
    req.write_text("torch==2.5.1\ntorchvision==0.20.1\n")
    dest = tmp_path / "wheels"

    called: list[tuple] = []

    def fake_download(req_file, py_version, dest_dir, console, label, timeout=300):  # noqa: ARG001
        called.append((req_file, py_version, dest_dir))
        return 99

    monkeypatch.setattr(wm, "download_wheels", fake_download)

    class _Console:
        def print(self, *a, **kw): pass

    n = wm.download_wheels_delta(
        str(req), "3.10", str(dest), _Console(), "test",
        image_pins={"torch": "2.5.1", "torchvision": "0.20.1"},
    )
    assert n == 0
    assert called == []
    assert dest.is_dir()


def test_download_wheels_delta_falls_through_with_empty_manifest(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No manifest → behaviour identical to ``download_wheels`` (unfiltered)."""
    req = tmp_path / "req.txt"
    req.write_text("torch==2.5.1\n")
    dest = tmp_path / "wheels"

    captured: dict[str, str] = {}

    def fake_download(req_file, py_version, dest_dir, console, label, timeout=300):  # noqa: ARG001
        captured["req"] = req_file
        return 1

    monkeypatch.setattr(wm, "download_wheels", fake_download)

    class _Console:
        def print(self, *a, **kw): pass

    n = wm.download_wheels_delta(
        str(req), "3.10", str(dest), _Console(), "test",
        image_pins=None,
    )
    assert n == 1
    assert captured["req"] == str(req)


def test_download_wheels_delta_downloads_only_unbaked_deltas(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """User has 4 deps, 2 are baked.  Only the other 2 must be downloaded."""
    req = tmp_path / "req.txt"
    req.write_text("torch==2.5.1\nnumpy==1.26.4\nmyapp-only==9.9.9\nrequests==2.31.0\n")
    dest = tmp_path / "wheels"

    captured: dict[str, str] = {}

    def fake_download(req_file, py_version, dest_dir, console, label, timeout=300):  # noqa: ARG001
        with open(req_file, "r") as f:
            captured["text"] = f.read()
        os.makedirs(dest_dir, exist_ok=True)
        (os.path.join(dest_dir, "fake.whl"),)
        return 2

    monkeypatch.setattr(wm, "download_wheels", fake_download)

    class _Console:
        def print(self, *a, **kw): pass

    n = wm.download_wheels_delta(
        str(req), "3.10", str(dest), _Console(), "test",
        image_pins={"torch": "2.5.1", "numpy": "1.26.4"},
    )
    assert n == 2
    text = captured["text"]
    assert "torch==2.5.1" not in text
    assert "numpy==1.26.4" not in text
    assert "myapp-only==9.9.9" in text
    assert "requests==2.31.0" in text
