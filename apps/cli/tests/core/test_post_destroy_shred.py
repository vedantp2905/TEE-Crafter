"""Tests for the post-destroy secret-shredding helper (G-4)."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from tee_crafter.core.iac.post_destroy_shred import (
    is_covered_by_shred_globs,
    shred_post_destroy,
)

TEMPLATES_DIR = (Path(__file__).resolve().parents[2]
                 / "src" / "tee_crafter" / "templates")

#: `filename = abspath("${path.module}/sgx_ssh_key")` and the `.pem` variants.
_FILENAME_RE = re.compile(r'filename\s*=\s*(?P<expr>.+)')
_MODULE_PATH_RE = re.compile(r'\$\{path\.module\}/(?P<name>[^"\']+)')


def _sensitive_filenames(tf_path: Path) -> list[str]:
    """Basenames every ``local_sensitive_file`` in *tf_path* writes."""
    text = tf_path.read_text(encoding="utf-8")
    names: list[str] = []
    for block in re.finditer(
            r'resource\s+"local_sensitive_file"\s+"[^"]+"\s*\{(?P<body>.*?)\n\}',
            text, flags=re.DOTALL):
        m = _FILENAME_RE.search(block.group("body"))
        assert m, f"{tf_path}: local_sensitive_file with no filename"
        name = _MODULE_PATH_RE.search(m.group("expr"))
        assert name, f"{tf_path}: unparsed filename {m.group('expr')!r}"
        names.append(name.group("name"))
    return names


def test_templates_are_discoverable():
    templates = sorted(TEMPLATES_DIR.glob("*/main.template.tf")) + \
        sorted(TEMPLATES_DIR.glob("*/*/main.template.tf"))
    assert len(templates) == 10, [str(t) for t in templates]


@pytest.mark.parametrize("tf_path", sorted(
    list(TEMPLATES_DIR.glob("*/main.template.tf"))
    + list(TEMPLATES_DIR.glob("*/*/main.template.tf"))),
    ids=lambda p: str(p.relative_to(TEMPLATES_DIR)))
def test_every_template_sensitive_file_is_shredded(tf_path: Path):
    """The durable fix for filename drift.

    Five of seven SSH private keys survived teardown because the glob was
    ``*_ssh_key.pem`` while ``sgx``, ``tdx/azure``, ``snp/gcp``, ``tdx/gcp``
    and ``gpu_cc/gcp`` write extension-less names.  Rather than re-enumerate
    the names, assert that whatever the templates write today is covered.
    """
    for name in _sensitive_filenames(tf_path):
        assert is_covered_by_shred_globs(name), (
            f"{tf_path.relative_to(TEMPLATES_DIR)} writes {name!r}, which no "
            f"_SHRED_GLOBS entry matches — it will survive terraform destroy")


def test_extensionless_ssh_keys_are_covered():
    """Explicit regression list for the five names that used to be missed."""
    for name in ("sgx_ssh_key", "tdx_ssh_key", "snp_gcp_ssh_key",
                 "tdx_gcp_ssh_key", "gpu_cc_gcp_ssh_key"):
        assert is_covered_by_shred_globs(name), name


def test_app_env_is_covered():
    assert is_covered_by_shred_globs("app.env")
    assert is_covered_by_shred_globs("app/app.env")


def test_unrelated_files_are_not_covered():
    for name in ("main.tf", "terraform.tfstate", "byok.json", "app/Dockerfile"):
        assert not is_covered_by_shred_globs(name), name


def _populate(build_dir: Path) -> dict[str, Path]:
    files = {
        "ssh": build_dir / "snp_ssh_key.pem",
        "ssh_alt": build_dir / "gpu_cc_ssh_key.pem",
        # Extension-less names written by sgx / tdx-azure / *-gcp templates.
        "ssh_sgx": build_dir / "sgx_ssh_key",
        "ssh_tdx": build_dir / "tdx_ssh_key",
        "ssh_snp_gcp": build_dir / "snp_gcp_ssh_key",
        "ssh_tdx_gcp": build_dir / "tdx_gcp_ssh_key",
        "ssh_gpu_gcp": build_dir / "gpu_cc_gcp_ssh_key",
        "tfstate_backup": build_dir / "terraform.tfstate.backup",
        "authorised": build_dir / "iap_authorised_keys.tmp",
        "siem": build_dir / "siem.env",
        "byok": build_dir / "byok.env",
        "app_siem": build_dir / "app" / "siem.env",
        "app_env": build_dir / "app.env",
        "app_app_env": build_dir / "app" / "app.env",
        "keep1": build_dir / "main.tf",
        "keep2": build_dir / "terraform.tfstate",
    }
    (build_dir / "app").mkdir(parents=True, exist_ok=True)
    for path in files.values():
        path.write_text("x" * 64)
    return files


def test_shreds_known_globs(tmp_path: Path):
    files = _populate(tmp_path)
    removed = shred_post_destroy(str(tmp_path))
    expected = [k for k in files if not k.startswith("keep")]
    assert set(str(files[k]) for k in expected).issubset(set(removed))
    for key in expected:
        assert not files[key].exists(), key
    man = tmp_path / "post_destroy_shred_manifest.txt"
    assert man.is_file()
    txt = man.read_text(encoding="utf-8")
    assert "siem.env" in txt
    assert "post-destroy shred manifest" in txt


def test_whole_file_is_overwritten_not_just_the_first_8mib(tmp_path: Path):
    """The zero-fill used to stop at 8 MiB, silently leaving the rest.

    ``terraform.tfstate.backup`` is both the largest file in the list and the
    one the module calls "the last remaining copy of these secrets".
    """
    marker = b"SECRET-PAST-8MIB"
    target = tmp_path / "terraform.tfstate.backup"
    with open(target, "wb") as fh:
        fh.write(b"\xa5" * (9 * 1024 * 1024))
        fh.write(marker)
    size = target.stat().st_size

    # A hard link keeps the inode (and therefore the bytes actually written to
    # disk) observable after shred_post_destroy unlinks its own path.
    witness = tmp_path / "witness.bin"
    os.link(target, witness)

    shred_post_destroy(str(tmp_path))

    assert not target.exists()
    content = witness.read_bytes()
    assert len(content) == size
    assert marker not in content
    assert content == b"\x00" * size


def test_preserves_unrelated_files(tmp_path: Path):
    files = _populate(tmp_path)
    shred_post_destroy(str(tmp_path))
    assert files["keep1"].is_file()
    assert files["keep2"].is_file()


def test_missing_dir_is_noop(tmp_path: Path):
    assert shred_post_destroy(str(tmp_path / "nope")) == []


def test_idempotent(tmp_path: Path):
    _populate(tmp_path)
    first = shred_post_destroy(str(tmp_path))
    second = shred_post_destroy(str(tmp_path))
    assert first
    assert second == []
