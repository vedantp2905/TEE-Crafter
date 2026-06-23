"""Tests for `core/builder/`: template rendering, artifact staging for all TEE platforms."""

import os

import pytest

from tee_crafter.core.builder import (
    stage_artifacts,
    stage_sgx_artifacts,
    stage_snp_aws_artifacts,
    stage_snp_azure_artifacts,
    stage_tdx_artifacts,
)


@pytest.fixture
def source_app(tmp_path):
    """Create a minimal source app directory."""
    src = tmp_path / "myapp"
    src.mkdir()
    (src / "app.py").write_text('if __name__ == "__main__":\n    print("hello")\n')
    (src / "requirements.txt").write_text("numpy==1.26\n")
    return str(src)


class TestStageArtifactsNitro:
    def test_creates_build_dir(self, source_app, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        vsock_code = "# vsock code\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        dockerfile = "FROM python:3.12\n"
        build_path = stage_artifacts(source_app, vsock_code, dockerfile, stage_label="nitro")
        assert os.path.isdir(build_path)

    def test_nitro_layout(self, source_app, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        vsock_code = "# vsock code\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        dockerfile = "FROM python:3.12\n"
        build_path = stage_artifacts(source_app, vsock_code, dockerfile, stage_label="nitro")
        assert os.path.isfile(os.path.join(build_path, "app_vsock.py"))
        assert os.path.isfile(os.path.join(build_path, "Dockerfile"))
        assert os.path.isfile(os.path.join(build_path, "app.py"))

    def test_output_schema_not_consumed(self, source_app, tmp_path, monkeypatch):
        """Container-orchestrated model: an output_schema.json in the source is
        ignored — the in-TEE _OUTPUT_SCHEMA placeholder is left inert (None)."""
        monkeypatch.chdir(tmp_path)
        with open(os.path.join(source_app, "output_schema.json"), "w") as f:
            f.write('{"type": "object", "properties": {"result": {"type": "number"}}}')
        vsock_code = "code\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\nmore"
        build_path = stage_artifacts(source_app, vsock_code, "FROM python:3.12", stage_label="nitro")
        vsock_content = open(os.path.join(build_path, "app_vsock.py")).read()
        # Placeholder is NOT replaced; no schema literal is embedded.
        assert "_OUTPUT_SCHEMA = None" in vsock_content
        assert '"result"' not in vsock_content
        assert not os.path.isfile(os.path.join(build_path, "tee_crafter_output_validator.py"))


class TestStageArtifactsSGX:
    def test_sgx_layout(self, source_app, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        vsock_code = "# sgx\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_artifacts(source_app, vsock_code, "", stage_label="sgx-azure")
        assert os.path.isfile(os.path.join(build_path, "app_vsock.py"))
        assert os.path.isdir(os.path.join(build_path, "app"))
        assert os.path.isfile(os.path.join(build_path, "app", "app.py"))


class TestStageArtifactsTDX:
    def test_tdx_layout(self, source_app, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        vsock_code = "# tdx\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_artifacts(source_app, vsock_code, "", stage_label="tdx-azure")
        assert os.path.isdir(os.path.join(build_path, "app"))

    def test_tdx_copies_source(self, source_app, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        vsock_code = "# tdx\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_artifacts(source_app, vsock_code, "", stage_label="tdx-azure")
        assert os.path.isfile(os.path.join(build_path, "app", "app.py"))


class TestStageSgxArtifacts:
    def test_new_build_dir(self, source_app, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        gramine_code = "# gramine\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        manifest = "[manifest]\n"
        build_path = stage_sgx_artifacts(source_app, gramine_code, manifest)
        assert os.path.isdir(build_path)
        assert os.path.isfile(os.path.join(build_path, "app_gramine.manifest.toml"))
        assert os.path.isfile(os.path.join(build_path, "app", "app_gramine.py"))

    def test_existing_build_dir(self, source_app, tmp_path):
        app_dir = os.path.join(str(tmp_path), "app")
        os.makedirs(app_dir)
        gramine_code = "# gramine\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        manifest = "[manifest]\n"
        build_path = stage_sgx_artifacts(source_app, gramine_code, manifest, existing_build_dir=str(tmp_path))
        assert os.path.isfile(os.path.join(build_path, "app", "app_gramine.py"))
        assert os.path.isfile(os.path.join(build_path, "app_gramine.manifest.toml"))


class TestStageTdxArtifacts:
    def test_new_build_dir(self, source_app, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        tdx_code = "# tdx\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_tdx_artifacts(source_app, tdx_code)
        assert os.path.isdir(build_path)
        assert os.path.isfile(os.path.join(build_path, "app", "app_tdx.py"))

    def test_existing_build_dir(self, source_app, tmp_path):
        app_dir = os.path.join(str(tmp_path), "app")
        os.makedirs(app_dir)
        tdx_code = "# tdx\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_tdx_artifacts(source_app, tdx_code, existing_build_dir=str(tmp_path))
        assert os.path.isfile(os.path.join(build_path, "app", "app_tdx.py"))


class TestStageSnpAwsArtifacts:
    def test_new_build_dir(self, source_app, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        snp_code = "# snp\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_snp_aws_artifacts(source_app, snp_code)
        assert os.path.isdir(build_path)
        assert os.path.isfile(os.path.join(build_path, "app", "app_snp.py"))

    def test_existing_build_dir(self, source_app, tmp_path):
        snp_code = "# snp\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_snp_aws_artifacts(source_app, snp_code, existing_build_dir=str(tmp_path))
        assert os.path.isfile(os.path.join(build_path, "app", "app_snp.py"))


class TestStageSnpAzureArtifacts:
    def test_new_build_dir(self, source_app, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        snp_code = "# snp azure\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_snp_azure_artifacts(source_app, snp_code)
        assert os.path.isdir(build_path)
        assert os.path.isfile(os.path.join(build_path, "app", "app_snp.py"))

    def test_existing_build_dir(self, source_app, tmp_path):
        snp_code = "# snp azure\n_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_snp_azure_artifacts(source_app, snp_code, existing_build_dir=str(tmp_path))
        assert os.path.isfile(os.path.join(build_path, "app", "app_snp.py"))


class TestIgnorePatterns:
    def test_venv_excluded(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("pass")
        venv = src / "venv"
        venv.mkdir()
        (venv / "junk.py").write_text("junk")
        vsock_code = "_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_artifacts(str(src), vsock_code, "FROM python:3.12", stage_label="nitro")
        assert not os.path.isdir(os.path.join(build_path, "venv"))

    def test_git_excluded(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("pass")
        git = src / ".git"
        git.mkdir()
        (git / "HEAD").write_text("ref")
        vsock_code = "_OUTPUT_SCHEMA = None  # OUTPUT_SCHEMA_PLACEHOLDER\n"
        build_path = stage_artifacts(str(src), vsock_code, "FROM python:3.12", stage_label="nitro")
        assert not os.path.isdir(os.path.join(build_path, ".git"))
