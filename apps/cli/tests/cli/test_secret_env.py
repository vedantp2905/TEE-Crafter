"""Tests for attested sealed-.env injection (host seal + in-TEE release)."""
from __future__ import annotations

import base64
import importlib.util
import json
import os

import pytest

from tee_crafter.cli.commands.deploy.secret_env import (
    SecretEnvError,
    apply_secret_env,
    load_dotenv_plaintext,
    seal_secret_env,
)


class _FakeKms:
    """Trivial reversible 'wrap': ciphertext = b'WRAP|' + dek."""

    def encrypt(self, *, KeyId, Plaintext, EncryptionContext):  # noqa: N803 (boto3 casing)
        assert KeyId
        return {"CiphertextBlob": b"WRAP|" + Plaintext}


def _decrypt_bundle(bundle_b64: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    bundle = json.loads(base64.b64decode(bundle_b64))
    dek = base64.b64decode(bundle["wrapped_dek_b64"])[len("WRAP|"):]
    nonce = base64.b64decode(bundle["env_nonce_b64"])
    ct = base64.b64decode(bundle["env_ct_b64"])
    enc_ctx = bundle.get("enc_ctx") or {}
    aad = json.dumps(enc_ctx, sort_keys=True).encode() if enc_ctx else b""
    return AESGCM(dek).decrypt(nonce, ct, aad)


class TestLoadDotenv:
    def test_reads_valid(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("DB_PASSWORD=hunter2\n# comment\nAPI_TOKEN=abc\n")
        assert b"hunter2" in load_dotenv_plaintext(str(p))

    def test_empty_rejected(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("   \n")
        with pytest.raises(SecretEnvError):
            load_dotenv_plaintext(str(p))

    def test_no_assignment_rejected(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("# just a comment\nnot an assignment\n")
        with pytest.raises(SecretEnvError):
            load_dotenv_plaintext(str(p))


class TestSeal:
    def test_round_trip(self):
        pt = b"DB_PASSWORD=hunter2\nAPI_TOKEN=abc\n"
        bundle = seal_secret_env(
            pt, provider="aws-kms", key_id="arn:aws:kms:...:key/x",
            region="us-east-2", encryption_context={"app": "demo"},
            kms_client=_FakeKms(),
        )
        assert _decrypt_bundle(bundle) == pt

    def test_large_env_ok(self):
        # Envelope encryption -> no KMS 4 KiB limit.
        pt = ("X=" + "a" * 10000 + "\n").encode()
        bundle = seal_secret_env(
            pt, provider="aws-kms", key_id="k", kms_client=_FakeKms())
        assert _decrypt_bundle(bundle) == pt

    def test_unsupported_provider_rejected(self):
        with pytest.raises(SecretEnvError):
            seal_secret_env(b"A=1\n", provider="azure-kv", key_id="k",
                            kms_client=_FakeKms())

    def test_missing_key_id_rejected(self):
        with pytest.raises(SecretEnvError):
            seal_secret_env(b"A=1\n", provider="aws-kms", key_id="",
                            kms_client=_FakeKms())


class _Cfg:
    def __init__(self, provider, key_id="k"):
        self.provider = provider
        self.key_id = key_id
        self.region = "us-east-2"
        self.encryption_context = {}
        self.extra = {}


class TestApply:
    def test_no_byok_bakes_plaintext(self, tmp_path):
        """No BYOK -> plaintext baked into the measured image (build_dir/app.env)."""
        p = tmp_path / ".env"
        p.write_text("PORT=8080\nLOG_LEVEL=info\n")
        bd = tmp_path / "build"
        bd.mkdir()
        mode = apply_secret_env(str(bd), secrets_env_path=str(p), byok_config=_Cfg("none"))
        assert mode == "plaintext"
        baked = (bd / "app.env").read_text()
        assert "PORT=8080" in baked
        assert "LOG_LEVEL=info" in baked

    def test_no_byok_config_at_all(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("A=1\n")
        bd = tmp_path / "build"
        bd.mkdir()
        # byok_config omitted entirely -> still works (plaintext).
        assert apply_secret_env(str(bd), secrets_env_path=str(p)) == "plaintext"

    def test_sealable_seals_and_keeps_app_env_empty(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("DB_PASSWORD=hunter2\n")
        bd = tmp_path / "build"
        bd.mkdir()
        cfg = _Cfg("aws-kms")
        mode = apply_secret_env(
            str(bd), secrets_env_path=str(p), byok_config=cfg, kms_client=_FakeKms())
        assert mode == "sealed"
        assert "SECRET_ENV_BUNDLE_B64" in cfg.extra
        assert cfg.extra["SECRET_ENV"] == "1"
        assert _decrypt_bundle(cfg.extra["SECRET_ENV_BUNDLE_B64"]) == b"DB_PASSWORD=hunter2\n"
        # Sealed mode must NOT bake the plaintext into the image.
        assert "hunter2" not in (bd / "app.env").read_text()

    def test_ensure_app_env_creates_empty(self, tmp_path):
        from tee_crafter.cli.commands.deploy.secret_env import ensure_build_app_env
        bd = tmp_path / "build"
        bd.mkdir()
        path = ensure_build_app_env(str(bd))
        assert os.path.isfile(path)


class _CaptureConsole:
    def __init__(self):
        self.lines = []

    def print(self, msg):
        self.lines.append(str(msg))


class TestUndeliveredWarning:
    """The CLI must warn only when --secrets-env will not reach the workload.

    Delivery is now wired for every CVM platform (the tee-crafter-secrets
    oneshot) and for Nitro baked mode (EIF entrypoint).  The only remaining
    gaps are Nitro **sealed** (needs NSM recipient-unwrap) and SGX.
    """

    def test_nitro_baked_is_delivered_no_warning(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("PORT=8080\n")
        bd = tmp_path / "build"
        bd.mkdir()
        con = _CaptureConsole()
        apply_secret_env(str(bd), secrets_env_path=str(p), byok_config=_Cfg("none"),
                         console=con, tee_platform="nitro")
        assert not any("NOT see these variables" in ln for ln in con.lines)

    def test_cvm_baked_is_delivered_no_warning(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("PORT=8080\n")
        bd = tmp_path / "build"
        bd.mkdir()
        con = _CaptureConsole()
        apply_secret_env(str(bd), secrets_env_path=str(p), byok_config=_Cfg("none"),
                         console=con, tee_platform="snp-aws")
        assert not any("NOT see these variables" in ln for ln in con.lines)

    def test_cvm_sealed_is_delivered_no_warning(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("DB_PASSWORD=hunter2\n")
        bd = tmp_path / "build"
        bd.mkdir()
        con = _CaptureConsole()
        apply_secret_env(str(bd), secrets_env_path=str(p), byok_config=_Cfg("aws-kms"),
                         kms_client=_FakeKms(), console=con, tee_platform="snp-aws")
        assert not any("NOT see these variables" in ln for ln in con.lines)

    def test_sealed_warns_on_nitro(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("DB_PASSWORD=hunter2\n")
        bd = tmp_path / "build"
        bd.mkdir()
        con = _CaptureConsole()
        apply_secret_env(str(bd), secrets_env_path=str(p), byok_config=_Cfg("aws-kms"),
                         kms_client=_FakeKms(), console=con, tee_platform="nitro")
        assert any("NOT see these variables" in ln for ln in con.lines)

    def test_sgx_baked_warns(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("PORT=8080\n")
        bd = tmp_path / "build"
        bd.mkdir()
        con = _CaptureConsole()
        apply_secret_env(str(bd), secrets_env_path=str(p), byok_config=_Cfg("none"),
                         console=con, tee_platform="sgx-azure")
        assert any("NOT see these variables" in ln for ln in con.lines)


# ---------------------------------------------------------------------------
# In-TEE release (bootstrap_secret_env_release) with a fake orchestrator
# ---------------------------------------------------------------------------

_BOOT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "tee_crafter",
    "templates", "common", "tee_crafter_runtime_bootstrap.py",
)


@pytest.fixture(scope="module")
def boot():
    spec = importlib.util.spec_from_file_location("tcrb_under_test", _BOOT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Material:
    def __init__(self, plaintext):
        self.plaintext = plaintext
        self.attestation_age_seconds = 1.0
        self.attestation_sha256 = "deadbeef" * 8


class _Orchestrator:
    def __init__(self, dek):
        self._dek = dek

    def release(self, key_ref, encryption_context=None):
        # The sealed-env path asks us to decrypt extra['ciphertext_b64'] which
        # our fake KMS wrapped as b'WRAP|' + dek.
        ct = base64.b64decode(key_ref.extra["ciphertext_b64"])
        assert ct.startswith(b"WRAP|")
        return _Material(ct[len("WRAP|"):])


class _KeyRef:
    def __init__(self, *, provider, key_id, region, unwrap, label, extra):
        self.extra = extra


class _Unwrap:
    DIRECT_BYTES = "direct_bytes"


def test_in_tee_release_round_trip(boot, tmp_path, monkeypatch):
    # Seal a .env with the fake KMS, then release it through the fake orchestrator.
    pt = b"DB_PASSWORD=hunter2\nAPI_TOKEN=xyz\n"
    bundle = seal_secret_env(pt, provider="aws-kms", key_id="k", kms_client=_FakeKms())
    monkeypatch.setenv("TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64", bundle)
    monkeypatch.setenv("TEE_CRAFTER_BYOK", "aws-kms")
    monkeypatch.setenv("TEE_CRAFTER_BYOK_KEY_ID", "k")

    monkeypatch.setattr(boot, "_try_import_keys", lambda: {
        "AttestedKeyRef": _KeyRef, "UnwrapAlgorithm": _Unwrap,
    })
    monkeypatch.setattr(boot, "_build_orchestrator",
                        lambda mods, ap, audit: (_Orchestrator(b""), "aws-kms"))

    env_path = str(tmp_path / "app.env")
    monkeypatch.delenv("DB_PASSWORD", raising=False)
    out = boot.bootstrap_secret_env_release(
        attestation_provider=object(), env_path=env_path)
    assert out == {"DB_PASSWORD": "hunter2", "API_TOKEN": "xyz"}
    assert os.path.isfile(env_path)
    assert oct(os.stat(env_path).st_mode)[-3:] == "600"
    assert os.environ["DB_PASSWORD"] == "hunter2"


def test_in_tee_release_absent_is_noop(boot, monkeypatch):
    monkeypatch.delenv("TEE_CRAFTER_BYOK_X_SECRET_ENV_BUNDLE_B64", raising=False)
    assert boot.bootstrap_secret_env_release(attestation_provider=object()) is None


class TestContainerWiring:
    def test_entrypoint_sources_both_env_files(self):
        from tee_crafter.core.packaging.container_wrap import generate_nitro_entrypoint
        sh = generate_nitro_entrypoint("python app.py", 8080, "/app")
        assert "/tee-crafter-runtime/app.env" in sh
        assert "/run/tee_crafter/app.env" in sh
        # Env must be sourced before the user server starts.
        assert sh.index("/run/tee_crafter/app.env") < sh.index("python app.py")

    def test_container_dockerfile_copies_app_env(self):
        from tee_crafter.core.builder import render_container_dockerfile_template
        df = render_container_dockerfile_template("user-img:tag", 8080)
        assert "COPY app.env /tee-crafter-runtime/app.env" in df
