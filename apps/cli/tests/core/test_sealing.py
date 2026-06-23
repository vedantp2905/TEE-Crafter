"""Round-trip tests for sealed input bundles."""
from __future__ import annotations

import io
import json
import os
import tarfile

import pytest

from tee_crafter.core.sealing import (
    SealedBundle, UnsealError, seal_input_directory, unseal_to_directory,
)


def _gen_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return priv_pem, pub_pem


def _populate(d):
    os.makedirs(os.path.join(d, "sub"), exist_ok=True)
    with open(os.path.join(d, "a.txt"), "w") as f:
        f.write("hello\n")
    with open(os.path.join(d, "sub", "b.json"), "w") as f:
        json.dump({"k": 1}, f)
    return d


class TestSealing:
    def test_round_trip(self, tmp_path):
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "bundle.sealed")
        bundle = seal_input_directory(
            input_dir=in_dir, target_pub_pem=pub,
            out_path=sealed_path, build_id="build-abc")
        assert isinstance(bundle, SealedBundle)
        assert os.path.isfile(bundle.sealed_path)
        assert os.path.isfile(bundle.manifest_path)
        assert bundle.size_bytes > 0

        # Manifest must NOT contain ciphertext or wrapped DEK.
        m = json.load(open(bundle.manifest_path))
        for forbidden in ("ciphertext_b64", "wrapped_dek_b64",
                          "iv_b64", "aad_b64", "tag_b64"):
            assert forbidden not in m

        out_dir = str(tmp_path / "out")
        result = unseal_to_directory(
            sealed_path=sealed_path, private_key_pem=priv, dest_dir=out_dir)
        assert result["plaintext_sha256"] == bundle.plaintext_sha256
        assert result["files_extracted"] == 2
        assert os.path.isfile(os.path.join(out_dir, "a.txt"))
        assert os.path.isfile(os.path.join(out_dir, "sub", "b.json"))
        with open(os.path.join(out_dir, "a.txt")) as f:
            assert f.read() == "hello\n"

    def test_wrong_private_key_rejected(self, tmp_path):
        priv1, pub1 = _gen_keypair()
        priv2, _pub2 = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        seal_input_directory(input_dir=in_dir, target_pub_pem=pub1,
                              out_path=sealed_path, build_id="x")
        with pytest.raises(UnsealError, match="DEK"):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv2,
                dest_dir=str(tmp_path / "out"))

    def test_target_spki_mismatch_rejected(self, tmp_path):
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        seal_input_directory(input_dir=in_dir, target_pub_pem=pub,
                              out_path=sealed_path, build_id="x")
        with pytest.raises(UnsealError, match="target_spki_sha256 mismatch"):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv,
                dest_dir=str(tmp_path / "out"),
                expected_target_spki_sha256="0" * 64)

    def test_build_id_mismatch_rejected(self, tmp_path):
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        seal_input_directory(input_dir=in_dir, target_pub_pem=pub,
                              out_path=sealed_path, build_id="build-abc")
        with pytest.raises(UnsealError, match="build_id mismatch"):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv,
                dest_dir=str(tmp_path / "out"),
                expected_build_id="build-xyz")

    def test_tampered_ciphertext_rejected(self, tmp_path):
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        seal_input_directory(input_dir=in_dir, target_pub_pem=pub,
                              out_path=sealed_path, build_id="x")
        env = json.load(open(sealed_path))
        # Flip a ciphertext bit
        ct = env["ciphertext_b64"]
        flipped = "A" if ct[0] != "A" else "B"
        env["ciphertext_b64"] = flipped + ct[1:]
        with open(sealed_path, "w") as f:
            json.dump(env, f)
        with pytest.raises(UnsealError, match="AES-GCM"):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv,
                dest_dir=str(tmp_path / "out"))

    def test_tampered_aad_rejected(self, tmp_path):
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        seal_input_directory(input_dir=in_dir, target_pub_pem=pub,
                              out_path=sealed_path, build_id="x")
        env = json.load(open(sealed_path))
        env["aad_b64"] = env["aad_b64"][:-4] + "AAAA"
        with open(sealed_path, "w") as f:
            json.dump(env, f)
        with pytest.raises(UnsealError, match="AES-GCM"):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv,
                dest_dir=str(tmp_path / "out"))

    @pytest.mark.parametrize("field,forged", [
        ("build_id", "build-xyz"),
        ("target_spki_sha256", "0" * 64),
        ("plaintext_sha256", "f" * 64),
    ])
    def test_relabelled_bundle_rejected(self, tmp_path, field, forged):
        """Editing an unauthenticated top-level field must not bypass the gates.

        ``build_id`` and ``target_spki_sha256`` used to be read straight off the
        envelope JSON, while GCM authenticated a *separate* ``aad_b64`` blob
        that was never cross-checked.  Rewriting one string -- no key material
        required -- opened both gates.  Now the AAD is the authority and the
        envelope must agree with it.
        """
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        seal_input_directory(input_dir=in_dir, target_pub_pem=pub,
                              out_path=sealed_path, build_id="build-abc")
        env = json.load(open(sealed_path))
        original = env[field]
        assert original != forged
        env[field] = forged
        with open(sealed_path, "w") as f:
            json.dump(env, f)

        # Relabelled to what the caller is asking for: the naive gate would
        # now pass.  It must still be rejected.
        kwargs = {}
        if field == "build_id":
            kwargs["expected_build_id"] = forged
        elif field == "target_spki_sha256":
            kwargs["expected_target_spki_sha256"] = forged
        with pytest.raises(UnsealError, match="relabelled"):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv,
                dest_dir=str(tmp_path / "out"), **kwargs)

    def test_relabelled_bundle_rejected_without_expectations(self, tmp_path):
        """Cross-check runs even when the caller passes no expected_* values."""
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        seal_input_directory(input_dir=in_dir, target_pub_pem=pub,
                              out_path=sealed_path, build_id="build-abc")
        env = json.load(open(sealed_path))
        env["build_id"] = "build-someone-elses"
        with open(sealed_path, "w") as f:
            json.dump(env, f)
        with pytest.raises(UnsealError, match="relabelled"):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv,
                dest_dir=str(tmp_path / "out"))

    def test_result_reports_the_authenticated_values(self, tmp_path):
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        bundle = seal_input_directory(
            input_dir=in_dir, target_pub_pem=pub,
            out_path=sealed_path, build_id="build-abc")
        result = unseal_to_directory(
            sealed_path=sealed_path, private_key_pem=priv,
            dest_dir=str(tmp_path / "out"),
            expected_build_id="build-abc",
            expected_target_spki_sha256=bundle.target_spki_sha256)
        assert result["build_id"] == "build-abc"
        assert result["target_spki_sha256"] == bundle.target_spki_sha256

    def test_non_json_aad_rejected(self, tmp_path):
        import base64 as _b64
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        seal_input_directory(input_dir=in_dir, target_pub_pem=pub,
                              out_path=sealed_path, build_id="x")
        env = json.load(open(sealed_path))
        # Re-encrypt so GCM still passes, but the AAD is not JSON.
        env["aad_b64"] = _b64.b64encode(b"not json").decode()
        with open(sealed_path, "w") as f:
            json.dump(env, f)
        # GCM fails first here, which is also a rejection; assert we never
        # reach extraction either way.
        with pytest.raises(UnsealError):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv,
                dest_dir=str(tmp_path / "out"))

    def test_unsupported_version_rejected(self, tmp_path):
        priv, pub = _gen_keypair()
        in_dir = _populate(str(tmp_path / "in"))
        sealed_path = str(tmp_path / "b.sealed")
        seal_input_directory(input_dir=in_dir, target_pub_pem=pub,
                              out_path=sealed_path, build_id="x")
        env = json.load(open(sealed_path))
        env["v"] = 99
        with open(sealed_path, "w") as f:
            json.dump(env, f)
        with pytest.raises(UnsealError, match="version"):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv,
                dest_dir=str(tmp_path / "out"))

    def test_missing_sealed_file(self, tmp_path):
        priv, _pub = _gen_keypair()
        with pytest.raises(UnsealError, match="not found"):
            unseal_to_directory(
                sealed_path=str(tmp_path / "nope"),
                private_key_pem=priv, dest_dir=str(tmp_path / "out"))

    def test_traversal_path_rejected(self, tmp_path, monkeypatch):
        # Construct a synthetic sealed bundle whose plaintext contains
        # a tar entry with `../escape` and verify the unseal step refuses.
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64
        import gzip
        import datetime as _dt

        priv, pub = _gen_keypair()
        # Hand-build an evil tar.
        buf = io.BytesIO()
        gz = gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0)
        with tarfile.open(fileobj=gz, mode="w") as tf:
            data = b"pwned"
            ti = tarfile.TarInfo(name="../escape.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        gz.close()
        plaintext = buf.getvalue()

        # Now wrap it manually with the matching keypair.
        target_pub = serialization.load_pem_public_key(pub)
        spki_der = target_pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        import hashlib
        spki_hex = hashlib.sha256(spki_der).hexdigest()

        dek = AESGCM.generate_key(bit_length=256)
        iv = b"\x00" * 12
        aad = json.dumps({
            "v": 1, "alg": "RSA-OAEP-SHA256+AES-256-GCM",
            "target_spki_sha256": spki_hex, "build_id": "x",
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ct = AESGCM(dek).encrypt(iv, plaintext, aad)
        body, tag = ct[:-16], ct[-16:]
        wrapped = target_pub.encrypt(
            dek, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(), label=None))
        env = {
            "v": 1, "alg": "RSA-OAEP-SHA256+AES-256-GCM",
            "target_spki_sha256": spki_hex, "build_id": "x",
            "wrapped_dek_b64": base64.b64encode(wrapped).decode(),
            "iv_b64": base64.b64encode(iv).decode(),
            "aad_b64": base64.b64encode(aad).decode(),
            "ciphertext_b64": base64.b64encode(body).decode(),
            "tag_b64": base64.b64encode(tag).decode(),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            "size_bytes": len(plaintext),
            "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat() + "Z",
        }
        sealed_path = str(tmp_path / "evil.sealed")
        with open(sealed_path, "w") as f:
            json.dump(env, f)
        with pytest.raises(UnsealError, match="traversal"):
            unseal_to_directory(
                sealed_path=sealed_path, private_key_pem=priv,
                dest_dir=str(tmp_path / "out"))

    def test_seal_rejects_non_directory(self, tmp_path):
        _priv, pub = _gen_keypair()
        # Not a directory
        target = tmp_path / "not_a_dir.txt"
        target.write_text("x")
        with pytest.raises(FileNotFoundError):
            seal_input_directory(
                input_dir=str(target), target_pub_pem=pub,
                out_path=str(tmp_path / "x.sealed"), build_id="b")

    def test_seal_rejects_non_rsa_key(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.generate()
        pub_pem = sk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        in_dir = _populate(str(tmp_path / "in"))
        with pytest.raises(TypeError, match="RSA"):
            seal_input_directory(
                input_dir=in_dir, target_pub_pem=pub_pem,
                out_path=str(tmp_path / "x.sealed"), build_id="b")
