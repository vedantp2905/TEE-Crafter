"""gpu-cc-azure is SEV-SNP under the Azure paravisor, so it had the same gap.

Its client used to state the limitation honestly -- "the HCL-minted SNP report
does not cover it ... it does not root it in AMD" -- and then continue. That is
accurate but weak: an attacker replaying a captured SNP report can generate
their own attestation key and sign a quote committing to their own key hash.

The HCL runtime data closes it, exactly as on snp-azure: AMD signs REPORT_DATA,
REPORT_DATA is sha256 of the runtime-data JSON, and that JSON names the key.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import struct
import types

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_TPL = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "tee_crafter", "templates", "gpu_cc", "azure")
_CLIENT = os.path.join(_TPL, "client.template.py")
_APP = os.path.join(_TPL, "app.template.py")


def _extract(path: str, names: list[str]) -> types.ModuleType:
    src = open(path, encoding="utf-8").read()
    mod = types.ModuleType("extracted")
    mod.__dict__.update(hashlib=hashlib, struct=struct, json=json,
                        base64=base64)
    want, got = set(names), set()
    for node in ast.parse(src).body:
        nm = node.name if isinstance(node, ast.FunctionDef) else None
        if nm in want:
            exec(compile(ast.Module([node], []), path, "exec"), mod.__dict__)
            got.add(nm)
    assert not want - got, f"missing {sorted(want - got)}"
    return mod


_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _modulus(key) -> bytes:
    n = key.public_key().public_numbers().n
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _pem(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def _runtime_data(key=_KEY) -> bytes:
    n = base64.urlsafe_b64encode(_modulus(key)).decode().rstrip("=")
    return json.dumps({
        "keys": [
            {"kid": "HCLEkPub", "kty": "RSA", "e": "AQAB", "n": n[::-1],
             "key_ops": ["encrypt"]},
            {"kid": "HCLAkPub", "kty": "RSA", "e": "AQAB", "n": n,
             "key_ops": ["sign"]},
        ],
        "vm-configuration": {"secure-boot": True, "tpm-enabled": True},
        "user-data": "00" * 32,
    }).encode()


def _report_data(rt: bytes) -> bytes:
    return hashlib.sha256(rt).digest() + b"\x00" * 32


@pytest.fixture(scope="module")
def verify():
    return _extract(_CLIENT,
                    ["verify_hcl_ak_binding",
                     "_ak_pub_has_modulus"]).verify_hcl_ak_binding


@pytest.fixture(scope="module")
def parse_rt():
    return _extract(_CLIENT, ["_parse_hcl_runtime_data"])._parse_hcl_runtime_data


class TestVerifier:

    def test_genuine_ak_passes(self, verify):
        rt = _runtime_data()
        assert verify(_report_data(rt), rt, _pem(_KEY)) is True

    def test_foreign_ak_is_rejected(self, verify):
        """The replay this exists to stop."""
        rt = _runtime_data()
        assert verify(_report_data(rt), rt, _pem(_OTHER)) is False

    def test_digest_mismatch_is_rejected(self, verify):
        rt = _runtime_data()
        assert verify(b"\x00" * 64, rt, _pem(_KEY)) is False

    def test_absent_runtime_data_is_rejected(self, verify):
        assert verify(_report_data(b"{}"), b"", _pem(_KEY)) is False

    def test_pem_is_what_the_app_sends(self, verify):
        """`tpm2_readpublic -f pem`, so a byte-substring test is always false."""
        assert _modulus(_KEY) not in _pem(_KEY)
        rt = _runtime_data()
        assert verify(_report_data(rt), rt, _pem(_KEY)) is True


class TestWireFormat:
    """The runtime data is appended after the TPM blob and must stay optional."""

    def test_reads_the_appended_field(self, parse_rt):
        tpm = b"\xaa" * 40
        rt = b'{"keys":[]}'
        blob = (struct.pack("<I", len(tpm)) + tpm
                + struct.pack("<I", len(rt)) + rt)
        assert parse_rt(blob) == rt

    def test_absent_field_yields_empty(self, parse_rt):
        """A certificate from a server built before this existed."""
        tpm = b"\xaa" * 40
        assert parse_rt(struct.pack("<I", len(tpm)) + tpm) == b""

    def test_truncated_length_yields_empty(self, parse_rt):
        tpm = b"\xaa" * 40
        blob = (struct.pack("<I", len(tpm)) + tpm
                + struct.pack("<I", 9999) + b"short")
        assert parse_rt(blob) == b""

    def test_empty_input_yields_empty(self, parse_rt):
        assert parse_rt(b"") == b""


class TestAppEmitsIt:

    def test_app_extracts_runtime_data(self):
        src = open(_APP, encoding="utf-8").read()
        assert "def _get_hcl_runtime_data" in src

    def test_app_appends_it_to_the_extension(self):
        src = open(_APP, encoding="utf-8").read()
        assert 'struct.pack("<I", len(_runtime_data)) + _runtime_data' in src

    def test_app_degrades_rather_than_failing(self):
        """A host with unexpected HCL framing must still attest."""
        src = open(_APP, encoding="utf-8").read()
        assert "if _runtime_data:" in src


class TestClientReportsHonestlyEitherWay:

    def test_established_wording_when_bound(self):
        src = open(_CLIENT, encoding="utf-8").read()
        assert "ESTABLISHED — the TPM Quote's attestation key is named" in src

    def test_the_old_honest_limitation_survives_when_unbound(self):
        src = open(_CLIENT, encoding="utf-8").read()
        assert "NOT \nESTABLISHED" in src or "NOT " in src
        assert "not \n                      \"anchored in AMD-signed evidence" in src \
            or "anchored in AMD-signed evidence" in src
