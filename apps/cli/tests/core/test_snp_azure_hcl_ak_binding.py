"""The Azure SEV-SNP attestation key must be rooted in AMD's signature.

Azure CVMs expose no ``/dev/sev-guest`` (verified on a live
``Standard_DC2as_v5`` on 2026-08-23), so the Hyper-V HCL fixes REPORT_DATA and
the ``report_data_strong`` binding is unreachable. The client therefore fell
back to verifying a TPM quote, and the strict AK-binding gate rejected that --
leaving ``snp-azure`` unable to pass a control whose remedy ("redeploy on an
instance exposing /dev/sev-guest") does not exist on the platform.

A quote on its own genuinely is weaker: an attacker replaying a captured SNP
report can generate their own AK and sign a quote committing to their own key
hash, which is self-consistent and passes. What closes that circularity is the
HCL runtime data, whose structure was read off the live host:

    sha256(runtime_data) == snp_report[REPORT_DATA : REPORT_DATA + 32]

and ``runtime_data`` is JSON carrying ``keys[kid == "HCLAkPub"]`` -- a JWK for
the RSA-2048 key whose private half signs the quote. AMD signs REPORT_DATA, so
AMD transitively vouches for the AK.
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

_CLIENT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "tee_crafter", "templates", "snp", "azure",
    "client.template.py")


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


@pytest.fixture(scope="module")
def verify():
    mod = _extract(_CLIENT,
                   ["verify_hcl_ak_binding", "_ak_pub_has_modulus"])
    return mod.verify_hcl_ak_binding


# Real RSA keys, and the AK public half in the **PEM** form the app actually
# sends (`tpm2_readpublic -c ... -f pem`).  Synthesising a raw blob with the
# modulus embedded is what let an always-false substring comparison pass 17
# tests while being inert on hardware.
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _modulus_of(key) -> bytes:
    n = key.public_key().public_numbers().n
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _pem_of(key) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)


MODULUS = _modulus_of(_KEY)


def _jwk(modulus: bytes = MODULUS, kid: str = "HCLAkPub") -> dict:
    return {
        "kid": kid,
        "kty": "RSA",
        "key_ops": ["sign"],
        "e": "AQAB",
        "n": base64.urlsafe_b64encode(modulus).decode().rstrip("="),
    }


def _runtime_data(keys=None) -> bytes:
    """Mirrors the live document: keys + vm-configuration + user-data."""
    return json.dumps({
        "keys": keys if keys is not None else [_jwk(), _jwk(
            bytes(range(256)), kid="HCLEkPub")],
        "vm-configuration": {"secure-boot": True, "tpm-enabled": True,
                             "vmUniqueId": "abc"},
        "user-data": "00" * 32,
    }).encode()


def _report_data(runtime_data: bytes) -> bytes:
    """REPORT_DATA is sha256(runtime_data) then 32 zero bytes, as observed."""
    return hashlib.sha256(runtime_data).digest() + b"\x00" * 32


def _ak_pub(modulus: bytes = MODULUS) -> bytes:
    """The AK public half as the app sends it: PEM.

    Defaults to the PEM of the key whose modulus ``MODULUS`` is, so the happy
    path exercises a real parse rather than a byte-substring coincidence.
    """
    if modulus == MODULUS:
        return _pem_of(_KEY)
    if modulus == _modulus_of(_OTHER):
        return _pem_of(_OTHER)
    # An arbitrary modulus that belongs to no real key: fall back to the raw
    # TPM2B_PUBLIC shape, which the verifier also supports.
    return b"\x01\x16\x00\x01\x00\x0b" + b"\x00" * 20 + modulus + b"\x00\x04"


class TestTheHappyPath:

    def test_matching_ak_is_accepted(self, verify):
        rt = _runtime_data()
        assert verify(_report_data(rt), rt, _ak_pub()) is True

    def test_it_works_with_the_real_document_shape(self, verify):
        """HCLEkPub present too, and HCLAkPub not first in the array."""
        rt = _runtime_data(keys=[_jwk(bytes(range(256)), kid="HCLEkPub"),
                                 _jwk()])
        assert verify(_report_data(rt), rt, _ak_pub()) is True


class TestTheAttackItCloses:

    def test_a_foreign_ak_is_rejected(self, verify):
        """The replay: real SNP report, attacker's own AK.

        The attacker holds a valid captured report and a valid quote from a key
        they control. Only the runtime-data binding distinguishes this from the
        genuine case. Both keys here are real RSA-2048 keys in PEM form.
        """
        rt = _runtime_data()
        assert verify(_report_data(rt), rt, _pem_of(_OTHER)) is False

    def test_substituted_runtime_data_is_rejected(self, verify):
        """Swapping in JSON that names the attacker's AK breaks the digest."""
        genuine = _runtime_data()
        forged = _runtime_data(keys=[_jwk(_modulus_of(_OTHER))])
        # REPORT_DATA still commits to the genuine document.
        assert verify(_report_data(genuine), forged, _ak_pub()) is False

    def test_report_data_mismatch_is_rejected(self, verify):
        rt = _runtime_data()
        assert verify(b"\x00" * 64, rt, _ak_pub()) is False


class TestItFailsClosedOnJunk:
    """A parsing quirk must be indistinguishable from "no strong binding",
    never from "verified"."""

    def test_empty_runtime_data(self, verify):
        assert verify(_report_data(b"{}"), b"", _ak_pub()) is False

    def test_empty_ak_pub(self, verify):
        rt = _runtime_data()
        assert verify(_report_data(rt), rt, b"") is False

    def test_short_report_data(self, verify):
        rt = _runtime_data()
        assert verify(b"\x00" * 8, rt, _ak_pub()) is False

    def test_non_json_runtime_data(self, verify):
        rt = b"not json at all"
        assert verify(_report_data(rt), rt, _ak_pub()) is False

    def test_no_hcl_ak_pub_key(self, verify):
        rt = _runtime_data(keys=[_jwk(kid="HCLEkPub")])
        assert verify(_report_data(rt), rt, _ak_pub()) is False

    def test_no_keys_array(self, verify):
        rt = json.dumps({"vm-configuration": {}}).encode()
        assert verify(_report_data(rt), rt, _ak_pub()) is False

    def test_malformed_modulus(self, verify):
        bad = dict(_jwk()); bad["n"] = "!!!not base64!!!"
        rt = _runtime_data(keys=[bad])
        assert verify(_report_data(rt), rt, _ak_pub()) is False

    def test_non_string_modulus(self, verify):
        bad = dict(_jwk()); bad["n"] = 12345
        rt = _runtime_data(keys=[bad])
        assert verify(_report_data(rt), rt, _ak_pub()) is False

    def test_implausibly_short_modulus_is_rejected(self, verify):
        """A 4-byte "modulus" would match almost any blob by chance."""
        rt = _runtime_data(keys=[_jwk(b"\x01\x02\x03\x04")])
        assert verify(_report_data(rt), rt, _ak_pub()) is False


class TestTheStrictGateAcceptsIt:

    def test_gate_lists_the_new_mode(self):
        src = open(_CLIENT, encoding="utf-8").read()
        assert 'binding_mode not in ("report_data_strong",' in src
        assert '"hcl_runtime_data_strong")' in src

    def test_the_dev_hatch_default_is_still_strict(self):
        """The fix must not have been "turn the gate off"."""
        src = open(_CLIENT, encoding="utf-8").read()
        assert 'os.environ.get("TEE_CRAFTER_STRICT_SNP_AK_BINDING", "1")' in src

    def test_upgrade_only_applies_to_quote_modes(self):
        src = open(_CLIENT, encoding="utf-8").read()
        assert 'if binding_mode in ("tpm_quote_strong", "tpm_quote_legacy"):' in src


class TestPemIsTheFormatTheAppActuallySends:
    """Regression guard for an always-false comparison that tests missed.

    The app runs ``tpm2_readpublic -c ... -f pem``, so ak_pub is PEM. Comparing
    the JWK modulus against it as a byte substring is silently always false --
    base64-of-DER contains none of the raw modulus bytes -- so the AK upgrade
    never fired on hardware while every unit test passed against a synthetic
    raw blob.
    """

    @pytest.fixture(scope="class")
    def has_modulus(self):
        return _extract(_CLIENT, ["_ak_pub_has_modulus"])._ak_pub_has_modulus

    def test_the_raw_modulus_is_not_a_substring_of_the_pem(self):
        """The fact that made the original check inert."""
        assert MODULUS not in _pem_of(_KEY)

    def test_pem_is_accepted(self, has_modulus):
        assert has_modulus(_pem_of(_KEY), MODULUS) is True

    def test_pem_of_a_different_key_is_rejected(self, has_modulus):
        assert has_modulus(_pem_of(_OTHER), MODULUS) is False

    def test_der_is_accepted(self, has_modulus):
        der = _KEY.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        assert has_modulus(der, MODULUS) is True

    def test_raw_tpm2b_public_still_works(self, has_modulus):
        raw = b"\x01\x16\x00\x01\x00\x0b" + b"\x00" * 20 + MODULUS
        assert has_modulus(raw, MODULUS) is True

    def test_a_leading_zero_in_the_jwk_modulus_still_matches(self, has_modulus):
        """JWK ``n`` may carry a leading zero byte; the parsed integer will not.

        Comparing integers rather than bytes is what makes these equal.
        """
        assert has_modulus(_pem_of(_KEY), b"\x00" + MODULUS) is True

    def test_garbage_is_rejected(self, has_modulus):
        assert has_modulus(b"not a key at all", MODULUS) is False
