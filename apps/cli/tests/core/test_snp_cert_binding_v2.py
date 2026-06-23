"""``snp-aws`` and ``snp-gcp`` must bind their certificate quote with v2.

Both platforms once hashed ``ecdh_pub ‖ container_digest``
raw — no length prefixes, no version label — while every other platform used the
length-prefixed, version-labelled v2 preimage that exists *specifically* so a v1
digest cannot be reinterpreted as a v2 one.

Not exploitable as it stood: both fields are fixed-length there (a 97-byte
uncompressed P-384 point and a ``sha256:…`` string), so the concatenation was
unambiguous in practice.  "Unambiguous because of a length coincidence" is the
property v2 exists to stop depending on, though — add a third field or make the
key length vary and the coincidence is gone.

The app and the client must agree byte-for-byte or every deploy fails closed, so
these tests extract the **real** functions from both templates by AST and check
they produce the same 32 bytes.  A test that reimplemented the encoding would
agree with itself and prove nothing.
"""
from __future__ import annotations

import ast
import hashlib
import os
import struct
import types

import pytest

PLATFORMS = ("aws", "gcp")

_TEMPLATES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "src", "tee_crafter", "templates", "snp")

#: A realistic uncompressed P-384 point and a realistic container digest.
_PUB = b"\x04" + b"\xaa" * 96
_DIGEST = "sha256:" + "ab" * 32


def _extract(path: str, names: list[str]) -> types.ModuleType:
    """Execute just *names* from *path* in an isolated module.

    The templates are not importable — they carry ``{placeholder}`` substitution
    markers and open device files at import time — so the functions under test
    are lifted out individually.
    """
    src = open(path, encoding="utf-8").read()
    mod = types.ModuleType("extracted")
    mod.__dict__.update(hashlib=hashlib, struct=struct)
    want, got = set(names), set()
    for node in ast.parse(src).body:
        nm = None
        if isinstance(node, ast.FunctionDef):
            nm = node.name
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and isinstance(node.targets[0], ast.Name)):
            nm = node.targets[0].id
        if nm in want:
            exec(compile(ast.Module([node], []), path, "exec"), mod.__dict__)
            got.add(nm)
    assert not want - got, f"{path}: missing {sorted(want - got)}"
    return mod


@pytest.fixture(scope="module")
def sides():
    out = {}
    for plat in PLATFORMS:
        out[plat] = (
            _extract(os.path.join(_TEMPLATES, plat, "app.template.py"), [
                "_ATTEST_BINDING_LABEL", "_attest_binding_preimage",
                "_attest_binding_digest", "_SNP_REPORT_USER_DATA_SIZE",
                "_generate_snp_report_data"]),
            _extract(os.path.join(_TEMPLATES, plat, "client.template.py"), [
                "_ATTEST_BINDING_LABEL", "_attest_binding_preimage",
                "_attest_binding_digest"]),
        )
    return out


@pytest.mark.parametrize("plat", PLATFORMS)
@pytest.mark.parametrize("digest", [_DIGEST, ""], ids=["with-digest", "no-digest"])
def test_app_report_data_matches_what_the_client_recomputes(sides, plat, digest):
    """The one property that must hold, or the platform fails every deploy.

    Both cases matter: v1 branched on whether a container digest existed (one
    field vs two), so an absent digest took a different code path on each side.
    v2 always passes two fields — an empty one is a zero-length field, not a
    shorter field list — so there is no branch left to get wrong.
    """
    app, client = sides[plat]
    report_data = app._generate_snp_report_data(
        app._attest_binding_preimage(_PUB, digest.encode()))
    assert report_data[:32] == client._attest_binding_digest(
        _PUB, digest.encode())


@pytest.mark.parametrize("plat", PLATFORMS)
def test_report_data_is_64_bytes_zero_padded(sides, plat):
    """SNP ``report_data`` is a fixed 64-byte field; only 32 carry the digest."""
    app, _ = sides[plat]
    rd = app._generate_snp_report_data(
        app._attest_binding_preimage(_PUB, _DIGEST.encode()))
    assert len(rd) == app._SNP_REPORT_USER_DATA_SIZE == 64
    assert rd[32:] == b"\x00" * 32


@pytest.mark.parametrize("plat", PLATFORMS)
def test_a_v1_digest_is_not_a_valid_v2_digest(sides, plat):
    """The version label has to be inside the hashed bytes to do anything.

    If it were only a comment, evidence minted under v1 would still satisfy a
    v2 verifier — which is the substitution v2 is meant to prevent.
    """
    _, client = sides[plat]
    v1 = hashlib.sha256(_PUB + _DIGEST.encode()).digest()
    assert v1 != client._attest_binding_digest(_PUB, _DIGEST.encode())


@pytest.mark.parametrize("plat", PLATFORMS)
def test_v2_resolves_the_field_split_ambiguity_that_v1_had(sides, plat):
    """The concrete defect, stated as a collision.

    Under v1, ``(b"ab", b"cd")`` and ``(b"abc", b"d")`` hash identically — the
    first assertion proves the hazard was real rather than theoretical. Under v2
    they must not.
    """
    _, client = sides[plat]
    assert (hashlib.sha256(b"ab" + b"cd").digest()
            == hashlib.sha256(b"abc" + b"d").digest()), "v1 was not ambiguous?"
    assert (client._attest_binding_digest(b"ab", b"cd")
            != client._attest_binding_digest(b"abc", b"d"))


@pytest.mark.parametrize("plat", PLATFORMS)
def test_a_shorter_field_list_cannot_be_padded_into_a_longer_one(sides, plat):
    """The field *count* is prefixed too, so arity is bound as well as length."""
    _, client = sides[plat]
    assert (client._attest_binding_digest(_PUB)
            != client._attest_binding_digest(_PUB, b""))


@pytest.mark.parametrize("plat", PLATFORMS)
def test_both_sides_agree_on_the_label(sides, plat):
    app, client = sides[plat]
    assert (app._ATTEST_BINDING_LABEL == client._ATTEST_BINDING_LABEL
            == b"tee-crafter/attest-binding/v2")


@pytest.mark.parametrize("plat", PLATFORMS)
def test_no_raw_concatenation_is_left_in_the_binding_sites(plat):
    """Guard against the v1 form coming back by copy-paste.

    Greps for the exact expression that was there, rather than for "any
    concatenation", so it stays quiet about unrelated code.
    """
    for name in ("app.template.py", "client.template.py"):
        src = open(os.path.join(_TEMPLATES, plat, name),
                   encoding="utf-8").read()
        assert "_ECDH_PUB_BYTES + _container_digest.encode()" not in src
        assert "enclave_pub_bytes + EXPECTED_CONTAINER_DIGEST.encode()" not in src


@pytest.mark.parametrize("plat", PLATFORMS)
def test_the_cert_quote_and_the_live_challenge_now_share_one_encoding(plat):
    """C3's point: two bindings on one platform used two different schemes.

    The live challenge was already v2 and fatal, which is why AUD-3 held
    throughout. Both call the same helper now.
    """
    src = open(os.path.join(_TEMPLATES, plat, "app.template.py"),
               encoding="utf-8").read()
    assert src.count("_attest_binding_preimage(") >= 2, (
        "expected the cert quote and the live challenge to both use it")
