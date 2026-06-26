"""The pinned AMD ARK fingerprints must be the ARK, not an intermediate.

Every SNP bake downloads an endorsement chain from ``kdsintf.amd.com`` and
compares the **last** certificate -- the self-signed AMD Root Key -- against a
fingerprint pinned in the setup script. Until 2026-08-24 all three scripts
pinned the wrong certificate.

``certs/amd-ark-milan.pem`` and ``certs/amd-ark-genoa.pem`` are each a
*two*-certificate bundle, ``[intermediate, ARK]``. The pins had been taken from
entry ``[0]`` -- ``CN=SEV-VLEK-Milan`` and ``CN=SEV-Genoa`` -- so the comparison
against the chain's real root could never succeed. A rejected chain is deleted
by the script, which means no snp-aws bake ever installed an AMD endorsement
chain at all, and nothing failed loudly enough to notice for months.

Client-side verification was never affected: the snp client also treats the last
certificate of each baked bundle as the ARK, and that has always been the real
root. The defect was confined to the bake-time pin.

These tests read the *assignment lines only*. Grepping the whole file would
match the old fingerprints quoted in the explanatory comment that now sits above
those assignments -- a test that passes by matching prose is worse than no test.
"""
from __future__ import annotations

import pathlib
import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

REPO = pathlib.Path(__file__).resolve().parents[2]
CERTS = REPO / "src" / "tee_crafter" / "certs"
SCRIPTS = REPO / "src" / "tee_crafter" / "scripts"

SETUP_SCRIPTS = {
    "snp-aws": SCRIPTS / "snp_aws" / "setup_snp_aws.sh",
    "snp-azure": SCRIPTS / "snp_azure" / "setup_snp_azure.sh",
    "snp-gcp": SCRIPTS / "snp_gcp" / "setup_snp_gcp.sh",
}

#: ``AMD_ARK_<GEN>_SHA256=`` at the start of a line, with the value either bare
#: or wrapped in a ``${TEE_CRAFTER_...:-default}`` override.
_ASSIGN = re.compile(
    r"^AMD_ARK_(MILAN|GENOA)_SHA256="
    r'"(?:\$\{TEE_CRAFTER_ARK_(?:MILAN|GENOA)_SHA256:-)?'
    r"((?:[0-9A-F]{2}:){31}[0-9A-F]{2})",
    re.MULTILINE,
)


def _colon_fingerprint(cert: x509.Certificate) -> str:
    raw = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(raw[i:i + 2] for i in range(0, len(raw), 2))


def _bundle(generation: str) -> list[x509.Certificate]:
    path = CERTS / f"amd-ark-{generation}.pem"
    return x509.load_pem_x509_certificates(path.read_bytes())


def _pins(platform: str) -> dict[str, str]:
    text = SETUP_SCRIPTS[platform].read_text()
    found = {gen.lower(): fp for gen, fp in _ASSIGN.findall(text)}
    assert found, f"no ARK pin assignments parsed out of {platform}"
    return found


@pytest.mark.parametrize("generation", ["milan", "genoa"])
def test_bundle_last_certificate_is_the_ark(generation):
    """The invariant the scripts rely on: last cert of the bundle is the root."""
    certs = _bundle(generation)
    assert len(certs) == 2, (
        f"amd-ark-{generation}.pem should be [intermediate, ARK]; "
        f"got {len(certs)} certificate(s)")
    ark = certs[-1]
    common_name = ark.subject.rfc4514_string()
    assert f"CN=ARK-{generation.capitalize()}" in common_name, common_name
    # Self-signed is what makes it a root rather than another intermediate.
    assert ark.issuer == ark.subject, "ARK is not self-signed"


@pytest.mark.parametrize("platform", sorted(SETUP_SCRIPTS))
@pytest.mark.parametrize("generation", ["milan", "genoa"])
def test_pin_equals_the_ark_not_the_intermediate(platform, generation):
    pinned = _pins(platform)[generation]
    certs = _bundle(generation)
    assert pinned == _colon_fingerprint(certs[-1]), (
        f"{platform} pins {pinned[:17]}… for {generation}, which is not the "
        f"ARK. This is the 2026-08-24 defect: the fingerprint of the "
        f"intermediate at entry [0] was pinned instead of the root at [-1].")
    assert pinned != _colon_fingerprint(certs[0]), (
        f"{platform} pins the {generation} intermediate, not the ARK")


def test_all_three_platforms_agree():
    """A per-generation ARK is a property of AMD, not of the cloud."""
    pins = {p: _pins(p) for p in SETUP_SCRIPTS}
    for generation in ("milan", "genoa"):
        values = {p: v[generation] for p, v in pins.items()}
        assert len(set(values.values())) == 1, (
            f"{generation} ARK pin differs across platforms: {values}")
