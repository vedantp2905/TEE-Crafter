"""A VCEK is signed by the ASK; a VLEK is not. Both intermediates must be baked.

Found on real GCP SEV-SNP hardware 2026-08-21.  The server obtained its report,
minted an RA-TLS certificate and served the client; the client then aborted::

    cert table: 2 typed entries (VLEK=no, VCEK=yes, ASK=yes, ARK=no)
    ...
    FATAL: AMD endorsement certificate chain verification FAILED.
    The VCEK does not chain to a trusted AMD root.

Cause: ``certs/amd-ark-milan.pem`` shipped ``[CN=SEV-VLEK-Milan, CN=ARK-Milan]``.
AMD signs a **VLEK** with ``SEV-VLEK-<Family>`` and a **VCEK** with the ASK,
``SEV-<Family>``.  AWS hands back a VLEK, so that bundle worked there; GCP hands
back a VCEK, and the client held no certificate that could have issued it, so
``_try_verify_against_chain`` -- which verifies the endorsement against
``chain_certs[0]`` -- could only fail.

Checked against AMD's own KDS (``kdsintf.amd.com/vcek/v1/<Family>/cert_chain``):
the Milan chain there is ``[CN=SEV-Milan, CN=ARK-Milan]`` and its ARK has the
**same SPKI digest** as the bundled one, so adding it widens which endorsements
verify without moving the root of trust.  ``amd-ark-genoa.pem`` already carried
``CN=SEV-Genoa`` (the ASK), which is why only Milan was broken -- and why a
per-family invariant, not a spot check, is what these tests assert.
"""

import hashlib
import pathlib
import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "tee_crafter"
_CERTS = _SRC / "certs"
_TEMPLATES = _SRC / "templates"

SNP_CLIENTS = ["snp/aws", "snp/azure", "snp/gcp"]
FAMILIES = ["milan", "genoa"]


def _load(path):
    return x509.load_pem_x509_certificates(path.read_bytes())


def _spki(cert):
    return hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _cn(cert):
    return cert.subject.rfc4514_string().split(",")[0]


def _family_chains(family):
    """Every baked chain for *family*: the ark bundle plus any ask bundle."""
    out = {}
    for prefix in ("ark", "ask"):
        p = _CERTS / f"amd-{prefix}-{family}.pem"
        if p.exists():
            out[prefix] = _load(p)
    return out


class TestAskIntermediateIsAvailable:
    @pytest.mark.parametrize("family", FAMILIES)
    def test_some_baked_chain_can_issue_a_vcek(self, family):
        """The invariant that was violated: an ASK must be baked per family.

        Without ``CN=SEV-<Family>`` in *some* baked bundle, no VCEK from that
        family can ever verify -- which is precisely what happened on GCP.
        """
        leaves = {_cn(chain[0]) for chain in _family_chains(family).values()}
        assert f"CN=SEV-{family.capitalize()}" in leaves, (
            f"no ASK baked for {family}; baked leaves are {sorted(leaves)}")

    def test_milan_still_has_the_vlek_intermediate(self):
        """AWS returns a VLEK. Fixing GCP must not break AWS."""
        leaves = {_cn(chain[0]) for chain in _family_chains("milan").values()}
        assert "CN=SEV-VLEK-Milan" in leaves


class TestEveryBakedChainIsWellFormed:
    @pytest.mark.parametrize("family", FAMILIES)
    def test_chains_are_leaf_first_and_root_last(self, family):
        """`_try_verify_against_chain` walks strictly by index, so order matters."""
        for prefix, chain in _family_chains(family).items():
            assert len(chain) >= 2, f"amd-{prefix}-{family}: too short"
            assert chain[0].subject != chain[0].issuer, (
                f"amd-{prefix}-{family}: first cert is self-signed, so the "
                f"walker would treat the root as the endorsement's issuer")
            assert chain[-1].subject == chain[-1].issuer, (
                f"amd-{prefix}-{family}: last cert is not self-signed, but the "
                f"walker pins chain[-1] as the ARK")

    @pytest.mark.parametrize("family", FAMILIES)
    def test_each_link_actually_verifies(self, family):
        """Not just ordered — cryptographically chained."""
        from cryptography.hazmat.primitives.asymmetric import padding
        for prefix, chain in _family_chains(family).items():
            for lower, upper in zip(chain, chain[1:]):
                upper.public_key().verify(
                    lower.signature,
                    lower.tbs_certificate_bytes,
                    padding.PSS(mgf=padding.MGF1(lower.signature_hash_algorithm),
                                salt_length=lower.signature_hash_algorithm.digest_size),
                    lower.signature_hash_algorithm,
                )

    @pytest.mark.parametrize("family", FAMILIES)
    def test_all_baked_chains_share_one_ark(self, family):
        """Two roots for one family would silently widen the trust anchor set."""
        arks = {_spki(chain[-1]) for chain in _family_chains(family).values()}
        assert len(arks) == 1, f"{family}: baked chains disagree on the ARK: {arks}"


class TestRenderedClientsCarryTheAsk:
    """The certs are useless unless they reach the generated client."""

    @pytest.mark.parametrize("rel", SNP_CLIENTS)
    def test_template_declares_the_ask_slot(self, rel):
        src = (_TEMPLATES / rel / "client.template.py").read_text()
        assert "_AMD_ASK_CA_MILAN_PEM" in src

    @pytest.mark.parametrize("rel", SNP_CLIENTS)
    def test_ask_chain_is_a_verification_candidate(self, rel):
        """Declaring it is not enough; it has to be tried."""
        src = (_TEMPLATES / rel / "client.template.py").read_text()
        cands = src[src.index("candidates = []"):src.index("if not candidates")]
        assert "_AMD_ASK_CA_MILAN_PEM" in cands

    @pytest.mark.parametrize("rel", SNP_CLIENTS)
    def test_ask_chain_labels_as_milan(self, rel):
        """The label is the client's only processor-family signal downstream."""
        src = (_TEMPLATES / rel / "client.template.py").read_text()
        cands = src[src.index("candidates = []"):src.index("if not candidates")]
        m = re.search(r'\("([A-Za-z]+)",\s*_AMD_ASK_CA_MILAN_PEM\)', cands)
        assert m and m.group(1) == "Milan", "ASK chain must report the Milan family"

    @pytest.mark.parametrize("rel", SNP_CLIENTS)
    def test_ask_ark_is_in_the_pinned_root_set(self, rel):
        """Otherwise the walk reaches an ARK it refuses to trust."""
        src = (_TEMPLATES / rel / "client.template.py").read_text()
        fn = src[src.index("def _trusted_ark_spki_digests"):
                 src.index("def _try_verify_against_chain")]
        assert "_AMD_ASK_CA_MILAN_PEM" in fn


class TestRenderSubstitutesRealCerts:
    @pytest.mark.parametrize("platform", ["snp-aws", "snp-azure", "snp-gcp"])
    def test_rendered_client_embeds_the_ask_chain(self, platform):
        from tee_crafter.core.builder import platforms as P
        fn = {
            "snp-aws": P.render_snp_aws_client_template,
            "snp-azure": P.render_snp_azure_client_template,
            "snp-gcp": P.render_snp_gcp_client_template,
        }[platform]
        src = fn(measurement="a" * 96, container_digest="sha256:" + "b" * 64)
        assert not re.findall(r"\{amd_[a-z_]*\}", src), "placeholder left unrendered"
        m = re.search(r'_AMD_ASK_CA_MILAN_PEM = """(.*?)"""', src, re.S)
        assert m, f"{platform}: no ASK chain in rendered client"
        chain = x509.load_pem_x509_certificates(m.group(1).strip().encode())
        assert [_cn(c) for c in chain] == ["CN=SEV-Milan", "CN=ARK-Milan"]

    def test_missing_anchor_is_fatal(self):
        """A wheel built without certs/ must refuse, not emit a trustless client."""
        from tee_crafter.core.builder.platforms import (
            MissingTrustAnchor,
            _load_amd_ask_ca,
        )
        with pytest.raises(MissingTrustAnchor):
            _load_amd_ask_ca("nosuchfamily")
