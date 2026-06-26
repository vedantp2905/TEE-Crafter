"""Every client must surface the attested chain-key commitment to the ledger.

All ten clients call ``resolve_chain_key_commitment`` and fold the value into
the binding the hardware signs — that half was never broken.  What was broken
is what happens *after*: only ``nitro``, ``gpu_cc/azure`` and ``gpu_cc/gcp``
put the value anywhere the deploy could see it.  The other seven verified it
and dropped it, so ``build_provenance.json`` recorded no commitment and
``verify-siem-chain`` reported *"Chain commitment: not pinned — events checked
for internal consistency only"*.  Confirmed on the real ``snp-aws`` build of
2026-08-23, whose ledger has an otherwise complete ``SNP client verification``
entry with no ``chain_key_commitment`` in it.

``snp-aws`` did print the value — as ``Audit-log chain-key commitment
(AMD-signed): <hex>``.  The extractor's regex wants ``[:=]`` directly after
"commitment", so the parenthetical defeated it.  That near-miss is why the test
below pins the *canonical* shape rather than "the hex appears somewhere".

Two supported ways to report it, both asserted here:

* in the ``ATTESTATION_REPORT`` JSON, for clients that assemble it after the
  binding check has passed;
* as a canonical ``chain_key_commitment: <64 hex>`` line, for clients whose
  JSON is assembled *before* that check — putting it in the JSON there would
  record a claim the hardware had not yet been shown to sign.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from tee_crafter.cli.deployment.common.attestation_report import (
    extract_attestation_report,
)

_TEMPLATES = (
    pathlib.Path(__file__).resolve().parents[2]
    / "src" / "tee_crafter" / "templates"
)

CLIENTS = [
    "nitro/client.template.py",
    "sgx/client.template.py",
    "gpu_cc/aws/client.template.py",
    "gpu_cc/azure/client.template.py",
    "gpu_cc/gcp/client.template.py",
    "snp/aws/client.template.py",
    "snp/azure/client.template.py",
    "snp/gcp/client.template.py",
    "tdx/azure/client.template.py",
    "tdx/gcp/client.template.py",
]

_COMMITMENT = "a" * 64

#: The canonical emission, exactly as the clients write it.
_CANONICAL_PRINT = re.compile(
    r'print\(\s*f"chain_key_commitment: \{commitment_ascii\.decode')


def _source(rel: str) -> str:
    p = _TEMPLATES / rel
    assert p.is_file(), f"client template missing: {p}"
    return p.read_text(encoding="utf-8")


def _report_dict_body(src: str) -> str:
    """The ``attestation_report = {...}`` literal, or "" if there is none."""
    start = src.find("attestation_report = {")
    if start == -1:
        return ""
    end = src.find("\n        }", start)
    return src[start:end] if end != -1 else src[start:]


class TestEveryClientReportsIt:
    @pytest.mark.parametrize("rel", CLIENTS)
    def test_client_surfaces_the_commitment(self, rel):
        src = _source(rel)
        in_json = '"chain_key_commitment"' in _report_dict_body(src)
        as_line = bool(_CANONICAL_PRINT.search(src))
        assert in_json or as_line, (
            f"{rel} verifies chain_key_commitment but never reports it — the "
            "deploy ledger will record nothing and verify-siem-chain's "
            "commitment pinning silently degrades"
        )

    @pytest.mark.parametrize("rel", CLIENTS)
    def test_client_still_verifies_it(self, rel):
        """Guard the other half: reporting a value nobody checked is worse
        than reporting nothing."""
        assert "resolve_chain_key_commitment(" in _source(rel)

    @pytest.mark.parametrize("rel", CLIENTS)
    def test_the_line_is_guarded_on_a_non_empty_value(self, rel):
        """``TEE_CRAFTER_ALLOW_UNBOUND_AUDIT_CHAIN=1`` yields ``b""``; nothing
        was anchored, so nothing may be recorded."""
        src = _source(rel)
        if not _CANONICAL_PRINT.search(src):
            pytest.skip("reports via the ATTESTATION_REPORT JSON instead")
        idx = _CANONICAL_PRINT.search(src).start()
        assert "if commitment_ascii:" in src[max(0, idx - 400):idx]


class TestTheExtractorActuallyPicksItUp:
    """The contract the canonical line is written against."""

    def test_canonical_line_is_extracted(self):
        out = extract_attestation_report(
            f"  some other diagnostic\nchain_key_commitment: {_COMMITMENT}\n")
        assert out.get("chain_key_commitment") == _COMMITMENT

    def test_the_old_prose_line_is_not_extracted(self):
        """Why snp-aws recorded nothing despite printing the value: the
        parenthetical sits between "commitment" and the colon."""
        out = extract_attestation_report(
            f"  Audit-log chain-key commitment (AMD-signed): {_COMMITMENT}\n")
        assert "chain_key_commitment" not in out

    def test_json_field_is_extracted(self):
        out = extract_attestation_report(
            'ATTESTATION_REPORT {"platform":"gpu-cc-aws",'
            f'"chain_key_commitment":"{_COMMITMENT}"}}\n')
        assert out.get("chain_key_commitment") == _COMMITMENT

    def test_json_does_not_erase_a_line_only_value(self):
        """The clients that emit the line also emit a JSON report without the
        field.  ``extract_attestation_report`` applies the JSON second, so this
        pins that it merges rather than replaces."""
        out = extract_attestation_report(
            f"chain_key_commitment: {_COMMITMENT}\n"
            'ATTESTATION_REPORT {"platform":"snp-aws","measurement":"'
            + "b" * 96 + '"}\n')
        assert out.get("chain_key_commitment") == _COMMITMENT
        assert out.get("platform") == "snp-aws"

    def test_a_short_value_is_refused(self):
        out = extract_attestation_report("chain_key_commitment: deadbeef\n")
        assert "chain_key_commitment" not in out
