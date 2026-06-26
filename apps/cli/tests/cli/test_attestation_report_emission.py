"""Regression tests for the ATTESTATION_REPORT line client templates emit.

Background
==========
Several client templates build an ``attestation_report`` dict and call
``json.dumps`` to print a single ``ATTESTATION_REPORT {<json>}`` line.
That line is the only piece of evidence used by audit checks
``ATT-006`` (nonce binding present) and ``ATT-007`` (TLS SPKI captured).

A bug in tdx/gcp, tdx/azure, sgx and gpu_cc/gcp client templates put a
raw ``bytes`` value into the dict under ``nonce_binding`` (the slice was
taken from the quote payload).  ``json.dumps`` then raised TypeError
and the surrounding ``except Exception: pass`` swallowed it — so the
line never reached stdout, and ATT-006 / ATT-007 were silently marked
FAIL on every TDX-GCP / SGX / GPU-CC GCP build.

These tests pin the contract: the static source of every client
template that emits ATTESTATION_REPORT must use a hex / string field
(not the raw bytes slice), and the json.dumps fallback must surface
failures to stderr rather than swallow them silently.
"""
from __future__ import annotations

import pathlib
import re


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_TEMPLATES = _REPO_ROOT / "src" / "tee_crafter" / "templates"

_CLIENTS_WITH_ATTESTATION_REPORT = [
    "tdx/gcp/client.template.py",
    "tdx/azure/client.template.py",
    "sgx/client.template.py",
    "gpu_cc/gcp/client.template.py",
    "gpu_cc/aws/client.template.py",
    "gpu_cc/azure/client.template.py",
    "snp/aws/client.template.py",
    "snp/azure/client.template.py",
    "snp/gcp/client.template.py",
    "nitro/client.template.py",
]


def test_no_raw_bytes_in_attestation_report():
    """``nonce_binding`` and friends must use the ``_hex`` field, never
    the raw bytes slice — otherwise json.dumps raises and the line is
    dropped silently (cf. tdx-gcp 20260520_003648 build).
    """
    pattern = re.compile(
        r'"nonce_binding"\s*:\s*[\w\.]+\.get\(\s*"report_data"\s*,'
    )
    offenders = []
    for rel in _CLIENTS_WITH_ATTESTATION_REPORT:
        p = _TEMPLATES / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8")
        if "ATTESTATION_REPORT" not in text:
            continue
        if pattern.search(text):
            offenders.append(rel)
    assert offenders == [], (
        "client templates still pass raw `report_data` bytes into the "
        "attestation_report dict — json.dumps will silently raise and "
        f"ATT-006 will FAIL on every build. Offenders: {offenders}"
    )


_PREVIOUSLY_BUGGY = [
    "tdx/gcp/client.template.py",
    "tdx/azure/client.template.py",
    "sgx/client.template.py",
    "gpu_cc/gcp/client.template.py",
]


def test_tdx_gcp_verify_dcap_passes_cert_der_into_scope():
    """Regression: ``_verify_dcap_attestation`` must receive ``cert_der``
    and ``server_cd`` — otherwise ``ATTESTATION_REPORT`` emission raises
    ``NameError`` and ATT-006/007 fail (tdx-gcp 20260520_015209 build).
    """
    text = (_TEMPLATES / "tdx/gcp/client.template.py").read_text(encoding="utf-8")
    assert "def _verify_dcap_attestation(" in text
    assert "cert_der: bytes" in text
    assert "return _verify_dcap_attestation(" in text
    assert "cert_der=cert_der" in text


def test_attestation_report_exception_path_surfaces_to_stderr():
    """The ``except`` around the ATTESTATION_REPORT print must NOT be a
    bare ``pass`` for the templates that previously suffered the
    ``report_data`` bytes regression — otherwise a future serialization
    bug goes unnoticed.
    """
    for rel in _PREVIOUSLY_BUGGY:
        p = _TEMPLATES / rel
        text = p.read_text(encoding="utf-8")
        idx = text.find("ATTESTATION_REPORT {json.dumps")
        assert idx != -1, f"{rel}: lost ATTESTATION_REPORT print"
        tail = text[idx:idx + 600]
        # The next ``except Exception`` after the print MUST log to
        # stderr, not be a silent ``pass``.
        assert "except Exception:\n        pass" not in tail, (
            f"{rel}: ATTESTATION_REPORT exception handler is still a bare "
            f"`pass` — serialization regressions will be invisible"
        )
        assert "file=sys.stderr" in tail, (
            f"{rel}: ATTESTATION_REPORT exception handler must print the "
            f"error to stderr"
        )


# ---------------------------------------------------------------------------
# chain_key_commitment must survive the trip from client stdout to the ledger
# ---------------------------------------------------------------------------

def test_chain_key_commitment_is_an_allowed_report_field():
    """Otherwise the allow-list filter silently drops it.

    ``_filter`` keeps only keys in ``REPORT_FIELDS``.  A client can emit
    ``chain_key_commitment`` on the ATTESTATION_REPORT line and, if the field
    is not allow-listed, it vanishes with no error -- so ``verify-provenance``
    could never pin the hardware-attested commitment, and
    ``verify-siem-chain`` would stay self-referential: the commitment would
    travel inside the very log it is supposed to authenticate.
    """
    from tee_crafter.cli.deployment.common.attestation_report import REPORT_FIELDS
    assert "chain_key_commitment" in REPORT_FIELDS


def test_chain_key_commitment_round_trips_from_the_report_line():
    from tee_crafter.cli.deployment.common.attestation_report import (
        extract_attestation_report,
    )
    commitment = "b" * 64
    line = (
        'ATTESTATION_REPORT {"platform": "tdx-gcp", '
        f'"chain_key_commitment": "{commitment}"}}'
    )
    out = extract_attestation_report(line)
    assert out["chain_key_commitment"] == commitment


def test_chain_key_commitment_parsed_from_a_human_readable_line():
    from tee_crafter.cli.deployment.common.attestation_report import (
        extract_attestation_report,
    )
    commitment = "c" * 64
    out = extract_attestation_report(
        f"  Audit-log chain-key commitment: {commitment}\n")
    assert out["chain_key_commitment"] == commitment


def test_a_wrong_width_commitment_is_not_accepted():
    """64 hex exactly. The clients reject any other width, so the one place an
    operator looks to confirm the value must not be laxer than they are."""
    from tee_crafter.cli.deployment.common.attestation_report import (
        extract_attestation_report,
    )
    # 65+ matters as much as 63: an anchored-length pattern that allowed the
    # match to start mid-token would happily read a 64-char window out of a
    # longer string and call it the commitment.
    for bad in ("d" * 63, "d" * 65, "d" * 70, "d" * 32, "not-hex-at-all"):
        out = extract_attestation_report(
            f"  chain_key_commitment: {bad}\n")
        assert "chain_key_commitment" not in out, bad
