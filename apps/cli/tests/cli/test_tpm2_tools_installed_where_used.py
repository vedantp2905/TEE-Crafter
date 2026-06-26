"""If a runtime template shells out to ``tpm2_*``, the bake must install it.

``gpu-cc-gcp`` shipped without this coupling holding. Its app template calls
``tpm2_pcrread`` to build the vTPM PCR bundle it publishes in the RA-TLS
certificate, and ``setup_gpu_cc_gcp.sh`` never installed ``tpm2-tools``. The
failure chain was silent all the way to the end:

    binary missing -> _get_vtpm_pcrs() returns {} -> certificate carries an
    empty PCR bundle -> client's verify_vtpm_pcrs fails closed on "empty PCR
    map" -> deploy refused

so the first symptom would have been a refused deploy *after* paying for an A3
instance, with nothing in the bake output hinting at the cause.

Nothing here asserts the reverse -- a script may install ``tpm2-tools`` for a
platform whose template does not call it (``snp-aws`` uses it from the capture
probe rather than the app), and that is not a defect.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "tee_crafter"
TEMPLATES = SRC / "templates"
SCRIPTS = SRC / "scripts"

#: template directory -> the setup script for the same platform.
_PLATFORM_SCRIPT = {
    "gpu_cc/aws": "gpu_cc_aws/setup_gpu_cc_aws.sh",
    "gpu_cc/azure": "gpu_cc_azure/setup_gpu_cc_azure.sh",
    "gpu_cc/gcp": "gpu_cc_gcp/setup_gpu_cc_gcp.sh",
    "snp/aws": "snp_aws/setup_snp_aws.sh",
    "snp/azure": "snp_azure/setup_snp_azure.sh",
    "snp/gcp": "snp_gcp/setup_snp_gcp.sh",
    "tdx/azure": "tdx_azure/setup_tdx.sh",
    "tdx/gcp": "tdx_gcp/setup_tdx_gcp.sh",
    "nitro": "nitro_aws/setup_nitro.sh",
    "sgx": "sgx_azure/setup_sgx.sh",
}

#: A ``tpm2_...`` invocation, not a mention. Comment lines are dropped before
#: matching: several of these templates *discuss* tpm2 tooling in prose, and an
#: assertion satisfied by a comment would pass no matter what the code did.
_TPM2_CALL = re.compile(r"\btpm2_[a-z]+\b")


def _code_only(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("#"))


def _templates_calling_tpm2():
    found = []
    for rel, script in sorted(_PLATFORM_SCRIPT.items()):
        tdir = TEMPLATES / rel
        if not tdir.is_dir():
            continue
        for template in sorted(tdir.glob("*.template.py")):
            calls = sorted(set(_TPM2_CALL.findall(_code_only(template.read_text()))))
            if calls:
                found.append((rel, script, template.name, calls))
    return found


def test_the_scan_finds_something():
    """Guard against the parametrisation silently collapsing to nothing."""
    assert _templates_calling_tpm2(), (
        "no template appears to call tpm2_* -- either the regex or the "
        "directory map has drifted, and the tests below would all vacuously "
        "pass")


@pytest.mark.parametrize(
    "platform,script,template,calls",
    _templates_calling_tpm2(),
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_tpm2_tools_is_installed_for_templates_that_call_it(
        platform, script, template, calls):
    script_path = SCRIPTS / script
    assert script_path.is_file(), f"{script} not found"
    body = _code_only(script_path.read_text())
    assert "tpm2-tools" in body, (
        f"{platform}/{template} calls {', '.join(calls)} but {script} does not "
        f"install tpm2-tools, so the binary is absent at runtime and the call "
        f"fails silently")


def test_gpu_cc_gcp_specifically_installs_it():
    """The platform this test file exists because of."""
    body = _code_only((SCRIPTS / "gpu_cc_gcp/setup_gpu_cc_gcp.sh").read_text())
    assert "tpm2-tools" in body
