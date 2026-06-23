"""Load ``templates/common/tee_crafter_maa.py`` the way a client would.

The MAA verifier is a *client support module*: it lives under
``templates/common/`` and the build copies it beside the rendered client, which
then imports it by bare name. It is deliberately not importable as
``tee_crafter.core.*`` — the client runs on the operator's machine from a build
directory and has no ``tee_crafter`` package on its path.

Tests therefore load it from its real location, so what is under test is the
file that actually ships rather than a second copy that could drift. Same
approach as ``test_tcb_status_eval.py`` takes for the shared TCB evaluator.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "src" / "tee_crafter" / "templates" / "common" / "tee_crafter_maa.py"
)

assert _MODULE_PATH.is_file(), f"MAA verifier missing at {_MODULE_PATH}"

_spec = importlib.util.spec_from_file_location("tee_crafter_maa_under_test",
                                               str(_MODULE_PATH))
_mod = importlib.util.module_from_spec(_spec)
sys.modules["tee_crafter_maa_under_test"] = _mod
_spec.loader.exec_module(_mod)

COMPLIANT_CVM = _mod.COMPLIANT_CVM
TDX_ATTESTATION_TYPE = _mod.TDX_ATTESTATION_TYPE
REQUIRED_ALG = _mod.REQUIRED_ALG
RTMR_CLAIMS = _mod.RTMR_CLAIMS
MaaVerdict = _mod.MaaVerdict
MaaVerificationError = _mod.MaaVerificationError
verify_maa_tdx_token = _mod.verify_maa_tdx_token
attest_tdx_dcap_quote = _mod.attest_tdx_dcap_quote
expected_issuer_for = _mod.expected_issuer_for
jwks_url_for = _mod.jwks_url_for

AZURE_GUEST_ATTESTATION_TYPE = _mod.AZURE_GUEST_ATTESTATION_TYPE
ISOLATION_TEE_CLAIM = _mod.ISOLATION_TEE_CLAIM
ATTESTATION_CLIENT_ENV = _mod.ATTESTATION_CLIENT_ENV
ATTESTATION_CLIENT_DEFAULT = _mod.ATTESTATION_CLIENT_DEFAULT
attestation_client_path = _mod.attestation_client_path
azure_guest_token = _mod.azure_guest_token
verify_maa_azure_guest_token = _mod.verify_maa_azure_guest_token
expected_client_payload_nonces = _mod.expected_client_payload_nonces
