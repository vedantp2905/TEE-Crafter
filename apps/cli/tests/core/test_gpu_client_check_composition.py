"""Ordering invariants in the GPU CC clients' verification chain.

Neither ``gpu-cc-gcp`` nor ``gpu-cc-aws`` has run against a live peer, both being
blocked on accelerator capacity rather than on code. The individual checks are
covered elsewhere against real synthetic crypto (``test_dcap_verify.py``,
``test_gpu_cc_gcp_intel_chain.py``, ``test_tcb_status_eval.py``). What no unit
test reached is the **assembly**: individually-correct checks composed in the
wrong order is a real failure class, and several of these checks are worthless
unless a specific predecessor already ran.

The three edges that matter, from the clients' own comments:

* ``verify_qe_report_signature`` must run **after** ``verify_pck_cert_chain``,
  because it consumes that call's validated ``pck_leaf``. Run first, or with a
  re-parsed leaf, and the QE binding is self-referential -- the attestation key
  is checked against a QE report from the same attacker-supplied quote.
* ``verify_gpu_nras_token`` must run **after** the nonce-binding recompute,
  because it takes ``expected_nonce_hex`` from it. Without that argument the
  token is accepted on NVIDIA's signature alone and a relayed attestation from
  another host passes.
* The audit chain-key commitment must only be *printed as attested* after the
  NRAS token verified, since NVIDIA's signature over ``eat_nonce`` is what makes
  the commitment mean anything.

Source-order assertions are a blunt instrument, and they are used here
deliberately: these are the invariants a live run would catch, a live run is
blocked on hardware nobody can buy today, and the alternative is shipping the
edges unguarded.
"""
from __future__ import annotations

from pathlib import Path

import pytest

TEMPLATES = (Path(__file__).parents[2]
             / "src" / "tee_crafter" / "templates" / "gpu_cc")

GCP = TEMPLATES / "gcp" / "client.template.py"
AWS = TEMPLATES / "aws" / "client.template.py"


def _body(path: Path) -> str:
    """The verify_ratls_connection body with ``#`` comments stripped.

    Two reasons for the narrowing. Starting at the function means an unrelated
    helper defined earlier cannot satisfy an ordering assertion. Dropping
    comments means a *mention* cannot either -- these clients explain their
    ordering in prose ("verify_gpu_nras_token() below confirms ..."), and an
    assertion that matched the explanation rather than the call would pass no
    matter how the code was reordered.

    String literals are deliberately kept: several assertions below anchor on
    the text of a ``print`` or an abort message.
    """
    src = path.read_text()
    body = src[src.index("def verify_ratls_connection("):]
    lines = []
    for line in body.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


@pytest.fixture(scope="module")
def gcp_body():
    return _body(GCP)


@pytest.fixture(scope="module")
def aws_body():
    return _body(AWS)


def _module_source(path: Path) -> str:
    """The whole template with ``#`` comments stripped.

    ``_body`` starts at ``verify_ratls_connection``, which is the right scope
    for ordering assertions inside the connection flow but excludes module-level
    constants and helper definitions that sit above it. Comments are stripped
    for the same reason as in ``_body``: these templates explain themselves at
    length, and an assertion that matched the explanation instead of the code
    would pass no matter what the code did.
    """
    lines = []
    for line in path.read_text().splitlines():
        if line.lstrip().startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


@pytest.fixture(scope="module")
def aws_source():
    return _module_source(AWS)


def _order(body: str, first: str, second: str) -> None:
    assert first in body, f"{first} missing from verify_ratls_connection"
    assert second in body, f"{second} missing from verify_ratls_connection"
    assert body.index(first) < body.index(second), (
        f"{first} must appear before {second}")


# --------------------------------------------------------------------------
# CPU chain: the PCK leaf has to be validated before it vouches for anything
# --------------------------------------------------------------------------

def test_pck_chain_precedes_qe_report_signature(gcp_body):
    _order(gcp_body, "verify_pck_cert_chain(", "verify_qe_report_signature(")


def test_qe_report_signature_uses_the_validated_leaf(gcp_body):
    """Passed through from pck_result rather than re-parsed, so the certificate
    that was validated and the one that is used cannot drift apart."""
    assert 'verify_qe_report_signature(quote_bytes, pck_result["pck_leaf"])' \
        in gcp_body


def test_signature_check_precedes_tcb_evaluation(gcp_body):
    """Evaluating TCB status on an unverified quote grades an attacker's
    self-reported SVNs."""
    _order(gcp_body, "verify_tdx_quote_signature(", "enforce_platform_tcb_status(")


def test_tcb_evaluation_consumes_the_validated_chain(gcp_body):
    assert "enforce_platform_tcb_status(quote_bytes, quote_info, pck_result)" \
        in gcp_body


def test_debug_bit_is_refused_before_any_trust_is_extended(gcp_body):
    _order(gcp_body, "TD_ATTRIBUTES", "verify_gpu_nras_token(")


# --------------------------------------------------------------------------
# GPU chain: the nonce binding is what stops a relayed attestation
# --------------------------------------------------------------------------

def test_nonce_binding_recompute_precedes_token_verification(gcp_body):
    _order(gcp_body, "_verify_nras_nonce_binding(", "verify_gpu_nras_token(")


def test_token_verification_receives_the_expected_nonce(gcp_body):
    """Called without expected_nonce_hex the token is accepted on NVIDIA's
    signature alone, which a relayed attestation from another GPU satisfies."""
    assert "verify_gpu_nras_token(gpu_token, expected_nonce_hex=expected_nonce_hex)" \
        in gcp_body


def test_spki_equality_precedes_token_verification(gcp_body):
    _order(gcp_body, "_compute_peer_spki_sha256(", "verify_gpu_nras_token(")


def test_chain_commitment_is_only_reported_after_nras_verified(gcp_body):
    """AUD-3: the commitment is only trustworthy once NVIDIA is confirmed to
    have signed this exact nonce."""
    _order(gcp_body, "verify_gpu_nras_token(",
           "Audit-log chain-key commitment (NVIDIA-signed via eat_nonce)")


# --------------------------------------------------------------------------
# Every gate is fatal
# --------------------------------------------------------------------------

@pytest.mark.parametrize("marker", [
    "TDX quote ECDSA signature verification FAILED",
    "QE report binding verification FAILED",
    "PCK certificate chain verification FAILED",
    "QE report signature verification FAILED",
    "GPU NRAS attestation failed",
    "NRAS nonce-binding check failed",
    "TLS SPKI mismatch",
    "vTPM measured-boot verification failed",
])
def test_gcp_failures_are_fatal(gcp_body, marker):
    """Each of these was, at some point in this project's history, a
    warn-and-continue. A gate that prints and proceeds is not a gate."""
    assert marker in gcp_body
    tail = gcp_body[gcp_body.index(marker):]
    assert "sys.exit(1)" in tail[:400], (
        f"{marker!r} does not abort promptly")


def test_gcp_requires_a_gpu_token(gcp_body):
    """Full-confidential means the GPU evidence is not optional."""
    assert "GPU NRAS attestation NOT PRESENT" in gcp_body


def test_gcp_refuses_an_unpinned_mrtd_by_default(gcp_body):
    """A valid quote proves the hardware, not which image booted on it."""
    assert "no MRTD pinned into this client" in gcp_body
    assert "_allow_unpinned_measurement()" in gcp_body


# --------------------------------------------------------------------------
# gpu-cc-aws: the honest refusal must stay honest
# --------------------------------------------------------------------------

def test_aws_verifies_the_nitrotpm_document_before_trusting_its_pcrs(aws_body, aws_source):
    """The CPU evidence must come from the signed document, not the JSON blob.

    Inverted from its original form on evidence. This used to assert
    `_nitrotpm_unverifiable()` was called, i.e. that the client refused CPU
    attestation outright, on the belief that no AWS NitroTPM root was pinned.
    Measured 2026-08-24: the document's cabundle roots at
    CN=aws.nitro-enclaves, byte-for-byte certs/nitro-root.pem. So the client
    verifies chain and signature locally, and the ordering that matters now is
    that verification precedes any use of the PCRs.
    """
    assert "verify_nitrotpm_document(" in aws_body
    verify_at = aws_source.index("def verify_nitrotpm_document")
    body = aws_source[verify_at:]
    sig_check = body.index("COSE_Sign1 signature does not verify")
    read_pcrs = body.index('payload.get("nitrotpm_pcrs")')
    assert sig_check < read_pcrs, (
        "the PCRs are read before the COSE_Sign1 signature is checked, so a "
        "forged document's values would be used")


def test_aws_pins_the_nitro_root_rather_than_delegating_to_kms(aws_source):
    """Local verification, so no AWS credentials are needed to check CPU
    evidence and the trust root stays in this repository."""
    assert "_AWS_NITRO_ROOT_CA_PEM" in aws_source
    assert "chain does not terminate at the pinned AWS Nitro root" in aws_source


def test_aws_keeps_self_reported_pcrs_separate_from_verified_ones(aws_source):
    """Two sources, two key names, so nothing downstream can conflate them.

    The unsigned NITROTPM_OID blob is still shipped for operator context; what
    must never happen is it landing under the same key as the hypervisor-signed
    values from the attestation document.
    """
    assert "nitrotpm_pcrs_self_reported" in aws_source
    assert "nitrotpm_pcrs_unverified" not in aws_source, (
        "the old key name is gone; a consumer reading it would now silently "
        "get nothing")
    verified_at = aws_source.index('"nitrotpm_pcrs":')
    self_at = aws_source.index('"nitrotpm_pcrs_self_reported":')
    assert verified_at != self_at


def test_aws_nonce_binding_still_precedes_token_verification(aws_body):
    _order(aws_body, "_verify_nras_nonce_binding(", "verify_gpu_nras_token(")
