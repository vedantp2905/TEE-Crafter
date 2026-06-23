"""The NitroTPM release chain, joined up, with no cloud.

Every link here was individually correct and collectively inert at one point in
this feature's life: ``pin_statement`` accepted ``pcr_values`` that no caller
passed, ``AWS_NITROTPM_RECIPIENT`` existed as an enum member nothing selected,
and ``build_for_platform`` returned an SEV-SNP provider whose report
``kms:Decrypt``'s ``Recipient`` parameter does not accept. A hardware run would
have reported success on the identity-gated path and proved nothing.

So these tests walk the seam, not the parts:

    bake records PCRs -> deploy reads them -> key policy carries the conditions
    -> provider produces a document -> adapter attaches it -> response unwraps

Plus the coupling that makes the feature safe to ship: PCR conditions and an
attesting runtime arrive together, or neither does.
"""
from __future__ import annotations

import json

import pytest

from tee_crafter.cli.commands.deploy.byok_mode import (
    UNWRAP_MODES, _NITROTPM_CAPABLE_PLATFORMS,
)
from tee_crafter.cli.deployment.common.byok_key_policy import (
    DECRYPT_SID, nitrotpm_pcrs_for_image, pin_byok_key_to_instance_role,
)
from tee_crafter.core.keys.attestation_providers import (
    NitroTpmAttestationProvider, build_for_platform,
)
from tee_crafter.core.measurements import registry
from tee_crafter.core.measurements.capture import (
    parse_nitrotpm_pcrs, snp_capture_command,
)

# 48 bytes: SHA-384, the bank a NitroTPM attestation document reports.
PCR4 = "ab" * 48
PCR7 = "cd" * 48
AMI = "ami-0a6e51a20a2d3ed81"
ROLE = "arn:aws:iam::950771918023:role/tee-crafter-snp-role-a1b2c3d4"


# --------------------------------------------------------------------------
# Link 1: the bake's capture transcript carries PCRs
# --------------------------------------------------------------------------

def test_snp_capture_command_probes_the_tpm():
    """Folded into the existing SNP capture rather than given its own VM, since
    each probe VM is a real instance-hour."""
    cmd = snp_capture_command()
    # SHA-384, not SHA-256: a NitroTPM document reports digest=SHA384 and KMS
    # matches those 48-byte values. Confirmed by decoding a real document on
    # 2026-08-24; a sha256 read produced 32-byte values that never match.
    assert "tpm2_pcrread sha384:4,7" in cmd


def test_pcr_probe_cannot_fail_the_capture():
    """An AMI without TpmSupport must still yield a launch measurement."""
    cmd = snp_capture_command()
    probe = cmd[:cmd.index("TEE_CRAFTER_PCR")] if "TEE_CRAFTER_PCR" in cmd else cmd
    assert "|| true" in probe or "|| true" in cmd


def test_transcript_parses_into_pcrs():
    transcript = (
        "TEE_CRAFTER_CPU_MODEL=AMD EPYC 7R13 Processor\n"
        f"TEE_CRAFTER_PCR4={PCR4.upper()}\n"
        f"TEE_CRAFTER_PCR7={PCR7}\n"
        "TEE_CRAFTER_MEASUREMENT=" + "ee" * 48 + "\n"
    )
    assert parse_nitrotpm_pcrs(transcript) == {"4": PCR4, "7": PCR7}


def test_transcript_without_a_tpm_parses_to_nothing():
    assert parse_nitrotpm_pcrs("TEE_CRAFTER_MEASUREMENT=" + "ee" * 48) == {}


# --------------------------------------------------------------------------
# Link 2: the deploy reads them back out of the registry
# --------------------------------------------------------------------------

@pytest.fixture
def registry_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "_REGISTRY_DIR", str(tmp_path))
    return tmp_path


def _write_record(registry_dir, **extra):
    path = registry_dir / "snp-aws"
    path.mkdir(parents=True, exist_ok=True)
    record = {"platform": "snp-aws", "image_id": AMI, "field": "measurement",
              "measurement": "ee" * 48, "source": "bake-ami", **extra}
    (path / (registry._sanitize(AMI) + ".json")).write_text(json.dumps(record))


def test_record_level_pcrs_are_found(registry_dir):
    _write_record(registry_dir, nitrotpm_pcrs={"4": PCR4, "7": PCR7})
    assert nitrotpm_pcrs_for_image("snp-aws", AMI) == {"4": PCR4, "7": PCR7}


def test_variant_level_pcrs_are_found(registry_dir):
    """The record-level field arrived after the per-variant one."""
    _write_record(registry_dir, variants=[
        {"instance_type": "m6a.large", "vcpu": 2,
         "nitrotpm_pcrs": {"4": PCR4, "7": PCR7}}])
    assert nitrotpm_pcrs_for_image("snp-aws", AMI) == {"4": PCR4, "7": PCR7}


def test_no_pcrs_recorded_returns_empty(registry_dir):
    _write_record(registry_dir)
    assert nitrotpm_pcrs_for_image("snp-aws", AMI) == {}


def test_unknown_image_returns_empty(registry_dir):
    assert nitrotpm_pcrs_for_image("snp-aws", "ami-nope") == {}


# --------------------------------------------------------------------------
# Link 3: the pin couples conditions to an attesting runtime
# --------------------------------------------------------------------------

class _Console:
    def __init__(self):
        self.lines = []

    def print(self, text=""):
        self.lines.append(str(text))


class _Kms:
    def __init__(self):
        self.policy = {"Version": "2012-10-17", "Statement": []}
        self.written = None

    def get_key_policy(self, **kw):
        return {"Policy": json.dumps(self.policy)}

    def put_key_policy(self, **kw):
        self.written = json.loads(kw["Policy"])


def _pin(registry_dir, unwrap, kms=None):
    kms = kms or _Kms()
    ok, detail = pin_byok_key_to_instance_role(
        console=_Console(), build_dir="/nonexistent", tee_platform="snp-aws",
        outputs={"instance_role_arn": ROLE}, region="us-east-2",
        kms_client=kms, ami_id=AMI,
        read_byok_config=lambda _d: {
            "provider": "aws-kms", "key_id": "arn:aws:kms:us-east-2:1:key/k",
            "unwrap": unwrap},
    )
    return ok, detail, kms


def test_direct_bytes_pins_identity_only(registry_dir):
    _write_record(registry_dir, nitrotpm_pcrs={"4": PCR4, "7": PCR7})
    ok, _detail, kms = _pin(registry_dir, "direct_bytes")
    assert ok
    stmt = next(s for s in kms.written["Statement"] if s["Sid"] == DECRYPT_SID)
    assert "StringEqualsIgnoreCase" not in stmt["Condition"]


def test_nitrotpm_unwrap_pins_the_pcr_conditions(registry_dir):
    _write_record(registry_dir, nitrotpm_pcrs={"4": PCR4, "7": PCR7})
    ok, _detail, kms = _pin(registry_dir, "aws_nitrotpm_recipient")
    assert ok
    stmt = next(s for s in kms.written["Statement"] if s["Sid"] == DECRYPT_SID)
    assert stmt["Condition"]["StringEqualsIgnoreCase"] == {
        "kms:RecipientAttestation:NitroTPMPCR4": PCR4,
        "kms:RecipientAttestation:NitroTPMPCR7": PCR7,
    }
    # Identity survives: without it, any attested instance in the account passes.
    assert stmt["Condition"]["ArnEquals"] == {"aws:PrincipalArn": ROLE}


def test_nitrotpm_unwrap_without_recorded_pcrs_fails_closed(registry_dir):
    """The operator asked for measurement gating. Silently pinning identity only
    would hand them a key that looks configured and gates nothing."""
    _write_record(registry_dir)
    ok, detail, kms = _pin(registry_dir, "aws_nitrotpm_recipient")
    assert ok is False
    assert "no NitroTPM PCRs are recorded" in detail
    assert kms.written is None, "must not rewrite the policy when refusing"


def test_pcrs_are_never_pinned_against_a_non_attesting_runtime(registry_dir):
    """The coupling that keeps this safe to ship. Once the conditions are on the
    key, KMS denies any request whose Recipient lacks a document -- so pinning
    them for a direct_bytes runtime would break BYOK outright."""
    _write_record(registry_dir, nitrotpm_pcrs={"4": PCR4, "7": PCR7})
    for unwrap in ("direct_bytes", "rsa_oaep_sha256", "aws_nitro_recipient"):
        _ok, _detail, kms = _pin(registry_dir, unwrap)
        stmt = next(s for s in kms.written["Statement"]
                    if s["Sid"] == DECRYPT_SID)
        assert "StringEqualsIgnoreCase" not in stmt["Condition"], unwrap


# --------------------------------------------------------------------------
# Link 4: the provider produces a document and keeps the key
# --------------------------------------------------------------------------

def test_unwrap_mode_is_accepted_by_the_config_validator():
    assert "aws_nitrotpm_recipient" in UNWRAP_MODES


def test_provider_selection_follows_the_unwrap_mode(monkeypatch):
    monkeypatch.delenv("TEE_CRAFTER_BYOK_UNWRAP", raising=False)
    assert type(build_for_platform("snp-aws")).__name__ \
        == "SnpAttestationProvider"
    assert isinstance(
        build_for_platform("snp-aws", unwrap="aws_nitrotpm_recipient"),
        NitroTpmAttestationProvider)


def test_provider_selection_reads_the_runtime_env(monkeypatch):
    """Same variable the bootstrap builds the key ref from, so the provider and
    the unwrap mode cannot disagree."""
    monkeypatch.setenv("TEE_CRAFTER_BYOK_UNWRAP", "aws_nitrotpm_recipient")
    assert isinstance(build_for_platform("snp-aws"),
                      NitroTpmAttestationProvider)


def test_nitro_aws_is_not_diverted(monkeypatch):
    """nitro-aws uses the Nitro *Enclaves* condition keys, a different key
    hierarchy, and is handled by the in-enclave NSM path."""
    monkeypatch.setenv("TEE_CRAFTER_BYOK_UNWRAP", "aws_nitrotpm_recipient")
    assert "nitro-aws" not in _NITROTPM_CAPABLE_PLATFORMS
    with pytest.raises(ValueError):
        build_for_platform("nitro-aws")


def test_provider_returns_a_document_and_retains_the_private_key():
    seen = {}

    def reader(public_der):
        seen["der"] = public_der
        return b"\xd2\x84document"

    provider = NitroTpmAttestationProvider(
        document_reader=reader,
        pcr_reader=lambda pcrs: {"4": PCR4, "7": PCR7},
        clock=lambda: 1000.0)
    assert provider.recipient_private_key is None
    blob, issued_at, measurement = provider.fresh(purpose="byok")

    assert blob == b"\xd2\x84document"
    assert issued_at == 1000.0
    assert len(measurement) == 64
    assert provider.recipient_private_key is not None
    # The public half inside the document is the one we kept the key for.
    from cryptography.hazmat.primitives import serialization
    assert seen["der"] == provider.recipient_private_key.public_key(
    ).public_bytes(serialization.Encoding.DER,
                   serialization.PublicFormat.SubjectPublicKeyInfo)


def test_unreadable_pcrs_do_not_block_a_release():
    """The advisory measurement is not the gate; KMS is. A TPM read failure must
    not stop a release KMS is about to check properly."""
    def boom(_pcrs):
        raise RuntimeError("no tpm")

    provider = NitroTpmAttestationProvider(
        document_reader=lambda der: b"doc", pcr_reader=boom)
    _blob, _ts, measurement = provider.fresh(purpose="byok")
    assert measurement == ""


# --------------------------------------------------------------------------
# Link 5: the adapter attaches it and the response round-trips
# --------------------------------------------------------------------------

def test_adapter_attaches_the_provider_document():
    import base64

    from tee_crafter.core.keys.aws_kms import AwsKmsAdapter
    from tee_crafter.core.keys.gating import FACT_NITROTPM_PCRS_PINNED
    from tee_crafter.core.keys.spec import (
        AttestedKeyRef, KeyGating, KeyProvider, KeyReleasePolicy,
        UnwrapAlgorithm,
    )

    class _DecryptKms:
        def __init__(self):
            self.request = None

        def decrypt(self, **kw):
            self.request = kw
            return {"CiphertextForRecipient": b"cms", "KeyId": "k"}

    provider = NitroTpmAttestationProvider(
        document_reader=lambda der: b"THE-DOCUMENT",
        pcr_reader=lambda pcrs: {"4": PCR4, "7": PCR7})
    document, _ts, _m = provider.fresh(purpose="byok")

    kms = _DecryptKms()
    material = AwsKmsAdapter(kms_client=kms).release(
        key_ref=AttestedKeyRef(
            provider=KeyProvider.AWS_KMS, key_id="arn:aws:kms:::key/k",
            unwrap=UnwrapAlgorithm.AWS_NITROTPM_RECIPIENT,
            extra={"ciphertext_b64": base64.b64encode(b"wrapped").decode(),
                   "tee_platform": "snp-aws",
                   FACT_NITROTPM_PCRS_PINNED: "true"}),
        attestation=document,
        policy=KeyReleasePolicy(allow_any_measurement=True))

    assert kms.request["Recipient"]["AttestationDocument"] == b"THE-DOCUMENT"
    assert material.gating is KeyGating.KMS_ENFORCED
    assert material.wrapped_for_recipient == b"cms"


def test_runtime_bootstrap_unwraps_the_cms_envelope():
    """Without this the measurement gate would pass and the DEK still would not
    arrive -- the release returns a CMS envelope, not plaintext."""
    import inspect

    from tee_crafter.templates.common import tee_crafter_runtime_bootstrap as boot

    src = inspect.getsource(boot)
    assert "AWS_NITROTPM_RECIPIENT" in src
    assert "decrypt_ciphertext_for_recipient" in src
    assert "recipient_private_key" in src


# --------------------------------------------------------------------------
# Link 6: the explicit Deny, without which the gate gates nothing
# --------------------------------------------------------------------------

def test_pinning_emits_explicit_deny_statements(registry_dir):
    """A conditional Allow restricts nothing on its own.

    Verified against live KMS on 2026-08-24: with only the conditional Allow, a
    decrypt carrying **no attestation document** succeeded, and so did one
    against a policy pinned to a deliberately wrong PCR4. The account-root
    delegation in every default key policy, plus an identity policy granting
    kms:Decrypt -- which ``aws_iam_role_policy.snp_byok_kms_decrypt`` hands the
    instance role -- authorised it by another path entirely.

    After adding the Denies, the same three calls returned SUCCESS / DENIED /
    DENIED as intended.
    """
    from tee_crafter.cli.deployment.common.byok_key_policy import (
        DENY_MISMATCH_SID_PREFIX, DENY_UNATTESTED_SID,
    )

    _write_record(registry_dir, nitrotpm_pcrs={"4": PCR4, "7": PCR7})
    _ok, _detail, kms = _pin(registry_dir, "aws_nitrotpm_recipient")
    stmts = {s["Sid"]: s for s in kms.written["Statement"]}

    absent = stmts[DENY_UNATTESTED_SID]
    assert absent["Effect"] == "Deny"
    assert absent["Action"] == ["kms:Decrypt"]
    # Null matches when the condition key is absent, i.e. no document attached.
    assert list(absent["Condition"]) == ["Null"]
    assert list(absent["Condition"]["Null"].values()) == ["true"]

    mismatch = [s for sid, s in stmts.items()
                if sid.startswith(DENY_MISMATCH_SID_PREFIX)]
    # One per PCR, deliberately: condition keys inside a single block are AND-ed,
    # so a combined StringNotEquals would deny only when *both* differed.
    assert len(mismatch) == 2
    for s in mismatch:
        assert s["Effect"] == "Deny"
        assert len(s["Condition"]["StringNotEqualsIgnoreCase"]) == 1


def test_deny_is_scoped_to_decrypt_only(registry_dir):
    """Encrypt must keep working -- the operator wraps the DEK from a workstation
    with no TPM -- and the key has to stay manageable."""
    _write_record(registry_dir, nitrotpm_pcrs={"4": PCR4, "7": PCR7})
    _ok, _d, kms = _pin(registry_dir, "aws_nitrotpm_recipient")
    for s in kms.written["Statement"]:
        if s["Effect"] == "Deny":
            assert s["Action"] == ["kms:Decrypt"], s["Sid"]


def test_no_deny_when_pcrs_are_not_pinned(registry_dir):
    """An identity-only pin must not brick a key that never claimed a gate."""
    _write_record(registry_dir, nitrotpm_pcrs={"4": PCR4, "7": PCR7})
    _ok, _d, kms = _pin(registry_dir, "direct_bytes")
    assert all(s["Effect"] == "Allow" for s in kms.written["Statement"])


def test_repinning_removes_stale_denies(registry_dir):
    """A re-bake moves PCR4. A leftover Deny naming the old value would deny the
    new image's perfectly valid attestation."""
    from tee_crafter.cli.deployment.common.byok_key_policy import pin_statement

    first = pin_statement({}, ROLE, "1", pcr_values={"4": PCR4, "7": PCR7})
    second = pin_statement(first, ROLE, "1",
                           pcr_values={"4": "ee" * 48, "7": "ff" * 48})
    blob = json.dumps(second)
    assert PCR4 not in blob and PCR7 not in blob
    assert len(second["Statement"]) == len(first["Statement"])
