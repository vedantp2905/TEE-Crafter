"""NitroTPM-gated key release on ``snp-aws``.

The point of this platform's BYOK path used to be that it had no measurement
gate: ``kms:Decrypt`` checked the caller's principal ARN and nothing else. These
tests cover the mechanism that changes that, and in particular the three ways it
could look like it works while not working:

1. a policy that pins PCRs but whose release path attaches no attestation
   document -- KMS denies every decrypt, so BYOK breaks rather than tightens;
2. a policy that pins only PCR7, which is the Secure Boot *policy* and so is
   shared by every AMI carrying the same certificates;
3. a ``DescribeKey`` grant left inside the attested statement, which KMS denies
   because that operation has no ``Recipient`` parameter and therefore can never
   satisfy the condition.
"""
from __future__ import annotations

import subprocess

import pytest

from tee_crafter.cli.deployment.common.byok_key_policy import (
    DECRYPT_SID, DESCRIBE_SID, pin_statement,
)
from tee_crafter.core.keys import nitrotpm
from tee_crafter.core.keys.gating import (
    FACT_NITROTPM_PCRS_PINNED, FACT_PCRS_PINNED, gating_for, gating_from_extra,
)
from tee_crafter.core.keys.spec import KeyGating, KeyProvider, UnwrapAlgorithm

ROLE = "arn:aws:iam::950771918023:role/tee-crafter-snp-role-a1b2c3d4"
ACCOUNT = "950771918023"
PCR4 = "ab" * 48
PCR7 = "cd" * 48
PCRS = {"4": PCR4, "7": PCR7}


# --------------------------------------------------------------------------
# The gating truth table
# --------------------------------------------------------------------------

def test_snp_aws_is_iam_scoped_until_pcrs_are_pinned():
    assert gating_for(KeyProvider.AWS_KMS, "snp-aws").gating is KeyGating.IAM_SCOPED


def test_snp_aws_upgrades_to_kms_enforced_with_nitrotpm_pcrs():
    row = gating_for(KeyProvider.AWS_KMS, "snp-aws",
                     **{FACT_NITROTPM_PCRS_PINNED: True})
    assert row.gating is KeyGating.KMS_ENFORCED
    assert row.enforced_by == "aws-kms-key-policy"
    assert row.measurement_gate == "policy-enforced"


def test_enclave_pcr_fact_does_not_upgrade_snp_aws():
    """The two condition-key families are not interchangeable.

    ``kms:RecipientAttestation:PCR0`` is the Nitro *Enclaves* hierarchy. An
    ``snp-aws`` instance is not an enclave, so a deploy that recorded the
    enclave fact must not be read as having pinned NitroTPM PCRs.
    """
    row = gating_for(KeyProvider.AWS_KMS, "snp-aws",
                     **{FACT_PCRS_PINNED: True})
    assert row.gating is KeyGating.IAM_SCOPED


def test_absent_fact_reads_as_the_weaker_verdict():
    assert gating_from_extra(
        KeyProvider.AWS_KMS, {"tee_platform": "snp-aws"}
    ).gating is KeyGating.IAM_SCOPED


def test_gpu_cc_aws_shares_the_upgrade_path():
    """``gpu-cc-aws`` is also a Nitro instance, and P5 supports NitroTPM."""
    row = gating_for(KeyProvider.AWS_KMS, "gpu-cc-aws",
                     **{FACT_NITROTPM_PCRS_PINNED: True})
    assert row.gating is KeyGating.KMS_ENFORCED


# --------------------------------------------------------------------------
# PCR selection and validation
# --------------------------------------------------------------------------

def test_default_selection_is_pcr4_and_pcr7():
    assert nitrotpm.DEFAULT_PINNED_PCRS == (4, 7)


def test_empty_pcr_selection_is_refused():
    with pytest.raises(nitrotpm.NitroTpmError, match="identity-gated"):
        nitrotpm.validate_pcr_selection([])


@pytest.mark.parametrize("pcr", [0, 1])
def test_aws_constant_pcrs_are_refused(pcr):
    """AWS documents PCR0/PCR1 as constant so early boot code can be updated."""
    with pytest.raises(nitrotpm.NitroTpmError, match="constant"):
        nitrotpm.validate_pcr_selection([pcr, 7])


def test_pcr_values_are_normalised_to_lowercase():
    assert nitrotpm.validate_pcr_value(7, "ABCD") == "abcd"


@pytest.mark.parametrize("bad", ["", "abc", "zz", "ab" * 97])
def test_malformed_pcr_values_are_refused(bad):
    with pytest.raises(nitrotpm.NitroTpmError):
        nitrotpm.validate_pcr_value(7, bad)


def test_selected_pcr_missing_from_the_registry_is_refused():
    """Better to fail than to quietly pin fewer registers than asked for."""
    with pytest.raises(nitrotpm.NitroTpmError, match="no value for it"):
        nitrotpm.pcr_conditions({"7": PCR7}, pcrs=(4, 7))


def test_condition_key_naming():
    assert nitrotpm.condition_key(7) == "kms:RecipientAttestation:NitroTPMPCR7"
    assert nitrotpm.condition_key(4) == "kms:RecipientAttestation:NitroTPMPCR4"


# --------------------------------------------------------------------------
# Key policy shape
# --------------------------------------------------------------------------

def _statements(policy):
    return {s["Sid"]: s for s in policy["Statement"]}


def test_without_pcrs_the_policy_keeps_one_identity_statement():
    stmts = _statements(pin_statement({}, ROLE, ACCOUNT))
    assert set(stmts) == {DECRYPT_SID}
    cond = stmts[DECRYPT_SID]["Condition"]
    assert "StringEqualsIgnoreCase" not in cond
    assert cond["ArnEquals"] == {"aws:PrincipalArn": ROLE}


def test_pinning_pcrs_adds_the_conditions_and_keeps_the_arn_check():
    """Both, not either: the ARN check stops any *other* attested instance in
    the account from decrypting."""
    stmts = _statements(pin_statement({}, ROLE, ACCOUNT, pcr_values=PCRS))
    cond = stmts[DECRYPT_SID]["Condition"]
    assert cond["StringEqualsIgnoreCase"] == {
        "kms:RecipientAttestation:NitroTPMPCR4": PCR4,
        "kms:RecipientAttestation:NitroTPMPCR7": PCR7,
    }
    assert cond["ArnEquals"] == {"aws:PrincipalArn": ROLE}
    assert cond["StringEquals"] == {"kms:CallerAccount": ACCOUNT}


def test_describekey_is_split_out_of_the_attested_statement():
    """DescribeKey has no Recipient parameter, so it can never present an
    attestation document. Left in the attested statement, KMS would deny it."""
    stmts = _statements(pin_statement({}, ROLE, ACCOUNT, pcr_values=PCRS))
    assert stmts[DECRYPT_SID]["Action"] == ["kms:Decrypt"]
    assert stmts[DESCRIBE_SID]["Action"] == ["kms:DescribeKey"]
    assert "StringEqualsIgnoreCase" not in stmts[DESCRIBE_SID]["Condition"]


def test_pinning_then_unpinning_removes_the_describe_statement():
    """Rewrites must not leave an orphan statement behind."""
    pinned = pin_statement({}, ROLE, ACCOUNT, pcr_values=PCRS)
    assert DESCRIBE_SID in _statements(pinned)
    unpinned = pin_statement(pinned, ROLE, ACCOUNT)
    assert set(_statements(unpinned)) == {DECRYPT_SID}


def test_operator_statements_survive_a_rewrite():
    existing = {"Version": "2012-10-17", "Statement": [
        {"Sid": "OperatorAdmin", "Effect": "Allow", "Action": "kms:*"},
    ]}
    out = pin_statement(existing, ROLE, ACCOUNT, pcr_values=PCRS)
    assert "OperatorAdmin" in _statements(out)


def test_pcr_values_in_the_policy_are_lowercased():
    stmts = _statements(pin_statement(
        {}, ROLE, ACCOUNT, pcr_values={"4": PCR4.upper(), "7": PCR7.upper()}))
    values = stmts[DECRYPT_SID]["Condition"]["StringEqualsIgnoreCase"].values()
    assert all(v == v.lower() for v in values)


# --------------------------------------------------------------------------
# Producing the document
# --------------------------------------------------------------------------

class _Completed:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_attestation_document_passes_the_public_key_as_a_file():
    """The DER public key is binary, so it cannot travel in argv."""
    seen = {}

    def runner(argv, **kwargs):
        seen["argv"] = argv
        idx = argv.index("--public-key")
        with open(argv[idx + 1], "rb") as handle:
            seen["key"] = handle.read()
        return _Completed(stdout=b"\xd2\x84document")

    doc = nitrotpm.attestation_document(b"DERKEY", runner=runner)
    assert doc == b"\xd2\x84document"
    assert seen["key"] == b"DERKEY"


def test_attestation_document_refuses_without_a_public_key():
    """No public key means KMS returns Plaintext, not CiphertextForRecipient."""
    with pytest.raises(nitrotpm.NitroTpmError, match="recipient public key"):
        nitrotpm.attestation_document(b"", runner=lambda *a, **k: _Completed())


def test_missing_binary_explains_the_tpmsupport_trap():
    def runner(*args, **kwargs):
        raise FileNotFoundError

    with pytest.raises(nitrotpm.NitroTpmError, match="TpmSupport"):
        nitrotpm.attestation_document(b"DER", runner=runner)


def test_nonzero_exit_surfaces_stderr():
    def runner(*args, **kwargs):
        return _Completed(returncode=3, stderr=b"tpm2 device busy")

    with pytest.raises(nitrotpm.NitroTpmError, match="tpm2 device busy"):
        nitrotpm.attestation_document(b"DER", runner=runner)


def test_empty_document_on_success_is_still_a_failure():
    def runner(*args, **kwargs):
        return _Completed(returncode=0, stdout=b"")

    with pytest.raises(nitrotpm.NitroTpmError, match="no document"):
        nitrotpm.attestation_document(b"DER", runner=runner)


def test_timeout_is_reported_as_a_nitrotpm_error():
    def runner(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nitro-tpm-attest", timeout=30)

    with pytest.raises(nitrotpm.NitroTpmError, match="did not return"):
        nitrotpm.attestation_document(b"DER", runner=runner)


def test_kms_unused_fields_are_omitted_when_not_supplied():
    """AWS documents nonce and user-data as 'Not used for attestation with AWS
    KMS', so the KMS path should not pass them and imply a binding."""
    seen = {}

    def runner(argv, **kwargs):
        seen["argv"] = argv
        return _Completed(stdout=b"doc")

    nitrotpm.attestation_document(b"DER", runner=runner)
    assert "--nonce" not in seen["argv"]
    assert "--user-data" not in seen["argv"]


def test_recipient_keypair_is_rsa():
    """nitro-tpm-attest documents '--public-key': only RSA keys are supported."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key, public_der = nitrotpm.generate_recipient_keypair()
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert public_der[:1] == b"\x30"  # DER SEQUENCE


# --------------------------------------------------------------------------
# The adapter
# --------------------------------------------------------------------------

class _FakeKms:
    def __init__(self, response):
        self.response, self.request = response, None

    def decrypt(self, **kwargs):
        self.request = kwargs
        return self.response


def _key_ref(unwrap, **extra):
    from tee_crafter.core.keys.spec import AttestedKeyRef
    import base64
    return AttestedKeyRef(
        provider=KeyProvider.AWS_KMS,
        key_id="arn:aws:kms:us-east-2:950771918023:key/abc",
        unwrap=unwrap,
        extra={"ciphertext_b64": base64.b64encode(b"wrapped").decode(),
               "tee_platform": "snp-aws", **extra},
    )


def _policy():
    from tee_crafter.core.keys.spec import KeyReleasePolicy
    return KeyReleasePolicy(allow_any_measurement=True)


def test_nitrotpm_unwrap_attaches_the_recipient_envelope():
    from tee_crafter.core.keys.aws_kms import AwsKmsAdapter

    kms = _FakeKms({"CiphertextForRecipient": b"cms", "KeyId": "abc"})
    material = AwsKmsAdapter(kms_client=kms).release(
        key_ref=_key_ref(UnwrapAlgorithm.AWS_NITROTPM_RECIPIENT,
                         **{FACT_NITROTPM_PCRS_PINNED: "true"}),
        attestation=b"cbor-doc", policy=_policy())

    assert kms.request["Recipient"] == {
        "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
        "AttestationDocument": b"cbor-doc",
    }
    assert material.plaintext is None
    assert material.wrapped_for_recipient == b"cms"
    assert material.gating is KeyGating.KMS_ENFORCED


def test_nitrotpm_unwrap_without_a_document_is_refused():
    """Attaching nothing would either be denied by KMS or, on a key without the
    condition, silently return plaintext. Neither is an attested release."""
    from tee_crafter.core.keys.aws_kms import AwsKmsAdapter
    from tee_crafter.core.keys.spec import KeyReleaseError

    kms = _FakeKms({"Plaintext": b"secret"})
    with pytest.raises(KeyReleaseError, match="requires an attestation document"):
        AwsKmsAdapter(kms_client=kms).release(
            key_ref=_key_ref(UnwrapAlgorithm.AWS_NITROTPM_RECIPIENT),
            attestation=b"", policy=_policy())


def test_missing_ciphertext_for_recipient_is_not_read_as_plaintext():
    from tee_crafter.core.keys.aws_kms import AwsKmsAdapter
    from tee_crafter.core.keys.spec import KeyReleaseError

    kms = _FakeKms({"Plaintext": b"secret"})
    with pytest.raises(KeyReleaseError, match="CiphertextForRecipient"):
        AwsKmsAdapter(kms_client=kms).release(
            key_ref=_key_ref(UnwrapAlgorithm.AWS_NITROTPM_RECIPIENT),
            attestation=b"doc", policy=_policy())


def test_plain_decrypt_stays_iam_scoped_even_if_the_fact_is_set():
    """A recorded fact must never upgrade a release that attached no document."""
    from tee_crafter.core.keys.aws_kms import AwsKmsAdapter

    kms = _FakeKms({"Plaintext": b"secret", "KeyId": "abc"})
    material = AwsKmsAdapter(kms_client=kms).release(
        key_ref=_key_ref(UnwrapAlgorithm.DIRECT_BYTES,
                         **{FACT_NITROTPM_PCRS_PINNED: "true"}),
        attestation=b"doc", policy=_policy())

    assert "Recipient" not in kms.request
    assert material.gating is KeyGating.IAM_SCOPED
