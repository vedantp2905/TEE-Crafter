"""Unit tests for tee_crafter.core.keys (BYOK / attestation-gated release)."""
from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Dict

import pytest

from tee_crafter.core.keys import (
    AttestedKeyMaterial, AttestedKeyRef, AttestationProvider,
    KeyGating, KeyProvider, KeyReleaseError, KeyReleaseOrchestrator,
    KeyReleasePolicy, KmsAdapter,
)
from tee_crafter.core.keys.gating import gating_for, gating_table
from tee_crafter.core.keys.spec import UnwrapAlgorithm
from tee_crafter.core.keys.aws_kms import AwsKmsAdapter
from tee_crafter.core.keys.azure_kv import AzureKeyVaultAdapter
from tee_crafter.core.keys.gcp_kms import GcpKmsAdapter, canonical_aad
from tee_crafter.core.keys.external_hsm import ExternalHsmAdapter


#: Every orchestrator test needs a policy that passes ``validate()``.  Since
#: FIX 3 an empty ``allowed_measurement_sha256`` is a hard error, so tests that
#: do not care about the allowlist opt out explicitly — which is exactly the
#: behaviour we want callers to have to spell out.
def _policy(**kw) -> KeyReleasePolicy:
    kw.setdefault("allow_any_measurement", True)
    return KeyReleasePolicy(**kw)


# ---------- Stub attestation provider ----------

class StubAttestation(AttestationProvider):
    def __init__(self, *, blob: bytes = b"FAKE_QUOTE",
                 measurement: str = "a" * 64,
                 issued_at_offset: float = 0.0):
        self.blob = blob
        self.measurement = measurement
        self.issued_at_offset = issued_at_offset
        self.calls = []

    def fresh(self, *, purpose, nonce=b""):
        self.calls.append((purpose, nonce))
        return self.blob, time.time() + self.issued_at_offset, self.measurement


class RecordingAudit:
    """Minimal audit sink.

    ``KeyReleasePolicy.require_signed_audit`` defaults to True and the
    orchestrator now refuses to be built without somewhere to record, so every
    orchestrator test needs one of these (or an explicit opt-out).
    """

    def __init__(self, *, raises: BaseException | None = None):
        self.events: list[tuple[str, dict]] = []
        self._raises = raises

    def record(self, phase, step, status, **kwargs):
        if self._raises is not None:
            raise self._raises
        self.events.append((status, kwargs))


class StubAdapter(KmsAdapter):
    provider = KeyProvider.LOCAL_FILE

    def __init__(self, *, plaintext: bytes = b"DEK-32-bytes----DEK-32-bytes----"):
        self.plaintext = plaintext
        self.last_call = None

    def release(self, *, key_ref, attestation, policy, encryption_context=None):
        self.last_call = {
            "key_ref": key_ref, "attestation": attestation,
            "policy": policy, "encryption_context": dict(encryption_context or {}),
        }
        return AttestedKeyMaterial(
            key_ref=key_ref, plaintext=self.plaintext,
            wrapped_for_recipient=None,
            unwrap_algorithm=UnwrapAlgorithm.DIRECT_BYTES,
            released_at=0.0, attestation_sha256="", attestation_age_seconds=0.0,
            audit_id="", provider_response_metadata={"adapter": "stub"},
        )


# ---------- KeyReleasePolicy ----------

class TestKeyReleasePolicy:
    def test_validate_accepts_pinned_measurement(self):
        assert KeyReleasePolicy(allowed_measurement_sha256=["a" * 64]).validate() == []

    def test_empty_allowlist_is_a_hard_failure(self):
        """The shipped default must not silently disable the measurement gate."""
        errs = KeyReleasePolicy().validate()
        assert any("allowed_measurement_sha256 is empty" in e for e in errs)

    def test_empty_allowlist_can_be_opted_out_in_code(self):
        assert KeyReleasePolicy(allow_any_measurement=True).validate() == []

    def test_empty_allowlist_can_be_opted_out_by_env(self, monkeypatch):
        monkeypatch.setenv("TEE_CRAFTER_BYOK_ALLOW_ANY_MEASUREMENT", "1")
        assert KeyReleasePolicy().validate() == []

    def test_validate_rejects_short_measurement(self):
        p = KeyReleasePolicy(allowed_measurement_sha256=["short"])
        errs = p.validate()
        assert any("not a 64-hex" in e for e in errs)

    def test_validate_rejects_zero_age(self):
        errs = _policy(max_attestation_age_seconds=0).validate()
        assert any("max_attestation_age_seconds" in e for e in errs)


# ---------- KeyReleaseOrchestrator ----------

class TestOrchestrator:
    def _make(self, **kw):
        attest = kw.pop("attest", StubAttestation())
        adapter = kw.pop("adapter", StubAdapter())
        policy = kw.pop("policy", _policy())
        kw.setdefault("audit", RecordingAudit())
        return KeyReleaseOrchestrator(
            attestation_provider=attest,
            adapters={KeyProvider.LOCAL_FILE: adapter},
            policy=policy,
            **kw,
        ), adapter, attest

    def test_release_happy_path(self):
        orch, adapter, attest = self._make()
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k-1",
                              label="dev")
        m = orch.release(ref, encryption_context={"app": "etl"})
        assert m.plaintext == adapter.plaintext
        assert m.attestation_sha256 == hashlib.sha256(b"FAKE_QUOTE").hexdigest()
        assert m.audit_id != ""
        assert adapter.last_call["encryption_context"] == {"app": "etl"}
        assert len(attest.calls) == 1

    def test_release_unknown_provider(self):
        orch, _, _ = self._make()
        ref = AttestedKeyRef(provider=KeyProvider.AWS_KMS, key_id="k")
        with pytest.raises(KeyReleaseError, match="No adapter"):
            orch.release(ref)

    def test_release_required_provider_mismatch(self):
        policy = _policy(required_provider=KeyProvider.AWS_KMS)
        orch = KeyReleaseOrchestrator(
            attestation_provider=StubAttestation(),
            adapters={KeyProvider.LOCAL_FILE: StubAdapter(),
                      KeyProvider.AWS_KMS: StubAdapter()},
            policy=policy,
            audit=RecordingAudit(),
        )
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k")
        with pytest.raises(KeyReleaseError, match="Policy fixes provider"):
            orch.release(ref)

    def test_release_attestation_too_old(self):
        attest = StubAttestation(issued_at_offset=-1000.0)
        orch, _, _ = self._make(attest=attest,
                                  policy=_policy(max_attestation_age_seconds=60))
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k")
        with pytest.raises(KeyReleaseError, match="old"):
            orch.release(ref)

    def test_release_measurement_allowlist(self):
        attest = StubAttestation(measurement="b" * 64)
        policy = KeyReleasePolicy(allowed_measurement_sha256=["a" * 64])
        orch, _, _ = self._make(attest=attest, policy=policy)
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k")
        with pytest.raises(KeyReleaseError, match="not in the policy allowlist"):
            orch.release(ref)

    def test_release_enforces_required_encryption_context(self):
        policy = _policy(require_encryption_context_keys=["tenant"])
        orch, _, _ = self._make(policy=policy)
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k")
        with pytest.raises(KeyReleaseError, match="encryption context"):
            orch.release(ref, encryption_context={"app": "etl"})

    def test_attestation_provider_failure_is_release_error(self):
        class Boom(AttestationProvider):
            def fresh(self, *, purpose, nonce=b""):
                raise RuntimeError("platform busy")
        orch = KeyReleaseOrchestrator(
            attestation_provider=Boom(),
            adapters={KeyProvider.LOCAL_FILE: StubAdapter()},
            policy=_policy(),
            audit=RecordingAudit(),
        )
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k")
        with pytest.raises(KeyReleaseError, match="attestation provider failed"):
            orch.release(ref)

    def test_audit_records_pass_and_fail(self):
        events = []

        class FakeAudit:
            def record(self, phase, step, status, **kwargs):
                events.append((status, kwargs.get("error", "")))

        orch = KeyReleaseOrchestrator(
            attestation_provider=StubAttestation(),
            adapters={KeyProvider.LOCAL_FILE: StubAdapter()},
            policy=KeyReleasePolicy(allowed_measurement_sha256=["c" * 64]),
            audit=FakeAudit(),
        )
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k")
        with pytest.raises(KeyReleaseError):
            orch.release(ref)
        assert events and events[0][0] == "fail"

    # ---- require_signed_audit is enforced, not decorative (B6) ----

    def test_require_signed_audit_refuses_orchestrator_without_sink(self):
        """The default policy cannot be built with nowhere to record."""
        policy = _policy()
        assert policy.require_signed_audit is True
        with pytest.raises(ValueError, match="require_signed_audit"):
            KeyReleaseOrchestrator(
                attestation_provider=StubAttestation(),
                adapters={KeyProvider.LOCAL_FILE: StubAdapter()},
                policy=policy,
            )

    def test_require_signed_audit_off_allows_no_sink(self):
        """Opting out explicitly is still allowed — that is the escape hatch."""
        orch = KeyReleaseOrchestrator(
            attestation_provider=StubAttestation(),
            adapters={KeyProvider.LOCAL_FILE: StubAdapter()},
            policy=_policy(require_signed_audit=False),
        )
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k")
        assert orch.release(ref).plaintext is not None

    def test_require_signed_audit_fails_closed_when_sink_rejects(self):
        """A release whose audit entry did not land must not hand out material."""
        audit = RecordingAudit(raises=RuntimeError("ledger is read-only"))
        orch, _, _ = self._make(audit=audit)
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k")
        with pytest.raises(KeyReleaseError, match="signed audit"):
            orch.release(ref)

    def test_audit_sink_failure_is_tolerated_when_policy_is_off(self):
        """Without the policy, a broken sink must not wedge the workload."""
        audit = RecordingAudit(raises=RuntimeError("ledger is read-only"))
        orch, adapter, _ = self._make(
            policy=_policy(require_signed_audit=False), audit=audit)
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k")
        assert orch.release(ref).plaintext == adapter.plaintext

    def test_orchestrator_rejects_invalid_policy(self):
        with pytest.raises(ValueError):
            KeyReleaseOrchestrator(
                attestation_provider=StubAttestation(),
                adapters={KeyProvider.LOCAL_FILE: StubAdapter()},
                policy=_policy(max_attestation_age_seconds=0),
                audit=RecordingAudit())

    def test_material_signature_is_stable(self):
        orch, _, _ = self._make()
        ref = AttestedKeyRef(provider=KeyProvider.LOCAL_FILE, key_id="k", region="us")
        m = orch.release(ref)
        sig1 = orch.material_signature(m)
        sig2 = orch.material_signature(m)
        assert sig1 == sig2 and len(sig1) == 16


# ---------- AWS KMS adapter ----------

class FakeKmsClient:
    def __init__(self, *, response: Dict[str, Any], should_raise: bool = False):
        self.response = response
        self.should_raise = should_raise
        self.last_request = None

    def decrypt(self, **kwargs):
        self.last_request = kwargs
        if self.should_raise:
            raise RuntimeError("AccessDenied")
        return self.response


class TestAwsKmsAdapter:
    def test_direct_bytes_path(self):
        client = FakeKmsClient(response={
            "Plaintext": b"my-dek-32-bytes----my-dek-32-byt",
            "KeyId": "arn:aws:kms:us-east-2:111:key/xxx",
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            "ResponseMetadata": {"RequestId": "rid-1"},
        })
        adapter = AwsKmsAdapter(kms_client=client)
        ref = AttestedKeyRef(
            provider=KeyProvider.AWS_KMS, key_id="arn:aws:kms:us-east-2:111:key/xxx",
            unwrap=UnwrapAlgorithm.DIRECT_BYTES,
            extra={"ciphertext_b64": base64.b64encode(b"CIPHERTEXT").decode()})
        m = adapter.release(key_ref=ref, attestation=b"QUOTE",
                             policy=KeyReleasePolicy(),
                             encryption_context={"app": "etl"})
        assert m.plaintext == b"my-dek-32-bytes----my-dek-32-byt"
        assert m.unwrap_algorithm == UnwrapAlgorithm.DIRECT_BYTES
        assert client.last_request["EncryptionContext"] == {"app": "etl"}
        assert "Recipient" not in client.last_request

    def test_nitro_recipient_path(self):
        client = FakeKmsClient(response={
            "CiphertextForRecipient": b"WRAPPED-FOR-ENCLAVE",
            "KeyId": "arn:aws:kms:us-east-2:111:key/yyy",
        })
        adapter = AwsKmsAdapter(kms_client=client)
        ref = AttestedKeyRef(
            provider=KeyProvider.AWS_KMS, key_id="arn:aws:kms:us-east-2:111:key/yyy",
            unwrap=UnwrapAlgorithm.AWS_NITRO_RECIPIENT,
            extra={"ciphertext_b64": base64.b64encode(b"CIPHERTEXT").decode()})
        m = adapter.release(key_ref=ref, attestation=b"NITRO_PKCS7",
                             policy=KeyReleasePolicy())
        assert m.plaintext is None
        assert m.wrapped_for_recipient == b"WRAPPED-FOR-ENCLAVE"
        assert m.unwrap_algorithm == UnwrapAlgorithm.AWS_NITRO_RECIPIENT
        recipient = client.last_request["Recipient"]
        assert recipient["AttestationDocument"] == b"NITRO_PKCS7"
        assert recipient["KeyEncryptionAlgorithm"] == "RSAES_OAEP_SHA_256"

    def test_missing_ciphertext_raises(self):
        adapter = AwsKmsAdapter(kms_client=FakeKmsClient(response={}))
        ref = AttestedKeyRef(provider=KeyProvider.AWS_KMS, key_id="arn:...")
        with pytest.raises(KeyReleaseError, match="ciphertext_b64"):
            adapter.release(key_ref=ref, attestation=b"q",
                             policy=KeyReleasePolicy())

    def test_kms_failure_wrapped(self):
        client = FakeKmsClient(response={}, should_raise=True)
        adapter = AwsKmsAdapter(kms_client=client)
        ref = AttestedKeyRef(
            provider=KeyProvider.AWS_KMS, key_id="arn",
            extra={"ciphertext_b64": base64.b64encode(b"x").decode()})
        with pytest.raises(KeyReleaseError, match="kms:Decrypt failed"):
            adapter.release(key_ref=ref, attestation=b"q",
                             policy=KeyReleasePolicy())

    def test_wrong_provider_rejected(self):
        adapter = AwsKmsAdapter(kms_client=FakeKmsClient(response={}))
        ref = AttestedKeyRef(provider=KeyProvider.GCP_KMS, key_id="g",
                              extra={"ciphertext_b64": "AA=="})
        with pytest.raises(KeyReleaseError, match="cannot release"):
            adapter.release(key_ref=ref, attestation=b"q",
                             policy=KeyReleasePolicy())


# ---------- Azure Key Vault adapter ----------

def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


#: A released-key envelope shaped like the one in Microsoft's own REST
#: reference sample for ``KeyReleaseResult.value``.  Built here by hand rather
#: than by calling anything in the adapter: the previous version of this test
#: fed the adapter base64 of ``b"WRAPPED-DEK"`` -- which is not an Azure
#: envelope at all -- and then asserted the adapter handed those same bytes
#: back.  It therefore passed while the adapter was returning the JSON envelope
#: as if it were wrapped key material, and no unwrap could ever have worked.
#: https://learn.microsoft.com/en-us/rest/api/keyvault/keys/release/release
_KEY_HSM_BYTES = b"\x01\x02\x03wrapped-aes-then-kwp\xff"


def _key_hsm_envelope(wrapped: bytes) -> str:
    """``key_hsm`` in the shape Managed HSM actually returns.

    Base64 of a JSON document, not of the ciphertext:
    ``{"schema_version", "header": {"kid", "alg", "enc"}, "ciphertext"}``.
    Taken from Microsoft's "Key Release Response" sample --
    https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp
    -- after this fixture spent its life asserting the wrong shape, which is
    exactly the sort of thing an invented fixture cannot notice.
    """
    return _b64u(json.dumps({
        "schema_version": "1.0",
        "header": {"kid": "TpmEphemeralEncryptionKey", "alg": "dir",
                   "enc": "CKM_RSA_AES_KEY_WRAP"},
        "ciphertext": _b64u(wrapped),
    }).encode())


def _release_envelope(*, kid: str, key_hsm: bytes = _KEY_HSM_BYTES) -> dict:
    return {
        "attributes": {"created": 1587425174, "enabled": True,
                       "exportable": True},
        "key": {
            "kty": "oct-HSM",
            "key_ops": ["decrypt", "encrypt"],
            "kid": kid,
            "key_hsm": _key_hsm_envelope(key_hsm),
        },
        "release_policy": {
            "contentType": "application/json; charset=utf-8; version=1.0",
            "data": _b64u(b"{}"),
        },
    }


def _bare_value(envelope: dict) -> str:
    """``value`` as the REST sample shows it: base64url of the JSON."""
    return _b64u(json.dumps(envelope).encode())


def _jws_value(envelope: dict) -> str:
    """``value`` as Managed HSM actually returns it: a 3-segment JWS."""
    return ".".join([_b64u(b'{"alg":"RS256"}'), _b64u(json.dumps(envelope).encode()),
                     _b64u(b"not-a-real-signature")])


class TestAzureKeyVaultAdapter:
    KID = "https://mhsm-foo.managedhsm.azure.net/keys/k/v1"

    def _adapter_and_ref(self, value, captured=None):
        def fake_http(method, url, headers, body):
            if captured is not None:
                captured.update(method=method, url=url, headers=headers, body=body)
            return {"value": value}
        return (AzureKeyVaultAdapter(http=fake_http),
                AttestedKeyRef(provider=KeyProvider.AZURE_KEY_VAULT,
                               key_id=self.KID))

    def test_release_extracts_key_hsm_not_the_envelope(self):
        captured = {}
        adapter, ref = self._adapter_and_ref(
            _bare_value(_release_envelope(kid=self.KID)), captured)
        m = adapter.release(key_ref=ref, attestation=b"jwt-token",
                             policy=KeyReleasePolicy(),
                             encryption_context={"nonce": "abcd"})
        # The wrapped material is key.key_hsm, decoded one level further in.
        assert m.wrapped_for_recipient == _KEY_HSM_BYTES
        assert m.unwrap_algorithm == UnwrapAlgorithm.CKM_RSA_AES_KEY_WRAP
        assert captured["body"]["target"] == "jwt-token"
        assert captured["body"]["nonce"] == "abcd"
        assert captured["body"]["enc"] == "CKM_RSA_AES_KEY_WRAP"
        assert "/release?api-version=" in captured["url"]

    def test_release_accepts_the_jws_shape_managed_hsm_returns(self):
        adapter, ref = self._adapter_and_ref(
            _jws_value(_release_envelope(kid=self.KID)))
        m = adapter.release(key_ref=ref, attestation=b"jwt",
                             policy=KeyReleasePolicy())
        assert m.wrapped_for_recipient == _KEY_HSM_BYTES

    def test_kid_comes_from_the_envelope_not_the_request(self):
        """A version mismatch between request and release must be visible."""
        other = "https://mhsm-foo.managedhsm.azure.net/keys/k/DIFFERENT"
        adapter, ref = self._adapter_and_ref(
            _bare_value(_release_envelope(kid=other)))
        m = adapter.release(key_ref=ref, attestation=b"jwt",
                             policy=KeyReleasePolicy())
        meta = m.provider_response_metadata
        assert meta["kid"] == other
        assert meta["kid_matches_request"] is False

    def test_plaintext_is_none_without_a_recipient_key(self):
        """Guards the fail-closed default, not a gap.

        The unwrap exists now, but only runs when the caller supplies
        ``recipient_private_key``. Constructed without one -- which is how the
        runtime bootstrap still builds it on Azure, because the key-encryption
        key is held by the vTPM and not by us -- ``release`` must return no
        plaintext so the bootstrap refuses rather than staging an empty DEK.
        """
        adapter, ref = self._adapter_and_ref(
            _bare_value(_release_envelope(kid=self.KID)))
        m = adapter.release(key_ref=ref, attestation=b"jwt",
                             policy=KeyReleasePolicy())
        assert m.plaintext is None

    def test_envelope_without_key_object_is_an_error(self):
        adapter, ref = self._adapter_and_ref(_bare_value({"attributes": {}}))
        with pytest.raises(KeyReleaseError, match="no `key` object"):
            adapter.release(key_ref=ref, attestation=b"x",
                            policy=KeyReleasePolicy())

    def test_envelope_without_key_hsm_is_an_error(self):
        env = _release_envelope(kid=self.KID)
        del env["key"]["key_hsm"]
        adapter, ref = self._adapter_and_ref(_bare_value(env))
        with pytest.raises(KeyReleaseError, match="no `key.key_hsm`"):
            adapter.release(key_ref=ref, attestation=b"x",
                            policy=KeyReleasePolicy())

    def test_value_that_is_not_json_is_an_error(self):
        adapter, ref = self._adapter_and_ref(_b64u(b"definitely not json"))
        with pytest.raises(KeyReleaseError, match="did not decode to JSON"):
            adapter.release(key_ref=ref, attestation=b"x",
                            policy=KeyReleasePolicy())

    def test_value_with_an_unexpected_segment_count_is_an_error(self):
        adapter, ref = self._adapter_and_ref("a.b")
        with pytest.raises(KeyReleaseError, match="dot-separated segments"):
            adapter.release(key_ref=ref, attestation=b"x",
                            policy=KeyReleasePolicy())

    def test_invalid_key_id(self):
        adapter = AzureKeyVaultAdapter(http=lambda *a, **k: {})
        ref = AttestedKeyRef(provider=KeyProvider.AZURE_KEY_VAULT, key_id="not-a-url")
        with pytest.raises(KeyReleaseError, match="full Key Vault key URL"):
            adapter.release(key_ref=ref, attestation=b"x", policy=KeyReleasePolicy())

    def test_missing_value_field(self):
        adapter = AzureKeyVaultAdapter(http=lambda *a, **k: {"kid": "k"})
        ref = AttestedKeyRef(
            provider=KeyProvider.AZURE_KEY_VAULT,
            key_id="https://mhsm.x.azure.net/keys/k/v")
        with pytest.raises(KeyReleaseError, match="`value` field"):
            adapter.release(key_ref=ref, attestation=b"x", policy=KeyReleasePolicy())


# ---------- GCP KMS adapter ----------

class FakeCloudKms:
    """Cloud-KMS-shaped AEAD that enforces AAD byte-equality, like the real one.

    The point of this stub is that it does NOT trust either side's opinion of
    what the AAD should be: it stores whatever ``encrypt`` was given and
    compares raw bytes on ``decrypt``.  Two mocks agreeing with each other is
    what let the wrap/unwrap mismatch ship in the first place.
    """

    def __init__(self):
        self._store: Dict[bytes, tuple] = {}
        self.last_decrypt_request: Dict[str, Any] = {}

    def encrypt(self, *, name: str, plaintext: bytes, aad: bytes) -> bytes:
        ciphertext = b"CT:" + hashlib.sha256(name.encode() + aad).digest()[:8] \
            + b":" + base64.b64encode(plaintext)
        self._store[ciphertext] = (name, aad, plaintext)
        return ciphertext

    def decrypt(self, req: Dict[str, Any]) -> Dict[str, Any]:
        self.last_decrypt_request = dict(req)
        entry = self._store.get(req["ciphertext"])
        if entry is None:
            raise RuntimeError("unknown ciphertext")
        name, aad, plaintext = entry
        if req["name"] != name:
            raise RuntimeError("wrong key name")
        # This is the check the real Cloud KMS makes, and the one that made
        # `--byok gcp-kms` impossible when the wrap side passed no AAD and the
        # unwrap side passed a fresh attestation report.
        if req.get("additional_authenticated_data", b"") != aad:
            raise RuntimeError(
                "Decryption failed: the additional authenticated data provided "
                "does not match the data used during encryption")
        return {"plaintext": plaintext, "name": name}


def _wrap_dek_like_the_sandbox(kms: FakeCloudKms, *, key_id: str,
                               dek: bytes, enc_ctx: Dict[str, str]) -> str:
    """Mirror ``byok-sandbox/gcp/wrap_dek.py``: canonical AAD, base64 output."""
    aad = canonical_aad(enc_ctx)
    return base64.b64encode(
        kms.encrypt(name=key_id, plaintext=dek, aad=aad)).decode("ascii")


_GCP_KEY = "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"


class TestGcpKmsAdapter:
    @pytest.mark.parametrize("enc_ctx", [
        {},
        {"app": "etl"},
        {"tenant": "acme", "app": "etl"},  # order must not matter
    ])
    def test_wrap_unwrap_round_trip(self, enc_ctx):
        """Wrap with the sandbox helper, unwrap with the adapter, for real.

        Not two mocks agreeing: ``FakeCloudKms`` enforces AAD equality, so any
        divergence between the wrap and unwrap AAD fails here.
        """
        kms = FakeCloudKms()
        dek = b"DEK-32-bytes----DEK-32-bytes----"
        ct_b64 = _wrap_dek_like_the_sandbox(
            kms, key_id=_GCP_KEY, dek=dek, enc_ctx=enc_ctx)

        adapter = GcpKmsAdapter(decrypt=kms.decrypt)
        ref = AttestedKeyRef(provider=KeyProvider.GCP_KMS, key_id=_GCP_KEY,
                              extra={"ciphertext_b64": ct_b64})
        m = adapter.release(key_ref=ref, attestation=b"FRESH_SNP_REPORT",
                             policy=_policy(),
                             encryption_context=enc_ctx or None)
        assert m.plaintext == dek

    def test_attestation_is_not_the_aad(self):
        """Regression guard for the shipped bug.

        Using the attestation blob as AAD cannot work — it is regenerated every
        boot, so the wrap side can never have known it.
        """
        kms = FakeCloudKms()
        ct_b64 = _wrap_dek_like_the_sandbox(
            kms, key_id=_GCP_KEY, dek=b"d" * 32, enc_ctx={"app": "etl"})
        adapter = GcpKmsAdapter(decrypt=kms.decrypt)
        ref = AttestedKeyRef(provider=KeyProvider.GCP_KMS, key_id=_GCP_KEY,
                              extra={"ciphertext_b64": ct_b64})
        adapter.release(key_ref=ref, attestation=b"FRESH_SNP_REPORT",
                         policy=_policy(), encryption_context={"app": "etl"})
        sent = kms.last_decrypt_request["additional_authenticated_data"]
        assert sent != b"FRESH_SNP_REPORT"
        assert sent == canonical_aad({"app": "etl"})

    def test_mismatched_encryption_context_fails_closed(self):
        kms = FakeCloudKms()
        ct_b64 = _wrap_dek_like_the_sandbox(
            kms, key_id=_GCP_KEY, dek=b"d" * 32, enc_ctx={"tenant": "acme"})
        adapter = GcpKmsAdapter(decrypt=kms.decrypt)
        ref = AttestedKeyRef(provider=KeyProvider.GCP_KMS, key_id=_GCP_KEY,
                              extra={"ciphertext_b64": ct_b64})
        with pytest.raises(KeyReleaseError, match="Decrypt failed"):
            adapter.release(key_ref=ref, attestation=b"q", policy=_policy(),
                             encryption_context={"tenant": "evil"})

    def test_canonical_aad_is_order_independent_and_empty_safe(self):
        assert canonical_aad(None) == b""
        assert canonical_aad({}) == b""
        assert canonical_aad({"b": "2", "a": "1"}) == b'{"a":"1","b":"2"}'
        assert canonical_aad({"a": "1", "b": "2"}) == canonical_aad({"b": "2", "a": "1"})

    def test_no_plaintext_in_response(self):
        adapter = GcpKmsAdapter(decrypt=lambda req: {"plaintext": b""})
        ref = AttestedKeyRef(
            provider=KeyProvider.GCP_KMS, key_id="projects/p/...",
            extra={"ciphertext_b64": base64.b64encode(b"x").decode()})
        with pytest.raises(KeyReleaseError, match="no plaintext"):
            adapter.release(key_ref=ref, attestation=b"q",
                             policy=_policy())

    def test_reports_iam_scoped_by_default(self):
        kms = FakeCloudKms()
        ct_b64 = _wrap_dek_like_the_sandbox(
            kms, key_id=_GCP_KEY, dek=b"d" * 32, enc_ctx={})
        adapter = GcpKmsAdapter(decrypt=kms.decrypt)
        ref = AttestedKeyRef(provider=KeyProvider.GCP_KMS, key_id=_GCP_KEY,
                              extra={"ciphertext_b64": ct_b64,
                                     "tee_platform": "snp-gcp"})
        m = adapter.release(key_ref=ref, attestation=b"q", policy=_policy())
        assert m.gating is KeyGating.IAM_SCOPED
        assert m.measurement_gate == "advisory"

    def test_attribute_condition_upgrades_to_kms_enforced(self):
        kms = FakeCloudKms()
        ct_b64 = _wrap_dek_like_the_sandbox(
            kms, key_id=_GCP_KEY, dek=b"d" * 32, enc_ctx={})
        adapter = GcpKmsAdapter(decrypt=kms.decrypt)
        ref = AttestedKeyRef(provider=KeyProvider.GCP_KMS, key_id=_GCP_KEY,
                              extra={"ciphertext_b64": ct_b64,
                                     "tee_platform": "snp-gcp",
                                     "attribute_condition_bound": "1"})
        m = adapter.release(key_ref=ref, attestation=b"q", policy=_policy())
        assert m.gating is KeyGating.KMS_ENFORCED
        assert m.measurement_gate == "policy-enforced"


class TestGcpKmsAadInterop:
    """The sandbox wrap tool carries its own copy of the canonicaliser."""

    def test_sandbox_copy_matches_core(self):
        import importlib.util
        from pathlib import Path

        wrap_dek = (Path(__file__).resolve().parents[2]
                    / "byok-sandbox" / "gcp" / "wrap_dek.py")
        assert wrap_dek.is_file(), wrap_dek
        spec = importlib.util.spec_from_file_location("_wrap_dek_gcp", wrap_dek)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        for ctx in ({}, {"a": "1"}, {"b": "2", "a": "1"}):
            assert mod._canonical_aad(ctx) == canonical_aad(ctx)


# ---------- External HSM adapter ----------

class TestExternalHsmAdapter:
    def test_release_direct_bytes(self):
        captured = {}

        def fake_http(method, url, headers, body):
            captured.update({"url": url, "headers": headers, "body": body})
            return {"wrapped_b64": base64.b64encode(b"DIRECT-DEK").decode(),
                    "unwrap": "direct_bytes",
                    "metadata": {"hsm_serial": "1234"}}

        adapter = ExternalHsmAdapter(
            endpoint="https://hsm.example.com/", http=fake_http,
            bearer_token="TOKEN-A")
        ref = AttestedKeyRef(
            provider=KeyProvider.EXTERNAL_HSM, key_id="key-1",
            unwrap=UnwrapAlgorithm.DIRECT_BYTES,
            extra={"tenant": "t1", "nonce": "n1"})
        m = adapter.release(key_ref=ref, attestation=b"QUOTE",
                             policy=KeyReleasePolicy(),
                             encryption_context={"workload": "etl"})
        assert m.plaintext == b"DIRECT-DEK"
        assert m.wrapped_for_recipient is None
        assert captured["headers"]["Authorization"] == "Bearer TOKEN-A"
        assert captured["body"]["tenant"] == "t1"
        assert captured["body"]["encryption_context"] == {"workload": "etl"}
        assert m.provider_response_metadata == {"hsm_serial": "1234"}

    def test_release_wrapped_for_recipient(self):
        def fake_http(method, url, headers, body):
            return {"wrapped_b64": base64.b64encode(b"WRAP").decode(),
                    "unwrap": "rsa_oaep_sha256"}

        adapter = ExternalHsmAdapter(endpoint="https://h.example.com",
                                       http=fake_http)
        ref = AttestedKeyRef(provider=KeyProvider.EXTERNAL_HSM, key_id="k1",
                              unwrap=UnwrapAlgorithm.RSA_OAEP_SHA256)
        m = adapter.release(key_ref=ref, attestation=b"q",
                             policy=KeyReleasePolicy())
        assert m.plaintext is None
        assert m.wrapped_for_recipient == b"WRAP"
        assert m.unwrap_algorithm == UnwrapAlgorithm.RSA_OAEP_SHA256

    def test_endpoint_must_be_https(self):
        with pytest.raises(ValueError, match="https://"):
            ExternalHsmAdapter(endpoint="http://insecure.example.com")

    def test_missing_wrapped_b64(self):
        adapter = ExternalHsmAdapter(endpoint="https://x", http=lambda *a, **k: {})
        ref = AttestedKeyRef(provider=KeyProvider.EXTERNAL_HSM, key_id="k")
        with pytest.raises(KeyReleaseError, match="wrapped_b64"):
            adapter.release(key_ref=ref, attestation=b"q",
                             policy=KeyReleasePolicy())

    def test_unknown_unwrap_in_response(self):
        adapter = ExternalHsmAdapter(
            endpoint="https://x",
            http=lambda *a, **k: {"wrapped_b64": "AA==", "unwrap": "moonbeam"})
        ref = AttestedKeyRef(provider=KeyProvider.EXTERNAL_HSM, key_id="k")
        with pytest.raises(KeyReleaseError, match="unknown unwrap"):
            adapter.release(key_ref=ref, attestation=b"q",
                             policy=_policy())

    def test_server_cannot_downgrade_the_unwrap_algorithm(self):
        """A hostile HSM must not be able to turn rsa_oaep_sha256 into raw bytes.

        Otherwise the adapter hands the server's chosen bytes back as
        ``material.plaintext``, which the runtime writes straight to
        ``$TEE_CRAFTER_BYOK_DEK_PATH`` for the app to use as its DEK.
        """
        adapter = ExternalHsmAdapter(
            endpoint="https://hsm.example.com",
            http=lambda *a, **k: {
                "wrapped_b64": base64.b64encode(b"ATTACKER-KEY").decode(),
                "unwrap": "direct_bytes"})
        ref = AttestedKeyRef(provider=KeyProvider.EXTERNAL_HSM, key_id="k",
                              unwrap=UnwrapAlgorithm.RSA_OAEP_SHA256)
        with pytest.raises(KeyReleaseError, match="refusing the downgrade"):
            adapter.release(key_ref=ref, attestation=b"q", policy=_policy())

    def test_omitted_unwrap_in_response_uses_the_caller_pin(self):
        adapter = ExternalHsmAdapter(
            endpoint="https://hsm.example.com",
            http=lambda *a, **k: {
                "wrapped_b64": base64.b64encode(b"WRAP").decode()})
        ref = AttestedKeyRef(provider=KeyProvider.EXTERNAL_HSM, key_id="k",
                              unwrap=UnwrapAlgorithm.RSA_OAEP_SHA256)
        m = adapter.release(key_ref=ref, attestation=b"q", policy=_policy())
        assert m.unwrap_algorithm == UnwrapAlgorithm.RSA_OAEP_SHA256
        assert m.plaintext is None
        assert m.wrapped_for_recipient == b"WRAP"

    def test_reports_gating_none(self):
        adapter = ExternalHsmAdapter(
            endpoint="https://hsm.example.com",
            http=lambda *a, **k: {
                "wrapped_b64": base64.b64encode(b"D" * 32).decode()})
        ref = AttestedKeyRef(provider=KeyProvider.EXTERNAL_HSM, key_id="k")
        m = adapter.release(key_ref=ref, attestation=b"q", policy=_policy())
        assert m.gating is KeyGating.NONE


# ---------- Per-provider gating truth table ----------

class TestGatingTable:
    """FIX 2: exactly one provider x platform family is really KMS-enforced."""

    @pytest.mark.parametrize("provider,platform,expected", [
        # AWS: only a PCR-pinned Nitro Recipient decrypt is enforced by KMS.
        (KeyProvider.AWS_KMS, "nitro-aws", KeyGating.IAM_SCOPED),
        (KeyProvider.AWS_KMS, "snp-aws", KeyGating.IAM_SCOPED),
        (KeyProvider.AWS_KMS, "gpu-cc-aws", KeyGating.IAM_SCOPED),
        # Azure: shared-MAA attestation-type-only policy is not workload-bound.
        (KeyProvider.AZURE_KEY_VAULT, "snp-azure", KeyGating.IAM_SCOPED),
        (KeyProvider.AZURE_KEY_VAULT, "tdx-azure", KeyGating.IAM_SCOPED),
        (KeyProvider.AZURE_KEY_VAULT, "gpu-cc-azure", KeyGating.IAM_SCOPED),
        (KeyProvider.AZURE_KEY_VAULT, "sgx-azure", KeyGating.IAM_SCOPED),
        # GCP: AAD has no policy semantics; the gate is the IAM grant.
        (KeyProvider.GCP_KMS, "snp-gcp", KeyGating.IAM_SCOPED),
        (KeyProvider.GCP_KMS, "tdx-gcp", KeyGating.IAM_SCOPED),
        (KeyProvider.GCP_KMS, "gpu-cc-gcp", KeyGating.IAM_SCOPED),
        (KeyProvider.EXTERNAL_HSM, "", KeyGating.NONE),
        (KeyProvider.LOCAL_FILE, "", KeyGating.NONE),
    ])
    def test_shipped_defaults(self, provider, platform, expected):
        assert gating_for(provider, platform).gating is expected

    @pytest.mark.parametrize("provider,platform,fact", [
        (KeyProvider.AWS_KMS, "nitro-aws", "pcrs_pinned"),
        (KeyProvider.AZURE_KEY_VAULT, "snp-azure", "workload_claims_bound"),
        (KeyProvider.AZURE_KEY_VAULT, "tdx-azure", "workload_claims_bound"),
        (KeyProvider.GCP_KMS, "snp-gcp", "attribute_condition_bound"),
    ])
    def test_facts_upgrade_to_kms_enforced(self, provider, platform, fact):
        row = gating_for(provider, platform, **{fact: True})
        assert row.gating is KeyGating.KMS_ENFORCED
        assert row.measurement_gate == "policy-enforced"

    def test_snp_aws_cannot_be_upgraded(self):
        """AWS KMS has no SEV-SNP attestation condition key — no fact helps."""
        row = gating_for(KeyProvider.AWS_KMS, "snp-aws",
                         pcrs_pinned=True, workload_claims_bound=True,
                         attribute_condition_bound=True)
        assert row.gating is KeyGating.IAM_SCOPED

    def test_unknown_platform_falls_back_to_the_weaker_row(self):
        assert gating_for(KeyProvider.GCP_KMS, "not-a-platform").gating \
            is KeyGating.IAM_SCOPED

    def test_table_is_json_shaped(self):
        table = gating_table()
        assert table
        for key, row in table.items():
            assert row["gating"] in ("kms-enforced", "iam-scoped", "none"), key
            assert row["measurement_gate"] in ("policy-enforced", "advisory"), key
            assert row["note"], key


class TestAdapterGatingReporting:
    def test_nitro_recipient_with_pinned_pcrs_is_kms_enforced(self):
        client = FakeKmsClient(response={
            "CiphertextForRecipient": b"WRAPPED", "KeyId": "arn"})
        adapter = AwsKmsAdapter(kms_client=client)
        ref = AttestedKeyRef(
            provider=KeyProvider.AWS_KMS, key_id="arn",
            unwrap=UnwrapAlgorithm.AWS_NITRO_RECIPIENT,
            extra={"ciphertext_b64": base64.b64encode(b"CT").decode(),
                   "tee_platform": "nitro-aws", "pcrs_pinned": "1"})
        m = adapter.release(key_ref=ref, attestation=b"DOC", policy=_policy())
        assert m.gating is KeyGating.KMS_ENFORCED
        assert m.measurement_gate == "policy-enforced"

    def test_snp_aws_direct_decrypt_reports_iam_scoped_even_with_pcrs_claimed(self):
        """A plain kms:Decrypt is identity-gated whatever the config claims."""
        client = FakeKmsClient(response={"Plaintext": b"d" * 32, "KeyId": "arn"})
        adapter = AwsKmsAdapter(kms_client=client)
        ref = AttestedKeyRef(
            provider=KeyProvider.AWS_KMS, key_id="arn",
            unwrap=UnwrapAlgorithm.DIRECT_BYTES,
            extra={"ciphertext_b64": base64.b64encode(b"CT").decode(),
                   "tee_platform": "snp-aws", "pcrs_pinned": "1"})
        m = adapter.release(key_ref=ref, attestation=b"REPORT", policy=_policy())
        assert m.gating is KeyGating.IAM_SCOPED
        assert m.provider_response_metadata["gating"] == "iam-scoped"

    def test_orchestrator_propagates_gating_and_marks_advisory(self):
        class GatedAdapter(StubAdapter):
            def release(self, *, key_ref, attestation, policy,
                        encryption_context=None):
                m = super().release(key_ref=key_ref, attestation=attestation,
                                     policy=policy,
                                     encryption_context=encryption_context)
                return AttestedKeyMaterial(
                    key_ref=m.key_ref, plaintext=m.plaintext,
                    wrapped_for_recipient=None,
                    unwrap_algorithm=m.unwrap_algorithm,
                    released_at=0.0, attestation_sha256="",
                    attestation_age_seconds=0.0, audit_id="",
                    provider_response_metadata={},
                    gating=KeyGating.IAM_SCOPED,
                    measurement_gate="advisory",
                    gating_note="identity only")

        orch = KeyReleaseOrchestrator(
            attestation_provider=StubAttestation(),
            adapters={KeyProvider.LOCAL_FILE: GatedAdapter()},
            policy=KeyReleasePolicy(allowed_measurement_sha256=["a" * 64]),
            audit=RecordingAudit(),
        )
        m = orch.release(AttestedKeyRef(provider=KeyProvider.LOCAL_FILE,
                                         key_id="k"))
        assert m.gating is KeyGating.IAM_SCOPED
        assert m.measurement_gate == "advisory"
        assert m.provider_response_metadata["measurement_gate"] == "advisory"
        assert m.provider_response_metadata["measurement_allowlist_entries"] == 1
        assert orch.describe_gating(m)["gating"] == "iam-scoped"
