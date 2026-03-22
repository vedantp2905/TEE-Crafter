"""Azure Key Vault Managed HSM adapter.

Azure Key Vault Managed HSM exposes a ``release`` operation
(``POST /keys/{name}/{version}/release``) that takes a JWT-encoded
attestation token from Azure Attestation Service and returns
``KeyReleaseResult.value`` -- "a signed object containing the released
key".  That object decodes to JSON with the wrapped key material at
``key.key_hsm``, under ``CKM_RSA_AES_KEY_WRAP``: an ephemeral AES key
wrapped with RSA-OAEP to the public key the attestation token bound to
this TEE, followed by the target key wrapped under that AES key with
AES-KWP.  It is not a JWE, and it is not a single RSA-OAEP blob; both
descriptions were in this file and both were wrong.
Only HSM-backed keys with a release policy attached are eligible.
https://learn.microsoft.com/en-us/rest/api/keyvault/keys/release/release

**The unwrap is now wired.** Pass ``recipient_private_key`` and ``release()``
returns ``plaintext`` instead of only ``wrapped_for_recipient``.  Pass
``expected_transfer_key`` — the key-encryption-key JWK from the verified MAA
token — alongside it and the binding is checked *before* any unwrap is
attempted, because the two failures mean very different things: wrapping to a
key we do not hold is a crypto error, but a token that bound a key we do not
hold is somebody else's token, and the second must not be reported as the first.

Without ``recipient_private_key`` the behaviour is unchanged: ``plaintext``
stays ``None`` and the runtime bootstrap refuses rather than staging an empty
DEK.

**Who owns the key-encryption key, and why this adapter cannot finish the job
on Azure.** The guest does *not* get to nominate that key.  Microsoft's
walkthrough calls it "a public RSA key **owned and protected by the target
execution environment**", surfaces it in the token as
``x-ms-runtime.keys[kid=TpmEphemeralEncryptionKey]``, and its private half is
sealed to the vTPM and reachable only through ``azguestattestation1``'s
``Decrypt`` API.  No Python process can supply ``recipient_private_key`` there,
so on a real Azure CVM ``release()`` returns ``plaintext=None`` and the runtime
bootstrap refuses — correctly, and fail-closed.
https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp

**That is now a routing decision, not an open gap.**  Azure CVM releases go
through :mod:`tee_crafter.core.keys.azure_skr_tool`, which delegates the whole
operation to Microsoft's ``AzureAttestSKR`` — the process that holds the sealed
key — and gets back an unwrapped DEK.  ``TEE_CRAFTER_BYOK=azure-skr`` selects it.

This adapter stays for the case it is actually right for: a flow where we *do*
own the recipient key, meaning an external HSM or a test.  It is not deprecated
and it is not the Azure path; picking it on a CVM fails closed rather than
quietly producing nothing.

**Unproven against a real Managed HSM** — every test drives it with locally
generated keys and with response shapes copied from the two Microsoft samples.

We deliberately keep the HTTP layer thin and pluggable so unit tests can
inject a fake transport.  In production, the per-platform template is
expected to inject an authenticated transport (DefaultAzureCredential
+ a workload-identity token).
"""
from __future__ import annotations

import base64
import json
from typing import Any, Callable, Dict, Optional

from tee_crafter.core.keys.gating import gating_from_extra
from tee_crafter.core.keys.spec import (
    AttestedKeyMaterial, AttestedKeyRef, KeyProvider, KeyReleaseError,
    KeyReleasePolicy, KmsAdapter, UnwrapAlgorithm,
)


JsonHttpClient = Callable[[str, str, Dict[str, str], Dict[str, Any]], Dict[str, Any]]
"""Callable that takes (method, url, headers, json_body) and returns a parsed
JSON response.  Decoupled from ``requests`` for testability."""


class AzureKeyVaultAdapter(KmsAdapter):
    provider = KeyProvider.AZURE_KEY_VAULT

    def __init__(
        self,
        *,
        http: Optional[JsonHttpClient] = None,
        api_version: str = "7.4",
        recipient_private_key: Any = None,
        expected_transfer_key: Optional[Dict[str, Any]] = None,
    ):
        """*recipient_private_key* is the RSA private half of the transfer key.

        *expected_transfer_key* is the JWK for its public half as it appeared in
        the **verified** MAA token (``x-ms-runtime.keys``, ``kid``
        ``HCLTransferKey``).  Supplying it is what turns "the unwrap failed"
        into "this token bound a key we do not hold".
        """
        self._http = http
        self._api_version = api_version
        self._recipient_private_key = recipient_private_key
        self._expected_transfer_key = expected_transfer_key

    def _default_http(self) -> JsonHttpClient:
        """Refuse, rather than send a request that cannot succeed.

        Key Vault's ``release`` operation is an authenticated data-plane call:
        it needs an ``Authorization: Bearer`` token for
        ``https://vault.azure.net``, normally obtained from IMDS via the VM's
        managed identity.  This class never had one — the transport built here
        sent ``Content-Type`` and nothing else, so every real call would have
        come back 401, and the module docstring's "the per-platform template is
        expected to inject an authenticated transport" was never acted on: the
        runtime bootstrap constructs ``AzureKeyVaultAdapter()`` with no ``http``.

        Two reasons this is a refusal and not a new IMDS integration. First, the
        Azure path is :mod:`tee_crafter.core.keys.azure_skr_tool` regardless —
        even with a token, the released key is wrapped to a vTPM-sealed KEK this
        process cannot unwrap, so authenticating would move the failure later,
        not remove it. Second, a 401 surfaced as "Key Vault release failed" is
        indistinguishable from a policy mismatch or a bad key id, and this
        adapter is otherwise correct; the honest failure is to say which piece
        is missing.

        Callers that genuinely hold the recipient key (an external HSM flow, or
        tests) inject ``http`` and never reach this.
        """
        raise KeyReleaseError(
            "AzureKeyVaultAdapter has no authenticated transport. Key Vault's "
            "`release` needs an AAD bearer token for https://vault.azure.net "
            "(normally from IMDS via the VM's managed identity), and this "
            "adapter has never sent an Authorization header — so the call "
            "would return 401. On an Azure CVM this is the wrong adapter "
            "anyway: the released key is wrapped to TpmEphemeralEncryptionKey, "
            "whose private half is sealed to the vTPM, so no Python process can "
            "unwrap it. Use TEE_CRAFTER_BYOK=azure-skr, which delegates both "
            "the release and the unwrap to AzureAttestSKR. Pass `http=` "
            "explicitly only if you hold the recipient private key yourself.")

    def release(
        self,
        *,
        key_ref: AttestedKeyRef,
        attestation: bytes,
        policy: KeyReleasePolicy,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> AttestedKeyMaterial:
        if key_ref.provider != KeyProvider.AZURE_KEY_VAULT:
            raise KeyReleaseError(
                f"AzureKeyVaultAdapter cannot release {key_ref.provider.value} keys")
        if not key_ref.key_id.startswith("https://"):
            raise KeyReleaseError(
                "Azure key_id must be the full Key Vault key URL "
                "(e.g. https://mhsm-name.managedhsm.azure.net/keys/foo/abcd1234)")

        # Azure expects a JWT *string* even though we hold raw bytes.  The
        # template layer that calls into us is responsible for ensuring
        # the attestation blob is the MAA-issued JWT string when this
        # adapter is wired in.
        try:
            attestation_jwt = attestation.decode("ascii")
        except UnicodeDecodeError:
            attestation_jwt = base64.b64encode(attestation).decode("ascii")

        nonce = (encryption_context or {}).get("nonce", "")
        url = f"{key_ref.key_id}/release?api-version={self._api_version}"
        headers = {"Content-Type": "application/json"}
        body = {"target": attestation_jwt, "nonce": nonce, "enc": "CKM_RSA_AES_KEY_WRAP"}

        http = self._http or self._default_http()
        try:
            resp = http("POST", url, headers, body)
        except Exception as exc:
            raise KeyReleaseError(f"Key Vault release failed: {exc}") from exc

        value = resp.get("value") or resp.get("Value")
        if not value:
            raise KeyReleaseError("Key Vault release response had no `value` field")
        envelope = _decode_release_envelope(value)
        wrapped, kid = _extract_key_hsm(envelope)

        # Order matters.  Check the binding before touching the ciphertext: if
        # the token bound a transfer key we do not hold, the unwrap below is
        # guaranteed to fail, and reporting that as a padding/crypto error
        # would hide the fact that this is not our release.
        if self._expected_transfer_key is not None and self._recipient_private_key is not None:
            if not transfer_key_matches(
                    self._expected_transfer_key, self._recipient_private_key):
                raise KeyReleaseError(
                    "the MAA token bound a different transfer key than the "
                    "private key held here, so this release was not wrapped "
                    "for this TEE. Refusing to attempt an unwrap that could "
                    "only fail, and refusing to treat it as a crypto error.")

        plaintext = None
        unwrap_meta: Dict[str, Any] = {}
        if self._recipient_private_key is not None:
            from tee_crafter.core.keys.rsa_aes_key_wrap import (
                KeyUnwrapError, unwrap_ckm_rsa_aes_key_wrap,
            )
            try:
                unwrapped = unwrap_ckm_rsa_aes_key_wrap(
                    wrapped, self._recipient_private_key)
            except KeyUnwrapError as exc:
                # Deliberately no ciphertext, no key bytes, no lengths beyond
                # the segment split in the message from the unwrapper itself.
                raise KeyReleaseError(
                    f"released key could not be unwrapped: {exc}") from exc
            plaintext = unwrapped.plaintext
            unwrap_meta = {
                "unwrapped": True,
                "oaep_hash": unwrapped.oaep_hash,
                "wrapped_aes_key_bytes": unwrapped.wrapped_aes_key_bytes,
            }

        # Secure Key Release is genuine, but only binds *this* workload when
        # the release policy pins x-ms-sevsnpvm-launchmeasurement / -hostdata.
        # The deploy side records that as extra['workload_claims_bound'].
        gating = gating_from_extra(KeyProvider.AZURE_KEY_VAULT, key_ref.extra)

        meta = {
            # The `kid` lives inside the released envelope, not at the top
            # level of the HTTP response -- `resp.get("kid")` was always
            # falling through to the requested key_id, so a version mismatch
            # between what we asked for and what was released was invisible.
            "kid": kid or key_ref.key_id,
            "kid_matches_request": bool(kid) and kid == key_ref.key_id,
            "release_policy_version": (
                (envelope.get("release_policy") or {}).get("contentType", "")),
            "raw": json.dumps(resp)[:400],
            **unwrap_meta,
            **gating.as_dict(),
        }
        return AttestedKeyMaterial(
            key_ref=key_ref,
            plaintext=plaintext,
            wrapped_for_recipient=wrapped,
            unwrap_algorithm=UnwrapAlgorithm.CKM_RSA_AES_KEY_WRAP,
            released_at=0.0,
            attestation_sha256="",
            attestation_age_seconds=0.0,
            audit_id="",
            provider_response_metadata=meta,
            gating=gating.gating,
            measurement_gate=gating.measurement_gate,
            gating_note=gating.note,
        )


def _pad_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)


#: ``kid`` of the key-encryption key Key Vault actually wraps to.
#:
#: Microsoft's walkthrough is explicit about which key this is and which one it
#: is *not*: "Key Vault picks the first suitable key from `keys` array property
#: in the `x-ms-runtime` object, it looks for a public RSA key with
#: `"key_use": ["enc"]` or `"key_ops": ["encrypt"]` ... Key Vault uses the
#: `TpmEphemeralEncryptionKey` key as the key-encryption key." And immediately
#: after: "Notice that there may be a key under
#: `$.x-ms-isolation-tee.x-ms-runtime.keys`, this is **not** the key that Key
#: Vault will be using" — that inner one is `HCLAkPub`, the attestation key.
#: https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp
#:
#: An earlier revision of this module called it ``HCLTransferKey``, which
#: appears in neither claim set. Wrapping to the wrong one of two RSA keys in
#: the same token is not a failure that shows up until a live release.
KEY_ENCRYPTION_KEY_KID = "TpmEphemeralEncryptionKey"

#: The attestation key in the *inner* isolation-tee claims. Named only so the
#: lookup below can refuse it explicitly rather than silently ranking it.
ISOLATION_TEE_AK_KID = "HCLAkPub"


def _b64u_uint(value: int) -> str:
    """Big-endian base64url of a JWK integer, minimal length, no padding."""
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def transfer_key_jwk(private_key: Any, *, kid: str = KEY_ENCRYPTION_KEY_KID
                     ) -> Dict[str, Any]:
    """Public half of a key-encryption key, in the JWK shape Key Vault expects.

    ``key_ops`` carries ``encrypt`` because that is one of the two markers Key
    Vault selects on ("a public RSA key with ``key_use`` ``enc`` or ``key_ops``
    containing ``encrypt``").

    Used for the *expected* side of the binding check and in tests. On a real
    Azure CVM the guest does not choose this key — see the module docstring.
    """
    numbers = private_key.public_key().public_numbers()
    return {
        "kid": kid,
        "kty": "RSA",
        "key_ops": ["encrypt"],
        "n": _b64u_uint(numbers.n),
        "e": _b64u_uint(numbers.e),
    }


def find_key_encryption_key(runtime_keys: Any,
                            *, kid: str = KEY_ENCRYPTION_KEY_KID
                            ) -> Optional[Dict[str, Any]]:
    """The key-encryption key from a verified token's ``x-ms-runtime.keys``.

    Pass the **top-level** ``x-ms-runtime.keys``. Do not pass
    ``x-ms-isolation-tee.x-ms-runtime.keys``: Microsoft's walkthrough says in
    terms that the key there "is **not** the key that Key Vault will be using",
    and ``ISOLATION_TEE_AK_KID`` is rejected below so that mistake fails loudly
    instead of producing an unwrap error three steps later.

    Matching on ``kid`` rather than taking the first entry is the same
    discipline the MAA verifier applies to JWKS lookup. Note Key Vault itself
    documents picking "the first suitable key"; being stricter than the service
    is safe — we only ever *check* a binding here, never choose one.
    """
    if not isinstance(runtime_keys, (list, tuple)):
        return None
    for entry in runtime_keys:
        if not isinstance(entry, dict):
            continue
        if entry.get("kid") == ISOLATION_TEE_AK_KID:
            raise KeyReleaseError(
                f"{ISOLATION_TEE_AK_KID} is the isolation-tee attestation key, "
                "not the key-encryption key. Pass the top-level "
                "`x-ms-runtime.keys`, not `x-ms-isolation-tee.x-ms-runtime.keys`.")
        if entry.get("kid") == kid:
            return entry
    return None


def transfer_key_matches(jwk: Optional[Dict[str, Any]], private_key: Any) -> bool:
    """True iff *jwk* is the public half of *private_key*.

    Compares the RSA modulus and exponent as integers rather than the encoded
    strings, because JWK base64url is only canonical if everybody agrees to
    strip leading zero bytes and padding — and a comparison that returns False
    over an encoding difference would reject a legitimate release.
    """
    if not isinstance(jwk, dict) or private_key is None:
        return False
    if jwk.get("kty") != "RSA":
        return False
    try:
        n = int.from_bytes(base64.urlsafe_b64decode(_pad_b64(jwk["n"])), "big")
        e = int.from_bytes(base64.urlsafe_b64decode(_pad_b64(jwk["e"])), "big")
    except (KeyError, TypeError, ValueError, base64.binascii.Error):
        return False
    numbers = private_key.public_key().public_numbers()
    return n == numbers.n and e == numbers.e


def _decode_release_envelope(value: str) -> Dict[str, Any]:
    """Decode ``KeyReleaseResult.value`` into the released-key envelope.

    The REST reference calls this field "a signed object containing the
    released key" and its sample response is base64url of a JSON document
    (``{"attributes": ..., "key": {...}, "release_policy": {...}}``).  Managed
    HSM returns the same document as the payload of a JWS, i.e. three
    dot-separated base64url segments.  Both shapes are accepted; anything else
    is an error rather than a guess.

    https://learn.microsoft.com/en-us/rest/api/keyvault/keys/release/release

    Note this does **not** verify the JWS signature.  The security of SKR does
    not rest on it: the key material inside is wrapped to a public key that the
    attestation token bound to this TEE, so an attacker who swaps the envelope
    still cannot unwrap. Verifying it would additionally require the vault's
    signing certificate, which is not plumbed here.  Recorded rather than
    silently skipped.
    """
    segments = value.split(".")
    if len(segments) == 3:
        raw = segments[1]  # JWS payload
    elif len(segments) == 1:
        raw = value
    else:
        raise KeyReleaseError(
            f"Key Vault `value` had {len(segments)} dot-separated segments; "
            "expected a bare base64url document or a 3-segment JWS")
    try:
        decoded = base64.urlsafe_b64decode(_pad_b64(raw))
    except Exception as exc:
        raise KeyReleaseError(f"Key Vault `value` is not base64url: {exc}") from exc
    try:
        envelope = json.loads(decoded)
    except ValueError as exc:
        raise KeyReleaseError(
            f"Key Vault `value` did not decode to JSON: {exc}") from exc
    if not isinstance(envelope, dict):
        raise KeyReleaseError(
            f"Key Vault `value` decoded to {type(envelope).__name__}, not an object")
    return envelope


def _locate_key_object(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Find the JWK inside a release envelope, across both documented shapes.

    The REST reference's sample is ``{"key": {...}}``.  The confidential-computing
    walkthrough's sample of a real Managed HSM response is nested two levels
    further, ``{"response": {"key": {"key": {...}}}}``:
    https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp
    ("Key Release Response").  Both are accepted; anything else is an error
    rather than a guess.
    """
    candidates = (
        envelope.get("key"),
        ((envelope.get("response") or {}).get("key") or {}).get("key")
        if isinstance(envelope.get("response"), dict) else None,
    )
    for cand in candidates:
        if isinstance(cand, dict) and cand.get("key_hsm"):
            return cand
    for cand in candidates:
        if isinstance(cand, dict):
            return cand
    raise KeyReleaseError(
        "Key Vault release envelope has no `key` object at `key` or "
        f"`response.key.key`; got keys {sorted(envelope)!r}")


def _extract_key_hsm(envelope: Dict[str, Any]) -> tuple[bytes, str]:
    """Pull the wrapped key bytes and the ``kid`` out of the envelope.

    Returns ``(wrapped_bytes, kid)``.

    ``key_hsm`` is **not** the ciphertext.  It base64-decodes to a further JSON
    document, and the CKM_RSA_AES_KEY_WRAP blob is the base64 ``ciphertext``
    field inside it::

        {"schema_version": "1.0",
         "header": {"kid": "TpmEphemeralEncryptionKey",
                    "alg": "dir", "enc": "CKM_RSA_AES_KEY_WRAP"},
         "ciphertext": "Rftxvr..lb"}

    -- https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp

    This file has now been wrong about this blob's shape three times: first it
    handed back the outer envelope text, then the base64-decode of ``key_hsm``
    itself.  Both would fail against a real Managed HSM, and neither could be
    caught by a test that invented the response.  Hence the doc link, and hence
    ``enc`` being checked rather than assumed.
    """
    key_obj = _locate_key_object(envelope)
    key_hsm = key_obj.get("key_hsm")
    if not key_hsm:
        raise KeyReleaseError(
            "Key Vault release envelope carries no `key.key_hsm`; nothing to "
            f"unwrap (kty={key_obj.get('kty')!r})")
    try:
        inner_raw = base64.urlsafe_b64decode(_pad_b64(key_hsm))
    except Exception as exc:
        raise KeyReleaseError(f"`key.key_hsm` is not base64url: {exc}") from exc
    if not inner_raw:
        raise KeyReleaseError("`key.key_hsm` decoded to zero bytes")

    try:
        inner = json.loads(inner_raw)
    except ValueError as exc:
        raise KeyReleaseError(
            "`key.key_hsm` did not decode to the documented JSON envelope "
            f"({exc}). Expected {{schema_version, header, ciphertext}}.") from exc
    if not isinstance(inner, dict):
        raise KeyReleaseError(
            f"`key.key_hsm` decoded to {type(inner).__name__}, not an object")

    header = inner.get("header") if isinstance(inner.get("header"), dict) else {}
    enc = str(header.get("enc") or "")
    if enc and enc != "CKM_RSA_AES_KEY_WRAP":
        raise KeyReleaseError(
            f"released key is wrapped with {enc!r}, not CKM_RSA_AES_KEY_WRAP; "
            "this adapter cannot unwrap it")

    ciphertext = inner.get("ciphertext")
    if not ciphertext:
        raise KeyReleaseError(
            "`key.key_hsm` envelope carries no `ciphertext`; "
            f"got keys {sorted(inner)!r}")
    try:
        wrapped = base64.urlsafe_b64decode(_pad_b64(str(ciphertext)))
    except Exception as exc:
        raise KeyReleaseError(
            f"`key_hsm.ciphertext` is not base64: {exc}") from exc
    if not wrapped:
        raise KeyReleaseError("`key_hsm.ciphertext` decoded to zero bytes")
    return wrapped, str(key_obj.get("kid") or "")
