"""Generic external-HSM adapter.

Some regulated buyers run their own HSM (Thales, Entrust, AWS
CloudHSM-direct, ...) behind a thin HTTPS gateway that takes an
attestation blob and returns a wrapped DEK.  This adapter codifies that
pattern so customers can integrate their HSM without forking
TEE-Crafter.

The wire protocol is intentionally simple JSON-over-HTTPS:

    POST  {endpoint}/release
    Authorization: Bearer <gateway token, optional>
    Content-Type: application/json
    {
      "key_id": "<customer key id>",
      "attestation_b64": "<base64(blob)>",
      "encryption_context": {...},
      "unwrap": "rsa_oaep_sha256" | "direct_bytes",
      "tenant": "<optional tenant id>",
      "nonce": "<hex>"
    }

    200 OK
    {
      "wrapped_b64": "<base64>",
      "unwrap": "rsa_oaep_sha256",
      "metadata": {...}
    }

The response's ``unwrap`` is an **echo**, not a choice: if it is present and
differs from the algorithm the caller pinned in ``key_ref.unwrap``, the release
is refused.  See :meth:`ExternalHsmAdapter.release`.

Customers can serve this from a Lambda / Cloud Run / Function App in
their own VPC with whatever IAM and audit pipeline they prefer.  Because that
policy is theirs, TEE-Crafter reports this provider's gating as
:attr:`~tee_crafter.core.keys.spec.KeyGating.NONE` -- we cannot assert what the
gateway checks.
"""
from __future__ import annotations

import base64
from typing import Any, Callable, Dict, Optional

from tee_crafter.core.keys.gating import gating_from_extra
from tee_crafter.core.keys.spec import (
    AttestedKeyMaterial, AttestedKeyRef, KeyProvider, KeyReleaseError,
    KeyReleasePolicy, KmsAdapter, UnwrapAlgorithm,
)


HttpClient = Callable[[str, str, Dict[str, str], Dict[str, Any]], Dict[str, Any]]


class ExternalHsmAdapter(KmsAdapter):
    provider = KeyProvider.EXTERNAL_HSM

    def __init__(
        self,
        *,
        endpoint: str,
        http: Optional[HttpClient] = None,
        bearer_token: Optional[str] = None,
        request_timeout: int = 15,
    ):
        if not endpoint or not endpoint.startswith("https://"):
            raise ValueError("ExternalHsmAdapter endpoint must be https://")
        self._endpoint = endpoint.rstrip("/")
        self._http = http
        self._bearer = bearer_token
        self._timeout = request_timeout

    def _default_http(self) -> HttpClient:
        try:
            import requests  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise KeyReleaseError(
                "requests is required for ExternalHsmAdapter; pass http=...") from exc

        def _post(method, url, headers, body):
            r = requests.request(method, url, headers=headers, json=body,
                                  timeout=self._timeout)
            r.raise_for_status()
            return r.json()
        return _post

    def release(
        self,
        *,
        key_ref: AttestedKeyRef,
        attestation: bytes,
        policy: KeyReleasePolicy,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> AttestedKeyMaterial:
        if key_ref.provider != KeyProvider.EXTERNAL_HSM:
            raise KeyReleaseError(
                f"ExternalHsmAdapter cannot release {key_ref.provider.value} keys")

        body = {
            "key_id": key_ref.key_id,
            "attestation_b64": base64.b64encode(attestation).decode("ascii"),
            "encryption_context": dict(encryption_context or {}),
            "unwrap": key_ref.unwrap.value,
            "tenant": key_ref.extra.get("tenant", ""),
            "nonce": key_ref.extra.get("nonce", ""),
            "label": key_ref.label,
        }
        headers = {"Content-Type": "application/json"}
        if self._bearer:
            headers["Authorization"] = f"Bearer {self._bearer}"

        http = self._http or self._default_http()
        try:
            resp = http("POST", f"{self._endpoint}/release", headers, body)
        except Exception as exc:
            raise KeyReleaseError(f"External HSM release failed: {exc}") from exc

        wrapped_b64 = resp.get("wrapped_b64")
        if not wrapped_b64:
            raise KeyReleaseError("External HSM response missing 'wrapped_b64'")
        try:
            wrapped = base64.b64decode(wrapped_b64)
        except Exception as exc:
            raise KeyReleaseError(f"wrapped_b64 is not valid base64: {exc}")

        # The unwrap algorithm is decided by the CALLER, never by the server.
        # The HSM is positioned as a third party in this design, so letting its
        # JSON response pick the algorithm is an attacker-controlled downgrade:
        # a caller asking for rsa_oaep_sha256 (material wrapped to a key only
        # the TEE holds) could be answered with direct_bytes, and the adapter
        # would hand the server's chosen bytes back as plaintext DEK.
        unwrap_str = resp.get("unwrap")
        if unwrap_str is not None and unwrap_str != key_ref.unwrap.value:
            try:
                UnwrapAlgorithm(unwrap_str)
            except ValueError:
                raise KeyReleaseError(
                    f"External HSM returned unknown unwrap={unwrap_str!r}")
            raise KeyReleaseError(
                f"External HSM returned unwrap={unwrap_str!r} but the caller "
                f"pinned {key_ref.unwrap.value!r}; refusing the downgrade")
        unwrap = key_ref.unwrap

        plaintext = wrapped if unwrap == UnwrapAlgorithm.DIRECT_BYTES else None
        wrapped_for_recipient = wrapped if unwrap != UnwrapAlgorithm.DIRECT_BYTES else None

        gating = gating_from_extra(KeyProvider.EXTERNAL_HSM, key_ref.extra)
        return AttestedKeyMaterial(
            key_ref=key_ref,
            plaintext=plaintext,
            wrapped_for_recipient=wrapped_for_recipient,
            unwrap_algorithm=unwrap,
            released_at=0.0,
            attestation_sha256="",
            attestation_age_seconds=0.0,
            audit_id="",
            provider_response_metadata=dict(resp.get("metadata") or {}),
            gating=gating.gating,
            measurement_gate=gating.measurement_gate,
            gating_note=gating.note,
        )
