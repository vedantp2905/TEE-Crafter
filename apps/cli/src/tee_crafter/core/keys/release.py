"""High-level orchestration for attestation-gated key release."""
from __future__ import annotations

import hashlib
import time
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple

from tee_crafter.core.keys.spec import (
    AttestedKeyMaterial, AttestedKeyRef, KeyProvider, KeyReleaseError,
    KeyReleasePolicy, KmsAdapter,
)


class AttestationProvider(ABC):
    """Returns a fresh attestation blob for a given purpose.

    Implementations live next to the platform integrations
    (Nitro/SNP/TDX/etc.).  The orchestrator only needs this thin
    interface so it can be unit-tested with a stub provider.
    """

    @abstractmethod
    def fresh(
        self,
        *,
        purpose: str,
        nonce: bytes = b"",
    ) -> Tuple[bytes, float, str]:
        """Return ``(attestation_blob, issued_at_unix, measurement_sha256)``.

        ``measurement_sha256`` should be the canonical hash of the
        platform's measurement (e.g. SHA-256(PCR0||PCR1||PCR2) for Nitro,
        SHA-256(MEASUREMENT) for SNP).  An empty string disables the
        measurement allowlist check (useful only for unit tests).
        """


class KeyReleaseOrchestrator:
    """Wires :class:`AttestationProvider` + :class:`KmsAdapter` + policy.

    Caller code looks like::

        orch = KeyReleaseOrchestrator(
            attestation_provider=NitroAttestation(),
            adapters={KeyProvider.AWS_KMS: AwsKmsAdapter(...)},
            policy=KeyReleasePolicy(
                allowed_measurement_sha256=["abc...def"],
                max_attestation_age_seconds=120,
            ),
            audit=build_audit_trail,
        )
        material = orch.release(key_ref, encryption_context={"app": "etl"})

    ``audit`` is required whenever the policy leaves ``require_signed_audit``
    at its default of True; see :meth:`_record_audit`.
    """

    def __init__(
        self,
        *,
        attestation_provider: AttestationProvider,
        adapters: Dict[KeyProvider, KmsAdapter],
        policy: KeyReleasePolicy,
        audit=None,
        clock=time.time,
    ):
        if not adapters:
            raise ValueError("KeyReleaseOrchestrator requires at least one adapter")
        self._attest = attestation_provider
        self._adapters = dict(adapters)
        self._policy = policy
        self._audit = audit
        self._clock = clock

        errs = policy.validate()
        if errs:
            raise ValueError("Invalid KeyReleasePolicy: " + "; ".join(errs))

        # ``require_signed_audit`` is documented as mandatory and ships set to
        # true in every customer ``byok.json``.  Until now nothing read it, so
        # a deployment could release key material with no audit sink attached
        # and still describe itself as audit-gated.  Enforce it here, at the
        # only place that can: refuse to construct an orchestrator that has
        # nowhere to record its decisions.  ``_record_audit`` completes the
        # enforcement by refusing to swallow a write failure.
        if policy.require_signed_audit and audit is None:
            raise ValueError(
                "KeyReleasePolicy.require_signed_audit is set but no audit sink "
                "was passed to KeyReleaseOrchestrator(audit=...).  Every release "
                "attempt has to be appended to the audit chain before the "
                "material is handed out.  Pass an audit trail, or set "
                "require_signed_audit=False "
                "(env TEE_CRAFTER_BYOK_REQUIRE_SIGNED_AUDIT=0) if you accept "
                "unaudited releases.")

    def policy(self) -> KeyReleasePolicy:
        return self._policy

    def supports(self, provider: KeyProvider) -> bool:
        return provider in self._adapters

    def release(
        self,
        key_ref: AttestedKeyRef,
        *,
        encryption_context: Optional[Dict[str, str]] = None,
        purpose: str = "data_decrypt",
        nonce: Optional[bytes] = None,
    ) -> AttestedKeyMaterial:
        adapter = self._adapters.get(key_ref.provider)
        if adapter is None:
            raise KeyReleaseError(
                f"No adapter registered for provider {key_ref.provider.value!r}; "
                f"have {[p.value for p in self._adapters]}")

        if self._policy.required_provider is not None and \
                key_ref.provider != self._policy.required_provider:
            raise KeyReleaseError(
                f"Policy fixes provider to {self._policy.required_provider.value!r}, "
                f"requested {key_ref.provider.value!r}")

        # Attestation must be fresh for THIS specific request.  Bind a
        # caller-supplied nonce when present, otherwise generate one so
        # responses cannot be replayed.
        if nonce is None:
            nonce = uuid.uuid4().bytes

        try:
            attestation, issued_at, measurement_sha = self._attest.fresh(
                purpose=purpose, nonce=nonce)
        except Exception as exc:
            self._record_audit("fail", key_ref, error=f"attestation provider failed: {exc!r}")
            raise KeyReleaseError(f"attestation provider failed: {exc!r}")

        att_age = max(0.0, self._clock() - float(issued_at))
        if att_age > self._policy.max_attestation_age_seconds:
            self._record_audit("fail", key_ref,
                                error=f"attestation too old: {att_age:.1f}s")
            raise KeyReleaseError(
                f"Attestation is {att_age:.0f}s old; policy max is "
                f"{self._policy.max_attestation_age_seconds}s")

        # NOTE ON WHAT THIS CHECK IS WORTH.  This runs in-process, on the CVM
        # host, over a report whose signature chain nobody verified.  Root on
        # that host can edit this file, and can skip it entirely by reading the
        # instance credentials from IMDS and calling the provider directly.  It
        # is therefore a *gate* only where the custodian evaluates the
        # measurement too (KeyGating.KMS_ENFORCED); everywhere else it is
        # advisory and the returned material says so.  See core/keys/gating.py.
        if self._policy.allowed_measurement_sha256:
            if not measurement_sha:
                self._record_audit("fail", key_ref,
                                    error="provider returned no measurement")
                raise KeyReleaseError(
                    "Policy requires a measurement allowlist but provider did not "
                    "supply one")
            if measurement_sha not in self._policy.allowed_measurement_sha256:
                self._record_audit("fail", key_ref,
                                    error=f"measurement {measurement_sha} not in allowlist")
                raise KeyReleaseError(
                    f"Measurement {measurement_sha} is not in the policy allowlist "
                    f"({len(self._policy.allowed_measurement_sha256)} entries)")

        if self._policy.require_encryption_context_keys:
            ctx = encryption_context or {}
            missing = [k for k in self._policy.require_encryption_context_keys
                       if k not in ctx]
            if missing:
                self._record_audit("fail", key_ref,
                                    error=f"missing encryption context: {missing}")
                raise KeyReleaseError(
                    f"Policy requires encryption context keys {missing} but they "
                    f"were not supplied")

        adapter.preflight(
            key_ref=key_ref, attestation=attestation,
            policy=self._policy, attestation_issued_at=issued_at)

        material = adapter.release(
            key_ref=key_ref, attestation=attestation,
            policy=self._policy, encryption_context=encryption_context)
        # Re-stamp orchestrator-derived metadata (the adapter may have
        # filled in only its own fields).  The adapter owns `gating` -- it is
        # the only layer that knows which provider API was actually called --
        # so it is carried through unchanged rather than recomputed here.
        meta = dict(material.provider_response_metadata)
        meta.setdefault("gating", material.gating.value)
        meta["measurement_gate"] = material.measurement_gate
        meta["measurement_allowlist_entries"] = len(
            self._policy.allowed_measurement_sha256)
        material = AttestedKeyMaterial(
            key_ref=material.key_ref,
            plaintext=material.plaintext,
            wrapped_for_recipient=material.wrapped_for_recipient,
            unwrap_algorithm=material.unwrap_algorithm,
            released_at=self._clock(),
            attestation_sha256=hashlib.sha256(attestation).hexdigest(),
            attestation_age_seconds=att_age,
            audit_id=material.audit_id or uuid.uuid4().hex,
            provider_response_metadata=meta,
            gating=material.gating,
            measurement_gate=material.measurement_gate,
            gating_note=material.gating_note,
        )
        self._record_audit("pass", key_ref,
                            audit_id=material.audit_id,
                            attestation_sha256=material.attestation_sha256,
                            attestation_age_seconds=round(material.attestation_age_seconds, 3),
                            unwrap_algorithm=material.unwrap_algorithm.value,
                            gating=material.gating.value,
                            measurement_gate=material.measurement_gate)
        return material

    # ---- internals ----

    def _record_audit(self, status: str, key_ref: AttestedKeyRef, **details) -> None:
        """Append one release decision to the audit chain.

        Under ``require_signed_audit`` a write failure is fatal: an audit entry
        that did not land is indistinguishable from a release that never
        happened, so swallowing the error would reintroduce exactly the gap the
        policy exists to close.  With the policy off, best-effort logging is
        kept so a broken sink cannot wedge a workload that never asked for the
        guarantee.
        """
        if self._audit is None:
            return
        try:
            self._audit.record(
                "Key Release", f"byok:{key_ref.provider.value}", status,
                key_id_tail=key_ref.key_id[-12:] if key_ref.key_id else "",
                provider=key_ref.provider.value,
                region=key_ref.region, label=key_ref.label,
                **details,
            )
        except Exception as exc:
            if self._policy.require_signed_audit:
                raise KeyReleaseError(
                    f"policy requires a signed audit record but the audit sink "
                    f"rejected the {status!r} entry: {exc!r}") from exc

    def material_signature(self, m: AttestedKeyMaterial) -> str:
        """Return a non-secret summary of *m* suitable for logs."""
        body = "|".join((
            m.key_ref.provider.value, m.key_ref.region, m.key_ref.short(),
            m.unwrap_algorithm.value, m.attestation_sha256,
            f"age={m.attestation_age_seconds:.1f}s",
        ))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]

    def describe_gating(self, m: AttestedKeyMaterial) -> Dict[str, object]:
        """Machine-readable gating summary for the evidence bundle.

        Deliberately separate from :meth:`material_signature`: the signature is
        a stability check, this is the claim a compliance reader acts on.
        """
        return {
            "provider": m.key_ref.provider.value,
            "gating": m.gating.value,
            "measurement_gate": m.measurement_gate,
            "measurement_allowlist_entries": len(
                self._policy.allowed_measurement_sha256),
            "note": m.gating_note,
        }
