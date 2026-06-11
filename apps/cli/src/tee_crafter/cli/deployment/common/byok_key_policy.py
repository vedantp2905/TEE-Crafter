"""Pin an AWS KMS BYOK key to the instance role, during the deploy.

On ``snp-aws`` and ``gpu-cc-aws`` there is no attestation condition key AWS will
evaluate (see ``core/keys/gating.py``, and ``docs/pending.md`` for why the
measurement-bound alternative is unbuilt rather than impossible),
so the caller's principal is the *entire* access control on the customer's DEK.
That makes pinning the exact role ARN the difference between "one instance" and
"anything in the account that can assume a matching role name".

The awkward part is timing. Terraform names the role with a per-deploy suffix
(``tee-crafter-snp-role-a1b2c3d4``), so the exact ARN does not exist when the
key and its wrapped DEK are created. Until now the two ways out were both bad:

* ``--instance-role-arn`` at key-creation time — impossible for a role that
  does not exist yet, so in practice it meant creating the key mid-deploy by
  hand;
* ``--allow-wildcard-role`` — the ``role/tee-crafter-<plat>-role-*`` pattern,
  which the sandbox tooling itself flags as DANGEROUS because anyone able to
  create a role matching that name can decrypt.

This module takes the third option: create the key ahead of time with no
decrypt grant at all, then rewrite the policy in place once Terraform has made
the role, before the workload ever asks for the DEK.

Two properties worth stating, because they are the reason this is safe:

* **Fail closed.** If the ARN cannot be read, or ``PutKeyPolicy`` fails, the
  caller aborts the deploy. Continuing would run the workload against whatever
  policy the key happened to carry, which is exactly the state this exists to
  prevent.
* **No cleanup needed at teardown.** The pinned ARN belongs to a role Terraform
  destroys, so the resting state of the key is "pinned to a principal that no
  longer exists" — nothing can decrypt with it until the next deploy re-pins.
  Reverting to a broader policy on the way out would be strictly worse.
"""
from __future__ import annotations

import os

import json
from typing import Any, Callable, Dict, Optional, Tuple

#: Platforms where the principal is the whole gate, so pinning is mandatory.
#: Mirrors ``byok-sandbox/byok_platforms.AWS_IAM_ONLY_TEE_PLATFORMS``; kept as a
#: literal because the sandbox is not importable from the installed package.
IAM_ONLY_AWS_PLATFORMS = frozenset({"snp-aws", "gpu-cc-aws"})

#: Sid of the statement this module owns. Rewriting by Sid rather than by index
#: means an operator's extra statements on the key survive untouched.
DECRYPT_SID = "AllowTeeInstanceRoleDecrypt"

#: Sid of the DescribeKey companion, split out only when PCRs are pinned. Owned
#: by this module on the same terms as :data:`DECRYPT_SID`: rewritten and removed
#: by Sid, so an operator's own statements are never touched.
DESCRIBE_SID = "AllowTeeInstanceRoleDescribeKey"

#: Sids of the explicit-Deny statements that make the measurement gate real.
#: Owned by this module and rewritten/removed by Sid, like the Allow pair.
DENY_UNATTESTED_SID = "DenyDecryptWithoutNitroTpmAttestation"
DENY_MISMATCH_SID_PREFIX = "DenyDecryptOnNitroTpmMismatch"


class KeyPolicyPinError(RuntimeError):
    """The BYOK key could not be pinned to this deploy's instance role."""


def _kms_client(region: str):
    import boto3  # imported lazily so non-AWS deploys need no boto3
    return boto3.client("kms", region_name=region)


def pin_statement(policy: Dict[str, Any], role_arn: str, account_id: str,
                  pcr_values: Optional[Dict[str, str]] = None,
                  pcrs: Optional[Any] = None,
                  ) -> Dict[str, Any]:
    """Return *policy* with the decrypt statement pinned to *role_arn*.

    Replaces the statement carrying :data:`DECRYPT_SID`, or appends one when the
    key was created with no decrypt grant at all — which is the recommended way
    to create these keys now, since a key that grants nothing until pinned has
    no window in which it is broadly readable.

    ``ArnEquals`` on the exact ARN, never ``ArnLike``: the whole point is to
    stop a name pattern standing in for an identity.

    When *pcr_values* is supplied the statement additionally carries
    ``kms:RecipientAttestation:NitroTPMPCR<n>`` equality conditions, which
    upgrades the gate from "this role is asking" to "this role, on an instance
    that booted this image". The identity condition stays: the two are
    complementary, and dropping the ARN check would let any attested instance in
    the account decrypt.

    Note what adding these conditions does to an unattested caller — KMS
    documents it plainly: "If the request does not include an attestation
    document, permission is denied because this condition is not satisfied." So
    a key pinned this way is unusable by a release path that does not attach a
    document, which is why the caller only pins PCRs when the deploy recorded
    that the image can produce one.
    """
    identity: Dict[str, Any] = {
        "StringEquals": {"kms:CallerAccount": account_id},
        "ArnEquals": {"aws:PrincipalArn": role_arn},
    }

    if not pcr_values:
        new_statements = [{
            "Sid": DECRYPT_SID,
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["kms:Decrypt", "kms:DescribeKey"],
            "Resource": "*",
            "Condition": identity,
        }]
    else:
        from tee_crafter.core.keys.nitrotpm import pcr_conditions

        # StringEqualsIgnoreCase per the AWS example: PCR digests are hex, and a
        # case-sensitive compare would turn a cosmetic difference into a denial.
        attested = dict(identity)
        attested["StringEqualsIgnoreCase"] = pcr_conditions(pcr_values, pcrs)

        # Two Allow statements, deliberately. The NitroTPM condition keys apply
        # to Decrypt, DeriveSharedSecret, GenerateDataKey, GenerateDataKeyPair
        # and GenerateRandom — *not* to DescribeKey, which has no Recipient
        # parameter and so can never present an attestation document. Leaving
        # DescribeKey in the attested statement would deny it outright, because
        # the condition key is absent from that request's context and an
        # equality condition on an absent key does not match.
        new_statements = [
            {
                "Sid": DECRYPT_SID,
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["kms:Decrypt"],
                "Resource": "*",
                "Condition": attested,
            },
            {
                "Sid": DESCRIBE_SID,
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["kms:DescribeKey"],
                "Resource": "*",
                "Condition": identity,
            },
        ]

        # --- and now the part that makes the gate actually gate ---
        #
        # A conditional *Allow* does not restrict anything on its own. KMS
        # authorises a request if ANY statement allows it, and a key policy
        # statement naming the account root delegates to IAM — so a caller whose
        # identity policy grants kms:Decrypt is authorised by that path and the
        # conditions above are never consulted.
        #
        # This is not hypothetical. Verified against live KMS on 2026-08-24 with
        # a real NitroTPM document: with the conditional Allow in place, a
        # decrypt carrying **no attestation document at all** succeeded, and so
        # did one against a policy pinned to a deliberately wrong PCR4. The
        # deciding statement was the account-root delegation that AWS puts in
        # every default key policy, combined with an identity policy granting
        # kms:Decrypt -- which is exactly what
        # ``aws_iam_role_policy.snp_byok_kms_decrypt`` gives the instance role.
        # The gate reported kms-enforced and enforced nothing.
        #
        # An explicit Deny is the only construct that fixes it, because Deny
        # beats every Allow regardless of which statement or policy it came from.
        #
        # Two shapes are needed, and they cannot be merged. Condition keys
        # within one block are AND-ed, so a single StringNotEquals naming both
        # PCRs would deny only when *both* differ -- a request matching PCR4 but
        # not PCR7 would sail through. Hence one mismatch statement per register,
        # plus a Null statement for "no document at all" (a non-IfExists
        # operator does not match an absent key, so the mismatch statements
        # cannot catch that case).
        #
        # Scoped to kms:Decrypt only. Encrypt must keep working -- the operator
        # wraps the DEK from a workstation that has no TPM -- and the key has to
        # stay manageable (PutKeyPolicy, ScheduleKeyDeletion), so a blanket
        # Deny on kms:* would brick it.
        #
        # Consequence worth stating plainly: this Deny binds ``Principal: "*"``,
        # so it applies to the account root and to every administrator. Once a
        # key is pinned this way, ciphertext under it is undecryptable by anyone
        # until the policy is re-pinned to the new measurements. That is the
        # intended posture for a workload DEK -- it is what "measurement-gated"
        # has to mean -- but it removes operator break-glass, and a re-bake that
        # moves PCR4 will require re-pinning before the workload can start.
        conditions = attested["StringEqualsIgnoreCase"]
        first_key = sorted(conditions)[0]
        new_statements.append({
            "Sid": DENY_UNATTESTED_SID,
            "Effect": "Deny",
            "Principal": "*",
            "Action": ["kms:Decrypt"],
            "Resource": "*",
            # Matches when the condition key is absent from the request context,
            # i.e. no NitroTPM attestation document was attached.
            "Condition": {"Null": {first_key: "true"}},
        })
        for index, (condition_key_name, expected) in enumerate(
                sorted(conditions.items())):
            new_statements.append({
                "Sid": f"{DENY_MISMATCH_SID_PREFIX}{index}",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["kms:Decrypt"],
                "Resource": "*",
                "Condition": {
                    "StringNotEqualsIgnoreCase": {condition_key_name: expected},
                },
            })

    # Sweep the Deny statements too. A re-pin after a re-bake must not leave a
    # stale Deny naming the *previous* image's PCRs, which would deny the new
    # image's perfectly valid attestation.
    owned = {DECRYPT_SID, DESCRIBE_SID, DENY_UNATTESTED_SID}
    out = dict(policy)
    def _is_ours(stmt) -> bool:
        sid = stmt.get("Sid") if isinstance(stmt, dict) else None
        if not isinstance(sid, str):
            return False
        return sid in owned or sid.startswith(DENY_MISMATCH_SID_PREFIX)

    statements = [s for s in (policy.get("Statement") or [])
                  if not _is_ours(s)]
    statements.extend(new_statements)
    out["Statement"] = statements
    out.setdefault("Version", "2012-10-17")
    return out


def nitrotpm_pcrs_for_image(tee_platform: str, image_id: str) -> Dict[str, str]:
    """NitroTPM PCRs the bake recorded for *image_id*, or ``{}``.

    Returning ``{}`` is the honest answer for every image baked before the
    capture existed, or one whose ``RegisterImage`` did not set
    ``TpmSupport=v2.0``. The caller then pins identity only, and the gating table
    reports ``iam-scoped`` rather than claiming a measurement gate that is not
    there.
    """
    if not image_id:
        return {}
    try:
        from tee_crafter.core.measurements import registry as _registry
        record = _registry.lookup(tee_platform, image_id) or {}
    except Exception:
        return {}
    pcrs = record.get("nitrotpm_pcrs")
    if isinstance(pcrs, dict) and pcrs:
        return {str(k): str(v) for k, v in pcrs.items()}
    # Fall back to a variant-level copy: the record-level field was added after
    # the per-variant one, so a record written in between has only the latter.
    for variant in record.get("variants") or []:
        candidate = variant.get("nitrotpm_pcrs") if isinstance(variant, dict) else None
        if isinstance(candidate, dict) and candidate:
            return {str(k): str(v) for k, v in candidate.items()}
    return {}


def instance_role_arn_from_outputs(outputs: Dict[str, Any]) -> str:
    """Read the role ARN Terraform published, or ``""``.

    Requires the ``instance_role_arn`` output added to the ``snp/aws`` and
    ``gpu_cc/aws`` templates. Older build directories predate it; the caller
    reports that as a pinning failure rather than proceeding unpinned.
    """
    value = (outputs or {}).get("instance_role_arn") or ""
    value = str(value).strip()
    return value if value.startswith("arn:") and ":role/" in value else ""


def pin_byok_key_after_apply(*, console, build_dir: str, tee_platform: str,
                            outputs: Dict[str, Any],
                            audit: Any = None) -> Tuple[bool, str]:
    """Pin the BYOK key right after a successful apply, for any flow.

    ``pin_byok_key_to_instance_role`` was reachable from exactly one call site --
    the ``snp-aws`` *service* phase -- so the container flows (both ``--batch``
    and the persistent container path) accepted ``--byok aws-kms`` and never
    rewrote the key policy. Measured 2026-08-24: a batch deploy with
    ``unwrap=aws_nitrotpm_recipient`` completed successfully against a key still
    carrying its default ``kms:*`` policy. No measurement condition, no
    ``ArnEquals`` narrowing to the instance role, and no refusal -- while the
    service phase treats exactly that state as fatal.

    This wrapper resolves the region and AMI from the deploy environment the same
    way the service phase does, so both paths reach identical behaviour from one
    implementation.
    """
    region = (os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION")
              or os.getenv("AWS_DEFAULT_REGION") or "us-east-2")
    ami_id = (os.getenv("TF_VAR_ami_id") or os.getenv("TEE_CRAFTER_AMI_ID") or "")
    return pin_byok_key_to_instance_role(
        console=console, build_dir=build_dir, tee_platform=tee_platform,
        outputs=outputs, region=region, audit=audit, ami_id=ami_id)


def pin_byok_key_to_instance_role(
    *,
    console,
    build_dir: str,
    tee_platform: str,
    outputs: Dict[str, Any],
    region: str,
    ami_id: str = "",
    audit: Any = None,
    kms_client: Optional[Any] = None,
    read_byok_config: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
) -> Tuple[bool, str]:
    """Pin this deploy's BYOK key to the role Terraform just created.

    Returns ``(ok, detail)``. ``ok`` is ``True`` when there was nothing to do —
    BYOK off, a non-AWS provider, or a platform that has a real attestation
    condition (``nitro-aws`` gates on ``kms:RecipientAttestation:PCR*``, so its
    policy must not be rewritten into an identity check).
    """
    if tee_platform not in IAM_ONLY_AWS_PLATFORMS:
        return True, "not an identity-gated AWS platform"

    reader = read_byok_config or _read_byok_config
    cfg = reader(build_dir)
    if not cfg:
        return True, "BYOK not configured"
    if (cfg.get("provider") or "").lower() != "aws-kms":
        return True, f"BYOK provider is {cfg.get('provider')!r}, not aws-kms"

    key_id = (cfg.get("key_id") or "").strip()
    if not key_id:
        return False, "BYOK config has no key_id"

    role_arn = instance_role_arn_from_outputs(outputs)
    if not role_arn:
        return False, (
            "Terraform published no usable `instance_role_arn` output, so the "
            "BYOK key cannot be pinned to this instance. Re-generate the "
            "Terraform for this build (the output was added 2026-08-23).")

    account_id = role_arn.split(":")[4] if role_arn.count(":") >= 4 else ""
    if not account_id:
        return False, f"could not read an account id out of {role_arn!r}"

    client = kms_client or _kms_client(region or cfg.get("region") or "us-east-2")
    try:
        current = json.loads(
            client.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    except Exception as exc:
        return False, f"could not read the current key policy: {exc}"

    # Measurement conditions, but only when the runtime will actually attach an
    # attestation document. These two must ship together or not at all: once
    # kms:RecipientAttestation:NitroTPMPCR* is on the key, KMS denies every
    # request whose Recipient lacks a document, so pinning PCRs against a
    # direct_bytes runtime would take BYOK from weakly-gated to non-functional.
    pcr_values: Dict[str, str] = {}
    wants_attested = (cfg.get("unwrap") or "") == "aws_nitrotpm_recipient"
    if wants_attested:
        pcr_values = nitrotpm_pcrs_for_image(tee_platform, ami_id)
        if not pcr_values:
            # Fail closed rather than silently downgrading. The operator asked
            # for measurement-gated release; giving them an identity-gated key
            # that *looks* configured is the worse outcome.
            return False, (
                "byok-config asks for unwrap=aws_nitrotpm_recipient, but no "
                f"NitroTPM PCRs are recorded for image {ami_id or '(unknown)'}. "
                "Re-bake with --enable-secure-boot so the AMI is registered "
                "with TpmSupport=v2.0 and the capture step records PCR4/PCR7, "
                "or set unwrap=direct_bytes to accept identity-gated release.")

    updated = pin_statement(current, role_arn, account_id,
                            pcr_values=pcr_values or None)
    if updated == current:
        detail = f"already pinned to {role_arn}"
        console.print(f"[dim]  BYOK key policy {detail}.[/dim]")
        return True, detail

    try:
        client.put_key_policy(KeyId=key_id, PolicyName="default",
                              Policy=json.dumps(updated))
    except Exception as exc:
        return False, f"PutKeyPolicy failed: {exc}"

    console.print(
        f"[green]✓ BYOK key pinned to this deploy's instance role[/green]\n"
        f"[dim]  {role_arn}[/dim]")
    if audit:
        audit.record(
            "Phase 4: Deployment", "BYOK key policy pinned to instance role",
            "pass", tee_platform=tee_platform, instance_role_arn=role_arn,
            byok_key_id=key_id,
            note="ArnEquals on the exact per-deploy role; no wildcard",
        )
    return True, f"pinned to {role_arn}"


def unwrap_staged_config(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Return the flat BYOK settings from either shape of ``byok.json``.

    The staged file is an envelope — ``{"provider", "enabled", "describe",
    "config": {...}}`` — with the settings that matter (``key_id``, ``region``,
    ``unwrap``) one level in. The operator-facing ``--byok-config`` file is
    flat. Reading only the flat shape found the envelope, saw no ``key_id``,
    and aborted a live ``snp-aws`` deploy with "BYOK config has no key_id"
    (2026-08-23) — a fail-closed abort, but on a file that was perfectly fine.
    """
    inner = doc.get("config")
    if isinstance(inner, dict) and inner.get("key_id"):
        merged = dict(inner)
        # The envelope's provider wins: it is what the deploy actually selected.
        merged.setdefault("provider", doc.get("provider"))
        if doc.get("provider"):
            merged["provider"] = doc["provider"]
        return merged
    return doc


def _read_byok_config(build_dir: str) -> Optional[Dict[str, Any]]:
    """Load the staged ``byok.json``, or ``None`` when BYOK is off."""
    import os

    from tee_crafter.core.audit import build_layout as _layout

    candidates = []
    for getter in ("byok_config", "byok_json"):
        fn = getattr(_layout, getter, None)
        if callable(fn):
            try:
                candidates.append(fn(build_dir))
            except Exception:
                pass
    candidates += [
        os.path.join(build_dir, "byok", "byok.json"),
        os.path.join(build_dir, "byok.json"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    doc = json.load(f)
            except (OSError, ValueError):
                continue
            if isinstance(doc, dict) and doc.get("provider"):
                if doc.get("enabled") is False:
                    return None
                return unwrap_staged_config(doc)
    return None
