"""Verify Microsoft Azure Attestation (MAA) tokens for confidential VMs.

**Two endpoints, two token shapes, and the difference is not cosmetic.**

``/attest/TdxVm`` verifies an Intel **DCAP quote** and issues a token whose TDX
claims are *flat* (``tdx_mrtd``, ``tdx_rtmr0``…).  ``/attest/AzureGuest``
consumes the Azure guest-attestation blob and issues a token whose hardware
verdict is *nested* under ``x-ms-isolation-tee``, with the guest's own data in a
top-level ``x-ms-runtime``.  Both claim sets are taken from Microsoft's
published examples rather than from memory:
https://learn.microsoft.com/en-us/azure/attestation/attestation-token-examples
https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp

Which one applies is a property of the *platform*, not a preference:

* **Azure CVMs (paravisor)** — ``tdx-azure``, ``snp-azure``.  The guest cannot
  get a DCAP quote.  The vTPM hands out a raw 1024-byte ``TDREPORT`` at offset
  32 of NV ``0x01400001``, MAC'd with a key only the TDX module and the Quoting
  Enclave hold.  ``/attest/TdxVm`` answers 400 to it, correctly.  Use
  :func:`azure_guest_token` + :func:`verify_maa_azure_guest_token`.
* **Anywhere a TD can quote itself** — ``tdx-gcp``, bare metal.  Use
  :func:`attest_tdx_dcap_quote` + :func:`verify_maa_tdx_token`, or skip MAA and
  verify against Intel's CA directly, which is what ``tdx-gcp`` does.

The AzureGuest path also moves **where the channel binding lives**.  On the DCAP
path we choose ``report_data`` and bind the session into the hardware report.  On
a paravisor CVM ``report_data`` is already spent on the paravisor's hash of its
own runtime claims, so the binding travels in
``x-ms-runtime.client-payload.nonce`` instead.  That is a weaker place to stand
— it is bound by MAA's signature over a value the guest supplied, not by the
hardware — and it is the strongest binding this platform offers.  Stated plainly
here because the previous code bound nothing at all on this path and looked
identical.

What a valid token asserts, and therefore what is checked here:

===========================  ==========================================
``x-ms-attestation-type``    ``tdxvm`` — this is a TDX VM, not SGX or SNP
``x-ms-compliance-status``   ``azure-compliant-cvm`` — MAA's own verdict
``tdx_mrtd`` / ``tdx_rtmrN`` the measurements to pin the workload to
``tdx_report_data``          64 bytes binding guest-chosen data (the
                             RA-TLS key hash) into the hardware report
``tdx_td_attributes_debug``  must be false; a debug TD is not production
``attester_tcb_status``      Intel's TCB verdict as MAA resolved it
===========================  ==========================================

Two attacks this deliberately closes:

* **Algorithm confusion / unsigned tokens.** ``alg`` is pinned to RS256 and the
  key comes from the JWKS, so ``{"alg":"none"}`` and HMAC-with-the-public-key
  are both rejected before any claim is read.
* **JWKS redirection.** The header's ``jku`` is advisory and attacker-influenced
  if the token is; it is checked against the expected issuer rather than
  followed. The caller supplies the JWKS it fetched from the issuer it chose.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence

#: ``x-ms-attestation-type`` for an Intel TDX confidential VM.
TDX_ATTESTATION_TYPE = "tdxvm"

#: ``x-ms-compliance-status`` MAA issues for a CVM that met its policy.
COMPLIANT_CVM = "azure-compliant-cvm"

#: Top-level ``x-ms-attestation-type`` of an ``/attest/AzureGuest`` token.  The
#: hardware verdict is *not* here -- it is nested under
#: :data:`ISOLATION_TEE_CLAIM`.  Checking only this one would accept a
#: non-confidential Trusted Launch VM, which also attests as ``azurevm``.
AZURE_GUEST_ATTESTATION_TYPE = "azurevm"

#: The nested object holding the hardware (SNP/TDX) verdict in an AzureGuest
#: token.  Named because Key Vault release policies address claims through it
#: (``x-ms-isolation-tee.x-ms-attestation-type``), so this string is part of the
#: contract with the SKR policy, not an implementation detail.
ISOLATION_TEE_CLAIM = "x-ms-isolation-tee"

#: MAA signs with RS256.  Pinned so a token cannot choose its own algorithm.
REQUIRED_ALG = "RS256"

#: The four TDX runtime measurement registers, in order.
RTMR_CLAIMS = ("tdx_rtmr0", "tdx_rtmr1", "tdx_rtmr2", "tdx_rtmr3")


class MaaVerificationError(ValueError):
    """The MAA token is absent, malformed, unsigned, or says the wrong thing."""


@dataclass(frozen=True)
class MaaVerdict:
    """What a verified token asserts.  Only built after every check passes."""

    issuer: str
    mrtd: str
    rtmrs: tuple
    report_data: str
    tcb_status: str
    compliance_status: str
    debug: bool
    runtime_keys: tuple = ()
    """``x-ms-runtime.keys`` — for SKR this carries ``HCLTransferKey``, the RSA
    public key Managed HSM wraps the released DEK to."""
    claims: Dict[str, Any] = field(default_factory=dict)


def expected_issuer_for(endpoint: str) -> str:
    """Normalise an MAA endpoint to the ``iss`` it will put in tokens."""
    return endpoint.rstrip("/")


def jwks_url_for(endpoint: str) -> str:
    return f"{expected_issuer_for(endpoint)}/certs"


def verify_maa_tdx_token(
    token: str,
    *,
    expected_issuer: str,
    jwks: Dict[str, Any],
    expected_mrtd: str = "",
    expected_rtmrs: Optional[Sequence[str]] = None,
    expected_report_data: str = "",
    now: Optional[float] = None,
    leeway_seconds: int = 60,
) -> MaaVerdict:
    """Verify *token* and return what it asserts, or raise.

    *jwks* is the parsed document the caller fetched from
    :func:`jwks_url_for`; fetching is the caller's job so this stays offline
    and testable.

    Empty ``expected_*`` values mean "report it, do not pin it" — pinning is the
    caller's policy decision. Everything else is mandatory.
    """
    claims = _decode_verified_claims(
        token, expected_issuer=expected_issuer, jwks=jwks, now=now,
        leeway_seconds=leeway_seconds)

    att_type = claims.get("x-ms-attestation-type", "")
    if att_type != TDX_ATTESTATION_TYPE:
        raise MaaVerificationError(
            f"x-ms-attestation-type is {att_type!r}, expected "
            f"{TDX_ATTESTATION_TYPE!r} — this token is not for a TDX VM")

    compliance = claims.get("x-ms-compliance-status", "")
    if compliance != COMPLIANT_CVM:
        raise MaaVerificationError(
            f"x-ms-compliance-status is {compliance!r}, expected "
            f"{COMPLIANT_CVM!r} — MAA did not consider this VM compliant")

    if claims.get("tdx_td_attributes_debug") is True:
        raise MaaVerificationError(
            "TD_ATTRIBUTES marks this a DEBUG trust domain; refusing "
            "production connection")
    if str(claims.get("dbgstat", "disabled")).lower() != "disabled":
        raise MaaVerificationError(
            f"dbgstat is {claims.get('dbgstat')!r}, expected 'disabled'")

    mrtd = str(claims.get("tdx_mrtd", "")).lower()
    if not mrtd:
        raise MaaVerificationError("token carries no tdx_mrtd")
    if expected_mrtd and mrtd != expected_mrtd.lower():
        raise MaaVerificationError(
            f"MRTD mismatch: token has {mrtd}, expected {expected_mrtd.lower()}")

    rtmrs = tuple(str(claims.get(name, "")).lower() for name in RTMR_CLAIMS)
    if expected_rtmrs:
        for idx, want in enumerate(expected_rtmrs):
            if not want:
                continue
            if rtmrs[idx] != want.lower():
                raise MaaVerificationError(
                    f"RTMR{idx} mismatch: token has {rtmrs[idx]}, "
                    f"expected {want.lower()}")

    report_data = str(claims.get("tdx_report_data", "")).lower()
    if expected_report_data and report_data != expected_report_data.lower():
        raise MaaVerificationError(
            "tdx_report_data does not match the expected channel binding; "
            "this token is for a different session")

    runtime = claims.get("x-ms-runtime") or {}
    keys = runtime.get("keys") if isinstance(runtime, dict) else None

    return MaaVerdict(
        issuer=str(claims.get("iss", "")),
        mrtd=mrtd,
        rtmrs=rtmrs,
        report_data=report_data,
        tcb_status=str(claims.get("attester_tcb_status", "")),
        compliance_status=compliance,
        debug=bool(claims.get("tdx_td_attributes_debug", False)),
        runtime_keys=tuple(keys) if isinstance(keys, list) else (),
        claims=claims,
    )


def _decode_verified_claims(
    token: str,
    *,
    expected_issuer: str,
    jwks: Dict[str, Any],
    now: Optional[float] = None,
    leeway_seconds: int = 60,
) -> Dict[str, Any]:
    """Signature/issuer/expiry hardening shared by both token shapes.

    One copy on purpose.  ``/attest/TdxVm`` and ``/attest/AzureGuest`` differ
    only in the *claims* they carry; the JWT layer beneath is identical, and two
    JWT verifiers drifting apart is how a bypass gets in (this repository has
    already shipped one such drift in its DCAP verifiers).  Everything here is
    about refusing a token, so the claim readers above can assume a token that
    MAA actually signed.
    """
    import jwt as _jwt

    if not token or not isinstance(token, str):
        raise MaaVerificationError("no MAA token supplied")
    issuer = expected_issuer_for(expected_issuer)
    if not issuer.startswith("https://"):
        raise MaaVerificationError(
            f"MAA issuer must be https, got {issuer!r}")

    try:
        header = _jwt.get_unverified_header(token)
    except Exception as exc:
        raise MaaVerificationError(f"token header is not valid JWT: {exc}") from exc

    alg = header.get("alg", "")
    if alg != REQUIRED_ALG:
        raise MaaVerificationError(
            f"MAA token alg is {alg!r}; only {REQUIRED_ALG} is accepted "
            "(refusing alg-confusion and unsigned tokens)")

    # `jku` points at the JWKS.  Never followed -- checked, so a token cannot
    # nominate its own key source.
    jku = header.get("jku", "")
    if jku and not jku.startswith(issuer + "/"):
        raise MaaVerificationError(
            f"token's jku {jku!r} is not under the expected issuer {issuer!r}")

    kid = header.get("kid", "")
    signing_key = _signing_key(jwks, kid)

    try:
        claims = _jwt.decode(
            token,
            signing_key,
            algorithms=[REQUIRED_ALG],
            issuer=issuer,
            leeway=leeway_seconds,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_iss": True,
                "require": ["iss", "exp", "nbf"],
            },
        )
    except _jwt.InvalidSignatureError as exc:
        raise MaaVerificationError(
            f"MAA token signature does not verify against the JWKS: {exc}") from exc
    except _jwt.ExpiredSignatureError as exc:
        raise MaaVerificationError(f"MAA token has expired: {exc}") from exc
    except Exception as exc:
        raise MaaVerificationError(f"MAA token rejected: {exc}") from exc

    # `now` is honoured explicitly as well: PyJWT reads the wall clock, and a
    # test that pins time must be able to say so.
    if now is not None:
        exp = float(claims.get("exp", 0))
        if now > exp + leeway_seconds:
            raise MaaVerificationError("MAA token has expired")
        nbf = float(claims.get("nbf", 0))
        if now + leeway_seconds < nbf:
            raise MaaVerificationError("MAA token is not yet valid")

    return claims


def expected_client_payload_nonces(binding: bytes) -> tuple:
    """The ``client-payload.nonce`` values a token may carry for *binding*.

    Two forms are accepted because the producer is Microsoft's
    ``AttestationClient``, not us, and it is the one that encodes the value.
    Its documented sample shows ``-n 1234`` arriving as
    ``"nonce": "MTIzNA=="`` -- base64 of the argument -- while the SKR sample
    app's README describes ``-n`` as free-form JSON passed through.  Rather than
    guess which applies to the binary version we baked, both the literal hex and
    its base64 encoding are accepted.

    This does not weaken the binding.  Both candidates are derived from the same
    32-byte digest, so a forger still has to make MAA sign a token containing one
    of two exact values it could only learn from this session.  What it avoids is
    a hard failure on an encoding detail, which is the failure mode that has cost
    the most live runs on this platform.
    """
    import base64

    hex_form = binding.hex()
    return (hex_form,
            base64.b64encode(hex_form.encode("ascii")).decode("ascii"),
            base64.b64encode(binding).decode("ascii"))


def verify_maa_azure_guest_token(
    token: str,
    *,
    expected_issuer: str,
    jwks: Dict[str, Any],
    expected_binding: bytes = b"",
    expected_isolation_type: str = TDX_ATTESTATION_TYPE,
    expected_mrtd: str = "",
    expected_rtmrs: Optional[Sequence[str]] = None,
    now: Optional[float] = None,
    leeway_seconds: int = 60,
) -> MaaVerdict:
    """Verify an ``/attest/AzureGuest`` token, or raise.

    This is the token shape Azure confidential VMs actually produce, and the
    only one that works on a paravisor-based CVM.  The guest cannot obtain an
    Intel DCAP quote there -- the vTPM hands out a *raw* ``TDREPORT`` (1024
    bytes at offset 32 of NV ``0x01400001``, per Microsoft's attestation report
    format table), whose ``REPORTMACSTRUCT`` is MAC'd with a key only the TDX
    module and the Quoting Enclave hold.  ``/attest/TdxVm`` wants a quote, so it
    answers 400 to a report; that is not a nesting bug and no amount of
    reshaping the body fixes it.

    Two structural differences from :func:`verify_maa_tdx_token` decide the
    checks below:

    * **The hardware verdict is nested** under ``x-ms-isolation-tee``.  The
      top-level ``x-ms-attestation-type`` is ``azurevm``, which a plain Trusted
      Launch VM also earns -- so checking only the outer claim would accept a VM
      with no memory encryption at all.  Both levels are therefore required.
    * **The channel binding is in ``x-ms-runtime.client-payload.nonce``**, not in
      ``report_data``.  On this path ``report_data`` is spent by the paravisor on
      the hash of its own runtime claims and is not ours to set, so binding
      through it is impossible.  Passing ``expected_binding`` is what turns this
      from "an Azure CVM exists somewhere" into "this session terminates inside
      it"; it is empty only for callers that have no session to bind.

    ``runtime_keys`` comes back from the **top-level** ``x-ms-runtime.keys``,
    which is where Key Vault looks for the key-encryption key
    (``TpmEphemeralEncryptionKey``).  Deliberately not the copy under
    ``x-ms-isolation-tee.x-ms-runtime.keys`` -- Microsoft's walkthrough says of
    that one "this is **not** the key that Key Vault will be using".
    https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp
    """
    claims = _decode_verified_claims(
        token, expected_issuer=expected_issuer, jwks=jwks, now=now,
        leeway_seconds=leeway_seconds)

    outer_type = str(claims.get("x-ms-attestation-type", ""))
    if outer_type != AZURE_GUEST_ATTESTATION_TYPE:
        raise MaaVerificationError(
            f"top-level x-ms-attestation-type is {outer_type!r}, expected "
            f"{AZURE_GUEST_ATTESTATION_TYPE!r} — this is not an AzureGuest token")

    tee = claims.get(ISOLATION_TEE_CLAIM)
    if not isinstance(tee, dict) or not tee:
        raise MaaVerificationError(
            f"token carries no {ISOLATION_TEE_CLAIM!r} object, so it makes no "
            "claim about confidential hardware at all. A Trusted Launch VM "
            "attests as 'azurevm' too; refusing to treat this as a CVM.")

    tee_type = str(tee.get("x-ms-attestation-type", ""))
    if tee_type != expected_isolation_type:
        raise MaaVerificationError(
            f"{ISOLATION_TEE_CLAIM}.x-ms-attestation-type is {tee_type!r}, "
            f"expected {expected_isolation_type!r}")

    compliance = str(tee.get("x-ms-compliance-status", ""))
    if compliance != COMPLIANT_CVM:
        raise MaaVerificationError(
            f"{ISOLATION_TEE_CLAIM}.x-ms-compliance-status is {compliance!r}, "
            f"expected {COMPLIANT_CVM!r} — MAA did not consider this VM a "
            "compliant Azure confidential VM")

    if tee.get("tdx_td_attributes_debug") is True:
        raise MaaVerificationError(
            "TD_ATTRIBUTES marks this a DEBUG trust domain; refusing "
            "production connection")
    if tee.get("x-ms-sevsnpvm-is-debuggable") is True:
        raise MaaVerificationError(
            "x-ms-sevsnpvm-is-debuggable is true; refusing production connection")
    dbgstat = str(tee.get("dbgstat", "disabled")).lower()
    if dbgstat != "disabled":
        raise MaaVerificationError(
            f"dbgstat is {dbgstat!r}, expected 'disabled'")

    mrtd = str(tee.get("tdx_mrtd", "")).lower()
    if expected_isolation_type == TDX_ATTESTATION_TYPE:
        if not mrtd:
            raise MaaVerificationError(
                f"{ISOLATION_TEE_CLAIM} carries no tdx_mrtd")
        if expected_mrtd and mrtd != expected_mrtd.lower():
            raise MaaVerificationError(
                f"MRTD mismatch: token has {mrtd}, "
                f"expected {expected_mrtd.lower()}")

    rtmrs = tuple(str(tee.get(name, "")).lower() for name in RTMR_CLAIMS)
    if expected_rtmrs:
        for idx, want in enumerate(expected_rtmrs):
            if not want:
                continue
            if rtmrs[idx] != want.lower():
                raise MaaVerificationError(
                    f"RTMR{idx} mismatch: token has {rtmrs[idx]}, "
                    f"expected {want.lower()}")

    runtime = claims.get("x-ms-runtime")
    runtime = runtime if isinstance(runtime, dict) else {}
    payload = runtime.get("client-payload")
    payload = payload if isinstance(payload, dict) else {}
    nonce = str(payload.get("nonce", ""))

    if expected_binding:
        if not nonce:
            raise MaaVerificationError(
                "token carries no x-ms-runtime.client-payload.nonce, so nothing "
                "ties it to this session. An unbound token attests that some "
                "Azure CVM exists, not that this channel terminates in one.")
        if nonce not in expected_client_payload_nonces(expected_binding):
            raise MaaVerificationError(
                "x-ms-runtime.client-payload.nonce does not match this "
                "session's attestation binding; this token was issued for a "
                "different session")

    keys = runtime.get("keys")

    return MaaVerdict(
        issuer=str(claims.get("iss", "")),
        mrtd=mrtd,
        rtmrs=rtmrs,
        report_data=str(tee.get("tdx_report_data", "")).lower(),
        tcb_status=str(tee.get("attester_tcb_status", "")),
        compliance_status=compliance,
        debug=bool(tee.get("tdx_td_attributes_debug", False)),
        runtime_keys=tuple(keys) if isinstance(keys, list) else (),
        claims=claims,
    )


def _signing_key(jwks: Dict[str, Any], kid: str):
    """Resolve the JWKS entry for *kid* into a public key.

    No "first RSA key" fallback: MAA rotates signing keys and publishes several
    at once, so accepting whichever happens to be first would verify a token
    against a key that did not sign it — sometimes.  A missing ``kid`` is an
    error, not an invitation to guess.
    """
    from jwt import PyJWK

    keys = (jwks or {}).get("keys")
    if not isinstance(keys, list) or not keys:
        raise MaaVerificationError("MAA JWKS has no `keys` array")
    if not kid:
        raise MaaVerificationError(
            "MAA token header has no `kid`; refusing to guess which of the "
            f"{len(keys)} published keys signed it")
    for entry in keys:
        if isinstance(entry, dict) and entry.get("kid") == kid:
            try:
                return PyJWK(entry).key
            except Exception as exc:
                raise MaaVerificationError(
                    f"JWKS entry for kid={kid!r} is not a usable key: {exc}") from exc
    raise MaaVerificationError(
        f"no JWKS entry for kid={kid!r} (JWKS publishes "
        f"{[k.get('kid') for k in keys if isinstance(k, dict)]})")


#: Default path of Microsoft's guest-attestation binary, baked by
#: ``scripts/tdx_azure/setup_tdx.sh``.  Overridable so a test can point at a
#: stub and so an image that stages it elsewhere is not forced to patch code.
ATTESTATION_CLIENT_ENV = "TEE_CRAFTER_ATTESTATION_CLIENT"
ATTESTATION_CLIENT_DEFAULT = "/usr/local/bin/AttestationClient"


def attestation_client_path() -> str:
    """Resolve the guest-attestation binary, honouring the env override."""
    import os

    return (os.environ.get(ATTESTATION_CLIENT_ENV) or "").strip() \
        or ATTESTATION_CLIENT_DEFAULT


def azure_guest_token(
    *,
    endpoint: str,
    binding: bytes = b"",
    binary: Optional[str] = None,
    run=None,
    timeout: int = 60,
) -> str:
    """Obtain an ``/attest/AzureGuest`` token from inside the CVM.

    Shells out to Microsoft's ``AttestationClient`` because the request body for
    that endpoint is a single opaque ``attestationInfo`` blob -- protocol
    version 2.0, carrying the TPM quote, the TCG event log, the vTPM AK
    certificate and the HCL hardware report.  It is not a documented wire
    format, and hand-building it is how you get a 400 that no amount of local
    testing predicts.  The library that builds it (``azguestattestation1``) is
    the same one whose TPM-sealed private key later unwraps a Secure Key
    Release, so it is a dependency this platform needs regardless.

    ``binding`` is the 32-byte session binding digest; it is passed as the
    client payload nonce and is what :func:`verify_maa_azure_guest_token` checks.
    Omitting it yields a token that proves a CVM exists but binds no channel,
    which is why the caller here always supplies one.

    Returns the raw JWT.  ``run`` is injectable for tests; the default uses
    ``subprocess``.
    """
    exe = binary or attestation_client_path()
    argv = [exe, "-a", expected_issuer_for(endpoint), "-o", "token"]
    if binding:
        argv += ["-n", binding.hex()]

    if run is None:
        import subprocess

        def run(argv_):  # type: ignore[misc]
            proc = subprocess.run(argv_, capture_output=True, timeout=timeout)
            return (proc.returncode,
                    proc.stdout.decode("utf-8", "replace"),
                    proc.stderr.decode("utf-8", "replace"))

    try:
        rc, out, err = run(argv)
    except FileNotFoundError as exc:
        raise MaaVerificationError(
            f"guest-attestation binary {exe!r} is not present. Azure CVMs have "
            "no other way to reach MAA: the vTPM yields a raw TDREPORT that "
            "/attest/TdxVm will not accept. Re-bake the image so setup_tdx.sh "
            f"installs it, or set {ATTESTATION_CLIENT_ENV}.") from exc
    except Exception as exc:
        raise MaaVerificationError(
            f"guest-attestation binary {exe!r} failed to run: {exc}") from exc

    if rc != 0:
        detail = (err or out or "").strip().replace("\n", " ")[:400]
        raise MaaVerificationError(
            f"{exe} exited {rc}: {detail or 'no output'}")

    token = (out or "").strip()
    # The binary prints the bare JWT on stdout for `-o token`; anything else
    # (its own diagnostics, a boolean true/false from a missing `-o`) must not
    # be handed onward as if it were a token.
    #
    # 1200 chars of the failing output, not 40.  A live run on 2026-08-23 died
    # here with MAA's own error envelope on stdout and this message truncated it
    # to `{"error":{"code":"InvalidParameter","mes` — the code was visible and
    # the `message` field, which is the part that says *which* parameter, was
    # not.  The VM was torn down before anything could be re-read, so the 40
    # cost a whole run.  Nothing secret is in scope: on this branch the output
    # is not a token, and a token would have matched the `eyJ` prefix and
    # returned above.
    if not token.startswith("eyJ"):
        detail = token.replace("\n", " ")[:1200]
        # stderr carries the guest-attestation library's own step-by-step trace
        # (the bake re-enables Logger::Log and points it here).  That is where
        # "Failed to retrieve the TD quote from IMDS" and "Empty Quote received
        # from IMDS TD Quote Endpoint" appear -- the difference between "MAA
        # rejected our evidence" and "we never built any evidence to send".
        trace = (err or "").strip().replace("\n", " | ")[-1500:]
        raise MaaVerificationError(
            f"{exe} did not return a JWT; refusing to treat its output as an "
            f"attestation token.\n"
            f"  stdout (<=1200 chars): {detail or '<empty>'}\n"
            f"  stderr trace (last 1500 chars): {trace or '<empty>'}")
    return token


def attest_tdx_dcap_quote(
    *,
    endpoint: str,
    tdx_quote: bytes,
    runtime_data: bytes = b"",
    # `/attest/TdxVm` exists only from this api-version. Measured against the
    # live shared provider on 2026-08-23 -- `2022-08-01` and `2020-10-01` both
    # return a bodiless 404, while `2023-04-01-preview` returns
    # `400 {"code":"InvalidOperation","message":"Quote is empty"}` for an empty
    # body, i.e. the route is there and validating. A real `tdx-azure` deploy
    # had already failed on the 404 with "MAA could not vouch for this VM".
    #
    # `/attest/SevSnpVm` answers on all three, which is the trap: pinning the
    # older version looks fine on SNP and 404s only on TDX.
    api_version: str = "2023-04-01-preview",
    http_post=None,
    timeout: int = 15,
) -> str:
    """POST an Intel **DCAP TD quote** to ``/attest/TdxVm`` and return the JWT.

    ``tdx_quote`` must be a real quote -- ECDSA-signed by the Quoting Enclave
    with a PCK certificate chain, as produced by configfs-tsm or the
    ``/dev/tdx_guest`` ioctl.  The endpoint's own schema calls the field "Quote
    of the TDX virtual machine to be attested", and that is load-bearing:

      This function was previously called ``attest_tdx_hcla`` and was handed the
      2600-byte Azure vTPM envelope.  That cannot work and was never going to.
      Per Microsoft's attestation report format table, offset 32 of NV
      ``0x01400001`` holds a *raw 1024-byte TDREPORT*, not a quote; its
      ``REPORTMACSTRUCT`` is MAC'd with a key held only by the TDX module and the
      Quoting Enclave, so MAA has nothing to verify it against.  Three live
      ``tdx-azure`` runs spent money discovering this as a 404 and then a 400.
      An Azure paravisor CVM has no DCAP path at all, so on that platform use
      :func:`azure_guest_token` instead.
      https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design

    Kept because it is the correct call wherever a TD *can* produce a quote and
    an operator wants MAA rather than Intel as the verifier. The renaming is the
    point: the old name invited exactly the combination that does not exist.

    ``http_post`` is injectable for tests; the default uses ``requests``.
    """
    import base64
    import json

    if tdx_quote[:4] == b"HCLA":
        raise MaaVerificationError(
            "refusing to POST an Azure vTPM HCLA envelope to /attest/TdxVm: "
            "that endpoint verifies Intel DCAP quotes, and the envelope carries "
            "a raw MAC'd TDREPORT which nothing can verify. Use "
            "azure_guest_token() for Azure CVMs.")

    url = f"{expected_issuer_for(endpoint)}/attest/TdxVm?api-version={api_version}"
    body = {
        "quote": base64.urlsafe_b64encode(tdx_quote).decode("ascii").rstrip("="),
    }
    if runtime_data:
        body["runtimeData"] = {
            "data": base64.urlsafe_b64encode(runtime_data).decode("ascii").rstrip("="),
            "dataType": "JSON",
        }

    if http_post is None:
        import requests  # type: ignore

        def http_post(u, payload):  # type: ignore[misc]
            resp = requests.post(u, json=payload, timeout=timeout)
            if resp.status_code >= 400:
                # MAA puts the actual reason in the body
                # (`{"error":{"code":...,"message":...}}`).  `raise_for_status`
                # throws that away and leaves only "400 Client Error: Bad
                # Request", which is what a live tdx-azure run reported --
                # true, and useless.  The body is MAA's own error text, not
                # attestation evidence, so surfacing it leaks nothing.
                detail = (resp.text or "")[:400].replace("\n", " ")
                raise MaaVerificationError(
                    f"MAA returned HTTP {resp.status_code} for {u}: {detail}")
            return resp.json()

    try:
        parsed = http_post(url, body)
    except Exception as exc:
        raise MaaVerificationError(f"MAA attest call failed: {exc}") from exc

    token = (parsed or {}).get("token")
    if not token:
        raise MaaVerificationError(
            f"MAA response had no `token` field: {json.dumps(parsed)[:200]}")
    return str(token)
