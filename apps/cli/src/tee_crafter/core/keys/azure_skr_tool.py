"""Azure Secure Key Release through Microsoft's ``AzureAttestSKR`` tool.

**Why this is a separate adapter rather than a flag on**
:class:`~tee_crafter.core.keys.azure_kv.AzureKeyVaultAdapter`.

That adapter does the release in Python: POST the attestation token to
``/keys/{name}/release``, pull ``key.key_hsm`` out of the envelope, and unwrap
the ``CKM_RSA_AES_KEY_WRAP`` blob with an RSA private key we hold.  Every step
of it is right, and on an Azure CVM the last step is impossible.

The key-encryption key is not ours to choose.  Key Vault picks it from the
attestation token's top-level ``x-ms-runtime.keys``, and on a CVM that key is
``TpmEphemeralEncryptionKey`` — *"a public RSA key owned and protected by the
target execution environment"*, whose private half is sealed to the vTPM and
reachable only through ``azguestattestation1``'s ``Decrypt`` API.  No Python
process can supply ``recipient_private_key``, so that path correctly returns
``plaintext=None`` and the bootstrap correctly refuses.
https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp

So the unwrap is delegated to the binary that can do it.  ``AzureAttestSKR``
(``cvm-securekey-release-app`` in Microsoft's guest-attestation repo, baked into
all three Azure CVM images by ``scripts/common/azure_guest_attestation.sh``)
attests the VM, releases the AKV key, and
uses it to unwrap a caller-supplied blob — all inside one process.

**This changes what the released key is, and that is an improvement.** The
released RSA key never enters this process; it stays inside the tool and is used
there as a key-encryption key. What crosses back is only the unwrapped DEK. A
compromise of this Python process therefore yields one data key, not the
long-lived AKV key that unwraps every future one.

**Proven against a real vault on 2026-08-23.** On a live ``snp-azure`` CVM
(``Standard_DC2as_v5``), ``AzureAttestSKR`` attested to MAA, Key Vault evaluated
the key's measurement-bound release policy, released the exportable RSA-3072 key
and unwrapped our DEK: the bytes returned hashed to
``564dcc0261e9082b9d8369276a95f9abca692bd7c56c0cb67e0ad87f2004e493``, identical
to the SHA-256 of the 32-byte DEK that had been wrapped. Retargeted from
``tdx-azure`` on purpose -- SEV-SNP is the isolation type the library supports
outright.

**The wire format is not two base64 strings, and assuming it was is what blocked
every in-guest release.** We send base64 (the wrapped DEK, on argv) but the tool
answers in *raw binary* on stdout. Two bugs followed from the wrong assumption:
the runner decoded stdout as UTF-8 with ``errors="replace"``, corrupting roughly
half the bytes of a random key, and the parser then rejected what survived with
"its output is not base64". Both are fixed; see :data:`Runner` and
:meth:`AzureSkrToolAdapter._decode_plaintext`.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import shlex
from typing import Callable, Dict, Optional, Tuple

from tee_crafter.core.keys.gating import gating_from_extra
from tee_crafter.core.keys.spec import (
    AttestedKeyMaterial, AttestedKeyRef, KeyProvider, KeyReleaseError,
    KeyReleasePolicy, KmsAdapter, UnwrapAlgorithm,
)

#: Where ``scripts/common/azure_guest_attestation.sh`` installs the tool, on
#: ``tdx-azure``, ``snp-azure`` and ``gpu-cc-azure`` alike.
SKR_TOOL_ENV = "TEE_CRAFTER_AZURE_SKR_TOOL"
SKR_TOOL_DEFAULT = "/usr/local/bin/AzureAttestSKR"

#: The MAA instance the tool attests against.  Shared with the attestation path
#: on purpose: releasing a key against a different authority than the one that
#: vouched for the channel would be two unrelated trust decisions wearing one
#: name.
MAA_ENDPOINT_ENV = "TEE_CRAFTER_MAA_ENDPOINT"

#: The DEK, wrapped to the AKV key's public half, base64.  Produced at
#: provisioning time (``AzureAttestSKR ... -w``, or any RSA-OAEP wrap against
#: the key's public material) and staged into the TEE as ciphertext.
WRAPPED_DEK_ENV = "TEE_CRAFTER_BYOK_AZURE_WRAPPED_DEK"

#: The base64 alphabet as raw byte values, for deciding whether the tool's
#: stdout could be an encoding rather than the key itself.
_B64_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

#: Symmetric key lengths a released DEK plausibly has, used only to decide
#: whether a single trailing newline was added by a wrapper.  Not a validity
#: check: an unusual length is passed through untouched rather than rejected,
#: because the caller -- not this parser -- knows what the key is for.
_PLAUSIBLE_KEY_LENS = frozenset((16, 24, 32, 48, 64))

#: Smallest byte length that could be a real symmetric key (AES-128).
#: Anything shorter is a truncated or partially-written stream, not a key.
_MIN_KEY_LEN = 16

Runner = Callable[[list], Tuple[int, bytes, str]]
"""``argv -> (returncode, stdout_bytes, stderr_text)``.  Injected in tests.

**stdout is bytes, deliberately.**  ``AzureAttestSKR`` writes the unwrapped DEK
to stdout as raw binary, and decoding it as text destroys it: the old
``decode("utf-8", "replace")`` replaced every invalid sequence with U+FFFD, so
roughly half the bytes of a random 32-byte key came back corrupted before
anything had a chance to use them.  stderr stays text -- it carries the
library's diagnostics, which are genuinely UTF-8.
"""


def skr_tool_path() -> str:
    return (os.environ.get(SKR_TOOL_ENV) or "").strip() or SKR_TOOL_DEFAULT


def _default_runner(timeout: int) -> Runner:
    def _run(argv: list) -> Tuple[int, bytes, str]:
        import subprocess

        proc = subprocess.run(argv, capture_output=True, timeout=timeout)
        return (proc.returncode,
                proc.stdout,
                proc.stderr.decode("utf-8", "replace"))
    return _run


def _redact(argv: list) -> str:
    """Render *argv* for an error message with the ciphertext elided.

    The wrapped DEK is not plaintext, but it is the exact blob an attacker needs
    alongside a TD compromise, and error strings reach logs and the SIEM. The
    key URL and endpoint stay: they are the things worth seeing when this fails.
    """
    out, skip = [], False
    for item in argv:
        if skip:
            out.append("<redacted>")
            skip = False
            continue
        out.append(item)
        if item == "-s":
            skip = True
    return " ".join(shlex.quote(x) for x in out)


class AzureSkrToolAdapter(KmsAdapter):
    """Release an Azure Key Vault / Managed HSM key and unwrap a DEK with it."""

    provider = KeyProvider.AZURE_KEY_VAULT

    def __init__(
        self,
        *,
        wrapped_dek_b64: str = "",
        maa_endpoint: str = "",
        tool: str = "",
        runner: Optional[Runner] = None,
        timeout: int = 120,
    ):
        self._wrapped_dek_b64 = (
            wrapped_dek_b64 or os.environ.get(WRAPPED_DEK_ENV, "")).strip()
        self._maa_endpoint = (
            maa_endpoint or os.environ.get(MAA_ENDPOINT_ENV, "")).strip().rstrip("/")
        self._tool = tool or skr_tool_path()
        self._runner = runner
        self._timeout = timeout

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
                f"AzureSkrToolAdapter cannot release {key_ref.provider.value} keys")
        if not key_ref.key_id.startswith("https://"):
            raise KeyReleaseError(
                "Azure key_id must be the full Key Vault key URL "
                "(e.g. https://mhsm-name.managedhsm.azure.net/keys/foo/abcd1234)")
        if not self._maa_endpoint:
            raise KeyReleaseError(
                f"{MAA_ENDPOINT_ENV} is unset. The tool attests to MAA before "
                "Key Vault will release anything, and an attestation authority "
                "chosen by whatever happens to be in the environment is not an "
                "attestation authority. Refusing to release.")
        if not self._maa_endpoint.startswith("https://"):
            raise KeyReleaseError(
                f"{MAA_ENDPOINT_ENV} must be https, got "
                f"{self._maa_endpoint!r}")
        if not self._wrapped_dek_b64:
            raise KeyReleaseError(
                f"no wrapped DEK supplied ({WRAPPED_DEK_ENV} is empty). This "
                "adapter unwraps a DEK *with* the released key rather than "
                "handing the released key back, so there is nothing to do "
                "without ciphertext. Wrap the DEK at provisioning time with "
                "the AKV key's public half.")
        # Validated here rather than left to the tool: a malformed blob comes
        # back as an opaque non-zero exit, and "your base64 is wrong" is not
        # something anyone should have to learn from a live CVM.
        try:
            base64.b64decode(self._wrapped_dek_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KeyReleaseError(
                f"{WRAPPED_DEK_ENV} is not valid base64: {exc}") from exc

        argv = [
            self._tool,
            "-a", self._maa_endpoint,
            "-k", key_ref.key_id,
            "-s", self._wrapped_dek_b64,
            "-u",
        ]
        # The MAA request nonce. Binding the release to the same value the
        # channel was attested with is what stops a token minted for one session
        # from being replayed to unwrap a key in another.
        nonce = (encryption_context or {}).get("nonce", "")
        if nonce:
            argv += ["-n", nonce]

        runner = self._runner or _default_runner(self._timeout)
        try:
            rc, out, err = runner(argv)
        except FileNotFoundError as exc:
            raise KeyReleaseError(
                f"{self._tool} is not present. Secure Key Release on an Azure "
                "CVM needs it: the key-encryption key Key Vault wraps to is "
                "sealed to the vTPM and reachable only through "
                "azguestattestation1. Re-bake the image, or set "
                f"{SKR_TOOL_ENV}.") from exc
        except Exception as exc:
            raise KeyReleaseError(
                f"{self._tool} failed to run: {exc}") from exc

        if rc != 0:
            detail = (err or out or "").strip().replace("\n", " ")[:400]
            raise KeyReleaseError(
                f"secure key release failed (exit {rc}) for "
                f"`{_redact(argv)}`: {detail or 'no output'}")

        plaintext = self._decode_plaintext(out)

        gating = gating_from_extra(KeyProvider.AZURE_KEY_VAULT, key_ref.extra)
        meta = {
            "kid": key_ref.key_id,
            "kid_matches_request": True,
            "unwrapped": True,
            "unwrap_delegated_to": self._tool,
            "maa_endpoint": self._maa_endpoint,
            "release_nonce_bound": bool(nonce),
            # Recorded because it is the security-relevant difference from the
            # Python path: the AKV key stayed inside the tool.
            "released_key_left_process": False,
            **gating.as_dict(),
        }
        return AttestedKeyMaterial(
            key_ref=key_ref,
            plaintext=plaintext,
            wrapped_for_recipient=None,
            unwrap_algorithm=UnwrapAlgorithm.CKM_RSA_AES_KEY_WRAP,
            released_at=0.0,
            attestation_sha256=hashlib.sha256(attestation or b"").hexdigest(),
            attestation_age_seconds=0.0,
            audit_id="",
            provider_response_metadata=meta,
            gating=gating.gating,
            measurement_gate=gating.measurement_gate,
            gating_note=gating.note,
        )

    @staticmethod
    def _decode_plaintext(stdout: bytes) -> bytes:
        """Take the unwrapped DEK off the tool's stdout.

        **The shipped tool writes the key as raw binary, not base64.** This
        assumed base64 and was wrong, which is what blocked every in-guest
        release on ``snp-azure``: the tool exited 0, and we rejected its output
        with *"its output is not base64 … refusing to use it as key material"*.

        Measured twice on a live SEV-SNP CVM (2026-08-23). Driving
        ``AzureAttestSKR -a … -k … -s … -u`` by hand produced exactly 32 bytes
        on stdout, with no trailing newline and no diagnostics -- those go to
        stderr -- and ``sha256`` of those bytes equalled ``sha256`` of the
        32-byte DEK that had been wrapped. So stdout *is* the key.

        Base64 is still accepted, because it costs one cheap test and keeps any
        build or wrapper that does encode working. The discrimination is safe: a
        base64 payload is entirely within the 64-character alphabet (plus
        padding) and a multiple of four long, and the chance that 32 uniformly
        random key bytes all land in that alphabet is ``(64/256) ** 32``, about
        one in 2**64. Raw is therefore the default and base64 the special case,
        which is the opposite of the original ordering.

        Empty output is an error, not an empty key: a zero-length DEK would
        surface later as a decryption failure, far from any of this context.
        """
        if not stdout:
            raise KeyReleaseError(
                "secure key release reported success but printed nothing; "
                "refusing to treat an empty result as a released key")

        # Base64 form, if and only if the whole payload can be nothing else.
        # The length floor below applies to the decoded result too: a short
        # ASCII error string like b"Segfault" happens to be all-base64-alphabet
        # and a multiple of four, so without that it decoded to a 6-byte "key"
        # and sailed past the check entirely.
        probe = stdout.strip()
        if (probe and len(probe) % 4 == 0
                and all(c in _B64_BYTES for c in probe)):
            try:
                decoded = base64.b64decode(probe, validate=True)
            except (binascii.Error, ValueError):
                decoded = b""
            if len(decoded) >= _MIN_KEY_LEN:
                return decoded

        # Raw form. Deliberately no unconditional strip(): a random key byte is
        # whitespace about 2% of the time, and trimming it would silently hand
        # back a short key. Only a trailing newline is removed, and only when
        # doing so turns an implausible length into a plausible one -- so a
        # wrapper that adds "\n" is tolerated without truncating a key that
        # genuinely ends in 0x0a.
        raw = stdout
        if len(raw) not in _PLAUSIBLE_KEY_LENS:
            trimmed = raw.rstrip(b"\r\n")
            if len(trimmed) in _PLAUSIBLE_KEY_LENS:
                raw = trimmed

        # Two things still must not become key material, because accepting raw
        # bytes removed the base64 decode that used to reject them implicitly:
        #
        #   * whitespace-only output -- the tool said nothing useful, and a key
        #     of spaces would "work" all the way to a wrong decryption;
        #   * anything shorter than the smallest real symmetric key, which is
        #     what a truncated or partially-written stream looks like.
        if not raw.strip():
            raise KeyReleaseError(
                "secure key release reported success but printed only "
                "whitespace; refusing to treat that as a released key")
        if len(raw) < _MIN_KEY_LEN:
            raise KeyReleaseError(
                f"secure key release returned {len(raw)} byte(s), which is "
                f"shorter than the smallest plausible key ({_MIN_KEY_LEN}); "
                "refusing to use a truncated result as key material")
        return raw
