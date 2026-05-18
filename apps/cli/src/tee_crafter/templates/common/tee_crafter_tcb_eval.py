"""Intel DCAP platform TCB status evaluation — one implementation, four clients.

Every Intel-anchored client in this tree (``sgx``, ``tdx/azure``, ``tdx/gcp``,
``gpu_cc/gcp``) used to stop after "the QE report was signed by a PCK leaf that
chains to Intel's root".  That proves the quote came from Intel-provisioned
hardware.  It says nothing about whether that hardware is *current*: an
``OutOfDate`` platform running microcode with known privilege-escalation
errata, or a platform whose PCK key Intel has **revoked**, produces a quote
that passes every one of those checks.  This module is the missing step.

It is deliberately a single shared module rather than a fourth (and fifth) copy
of the same verifier.  The last three attestation bugs found in this repository
were all "four copies drifted": one client's ``verify_qe_report_signature`` was
simply absent, which was a full attestation bypass.  The clients import this
file — see ``_load_tcb_eval_module`` in each ``client.template.py`` — and
contribute only the two X.509 constraint helpers they already own
(``check_leaf_certificate`` / ``check_ca_certificate``), passed in as
arguments so that those too exist in one place per client rather than being
re-implemented here.


Input: the collateral bundle
----------------------------
The build stages a ``tcb_collateral.json`` next to ``client.py``.  It carries,
for each Intel PCS collateral item, the **verbatim response body** and the
issuer chain PEM that Intel returned alongside it (``TCB-Info-Issuer-Chain``,
``SGX-Enclave-Identity-Issuer-Chain``, ``SGX-PCK-CRL-Issuer-Chain``; Intel
documents the chain contents as ``<Signing Certificate><Root CA Certificate>``
— see https://api.portal.trustedservices.intel.com/content/documentation.html).

Schema (``schema_version: 1``), written by
``core/attestation/tcb_collateral.py::stage_tcb_collateral`` and read here
through :class:`CollateralBundle`, which is the only place in this module that
knows the field names::

    {
      "schema_version": 1,
      "fetched_at": "2026-08-20T12:00:00Z",     # UTC, second precision, "Z"
      "source": "https://api.trustedservices.intel.com",
      "fmspc": "00806F050000" | null,
      "root_ca_sha256": "<hex>",                 # diagnostic only, see below
      "complete": true | false,
      "missing": ["sgx_tcb_info", "tdx_tcb_info"],
      "items": {
        "<one of six names>": {
          "kind": "tcb_info" | "enclave_identity" | "pck_crl",
          "url": ..., "endpoint": ...,
          "body": "<response text, or base64 for DER CRLs>",
          "body_encoding": "utf-8" | "base64",
          "signed_value_key": "tcbInfo" | "enclaveIdentity" | null,
          "issuer_chain_pem": "<PEM, leaf-first, incl. Intel's root copy>",
          "issuer_chain_header": "TCB-Info-Issuer-Chain" | ...
        }
      }
    }

The six item names are ``sgx_tcb_info``, ``tdx_tcb_info``,
``sgx_qe_identity``, ``tdx_qe_identity``, ``sgx_pck_crl_platform`` and
``sgx_pck_crl_processor``.  For ``body_encoding: "utf-8"``,
``body.encode("utf-8")`` is byte-identical to the wire bytes, and the signed
slice is taken from *those*.

``complete``, ``missing`` and ``root_ca_sha256`` are **diagnostics only**.
They are strings in a file on disk, so letting ``complete: false`` select a
lenient branch would be exactly the "absent" tri-state that made earlier
bypasses reachable.  Every decision is driven by what the items contain and by
signatures anchored on the pinned root — which is deliberately *not* in the
bundle.

Everything in it is untrusted.  The bundle is a file on the operator's disk,
not something delivered over an authenticated channel, so every field is
re-verified here against the **pinned** ``certs/intel-sgx-dcap-root.pem``.


Two traps this module is built around
-------------------------------------
1. **Never re-serialize.**  Intel's ECDSA signature is computed over the
   ``tcbInfo`` / ``enclaveIdentity`` value as it appears in the response body
   (Intel's own responses contain no whitespace, so "the raw bytes" and "the
   body without whitespace" are the same thing).  ``json.loads`` followed by
   ``json.dumps`` *usually* reproduces identical bytes on CPython, because
   dicts preserve insertion order — which is exactly what makes it dangerous.
   It keeps working until a number reformats (``1.0`` vs ``1``, exponent
   forms) or somebody adds ``sort_keys=True``, and then every signature check
   in the fleet fails at once, or worse, is "fixed" by relaxing it.  So the
   signed bytes are sliced out of the raw body by
   :func:`raw_top_level_value` and verified as-is.  ``json.loads`` is used
   only to *read* already-verified values.

2. **Never anchor on the collateral's own root.**  Intel's issuer-chain header
   ships ``<signing certificate><root CA certificate>``, so it is easy to write
   a walk that terminates at "the root that came with the bundle".  That is
   circular: whoever supplies the bundle supplies the chain and satisfies the
   check for free, and the bundle is a file on disk rather than something
   delivered over an authenticated channel.  This module anchors *only* on the
   pinned root the client passes in: a trailing copy of it in the chain is
   dropped as redundant, and a chain topped by any other self-signed
   certificate is refused by name.  See
   ``test_self_consistent_bundle_with_embedded_root_is_rejected``.

3. **The signing certificate is a non-CA leaf.**  Intel's
   ``CN=Intel SGX TCB Signing`` carries ``CA:FALSE`` with ``keyUsage
   digitalSignature, contentCommitment``; the PCK Platform CA that signs the
   CRLs carries ``CA:TRUE pathlen:0`` with ``keyCertSign, cRLSign``.  So the
   document signer must be constrained with the client's
   ``check_leaf_certificate`` and the CRL signer with its
   ``check_ca_certificate`` — the two are not interchangeable.


The TDX module is a second TCB
-----------------------------
For TDX there are *two* things to evaluate, not one.  The platform TCB (FMSPC,
CPUSVN, PCESVN, ``tdxtcbcomponents``) says whether the CPU's microcode is
current.  It says nothing about the **TDX module** — the SEAM code that
actually enforces the TD's isolation — which has its own signer
(MRSIGNERSEAM), its own attributes (SEAMATTRIBUTES) and its own SVN, and which
Intel describes in ``tcbInfo.tdxModule`` and ``tcbInfo.tdxModuleIdentities``.
:func:`evaluate_tdx_module` checks all three, and
:func:`converge_tdx_module_status` folds the module's ``tcbStatus`` into the
platform's the way Intel's QVL does, so a current CPU running a SEAM module
with published errata cannot report ``UpToDate``.  This needs the TD report
body, which is why :func:`evaluate` takes ``td_report_body`` and refuses TDX
without it.  SGX has no TDX module and is unaffected.


Fail-closed
-----------
Every failure raises a :class:`TcbEvalError` subclass.  There is no "absent"
or "skipped" state: a missing bundle, an unparseable bundle, a bundle with no
CRL covering the PCK leaf — all of them are failures.  A tri-state that let
attacker-truncated input select the lenient branch is how the QE-report-binding
bypass worked, and this module does not reintroduce one.  The single escape
hatch is ``TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS=1``, which skips the whole
evaluation behind a loud banner, matching
``TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT``.
"""
import base64
import datetime
import hashlib
import json
import os
import sys

# ---------------------------------------------------------------------------
# Environment knobs
# ---------------------------------------------------------------------------

#: Path override for the collateral bundle.
ENV_COLLATERAL_PATH = "TEE_CRAFTER_TCB_COLLATERAL"

#: Staleness bound override, in hours.  See :data:`DEFAULT_MAX_AGE_SECONDS`.
ENV_MAX_AGE_HOURS = "TEE_CRAFTER_TCB_COLLATERAL_MAX_AGE_HOURS"

#: Comma-separated additional platform ``tcbStatus`` values to accept.  Only
#: names in :data:`OPTIONAL_ALLOWABLE_STATUSES` may appear; anything else is a
#: fatal configuration error rather than a silently ignored typo.
ENV_ALLOW_STATUS = "TEE_CRAFTER_TCB_ALLOW_STATUS"

#: The single, loud escape hatch.  Skips the entire evaluation.
ENV_ALLOW_UNVERIFIED = "TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS"

#: Default filename staged next to ``client.py`` by the build.
COLLATERAL_FILENAME = "tcb_collateral.json"

#: Baked-image fallback, mirroring the ``qe_identity.json`` convention the TDX
#: clients already used (``$ENV`` -> file beside the script -> ``/etc``).
COLLATERAL_ETC_PATH = "/etc/tee_crafter/" + COLLATERAL_FILENAME

#: Seven days.  Justification: the signature over Intel's collateral does not
#: bound *when it was fetched*, only what it says, so a bundle can sit in a
#: build directory indefinitely and keep verifying while a platform is revoked
#: underneath it.  Seven days matches the credential-rotation cadence this
#: organisation already runs on, is short enough that a revocation published by
#: Intel cannot be ignored for a quarter, and is long enough that re-running a
#: client against a still-running deployment a few days after the build does
#: not push operators toward the escape hatch — which would be strictly worse.
#: Override with :data:`ENV_MAX_AGE_HOURS`.  Independently of this bound, the
#: ``nextUpdate`` that Intel signs into ``tcbInfo`` / ``enclaveIdentity`` must
#: not be in the past; that one is not affected by the override, because it is
#: Intel's own statement about the document's lifetime.
DEFAULT_MAX_AGE_SECONDS = 7 * 24 * 3600

#: Intel's SGX extension in a PCK certificate.  FMSPC is at ``.4``; the nested
#: TCB sequence at ``.2`` carries the 16 component SVNs (``.2.1`` ... ``.2.16``),
#: PCESVN (``.2.17``) and CPUSVN (``.2.18``).
SGX_EXTENSION_OID = "1.2.840.113741.1.13.1"
_OID_FMSPC = SGX_EXTENSION_OID + ".4"
_OID_PCEID = SGX_EXTENSION_OID + ".3"
_OID_TCB = SGX_EXTENSION_OID + ".2"
_OID_PCESVN = _OID_TCB + ".17"
_OID_CPUSVN = _OID_TCB + ".18"

#: The pinned anchor's subject CN, checked before any chain walk so that a
#: build which injected the wrong certificate says so instead of failing with
#: an opaque signature error.
EXPECTED_ROOT_CA_CN = "Intel SGX Root CA"

#: Accepted by default.
DEFAULT_ALLOWED_STATUSES = frozenset({"UpToDate"})

#: May be added to the allowed set via :data:`ENV_ALLOW_STATUS`.  Each of these
#: means "the microcode is current, but the platform needs a BIOS setting
#: changed and/or the enclave needs software hardening" — a real risk that some
#: operators knowingly accept, so it is a policy decision rather than a hard no.
OPTIONAL_ALLOWABLE_STATUSES = frozenset({
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded",
})

#: Never accepted, by any policy.  ``OutOfDate*`` means the platform is running
#: a TCB Intel has superseded for security reasons; ``Revoked`` means Intel has
#: withdrawn trust in it outright.
NEVER_ALLOWED_STATUSES = frozenset({
    "OutOfDate",
    "OutOfDateConfigurationNeeded",
    "Revoked",
})


# ---------------------------------------------------------------------------
# Errors — one class per reason, so callers and tests can be specific
# ---------------------------------------------------------------------------

class TcbEvalError(Exception):
    """Base class.  Every failure in this module is fatal for the caller."""


class CollateralMissing(TcbEvalError):
    """No bundle at any of the searched locations, or an item is absent."""


class CollateralMalformed(TcbEvalError):
    """The bundle exists but is not the shape this module can verify."""


class CollateralUntrusted(TcbEvalError):
    """A signature or certificate chain in the bundle did not verify."""


class TcbInfoUnavailable(CollateralMissing):
    """The bundle carries no TCBInfo for this TEE.

    Its own class because it is the one failure with a *known, benign* cause —
    the build host cannot know the platform's FMSPC, which only exists in a
    real quote's PCK leaf — and therefore the one that deserves a message
    naming the exact value to rebuild with.  It is still a hard failure: a
    missing TCBInfo must never silently skip ``tcbStatus`` evaluation, which is
    the entire point of this module.
    """


class CollateralStale(TcbEvalError):
    """``fetched_at`` is older than the staleness bound, or Intel's own
    ``nextUpdate`` on the document has passed."""


class TcbPolicyError(TcbEvalError):
    """The operator's status policy is itself invalid."""


class TcbStatusRejected(TcbEvalError):
    """The platform's resolved ``tcbStatus`` is not accepted."""


class QeIdentityRejected(TcbEvalError):
    """The Quoting Enclave does not match the signed QEIdentity."""


class TdxModuleRejected(TcbEvalError):
    """The TDX module (SEAM) in the quote is not the one Intel describes.

    Distinct from :class:`TcbStatusRejected` because the platform's own TCB can
    be perfectly current while the TDX module running on it is signed by
    somebody else, has non-zero SEAMATTRIBUTES, or is a version Intel does not
    publish an identity for.  All three mean "this is not Intel's TDX module",
    which is a different remediation from "patch your microcode".
    """


class PckRevoked(TcbEvalError):
    """A certificate in the PCK chain appears on an Intel CRL, or no CRL in
    the bundle covers it (which is indistinguishable from revoked)."""


class PckExtensionError(TcbEvalError):
    """The PCK leaf's SGX extension is missing or unparseable."""


# ---------------------------------------------------------------------------
# Locating the bundle — same convention the TDX clients used for QEIdentity
# ---------------------------------------------------------------------------

def collateral_lookup_path() -> str:
    """Return the first existing bundle path, else the baked-image default.

    Resolution order, matching the ``_qe_identity_lookup_path`` convention the
    TDX clients already followed: ``$TEE_CRAFTER_TCB_COLLATERAL`` overrides
    everything; otherwise prefer ``tcb_collateral.json`` sitting next to this
    module (the build stages it there, alongside ``client.py``); fall back to
    ``/etc/tee_crafter/tcb_collateral.json`` for baked images.
    """
    env = os.environ.get(ENV_COLLATERAL_PATH)
    if env:
        return env
    try:
        sibling = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), COLLATERAL_FILENAME)
    except Exception:  # pragma: no cover - __file__ absent under exec()
        sibling = ""
    if sibling and os.path.exists(sibling):
        return sibling
    return COLLATERAL_ETC_PATH


# ---------------------------------------------------------------------------
# Raw-byte JSON slicing — the "never re-serialize" half of the design
# ---------------------------------------------------------------------------

def _ws_skip(buf: bytes, i: int) -> int:
    while i < len(buf) and buf[i] in b" \t\r\n":
        i += 1
    return i


def _scan_string(buf: bytes, i: int) -> int:
    """*i* points at the opening quote.  Return the index past the closing one."""
    if i >= len(buf) or buf[i:i + 1] != b'"':
        raise CollateralMalformed("expected a JSON string")
    i += 1
    while i < len(buf):
        c = buf[i:i + 1]
        if c == b"\\":
            i += 2
            continue
        if c == b'"':
            return i + 1
        i += 1
    raise CollateralMalformed("unterminated JSON string")


def _scan_value(buf: bytes, i: int) -> int:
    """Return the index just past the JSON value starting at *i*."""
    i = _ws_skip(buf, i)
    if i >= len(buf):
        raise CollateralMalformed("truncated JSON value")
    c = buf[i:i + 1]
    if c == b'"':
        return _scan_string(buf, i)
    if c in (b"{", b"["):
        closing = b"}" if c == b"{" else b"]"
        depth = 0
        while i < len(buf):
            ch = buf[i:i + 1]
            if ch == b'"':
                i = _scan_string(buf, i)
                continue
            if ch in (b"{", b"["):
                depth += 1
            elif ch in (b"}", b"]"):
                depth -= 1
                if depth == 0:
                    if ch != closing:
                        raise CollateralMalformed("mismatched JSON brackets")
                    return i + 1
            i += 1
        raise CollateralMalformed("unterminated JSON object or array")
    # number / true / false / null: run to the next structural character.
    start = i
    while i < len(buf) and buf[i:i + 1] not in b",}] \t\r\n":
        i += 1
    if i == start:
        raise CollateralMalformed("empty JSON value")
    return i


def raw_top_level_value(raw: bytes, key: str) -> bytes:
    """Return the **verbatim bytes** of top-level *key*'s value in *raw*.

    This is what Intel signs.  Slicing rather than re-encoding is the whole
    point: a document that has been through ``json.loads``/``json.dumps`` is a
    different byte string, and must fail signature verification instead of
    being silently re-signed by our own serializer's happy accident of
    reproducing Intel's byte order.

    Only *top-level* keys are considered, so the same key name appearing inside
    a nested object or string cannot be selected.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise CollateralMalformed("raw document is not bytes")
    raw = bytes(raw)
    want = key.encode("utf-8")
    i = _ws_skip(raw, 0)
    if raw[i:i + 1] != b"{":
        raise CollateralMalformed("document is not a JSON object")
    i += 1
    found = None
    while True:
        i = _ws_skip(raw, i)
        if raw[i:i + 1] == b"}":
            break
        key_end = _scan_string(raw, i)
        name = raw[i + 1:key_end - 1]
        i = _ws_skip(raw, key_end)
        if raw[i:i + 1] != b":":
            raise CollateralMalformed("malformed JSON member (no ':')")
        value_start = _ws_skip(raw, i + 1)
        value_end = _scan_value(raw, value_start)
        if name == want:
            if found is not None:
                raise CollateralMalformed(
                    f"document declares {key!r} more than once, so which bytes "
                    "Intel signed is ambiguous")
            found = raw[value_start:value_end]
        i = _ws_skip(raw, value_end)
        if raw[i:i + 1] == b",":
            i += 1
            continue
        if raw[i:i + 1] == b"}":
            break
        raise CollateralMalformed("malformed JSON object (expected ',' or '}')")
    if found is None:
        raise CollateralMalformed(f"document has no top-level {key!r} member")
    return found


def split_signed_document(raw: bytes, value_key: str) -> tuple:
    """Split an Intel PCS response into ``(signed_bytes, r_s_signature, value)``.

    *value_key* is ``"tcbInfo"`` or ``"enclaveIdentity"``.  ``signed_bytes`` is
    the verbatim slice; ``value`` is that slice parsed, for reading fields
    *after* the signature over it has been checked.
    """
    signed = raw_top_level_value(raw, value_key)
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollateralMalformed(f"response body is not valid JSON: {exc}") from exc
    if not isinstance(envelope, dict):
        raise CollateralMalformed("response body is not a JSON object")
    sig_hex = envelope.get("signature")
    if not isinstance(sig_hex, str) or not sig_hex:
        raise CollateralMalformed(
            f"response body has no 'signature' alongside {value_key!r}")
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise CollateralMalformed(f"'signature' is not hex: {exc}") from exc
    if len(sig) != 64:
        raise CollateralMalformed(
            f"'signature' is {len(sig)} bytes, expected 64 (ECDSA P-256 r||s)")
    try:
        value = json.loads(signed.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollateralMalformed(
            f"{value_key!r} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CollateralMalformed(f"{value_key!r} is not a JSON object")
    return signed, sig, value


# ---------------------------------------------------------------------------
# Bundle accessors — the contained place where the builder's schema is read
# ---------------------------------------------------------------------------

#: The bundle schema this reader understands.  A bundle from a newer builder is
#: refused rather than read optimistically: a field this version does not know
#: about could be the one carrying the check it is meant to perform.
SCHEMA_VERSION = 1

#: The six item names ``core/attestation/tcb_collateral.py`` can emit, and the
#: ``kind`` each declares.  This table and :data:`_ITEMS_BY_TEE` are the only
#: places in this module that know the builder's schema, so reconciling the two
#: halves of this change is an edit here rather than a hunt through the
#: verifier.
_ITEM_KINDS = {
    "sgx_tcb_info": "tcb_info",
    "tdx_tcb_info": "tcb_info",
    "sgx_qe_identity": "enclave_identity",
    "tdx_qe_identity": "enclave_identity",
    "sgx_pck_crl_platform": "pck_crl",
    "sgx_pck_crl_processor": "pck_crl",
    # Intel SGX Root CA CRL. Declares kind "pck_crl" honestly: it is a DER CRL
    # in the PCK trust hierarchy with no signed JSON value. Its presence is what
    # turns the PCK *CA* from "NOT COVERED" into a hard revocation check -- the
    # PCK CRLs above are issued by a PCK CA and so cannot cover that CA itself.
    # The builder verifies this one against the pinned root directly, with no
    # chain parameter at all; the bundle's issuer_chain_pem for it is the pinned
    # root's own PEM, present only so a uniform reader works unchanged.
    "sgx_root_ca_crl": "pck_crl",
}

#: The JSON key whose *raw* bytes Intel signs, per kind.  CRLs are DER and are
#: signed as a whole, so they have none.
_KIND_SIGNED_KEY = {
    "tcb_info": "tcbInfo",
    "enclave_identity": "enclaveIdentity",
    "pck_crl": None,
}

#: Which items each TEE evaluates.  The PCK CRLs are shared: TDX platforms are
#: provisioned through the same SGX PCK infrastructure.
_ITEMS_BY_TEE = {
    "sgx": {"tcb_info": "sgx_tcb_info", "qe_identity": "sgx_qe_identity"},
    "tdx": {"tcb_info": "tdx_tcb_info", "qe_identity": "tdx_qe_identity"},
}
_CRL_ITEMS = ("sgx_pck_crl_platform", "sgx_pck_crl_processor",
              "sgx_root_ca_crl")


class CollateralItem:
    """One verified-on-the-wire Intel document, as stored in the bundle."""

    def __init__(self, name: str, kind: str, body: bytes,
                 issuer_chain_pem: bytes, extra: dict):
        self.name = name
        self.kind = kind
        self.body = body
        self.issuer_chain_pem = issuer_chain_pem
        self.extra = extra

    @property
    def label(self) -> str:
        return self.name

    @property
    def signed_value_key(self):
        return _KIND_SIGNED_KEY[self.kind]


class CollateralBundle:
    """Read-only accessor over the build's ``tcb_collateral.json``.

    Mirrors the read semantics of
    ``core/attestation/tcb_collateral.py::verify_collateral_bundle``, which is
    the builder-side reference implementation.  A standalone client script
    cannot import that module, so the semantics are matched rather than shared;
    the two are kept honest by this module's tests plus the shape assertions
    below, which refuse anything the reference would also refuse.

    Note what is *not* trusted here: ``complete``, ``missing`` and
    ``root_ca_sha256`` are all attacker-controllable strings in a file on disk.
    They are used for **diagnostics only**.  Every decision is driven by what
    the items actually contain and by signatures anchored on the pinned root.
    Letting a self-declared ``complete: false`` select a lenient branch would
    be exactly the "absent" tri-state that made earlier bypasses reachable.
    """

    def __init__(self, doc, source: str):
        if not isinstance(doc, dict):
            raise CollateralMalformed(
                f"{source}: top level is {type(doc).__name__}, not an object")
        version = doc.get("schema_version")
        if version != SCHEMA_VERSION:
            raise CollateralMalformed(
                f"{source}: schema_version {version!r} is not "
                f"{SCHEMA_VERSION}. This client cannot read that bundle; "
                "rebuild the client and the bundle from the same commit.")
        items = doc.get("items")
        if not isinstance(items, dict) or not items:
            raise CollateralMalformed(f"{source}: bundle has no 'items' object")
        for name in items:
            if name not in _ITEM_KINDS:
                raise CollateralMalformed(
                    f"{source}: bundle carries unknown item {name!r}")
        declared_missing = doc.get("missing") or []
        if not isinstance(declared_missing, list):
            raise CollateralMalformed(f"{source}: 'missing' is not a list")
        for name in declared_missing:
            if name in items:
                raise CollateralMalformed(
                    f"{source}: bundle lists {name!r} as missing but also "
                    "carries it; refusing to guess which claim is true")
        self._doc = doc
        self._items = items
        self.source = source

    @classmethod
    def load(cls, path: str = ""):
        path = path or collateral_lookup_path()
        if not os.path.exists(path):
            raise CollateralMissing(
                f"no Intel TCB collateral bundle at {path}. The build stages "
                f"{COLLATERAL_FILENAME} next to the client from Intel PCS; "
                f"re-run the build with network access, point "
                f"${ENV_COLLATERAL_PATH} at a fetched copy, or set "
                f"{ENV_ALLOW_UNVERIFIED}=1 to run with the platform TCB level "
                "unchecked (development only).")
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            raise CollateralMissing(
                f"cannot read TCB collateral bundle {path}: {exc}") from exc
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CollateralMalformed(
                f"{path} is not valid JSON: {exc}") from exc
        return cls(doc, path)

    # -- diagnostics (never decisions) -------------------------------------

    @property
    def declared_fmspc(self):
        return self._doc.get("fmspc")

    @property
    def declared_missing(self) -> list:
        return list(self._doc.get("missing") or [])

    @property
    def declared_complete(self) -> bool:
        return bool(self._doc.get("complete"))

    @property
    def declared_source(self) -> str:
        return self._doc.get("source") or ""

    @property
    def declared_root_ca_sha256(self) -> str:
        value = self._doc.get("root_ca_sha256")
        return value if isinstance(value, str) else ""

    def has(self, name: str) -> bool:
        return name in self._items

    # -- items -------------------------------------------------------------

    def item(self, name: str) -> CollateralItem:
        node = self._items.get(name)
        if node is None:
            raise CollateralMissing(
                f"{self.source}: the bundle does not carry {name!r}. An "
                "incomplete bundle is a failure, not a partial check.")
        if not isinstance(node, dict):
            raise CollateralMalformed(
                f"{self.source}: item {name!r} is not an object")
        kind = node.get("kind")
        expected_kind = _ITEM_KINDS[name]
        if kind != expected_kind:
            raise CollateralMalformed(
                f"{self.source}: item {name!r} declares kind {kind!r}, "
                f"expected {expected_kind!r}")
        chain = node.get("issuer_chain_pem")
        if not isinstance(chain, str) or "BEGIN CERTIFICATE" not in chain:
            raise CollateralMalformed(
                f"{self.source}: item {name!r} has no 'issuer_chain_pem'")
        body = node.get("body")
        if not isinstance(body, str) or not body:
            raise CollateralMalformed(
                f"{self.source}: item {name!r} has no 'body'")
        encoding = node.get("body_encoding")
        if encoding == "utf-8":
            # ``body.encode("utf-8")`` is byte-identical to the wire bytes.
            # These are the bytes Intel signed; they are never re-serialized.
            raw = body.encode("utf-8")
        elif encoding == "base64":
            try:
                raw = base64.b64decode(body, validate=True)
            except (ValueError, TypeError) as exc:
                raise CollateralMalformed(
                    f"{self.source}: item {name!r} body is not valid base64: "
                    f"{exc}") from exc
        else:
            raise CollateralMalformed(
                f"{self.source}: item {name!r} has unsupported body_encoding "
                f"{encoding!r}")
        declared_key = node.get("signed_value_key")
        if declared_key != _KIND_SIGNED_KEY[expected_kind]:
            raise CollateralMalformed(
                f"{self.source}: item {name!r} declares signed_value_key "
                f"{declared_key!r}, expected "
                f"{_KIND_SIGNED_KEY[expected_kind]!r}. The bundle does not get "
                "to choose which bytes count as signed.")
        return CollateralItem(name, expected_kind, raw,
                              chain.encode("utf-8"), node)

    def tcb_info(self, tee: str) -> CollateralItem:
        return self.item(_ITEMS_BY_TEE[tee]["tcb_info"])

    def qe_identity(self, tee: str) -> CollateralItem:
        return self.item(_ITEMS_BY_TEE[tee]["qe_identity"])

    def pck_crls(self) -> list:
        present = [name for name in _CRL_ITEMS if self.has(name)]
        if not present:
            raise CollateralMissing(
                f"{self.source}: the bundle carries no PCK CRL "
                f"(expected any of {list(_CRL_ITEMS)}). Without one a revoked "
                "platform key is indistinguishable from a good one.")
        return [self.item(name) for name in present]

    # -- freshness ----------------------------------------------------------

    def fetched_at(self) -> datetime.datetime:
        value = self._doc.get("fetched_at")
        if not value:
            raise CollateralMalformed(
                f"{self.source}: bundle has no 'fetched_at', so its age cannot "
                "be bounded")
        return _parse_timestamp(value, "fetched_at")


def check_root_ca_fingerprint(bundle: CollateralBundle, pinned_root) -> str:
    """Compare the builder's recorded anchor with the pinned one.

    Diagnostic only, and deliberately so: the bundle states which root the
    *build* verified against, and a file on disk cannot be allowed to influence
    what this client trusts.  A mismatch is reported because it almost always
    means the client and the bundle were built from different commits, but the
    decision is made by the signature check against ``pinned_root``.  Returns a
    human-readable note, empty when they agree.
    """
    from cryptography.hazmat.primitives import hashes

    declared = bundle.declared_root_ca_sha256.lower()
    if not declared:
        return ""
    actual = pinned_root.fingerprint(hashes.SHA256()).hex()
    if declared == actual:
        return ""
    return (f"bundle records root_ca_sha256={declared[:16]}... but this client "
            f"pins {actual[:16]}...; the collateral signature check below is "
            "what decides, and it will fail if they really differ")


def _parse_timestamp(value, label) -> datetime.datetime:
    if isinstance(value, (int, float)):
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc)
    if not isinstance(value, str):
        raise CollateralMalformed(
            f"{label} is {type(value).__name__}, expected an ISO-8601 string")
    text = value.strip()
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError as exc:
        raise CollateralMalformed(
            f"{label}={text!r} is not ISO-8601: {exc}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def resolve_max_age_seconds(default: int = DEFAULT_MAX_AGE_SECONDS) -> int:
    raw = os.environ.get(ENV_MAX_AGE_HOURS)
    if not raw:
        return default
    try:
        hours = float(raw)
    except ValueError as exc:
        raise TcbPolicyError(
            f"{ENV_MAX_AGE_HOURS}={raw!r} is not a number") from exc
    if hours <= 0:
        raise TcbPolicyError(
            f"{ENV_MAX_AGE_HOURS}={raw!r} must be positive; a zero or negative "
            "bound would disable the staleness check silently. Use "
            f"{ENV_ALLOW_UNVERIFIED}=1 if that is really what you want.")
    return int(hours * 3600)


def check_freshness(bundle: CollateralBundle, *, now=None,
                    max_age_seconds: int = 0) -> float:
    """Bound how long ago the bundle was fetched.  Returns its age in seconds."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    max_age = max_age_seconds or resolve_max_age_seconds()
    fetched = bundle.fetched_at()
    age = (now - fetched).total_seconds()
    if age < -300:
        raise CollateralStale(
            f"collateral fetched_at {fetched.isoformat()} is in the future "
            f"(now {now.isoformat()}); the bundle or this host's clock is wrong")
    if age > max_age:
        raise CollateralStale(
            f"Intel TCB collateral is {age / 3600:.1f}h old "
            f"(fetched {fetched.isoformat()}), over the {max_age / 3600:.1f}h "
            "bound. Intel's signature says what the document contains, not "
            "when you got it, so stale collateral cannot show a revocation "
            "published since. Refresh it by re-running the build with network "
            f"access, or raise the bound with ${ENV_MAX_AGE_HOURS}.")
    return age


def check_next_update(document: dict, label: str, *, now=None) -> None:
    """Reject a document whose Intel-signed ``nextUpdate`` has passed.

    Unlike the ``fetched_at`` bound this is Intel's own statement about the
    document's lifetime, so ``$TEE_CRAFTER_TCB_COLLATERAL_MAX_AGE_HOURS`` does
    not relax it.
    """
    raw = document.get("nextUpdate")
    if not raw:
        raise CollateralMalformed(
            f"{label} has no 'nextUpdate', so its lifetime is unbounded")
    next_update = _parse_timestamp(raw, f"{label}.nextUpdate")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now > next_update:
        raise CollateralStale(
            f"{label} expired at {next_update.isoformat()} (now "
            f"{now.isoformat()}). Intel has published a newer document; "
            "re-run the build with network access to fetch it.")


# ---------------------------------------------------------------------------
# Offline re-verification of the bundle's signatures
# ---------------------------------------------------------------------------

def _load_pem_chain(pem: bytes, label: str) -> list:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    blocks = []
    remainder = pem
    begin, end = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
    while begin in remainder:
        start = remainder.index(begin)
        stop = remainder.index(end) + len(end) if end in remainder else -1
        if stop < 0:
            raise CollateralMalformed(f"{label}: unterminated PEM block")
        blocks.append(remainder[start:stop])
        remainder = remainder[stop:]
    if not blocks:
        raise CollateralMalformed(
            f"{label}: no PEM certificate found in the issuer chain")
    try:
        return [x509.load_pem_x509_certificate(b, default_backend())
                for b in blocks]
    except Exception as exc:
        raise CollateralMalformed(
            f"{label}: issuer chain is not parseable X.509: {exc}") from exc


def load_pinned_root(pem: str):
    """Load and sanity-check the pinned Intel SGX Root CA."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    if not pem or not pem.strip():
        raise CollateralUntrusted(
            "this client carries no pinned Intel root CA, so no collateral "
            "signature can be anchored")
    try:
        root = x509.load_pem_x509_certificate(pem.strip().encode()
                                              if isinstance(pem, str)
                                              else pem.strip(),
                                              default_backend())
    except Exception as exc:
        raise CollateralUntrusted(
            f"the pinned Intel root CA is not a parseable certificate: "
            f"{exc}") from exc
    cn = next((a.value for a in root.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME)), "")
    if cn != EXPECTED_ROOT_CA_CN:
        raise CollateralUntrusted(
            f"the pinned trust anchor is {cn!r}, not {EXPECTED_ROOT_CA_CN!r}; "
            "this build injected the wrong certificate")
    if not isinstance(root.public_key(), ec.EllipticCurvePublicKey):
        raise CollateralUntrusted(
            "the pinned Intel root CA public key is not ECDSA")
    return root


def _check_validity(cert, label, now):
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise CollateralUntrusted(
            f"{label} is outside its validity window "
            f"({cert.not_valid_before_utc} - {cert.not_valid_after_utc})")


def _check_signing_leaf(cert, label, check_leaf_certificate):
    """Constrain a document-signing leaf.

    Intel's ``CN=Intel SGX TCB Signing`` certificate is an **end entity**:
    ``basicConstraints CA:FALSE`` with ``keyUsage digitalSignature,
    contentCommitment`` (observed against live Intel PCS, 2026-08-20).  So do
    not require CA:TRUE of it — require the opposite, which is exactly what the
    client's own ``check_leaf_certificate`` already asserts, and additionally
    that its keyUsage permits signing.  Matches
    ``core/attestation/tcb_collateral.py::_check_signing_leaf``.
    """
    from cryptography import x509

    check_leaf_certificate(cert)
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return  # keyUsage is optional in RFC 5280; nothing to check
    if not ku.digital_signature:
        raise ValueError(
            f"{label} has a keyUsage extension without digitalSignature, so it "
            "is not permitted to sign this document")


def _check_crl_signer(cert, label, check_ca_certificate):
    """Constrain a CRL-signing certificate.

    Unlike a document signer, a CRL signer really is a CA: Intel's
    ``CN=Intel SGX PCK Platform CA`` is ``CA:TRUE pathlen:0`` with
    ``keyCertSign, cRLSign`` (observed 2026-08-20).  The client's
    ``check_ca_certificate`` covers basicConstraints and keyCertSign; cRLSign
    is the extra this use adds.
    """
    from cryptography import x509

    check_ca_certificate(cert, 0, remaining_intermediates=0)
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not ku.crl_sign:
        raise ValueError(
            f"{label} has a keyUsage extension without cRLSign but signed a CRL")


def verify_issuer_chain(issuer_chain_pem: bytes, pinned_root, label, *,
                        check_leaf_certificate, check_ca_certificate,
                        now=None, signer_is_ca: bool = False):
    """Validate a collateral issuer chain and return its signing certificate.

    ``issuer_chain_pem`` is leaf-first, as Intel sends it
    (``<signing certificate><root CA certificate>``).  The root shipped inside
    the chain is **never** the anchor: a trailing copy of the pinned root is
    dropped as redundant, a chain topped by any *other* self-signed certificate
    is refused by name, and the final signature check always uses
    *pinned_root*.  Anchoring on the bundle's own root would be circular —
    whoever supplies the collateral supplies the chain, and the bundle is a
    file on disk, not something delivered over an authenticated channel.

    ``signer_is_ca`` switches the leaf constraint for CRL chains, whose signer
    genuinely is a CA.  Semantics mirror
    ``core/attestation/tcb_collateral.py::verify_issuer_chain``.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import InvalidSignature

    now = now or datetime.datetime.now(datetime.timezone.utc)
    chain = _load_pem_chain(issuer_chain_pem, label)

    # Intel's chain ends with its own copy of the root.  Drop it: we anchor on
    # the pinned file, and counting it as an intermediate would spend a pathLen
    # budget on a certificate that is not one.  x509.Certificate equality is
    # over the DER encoding, so a re-encoded copy still compares equal.
    if len(chain) > 1 and chain[-1] == pinned_root:
        chain = chain[:-1]

    top = chain[-1]
    if top != pinned_root and top.subject == top.issuer:
        raise CollateralUntrusted(
            f"{label}: the issuer chain terminates at a self-signed "
            f"certificate ({top.subject.rfc4514_string()}) that is not the "
            f"pinned {pinned_root.subject.rfc4514_string()}. A chain anchored "
            "on a root supplied by the same party that supplied the collateral "
            "proves nothing.")

    signer = chain[0]
    for idx, cert in enumerate([pinned_root] + chain):
        _check_validity(cert, f"{label}: certificate [{idx}]", now)

    extra = 1 if signer_is_ca else 0
    try:
        if signer_is_ca:
            _check_crl_signer(signer, f"{label}: signing certificate [0]",
                              check_ca_certificate)
        else:
            _check_signing_leaf(signer, f"{label}: signing certificate [0]",
                                check_leaf_certificate)
        for i in range(1, len(chain)):
            check_ca_certificate(chain[i], i,
                                 remaining_intermediates=i - 1 + extra)
        check_ca_certificate(pinned_root, len(chain),
                             remaining_intermediates=len(chain) - 1 + extra)
    except CollateralUntrusted:
        raise
    except Exception as exc:
        raise CollateralUntrusted(
            f"{label}: X.509 constraint check failed: {exc}") from exc

    for i in range(len(chain)):
        issuer = chain[i + 1] if i + 1 < len(chain) else pinned_root
        issuer_pub = issuer.public_key()
        if not isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            raise CollateralUntrusted(
                f"{label}: issuer certificate [{i + 1}] public key is not "
                "ECDSA")
        try:
            issuer_pub.verify(
                chain[i].signature,
                chain[i].tbs_certificate_bytes,
                ec.ECDSA(chain[i].signature_hash_algorithm),
            )
        except InvalidSignature as exc:
            who = ("the pinned Intel SGX Root CA" if i + 1 == len(chain)
                   else f"issuer certificate [{i + 1}]")
            raise CollateralUntrusted(
                f"{label}: {who} did not sign "
                f"{chain[i].subject.rfc4514_string()}") from exc
    return signer


def verify_signed_document(item: CollateralItem, pinned_root, *,
                           check_leaf_certificate, check_ca_certificate,
                           now=None) -> dict:
    """Verify one Intel document over its **raw** bytes and return its value."""
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    value_key = item.signed_value_key
    signed, sig, value = split_signed_document(item.body, value_key)
    signer = verify_issuer_chain(
        item.issuer_chain_pem, pinned_root, item.label,
        check_leaf_certificate=check_leaf_certificate,
        check_ca_certificate=check_ca_certificate, now=now)
    signer_pub = signer.public_key()
    if not isinstance(signer_pub, ec.EllipticCurvePublicKey):
        raise CollateralUntrusted(
            f"{item.label}: signing certificate key is "
            f"{type(signer_pub).__name__}, not ECDSA")
    # Check the curve, not just "is it EC".  The r||s split below is a fixed 32
    # bytes each, which is only correct for P-256.  A P-384 signer produces a
    # 96-byte signature, and splitting that at 32 yields values that are not r
    # and s — so the verify would fail, but with the *wrong* explanation: the
    # error raised below says the document was modified or re-serialized, and
    # an operator would go looking for a JSON round-trip bug that does not
    # exist.  Refuse here with the curve named instead.
    #
    # Intel's own signing certificate is the authority for this, not a sample:
    # the chain served alongside every document has `CN=Intel SGX TCB Signing`
    # with an EC secp256r1 key and `ecdsa-with-SHA256`.  Mirrors the builder's
    # check in core/attestation/tcb_collateral.py so both halves refuse for the
    # same stated reason.
    if not isinstance(signer_pub.curve, ec.SECP256R1):
        raise CollateralUntrusted(
            f"{item.label}: signing certificate key is on curve "
            f"{signer_pub.curve.name}, but Intel signs collateral with "
            f"P-256 (secp256r1). Refusing rather than mis-parsing a "
            f"{len(sig)}-byte signature as two 32-byte halves.")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    try:
        signer_pub.verify(utils.encode_dss_signature(r, s), signed,
                          ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise CollateralUntrusted(
            f"{item.label}: Intel's signature does not cover these "
            f"{len(signed)} bytes of {value_key!r}. Either the document was "
            "modified, or it was re-serialized: json.loads -> json.dumps "
            "changes the bytes and therefore breaks the signature, so the "
            "verbatim response body must be stored and verified as-is. "
            f"sha256={hashlib.sha256(signed).hexdigest()[:16]}") from exc
    return value


# ---------------------------------------------------------------------------
# PCK certificate SGX extension: FMSPC, CPUSVN, PCESVN, component SVNs
# ---------------------------------------------------------------------------

def _der_tlv(buf: bytes, i: int):
    """Return ``(tag, content_start, content_end)`` for the TLV at *i*."""
    if i + 2 > len(buf):
        raise PckExtensionError("truncated DER")
    tag = buf[i]
    length = buf[i + 1]
    j = i + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or j + count > len(buf):
            raise PckExtensionError("unsupported DER length encoding")
        length = int.from_bytes(buf[j:j + count], "big")
        j += count
    if j + length > len(buf):
        raise PckExtensionError("DER length runs past the end of the buffer")
    return tag, j, j + length


def _der_oid(content: bytes) -> str:
    if not content:
        raise PckExtensionError("empty OID")
    first = content[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _der_int(content: bytes) -> int:
    return int.from_bytes(content, "big", signed=True)


def _collect_sgx_extension(buf: bytes, start: int, end: int, prefix: str, out):
    """Walk Intel's ``SEQUENCE OF SEQUENCE {OID, ANY}`` into ``out[oid] = tlv``."""
    i = start
    while i < end:
        tag, cs, ce = _der_tlv(buf, i)
        i = ce
        if tag != 0x30:
            continue
        oid_tag, oid_cs, oid_ce = _der_tlv(buf, cs)
        if oid_tag != 0x06:
            continue
        oid = _der_oid(buf[oid_cs:oid_ce])
        if oid_ce >= ce:
            continue
        val_tag, val_cs, val_ce = _der_tlv(buf, oid_ce)
        out[oid] = (val_tag, buf[val_cs:val_ce])
        if val_tag == 0x30:
            _collect_sgx_extension(buf, val_cs, val_ce, oid, out)


class PlatformTcb:
    """The platform TCB descriptors read out of the PCK leaf."""

    def __init__(self, fmspc: bytes, pceid: bytes, cpusvn: bytes, pcesvn: int,
                 sgx_components: list):
        self.fmspc = fmspc
        self.pceid = pceid
        self.cpusvn = cpusvn
        self.pcesvn = pcesvn
        self.sgx_components = sgx_components

    @property
    def fmspc_hex(self) -> str:
        return self.fmspc.hex()

    @property
    def pceid_hex(self) -> str:
        return self.pceid.hex()


def parse_pck_platform_tcb(pck_leaf) -> PlatformTcb:
    """Extract FMSPC / PCEID / CPUSVN / PCESVN / component SVNs from a PCK leaf.

    The SGX extension (OID ``1.2.840.113741.1.13.1``) is not a structure
    ``cryptography`` knows, so it arrives as an ``UnrecognizedExtension`` and
    has to be walked as DER.  Intel's layout: FMSPC at ``.4`` (6 bytes), PCEID
    at ``.3`` (2 bytes), and a nested TCB sequence at ``.2`` holding the 16
    component SVNs (``.2.1`` ... ``.2.16``), PCESVN (``.2.17``) and CPUSVN
    (``.2.18``, 16 bytes).
    """
    from cryptography import x509

    try:
        ext = pck_leaf.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(SGX_EXTENSION_OID))
    except x509.ExtensionNotFound as exc:
        raise PckExtensionError(
            "the PCK leaf carries no Intel SGX extension (OID "
            f"{SGX_EXTENSION_OID}), so its FMSPC and TCB level are unknown "
            "and no TCBInfo can be selected for it") from exc
    raw = getattr(ext.value, "value", None)
    if not isinstance(raw, (bytes, bytearray)):
        raise PckExtensionError("the PCK SGX extension has no raw DER value")
    raw = bytes(raw)
    tag, cs, ce = _der_tlv(raw, 0)
    if tag != 0x30:
        raise PckExtensionError("the PCK SGX extension is not a DER SEQUENCE")
    found = {}
    _collect_sgx_extension(raw, cs, ce, SGX_EXTENSION_OID, found)

    def _octets(oid, name, size):
        entry = found.get(oid)
        if entry is None:
            raise PckExtensionError(
                f"the PCK SGX extension has no {name} ({oid})")
        value = entry[1]
        if len(value) != size:
            raise PckExtensionError(
                f"{name} is {len(value)} bytes, expected {size}")
        return value

    fmspc = _octets(_OID_FMSPC, "FMSPC", 6)
    pceid = _octets(_OID_PCEID, "PCEID", 2)
    cpusvn = _octets(_OID_CPUSVN, "CPUSVN", 16)
    pcesvn_entry = found.get(_OID_PCESVN)
    if pcesvn_entry is None:
        raise PckExtensionError(
            f"the PCK SGX extension has no PCESVN ({_OID_PCESVN})")
    pcesvn = _der_int(pcesvn_entry[1])

    # Intel provides the 16 component SVNs individually and *also* as the
    # concatenated CPUSVN.  Prefer the individual fields (that is what Intel's
    # own QVL compares); fall back to CPUSVN's bytes, which carry the same
    # values in the same order, if a certificate omits them.
    components = []
    for idx in range(1, 17):
        entry = found.get(f"{_OID_TCB}.{idx}")
        if entry is None:
            components = list(cpusvn)
            break
        components.append(_der_int(entry[1]))
    if len(components) != 16:
        raise PckExtensionError(
            f"resolved {len(components)} SGX TCB component SVNs, expected 16")
    return PlatformTcb(fmspc, pceid, cpusvn, pcesvn, components)


# ---------------------------------------------------------------------------
# Status policy
# ---------------------------------------------------------------------------

def resolve_allowed_statuses(allowed=None) -> frozenset:
    """Return the accepted ``tcbStatus`` set: default plus explicit policy.

    ``OutOfDate``, ``OutOfDateConfigurationNeeded`` and ``Revoked`` can never
    be added.  An unrecognised name in the policy variable is a fatal
    configuration error, not a silently dropped entry: an operator who
    mistypes ``SWHardeningNeeded`` should find out from a failed run, not from
    an audit six months later.
    """
    if allowed is not None:
        return frozenset(allowed)
    result = set(DEFAULT_ALLOWED_STATUSES)
    raw = os.environ.get(ENV_ALLOW_STATUS, "")
    for name in (part.strip() for part in raw.split(",")):
        if not name:
            continue
        if name in DEFAULT_ALLOWED_STATUSES:
            continue
        if name not in OPTIONAL_ALLOWABLE_STATUSES:
            raise TcbPolicyError(
                f"{ENV_ALLOW_STATUS} lists {name!r}, which cannot be allowed. "
                f"Permitted values: {sorted(OPTIONAL_ALLOWABLE_STATUSES)}. "
                f"{sorted(NEVER_ALLOWED_STATUSES)} are refused under every "
                "policy — an out-of-date or revoked platform is not a "
                "configuration choice.")
        result.add(name)
    return frozenset(result)


# ---------------------------------------------------------------------------
# tcbStatus resolution
# ---------------------------------------------------------------------------

def _level_tcb(level, label):
    tcb = level.get("tcb")
    if not isinstance(tcb, dict):
        raise CollateralMalformed(f"{label}: TCB level has no 'tcb' object")
    return tcb


def _component_svns(tcb, key, label):
    raw = tcb.get(key)
    if not isinstance(raw, list) or len(raw) != 16:
        raise CollateralMalformed(
            f"{label}: {key} is not a 16-element array")
    out = []
    for entry in raw:
        if isinstance(entry, dict):
            svn = entry.get("svn")
        else:
            svn = entry
        if not isinstance(svn, int):
            raise CollateralMalformed(
                f"{label}: {key} entry has no integer 'svn'")
        out.append(svn)
    return out


def resolve_tcb_status(tcb_info: dict, platform: PlatformTcb, *, tee: str,
                       report_cpusvn: bytes = b"", tee_tcb_svn: bytes = b"",
                       label: str = "TCBInfo") -> tuple:
    """Resolve the platform's ``tcbStatus`` per Intel's comparison algorithm.

    A level matches when *every* component the level names is at or below what
    the platform reports:

    * the 16 SGX component SVNs from the PCK leaf's extension;
    * the report body's CPUSVN bytes, when the caller supplies them.  Intel's
      QVL compares only the certificate, but the certificate describes the TCB
      the platform was *provisioned* at; requiring the running report's CPUSVN
      to clear the same floor can only reject, never accept, and it is what the
      brief for this change asked for;
    * PCESVN from the PCK leaf's extension;
    * for TDX, the quote's ``TEE_TCB_SVN`` against ``tdxtcbcomponents``.

    Intel documents ``tcbLevels`` as sorted in descending TCB order and its QVL
    takes the first match.  We instead take the highest-TCB match, computed
    from the level's own component vector, so the answer does not depend on the
    order of an array we did not sort.  For a conforming document the two are
    the same thing.

    Returns ``(status, level, index)``.
    """
    levels = tcb_info.get("tcbLevels")
    if not isinstance(levels, list) or not levels:
        raise CollateralMalformed(f"{label} has no 'tcbLevels' array")

    want_tdx = tee == "tdx"
    if want_tdx and len(tee_tcb_svn) != 16:
        raise CollateralMalformed(
            f"TDX evaluation needs a 16-byte TEE_TCB_SVN, got "
            f"{len(tee_tcb_svn)} bytes")

    best = None
    for idx, level in enumerate(levels):
        if not isinstance(level, dict):
            raise CollateralMalformed(f"{label}: tcbLevels[{idx}] is not an object")
        tcb = _level_tcb(level, f"{label}[{idx}]")
        sgx_needed = _component_svns(tcb, "sgxtcbcomponents", f"{label}[{idx}]")
        pcesvn_needed = tcb.get("pcesvn")
        if not isinstance(pcesvn_needed, int):
            raise CollateralMalformed(
                f"{label}[{idx}]: 'pcesvn' is not an integer")

        if any(have < need for have, need in
               zip(platform.sgx_components, sgx_needed)):
            continue
        if report_cpusvn and any(
                have < need for have, need in zip(report_cpusvn, sgx_needed)):
            continue
        if platform.pcesvn < pcesvn_needed:
            continue

        rank = tuple(sgx_needed) + (pcesvn_needed,)
        if want_tdx:
            tdx_needed = _component_svns(tcb, "tdxtcbcomponents",
                                         f"{label}[{idx}]")
            if any(have < need for have, need in
                   zip(tee_tcb_svn, tdx_needed)):
                continue
            rank = rank + tuple(tdx_needed)

        status = level.get("tcbStatus")
        if not isinstance(status, str) or not status:
            raise CollateralMalformed(
                f"{label}[{idx}] has no 'tcbStatus' string")
        if best is None or rank > best[0]:
            best = (rank, status, level, idx)

    if best is None:
        raise TcbStatusRejected(
            "the platform's TCB is below every level Intel publishes for FMSPC "
            f"{platform.fmspc_hex} (PCK components "
            f"{list(platform.sgx_components)}, PCESVN {platform.pcesvn}"
            + (f", TEE_TCB_SVN {tee_tcb_svn.hex()}" if want_tdx else "")
            + "). This platform is older than the oldest TCB level Intel still "
            "describes, which is strictly worse than OutOfDate.")
    return best[1], best[2], best[3]


def check_tcb_info_applies(tcb_info: dict, platform: PlatformTcb, *, tee: str,
                           label: str = "TCBInfo") -> None:
    """Refuse a TCBInfo that describes a different platform or TEE."""
    doc_id = tcb_info.get("id")
    expected_id = {"sgx": "SGX", "tdx": "TDX"}[tee]
    if doc_id is not None and doc_id != expected_id:
        raise CollateralMalformed(
            f"{label} is for id={doc_id!r}, but this client is verifying "
            f"{expected_id}")
    if tee == "tdx" and doc_id is None:
        raise CollateralMalformed(
            f"{label} has no 'id'; TDX evaluation needs a v3 TCBInfo "
            "(id=\"TDX\") because only v3 carries tdxtcbcomponents")
    fmspc = tcb_info.get("fmspc")
    if not isinstance(fmspc, str) or not fmspc:
        raise CollateralMalformed(f"{label} has no 'fmspc'")
    if fmspc.lower() != platform.fmspc_hex.lower():
        raise CollateralMalformed(
            f"{label} is for FMSPC {fmspc.lower()} but this platform's PCK "
            f"leaf says {platform.fmspc_hex}. The bundle was fetched for a "
            "different CPU model; no statement in it applies here.")
    pce_id = tcb_info.get("pceId")
    if isinstance(pce_id, str) and pce_id:
        if pce_id.lower() != platform.pceid_hex.lower():
            raise CollateralMalformed(
                f"{label} is for pceId {pce_id.lower()} but this platform's "
                f"PCK leaf says {platform.pceid_hex}")


# ---------------------------------------------------------------------------
# QEIdentity
# ---------------------------------------------------------------------------

def _apply_mask(value: bytes, mask: bytes) -> bytes:
    """Bitwise-AND *value* with *mask*.

    Extracted so the QEIdentity ``attributes``/``miscselect`` comparison and
    the TDX module ``attributes`` comparison mask identically — the second one
    was originally written as a copy, and a copy is how the earlier
    "four clients drifted" attestation bugs started.
    """
    return bytes(a & b for a, b in zip(value, mask))


def _mask_equal(reported: bytes, expected_hex: str, mask_hex: str, name: str):
    try:
        expected = bytes.fromhex(expected_hex)
        mask = bytes.fromhex(mask_hex)
    except (TypeError, ValueError) as exc:
        raise CollateralMalformed(
            f"QEIdentity {name}/{name}Mask is not hex: {exc}") from exc
    if len(expected) != len(reported) or len(mask) != len(reported):
        raise CollateralMalformed(
            f"QEIdentity {name} is {len(expected)} bytes and its mask "
            f"{len(mask)}; the QE report field is {len(reported)}")
    masked_report = _apply_mask(reported, mask)
    masked_expected = _apply_mask(expected, mask)
    if masked_report != masked_expected:
        raise QeIdentityRejected(
            f"the QE report's {name} does not match the signed QEIdentity "
            f"under its mask (report {masked_report.hex()}, expected "
            f"{masked_expected.hex()}, mask {mask.hex()})")


def evaluate_qe_identity(enclave_identity: dict, qe_report: bytes, *, tee: str,
                         allowed_statuses: frozenset) -> dict:
    """Check the QE report against the signed QEIdentity.

    ``qe_report`` is the 384-byte ``sgx_report_body_t`` the caller located in
    the quote (SGX v3: offset 564; TDX v4: ``_locate_qe_report_offset``).
    Field offsets inside it: MISCSELECT at 16 (4 bytes), ATTRIBUTES at 48
    (16 bytes), MRSIGNER at 128 (32 bytes), ISVPRODID at 256 and ISVSVN at 258
    (both little-endian uint16).
    """
    if len(qe_report) != 384:
        raise QeIdentityRejected(
            f"the QE report is {len(qe_report)} bytes, expected 384; there is "
            "nothing to compare against QEIdentity")

    expected_id = {"sgx": "QE", "tdx": "TD_QE"}[tee]
    doc_id = enclave_identity.get("id")
    if doc_id is not None and doc_id != expected_id:
        raise CollateralMalformed(
            f"QEIdentity is for id={doc_id!r}, expected {expected_id!r}")

    miscselect = qe_report[16:20]
    attributes = qe_report[48:64]
    mrsigner = qe_report[128:160]
    isvprodid = int.from_bytes(qe_report[256:258], "little")
    isvsvn = int.from_bytes(qe_report[258:260], "little")

    for name, reported in (("miscselect", miscselect), ("attributes", attributes)):
        expected_hex = enclave_identity.get(name)
        mask_hex = enclave_identity.get(name + "Mask")
        if not isinstance(expected_hex, str) or not isinstance(mask_hex, str):
            raise CollateralMalformed(
                f"QEIdentity has no {name}/{name}Mask pair")
        _mask_equal(reported, expected_hex, mask_hex, name)

    want_prodid = enclave_identity.get("isvprodid")
    if not isinstance(want_prodid, int):
        raise CollateralMalformed("QEIdentity has no integer 'isvprodid'")
    if isvprodid != want_prodid:
        raise QeIdentityRejected(
            f"the QE report's ISVPRODID is {isvprodid}, the signed QEIdentity "
            f"says {want_prodid} — this is not the Quoting Enclave Intel "
            "described")

    want_mrsigner = enclave_identity.get("mrsigner")
    if isinstance(want_mrsigner, str) and want_mrsigner:
        if mrsigner.hex().lower() != want_mrsigner.lower():
            raise QeIdentityRejected(
                f"the QE report's MRSIGNER is {mrsigner.hex()}, the signed "
                f"QEIdentity says {want_mrsigner.lower()}")

    levels = enclave_identity.get("tcbLevels")
    if not isinstance(levels, list) or not levels:
        raise CollateralMalformed("QEIdentity has no 'tcbLevels' array")
    best = None
    for idx, level in enumerate(levels):
        if not isinstance(level, dict):
            raise CollateralMalformed(
                f"QEIdentity tcbLevels[{idx}] is not an object")
        tcb = _level_tcb(level, f"QEIdentity[{idx}]")
        want_svn = tcb.get("isvsvn")
        if not isinstance(want_svn, int):
            raise CollateralMalformed(
                f"QEIdentity tcbLevels[{idx}]: 'isvsvn' is not an integer")
        if isvsvn < want_svn:
            continue
        status = level.get("tcbStatus")
        if not isinstance(status, str) or not status:
            raise CollateralMalformed(
                f"QEIdentity tcbLevels[{idx}] has no 'tcbStatus' string")
        if best is None or want_svn > best[0]:
            best = (want_svn, status)

    if best is None:
        floors = sorted(
            lvl.get("tcb", {}).get("isvsvn", 0) for lvl in levels
            if isinstance(lvl, dict))
        raise QeIdentityRejected(
            f"the QE report's ISVSVN is {isvsvn}, below every level in the "
            f"signed QEIdentity (lowest {floors[0] if floors else '?'}). The "
            "Quoting Enclave that produced this quote is older than anything "
            "Intel still vouches for.")

    status = best[1]
    if status not in allowed_statuses:
        raise QeIdentityRejected(
            f"the Quoting Enclave's QEIdentity tcbStatus is {status!r} at "
            f"ISVSVN {isvsvn}; accepted statuses are "
            f"{sorted(allowed_statuses)}")
    return {"status": status, "isvsvn": isvsvn, "isvprodid": isvprodid,
            "matched_isvsvn": best[0]}


# ---------------------------------------------------------------------------
# TDX module (SEAM) identity and TCB level
# ---------------------------------------------------------------------------

#: Byte positions inside ``TEE_TCB_SVN`` (the 16 bytes at TD report body offset
#: 0).  These two are NOT interchangeable and the repository has already
#: shipped them the wrong way round — see ``TDX-3`` in
#: ``templates/tdx/azure/client.template.py``, which reads ``[0]`` as the major
#: version.  Intel's own verification library is explicit:
#:
#:   ``static constexpr uint16_t TDX_MODULE_MAJOR_SVN_INDEX = 1; // aka
#:   TDX_MODULE_VERSION_INDEX``
#:   ``static constexpr uint16_t TDX_MODULE_MINOR_SVN_INDEX = 0;``
#:
#: — intel/SGX-TDX-DCAP-QuoteVerificationLibrary,
#: ``Src/AttestationLibrary/src/Verifiers/Checks/EvaluateTcb.cpp`` lines
#: 110-111 (read 2026-08-20).  Index 1 selects *which*
#: ``tdxModuleIdentities`` entry applies; index 0 is the ISV SVN compared
#: against that entry's ``tcbLevels[].tcb.isvsvn``.
TDX_MODULE_VERSION_INDEX = 1
TDX_MODULE_ISVSVN_INDEX = 0

#: The three ``tcbStatus`` values Intel permits inside a
#: ``tdxModuleIdentities[].tcbLevels[]`` entry.  Narrower than the platform
#: set: a TDX module cannot be "ConfigurationNeeded".  From
#: ``VALID_TDX_MODULE_STATUSES`` in the same ``EvaluateTcb.cpp`` (lines
#: 104-108).  Anything else is a document we do not understand, so it is
#: refused rather than mapped to the nearest known value.
TDX_MODULE_LEVEL_STATUSES = frozenset({"UpToDate", "OutOfDate", "Revoked"})

#: Byte layout of the TD report body, which the caller passes in whole so that
#: these offsets live in exactly one place instead of in each client.  Taken
#: from the layout ``parse_tdx_quote`` in the TDX clients already documents and
#: parses (``templates/tdx/azure/client.template.py``): the body starts at
#: quote offset 48, ``TEE_TCB_SVN`` at body offset 0 (16 bytes), MRSEAM at 16
#: (48), **MRSIGNERSEAM at 64 (48)**, **SEAMATTRIBUTES at 112 (8)**,
#: TDATTRIBUTES at 120 (8), XFAM at 128 (8), MRTD at 136 (48).
TD_REPORT_BODY_MIN_LEN = 584
_TD_MRSIGNERSEAM = (64, 112)
_TD_SEAMATTRIBUTES = (112, 120)


def tdx_module_identity_id(version: int) -> str:
    """Render the ``tdxModuleIdentities[].id`` that *version* selects.

    Intel builds the key as ``"TDX_" + bytesToHexString({tdxModuleVersion})``
    and upper-cases the *document's* id before comparing
    (``findTdxModuleIdentity``,
    ``Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp``, read
    2026-08-20).  ``bytesToHexString`` emits upper-case, two digits per byte
    (``Src/AttestationCommons/include/OpensslHelpers/Bytes.h``), so the key is
    e.g. ``TDX_01`` for version 1 and ``TDX_0A`` for version 10 — never
    ``TDX_1``.  Matching Intel's case-folding here rather than requiring
    upper-case in the document is deliberate: live PCS emits ``TDX_01`` /
    ``TDX_03`` (observed 2026-08-20), but Intel's own verifier accepts either
    case and diverging would reject a document Intel considers valid.
    """
    return "TDX_%02X" % (version & 0xFF)


def td_report_module_fields(td_report_body: bytes, tee_tcb_svn: bytes,
                            *, label: str = "TD report") -> tuple:
    """Slice ``(mrsignerseam, seam_attributes)`` out of the TD report body.

    *tee_tcb_svn* is what the caller already parsed out of the same quote; it
    is re-derived here and cross-checked, because the one plausible way to
    misuse this function is to hand it the whole quote instead of the body at
    offset 48, and in that case the first 16 bytes are the quote header rather
    than ``TEE_TCB_SVN``.  A length check alone would not catch that.

    Accepts a body *at least* ``TD_REPORT_BODY_MIN_LEN`` long rather than
    exactly that: TDX 1.5 quotes carry ``TD_REPORT15`` (584 + TEE_TCB_SVN2 and
    MRSERVICETD), whose first 584 bytes have the identical layout.  Everything
    read here lives in the first 120 bytes, which both versions share.
    """
    if not isinstance(td_report_body, (bytes, bytearray)) or not td_report_body:
        raise CollateralMalformed(
            f"{label}: TDX evaluation needs the TD report body (the 584 bytes "
            "at quote offset 48) to check the TDX module's MRSIGNERSEAM and "
            "SEAMATTRIBUTES, and none was supplied. This is a client wiring "
            "error, not a bad quote: the caller must pass "
            "td_report_body=quote_bytes[48:632]. Refusing rather than skipping "
            "the check — an unverified TDX module is a module signed by "
            "whoever wrote the hypervisor.")
    td_report_body = bytes(td_report_body)
    if len(td_report_body) < TD_REPORT_BODY_MIN_LEN:
        raise CollateralMalformed(
            f"{label}: TD report body is {len(td_report_body)} bytes, expected "
            f"at least {TD_REPORT_BODY_MIN_LEN}")
    if len(tee_tcb_svn) != 16:
        raise CollateralMalformed(
            f"{label}: TEE_TCB_SVN is {len(tee_tcb_svn)} bytes, expected 16")
    if td_report_body[0:16] != bytes(tee_tcb_svn):
        raise CollateralMalformed(
            f"{label}: the TD report body's first 16 bytes "
            f"({td_report_body[0:16].hex()}) are not the TEE_TCB_SVN the "
            f"caller passed ({bytes(tee_tcb_svn).hex()}). These must be the "
            "same bytes from the same quote; the usual cause is passing the "
            "whole quote instead of quote_bytes[48:632], which makes the quote "
            "header masquerade as TEE_TCB_SVN.")
    return (td_report_body[_TD_MRSIGNERSEAM[0]:_TD_MRSIGNERSEAM[1]],
            td_report_body[_TD_SEAMATTRIBUTES[0]:_TD_SEAMATTRIBUTES[1]])


def _tdx_module_expected(node: dict, where: str) -> tuple:
    """Read ``(mrsigner, attributes, attributesMask)`` as bytes from *node*."""
    out = []
    for field, size in (("mrsigner", 48), ("attributes", 8),
                        ("attributesMask", 8)):
        value = node.get(field)
        if not isinstance(value, str) or not value:
            raise CollateralMalformed(
                f"{where} has no {field!r} string. Intel's TDX TCBInfo always "
                "carries all three of mrsigner/attributes/attributesMask "
                "(observed across every FMSPC with TDX collateral, "
                "2026-08-20); a document without them cannot be evaluated and "
                "is refused rather than partially checked.")
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise CollateralMalformed(
                f"{where}: {field}={value!r} is not hex: {exc}") from exc
        if len(raw) != size:
            raise CollateralMalformed(
                f"{where}: {field} is {len(raw)} bytes, expected {size}")
        out.append(raw)
    return tuple(out)


def evaluate_tdx_module(tcb_info: dict, *, tee_tcb_svn: bytes,
                        mrsignerseam: bytes, seam_attributes: bytes,
                        label: str = "TCBInfo") -> dict:
    """Check the quote's TDX module against ``tdxModule``/``tdxModuleIdentities``.

    Until this existed the TDX module was covered only by a hand-rolled
    "version >= 1.5" floor in the TDX client, which compared the wrong
    ``TEE_TCB_SVN`` bytes (see :data:`TDX_MODULE_VERSION_INDEX`) and never
    looked at who signed the module at all.  A SEAM module signed by anyone —
    including the untrusted hypervisor — passed.

    The algorithm, from Intel's QVL (``checkTdxModule`` in
    ``Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp`` lines 143-215
    and ``tdxEvaluateTCB`` in ``.../Checks/EvaluateTcb.cpp`` lines 305-400,
    both read 2026-08-20), plus the field shapes confirmed against live PCS
    (``https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=...``):

    1. The baseline expectation is ``tcbInfo.tdxModule``:
       ``{"mrsigner": <96 hex chars>, "attributes": <16>,
       "attributesMask": <16>}``.  Live PCS returns
       ``mrsigner`` = 48 zero bytes, ``attributes`` = 8 zero bytes,
       ``attributesMask`` = ``FFFFFFFFFFFFFFFF`` for every FMSPC that has TDX
       collateral, i.e. "SEAMATTRIBUTES must be entirely zero".
    2. ``version = TEE_TCB_SVN[1]``.  When it is non-zero the expectation is
       *replaced* by the ``tdxModuleIdentities`` entry whose ``id`` is
       ``TDX_<version as two upper-case hex digits>``, and that entry's
       ``tcbLevels`` additionally yield a module ``tcbStatus``: the highest
       ``tcb.isvsvn`` that ``TEE_TCB_SVN[0]`` clears.  When it is zero there is
       no per-version identity and no module status — only the MRSIGNERSEAM /
       SEAMATTRIBUTES comparison against ``tdxModule``.
    3. MRSIGNERSEAM is compared byte-exactly (QVL does not mask it, and there
       is no ``mrsignerMask`` in the document).  SEAMATTRIBUTES is compared
       under ``attributesMask``, via the same :func:`_apply_mask` the
       QEIdentity comparison uses.

    Two deliberate divergences from QVL, both noted because "we match Intel"
    is otherwise the claim a reader will assume:

    * QVL's SEAMATTRIBUTES loop is
      ``if (a[i] != 0 || a[i] != expected[i]) fail``, which ignores
      ``attributesMask`` entirely and demands the byte be zero *and* equal.
      We apply the documented masked comparison.  On every FMSPC Intel
      currently publishes the two are the same test, because ``attributes`` is
      all-zero under an all-ones mask; the masked form is what keeps working
      if Intel ever ships a non-zero expectation.
    * We take the highest matching ``isvsvn`` rather than the first entry in
      document order, matching what :func:`resolve_tcb_status` and
      :func:`evaluate_qe_identity` already do here.  For the
      descending-sorted array Intel documents, identical.

    Returns a summary dict.  Raises :class:`TdxModuleRejected` when the quote's
    module is not the described one, and :class:`CollateralMalformed` when the
    document cannot support the check.

    Fail-closed on absence, deliberately: a TDX ``tcbInfo`` with no
    ``tdxModule`` (or no matching identity when the version demands one) is
    refused, not waved through.  That is safe as well as correct — on
    2026-08-20 all 16 of the 39 FMSPCs in
    ``/sgx/certification/v4/fmspcs?platform=all`` for which
    ``/tdx/certification/v4/tcb`` returns 200 carry ``version: 3``, a
    ``tdxModule`` object, and ``tdxModuleIdentities`` with exactly the ids
    ``TDX_03`` and ``TDX_01``; the remaining 23 return 404 and so never reach
    TDX evaluation at all.  Intel's own verifier is equally hard here
    (``STATUS_TCB_INFO_MISMATCH`` / ``STATUS_TCB_NOT_SUPPORTED``).
    """
    if len(mrsignerseam) != 48:
        raise CollateralMalformed(
            f"{label}: MRSIGNERSEAM from the TD report is "
            f"{len(mrsignerseam)} bytes, expected 48")
    if len(seam_attributes) != 8:
        raise CollateralMalformed(
            f"{label}: SEAMATTRIBUTES from the TD report is "
            f"{len(seam_attributes)} bytes, expected 8")
    if len(tee_tcb_svn) != 16:
        raise CollateralMalformed(
            f"{label}: TEE_TCB_SVN is {len(tee_tcb_svn)} bytes, expected 16")

    version = tcb_info.get("version")
    if not isinstance(version, int) or version < 3:
        raise CollateralMalformed(
            f"{label} declares version {version!r}; the TDX module fields "
            "(tdxModule / tdxModuleIdentities) only exist from TCBInfo v3, so "
            "the TDX module cannot be evaluated against this document. Every "
            "TDX TCBInfo Intel serves is v3 (observed 2026-08-20). Re-fetch "
            "the collateral.")

    base = tcb_info.get("tdxModule")
    if not isinstance(base, dict):
        raise CollateralMalformed(
            f"{label} carries no 'tdxModule' object, so the expected "
            "MRSIGNERSEAM of the TDX module is unknown and a module signed by "
            "anybody at all would go unnoticed. Every TDX TCBInfo Intel serves "
            "carries it (observed 2026-08-20 across all 16 FMSPCs with TDX "
            "collateral). Re-fetch the collateral rather than relaxing this.")
    where = f"{label}.tdxModule"
    expected_mrsigner, expected_attrs, attrs_mask = _tdx_module_expected(
        base, where)

    module_version = tee_tcb_svn[TDX_MODULE_VERSION_INDEX]
    module_isvsvn = tee_tcb_svn[TDX_MODULE_ISVSVN_INDEX]
    identity_id = ""
    status = ""
    tcb_date = ""
    advisory_ids = []
    matched_isvsvn = None

    if module_version > 0:
        # Quote version is not consulted here even though QVL gates the
        # identity override on ``header.version > 3``: TDX quotes are v4 or
        # v5 by construction (v3 is SGX-only, and parse_tdx_quote refuses a
        # non-TDX tee_type), so the gate is vacuous for anything that reaches
        # this module.  ``tdxEvaluateTCB``, which computes the status, has no
        # version gate at all.
        identity_id = tdx_module_identity_id(module_version)
        identities = tcb_info.get("tdxModuleIdentities")
        if not isinstance(identities, list) or not identities:
            raise CollateralMalformed(
                f"{label} has no 'tdxModuleIdentities' array, but this quote's "
                f"TEE_TCB_SVN[{TDX_MODULE_VERSION_INDEX}] is {module_version} "
                f"({identity_id}), so an identity is required to know what "
                "that module version should look like and how current it is.")
        match = None
        for idx, entry in enumerate(identities):
            if not isinstance(entry, dict):
                raise CollateralMalformed(
                    f"{label}: tdxModuleIdentities[{idx}] is not an object")
            entry_id = entry.get("id")
            if not isinstance(entry_id, str):
                raise CollateralMalformed(
                    f"{label}: tdxModuleIdentities[{idx}] has no 'id' string")
            if entry_id.upper() != identity_id:
                continue
            if match is not None:
                raise CollateralMalformed(
                    f"{label} declares {identity_id!r} more than once in "
                    "tdxModuleIdentities; which one Intel meant is ambiguous")
            match = (idx, entry)
        if match is None:
            raise TdxModuleRejected(
                f"this quote reports TDX module version {module_version} "
                f"(TEE_TCB_SVN[{TDX_MODULE_VERSION_INDEX}]), so Intel's "
                f"TCBInfo must describe {identity_id!r} — it describes "
                + str(sorted(str(e.get("id")) for e in identities))
                + ". Intel does not publish an identity for this module "
                "version, so nothing vouches for the SEAM module running this "
                "TD.")
        idx, entry = match
        where = f"{label}.tdxModuleIdentities[{idx}] ({identity_id})"
        expected_mrsigner, expected_attrs, attrs_mask = _tdx_module_expected(
            entry, where)

        levels = entry.get("tcbLevels")
        if not isinstance(levels, list) or not levels:
            raise CollateralMalformed(f"{where} has no 'tcbLevels' array")
        best = None
        for level_idx, level in enumerate(levels):
            if not isinstance(level, dict):
                raise CollateralMalformed(
                    f"{where}: tcbLevels[{level_idx}] is not an object")
            tcb = _level_tcb(level, f"{where}[{level_idx}]")
            want = tcb.get("isvsvn")
            if not isinstance(want, int):
                raise CollateralMalformed(
                    f"{where}: tcbLevels[{level_idx}].tcb.isvsvn is not an "
                    "integer")
            level_status = level.get("tcbStatus")
            if level_status not in TDX_MODULE_LEVEL_STATUSES:
                raise CollateralMalformed(
                    f"{where}: tcbLevels[{level_idx}].tcbStatus is "
                    f"{level_status!r}, which is not one of "
                    f"{sorted(TDX_MODULE_LEVEL_STATUSES)}. Refusing to guess "
                    "what an unknown TDX module status means.")
            if module_isvsvn < want:
                continue
            if best is None or want > best[0]:
                best = (want, level_status, level)
        if best is None:
            floors = sorted(
                lvl.get("tcb", {}).get("isvsvn", 0) for lvl in levels
                if isinstance(lvl, dict))
            raise TdxModuleRejected(
                f"the TDX module's ISV SVN is {module_isvsvn} "
                f"(TEE_TCB_SVN[{TDX_MODULE_ISVSVN_INDEX}]), below every level "
                f"{where} describes (lowest {floors[0] if floors else '?'}). "
                "This SEAM module is older than anything Intel still vouches "
                "for.")
        matched_isvsvn, status, level = best
        tcb_date = level.get("tcbDate", "")
        advisory_ids = list(level.get("advisoryIDs") or [])

    if mrsignerseam != expected_mrsigner:
        raise TdxModuleRejected(
            f"the TD report's MRSIGNERSEAM is {mrsignerseam.hex()}, but "
            f"{where} says the TDX module is signed by "
            f"{expected_mrsigner.hex()}. The SEAM module measured into this "
            "quote is not the one Intel published, so the TD's isolation "
            "rests on code of unknown origin.")

    masked_report = _apply_mask(seam_attributes, attrs_mask)
    masked_expected = _apply_mask(expected_attrs, attrs_mask)
    if masked_report != masked_expected:
        raise TdxModuleRejected(
            f"the TD report's SEAMATTRIBUTES is {seam_attributes.hex()}, which "
            f"does not match {where}'s attributes {expected_attrs.hex()} under "
            f"mask {attrs_mask.hex()} (report {masked_report.hex()} vs "
            f"expected {masked_expected.hex()}). Intel currently publishes an "
            "all-zero expectation, so any set bit here is a TDX module running "
            "with attributes Intel does not describe.")

    return {
        "version": module_version,
        "isvsvn": module_isvsvn,
        "identity_id": identity_id,
        "source": where,
        "mrsignerseam": mrsignerseam.hex(),
        "seam_attributes": seam_attributes.hex(),
        "status": status,
        "matched_isvsvn": matched_isvsvn,
        "tcb_date": tcb_date,
        "advisory_ids": advisory_ids,
    }


#: How a TDX module ``tcbStatus`` degrades the platform ``tcbStatus``.  Intel
#: calls this convergence (``convergeTcbStatuses``,
#: ``Src/AttestationLibrary/src/Verifiers/Checks/EvaluateTcb.cpp`` lines
#: 187-224, read 2026-08-20): an out-of-date *component* makes the whole
#: evaluation out of date, and the ``ConfigurationNeeded`` flavours keep their
#: configuration flag while gaining the out-of-date one.  Without this step
#: matching MRSIGNERSEAM would be the only thing the module check bought, and a
#: TD running a SEAM module with published errata would still report UpToDate.
_TDX_MODULE_OUT_OF_DATE_MAP = {
    "UpToDate": "OutOfDate",
    "SWHardeningNeeded": "OutOfDate",
    "ConfigurationNeeded": "OutOfDateConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded": "OutOfDateConfigurationNeeded",
}


def converge_tdx_module_status(platform_status: str,
                               module_status: str) -> str:
    """Fold a TDX module ``tcbStatus`` into the platform's.

    ``module_status`` is ``""`` when the quote reports TDX module version 0,
    which carries no per-version identity and therefore no module status; the
    platform status then stands unchanged.
    """
    if module_status == "Revoked":
        return "Revoked"
    if module_status == "OutOfDate":
        return _TDX_MODULE_OUT_OF_DATE_MAP.get(platform_status,
                                               platform_status)
    return platform_status


# ---------------------------------------------------------------------------
# PCK CRL
# ---------------------------------------------------------------------------

def _load_crl(data: bytes, label: str):
    from cryptography import x509

    errors = []
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            return loader(data)
        except Exception as exc:  # noqa: BLE001 - try the other encoding
            errors.append(f"{loader.__name__}: {exc}")
    raise CollateralMalformed(
        f"{label} is neither DER nor PEM CRL ({'; '.join(errors)})")


def check_pck_not_revoked(pck_chain: list, crl_items: list, pinned_root, *,
                          check_leaf_certificate, check_ca_certificate,
                          now=None) -> dict:
    """Reject a revoked PCK leaf or intermediate.

    Coverage rule, and the one honest gap in it:

    * Every certificate whose issuer is **not** the pinned root — in practice
      the PCK leaf — must be covered by a CRL in the bundle that its own issuer
      signed.  "No CRL for this CA" is a hard failure here: an uncovered
      certificate is indistinguishable from a revoked one, and calling that
      fine is precisely the soft-skip that made earlier attestation bypasses
      reachable.

    * A certificate issued **by the pinned root** — the PCK Platform/Processor
      CA itself — is checked when a root-issued CRL is present, and reported as
      *not covered* when it is not.  The builder fetches
      ``/pckcrl?ca=platform`` and ``?ca=processor``; Intel publishes the Root CA
      CRL at a separate distribution point
      (https://certificates.trustedservices.intel.com/IntelSGXRootCA.der) that
      the bundle does not currently carry.  Making that a hard failure today
      would fail every deploy over a revocation Intel has never issued, so the
      gap is *named in the output* instead of hidden: ``enforce`` prints that
      root-level revocation was not covered, and never prints PASSED for it.
      Add the root CRL to the bundle and this tightens with no client change.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    from cryptography.exceptions import InvalidSignature

    by_issuer = {}
    for item in crl_items:
        crl = _load_crl(item.body, item.label)
        signer = verify_issuer_chain(
            item.issuer_chain_pem, pinned_root, item.label,
            check_leaf_certificate=check_leaf_certificate,
            check_ca_certificate=check_ca_certificate, now=now,
            signer_is_ca=True)
        if crl.issuer != signer.subject:
            raise CollateralMalformed(
                f"{item.label}: CRL issuer {crl.issuer.rfc4514_string()!r} is "
                f"not the subject of its own issuer chain "
                f"({signer.subject.rfc4514_string()!r})")
        signer_pub = signer.public_key()
        try:
            valid = crl.is_signature_valid(signer_pub)
        except InvalidSignature:
            valid = False
        if not valid:
            raise CollateralUntrusted(
                f"{item.label}: CRL signature does not verify against its "
                "issuer certificate")
        next_update = getattr(crl, "next_update_utc", None)
        if next_update is None:
            raise CollateralMalformed(
                f"{item.label}: CRL has no nextUpdate, so its lifetime is "
                "unbounded")
        if now > next_update:
            raise CollateralStale(
                f"{item.label}: CRL expired at {next_update.isoformat()}; a "
                "revocation published since would be invisible")
        by_issuer.setdefault(crl.issuer, []).append((item.label, crl))

    checked = 0
    uncovered_root_issued = []
    for idx, cert in enumerate(pck_chain):
        if cert == pinned_root:
            continue
        crls = by_issuer.get(cert.issuer)
        if not crls:
            if cert.issuer == pinned_root.subject:
                uncovered_root_issued.append(cert.subject.rfc4514_string())
                continue
            raise PckRevoked(
                f"no CRL in the bundle was issued by "
                f"{cert.issuer.rfc4514_string()!r}, the issuer of PCK chain "
                f"certificate [{idx}] ({cert.subject.rfc4514_string()!r}). "
                "Without it a revoked certificate looks exactly like a valid "
                "one. The bundle must carry the PCK CA CRL "
                "(sgx_pck_crl_platform / sgx_pck_crl_processor).")
        for crl_label, crl in crls:
            if crl.get_revoked_certificate_by_serial_number(
                    cert.serial_number) is not None:
                raise PckRevoked(
                    f"PCK chain certificate [{idx}] "
                    f"({cert.subject.rfc4514_string()!r}, serial "
                    f"{cert.serial_number:x}) is listed as revoked on "
                    f"{crl_label}. Intel has withdrawn trust in this platform "
                    "key.")
        checked += 1
    if not checked:
        raise PckRevoked(
            "no certificate in the PCK chain was covered by any CRL in the "
            "bundle, so nothing about this platform's revocation status is "
            "known")
    return {"certificates_checked": checked, "crls": len(crl_items),
            "uncovered_root_issued": uncovered_root_issued}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def evaluate(*, tee: str, pck_chain: list, qe_report: bytes,
             pinned_root_ca_pem: str, check_leaf_certificate,
             check_ca_certificate, report_cpusvn: bytes = b"",
             tee_tcb_svn: bytes = b"", td_report_body: bytes = b"",
             collateral_path: str = "",
             now=None, max_age_seconds: int = 0,
             allowed_statuses=None) -> dict:
    """Run the whole evaluation in Intel's DCAP QVL order.

    1. load the bundle and re-verify every signature against the **pinned**
       root (never the bundle's own copy);
    2. bound its age, and Intel's own ``nextUpdate``;
    3. read FMSPC / CPUSVN / PCESVN out of the PCK leaf;
    4. resolve ``tcbStatus``;
    5. for TDX, check the TDX module against ``tdxModule`` /
       ``tdxModuleIdentities`` and fold its status into the platform's;
    6. apply the policy to the converged status;
    7. check QEIdentity against the QE report;
    8. check the PCK CRLs.

    ``td_report_body`` is the TD report body, ``quote_bytes[48:632]``, and is
    **required for TDX**: it is where MRSIGNERSEAM and SEAMATTRIBUTES live.
    It is ignored for SGX, which has no TDX module.

    Raises a :class:`TcbEvalError` subclass on any failure.  Returns a summary
    dict on success.
    """
    if tee not in _ITEMS_BY_TEE:
        raise TcbPolicyError(f"unknown TEE {tee!r}")
    if not pck_chain:
        raise CollateralMalformed(
            "no PCK certificate chain was passed to the TCB evaluation")

    now = now or datetime.datetime.now(datetime.timezone.utc)
    allowed = resolve_allowed_statuses(allowed_statuses)
    pinned_root = load_pinned_root(pinned_root_ca_pem)
    bundle = CollateralBundle.load(collateral_path)
    notes = []
    root_note = check_root_ca_fingerprint(bundle, pinned_root)
    if root_note:
        notes.append(root_note)

    age = check_freshness(bundle, now=now, max_age_seconds=max_age_seconds)

    # The FMSPC is a property of the platform, readable only from a real
    # quote's PCK leaf, so the build host cannot know it and the default bundle
    # ships without TCBInfo.  Parse the leaf *before* demanding the item so the
    # failure can tell the operator the exact value to rebuild with.
    platform = parse_pck_platform_tcb(pck_chain[0])

    tcb_item_name = _ITEMS_BY_TEE[tee]["tcb_info"]
    if not bundle.has(tcb_item_name):
        raise TcbInfoUnavailable(
            f"the collateral bundle at {bundle.source} carries no "
            f"{tcb_item_name!r}, so this platform's tcbStatus cannot be "
            "resolved and the quote is refused.\n"
            f"  This platform's FMSPC is {platform.fmspc_hex.upper()} "
            f"(read from the PCK leaf just verified).\n"
            "  The FMSPC identifies the CPU model and only exists in a real "
            "quote, so the build host could not know it in advance; Intel's "
            "/tcb endpoint requires it.\n"
            f"  Fix: re-run the build with TEE_CRAFTER_FMSPC="
            f"{platform.fmspc_hex.upper()} so the bundle includes TCBInfo for "
            "this platform, or point $" + ENV_COLLATERAL_PATH + " at a bundle "
            "that already does.\n"
            f"  Bundle says: complete={bundle.declared_complete}, "
            f"missing={bundle.declared_missing}, "
            f"fmspc={bundle.declared_fmspc!r}.")

    tcb_info = verify_signed_document(
        bundle.item(tcb_item_name), pinned_root,
        check_leaf_certificate=check_leaf_certificate,
        check_ca_certificate=check_ca_certificate, now=now)
    check_next_update(tcb_info, tcb_item_name, now=now)

    enclave_identity = verify_signed_document(
        bundle.qe_identity(tee), pinned_root,
        check_leaf_certificate=check_leaf_certificate,
        check_ca_certificate=check_ca_certificate, now=now)
    check_next_update(enclave_identity, _ITEMS_BY_TEE[tee]["qe_identity"],
                      now=now)

    check_tcb_info_applies(tcb_info, platform, tee=tee, label=tcb_item_name)

    platform_status, level, level_index = resolve_tcb_status(
        tcb_info, platform, tee=tee, report_cpusvn=report_cpusvn,
        tee_tcb_svn=tee_tcb_svn, label=tcb_item_name)

    # The TDX module is a second, independent TCB: the platform's microcode can
    # be current while the SEAM module measured into the quote is signed by
    # somebody else or carries published errata.  Evaluated before the policy
    # check below so an OutOfDate module cannot be hidden behind an UpToDate
    # platform.  SGX has no TDX module, so this is TDX-only.
    tdx_module = None
    status = platform_status
    if tee == "tdx":
        mrsignerseam, seam_attributes = td_report_module_fields(
            td_report_body, tee_tcb_svn, label=tcb_item_name)
        tdx_module = evaluate_tdx_module(
            tcb_info, tee_tcb_svn=tee_tcb_svn, mrsignerseam=mrsignerseam,
            seam_attributes=seam_attributes, label=tcb_item_name)
        status = converge_tdx_module_status(platform_status,
                                           tdx_module["status"])
        if status != platform_status:
            notes.append(
                f"TDX module {tdx_module['identity_id']} at ISV SVN "
                f"{tdx_module['isvsvn']} is {tdx_module['status']} "
                f"(tcbDate {tdx_module['tcb_date'] or '?'}, advisories "
                f"{tdx_module['advisory_ids'] or 'none published'}), which "
                f"degrades the platform status {platform_status} -> {status}")

    if status in NEVER_ALLOWED_STATUSES or status not in allowed:
        raise TcbStatusRejected(
            f"the platform's Intel TCB status is {status!r} (FMSPC "
            f"{platform.fmspc_hex}, tcbLevels[{level_index}], tcbDate "
            f"{level.get('tcbDate', '?')}, advisories "
            f"{level.get('advisoryIDs') or []}). Accepted: {sorted(allowed)}."
            + ("" if tdx_module is None or status == platform_status else
               f" The platform's own level is {platform_status!r}; the TDX "
               f"module {tdx_module['identity_id']} at ISV SVN "
               f"{tdx_module['isvsvn']} is {tdx_module['status']!r} and "
               "degrades it.")
            + (f" {status!r} is refused under every policy."
               if status in NEVER_ALLOWED_STATUSES
               else f" Set {ENV_ALLOW_STATUS} to accept it deliberately."))

    qe = evaluate_qe_identity(enclave_identity, qe_report, tee=tee,
                              allowed_statuses=allowed)
    crl = check_pck_not_revoked(
        pck_chain, bundle.pck_crls(), pinned_root,
        check_leaf_certificate=check_leaf_certificate,
        check_ca_certificate=check_ca_certificate, now=now)

    return {
        "tee": tee,
        "source": bundle.source,
        "pcs_source": bundle.declared_source,
        "collateral_age_seconds": age,
        "fmspc": platform.fmspc_hex,
        "pceid": platform.pceid_hex,
        "pcesvn": platform.pcesvn,
        "cpusvn": platform.cpusvn.hex(),
        "tcb_status": status,
        "platform_tcb_status": platform_status,
        "tdx_module": tdx_module,
        "tcb_level_index": level_index,
        "tcb_date": level.get("tcbDate", ""),
        "advisory_ids": level.get("advisoryIDs") or [],
        "tcb_evaluation_data_number": tcb_info.get("tcbEvaluationDataNumber"),
        "qe_identity": qe,
        "crl": crl,
        "allowed_statuses": sorted(allowed),
        "notes": notes,
    }


def _banner(lines, stream):
    bar = "*" * 78
    print(bar, file=stream)
    for line in lines:
        print(line, file=stream)
    print(bar, file=stream)


def enforce(*, tee: str, pck_chain: list, qe_report: bytes,
            pinned_root_ca_pem: str, check_leaf_certificate,
            check_ca_certificate, report_cpusvn: bytes = b"",
            tee_tcb_svn: bytes = b"", td_report_body: bytes = b"",
            collateral_path: str = "",
            now=None, max_age_seconds: int = 0, allowed_statuses=None,
            stream=None):
    """:func:`evaluate` plus operator-visible output and the escape hatch.

    Returns the summary dict, or ``None`` when the operator has explicitly
    opted out via ``TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS=1``.  Raises a
    :class:`TcbEvalError` subclass otherwise — the caller turns that into a
    fatal exit.
    """
    stream = stream or sys.stderr
    if os.environ.get(ENV_ALLOW_UNVERIFIED) == "1":
        _banner([
            f"WARNING: {ENV_ALLOW_UNVERIFIED}=1 is set, so this client did NOT",
            "evaluate the platform's Intel TCB status. An OUT-OF-DATE platform",
            "running microcode with published errata, or one whose PCK key",
            "Intel has REVOKED, will be accepted. The quote still proves the",
            "hardware; nothing here proves the hardware is trustworthy.",
            "Never use in production.",
        ], stream)
        return None

    result = evaluate(
        tee=tee, pck_chain=pck_chain, qe_report=qe_report,
        pinned_root_ca_pem=pinned_root_ca_pem,
        check_leaf_certificate=check_leaf_certificate,
        check_ca_certificate=check_ca_certificate,
        report_cpusvn=report_cpusvn, tee_tcb_svn=tee_tcb_svn,
        td_report_body=td_report_body,
        collateral_path=collateral_path, now=now,
        max_age_seconds=max_age_seconds, allowed_statuses=allowed_statuses)

    print(f"  Intel collateral:   {result['source']} "
          f"({result['collateral_age_seconds'] / 3600:.1f}h old, "
          f"tcbEvaluationDataNumber="
          f"{result['tcb_evaluation_data_number']})", file=stream)
    print(f"  Platform FMSPC:     {result['fmspc']} "
          f"(CPUSVN {result['cpusvn']}, PCESVN {result['pcesvn']})",
          file=stream)
    print(f"  Platform tcbStatus: {result['tcb_status']} "
          f"(tcbLevels[{result['tcb_level_index']}], "
          f"tcbDate {result['tcb_date']})", file=stream)
    module = result.get("tdx_module")
    if module is not None:
        if module["identity_id"]:
            print(f"  TDX module:         {module['identity_id']} ISV SVN "
                  f"{module['isvsvn']} -> {module['status']} "
                  f"(>= {module['matched_isvsvn']}, tcbDate "
                  f"{module['tcb_date'] or '?'}), MRSIGNERSEAM and "
                  "SEAMATTRIBUTES match Intel's TCBInfo", file=stream)
        else:
            # TEE_TCB_SVN[1] == 0: no per-version identity exists, so Intel
            # publishes no tcbStatus for the module.  Say so rather than
            # printing an empty status that reads like a pass.
            print("  TDX module:         version 0, so Intel publishes no "
                  "module tcbStatus; MRSIGNERSEAM and SEAMATTRIBUTES match "
                  "tcbInfo.tdxModule", file=stream)
    print(f"  QE identity:        {result['qe_identity']['status']} "
          f"(ISVSVN {result['qe_identity']['isvsvn']} >= "
          f"{result['qe_identity']['matched_isvsvn']}, ISVPRODID "
          f"{result['qe_identity']['isvprodid']})", file=stream)
    print(f"  PCK revocation:     {result['crl']['certificates_checked']} "
          f"certificate(s) clear against {result['crl']['crls']} CRL(s)",
          file=stream)
    for subject in result["crl"]["uncovered_root_issued"]:
        print("  PCK revocation:     NOT COVERED for "
              f"{subject} — the bundle carries no Intel SGX Root CA CRL, so "
              "revocation of the PCK CA itself was not checked", file=stream)
    for note in result["notes"]:
        print(f"  NOTE:               {note}", file=stream)
    if result["tcb_status"] not in DEFAULT_ALLOWED_STATUSES:
        _banner([
            f"WARNING: the platform's Intel TCB status is "
            f"{result['tcb_status']},",
            f"accepted only because {ENV_ALLOW_STATUS} lists it. Advisories: "
            f"{', '.join(result['advisory_ids']) or 'none published'}.",
            "The platform needs a BIOS/configuration change and/or the enclave",
            "needs software hardening before this is a production posture.",
        ], stream)
    else:
        print("  Platform TCB evaluation: PASSED", file=stream)
    return result
