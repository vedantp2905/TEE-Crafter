"""Fetch, verify and bundle Intel PCS TCB collateral at build time.

Why this exists
---------------
``core/builder/platforms.py`` used to download the TDX QEIdentity document
and write it next to the generated client without ever checking Intel's
signature on it.  The document was trusted purely because it arrived over
TLS, which means anyone who can terminate TLS on the build host's egress
path (a corporate proxy, a compromised internal PCS mirror, a
``TEE_CRAFTER_TDX_QE_IDENTITY_URL`` pointed at an attacker) could hand the
build an arbitrary QEIdentity and the client would enforce it as gospel.

This module closes that hole and adds the rest of the collateral Intel's
DCAP Quote Verification Library needs, in QVL order (the client-side half is
``templates/common/tee_crafter_tcb_eval.py``, reached via
``enforce_platform_tcb_status``):

  1. TCBInfo for the platform FMSPC        -> tcbStatus resolution
  2. QEIdentity                            -> QE ISVSVN / MISCSELECT / ATTRIBUTES
  3. PCK CRLs (platform + processor CA)    -> revoked platform keys
  4. Intel Root CA CRL                     -> revoked PCK *CA*

Item 4 is the one that is easy to miss.  The platform/processor CRLs are
issued *by* a PCK CA, so they can revoke a PCK leaf but never the PCK CA
itself; the PCK CA is issued by the Intel Root CA, and only the root's own CRL
can revoke it.  Without it a revoked PCK CA is undetectable -- which is what
the client reports as ``PCK revocation: NOT COVERED``.

Everything is signature-verified *here*, on the build host, and then stored
verbatim in a single ``tcb_collateral.json`` bundle so the client can repeat
the same verification offline.

The verbatim-bytes rule
-----------------------
Intel's ECDSA signature on a TCBInfo document covers the serialized bytes of
the ``tcbInfo`` *value* exactly as they appear in the HTTP response body --
not a re-serialization of the parsed object.  Same for ``enclaveIdentity`` in
QEIdentity.  So this module slices the raw substring out of the response body
and stores the response body verbatim; it never round-trips the signed value
through a ``dict``.

This was confirmed empirically against live PCS output on 2026-08-20 (see
``extract_signed_value``): Intel's real signature on
``/tdx/certification/v4/tcb?fmspc=00806F050000`` verified against the raw
substring.  It *also* verified against
``json.dumps(doc["tcbInfo"], separators=(",", ":"))`` -- because Intel
currently emits whitespace-free JSON and CPython dicts preserve document key
order, so that re-serialization happened to reproduce the same bytes.  It
failed against ``sort_keys=True`` and against default (spaced) ``json.dumps``.

That coincidence is the trap: re-serializing looks like it works, right up
until a number reformats (``1.0`` vs ``1``, exponent forms), a mirror
pretty-prints, or somebody adds ``sort_keys=True``.  Raw bytes are robust to
all of it.  ``tests/core/test_tcb_collateral_fetch.py`` pins this with a
document whose on-wire form no ``json.dumps`` setting can reproduce.

Anchoring
---------
Intel returns the signing chain in a response header as URL-encoded PEM, and
that chain *includes a copy of the Intel SGX Root CA*.  Validating "the chain
terminates at the root it shipped with" is circular and worthless -- an
attacker supplying both document and chain satisfies it trivially.  The final
signature check here is always performed with the public key of the
**pinned** ``certs/intel-sgx-dcap-root.pem``, so a self-minted chain carrying
its own self-signed root cannot validate no matter what the header says.

Stdlib + ``cryptography`` only.  No new dependencies.
"""

from __future__ import annotations

import base64
import datetime
import json
import logging
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

logger = logging.getLogger(__name__)

#: Everything ``cryptography`` raises for "this signature is no good" or "I
#: cannot even evaluate it".  Caught narrowly so a genuine bug in this module
#: surfaces as a crash instead of being reported as a verification failure.
_SIGNATURE_FAILURES = (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError)

__all__ = [
    "SCHEMA_VERSION",
    "BUNDLE_FILENAME",
    "DEFAULT_PCS_BASE_URL",
    "DEFAULT_CERTIFICATES_BASE_URL",
    "ENV_PCS_BASE_URL",
    "ENV_CERTIFICATES_BASE_URL",
    "ENV_FMSPC",
    "REQUIRED_ITEMS",
    "FMSPC_ITEMS",
    "CollateralError",
    "CollateralFetchError",
    "CollateralVerificationError",
    "CollateralFormatError",
    "ChainVerificationError",
    "SignatureVerificationError",
    "HttpResponse",
    "extract_signed_value",
    "decode_issuer_chain",
    "load_pinned_intel_root",
    "verify_issuer_chain",
    "verify_signed_json",
    "verify_pck_crl",
    "verify_root_ca_crl",
    "build_collateral_bundle",
    "verify_collateral_bundle",
    "stage_tcb_collateral",
]

# ---------------------------------------------------------------------------
# Constants / bundle schema
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 1
BUNDLE_FILENAME = "tcb_collateral.json"
QE_IDENTITY_COMPAT_FILENAME = "qe_identity.json"

DEFAULT_PCS_BASE_URL = "https://api.trustedservices.intel.com"
#: Intel publishes the Root CA CRL from a *different* host -- an S3/CloudFront
#: object store, not the PCS API (observed 2026-08-20: 200,
#: ``content-type: binary/octet-stream``, ``server: AmazonS3``).  It therefore
#: needs its own base URL and its own mirror override; ``ENV_PCS_BASE_URL``
#: cannot cover a second host.
DEFAULT_CERTIFICATES_BASE_URL = "https://certificates.trustedservices.intel.com"

#: Air-gapped / internal-mirror override, mirroring the old
#: ``TEE_CRAFTER_TDX_QE_IDENTITY_URL`` escape hatch but for the whole PCS.
ENV_PCS_BASE_URL = "TEE_CRAFTER_PCS_BASE_URL"
#: Mirror override for the certificate distribution host above.  Separate from
#: ``ENV_PCS_BASE_URL`` on purpose: an air-gapped operator mirroring one host
#: has not necessarily mirrored the other, and silently falling back to the
#: public host for half the collateral would defeat the air gap.  Setting one
#: of the two and not the other is therefore refused outright -- see
#: ``_check_hosts_not_mixed`` -- so "mirrored" and "public" cannot be mixed by
#: accident.  To mix them on purpose, set the other variable to the public URL
#: explicitly.
ENV_CERTIFICATES_BASE_URL = "TEE_CRAFTER_PCS_CERTIFICATES_BASE_URL"
#: The platform FMSPC is only knowable from a real quote's PCK leaf, so the
#: build host has to be told which platform it is targeting.
ENV_FMSPC = "TEE_CRAFTER_FMSPC"
#: Retired.  It named a single endpoint, so there is no way to translate it
#: into a base URL for the other five.  Silently ignoring it would send an
#: air-gapped build at the public PCS, so ``stage_tcb_collateral`` refuses
#: instead of guessing.
ENV_RETIRED_QE_IDENTITY_URL = "TEE_CRAFTER_TDX_QE_IDENTITY_URL"

_USER_AGENT = "tee-crafter/tcb-collateral-fetcher"

# Intel signs TCBInfo/QEIdentity with ECDSA P-256 over SHA-256 and emits the
# signature as 64 raw bytes (r||s) hex-encoded.
_RAW_ECDSA_SIG_LEN = 64


@dataclass(frozen=True)
class _ItemSpec:
    """One collateral endpoint and how to verify what it returns."""

    name: str
    kind: str                       # "tcb_info" | "enclave_identity" | "pck_crl"
    path: str
    query: tuple[tuple[str, str], ...]
    #: JSON key whose *raw* bytes Intel signed; ``None`` for CRLs.
    signed_value_key: Optional[str]
    #: Response headers that may carry the URL-encoded issuer chain PEM,
    #: in preference order.  Intel currently sends ``TCB-Info-Issuer-Chain``
    #: for both the SGX and TDX TCBInfo endpoints (observed 2026-08-20); the
    #: ``SGX-``-prefixed spelling is accepted because Intel's own
    #: documentation has used it.
    chain_headers: tuple[str, ...]
    needs_fmspc: bool
    #: How ``body`` is stored in the bundle: JSON documents keep their exact
    #: UTF-8 text, DER CRLs are base64'd because JSON cannot hold raw bytes.
    body_encoding: str
    #: Which Intel host serves this item: ``"api"`` (the PCS API) or
    #: ``"certificates"`` (the certificate/CRL distribution point).
    host: str = "api"
    #: ``True`` for collateral signed *directly* by the pinned Intel SGX Root
    #: CA, which arrives with no issuer-chain header because there is no chain
    #: to walk.  This is a distinct verification path (``verify_root_ca_crl``)
    #: that takes no chain argument at all, so a root-signed item structurally
    #: cannot be validated against a chain-supplied issuer.  Keeping it a
    #: declared property of the spec rather than "did a header happen to be
    #: absent?" is what stops a stripped header from silently selecting the
    #: weaker path.
    root_signed: bool = False


_ITEM_SPECS: tuple[_ItemSpec, ...] = (
    _ItemSpec(
        name="sgx_tcb_info",
        kind="tcb_info",
        path="/sgx/certification/v4/tcb",
        query=(),
        signed_value_key="tcbInfo",
        chain_headers=("TCB-Info-Issuer-Chain", "SGX-TCB-Info-Issuer-Chain"),
        needs_fmspc=True,
        body_encoding="utf-8",
    ),
    _ItemSpec(
        name="tdx_tcb_info",
        kind="tcb_info",
        path="/tdx/certification/v4/tcb",
        query=(),
        signed_value_key="tcbInfo",
        chain_headers=("TCB-Info-Issuer-Chain", "SGX-TCB-Info-Issuer-Chain"),
        needs_fmspc=True,
        body_encoding="utf-8",
    ),
    _ItemSpec(
        name="sgx_qe_identity",
        kind="enclave_identity",
        path="/sgx/certification/v4/qe/identity",
        query=(),
        signed_value_key="enclaveIdentity",
        chain_headers=("SGX-Enclave-Identity-Issuer-Chain",),
        needs_fmspc=False,
        body_encoding="utf-8",
    ),
    _ItemSpec(
        name="tdx_qe_identity",
        kind="enclave_identity",
        path="/tdx/certification/v4/qe/identity",
        query=(),
        signed_value_key="enclaveIdentity",
        chain_headers=("SGX-Enclave-Identity-Issuer-Chain",),
        needs_fmspc=False,
        body_encoding="utf-8",
    ),
    _ItemSpec(
        name="sgx_pck_crl_platform",
        kind="pck_crl",
        path="/sgx/certification/v4/pckcrl",
        # The v4 endpoint defaults to PEM (``application/x-pem-file``);
        # ``encoding=der`` is required to get DER.  Observed 2026-08-20.
        query=(("ca", "platform"), ("encoding", "der")),
        signed_value_key=None,
        chain_headers=("SGX-PCK-CRL-Issuer-Chain",),
        needs_fmspc=False,
        body_encoding="base64",
    ),
    _ItemSpec(
        name="sgx_pck_crl_processor",
        kind="pck_crl",
        path="/sgx/certification/v4/pckcrl",
        query=(("ca", "processor"), ("encoding", "der")),
        signed_value_key=None,
        chain_headers=("SGX-PCK-CRL-Issuer-Chain",),
        needs_fmspc=False,
        body_encoding="base64",
    ),
    _ItemSpec(
        # Closes the "PCK revocation: NOT COVERED" gap the client reports for
        # the PCK CA itself.  The platform/processor CRLs above are *issued by*
        # a PCK CA, so they can revoke a PCK leaf but never the PCK CA; the PCK
        # CA is issued by the Intel Root CA, and only the root's own CRL can
        # revoke it.
        #
        # Three ways this item differs from every other one, all observed
        # against the live endpoint on 2026-08-20:
        #   * different host (see DEFAULT_CERTIFICATES_BASE_URL),
        #   * no issuer-chain header of any kind -- it is a plain object served
        #     by S3/CloudFront,
        #   * signed directly by the pinned root, so there is no chain to walk.
        # It still declares kind "pck_crl" because that is exactly what it is:
        # a CRL in the PCK trust hierarchy, DER-encoded, with no signed JSON
        # value.  Reusing the kind keeps the client's item contract
        # (body_encoding "base64", signed_value_key null) unchanged.
        name="sgx_root_ca_crl",
        kind="pck_crl",
        path="/IntelSGXRootCA.der",
        query=(),
        signed_value_key=None,
        chain_headers=(),
        needs_fmspc=False,
        body_encoding="base64",
        host="certificates",
        root_signed=True,
    ),
)

_SPECS_BY_NAME = {spec.name: spec for spec in _ITEM_SPECS}

#: Items a complete bundle always carries.
REQUIRED_ITEMS: tuple[str, ...] = tuple(
    spec.name for spec in _ITEM_SPECS if not spec.needs_fmspc
)
#: Items that can only be fetched once the target platform's FMSPC is known.
FMSPC_ITEMS: tuple[str, ...] = tuple(
    spec.name for spec in _ITEM_SPECS if spec.needs_fmspc
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CollateralError(Exception):
    """Base class for every failure in this module."""


class CollateralFetchError(CollateralError):
    """The collateral could not be retrieved (network, HTTP status, ...)."""


class CollateralVerificationError(CollateralError):
    """The collateral was retrieved but could not be trusted."""


class CollateralFormatError(CollateralVerificationError):
    """The response was not shaped like the PCS document it claims to be."""


class ChainVerificationError(CollateralVerificationError):
    """The issuer chain does not validate to the pinned Intel SGX Root CA."""


class SignatureVerificationError(CollateralVerificationError):
    """Intel's signature over the collateral does not verify."""


# ---------------------------------------------------------------------------
# Raw-bytes extraction
# ---------------------------------------------------------------------------


def extract_signed_value(body: bytes, key: str) -> bytes:
    """Return the verbatim bytes of ``body``'s top-level ``key`` object.

    This is a deliberately dumb scanner over the *response bytes*: find
    ``"<key>":``, skip whitespace, then walk from the opening ``{`` to its
    matching ``}`` while respecting JSON string quoting and backslash
    escapes.  The slice returned is exactly what Intel signed.

    Nothing here parses JSON, because parsing is the bug: ``json.loads``
    followed by ``json.dumps`` re-formats numbers, re-escapes strings and can
    reorder keys, any one of which invalidates the signature.  See the module
    docstring for the measurement that established this.

    Raises ``CollateralFormatError`` if the key is absent or the object is
    unterminated.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise CollateralFormatError("response body must be bytes")
    body = bytes(body)

    needle = b'"' + key.encode("utf-8") + b'":'
    start = body.find(needle)
    if start < 0:
        # Tolerate whitespace between the key and its colon, e.g. a mirror
        # that pretty-prints.  Only the value bytes matter for the signature,
        # so locating the key loosely is safe.
        loose = b'"' + key.encode("utf-8") + b'"'
        idx = body.find(loose)
        if idx < 0:
            raise CollateralFormatError(f"response body has no {key!r} member")
        cursor = idx + len(loose)
        while cursor < len(body) and body[cursor:cursor + 1].isspace():
            cursor += 1
        if body[cursor:cursor + 1] != b":":
            raise CollateralFormatError(f"response body has no {key!r} member")
        cursor += 1
    else:
        cursor = start + len(needle)

    while cursor < len(body) and body[cursor:cursor + 1].isspace():
        cursor += 1
    if body[cursor:cursor + 1] != b"{":
        raise CollateralFormatError(f"{key!r} member is not a JSON object")

    depth = 0
    in_string = False
    escaped = False
    i = cursor
    while i < len(body):
        ch = body[i:i + 1]
        if in_string:
            if escaped:
                escaped = False
            elif ch == b"\\":
                escaped = True
            elif ch == b'"':
                in_string = False
        elif ch == b'"':
            in_string = True
        elif ch == b"{":
            depth += 1
        elif ch == b"}":
            depth -= 1
            if depth == 0:
                return body[cursor:i + 1]
        i += 1
    raise CollateralFormatError(f"{key!r} member is not terminated")


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------


def load_pinned_intel_root() -> x509.Certificate:
    """Load the repo-pinned ``CN=Intel SGX Root CA`` trust anchor.

    Deliberately reuses ``core/builder/platforms._load_trust_anchor`` so the
    build has exactly one Intel root of trust: the same PEM that gets baked
    into every rendered client.  A missing anchor is a hard error there, which
    is what we want -- an empty trust store must not degrade to "accept
    anything".
    """
    from tee_crafter.core.builder.platforms import _load_intel_root_ca

    pem = _load_intel_root_ca()
    if not pem or not pem.strip():
        raise ChainVerificationError("pinned Intel SGX Root CA PEM is empty")
    try:
        return x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except ValueError as exc:
        raise ChainVerificationError(
            f"pinned Intel SGX Root CA PEM is not a certificate: {exc}"
        ) from exc


def decode_issuer_chain(header_value: str) -> str:
    """Percent-decode the issuer-chain header into ordinary PEM text.

    Intel sends the chain URL-encoded (``-----BEGIN%20CERTIFICATE-----%0A...``)
    as ``<signing certificate><root CA certificate>``.
    """
    if not isinstance(header_value, str) or not header_value.strip():
        raise CollateralFormatError("issuer chain header is empty")
    pem = urllib.parse.unquote(header_value)
    if "-----BEGIN CERTIFICATE-----" not in pem:
        raise CollateralFormatError(
            "issuer chain header does not decode to PEM certificates"
        )
    return pem


def _parse_chain(pem: str) -> list[x509.Certificate]:
    try:
        certs = x509.load_pem_x509_certificates(pem.encode("utf-8"))
    except ValueError as exc:
        raise CollateralFormatError(f"issuer chain is not valid PEM: {exc}") from exc
    if not certs:
        raise CollateralFormatError("issuer chain contains no certificates")
    return list(certs)


def _check_validity(certs: Iterable[x509.Certificate], now: datetime.datetime) -> None:
    for idx, cert in enumerate(certs):
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            raise ChainVerificationError(
                f"certificate [{idx}] ({cert.subject.rfc4514_string()}) outside "
                f"its validity window "
                f"({cert.not_valid_before_utc} .. {cert.not_valid_after_utc})"
            )


def _check_ca_certificate(cert: x509.Certificate, label: str,
                          remaining_intermediates: int,
                          *, require_crl_sign: bool = False) -> None:
    """basicConstraints/keyUsage discipline for a certificate used as an issuer.

    Mirrors ``check_ca_certificate`` in ``templates/tdx/gcp/client.template.py``:
    a chain walk that only checks signatures accepts an end-entity certificate
    acting as a CA, so anyone holding any Intel-issued leaf could mint a forged
    signer.  ``remaining_intermediates`` is the number of CA certificates below
    this one, which is what ``pathLenConstraint`` bounds.
    """
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise ChainVerificationError(
            f"{label} has no basicConstraints extension, so it is not a CA"
        ) from None
    if not bc.ca:
        raise ChainVerificationError(f"{label} has basicConstraints CA:FALSE")
    if bc.path_length is not None and remaining_intermediates > bc.path_length:
        raise ChainVerificationError(
            f"{label} has pathLenConstraint={bc.path_length} but "
            f"{remaining_intermediates} intermediate(s) follow it in the chain"
        )
    # keyUsage is optional in RFC 5280.  Authoritative when present; nothing to
    # check when absent, and rejecting then would break a conforming chain.
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not ku.key_cert_sign:
        raise ChainVerificationError(
            f"{label} has a keyUsage extension without keyCertSign"
        )
    if require_crl_sign and not ku.crl_sign:
        raise ChainVerificationError(
            f"{label} has a keyUsage extension without cRLSign but signed a CRL"
        )


def _check_signing_leaf(cert: x509.Certificate, label: str) -> None:
    """Reject a document-signing leaf that is not permitted to sign documents.

    Intel's ``CN=Intel SGX TCB Signing`` certificate carries
    ``basicConstraints CA:FALSE`` and ``keyUsage digitalSignature,
    contentCommitment`` (observed 2026-08-20), so a conforming Intel leaf
    passes.  A leaf asserting ``CA:TRUE`` is rejected for the same reason
    ``check_leaf_certificate`` rejects a CA:TRUE PCK leaf: it could mint
    further certificates under the pinned root.
    """
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        bc = None
    if bc is not None and bc.ca:
        raise ChainVerificationError(f"{label} asserts basicConstraints CA:TRUE")
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not ku.digital_signature:
        raise ChainVerificationError(
            f"{label} has a keyUsage extension without digitalSignature, so it "
            "is not permitted to sign this document"
        )


def _verify_cert_signature(child: x509.Certificate, issuer: x509.Certificate,
                           label: str) -> None:
    issuer_pub = issuer.public_key()
    if not isinstance(issuer_pub, ec.EllipticCurvePublicKey):
        raise ChainVerificationError(f"{label} public key is not ECDSA")
    try:
        issuer_pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )
    except _SIGNATURE_FAILURES as exc:
        raise ChainVerificationError(
            f"{label} did not sign {child.subject.rfc4514_string()}: "
            f"{type(exc).__name__}"
        ) from exc


def verify_issuer_chain(chain_pem: str, *,
                        root_ca: Optional[x509.Certificate] = None,
                        now: Optional[datetime.datetime] = None,
                        leaf_is_ca: bool = False,
                        require_crl_sign: bool = False) -> x509.Certificate:
    """Validate an Intel issuer chain against the *pinned* root and return the signer.

    ``chain_pem`` is leaf-first, as Intel sends it.  The chain's own trailing
    root CA copy is never used as the anchor: the final signature check always
    uses ``root_ca`` (the pinned ``certs/intel-sgx-dcap-root.pem`` unless a
    test injects one).  A self-minted chain that ships its own self-signed
    "root" therefore fails, which is the whole point -- otherwise an attacker
    who controls the document also controls the anchor.

    ``leaf_is_ca`` is for CRLs, whose signer (``CN=Intel SGX PCK Platform CA``)
    genuinely is a CA; ``require_crl_sign`` then also demands ``cRLSign``.

    Raises ``ChainVerificationError`` / ``CollateralFormatError``.
    """
    if root_ca is None:
        root_ca = load_pinned_intel_root()
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    chain = _parse_chain(chain_pem)

    # Drop a trailing copy of the pinned root: it is redundant (we anchor on
    # the pinned file) and counting it as an intermediate would spend a
    # pathLen budget on a certificate that is not one.  x509.Certificate
    # equality is over the DER encoding, so a re-encoded copy compares equal.
    if len(chain) > 1 and chain[-1] == root_ca:
        chain = chain[:-1]

    signer = chain[0]

    # A chain topped by some *other* self-signed certificate is the circular
    # case: refuse it by name rather than letting it fail obscurely below.
    top = chain[-1]
    if top != root_ca and top.subject == top.issuer:
        raise ChainVerificationError(
            "issuer chain terminates at a self-signed certificate "
            f"({top.subject.rfc4514_string()}) that is not the pinned "
            f"{root_ca.subject.rfc4514_string()}"
        )

    _check_validity([root_ca, *chain], now)

    if leaf_is_ca:
        _check_ca_certificate(signer, "signing certificate [0]",
                              remaining_intermediates=0,
                              require_crl_sign=require_crl_sign)
    else:
        _check_signing_leaf(signer, "signing certificate [0]")
    for i in range(1, len(chain)):
        _check_ca_certificate(chain[i], f"issuer certificate [{i}]",
                              remaining_intermediates=i - 1 + int(leaf_is_ca))
    _check_ca_certificate(root_ca, "pinned Intel SGX Root CA",
                          remaining_intermediates=len(chain) - 1 + int(leaf_is_ca))

    for i in range(len(chain) - 1):
        _verify_cert_signature(chain[i], chain[i + 1], f"issuer certificate [{i + 1}]")
    _verify_cert_signature(chain[-1], root_ca, "pinned Intel SGX Root CA")

    return signer


# ---------------------------------------------------------------------------
# Document signature verification
# ---------------------------------------------------------------------------


def _raw_ecdsa_to_der(signature_hex: str) -> bytes:
    try:
        raw = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise CollateralFormatError(
            f"signature is not hex: {exc}"
        ) from exc
    if len(raw) != _RAW_ECDSA_SIG_LEN:
        raise CollateralFormatError(
            f"signature is {len(raw)} bytes, expected {_RAW_ECDSA_SIG_LEN} "
            "(raw ECDSA P-256 r||s)"
        )
    half = _RAW_ECDSA_SIG_LEN // 2
    return asym_utils.encode_dss_signature(
        int.from_bytes(raw[:half], "big"),
        int.from_bytes(raw[half:], "big"),
    )


def verify_signed_json(body: bytes, signed_value_key: str, chain_pem: str, *,
                       root_ca: Optional[x509.Certificate] = None,
                       now: Optional[datetime.datetime] = None) -> bytes:
    """Verify Intel's signature over ``body``'s ``signed_value_key`` value.

    Returns the verbatim signed bytes on success so callers can hash or store
    them.  Raises ``CollateralFormatError``, ``ChainVerificationError`` or
    ``SignatureVerificationError``.

    The signature input is the raw slice from ``body`` -- never a
    re-serialization.  ``body`` is parsed only to read the sibling
    ``signature`` field.
    """
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollateralFormatError(f"response body is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise CollateralFormatError("response body is not a JSON object")
    signature_hex = doc.get("signature")
    if not isinstance(signature_hex, str) or not signature_hex:
        raise CollateralFormatError("response body has no 'signature' string")
    if not isinstance(doc.get(signed_value_key), dict):
        raise CollateralFormatError(
            f"response body has no {signed_value_key!r} object"
        )

    signed_bytes = extract_signed_value(body, signed_value_key)
    der_signature = _raw_ecdsa_to_der(signature_hex)

    signer = verify_issuer_chain(chain_pem, root_ca=root_ca, now=now)
    signer_pub = signer.public_key()
    if not isinstance(signer_pub, ec.EllipticCurvePublicKey):
        raise ChainVerificationError("signing certificate public key is not ECDSA")
    # ECDSA P-256/SHA-256 is *inferred* from four live samples (2026-08-20), not
    # from a normative Intel statement.  So state the assumption and fail closed
    # on anything else rather than guessing an algorithm from the data: a
    # 64-byte r||s blob is only unambiguous for a 256-bit curve, and on a
    # different curve the split below would silently produce garbage that a
    # lenient verifier could be talked into accepting.  There is deliberately no
    # "unknown algorithm -> skip" branch anywhere in this module.
    if not isinstance(signer_pub.curve, ec.SECP256R1):
        raise ChainVerificationError(
            f"signing certificate key is on curve {signer_pub.curve.name}, but "
            "this verifier only understands the ECDSA P-256/SHA-256 signature "
            "encoding Intel is observed to use (64-byte raw r||s). Refusing to "
            "guess; teach this module the new algorithm explicitly."
        )
    try:
        signer_pub.verify(der_signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
    except _SIGNATURE_FAILURES as exc:
        raise SignatureVerificationError(
            f"Intel signature over {signed_value_key!r} did not verify "
            f"({type(exc).__name__}); the document was modified in transit, or "
            "the verifier re-serialized it instead of using the response bytes"
        ) from exc
    return signed_bytes


def verify_pck_crl(crl_der: bytes, chain_pem: str, *,
                   root_ca: Optional[x509.Certificate] = None,
                   now: Optional[datetime.datetime] = None
                   ) -> x509.CertificateRevocationList:
    """Verify a DER PCK CRL against its issuer chain and the pinned root."""
    crl = _load_crl(crl_der)
    issuer_cert = verify_issuer_chain(chain_pem, root_ca=root_ca, now=now,
                                      leaf_is_ca=True, require_crl_sign=True)
    if crl.issuer != issuer_cert.subject:
        raise ChainVerificationError(
            f"CRL issuer {crl.issuer.rfc4514_string()!r} does not match the "
            f"chain's signing certificate {issuer_cert.subject.rfc4514_string()!r}"
        )
    _verify_crl_signature(crl, issuer_cert, "PCK CRL")
    return crl


def _load_crl(crl_der: bytes) -> x509.CertificateRevocationList:
    try:
        return x509.load_der_x509_crl(bytes(crl_der))
    except ValueError as exc:
        raise CollateralFormatError(f"not a DER X.509 CRL: {exc}") from exc


def _verify_crl_signature(crl: x509.CertificateRevocationList,
                          issuer_cert: x509.Certificate, label: str) -> None:
    """Check a CRL's signature, failing closed on anything unexpected.

    ``is_signature_valid`` returns ``False`` for a bad signature.  Measured on
    the pinned ``cryptography`` version (2026-08-20), it *also* returns ``False``
    rather than raising when the CRL's algorithm does not match the key type --
    an RSA-signed and an Ed25519-signed CRL both returned ``False`` against an
    EC public key.  So the ``except`` below is currently unreachable in
    production.

    It is kept deliberately, and tested by fault injection
    (``test_an_unevaluable_crl_signature_is_rejected_not_skipped``), because the
    alternative is worse in exactly one direction: if a future version starts
    raising instead, an uncaught exception would escape as a crash, and the
    obvious "fix" under time pressure is a bare ``except: pass`` that turns
    "I could not check this" into "this is fine".  Pinning the fail-closed
    behaviour now means that regression cannot be introduced quietly.
    """
    issuer_pub = issuer_cert.public_key()
    if not isinstance(issuer_pub, ec.EllipticCurvePublicKey):
        raise ChainVerificationError(f"{label} issuer public key is not ECDSA")
    try:
        valid = crl.is_signature_valid(issuer_pub)
    except _SIGNATURE_FAILURES as exc:
        raise SignatureVerificationError(
            f"{label} signature could not be evaluated against "
            f"{issuer_cert.subject.rfc4514_string()} "
            f"({type(exc).__name__}: {exc}); treating an uncheckable signature "
            "as invalid"
        ) from exc
    if not valid:
        raise SignatureVerificationError(
            f"{label} signature did not verify against its issuer certificate "
            f"({issuer_cert.subject.rfc4514_string()})"
        )


def verify_root_ca_crl(crl_der: bytes, *,
                       root_ca: Optional[x509.Certificate] = None,
                       now: Optional[datetime.datetime] = None
                       ) -> x509.CertificateRevocationList:
    """Verify the Intel Root CA CRL against the pinned root, and nothing else.

    This is the CRL that can revoke a PCK *CA* (``CN=Intel SGX PCK Platform
    CA`` / ``Processor CA``).  The platform/processor CRLs are issued *by* a PCK
    CA and so can only ever revoke a PCK leaf; without this item a revoked PCK
    CA is undetectable, which is what the client reports as
    ``PCK revocation: NOT COVERED``.

    Note the signature: there is **no chain parameter**.  Intel serves this CRL
    with no issuer-chain header (observed 2026-08-20), it is signed directly by
    the root, and the pinned root is the only acceptable issuer -- so the
    circular-anchor trap is closed by construction rather than by a check that
    could be reordered away.  There is no argument through which a caller could
    supply an alternative issuer, and no code path by which a stripped header
    could downgrade a chained item onto this weaker-looking route: the spec
    declares ``root_signed`` up front.

    This is *stronger* than ``verify_pck_crl``, not weaker: zero attacker-
    influenced inputs participate in choosing the verification key.
    """
    if root_ca is None:
        root_ca = load_pinned_intel_root()
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    crl = _load_crl(crl_der)

    # The pinned root must itself be currently valid and permitted to sign
    # CRLs.  Intel's root is CA:TRUE pathlen:1 with keyCertSign+cRLSign
    # (observed 2026-08-20), so a conforming anchor passes.
    _check_validity([root_ca], now)
    _check_ca_certificate(root_ca, "pinned Intel SGX Root CA",
                          remaining_intermediates=0, require_crl_sign=True)

    if crl.issuer != root_ca.subject:
        raise ChainVerificationError(
            f"root CA CRL issuer {crl.issuer.rfc4514_string()!r} is not the "
            f"pinned {root_ca.subject.rfc4514_string()!r}; only the pinned root "
            "may issue this CRL"
        )
    _verify_crl_signature(crl, root_ca, "root CA CRL")
    return crl


# ---------------------------------------------------------------------------
# HTTP (injectable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HttpResponse:
    """Minimal HTTP response shape so tests can inject without a network."""

    status: int
    headers: dict
    body: bytes

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup (HTTP header names are case-insensitive)."""
        target = name.lower()
        for key, value in self.headers.items():
            if isinstance(key, str) and key.lower() == target:
                return value
        return None


HttpGet = Callable[[str, float], HttpResponse]


def _certifi_context() -> Optional["ssl.SSLContext"]:
    """A verifying TLS context using ``certifi``'s bundle, or ``None``.

    ``None`` when ``certifi`` is not installed or its bundle is unreadable —
    the caller then reports the original TLS error rather than inventing a
    second one.
    """
    try:
        import certifi
    except ImportError:
        return None
    try:
        return ssl.create_default_context(cafile=certifi.where())
    except OSError:
        return None


def _is_tls_verification_error(exc: BaseException) -> bool:
    """True for a certificate-verification failure, however it is wrapped.

    ``urllib`` wraps the original ``ssl.SSLCertVerificationError`` inside
    ``URLError.reason``, so checking the outer type alone misses every real
    occurrence.
    """
    if isinstance(exc, ssl.SSLError):
        return True
    return isinstance(getattr(exc, "reason", None), ssl.SSLError)


#: Appended to a TLS failure so the fix is in the error, not in a runbook.
_TLS_HINT = (
    "This is a TLS trust-store problem on the build host, not a problem with "
    "Intel's collateral: every document is verified against the pinned Intel "
    "SGX Root CA after download, so TLS here is transport hygiene rather than "
    "the trust anchor. If `curl` reaches the same URL successfully, this "
    "interpreter has no usable CA bundle for it. Install `certifi` into the "
    "same environment, or point SSL_CERT_FILE at a CA bundle."
)


def _urllib_get(url: str, timeout: float) -> HttpResponse:
    """GET *url*, retrying once through ``certifi`` on a TLS trust failure.

    The retry exists because the first live run of this module failed with
    ``CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`` on a
    host where ``curl`` against the same URL returned 200 and ``certifi`` was
    installed in the same virtualenv — a `python-build-standalone` interpreter
    (what ``uv`` and ``pyenv`` install) whose default trust store could not
    chain Intel's certificate. Read as a network fault, that error sends an
    operator to their firewall rules.

    The retry is driven by the **actual failure**, not by inspecting the
    default store first. An earlier version treated an empty
    ``get_ca_certs()`` as the signal; on the very host that motivated this it
    reported 128 loaded certificates and still could not verify, so the proxy
    signal was simply wrong.

    Verification is never disabled — the fallback swaps one verifying CA bundle
    for another. Safe here specifically because the pinned Intel root, not TLS,
    is what establishes trust in the fetched bytes.
    """
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
    )

    def _attempt(context: Optional["ssl.SSLContext"]) -> HttpResponse:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=context) as response:
            return HttpResponse(
                status=response.status,
                headers=dict(response.headers.items()),
                body=response.read(),
            )

    try:
        return _attempt(None)
    except urllib.error.HTTPError as exc:
        # An HTTPError is still a response; surface its status for the message.
        return HttpResponse(status=exc.code, headers=dict(exc.headers.items() if exc.headers else {}),
                            body=exc.read() if hasattr(exc, "read") else b"")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        fallback = _certifi_context() if _is_tls_verification_error(exc) else None
        if fallback is not None:
            try:
                response = _attempt(fallback)
            except urllib.error.HTTPError as retry_exc:
                return HttpResponse(
                    status=retry_exc.code,
                    headers=dict(retry_exc.headers.items() if retry_exc.headers else {}),
                    body=retry_exc.read() if hasattr(retry_exc, "read") else b"")
            except (urllib.error.URLError, TimeoutError, OSError):
                # Fall through and report the *original* error: the retry
                # failing too means certifi was not the missing piece.
                pass
            else:
                logger.warning(
                    "This interpreter's default TLS trust store could not "
                    "verify %s, but certifi's bundle could. Proceeding with "
                    "certifi. Collateral is still verified against the pinned "
                    "Intel SGX Root CA regardless of transport.", url)
                return response
        message = f"{type(exc).__name__}: {exc}"
        if _is_tls_verification_error(exc):
            message = f"{message}\n{_TLS_HINT}"
        raise CollateralFetchError(message) from exc


# ---------------------------------------------------------------------------
# Bundle assembly
# ---------------------------------------------------------------------------


def _resolve_bases(base_url: Optional[str],
                   certificates_base_url: Optional[str]) -> dict:
    """Map each ``_ItemSpec.host`` to its effective base URL.

    Two hosts, two independent overrides.  Chosen over an absolute-``url``
    escape hatch on the spec because an absolute URL cannot be redirected at a
    mirror -- and an air-gapped operator needs to redirect *both* hosts, not
    just the API.  Keeping ``path`` + base-URL joining for both means one
    mechanism, and ``endpoint`` stays a meaningful relative path in the bundle.

    Because the two overrides are independent, an operator who mirrors PCS for
    an air-gapped build and sets only ``TEE_CRAFTER_PCS_BASE_URL`` still
    reaches the *public* ``certificates.trustedservices.intel.com`` for the
    Root CA CRL.  The build succeeds, the bundle records both hosts, and
    nothing says the air gap just leaked -- so this refuses instead.  See
    :func:`_check_hosts_not_mixed`.
    """
    api = base_url or os.environ.get(ENV_PCS_BASE_URL)
    certificates = (certificates_base_url
                    or os.environ.get(ENV_CERTIFICATES_BASE_URL))
    _check_hosts_not_mixed(api, certificates)
    return {
        "api": (api or DEFAULT_PCS_BASE_URL).rstrip("/"),
        "certificates": (certificates
                         or DEFAULT_CERTIFICATES_BASE_URL).rstrip("/"),
    }


def _check_hosts_not_mixed(api: Optional[str],
                           certificates: Optional[str]) -> None:
    """Refuse a half-mirrored configuration.

    Collateral comes from two Intel hosts with one override each, so there are
    four configurations.  Both-default (a normal networked build) and
    both-set (a fully mirrored build) are fine.  The two mixed cases are not:
    one host is redirected at an internal mirror while the other silently falls
    back to Intel's public infrastructure.  For an air-gapped build that is a
    real egress attempt where the operator believes there is none; for a
    pinned-mirror build it means half the collateral came from somewhere the
    operator did not choose.

    A **hard** refusal with no dedicated bypass flag, deliberately.  The
    override already exists and is self-documenting: an operator who really
    wants one mirrored host and one public host sets the other variable
    *explicitly* to the public URL.  That records the intent in the same place
    the mirror is configured, where a reviewer will see it.  Adding a
    ``TEE_CRAFTER_ALLOW_MIXED_PCS_HOSTS``-style flag would be a second way to
    say the same thing, and a boolean pasted into a CI template is exactly the
    kind of thing that outlives the reason for it -- whereas a literal
    ``https://certificates.trustedservices.intel.com`` in the environment
    cannot be mistaken for anything else.

    Note what this does *not* do: it does not try to tell a "mirror" URL from a
    "public" one by hostname.  Whether a URL is a mirror is not a property of
    its spelling, and a heuristic there would both miss mirrors that proxy the
    real hostname and fire on legitimate setups.  What is checked is only
    whether the operator configured one host and left the other on its
    built-in default.
    """
    if bool(api) == bool(certificates):
        return
    if api:
        raise CollateralError(
            f"the Intel PCS API host is overridden ({api!r}) but the "
            "certificate distribution host is not, so the Root CA CRL would "
            f"still be fetched from the public {DEFAULT_CERTIFICATES_BASE_URL}. "
            "Intel serves collateral from two hosts and each has its own "
            f"override: {ENV_PCS_BASE_URL} for the API and "
            f"{ENV_CERTIFICATES_BASE_URL} for the certificate/CRL "
            "distribution point.\n"
            f"  Fix: set {ENV_CERTIFICATES_BASE_URL} to your mirror's base "
            "URL as well.\n"
            f"  If reaching the public host really is intended, set "
            f"{ENV_CERTIFICATES_BASE_URL}={DEFAULT_CERTIFICATES_BASE_URL} "
            "explicitly. Refusing to make that choice silently: on an "
            "air-gapped build host it is an egress attempt the operator "
            "believes cannot happen."
        )
    raise CollateralError(
        f"the Intel certificate distribution host is overridden "
        f"({certificates!r}) but the PCS API host is not, so TCBInfo, "
        "QEIdentity and the PCK CRLs would still be fetched from the public "
        f"{DEFAULT_PCS_BASE_URL}. Intel serves collateral from two hosts and "
        f"each has its own override: {ENV_PCS_BASE_URL} for the API and "
        f"{ENV_CERTIFICATES_BASE_URL} for the certificate/CRL distribution "
        "point.\n"
        f"  Fix: set {ENV_PCS_BASE_URL} to your mirror's base URL as well.\n"
        f"  If reaching the public host really is intended, set "
        f"{ENV_PCS_BASE_URL}={DEFAULT_PCS_BASE_URL} explicitly. Refusing to "
        "make that choice silently: on an air-gapped build host it is an "
        "egress attempt the operator believes cannot happen."
    )


def _item_url(base_url: str, spec: _ItemSpec, fmspc: Optional[str]) -> str:
    query = list(spec.query)
    if spec.needs_fmspc:
        if not fmspc:
            raise CollateralError(f"{spec.name} requires an FMSPC")
        query.insert(0, ("fmspc", fmspc))
    path = spec.path
    if query:
        path = f"{path}?{urllib.parse.urlencode(query)}"
    return base_url.rstrip("/") + path


def _normalise_fmspc(fmspc: Optional[str]) -> Optional[str]:
    if fmspc is None:
        return None
    cleaned = fmspc.strip().upper()
    if not cleaned:
        return None
    if len(cleaned) != 12 or any(c not in "0123456789ABCDEF" for c in cleaned):
        raise CollateralError(
            f"FMSPC {fmspc!r} is not 12 hex characters (6 bytes); the FMSPC "
            "lives in the PCK leaf's SGX extension, OID 1.2.840.113741.1.13.1.4"
        )
    return cleaned


def _fetch_and_verify_item(spec: _ItemSpec, base_url: str, fmspc: Optional[str],
                           *, http_get: HttpGet, timeout: float,
                           root_ca: x509.Certificate,
                           now: datetime.datetime) -> dict:
    url = _item_url(base_url, spec, fmspc)
    response = http_get(url, timeout)
    if not isinstance(response, HttpResponse):
        raise CollateralFetchError(
            f"{spec.name}: http_get returned {type(response).__name__}, "
            "expected HttpResponse"
        )
    if response.status != 200:
        raise CollateralFetchError(f"{spec.name}: HTTP {response.status} from {url}")
    if not response.body:
        raise CollateralFetchError(f"{spec.name}: empty response body from {url}")

    if spec.root_signed:
        # No chain arrives and none is consulted: verified directly against the
        # pinned root.  The chain PEM stored below is *generated locally* from
        # that same pinned certificate, purely so the client's uniform
        # "every CRL item has an issuer chain" reader has something consistent
        # to read.  It is never an input to this verification.
        verify_root_ca_crl(response.body, root_ca=root_ca, now=now)
        header_name = None
        chain_pem = root_ca.public_bytes(
            serialization.Encoding.PEM).decode("ascii")
    else:
        header_name = None
        header_value = None
        for candidate in spec.chain_headers:
            value = response.header(candidate)
            if value:
                header_name, header_value = candidate, value
                break
        if header_value is None:
            raise CollateralFormatError(
                f"{spec.name}: response carries none of the issuer-chain headers "
                f"{list(spec.chain_headers)}"
            )
        chain_pem = decode_issuer_chain(header_value)

        if spec.kind == "pck_crl":
            verify_pck_crl(response.body, chain_pem, root_ca=root_ca, now=now)
        else:
            verify_signed_json(response.body, spec.signed_value_key, chain_pem,
                               root_ca=root_ca, now=now)

    if spec.body_encoding == "utf-8":
        body_field = response.body.decode("utf-8")
    else:
        body_field = base64.b64encode(response.body).decode("ascii")

    item = {
        "kind": spec.kind,
        "url": url,
        "endpoint": url[len(base_url.rstrip("/")):],
        "body": body_field,
        "body_encoding": spec.body_encoding,
        "signed_value_key": spec.signed_value_key,
        "issuer_chain_pem": chain_pem,
        "issuer_chain_header": header_name,
    }
    if spec.needs_fmspc:
        item["fmspc"] = fmspc
    for key, value in spec.query:
        if key != "encoding":
            item[key] = value
    return item


def build_collateral_bundle(fmspc: Optional[str] = None, *,
                            base_url: Optional[str] = None,
                            certificates_base_url: Optional[str] = None,
                            timeout: float = 10.0,
                            http_get: Optional[HttpGet] = None,
                            root_ca: Optional[x509.Certificate] = None,
                            now: Optional[datetime.datetime] = None) -> dict:
    """Fetch and verify every collateral item, returning the bundle dict.

    All-or-nothing: any fetch or verification failure raises, so a caller can
    never end up writing a half-populated bundle.  The only way an item is
    legitimately absent is ``fmspc=None``, which makes the two TCBInfo items
    unfetchable -- and that case is declared in the bundle itself via
    ``complete: false`` and ``missing: [...]`` rather than being silent.

    ``http_get(url, timeout) -> HttpResponse`` is injectable; the default uses
    ``urllib``.  Tests must always inject.
    """
    bases = _resolve_bases(base_url, certificates_base_url)
    fmspc = _normalise_fmspc(fmspc)
    if http_get is None:
        http_get = _urllib_get
    if root_ca is None:
        root_ca = load_pinned_intel_root()
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    items: dict = {}
    missing: list[str] = []
    for spec in _ITEM_SPECS:
        if spec.needs_fmspc and not fmspc:
            missing.append(spec.name)
            continue
        items[spec.name] = _fetch_and_verify_item(
            spec, bases[spec.host], fmspc, http_get=http_get, timeout=timeout,
            root_ca=root_ca, now=now,
        )

    return {
        "schema_version": SCHEMA_VERSION,
        # The client enforces a staleness bound against this, so it has to be
        # the real fetch time.  Second precision, trailing "Z", UTC.
        "fetched_at": now.astimezone(datetime.timezone.utc)
                         .replace(microsecond=0)
                         .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": bases["api"],
        # Second host, recorded separately because ``source`` no longer covers
        # every item.  Diagnostic only, like ``source``.
        "certificates_source": bases["certificates"],
        "fmspc": fmspc,
        # Fingerprint of the anchor this bundle was verified against.  Not a
        # trust anchor -- the client anchors on its own baked-in PEM -- but it
        # lets the client notice a bundle built against a different root.
        "root_ca_sha256": root_ca.fingerprint(hashes.SHA256()).hex(),
        "complete": not missing,
        "missing": missing,
        "items": items,
    }


def verify_collateral_bundle(bundle: dict, *,
                             root_ca: Optional[x509.Certificate] = None,
                             now: Optional[datetime.datetime] = None,
                             require_complete: bool = True) -> list[str]:
    """Re-verify a bundle offline, exactly as the client must.

    Returns the list of item names verified.  Raises on anything that would
    make the bundle untrustworthy.  This is the reference implementation of
    the client-side read path and needs no network.
    """
    if not isinstance(bundle, dict):
        raise CollateralFormatError("bundle is not a JSON object")
    if bundle.get("schema_version") != SCHEMA_VERSION:
        raise CollateralFormatError(
            f"bundle schema_version {bundle.get('schema_version')!r} != "
            f"{SCHEMA_VERSION}"
        )
    if not isinstance(bundle.get("fetched_at"), str) or not bundle["fetched_at"]:
        raise CollateralFormatError("bundle has no 'fetched_at'")
    items = bundle.get("items")
    if not isinstance(items, dict):
        raise CollateralFormatError("bundle has no 'items' object")

    absent = [name for name in REQUIRED_ITEMS if name not in items]
    if absent:
        raise CollateralFormatError(
            f"bundle is missing always-required item(s): {absent}"
        )
    if require_complete:
        if not bundle.get("complete"):
            raise CollateralFormatError(
                f"bundle declares itself incomplete (missing "
                f"{bundle.get('missing')!r})"
            )
        absent = [name for name in FMSPC_ITEMS if name not in items]
        if absent:
            raise CollateralFormatError(
                f"bundle claims to be complete but omits {absent}"
            )
    # A bundle that lists an item in `missing` while also carrying it (or vice
    # versa) is self-inconsistent; refuse rather than guess which is true.
    declared_missing = bundle.get("missing") or []
    if not isinstance(declared_missing, list):
        raise CollateralFormatError("bundle 'missing' is not a list")
    for name in declared_missing:
        if name in items:
            raise CollateralFormatError(
                f"bundle lists {name!r} as missing but also carries it"
            )

    if root_ca is None:
        root_ca = load_pinned_intel_root()
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    verified: list[str] = []
    for name, item in items.items():
        spec = _SPECS_BY_NAME.get(name)
        if spec is None:
            raise CollateralFormatError(f"bundle carries unknown item {name!r}")
        if not isinstance(item, dict):
            raise CollateralFormatError(f"bundle item {name!r} is not an object")
        chain_pem = item.get("issuer_chain_pem")
        if not isinstance(chain_pem, str):
            raise CollateralFormatError(
                f"bundle item {name!r} has no 'issuer_chain_pem'"
            )
        body = item.get("body")
        if not isinstance(body, str):
            raise CollateralFormatError(f"bundle item {name!r} has no 'body'")
        encoding = item.get("body_encoding")
        if encoding == "utf-8":
            raw = body.encode("utf-8")
        elif encoding == "base64":
            try:
                raw = base64.b64decode(body, validate=True)
            except (ValueError, TypeError) as exc:
                raise CollateralFormatError(
                    f"bundle item {name!r} body is not valid base64: {exc}"
                ) from exc
        else:
            raise CollateralFormatError(
                f"bundle item {name!r} has unsupported body_encoding "
                f"{encoding!r}"
            )
        # Route on the *spec*, keyed by the item name, never on anything the
        # file says about itself.  A bundle that relabelled the root CA CRL as
        # a chained PCK CRL (or vice versa) cannot pick a different verifier.
        if spec.root_signed:
            verify_root_ca_crl(raw, root_ca=root_ca, now=now)
        elif spec.kind == "pck_crl":
            verify_pck_crl(raw, chain_pem, root_ca=root_ca, now=now)
        else:
            verify_signed_json(raw, spec.signed_value_key, chain_pem,
                               root_ca=root_ca, now=now)
        verified.append(name)
    return verified


# ---------------------------------------------------------------------------
# Build wiring
# ---------------------------------------------------------------------------


def _atomic_write(path: str, data: bytes) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def stage_tcb_collateral(build_dir: str, *,
                         fmspc: Optional[str] = None,
                         base_url: Optional[str] = None,
                         certificates_base_url: Optional[str] = None,
                         timeout: float = 10.0,
                         http_get: Optional[HttpGet] = None,
                         write_qe_identity_compat: bool = True,
                         ) -> tuple[bool, str]:
    """Fetch, verify and stage ``tcb_collateral.json`` into ``build_dir``.

    Returns ``(ok, detail)``; ``detail`` is a one-line summary on success or
    the failure reason otherwise.  Nothing is written unless every attempted
    item fetched *and* verified, so a failed run leaves no bundle at all and
    the client fails closed -- which is the correct default.

    ``fmspc`` falls back to ``$TEE_CRAFTER_FMSPC``.  Without it the two
    TCBInfo items cannot be fetched (the FMSPC is a property of the target
    platform, only readable from a real quote's PCK leaf), and the bundle is
    written with ``complete: false`` so the client knows precisely which
    checks it must refuse to perform.

    ``write_qe_identity_compat`` also drops the verbatim TDX QEIdentity body
    at ``qe_identity.json`` for the already-shipped TDX clients, whose
    ``_qe_identity_lookup_path`` reads that filename.  Same bytes, same single
    verification path -- the difference from the old ``fetch_tdx_qe_identity``
    is that these bytes have now had Intel's signature checked.
    """
    retired = os.environ.get(ENV_RETIRED_QE_IDENTITY_URL)
    if retired and not (base_url or os.environ.get(ENV_PCS_BASE_URL)):
        return False, (
            f"{ENV_RETIRED_QE_IDENTITY_URL}={retired!r} is no longer honoured: "
            "the build now fetches seven collateral endpoints across two hosts, "
            f"not one.  Set {ENV_PCS_BASE_URL} (and "
            f"{ENV_CERTIFICATES_BASE_URL} for the Root CA CRL) to your "
            "mirror's base URLs instead.  Refusing to fall back to the public "
            "Intel PCS, which would defeat the air-gap this variable existed "
            "for."
        )

    effective_fmspc = fmspc if fmspc is not None else os.environ.get(ENV_FMSPC)
    try:
        bundle = build_collateral_bundle(
            effective_fmspc, base_url=base_url,
            certificates_base_url=certificates_base_url, timeout=timeout,
            http_get=http_get,
        )
    except CollateralError as exc:
        return False, f"{type(exc).__name__}: {exc}"

    payload = json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8")
    try:
        os.makedirs(build_dir, exist_ok=True)
        _atomic_write(os.path.join(build_dir, BUNDLE_FILENAME), payload)
        if write_qe_identity_compat:
            tdx_qe = bundle["items"].get("tdx_qe_identity")
            if tdx_qe is not None:
                _atomic_write(
                    os.path.join(build_dir, QE_IDENTITY_COMPAT_FILENAME),
                    tdx_qe["body"].encode("utf-8"),
                )
    except OSError as exc:
        return False, f"could not write collateral bundle: {exc}"

    return True, _summarise(bundle)


def _summarise(bundle: dict) -> str:
    items = bundle.get("items") or {}
    parts = [
        f"schema={bundle.get('schema_version')}",
        f"source={bundle.get('source')}",
        f"certificates_source={bundle.get('certificates_source')}",
        f"fetched_at={bundle.get('fetched_at')}",
        f"fmspc={bundle.get('fmspc') or 'unset'}",
        f"items={len(items)}",
        f"complete={'yes' if bundle.get('complete') else 'no'}",
    ]
    if bundle.get("missing"):
        parts.append("missing=" + ",".join(bundle["missing"]))
    tdx_qe = items.get("tdx_qe_identity")
    if tdx_qe:
        try:
            identity = json.loads(tdx_qe["body"])["enclaveIdentity"]
            parts.append(
                f"tdx_qe(id={identity.get('id', '?')},"
                f"tcbEvaluationDataNumber={identity.get('tcbEvaluationDataNumber', '?')},"
                f"nextUpdate={identity.get('nextUpdate', '?')})"
            )
        except (KeyError, TypeError, ValueError):
            pass
    return " ".join(parts)
