"""Intel platform TCB status evaluation — the client side.

Every fixture here is minted locally with ``cryptography`` and hand-rolled DER:
the root CA, the TCB signing certificate, the PCK CA, the PCK leaf and its
Intel SGX extension, the CRLs, and the ECDSA signatures over the ``tcbInfo`` /
``enclaveIdentity`` bodies.  Nothing is derived by calling the code under test,
so a bug in the evaluator cannot make a fabricated bundle look genuine.

There is no Intel hardware and no network access on the machine that wrote
these tests.  What is verified here is the *logic*: which documents are
accepted, which are refused, and that the refusal is the default.  Behaviour
against live Intel PCS collateral on a real SGX/TDX platform is untested.
"""
from __future__ import annotations

import ast
import base64
import datetime
import importlib.util
import io
import json
import os
import sys
import types

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from tee_crafter.core.builder import platforms

import tee_crafter

_PKG_DIR = os.path.dirname(os.path.abspath(tee_crafter.__file__))
_SHARED_MODULE_PATH = os.path.join(
    _PKG_DIR, "templates", "common", "tee_crafter_tcb_eval.py")

_EXT_OID = "1.2.840.113741.1.13.1"
_TCB_OID = _EXT_OID + ".2"

NOW = datetime.datetime(2026, 8, 19, 12, 0, 0, tzinfo=datetime.timezone.utc)


# ---------------------------------------------------------------------------
# Loading the module under test the same way a rendered client does
# ---------------------------------------------------------------------------

def _load_shared_module(name: str = "tee_crafter_tcb_eval_under_test"):
    spec = importlib.util.spec_from_file_location(name, _SHARED_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tcb():
    return _load_shared_module()


def _load_client(source: str, name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    exec(compile(source, f"{name}.py", "exec"), module.__dict__)
    return module


@pytest.fixture(scope="module")
def sgx_client():
    return _load_client(
        platforms.render_sgx_client_template(mrenclave="ab" * 32,
                                            mrsigner="cd" * 32),
        "sgx_client_under_test")


@pytest.fixture(scope="module")
def cert_checks(sgx_client):
    """The two X.509 constraint helpers the clients inject.

    Taken from a real rendered client rather than reimplemented, because the
    point of the shared module's dependency injection is that these exist once
    per client and are reused, not copied.
    """
    return {
        "check_leaf_certificate": sgx_client.check_leaf_certificate,
        "check_ca_certificate": sgx_client.check_ca_certificate,
    }


# ---------------------------------------------------------------------------
# Minimal DER writer, so the PCK leaf carries a real Intel SGX extension
# ---------------------------------------------------------------------------

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        out.extend(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _der_int(value: int) -> bytes:
    if value == 0:
        return _tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return _tlv(0x02, body)


def _der_octets(raw: bytes) -> bytes:
    return _tlv(0x04, raw)


def _der_seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _pair(oid: str, value: bytes) -> bytes:
    return _der_seq(_der_oid(oid), value)


def build_sgx_extension(*, fmspc: bytes, pceid: bytes, cpusvn: bytes,
                        pcesvn: int, components=None,
                        omit_fmspc: bool = False) -> bytes:
    """Encode Intel's PCK ``SGXExtensions`` structure by hand."""
    comps = list(components) if components is not None else list(cpusvn)
    tcb_entries = [_pair(f"{_TCB_OID}.{i + 1}", _der_int(svn))
                   for i, svn in enumerate(comps)]
    tcb_entries.append(_pair(f"{_TCB_OID}.17", _der_int(pcesvn)))
    tcb_entries.append(_pair(f"{_TCB_OID}.18", _der_octets(cpusvn)))
    entries = [
        _pair(_EXT_OID + ".1", _der_octets(b"\x11" * 16)),   # PPID
        _pair(_TCB_OID, _der_seq(*tcb_entries)),
        _pair(_EXT_OID + ".3", _der_octets(pceid)),
    ]
    if not omit_fmspc:
        entries.append(_pair(_EXT_OID + ".4", _der_octets(fmspc)))
    return _der_seq(*entries)


# ---------------------------------------------------------------------------
# A self-minted stand-in for Intel's PKI and PCS
# ---------------------------------------------------------------------------

def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
    ])


def _mint_ca(cn: str, *, issuer_cert=None, issuer_key=None, path_length=1):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(cn)
    issuer = subject if issuer_cert is None else issuer_cert.subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=30))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length),
                       critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=False, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=True,
                          crl_sign=True, encipher_only=False,
                          decipher_only=False),
            critical=True)
    )
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return key, cert


def _mint_leaf(cn: str, *, issuer_cert, issuer_key, extra_extensions=()):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=30))
        .not_valid_after(NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
    )
    for ext, critical in extra_extensions:
        builder = builder.add_extension(ext, critical=critical)
    return key, builder.sign(issuer_key, hashes.SHA256())


def _pem(*certs) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def _raw_ecdsa(key, payload: bytes) -> str:
    """Sign *payload* and return Intel's 128-hex ``r || s`` encoding."""
    der = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def _signed_body(key, value_key: str, ordered_pairs) -> bytes:
    """Serialize an Intel-style response body **once** and sign those bytes.

    ``ordered_pairs`` is a list of ``(key, value)`` in Intel's document order,
    deliberately *not* alphabetical, so that a ``sort_keys=True`` round-trip
    really does change the bytes.
    """
    value = "{" + ",".join(
        f"{json.dumps(k)}:{json.dumps(v, separators=(',', ':'))}"
        for k, v in ordered_pairs) + "}"
    signature = _raw_ecdsa(key, value.encode("utf-8"))
    return (f'{{"{value_key}":{value},"signature":"{signature}"}}'
            ).encode("utf-8")


def _level(components, pcesvn, status, *, tdx=None,
           date="2025-11-13T00:00:00Z", advisories=()):
    tcb = {"sgxtcbcomponents": [{"svn": svn} for svn in components],
           "pcesvn": pcesvn}
    if tdx is not None:
        tcb["tdxtcbcomponents"] = [{"svn": svn} for svn in tdx]
    return {"tcb": tcb, "tcbDate": date, "tcbStatus": status,
            "advisoryIDs": list(advisories)}


#: "the fixture default", so a test can pass ``None`` to *drop* a field.
_DEFAULT = object()

_PLATFORM_COMPONENTS = [5] * 16
_PLATFORM_CPUSVN = bytes(_PLATFORM_COMPONENTS)
_PLATFORM_PCESVN = 13
_PLATFORM_FMSPC = bytes.fromhex("00906ea10000")
_PLATFORM_PCEID = bytes.fromhex("0000")
# TEE_TCB_SVN as a real TDX quote carries it: byte 0 is the TDX module's ISV
# SVN, byte 1 is the module *version* that selects a ``tdxModuleIdentities``
# entry.  Not interchangeable -- see TDX_MODULE_VERSION_INDEX in the module
# under test.  [5, 3, ...] means "TDX_03 module at ISV SVN 5", which is
# UpToDate in the identity table below, and still clears tdxtcbcomponents
# level 1 ([4, 0, ...]) so the pre-existing platform-level assertions hold.
_TEE_TCB_SVN = bytes([5, 3] + [0] * 14)

# Verbatim from Intel PCS, 2026-08-20:
#   https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90C06F000000
# Every FMSPC for which Intel serves TDX collateral returns exactly these
# values for ``tdxModule`` -- an all-zero MRSIGNERSEAM (Intel's own SEAM
# modules are not signed with a non-zero MRSIGNER) under an all-ones attributes
# mask, i.e. "SEAMATTRIBUTES must be entirely zero".
_TDX_MODULE_MRSIGNER = "00" * 48
_TDX_MODULE_ATTRIBUTES = "0000000000000000"
_TDX_MODULE_ATTRIBUTES_MASK = "FFFFFFFFFFFFFFFF"


def _tdx_module(mrsigner: str = _TDX_MODULE_MRSIGNER) -> dict:
    return {"mrsigner": mrsigner, "attributes": _TDX_MODULE_ATTRIBUTES,
            "attributesMask": _TDX_MODULE_ATTRIBUTES_MASK}


def _tdx_module_identities(mrsigner: str = _TDX_MODULE_MRSIGNER) -> list:
    """The ``tdxModuleIdentities`` array Intel publishes, ids and SVNs intact.

    Copied from the same live response: two entries, ``TDX_03`` and ``TDX_01``,
    each with descending ``tcbLevels``.  The advisory lists are trimmed to one
    entry apiece; nothing under test reads more than their presence.
    """
    return [
        {"id": "TDX_03", **_tdx_module(mrsigner),
         "tcbLevels": [
             {"tcb": {"isvsvn": 5}, "tcbDate": "2025-08-13T00:00:00Z",
              "tcbStatus": "UpToDate"},
             {"tcb": {"isvsvn": 3}, "tcbDate": "2025-05-14T00:00:00Z",
              "tcbStatus": "OutOfDate",
              "advisoryIDs": ["INTEL-SA-01312"]},
         ]},
        {"id": "TDX_01", **_tdx_module(mrsigner),
         "tcbLevels": [
             {"tcb": {"isvsvn": 11}, "tcbDate": "2025-08-13T00:00:00Z",
              "tcbStatus": "UpToDate"},
             {"tcb": {"isvsvn": 6}, "tcbDate": "2025-05-14T00:00:00Z",
              "tcbStatus": "OutOfDate",
              "advisoryIDs": ["INTEL-SA-01245"]},
         ]},
    ]


def build_td_report_body(*, tee_tcb_svn: bytes = _TEE_TCB_SVN,
                         mrsignerseam: bytes | None = None,
                         seam_attributes: bytes = bytes(8),
                         length: int = 584) -> bytes:
    """A TD report body: the 584 bytes a TDX v4 quote carries at offset 48.

    Only the four fields the evaluator reads are populated meaningfully:
    TEE_TCB_SVN at 0, MRSEAM at 16 (never read, filled with a recognisable
    pattern so a wrong offset shows up as garbage rather than as zeros that
    happen to match), MRSIGNERSEAM at 64 and SEAMATTRIBUTES at 112.
    """
    if mrsignerseam is None:
        mrsignerseam = bytes.fromhex(_TDX_MODULE_MRSIGNER)
    body = bytearray(length)
    body[0:16] = tee_tcb_svn
    body[16:64] = b"\x5a" * 48
    body[64:112] = mrsignerseam
    body[112:120] = seam_attributes
    return bytes(body)

_QE_MRSIGNER = bytes.fromhex(
    "8c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff")


def build_qe_report(*, isvsvn: int = 8, isvprodid: int = 2,
                    cpusvn: bytes = _PLATFORM_CPUSVN,
                    miscselect: bytes = b"\x00\x00\x00\x00",
                    attributes: bytes | None = None,
                    mrsigner: bytes = _QE_MRSIGNER) -> bytes:
    """A 384-byte ``sgx_report_body_t`` for the Quoting Enclave."""
    report = bytearray(384)
    report[0:16] = cpusvn
    report[16:20] = miscselect
    report[48:64] = attributes if attributes is not None else (
        b"\x11" + b"\x00" * 7 + b"\xe7" + b"\x00" * 7)
    report[128:160] = mrsigner
    report[256:258] = isvprodid.to_bytes(2, "little")
    report[258:260] = isvsvn.to_bytes(2, "little")
    return bytes(report)


class IntelWorld:
    """Root CA, TCB signing cert, PCK chain, CRLs and signed PCS documents."""

    def __init__(self, *, root_cn: str = "Intel SGX Root CA"):
        self.root_key, self.root = _mint_ca(root_cn, path_length=1)
        self.tcb_signing_key, self.tcb_signing = _mint_leaf(
            "Intel SGX TCB Signing", issuer_cert=self.root,
            issuer_key=self.root_key)
        self.pck_ca_key, self.pck_ca = _mint_ca(
            "Intel SGX PCK Platform CA", issuer_cert=self.root,
            issuer_key=self.root_key, path_length=0)
        self.pck_leaf_key, self.pck_leaf = self._mint_pck_leaf()

    # -- PKI ---------------------------------------------------------------

    def _mint_pck_leaf(self, **ext_kwargs):
        params = dict(fmspc=_PLATFORM_FMSPC, pceid=_PLATFORM_PCEID,
                      cpusvn=_PLATFORM_CPUSVN, pcesvn=_PLATFORM_PCESVN,
                      components=_PLATFORM_COMPONENTS)
        params.update(ext_kwargs)
        der = build_sgx_extension(**params)
        ext = x509.UnrecognizedExtension(x509.ObjectIdentifier(_EXT_OID), der)
        return _mint_leaf("Intel SGX PCK Certificate",
                          issuer_cert=self.pck_ca, issuer_key=self.pck_ca_key,
                          extra_extensions=[(ext, False)])

    def pck_chain(self):
        return [self.pck_leaf, self.pck_ca, self.root]

    @property
    def root_pem(self) -> str:
        return self.root.public_bytes(serialization.Encoding.PEM).decode()

    # -- signed PCS documents ---------------------------------------------

    def tcb_info_body(self, *, levels=None, tee: str = "sgx",
                      fmspc: bytes | None = None,
                      next_update: str = "2026-09-18T12:00:00Z",
                      version: int = 3,
                      tdx_module=_DEFAULT, tdx_module_identities=_DEFAULT,
                      signing_key=None, extra=()) -> bytes:
        if levels is None:
            levels = self.default_levels(tee)
        pairs = [
            ("id", "SGX" if tee == "sgx" else "TDX"),
            ("version", version),
            ("issueDate", "2026-08-18T12:00:00Z"),
            ("nextUpdate", next_update),
            ("fmspc", (fmspc if fmspc is not None else _PLATFORM_FMSPC).hex()),
            ("pceId", _PLATFORM_PCEID.hex()),
            ("tcbType", 0),
            ("tcbEvaluationDataNumber", 19),
        ]
        # Intel's document order for a TDX TCBInfo: tdxModule and
        # tdxModuleIdentities sit between tcbEvaluationDataNumber and
        # tcbLevels.  Order matters here because the signature covers the
        # serialized bytes, so keeping Intel's order keeps the fixture honest.
        if tee == "tdx":
            if tdx_module is _DEFAULT:
                tdx_module = _tdx_module()
            if tdx_module_identities is _DEFAULT:
                tdx_module_identities = _tdx_module_identities()
            if tdx_module is not None:
                pairs.append(("tdxModule", tdx_module))
            if tdx_module_identities is not None:
                pairs.append(("tdxModuleIdentities", tdx_module_identities))
        pairs.append(("tcbLevels", levels))
        pairs.extend(extra)
        return _signed_body(signing_key or self.tcb_signing_key, "tcbInfo",
                            pairs)

    @staticmethod
    def default_levels(tee: str = "sgx"):
        tdx_hi = [6, 0] + [0] * 14 if tee == "tdx" else None
        tdx_ok = [4, 0] + [0] * 14 if tee == "tdx" else None
        tdx_lo = [1, 0] + [0] * 14 if tee == "tdx" else None
        return [
            _level([7] * 16, 15, "UpToDate", tdx=tdx_hi),
            _level([5] * 16, 13, "UpToDate", tdx=tdx_ok),
            _level([3] * 16, 11, "OutOfDate", tdx=tdx_lo,
                   advisories=["INTEL-SA-00999"]),
        ]

    def qe_identity_body(self, *, tee: str = "sgx", levels=None,
                         next_update: str = "2026-09-18T12:00:00Z",
                         signing_key=None, overrides=None) -> bytes:
        if levels is None:
            levels = [
                {"tcb": {"isvsvn": 8}, "tcbDate": "2025-11-13T00:00:00Z",
                 "tcbStatus": "UpToDate"},
                {"tcb": {"isvsvn": 5}, "tcbDate": "2024-03-13T00:00:00Z",
                 "tcbStatus": "OutOfDate"},
            ]
        doc = {
            "id": "QE" if tee == "sgx" else "TD_QE",
            "version": 2,
            "issueDate": "2026-08-18T12:00:00Z",
            "nextUpdate": next_update,
            "tcbEvaluationDataNumber": 19,
            "miscselect": "00000000",
            "miscselectMask": "FFFFFFFF",
            "attributes": "11000000000000000000000000000000",
            "attributesMask": "FBFFFFFFFFFFFFFF00000000000000 00".replace(" ", ""),
            "mrsigner": _QE_MRSIGNER.hex(),
            "isvprodid": 2,
            "tcbLevels": levels,
        }
        doc.update(overrides or {})
        return _signed_body(signing_key or self.tcb_signing_key,
                            "enclaveIdentity", list(doc.items()))

    # -- CRLs --------------------------------------------------------------

    def _crl(self, issuer_cert, issuer_key, revoked_serials,
             *, next_update_days: int = 30):
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer_cert.subject)
            .last_update(NOW - datetime.timedelta(days=1))
            .next_update(NOW + datetime.timedelta(days=next_update_days))
        )
        for serial in revoked_serials:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(NOW - datetime.timedelta(days=2))
                .build())
        return builder.sign(issuer_key, hashes.SHA256())

    def crl_item(self, ca: str = "platform", *, issuer_cert=None,
                 issuer_key=None, revoked=(), chain=None, **kwargs) -> dict:
        issuer_cert = issuer_cert if issuer_cert is not None else self.pck_ca
        issuer_key = issuer_key if issuer_key is not None else self.pck_ca_key
        crl = self._crl(issuer_cert, issuer_key, revoked, **kwargs)
        return {
            "kind": "pck_crl",
            "ca": ca,
            "url": ("https://api.trustedservices.intel.com/sgx/certification/"
                    f"v4/pckcrl?ca={ca}&encoding=der"),
            "endpoint": f"/sgx/certification/v4/pckcrl?ca={ca}",
            "body": base64.b64encode(
                crl.public_bytes(serialization.Encoding.DER)).decode(),
            "body_encoding": "base64",
            "signed_value_key": None,
            "issuer_chain_pem": (chain if chain is not None
                                 else _pem(issuer_cert, self.root)).decode(),
            "issuer_chain_header": "SGX-PCK-CRL-Issuer-Chain",
        }

    def root_crl_item(self, revoked=(), **kwargs) -> dict:
        """A Root-CA-issued CRL.

        The builder does not currently fetch one (Intel publishes it at a
        separate distribution point), so this exists to prove the intermediate
        *is* checked when it is available.
        """
        return self.crl_item("platform", issuer_cert=self.root,
                             issuer_key=self.root_key, revoked=revoked,
                             chain=_pem(self.root), **kwargs)

    # -- the bundle --------------------------------------------------------

    def json_item(self, kind: str, body: bytes, *, chain=None,
                  fmspc: bytes | None = None, tee: str = "sgx") -> dict:
        signed_key = ("tcbInfo" if kind == "tcb_info" else "enclaveIdentity")
        endpoint = ("/{}/certification/v4/tcb".format(tee) if kind == "tcb_info"
                    else "/{}/certification/v4/qe/identity".format(tee))
        item = {
            "kind": kind,
            "url": "https://api.trustedservices.intel.com" + endpoint,
            "endpoint": endpoint,
            "body": body.decode("utf-8"),
            "body_encoding": "utf-8",
            "signed_value_key": signed_key,
            "issuer_chain_pem": (chain if chain is not None
                                 else _pem(self.tcb_signing,
                                           self.root)).decode(),
            "issuer_chain_header": ("TCB-Info-Issuer-Chain"
                                    if kind == "tcb_info"
                                    else "SGX-Enclave-Identity-Issuer-Chain"),
        }
        if kind == "tcb_info":
            item["fmspc"] = (fmspc if fmspc is not None
                             else _PLATFORM_FMSPC).hex().upper()
        return item

    def bundle(self, *, tee: str = "sgx", fetched_at=None,
               tcb_info_body=None, qe_identity_body=None,
               tcb_chain=None, qe_chain=None, crls=None,
               drop=(), overrides=None, root_ca_sha256=None) -> dict:
        fetched = fetched_at or (NOW - datetime.timedelta(hours=2))
        items = {}
        if "tcb_info" not in drop:
            items[f"{tee}_tcb_info"] = self.json_item(
                "tcb_info",
                tcb_info_body if tcb_info_body is not None
                else self.tcb_info_body(tee=tee),
                chain=tcb_chain, tee=tee)
        if "qe_identity" not in drop:
            items[f"{tee}_qe_identity"] = self.json_item(
                "enclave_identity",
                qe_identity_body if qe_identity_body is not None
                else self.qe_identity_body(tee=tee),
                chain=qe_chain, tee=tee)
        if "pck_crl" not in drop:
            for entry in (crls if crls is not None else [self.crl_item()]):
                items[f"sgx_pck_crl_{entry['ca']}"] = entry
        missing = sorted(set(_ALL_ITEMS_FOR[tee]) - set(items))
        if root_ca_sha256 is None:
            root_ca_sha256 = self.root.fingerprint(hashes.SHA256()).hex()
        doc = {
            "schema_version": 1,
            "fetched_at": fetched.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": "https://api.trustedservices.intel.com",
            "fmspc": _PLATFORM_FMSPC.hex().upper(),
            "root_ca_sha256": root_ca_sha256,
            "complete": not missing,
            "missing": missing,
            "items": items,
        }
        doc.update(overrides or {})
        return doc

    def write_bundle(self, tmp_path, name="tcb_collateral.json", **kwargs) -> str:
        path = os.path.join(str(tmp_path), name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.bundle(**kwargs), fh, indent=2, sort_keys=True)
        return path


_ALL_ITEMS_FOR = {
    "sgx": ("sgx_tcb_info", "sgx_qe_identity", "sgx_pck_crl_platform",
            "sgx_pck_crl_processor"),
    "tdx": ("tdx_tcb_info", "tdx_qe_identity", "sgx_pck_crl_platform",
            "sgx_pck_crl_processor"),
}


@pytest.fixture()
def world():
    return IntelWorld()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    # The client's loader caches into sys.modules by design (a rendered client
    # imports the evaluator once).  Drop it between tests so a test that loads
    # it successfully cannot make the "not staged" case pass by accident.
    monkeypatch.delitem(sys.modules, "tee_crafter_tcb_eval", raising=False)
    for name in ("TEE_CRAFTER_TCB_COLLATERAL",
                 "TEE_CRAFTER_TCB_COLLATERAL_MAX_AGE_HOURS",
                 "TEE_CRAFTER_TCB_ALLOW_STATUS",
                 "TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS",
                 "TEE_CRAFTER_TCB_EVAL_MODULE"):
        monkeypatch.delenv(name, raising=False)


def _kwargs(tcb, world, cert_checks, path, *, tee="sgx", qe_report=None,
            report_cpusvn=_PLATFORM_CPUSVN, **overrides):
    # The TD report body has to agree with TEE_TCB_SVN (the evaluator
    # cross-checks them, so that handing it a whole quote instead of the body
    # at offset 48 cannot pass unnoticed).  Derive it from whichever SVN is in
    # effect so that overriding tee_tcb_svn alone stays consistent; an explicit
    # td_report_body override still wins, via base.update below.
    svn = overrides.get("tee_tcb_svn",
                        _TEE_TCB_SVN if tee == "tdx" else b"")
    base = dict(
        tee=tee,
        pck_chain=world.pck_chain(),
        qe_report=qe_report if qe_report is not None else build_qe_report(),
        report_cpusvn=report_cpusvn,
        tee_tcb_svn=svn,
        td_report_body=(build_td_report_body(tee_tcb_svn=svn)
                        if tee == "tdx" else b""),
        pinned_root_ca_pem=world.root_pem,
        collateral_path=path,
        now=NOW,
        **cert_checks,
    )
    base.update(overrides)
    return base


# ===========================================================================
# 1. tcbStatus resolution
# ===========================================================================

def test_up_to_date_platform_is_accepted(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path)
    result = tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert result["tcb_status"] == "UpToDate"
    assert result["fmspc"] == _PLATFORM_FMSPC.hex()
    assert result["pcesvn"] == _PLATFORM_PCESVN
    assert result["qe_identity"]["status"] == "UpToDate"
    # The leaf is covered by the PCK CA CRL; the PCK CA itself is issued by the
    # root, and the bundle schema carries no Root CA CRL, so it is reported as
    # uncovered rather than quietly counted as clear.
    assert result["crl"]["certificates_checked"] == 1
    assert result["crl"]["uncovered_root_issued"] == [
        "O=Intel Corporation,CN=Intel SGX PCK Platform CA"]


def test_out_of_date_platform_is_rejected(tcb, world, cert_checks, tmp_path):
    levels = [_level([5] * 16, 13, "OutOfDate",
                     advisories=["INTEL-SA-00615"])]
    path = world.write_bundle(
        tmp_path, tcb_info_body=world.tcb_info_body(levels=levels))
    with pytest.raises(tcb.TcbStatusRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "OutOfDate" in str(exc.value)
    assert "INTEL-SA-00615" in str(exc.value)


def test_revoked_platform_is_rejected(tcb, world, cert_checks, tmp_path):
    levels = [_level([5] * 16, 13, "Revoked")]
    path = world.write_bundle(
        tmp_path, tcb_info_body=world.tcb_info_body(levels=levels))
    with pytest.raises(tcb.TcbStatusRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "Revoked" in str(exc.value)


def test_revoked_is_refused_even_when_the_policy_lists_it(tcb):
    """No policy can allow ``Revoked``; the attempt is itself an error."""
    os.environ["TEE_CRAFTER_TCB_ALLOW_STATUS"] = "Revoked"
    try:
        with pytest.raises(tcb.TcbPolicyError) as exc:
            tcb.resolve_allowed_statuses()
    finally:
        del os.environ["TEE_CRAFTER_TCB_ALLOW_STATUS"]
    assert "Revoked" in str(exc.value)


def test_sw_hardening_needed_is_rejected_by_default(tcb, world, cert_checks,
                                                   tmp_path):
    levels = [_level([5] * 16, 13, "SWHardeningNeeded")]
    path = world.write_bundle(
        tmp_path, tcb_info_body=world.tcb_info_body(levels=levels))
    with pytest.raises(tcb.TcbStatusRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "SWHardeningNeeded" in str(exc.value)
    assert "TEE_CRAFTER_TCB_ALLOW_STATUS" in str(exc.value)


def test_sw_hardening_needed_is_accepted_under_explicit_policy(
        tcb, world, cert_checks, tmp_path, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_TCB_ALLOW_STATUS", "SWHardeningNeeded")
    levels = [_level([5] * 16, 13, "SWHardeningNeeded")]
    path = world.write_bundle(
        tmp_path, tcb_info_body=world.tcb_info_body(levels=levels))
    result = tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert result["tcb_status"] == "SWHardeningNeeded"


def test_configuration_needed_policy_is_independent_of_sw_hardening(
        tcb, world, cert_checks, tmp_path, monkeypatch):
    """Allowing one optional status must not allow the other."""
    monkeypatch.setenv("TEE_CRAFTER_TCB_ALLOW_STATUS", "SWHardeningNeeded")
    levels = [_level([5] * 16, 13, "ConfigurationNeeded")]
    path = world.write_bundle(
        tmp_path, tcb_info_body=world.tcb_info_body(levels=levels))
    with pytest.raises(tcb.TcbStatusRejected):
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))


def test_cpusvn_below_every_level_is_rejected(tcb, world, cert_checks,
                                              tmp_path):
    """A platform older than the oldest published level has no status at all."""
    levels = [_level([9] * 16, 15, "UpToDate"),
              _level([7] * 16, 14, "OutOfDate")]
    path = world.write_bundle(
        tmp_path, tcb_info_body=world.tcb_info_body(levels=levels))
    with pytest.raises(tcb.TcbStatusRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "below every level" in str(exc.value)


def test_report_cpusvn_below_every_level_is_rejected(tcb, world, cert_checks,
                                                     tmp_path):
    """The running report's CPUSVN is a floor too, not just the certificate's."""
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.TcbStatusRejected):
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               report_cpusvn=bytes(16)))


def test_highest_matching_level_wins_whatever_the_array_order(
        tcb, world, cert_checks, tmp_path):
    """Three levels match; the resolved status must come from the highest TCB.

    The array is deliberately shuffled so the answer cannot come from "take the
    first entry".
    """
    levels = [
        _level([3] * 16, 11, "OutOfDate"),
        _level([5] * 16, 13, "UpToDate"),
        _level([4] * 16, 12, "ConfigurationNeeded"),
        _level([9] * 16, 15, "UpToDate"),          # does not match
    ]
    path = world.write_bundle(
        tmp_path, tcb_info_body=world.tcb_info_body(levels=levels))
    result = tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert result["tcb_status"] == "UpToDate"
    assert result["tcb_level_index"] == 1


def test_pcesvn_below_the_level_excludes_it(tcb, world, cert_checks, tmp_path):
    """Matching components are not enough: PCESVN gates the level too."""
    levels = [_level([5] * 16, _PLATFORM_PCESVN + 1, "UpToDate"),
              _level([5] * 16, _PLATFORM_PCESVN, "OutOfDate")]
    path = world.write_bundle(
        tmp_path, tcb_info_body=world.tcb_info_body(levels=levels))
    with pytest.raises(tcb.TcbStatusRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "OutOfDate" in str(exc.value)


def test_tdx_compares_tee_tcb_svn_against_tdxtcbcomponents(
        tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path, tee="tdx")
    result = tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="tdx",
                                    qe_report=build_qe_report()))
    assert result["tcb_status"] == "UpToDate"
    assert result["tcb_level_index"] == 1


def test_tdx_rejects_a_tee_tcb_svn_below_every_level(
        tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path, tee="tdx")
    with pytest.raises(tcb.TcbStatusRejected):
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="tdx",
                               tee_tcb_svn=bytes(16)))


def test_tdx_tcb_info_is_not_accepted_for_sgx(tcb, world, cert_checks,
                                              tmp_path):
    """A TDX TCBInfo filed under the SGX item name must still be refused."""
    path = world.write_bundle(tmp_path,
                              tcb_info_body=world.tcb_info_body(tee="tdx"))
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="sgx"))
    assert "TDX" in str(exc.value)


def test_tcb_info_for_another_fmspc_is_rejected(tcb, world, cert_checks,
                                                tmp_path):
    other = bytes.fromhex("10a06d070000")
    path = world.write_bundle(
        tmp_path, tcb_info_body=world.tcb_info_body(fmspc=other))
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert other.hex() in str(exc.value)


# ===========================================================================
# 2. Raw bytes: a re-serialized document must not verify
# ===========================================================================

@pytest.mark.parametrize("dumps_kwargs", [
    {},                                    # default separators: adds spaces
    {"separators": (",", ":"), "sort_keys": True},   # reorders keys
])
def test_round_tripped_collateral_is_rejected(tcb, world, cert_checks,
                                              tmp_path, dumps_kwargs):
    """``json.loads`` -> ``json.dumps`` changes the signed bytes.

    It usually *looks* harmless on CPython because dicts keep document order,
    which is exactly why this needs a test rather than a comment: the first
    number that reformats, or the first ``sort_keys=True``, silently breaks
    every signature in the fleet.
    """
    original = world.tcb_info_body()
    round_tripped = json.dumps(json.loads(original.decode()),
                               **dumps_kwargs).encode()
    assert round_tripped != original
    path = world.write_bundle(tmp_path, tcb_info_body=round_tripped)
    with pytest.raises(tcb.CollateralUntrusted) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "re-serialized" in str(exc.value)


def test_raw_slice_is_byte_identical_to_the_response(tcb, world):
    """The verifier must hash the response's own bytes, not a re-encoding."""
    body = world.tcb_info_body()
    signed = tcb.raw_top_level_value(body, "tcbInfo")
    assert signed in body
    assert body.index(signed) == body.index(b'"tcbInfo":') + len(b'"tcbInfo":')


def test_raw_slice_ignores_a_nested_key_of_the_same_name(tcb):
    raw = b'{"outer":{"tcbInfo":"decoy"},"tcbInfo":{"real":1}}'
    assert tcb.raw_top_level_value(raw, "tcbInfo") == b'{"real":1}'


def test_duplicated_signed_key_is_ambiguous_and_rejected(tcb):
    raw = b'{"tcbInfo":{"a":1},"tcbInfo":{"a":2},"signature":"00"}'
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.raw_top_level_value(raw, "tcbInfo")
    assert "more than once" in str(exc.value)


def test_tampered_tcb_status_is_rejected(tcb, world, cert_checks, tmp_path):
    """Flipping the status in the body breaks Intel's signature over it."""
    body = world.tcb_info_body()
    tampered = body.replace(b'"tcbStatus":"OutOfDate"',
                            b'"tcbStatus":"UpToDate"')
    assert tampered != body
    path = world.write_bundle(tmp_path, tcb_info_body=tampered)
    with pytest.raises(tcb.CollateralUntrusted):
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))


def test_resigning_with_another_key_is_rejected(tcb, world, cert_checks,
                                                tmp_path):
    """A well-formed body signed by a key the pinned root never certified."""
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    body = world.tcb_info_body(
        levels=[_level([5] * 16, 13, "UpToDate")], signing_key=rogue_key)
    path = world.write_bundle(tmp_path, tcb_info_body=body)
    with pytest.raises(tcb.CollateralUntrusted):
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))


# ===========================================================================
# 3. Trust anchoring — the bundle's own root proves nothing
# ===========================================================================

def test_self_consistent_bundle_with_embedded_root_is_rejected(
        tcb, world, cert_checks, tmp_path):
    """The whole-bundle forgery: attacker mints root, signing cert and body.

    Every internal check the bundle offers is satisfied — the signing
    certificate chains to the root that ships *inside* the bundle, and the
    root signed it.  That is circular, and it is the same shape as the
    ``gpu-cc-gcp`` bypass where every check read from one attacker-supplied
    blob.  Anchoring on the pinned certificate is what breaks it.
    """
    rogue = IntelWorld()          # its own root, also CN=Intel SGX Root CA
    body = rogue.tcb_info_body(levels=[_level([5] * 16, 13, "UpToDate")])
    path = world.write_bundle(
        tmp_path, tcb_info_body=body,
        tcb_chain=_pem(rogue.tcb_signing, rogue.root))
    with pytest.raises(tcb.CollateralUntrusted) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    message = str(exc.value)
    assert "terminates at a self-signed certificate" in message
    assert "not the pinned" in message


def test_chain_omitting_the_root_still_needs_the_pinned_signature(
        tcb, world, cert_checks, tmp_path):
    """Dropping the root from the chain does not dodge the anchor."""
    rogue = IntelWorld()
    body = rogue.tcb_info_body(levels=[_level([5] * 16, 13, "UpToDate")])
    path = world.write_bundle(tmp_path, tcb_info_body=body,
                              tcb_chain=_pem(rogue.tcb_signing))
    with pytest.raises(tcb.CollateralUntrusted) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "did not sign" in str(exc.value)


def test_a_bogus_intermediate_in_the_collateral_chain_is_refused(
        tcb, world, cert_checks, tmp_path):
    """Splicing a real Intel CA into the chain does not make the walk succeed.

    The walk allows intermediates (matching the builder-side reference), so the
    refusal has to come from the signature relation, not from a length check:
    the PCK CA never signed the TCB signing certificate.
    """
    path = world.write_bundle(
        tmp_path,
        tcb_chain=_pem(world.tcb_signing, world.pck_ca, world.root))
    with pytest.raises(tcb.CollateralUntrusted) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "did not sign" in str(exc.value)


def test_a_signing_leaf_without_digital_signature_is_refused(
        tcb, world, cert_checks, tmp_path):
    """Intel's TCB signing leaf carries keyUsage digitalSignature.

    A leaf whose keyUsage omits it is not permitted to sign the document, and
    the client's ``check_leaf_certificate`` alone would not catch that — it
    only rejects CA:TRUE.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Intel SGX TCB Signing"))
        .issuer_name(world.root.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=False, content_commitment=True,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=False,
                          crl_sign=False, encipher_only=False,
                          decipher_only=False),
            critical=True)
        .sign(world.root_key, hashes.SHA256())
    )
    body = world.tcb_info_body(signing_key=key)
    path = world.write_bundle(tmp_path, tcb_info_body=body,
                              tcb_chain=_pem(cert, world.root))
    with pytest.raises(tcb.CollateralUntrusted) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "digitalSignature" in str(exc.value)


def test_a_ca_signing_certificate_is_refused(tcb, world, cert_checks,
                                              tmp_path):
    """A collateral signer asserting CA:TRUE could mint more certificates."""
    _, ca_signer = _mint_ca("Intel SGX TCB Signing", issuer_cert=world.root,
                            issuer_key=world.root_key, path_length=0)
    path = world.write_bundle(tmp_path,
                              tcb_chain=_pem(ca_signer, world.root))
    with pytest.raises(tcb.CollateralUntrusted) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "constraint check failed" in str(exc.value)


def test_wrong_pinned_anchor_is_named_not_guessed(tcb, world, cert_checks,
                                                  tmp_path):
    other = IntelWorld(root_cn="Intel SGX Attestation Report Signing CA")
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.CollateralUntrusted) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               pinned_root_ca_pem=other.root_pem))
    assert "Attestation Report Signing CA" in str(exc.value)


def test_clients_pin_the_shipped_intel_sgx_root_ca():
    """The anchor the clients actually carry is the DCAP root, not the EPID one."""
    root_pem = platforms._load_intel_root_ca()
    cert = x509.load_pem_x509_certificate(root_pem.encode())
    cn = next(a.value for a in cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME))
    assert cn == "Intel SGX Root CA"
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)


# ===========================================================================
# 4. Staleness
# ===========================================================================

def test_fresh_collateral_is_accepted(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(
        tmp_path, fetched_at=NOW - datetime.timedelta(hours=6))
    result = tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert 6 * 3600 - 5 < result["collateral_age_seconds"] < 6 * 3600 + 5


def test_stale_collateral_is_rejected(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(
        tmp_path, fetched_at=NOW - datetime.timedelta(days=9))
    with pytest.raises(tcb.CollateralStale) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    message = str(exc.value)
    assert "216.0h old" in message
    assert "TEE_CRAFTER_TCB_COLLATERAL_MAX_AGE_HOURS" in message


def test_the_staleness_bound_is_overridable(tcb, world, cert_checks, tmp_path,
                                            monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_TCB_COLLATERAL_MAX_AGE_HOURS", "480")
    path = world.write_bundle(
        tmp_path, fetched_at=NOW - datetime.timedelta(days=9))
    assert tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))


def test_a_non_positive_bound_is_a_configuration_error(tcb, monkeypatch):
    """Silently disabling the check by setting it to zero is not on offer."""
    monkeypatch.setenv("TEE_CRAFTER_TCB_COLLATERAL_MAX_AGE_HOURS", "0")
    with pytest.raises(tcb.TcbPolicyError):
        tcb.resolve_max_age_seconds()


def test_default_staleness_bound_is_seven_days(tcb):
    assert tcb.DEFAULT_MAX_AGE_SECONDS == 7 * 24 * 3600


def test_future_dated_collateral_is_rejected(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(
        tmp_path, fetched_at=NOW + datetime.timedelta(days=2))
    with pytest.raises(tcb.CollateralStale) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "in the future" in str(exc.value)


def test_expired_next_update_is_rejected_despite_a_fresh_fetch(
        tcb, world, cert_checks, tmp_path):
    """Intel's own ``nextUpdate`` is not relaxed by the fetch-age override."""
    body = world.tcb_info_body(next_update="2026-07-01T00:00:00Z")
    path = world.write_bundle(tmp_path, tcb_info_body=body,
                              fetched_at=NOW - datetime.timedelta(minutes=5))
    with pytest.raises(tcb.CollateralStale) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "expired at" in str(exc.value)


def test_expired_crl_is_rejected(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(
        tmp_path, crls=[world.crl_item(next_update_days=-1)])
    with pytest.raises(tcb.CollateralStale) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "CRL expired" in str(exc.value)


# ===========================================================================
# 5. Missing / partial bundles are hard failures
# ===========================================================================

def test_absent_bundle_is_a_hard_failure(tcb, world, cert_checks, tmp_path):
    missing = os.path.join(str(tmp_path), "nope.json")
    with pytest.raises(tcb.CollateralMissing) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, missing))
    assert "TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS" in str(exc.value)


def test_bundle_without_tcb_info_names_the_observed_fmspc(
        tcb, world, cert_checks, tmp_path):
    """The default build cannot know the FMSPC, so this is the common case.

    It must still be a hard failure — a missing TCBInfo may never silently skip
    ``tcbStatus`` — but the message has to carry the value the operator needs,
    which the client has just parsed out of the PCK leaf.
    """
    path = world.write_bundle(tmp_path, drop=("tcb_info",))
    with pytest.raises(tcb.TcbInfoUnavailable) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    message = str(exc.value)
    assert _PLATFORM_FMSPC.hex().upper() in message
    assert f"TEE_CRAFTER_FMSPC={_PLATFORM_FMSPC.hex().upper()}" in message
    assert "complete=False" in message
    assert "sgx_tcb_info" in message


def test_tcb_info_unavailable_is_still_a_collateral_failure(tcb):
    """Its own class, but never a softer outcome."""
    assert issubclass(tcb.TcbInfoUnavailable, tcb.CollateralMissing)
    assert issubclass(tcb.TcbInfoUnavailable, tcb.TcbEvalError)


@pytest.mark.parametrize("dropped, expected", [
    ("qe_identity", "sgx_qe_identity"),
    ("pck_crl", "PCK CRL"),
])
def test_partial_bundle_is_a_hard_failure(tcb, world, cert_checks, tmp_path,
                                          dropped, expected):
    path = world.write_bundle(tmp_path, drop=(dropped,))
    with pytest.raises(tcb.CollateralMissing) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert expected in str(exc.value)


def test_empty_bundle_is_a_hard_failure(tcb, world, cert_checks, tmp_path):
    path = os.path.join(str(tmp_path), "empty.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{}")
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "schema_version" in str(exc.value)


def test_a_newer_schema_version_is_refused(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path, overrides={"schema_version": 2})
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "schema_version" in str(exc.value)


def test_an_unknown_item_name_is_refused(tcb, world, cert_checks, tmp_path):
    doc = world.bundle()
    doc["items"]["sgx_something_new"] = doc["items"]["sgx_tcb_info"]
    path = os.path.join(str(tmp_path), "unknown.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "unknown item" in str(exc.value)


def test_a_self_contradicting_missing_list_is_refused(tcb, world, cert_checks,
                                                      tmp_path):
    """Listed as missing *and* carried: refuse rather than pick a claim."""
    path = world.write_bundle(tmp_path,
                              overrides={"missing": ["sgx_tcb_info"]})
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "also carries it" in str(exc.value)


def test_a_declared_complete_flag_cannot_conjure_a_missing_item(
        tcb, world, cert_checks, tmp_path):
    """``complete: true`` on a bundle with no TCBInfo changes nothing.

    The flag is a diagnostic.  If it could steer the decision, an attacker with
    write access to the file would choose the branch.
    """
    path = world.write_bundle(tmp_path, drop=("tcb_info",),
                              overrides={"complete": True, "missing": []})
    with pytest.raises(tcb.TcbInfoUnavailable):
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))


def test_item_without_an_issuer_chain_is_a_hard_failure(
        tcb, world, cert_checks, tmp_path):
    doc = world.bundle()
    doc["items"]["sgx_tcb_info"].pop("issuer_chain_pem")
    path = os.path.join(str(tmp_path), "nochain.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "issuer_chain_pem" in str(exc.value)


def test_an_item_lying_about_its_signed_value_key_is_refused(
        tcb, world, cert_checks, tmp_path):
    """The bundle does not get to choose which bytes count as signed."""
    doc = world.bundle()
    doc["items"]["sgx_tcb_info"]["signed_value_key"] = "signature"
    path = os.path.join(str(tmp_path), "wrongkey.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "signed_value_key" in str(exc.value)


def test_an_item_lying_about_its_kind_is_refused(tcb, world, cert_checks,
                                                 tmp_path):
    doc = world.bundle()
    doc["items"]["sgx_tcb_info"]["kind"] = "pck_crl"
    path = os.path.join(str(tmp_path), "wrongkind.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "kind" in str(exc.value)


def test_an_unsupported_body_encoding_is_refused(tcb, world, cert_checks,
                                                 tmp_path):
    doc = world.bundle()
    doc["items"]["sgx_tcb_info"]["body_encoding"] = "hex"
    path = os.path.join(str(tmp_path), "hexbody.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "body_encoding" in str(exc.value)


def test_a_root_fingerprint_mismatch_is_reported_not_trusted(
        tcb, world, cert_checks, tmp_path):
    """``root_ca_sha256`` is a diagnostic; the signature check still decides."""
    path = world.write_bundle(tmp_path, root_ca_sha256="ab" * 32)
    stream = io.StringIO()
    result = tcb.enforce(stream=stream,
                         **_kwargs(tcb, world, cert_checks, path))
    assert result["tcb_status"] == "UpToDate"
    assert "root_ca_sha256" in stream.getvalue()


def test_missing_pck_sgx_extension_is_a_hard_failure(
        tcb, world, cert_checks, tmp_path):
    """No FMSPC means no TCBInfo applies; that is a failure, not a skip."""
    _, plain_leaf = _mint_leaf("Intel SGX PCK Certificate",
                               issuer_cert=world.pck_ca,
                               issuer_key=world.pck_ca_key)
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.PckExtensionError) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               pck_chain=[plain_leaf, world.pck_ca,
                                          world.root]))
    assert "no Intel SGX extension" in str(exc.value)


def test_pck_extension_without_fmspc_is_a_hard_failure(
        tcb, world, cert_checks, tmp_path):
    _, leaf = world._mint_pck_leaf(omit_fmspc=True)
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.PckExtensionError) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               pck_chain=[leaf, world.pck_ca, world.root]))
    assert "FMSPC" in str(exc.value)


def test_no_pck_chain_is_a_hard_failure(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.CollateralMalformed):
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, pck_chain=[]))


# ===========================================================================
# 6. FMSPC / CPUSVN / PCESVN extraction
# ===========================================================================

def test_pck_extension_fields_are_extracted(tcb, world):
    platform = tcb.parse_pck_platform_tcb(world.pck_leaf)
    assert platform.fmspc_hex == _PLATFORM_FMSPC.hex()
    assert platform.pceid_hex == _PLATFORM_PCEID.hex()
    assert platform.cpusvn == _PLATFORM_CPUSVN
    assert platform.pcesvn == _PLATFORM_PCESVN
    assert platform.sgx_components == _PLATFORM_COMPONENTS


def test_component_svns_fall_back_to_cpusvn_bytes(tcb, world):
    """Some certificates carry only the concatenated CPUSVN."""
    cpusvn = bytes(range(1, 17))
    der = build_sgx_extension(fmspc=_PLATFORM_FMSPC, pceid=_PLATFORM_PCEID,
                              cpusvn=cpusvn, pcesvn=7, components=[])
    ext = x509.UnrecognizedExtension(x509.ObjectIdentifier(_EXT_OID), der)
    _, leaf = _mint_leaf("Intel SGX PCK Certificate",
                         issuer_cert=world.pck_ca, issuer_key=world.pck_ca_key,
                         extra_extensions=[(ext, False)])
    platform = tcb.parse_pck_platform_tcb(leaf)
    assert platform.sgx_components == list(cpusvn)


# ===========================================================================
# 7. QEIdentity
# ===========================================================================

def test_qe_isvsvn_below_the_signed_minimum_is_rejected(
        tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.QeIdentityRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               qe_report=build_qe_report(isvsvn=2)))
    assert "below every level" in str(exc.value)


def test_qe_isvsvn_matching_an_out_of_date_level_is_rejected(
        tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.QeIdentityRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               qe_report=build_qe_report(isvsvn=6)))
    assert "OutOfDate" in str(exc.value)


def test_qe_isvprodid_mismatch_is_rejected(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.QeIdentityRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               qe_report=build_qe_report(isvprodid=9)))
    assert "ISVPRODID" in str(exc.value)


def test_qe_attributes_mask_mismatch_is_rejected(tcb, world, cert_checks,
                                                 tmp_path):
    """A QE reporting DEBUG in ATTRIBUTES fails the masked comparison."""
    path = world.write_bundle(tmp_path)
    debug_attrs = b"\x13" + b"\x00" * 7 + b"\xe7" + b"\x00" * 7
    with pytest.raises(tcb.QeIdentityRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               qe_report=build_qe_report(
                                   attributes=debug_attrs)))
    assert "attributes" in str(exc.value)


def test_qe_miscselect_mask_mismatch_is_rejected(tcb, world, cert_checks,
                                                 tmp_path):
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.QeIdentityRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               qe_report=build_qe_report(
                                   miscselect=b"\x01\x00\x00\x00")))
    assert "miscselect" in str(exc.value)


def test_qe_mrsigner_mismatch_is_rejected(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.QeIdentityRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               qe_report=build_qe_report(mrsigner=b"\xaa" * 32)))
    assert "MRSIGNER" in str(exc.value)


def test_truncated_qe_report_is_rejected(tcb, world, cert_checks, tmp_path):
    """A short QE report is unusable input, never acceptable input."""
    path = world.write_bundle(tmp_path)
    with pytest.raises(tcb.QeIdentityRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path,
                               qe_report=build_qe_report()[:200]))
    assert "384" in str(exc.value)


def test_sgx_qe_identity_is_not_accepted_for_tdx(tcb, world, cert_checks,
                                                 tmp_path):
    path = world.write_bundle(
        tmp_path, tee="tdx", qe_identity_body=world.qe_identity_body(tee="sgx"))
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="tdx"))
    assert "TD_QE" in str(exc.value)


# ===========================================================================
# 8. PCK CRL
# ===========================================================================

def _crl_items(tcb, *entries):
    """Wrap raw bundle CRL entries as the accessor objects the checker takes."""
    return [tcb.CollateralItem(entry.get("ca", "platform"), "pck_crl",
                               base64.b64decode(entry["body"]),
                               entry["issuer_chain_pem"].encode(), entry)
            for entry in entries]


def test_revoked_pck_leaf_is_rejected(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(
        tmp_path,
        crls=[world.crl_item(revoked=[world.pck_leaf.serial_number])])
    with pytest.raises(tcb.PckRevoked) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "revoked" in str(exc.value).lower()
    assert f"{world.pck_leaf.serial_number:x}" in str(exc.value)


def test_revoked_pck_intermediate_is_rejected(tcb, world, cert_checks):
    """Intel revokes a whole class of platform by revoking the PCK CA.

    Driven through ``check_pck_not_revoked`` directly: the bundle schema has
    only the two ``/pckcrl`` slots, so a Root-CA-issued CRL cannot be carried
    in one today.  The check must still enforce it when it is available.
    """
    pinned = tcb.load_pinned_root(world.root_pem)
    items = _crl_items(
        tcb, world.crl_item(),
        world.root_crl_item(revoked=[world.pck_ca.serial_number]))
    with pytest.raises(tcb.PckRevoked) as exc:
        tcb.check_pck_not_revoked(world.pck_chain(), items, pinned,
                                  now=NOW, **cert_checks)
    assert "PCK Platform CA" in str(exc.value)


def test_root_issued_certificate_without_a_crl_is_reported_not_passed(
        tcb, world, cert_checks, tmp_path):
    """The one coverage gap is named in the output, never called PASSED."""
    stream = io.StringIO()
    path = world.write_bundle(tmp_path)
    result = tcb.enforce(stream=stream,
                         **_kwargs(tcb, world, cert_checks, path))
    assert result["crl"]["uncovered_root_issued"], (
        "the PCK CA is issued by the root and the bundle carries no root CRL, "
        "so this must be recorded as uncovered")
    output = stream.getvalue()
    assert "NOT COVERED" in output
    assert "Intel SGX Root CA CRL" in output


def test_root_issued_certificate_with_a_crl_is_checked(tcb, world,
                                                        cert_checks):
    pinned = tcb.load_pinned_root(world.root_pem)
    items = _crl_items(tcb, world.crl_item(), world.root_crl_item())
    result = tcb.check_pck_not_revoked(world.pck_chain(), items, pinned,
                                       now=NOW, **cert_checks)
    assert result["uncovered_root_issued"] == []
    assert result["certificates_checked"] == 2


def test_a_crl_covering_nothing_in_the_chain_is_a_hard_failure(
        tcb, world, cert_checks, tmp_path):
    """No CRL for the leaf's issuer is indistinguishable from revoked."""
    other = IntelWorld()
    foreign = world.crl_item(issuer_cert=other.pck_ca,
                             issuer_key=other.pck_ca_key,
                             chain=_pem(other.pck_ca, world.root))
    path = world.write_bundle(tmp_path, crls=[foreign])
    with pytest.raises(tcb.TcbEvalError) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert isinstance(exc.value, (tcb.PckRevoked, tcb.CollateralUntrusted))


def test_crl_signed_by_a_rogue_ca_is_rejected(tcb, world, cert_checks,
                                              tmp_path):
    rogue = IntelWorld()
    path = world.write_bundle(tmp_path, crls=[rogue.crl_item()])
    with pytest.raises(tcb.CollateralUntrusted) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "self-signed certificate" in str(exc.value)


def test_crl_whose_issuer_does_not_match_its_chain_is_rejected(
        tcb, world, cert_checks, tmp_path):
    """The CRL and the chain vouching for it must describe the same CA."""
    mismatched = world.crl_item(chain=_pem(world.tcb_signing, world.root))
    path = world.write_bundle(tmp_path, crls=[mismatched])
    with pytest.raises(tcb.CollateralUntrusted) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path))
    assert "constraint check failed" in str(exc.value)


# ===========================================================================
# 9. The escape hatch is single, explicit and loud
# ===========================================================================

def test_escape_hatch_skips_the_evaluation_with_a_banner(
        tcb, world, cert_checks, tmp_path, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS", "1")
    stream = io.StringIO()
    missing = os.path.join(str(tmp_path), "absent.json")
    assert tcb.enforce(stream=stream,
                       **_kwargs(tcb, world, cert_checks, missing)) is None
    output = stream.getvalue()
    assert "*" * 78 in output
    assert "REVOKED" in output
    assert "Never use in production" in output
    assert "PASSED" not in output


def test_escape_hatch_needs_the_exact_value_one(tcb, world, cert_checks,
                                                tmp_path, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_ALLOW_UNVERIFIED_TCB_STATUS", "true")
    missing = os.path.join(str(tmp_path), "absent.json")
    with pytest.raises(tcb.CollateralMissing):
        tcb.enforce(stream=io.StringIO(),
                    **_kwargs(tcb, world, cert_checks, missing))


def test_enforce_prints_passed_only_on_a_clean_evaluation(
        tcb, world, cert_checks, tmp_path):
    stream = io.StringIO()
    path = world.write_bundle(tmp_path)
    result = tcb.enforce(stream=stream,
                         **_kwargs(tcb, world, cert_checks, path))
    output = stream.getvalue()
    assert result["tcb_status"] == "UpToDate"
    assert "Platform TCB evaluation: PASSED" in output
    assert _PLATFORM_FMSPC.hex() in output


def test_enforce_never_prints_passed_for_a_policy_accepted_status(
        tcb, world, cert_checks, tmp_path, monkeypatch):
    monkeypatch.setenv("TEE_CRAFTER_TCB_ALLOW_STATUS", "SWHardeningNeeded")
    stream = io.StringIO()
    path = world.write_bundle(
        tmp_path,
        tcb_info_body=world.tcb_info_body(
            levels=[_level([5] * 16, 13, "SWHardeningNeeded",
                           advisories=["INTEL-SA-00657"])]))
    tcb.enforce(stream=stream, **_kwargs(tcb, world, cert_checks, path))
    output = stream.getvalue()
    assert "Platform TCB evaluation: PASSED" not in output
    assert "WARNING" in output
    assert "INTEL-SA-00657" in output


def test_only_one_env_var_can_skip_the_evaluation(tcb):
    """Guard against a second, quieter bypass appearing later."""
    source = open(_SHARED_MODULE_PATH, encoding="utf-8").read()
    tree = ast.parse(source)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "enforce")
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "ENV_ALLOW_UNVERIFIED" in names
    bypass_returns = [n for n in ast.walk(fn)
                      if isinstance(n, ast.Return)
                      and isinstance(n.value, ast.Constant)
                      and n.value.value is None]
    assert len(bypass_returns) == 1, (
        "enforce() has more than one early 'return None'; each one is a path "
        "that accepts a quote without evaluating its TCB status")


# ===========================================================================
# 10. Every client invokes the evaluation, and a failure is fatal
# ===========================================================================

_CLIENTS = {
    "sgx": ("sgx/client.template.py", "verify_ratls_connection",
            lambda: platforms.render_sgx_client_template(
                mrenclave="ab" * 32, mrsigner="cd" * 32)),
    "tdx-azure": ("tdx/azure/client.template.py", "_verify_dcap_attestation",
                  lambda: platforms.render_tdx_client_template(
                      mrtd="ab" * 48)),
    "tdx-gcp": ("tdx/gcp/client.template.py", "_verify_dcap_attestation",
                lambda: platforms.render_tdx_gcp_client_template(
                    mrtd="ab" * 48)),
    "gpu-cc-gcp": ("gpu_cc/gcp/client.template.py", "verify_ratls_connection",
                   lambda: platforms.render_gpu_cc_gcp_client_template(
                       mrtd="ab" * 48)),
}


def _template_source(relpath: str) -> str:
    path = os.path.join(_PKG_DIR, "templates", *relpath.split("/"))
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.parametrize("platform", sorted(_CLIENTS))
def test_client_calls_the_evaluation_inside_its_verifier(platform):
    """Walked with ``ast``, so a comment mentioning the call cannot satisfy it."""
    relpath, verifier, _ = _CLIENTS[platform]
    tree = ast.parse(_template_source(relpath))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == verifier)
    calls = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.setdefault(node.func.id, node.lineno)
    assert "enforce_platform_tcb_status" in calls, (
        f"{relpath}: {verifier} does not evaluate the platform TCB status")
    # ...and it must happen after the QE report signature is established, so
    # the chain it evaluates has already been walked to the pinned root.
    # Compared by source line, because ast.walk is breadth-first, not textual.
    assert calls["enforce_platform_tcb_status"] > \
        calls["verify_qe_report_signature"], (
            f"{relpath}: the TCB evaluation runs before the QE report "
            "signature is verified")


@pytest.mark.parametrize("platform", sorted(_CLIENTS))
def test_client_treats_an_evaluation_failure_as_fatal(platform, monkeypatch):
    _, _, render = _CLIENTS[platform]
    client = _load_client(render(), f"{platform}_fatal_under_test")

    def _boom(*_a, **_k):
        raise RuntimeError("collateral bundle is missing")

    monkeypatch.setitem(client.__dict__, "load_tcb_eval_module", _boom)
    args = (b"\x00" * 5000, {"pck_chain": []})
    if platform != "sgx":
        args = (b"\x00" * 5000, {"tee_tcb_svn": "00" * 16}, {"pck_chain": []})
    with pytest.raises(SystemExit) as exc:
        client.enforce_platform_tcb_status(*args)
    assert exc.value.code == 1


@pytest.mark.parametrize("platform", sorted(_CLIENTS))
def test_client_fails_when_the_shared_module_is_not_staged(platform,
                                                           monkeypatch,
                                                           tmp_path):
    """A build that forgot to stage the evaluator must not verify quotes."""
    _, _, render = _CLIENTS[platform]
    client = _load_client(render(), f"{platform}_nomodule_under_test")
    monkeypatch.setenv("TEE_CRAFTER_TCB_EVAL_MODULE",
                       os.path.join(str(tmp_path), "not-here.py"))
    monkeypatch.setattr(client, "_tcb_eval_module_candidates",
                        lambda: [os.path.join(str(tmp_path), "not-here.py")])
    # Other test modules in this suite put templates/common on sys.path to
    # exercise the in-TEE runtime modules, which would make the plain import
    # succeed.  Take it away: this test is about a build that did not stage
    # the file at all.
    monkeypatch.setattr(sys, "path",
                        [p for p in sys.path
                         if "templates" not in p.replace(os.sep, "/")])
    with pytest.raises(RuntimeError) as exc:
        client.load_tcb_eval_module()
    assert "is neither next to this client" in str(exc.value)


@pytest.mark.parametrize("platform", sorted(_CLIENTS))
def test_client_loads_the_real_shared_module_by_path(platform, monkeypatch):
    """The sibling-module import path works against the file we ship."""
    _, _, render = _CLIENTS[platform]
    client = _load_client(render(), f"{platform}_load_under_test")
    monkeypatch.setenv("TEE_CRAFTER_TCB_EVAL_MODULE", _SHARED_MODULE_PATH)
    monkeypatch.setattr(client, "_tcb_eval_module_candidates",
                        lambda: [_SHARED_MODULE_PATH])
    module = client.load_tcb_eval_module()
    assert hasattr(module, "enforce")
    assert module.DEFAULT_ALLOWED_STATUSES == frozenset({"UpToDate"})


@pytest.mark.parametrize("platform", sorted(_CLIENTS))
def test_client_returns_the_whole_pck_chain_for_revocation_checking(platform):
    relpath, _, _ = _CLIENTS[platform]
    assert '"pck_chain": chain' in _template_source(relpath), (
        f"{relpath}: verify_pck_cert_chain must hand back the whole chain, or "
        "the CRL check can only cover the leaf")


def test_the_hand_copied_qe_svn_floor_is_gone():
    """``_MIN_KNOWN_QE_SVN`` silently went stale while reading as assurance."""
    for relpath, _, _ in _CLIENTS.values():
        source = _template_source(relpath)
        assert "_MIN_KNOWN_QE_SVN" not in source, relpath
        assert "def _check_qe_identity_tcb_status" not in source, relpath


def test_no_client_still_carries_the_tcb_collateral_todo():
    for relpath, _, _ in _CLIENTS.values():
        assert "TODO(tcb-collateral)" not in _template_source(relpath), relpath


def test_the_evaluator_exists_once(tcb):
    """One shared module, not a copy per client."""
    copies = [relpath for relpath, _, _ in _CLIENTS.values()
              if "def resolve_tcb_status(" in _template_source(relpath)]
    assert copies == [], f"the evaluator was copied into {copies}"


# ===========================================================================
# C19. The TDX module (SEAM): tdxModule / tdxModuleIdentities
# ===========================================================================
#
# Before this the TDX module was covered only by a hand-rolled "version >= 1.5"
# floor in the TDX client, which read TEE_TCB_SVN[0] as the major version --
# the opposite of Intel's own verifier -- and never checked who signed the
# module at all.  A SEAM module signed by the hypervisor passed.
#
# _REAL_TDX_TCB_INFO is the verbatim body Intel PCS returned on 2026-08-20 for
#   https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90C06F000000
# checked in under tests/core/fixtures/.  Field names, hex widths, ids and SVNs
# in the tests below are that document's, not invented: mrsigner is 96 hex
# chars (48 bytes), attributes and attributesMask 16 (8 bytes), and the
# identities are exactly TDX_03 (isvsvn 5 UpToDate, 3 OutOfDate) and TDX_01
# (isvsvn 11 UpToDate, then 6, 4, 2 OutOfDate).

_FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "fixtures")
_REAL_TDX_PCS_BODY_PATH = os.path.join(
    _FIXTURE_DIR, "intel_pcs_tdx_tcb_info_90C06F000000.json")


@pytest.fixture(scope="module")
def real_tdx_tcb_info():
    with open(_REAL_TDX_PCS_BODY_PATH, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))["tcbInfo"]


def _svn(isvsvn: int, version: int) -> bytes:
    """TEE_TCB_SVN with the module ISV SVN at [0] and the version at [1]."""
    return bytes([isvsvn, version] + [0] * 14)


# -- the real Intel document ------------------------------------------------

def test_the_real_pcs_fixture_has_the_shape_the_tests_assume(
        real_tdx_tcb_info):
    """Guards the fixture, so a re-fetch that changes shape fails loudly."""
    assert real_tdx_tcb_info["id"] == "TDX"
    assert real_tdx_tcb_info["version"] == 3
    module = real_tdx_tcb_info["tdxModule"]
    assert len(module["mrsigner"]) == 96
    assert len(module["attributes"]) == 16
    assert len(module["attributesMask"]) == 16
    assert [i["id"] for i in real_tdx_tcb_info["tdxModuleIdentities"]] == \
        ["TDX_03", "TDX_01"]


@pytest.mark.parametrize("identity_id,isvsvn,version", [
    ("TDX_03", 5, 3),
    ("TDX_01", 11, 1),
])
def test_a_real_world_up_to_date_tdx_module_is_accepted(
        tcb, real_tdx_tcb_info, identity_id, isvsvn, version):
    """Intel's own document, Intel's own SVNs, an all-zero MRSIGNERSEAM."""
    expected = bytes.fromhex(real_tdx_tcb_info["tdxModule"]["mrsigner"])
    result = tcb.evaluate_tdx_module(
        real_tdx_tcb_info, tee_tcb_svn=_svn(isvsvn, version),
        mrsignerseam=expected, seam_attributes=bytes(8))
    assert result["identity_id"] == identity_id
    assert result["status"] == "UpToDate"
    assert result["matched_isvsvn"] == isvsvn
    assert result["version"] == version
    assert result["isvsvn"] == isvsvn


def test_a_real_world_tampered_mrsignerseam_is_rejected(tcb,
                                                        real_tdx_tcb_info):
    """One flipped bit in MRSIGNERSEAM and the module is somebody else's."""
    expected = bytearray(
        bytes.fromhex(real_tdx_tcb_info["tdxModule"]["mrsigner"]))
    expected[47] ^= 0x01
    with pytest.raises(tcb.TdxModuleRejected) as exc:
        tcb.evaluate_tdx_module(
            real_tdx_tcb_info, tee_tcb_svn=_svn(5, 3),
            mrsignerseam=bytes(expected), seam_attributes=bytes(8))
    assert "MRSIGNERSEAM" in str(exc.value)


def test_a_real_world_out_of_date_module_svn_yields_out_of_date(
        tcb, real_tdx_tcb_info):
    """TDX_03 at ISV SVN 3 is OutOfDate in Intel's published table."""
    expected = bytes.fromhex(real_tdx_tcb_info["tdxModule"]["mrsigner"])
    result = tcb.evaluate_tdx_module(
        real_tdx_tcb_info, tee_tcb_svn=_svn(3, 3), mrsignerseam=expected,
        seam_attributes=bytes(8))
    assert result["status"] == "OutOfDate"
    assert result["matched_isvsvn"] == 3
    assert result["advisory_ids"], "Intel publishes advisories for this level"
    # ... and that is what makes an otherwise-current platform unacceptable.
    assert tcb.converge_tdx_module_status("UpToDate", "OutOfDate") == \
        "OutOfDate"


def test_a_real_world_module_svn_below_every_level_is_rejected(
        tcb, real_tdx_tcb_info):
    expected = bytes.fromhex(real_tdx_tcb_info["tdxModule"]["mrsigner"])
    with pytest.raises(tcb.TdxModuleRejected) as exc:
        tcb.evaluate_tdx_module(
            real_tdx_tcb_info, tee_tcb_svn=_svn(1, 3),
            mrsignerseam=expected, seam_attributes=bytes(8))
    assert "ISV SVN is 1" in str(exc.value)
    assert "lowest 3" in str(exc.value)


def test_a_real_world_module_version_intel_does_not_publish_is_rejected(
        tcb, real_tdx_tcb_info):
    expected = bytes.fromhex(real_tdx_tcb_info["tdxModule"]["mrsigner"])
    with pytest.raises(tcb.TdxModuleRejected) as exc:
        tcb.evaluate_tdx_module(
            real_tdx_tcb_info, tee_tcb_svn=_svn(11, 7),
            mrsignerseam=expected, seam_attributes=bytes(8))
    assert "TDX_07" in str(exc.value)


def test_real_world_non_zero_seam_attributes_are_rejected(tcb,
                                                          real_tdx_tcb_info):
    """Intel's mask is all-ones over an all-zero expectation."""
    expected = bytes.fromhex(real_tdx_tcb_info["tdxModule"]["mrsigner"])
    with pytest.raises(tcb.TdxModuleRejected) as exc:
        tcb.evaluate_tdx_module(
            real_tdx_tcb_info, tee_tcb_svn=_svn(5, 3),
            mrsignerseam=expected,
            seam_attributes=b"\x00\x00\x00\x00\x00\x00\x00\x80")
    assert "SEAMATTRIBUTES" in str(exc.value)


# -- the two TEE_TCB_SVN indices are not interchangeable --------------------

def test_the_version_and_isvsvn_bytes_are_not_swapped(tcb,
                                                      real_tdx_tcb_info):
    """[isvsvn, version], per Intel's TDX_MODULE_*_SVN_INDEX constants.

    Reading them the other way round is the bug already shipped in the TDX
    client's hand-rolled floor, so it gets its own test: TEE_TCB_SVN
    ``[5, 3, ...]`` must select TDX_03, and the transposed ``[3, 5, ...]`` must
    look for a TDX_05 that Intel does not publish.
    """
    expected = bytes.fromhex(real_tdx_tcb_info["tdxModule"]["mrsigner"])
    ok = tcb.evaluate_tdx_module(
        real_tdx_tcb_info, tee_tcb_svn=_svn(5, 3), mrsignerseam=expected,
        seam_attributes=bytes(8))
    assert ok["identity_id"] == "TDX_03"

    with pytest.raises(tcb.TdxModuleRejected) as exc:
        tcb.evaluate_tdx_module(
            real_tdx_tcb_info, tee_tcb_svn=bytes([3, 5] + [0] * 14),
            mrsignerseam=expected, seam_attributes=bytes(8))
    assert "TDX_05" in str(exc.value)


@pytest.mark.parametrize("version,expected", [
    (0, "TDX_00"), (1, "TDX_01"), (3, "TDX_03"), (10, "TDX_0A"),
    (255, "TDX_FF"),
])
def test_identity_id_is_two_upper_case_hex_digits(tcb, version, expected):
    assert tcb.tdx_module_identity_id(version) == expected


def test_a_lower_case_identity_id_still_matches(tcb, real_tdx_tcb_info):
    """Intel's verifier upper-cases the document's id before comparing."""
    doc = json.loads(json.dumps(real_tdx_tcb_info))
    doc["tdxModuleIdentities"][0]["id"] = "tdx_03"
    expected = bytes.fromhex(doc["tdxModule"]["mrsigner"])
    result = tcb.evaluate_tdx_module(doc, tee_tcb_svn=_svn(5, 3),
                                    mrsignerseam=expected,
                                    seam_attributes=bytes(8))
    assert result["identity_id"] == "TDX_03"


# -- TD report body offsets -------------------------------------------------

def test_mrsignerseam_is_read_from_offset_64_not_16(tcb, real_tdx_tcb_info):
    """MRSEAM sits at 16 and MRSIGNERSEAM at 64; off-by-48 must not pass.

    The expected value is planted at MRSEAM's offset and garbage at
    MRSIGNERSEAM's, so an implementation reading the wrong field would accept.
    """
    expected = bytes.fromhex(real_tdx_tcb_info["tdxModule"]["mrsigner"])
    body = bytearray(build_td_report_body(tee_tcb_svn=_svn(5, 3)))
    body[16:64] = expected
    body[64:112] = b"\xa5" * 48
    mrsignerseam, seam_attributes = tcb.td_report_module_fields(
        bytes(body), _svn(5, 3))
    assert mrsignerseam == b"\xa5" * 48
    with pytest.raises(tcb.TdxModuleRejected):
        tcb.evaluate_tdx_module(real_tdx_tcb_info, tee_tcb_svn=_svn(5, 3),
                                mrsignerseam=mrsignerseam,
                                seam_attributes=seam_attributes)


def test_seam_attributes_are_read_from_112_not_td_attributes_at_120(
        tcb, real_tdx_tcb_info):
    """TD_ATTRIBUTES is a *different* field and is not the module's."""
    body = bytearray(build_td_report_body(tee_tcb_svn=_svn(5, 3)))
    body[112:120] = bytes(8)          # SEAMATTRIBUTES: zero, as Intel expects
    body[120:128] = b"\xff" * 8       # TD_ATTRIBUTES: irrelevant here
    _, seam_attributes = tcb.td_report_module_fields(bytes(body), _svn(5, 3))
    assert seam_attributes == bytes(8)
    expected = bytes.fromhex(real_tdx_tcb_info["tdxModule"]["mrsigner"])
    result = tcb.evaluate_tdx_module(
        real_tdx_tcb_info, tee_tcb_svn=_svn(5, 3), mrsignerseam=expected,
        seam_attributes=seam_attributes)
    assert result["status"] == "UpToDate"


def test_a_td_report_15_body_is_accepted(tcb):
    """TDX 1.5 quotes carry a longer body with the same first 584 bytes."""
    body = build_td_report_body(tee_tcb_svn=_svn(5, 3), length=648)
    mrsignerseam, seam_attributes = tcb.td_report_module_fields(
        body, _svn(5, 3))
    assert mrsignerseam == bytes(48)
    assert seam_attributes == bytes(8)


def test_a_truncated_td_report_body_is_refused(tcb):
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.td_report_module_fields(build_td_report_body()[:583],
                                   _TEE_TCB_SVN)
    assert "584" in str(exc.value)


def test_passing_the_whole_quote_instead_of_the_body_is_refused(tcb):
    """The 48-byte header would masquerade as TEE_TCB_SVN.

    A length check alone cannot catch this, so the caller's TEE_TCB_SVN is
    cross-checked against the body's own first 16 bytes.
    """
    quote = b"\x04\x00" + bytes(46) + build_td_report_body(
        tee_tcb_svn=_TEE_TCB_SVN)
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.td_report_module_fields(quote, _TEE_TCB_SVN)
    assert "quote_bytes[48:632]" in str(exc.value)


def test_an_absent_td_report_body_is_refused_not_skipped(tcb):
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.td_report_module_fields(b"", _TEE_TCB_SVN)
    assert "td_report_body=quote_bytes[48:632]" in str(exc.value)


# -- the attributes mask ----------------------------------------------------

def test_attributes_mask_is_applied(tcb):
    """A bit the mask clears must not cause a rejection.

    If the mask were dropped and SEAMATTRIBUTES compared byte-for-byte, this
    would fail -- which is the point of asserting it.
    """
    doc = {"version": 3,
           "tdxModule": {"mrsigner": _TDX_MODULE_MRSIGNER,
                         "attributes": "0000000000000000",
                         "attributesMask": "00FFFFFFFFFFFFFF"}}
    result = tcb.evaluate_tdx_module(
        doc, tee_tcb_svn=_svn(0, 0),
        mrsignerseam=bytes.fromhex(_TDX_MODULE_MRSIGNER),
        seam_attributes=b"\xff" + bytes(7))
    assert result["status"] == ""


def test_a_bit_inside_the_mask_is_still_rejected(tcb):
    doc = {"version": 3,
           "tdxModule": {"mrsigner": _TDX_MODULE_MRSIGNER,
                         "attributes": "0000000000000000",
                         "attributesMask": "00FFFFFFFFFFFFFF"}}
    with pytest.raises(tcb.TdxModuleRejected):
        tcb.evaluate_tdx_module(
            doc, tee_tcb_svn=_svn(0, 0),
            mrsignerseam=bytes.fromhex(_TDX_MODULE_MRSIGNER),
            seam_attributes=b"\x00\x01" + bytes(6))


def test_the_identity_overrides_the_tdx_module_baseline(tcb):
    """When a version selects an identity, *its* mrsigner is the expectation.

    Intel's verifier overwrites all three baseline values from the matched
    identity.  Here the baseline and the identity disagree, and only the
    identity's value may be accepted.
    """
    identity_signer = "ab" * 48
    doc = {
        "version": 3,
        "tdxModule": _tdx_module(),
        "tdxModuleIdentities": [
            {"id": "TDX_03", "mrsigner": identity_signer,
             "attributes": "0000000000000000",
             "attributesMask": "FFFFFFFFFFFFFFFF",
             "tcbLevels": [{"tcb": {"isvsvn": 5},
                            "tcbDate": "2025-08-13T00:00:00Z",
                            "tcbStatus": "UpToDate"}]},
        ],
    }
    result = tcb.evaluate_tdx_module(
        doc, tee_tcb_svn=_svn(5, 3),
        mrsignerseam=bytes.fromhex(identity_signer),
        seam_attributes=bytes(8))
    assert result["status"] == "UpToDate"

    with pytest.raises(tcb.TdxModuleRejected):
        tcb.evaluate_tdx_module(
            doc, tee_tcb_svn=_svn(5, 3),
            mrsignerseam=bytes.fromhex(_TDX_MODULE_MRSIGNER),
            seam_attributes=bytes(8))


# -- fail-closed on a document that cannot support the check ----------------

def test_a_tcb_info_without_tdx_module_is_refused(tcb):
    """Documented policy: refuse.

    Every FMSPC for which Intel serves TDX collateral carries tdxModule
    (16 of the 39 in /sgx/certification/v4/fmspcs, checked 2026-08-20; the
    other 23 return 404 for the TDX endpoint and never reach this code), so
    refusing cannot fire on a legitimate platform -- while allowing would mean
    a SEAM module signed by anybody at all goes unnoticed.
    """
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate_tdx_module({"version": 3}, tee_tcb_svn=_svn(5, 3),
                                mrsignerseam=bytes(48),
                                seam_attributes=bytes(8))
    assert "tdxModule" in str(exc.value)


def test_a_tcb_info_without_identities_is_refused_when_a_version_needs_one(
        tcb):
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate_tdx_module({"version": 3, "tdxModule": _tdx_module()},
                                tee_tcb_svn=_svn(5, 3),
                                mrsignerseam=bytes(48),
                                seam_attributes=bytes(8))
    assert "tdxModuleIdentities" in str(exc.value)


def test_identities_are_not_required_when_the_module_version_is_zero(tcb):
    """Version 0 selects no identity, so Intel publishes no module status.

    Matching ``tdxEvaluateTCB``, which only consults tdxModuleIdentities when
    TEE_TCB_SVN[1] > 0.  Refusing here would reject a platform Intel accepts.
    """
    result = tcb.evaluate_tdx_module(
        {"version": 3, "tdxModule": _tdx_module()}, tee_tcb_svn=_svn(9, 0),
        mrsignerseam=bytes(48), seam_attributes=bytes(8))
    assert result["status"] == ""
    assert result["identity_id"] == ""
    assert result["matched_isvsvn"] is None


def test_a_pre_v3_tcb_info_is_refused_for_the_module_check(tcb):
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate_tdx_module({"version": 2, "tdxModule": _tdx_module()},
                                tee_tcb_svn=_svn(5, 3),
                                mrsignerseam=bytes(48),
                                seam_attributes=bytes(8))
    assert "v3" in str(exc.value)


def test_a_duplicated_identity_id_is_refused(tcb):
    identities = _tdx_module_identities()
    identities.append(dict(identities[0]))
    doc = {"version": 3, "tdxModule": _tdx_module(),
           "tdxModuleIdentities": identities}
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate_tdx_module(doc, tee_tcb_svn=_svn(5, 3),
                                mrsignerseam=bytes(48),
                                seam_attributes=bytes(8))
    assert "more than once" in str(exc.value)


def test_an_unknown_module_level_status_is_refused(tcb):
    identities = _tdx_module_identities()
    identities[0]["tcbLevels"][0]["tcbStatus"] = "ConfigurationNeeded"
    doc = {"version": 3, "tdxModule": _tdx_module(),
           "tdxModuleIdentities": identities}
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate_tdx_module(doc, tee_tcb_svn=_svn(5, 3),
                                mrsignerseam=bytes(48),
                                seam_attributes=bytes(8))
    assert "ConfigurationNeeded" in str(exc.value)


def test_an_identity_without_a_mrsigner_is_refused(tcb):
    identities = _tdx_module_identities()
    del identities[0]["mrsigner"]
    doc = {"version": 3, "tdxModule": _tdx_module(),
           "tdxModuleIdentities": identities}
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate_tdx_module(doc, tee_tcb_svn=_svn(5, 3),
                                mrsignerseam=bytes(48),
                                seam_attributes=bytes(8))
    assert "mrsigner" in str(exc.value)


# -- convergence ------------------------------------------------------------

@pytest.mark.parametrize("platform,module,expected", [
    ("UpToDate", "", "UpToDate"),
    ("UpToDate", "UpToDate", "UpToDate"),
    ("UpToDate", "OutOfDate", "OutOfDate"),
    ("SWHardeningNeeded", "OutOfDate", "OutOfDate"),
    ("ConfigurationNeeded", "OutOfDate", "OutOfDateConfigurationNeeded"),
    ("ConfigurationAndSWHardeningNeeded", "OutOfDate",
     "OutOfDateConfigurationNeeded"),
    ("OutOfDate", "OutOfDate", "OutOfDate"),
    ("UpToDate", "Revoked", "Revoked"),
    ("ConfigurationNeeded", "Revoked", "Revoked"),
    ("SWHardeningNeeded", "UpToDate", "SWHardeningNeeded"),
])
def test_module_status_converges_into_the_platform_status(tcb, platform,
                                                         module, expected):
    assert tcb.converge_tdx_module_status(platform, module) == expected


# -- end to end, through evaluate() ----------------------------------------

def test_tdx_module_is_evaluated_end_to_end(tcb, world, cert_checks,
                                            tmp_path):
    path = world.write_bundle(tmp_path, tee="tdx")
    result = tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="tdx"))
    assert result["tcb_status"] == "UpToDate"
    assert result["platform_tcb_status"] == "UpToDate"
    assert result["tdx_module"]["identity_id"] == "TDX_03"
    assert result["tdx_module"]["status"] == "UpToDate"


def test_a_tampered_mrsignerseam_is_rejected_end_to_end(tcb, world,
                                                        cert_checks,
                                                        tmp_path):
    path = world.write_bundle(tmp_path, tee="tdx")
    forged = bytes.fromhex("de" * 48)
    with pytest.raises(tcb.TdxModuleRejected) as exc:
        tcb.evaluate(**_kwargs(
            tcb, world, cert_checks, path, tee="tdx",
            td_report_body=build_td_report_body(mrsignerseam=forged)))
    assert "de" * 48 in str(exc.value)


def test_an_out_of_date_tdx_module_rejects_an_up_to_date_platform(
        tcb, world, cert_checks, tmp_path):
    """The check that actually buys something beyond matching a signer.

    The platform level here is UpToDate on its own terms; only the module is
    behind.  Without convergence this quote would be accepted.
    """
    levels = [_level([5] * 16, _PLATFORM_PCESVN, "UpToDate",
                     tdx=[3, 0] + [0] * 14)]
    path = world.write_bundle(
        tmp_path, tee="tdx",
        tcb_info_body=world.tcb_info_body(tee="tdx", levels=levels))
    with pytest.raises(tcb.TcbStatusRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="tdx",
                               tee_tcb_svn=_svn(3, 3)))
    message = str(exc.value)
    assert "'OutOfDate'" in message
    assert "TDX_03" in message
    assert "platform's own level is 'UpToDate'" in message


def test_an_out_of_date_module_is_refused_even_with_an_allow_status_policy(
        tcb, world, cert_checks, tmp_path):
    """ConfigurationNeeded + OutOfDate module = OutOfDateConfigurationNeeded.

    Which is in NEVER_ALLOWED_STATUSES, so no ``TEE_CRAFTER_TCB_ALLOW_STATUS``
    setting can bring it back.
    """
    levels = [_level([5] * 16, _PLATFORM_PCESVN, "ConfigurationNeeded",
                     tdx=[3, 0] + [0] * 14)]
    path = world.write_bundle(
        tmp_path, tee="tdx",
        tcb_info_body=world.tcb_info_body(tee="tdx", levels=levels))
    with pytest.raises(tcb.TcbStatusRejected) as exc:
        tcb.evaluate(**_kwargs(
            tcb, world, cert_checks, path, tee="tdx",
            tee_tcb_svn=_svn(3, 3),
            allowed_statuses=frozenset({"UpToDate", "ConfigurationNeeded",
                                        "OutOfDateConfigurationNeeded"})))
    assert "OutOfDateConfigurationNeeded" in str(exc.value)


def test_a_revoked_tdx_module_is_rejected(tcb, world, cert_checks, tmp_path):
    identities = _tdx_module_identities()
    identities[0]["tcbLevels"][0]["tcbStatus"] = "Revoked"
    path = world.write_bundle(
        tmp_path, tee="tdx",
        tcb_info_body=world.tcb_info_body(tee="tdx",
                                          tdx_module_identities=identities))
    with pytest.raises(tcb.TcbStatusRejected) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="tdx"))
    assert "Revoked" in str(exc.value)


def test_a_tdx_bundle_without_tdx_module_is_refused_end_to_end(
        tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(
        tmp_path, tee="tdx",
        tcb_info_body=world.tcb_info_body(tee="tdx", tdx_module=None,
                                          tdx_module_identities=None))
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="tdx"))
    assert "tdxModule" in str(exc.value)


def test_tdx_evaluation_without_a_td_report_body_is_refused_end_to_end(
        tcb, world, cert_checks, tmp_path):
    """A client that forgets to plumb it through must fail, not skip."""
    path = world.write_bundle(tmp_path, tee="tdx")
    with pytest.raises(tcb.CollateralMalformed) as exc:
        tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="tdx",
                               td_report_body=b""))
    assert "td_report_body=quote_bytes[48:632]" in str(exc.value)


def test_sgx_evaluation_needs_no_tdx_module_and_no_td_report_body(
        tcb, world, cert_checks, tmp_path):
    """No SGX regression: tdxModule is TDX-only.

    The SGX TCBInfo the world builds carries neither tdxModule nor
    tdxModuleIdentities, and no TD report body is passed.
    """
    path = world.write_bundle(tmp_path, tee="sgx")
    result = tcb.evaluate(**_kwargs(tcb, world, cert_checks, path, tee="sgx"))
    assert result["tcb_status"] == "UpToDate"
    assert result["tdx_module"] is None
    assert result["platform_tcb_status"] == "UpToDate"


def test_enforce_reports_the_tdx_module(tcb, world, cert_checks, tmp_path):
    path = world.write_bundle(tmp_path, tee="tdx")
    stream = io.StringIO()
    tcb.enforce(**_kwargs(tcb, world, cert_checks, path, tee="tdx"),
                stream=stream)
    out = stream.getvalue()
    assert "TDX module:" in out
    assert "TDX_03" in out
    assert "PASSED" in out
