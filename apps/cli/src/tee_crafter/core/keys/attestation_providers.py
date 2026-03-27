"""Concrete :class:`AttestationProvider` implementations per TEE platform.

The :class:`~tee_crafter.core.keys.release.KeyReleaseOrchestrator` only needs a
thin ``fresh(purpose, nonce) -> (blob, issued_at, measurement_sha256)`` hook.
Until now only an ABC existed (``release.py``) plus stubs in tests, so the
in-TEE secret bootstrap had no real provider to gate releases with.  These
classes read the live platform report on the *host* (the CVM secrets oneshot
runs there with ``/dev/sev-guest`` / configfs-tsm access) and return:

* ``blob``               -- the raw attestation report (binds ``nonce`` in
                            REPORT_DATA so the KMS/HSM request cannot be
                            replayed);
* ``issued_at``          -- wall-clock capture time (freshness gate);
* ``measurement_sha256`` -- ``SHA-256(MEASUREMENT)`` (SNP) / ``SHA-256(MRTD)``
                            (TDX), the canonical allowlist value used by the
                            release policy and matched against the bake-time
                            pinned measurement.

Each reader is injectable (``report_reader``) so the policy/measurement logic
is unit-testable without a live TEE; the default readers touch the real device
nodes and therefore only succeed inside a genuine enclave/CVM.
"""
from __future__ import annotations

import hashlib
import os
import struct
import time
from typing import Callable, Optional, Tuple

from tee_crafter.core.keys.release import AttestationProvider
from tee_crafter.core.measurements.capture import (
    parse_snp_measurement,
    parse_tdx_mrtd,
)

# Raw-report reader signature: nonce_bytes -> report_bytes.
ReportReader = Callable[[bytes], bytes]


# --------------------------------------------------------------------------
# Intel TDX: where MRTD lives
# --------------------------------------------------------------------------
# There is no single "the" MRTD offset, which is why three different numbers
# were floating around this repo.  MRTD is a 48-byte SHA-384 whose position
# depends on which *container* you were handed, and there are two:
#
# 1. TDREPORT_STRUCT (1024 bytes) -- what TDCALL[TDG.MR.REPORT] returns, and
#    what Azure wraps in its HCLA blob.  Layout per the Intel TDX Module ABI
#    spec:
#        0   REPORTMACSTRUCT   256 bytes
#      256   TEE_TCB_INFO      256 bytes (239 used + 17 reserved)
#      512   TDINFO_STRUCT     512 bytes
#    and inside TDINFO_STRUCT:
#        0   ATTRIBUTES          8
#        8   XFAM                8
#       16   MRTD               48   <-- 512 + 16 = 528 absolute
#       64   MRCONFIGID         48
#    => MRTD at 528.  Azure prefixes a 32-byte HCLA header, hence 32 + 528.
#
# 2. TD Quote v4 (DCAP) -- what configfs-tsm's `outblob` and the Intel Quote
#    Generation Service return.  Layout:
#        0   Quote Header       48 bytes (version u16, att_key_type u16,
#                                         tee_type u32 == 0x81 for TDX, ...)
#       48   TD Quote Body     584 bytes:
#              +0    TEE_TCB_SVN        16
#             +16    MRSEAM             48
#             +64    MRSIGNERSEAM       48
#            +112    SEAMATTRIBUTES      8
#            +120    TDATTRIBUTES        8
#            +128    XFAM                8
#            +136    MRTD               48   <-- 48 + 136 = 184 absolute
#            +184    MRCONFIGID         48
#    => MRTD at 184.
#
# The previous default here, 0x130 (304), matches neither container.  It is not
# a boundary in either layout, so BYOK / sealed-.env could never have succeeded
# on any TDX platform.  Both correct values are corroborated inside this repo:
# templates/tdx/azure/client.template.py:353-361 documents the TDREPORT layout
# (mrtd at 528) and templates/tdx/azure/app.template.py:432-443 implements both
# branches; core/measurements/capture.py:54 uses 48 + 136 for the quote.
#
# `_read_tdx_report` below reads configfs-tsm `outblob`, which the Linux
# tdx-guest TSM provider fills with a TD Quote -- so the quote offset is the
# right default.  Rather than trust that, :func:`detect_tdx_mrtd_offset` sniffs
# the container and picks, so a platform that hands us a raw TDREPORT (or an
# Azure HCLA blob) still parses correctly instead of silently hashing the wrong
# 48 bytes.

#: MRTD offset inside a TD Quote v4 (48-byte header + 136 into the body).
TDX_QUOTE_MRTD_OFFSET = 48 + 136  # 184

#: MRTD offset inside a bare 1024-byte TDREPORT_STRUCT (TDINFO at 512, +16).
TDX_TDREPORT_MRTD_OFFSET = 512 + 16  # 528

#: MRTD offset inside an Azure HCLA blob (32-byte header, then the TDREPORT).
TDX_AZURE_HCLA_MRTD_OFFSET = 32 + TDX_TDREPORT_MRTD_OFFSET  # 560

#: Size of a TDREPORT_STRUCT, used to recognise a bare report.
TDX_TDREPORT_SIZE = 1024

#: ``tee_type`` value identifying TDX in a TD Quote header.
_TDX_QUOTE_TEE_TYPE = 0x00000081

#: Quote header ``version`` values we know how to offset into.
_TDX_QUOTE_VERSIONS = (4, 5)


def detect_tdx_mrtd_offset(report: bytes) -> int:
    """Return the MRTD offset for whichever TDX container *report* is.

    Recognises, in order: an Azure HCLA blob (``b"HCLA"`` magic), a TD Quote v4
    (header ``version`` 4/5 and ``tee_type`` 0x81), and a bare 1024-byte
    TDREPORT_STRUCT.  Raises :class:`ValueError` rather than guessing --
    hashing the wrong 48 bytes yields a plausible-looking measurement that
    silently never matches the allowlist, which is worse than a hard failure.
    """
    if len(report) >= 4 and report[:4] == b"HCLA":
        return TDX_AZURE_HCLA_MRTD_OFFSET
    if len(report) >= 8:
        version, _att_key_type, tee_type = struct.unpack_from("<HHI", report, 0)
        if version in _TDX_QUOTE_VERSIONS and tee_type == _TDX_QUOTE_TEE_TYPE:
            return TDX_QUOTE_MRTD_OFFSET
    if len(report) == TDX_TDREPORT_SIZE:
        return TDX_TDREPORT_MRTD_OFFSET
    raise ValueError(
        f"unrecognised TDX attestation container ({len(report)} bytes; "
        f"first 8 = {report[:8].hex()}).  Expected an Azure HCLA blob, a TD "
        f"Quote v4/v5, or a 1024-byte TDREPORT_STRUCT.  Pass an explicit "
        f"mrtd_offset to TdxAttestationProvider if your platform frames it "
        f"differently.")


# --------------------------------------------------------------------------
# Default device readers (only work inside a real TEE; replaced in tests).
# --------------------------------------------------------------------------

def _read_snp_report(nonce: bytes) -> bytes:
    """Read a SEV-SNP attestation report from ``/dev/sev-guest``.

    ``nonce`` (<=64 bytes) is placed in REPORT_DATA so the report is bound to
    this specific release request.
    """
    import ctypes
    import fcntl

    SNP_GET_REPORT = 0xC0205300  # _IOWR('S', 0, snp_guest_request_ioctl)

    class _ReportReq(ctypes.Structure):
        _fields_ = [("user_data", ctypes.c_uint8 * 64),
                    ("vmpl", ctypes.c_uint32),
                    ("rsvd", ctypes.c_uint8 * 28)]

    class _ReportResp(ctypes.Structure):
        _fields_ = [("data", ctypes.c_uint8 * 4000)]

    class _GuestReq(ctypes.Structure):
        _fields_ = [("msg_version", ctypes.c_uint8),
                    ("req_data", ctypes.c_uint64),
                    ("resp_data", ctypes.c_uint64),
                    ("fw_err", ctypes.c_uint64)]

    req = _ReportReq()
    nb = (nonce or b"")[:64]
    for i, byte in enumerate(nb):
        req.user_data[i] = byte
    resp = _ReportResp()
    g = _GuestReq()
    g.msg_version = 1
    g.req_data = ctypes.addressof(req)
    g.resp_data = ctypes.addressof(resp)
    with open("/dev/sev-guest", "rb") as fh:
        fcntl.ioctl(fh, SNP_GET_REPORT, g)
    blob = bytes(resp.data)
    # 32-byte response header precedes the 1184-byte report.
    return blob[32:32 + 1184]


def _read_tdx_report(nonce: bytes) -> bytes:
    """Read a TDX quote via configfs-tsm.

    Writes ``nonce`` into ``inblob`` and reads back ``outblob``.  The Linux
    ``tdx-guest`` TSM provider fills ``outblob`` with a **TD Quote v4**, not a
    bare TDREPORT -- see :data:`TDX_QUOTE_MRTD_OFFSET`.  The caller sniffs the
    container anyway rather than relying on that.  Best-effort: raises on any
    platform where the configfs-tsm path is absent.
    """
    import glob
    import os

    base = "/sys/kernel/config/tsm/report"
    # configfs-tsm requires creating an entry dir; reuse one if present.
    entries = sorted(glob.glob(os.path.join(base, "*")))
    entry = entries[0] if entries else None
    created = False
    if entry is None:
        entry = os.path.join(base, "tee-crafter")
        os.makedirs(entry, exist_ok=True)
        created = True
    try:
        with open(os.path.join(entry, "inblob"), "wb") as fh:
            fh.write((nonce or b"").ljust(64, b"\x00")[:64])
        with open(os.path.join(entry, "outblob"), "rb") as fh:
            return fh.read()
    finally:
        if created:
            try:
                os.rmdir(entry)
            except OSError:
                pass


# --------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------

class SnpAttestationProvider(AttestationProvider):
    """AMD SEV-SNP host-side attestation provider."""

    def __init__(self, report_reader: Optional[ReportReader] = None,
                 clock: Callable[[], float] = time.time):
        self._read = report_reader or _read_snp_report
        self._clock = clock

    def fresh(self, *, purpose: str, nonce: bytes = b"") -> Tuple[bytes, float, str]:
        report = self._read(nonce)
        measurement = parse_snp_measurement(report)
        meas_sha = hashlib.sha256(bytes.fromhex(measurement)).hexdigest()
        return report, self._clock(), meas_sha


class TdxAttestationProvider(AttestationProvider):
    """Intel TDX host-side attestation provider.

    ``mrtd_offset`` defaults to ``None``, meaning "sniff the container" via
    :func:`detect_tdx_mrtd_offset`.  Pass an explicit offset only to override
    detection on a platform that frames the report unusually.
    """

    def __init__(self, report_reader: Optional[ReportReader] = None,
                 clock: Callable[[], float] = time.time,
                 mrtd_offset: Optional[int] = None):
        self._read = report_reader or _read_tdx_report
        self._clock = clock
        self._mrtd_offset = mrtd_offset

    def fresh(self, *, purpose: str, nonce: bytes = b"") -> Tuple[bytes, float, str]:
        report = self._read(nonce)
        offset = (self._mrtd_offset if self._mrtd_offset is not None
                  else detect_tdx_mrtd_offset(report))
        mrtd = parse_tdx_mrtd(report, offset=offset)
        meas_sha = hashlib.sha256(bytes.fromhex(mrtd)).hexdigest()
        return report, self._clock(), meas_sha


#: Azure's HCL (Hyper-V Compatibility Layer) report framing in vTPM NV index
#: 0x01400001: a 32-byte header whose magic is ``HCLA``, then the standard
#: 1184-byte AMD SNP report.  Same constants as ``SNP_VTPM_HCL_SNIPPET`` in
#: core/measurements/capture.py and ``_get_snp_report_via_vtpm`` in
#: templates/snp/azure/app.template.py, so capture, runtime and key release all
#: read the identical bytes.
_HCL_HEADER_SIZE = 32
_HCL_MAGIC = b"HCLA"
_SNP_REPORT_SIZE = 1184
_AZURE_HCL_NV_INDEX = "0x01400001"


def _read_snp_report_vtpm(nonce: bytes) -> bytes:
    """Read a SEV-SNP report on an **Azure** CVM, via the vTPM.

    Azure SEV-SNP CVMs do not expose ``/dev/sev-guest`` -- that is the KVM
    guest driver, and under Hyper-V it is simply absent.  Verified on hardware
    on 2026-08-23: a live ``Standard_DC2as_v5`` has ``/dev/tpm0`` and
    ``/dev/tpmrm0`` and neither ``/dev/sev-guest`` nor ``/dev/sev``.  So
    :func:`_read_snp_report` raised ``FileNotFoundError`` for every BYOK
    release on this platform, which the orchestrator surfaced as
    "attestation provider failed" and then correctly failed closed -- meaning
    ``--byok`` could never succeed on ``snp-azure`` or ``gpu-cc-azure``.

    **``nonce`` cannot be honoured here, and that is a real limitation.** The
    HCL report is pre-minted by the host, so its REPORT_DATA is fixed and no
    guest-supplied challenge can appear in it.  The report is therefore not
    proof of freshness by itself.  It is still the right input for the
    orchestrator's two in-process checks (age, measurement allowlist), and the
    evidence that actually gates the release is minted separately and *is*
    nonce-bound: ``AzureAttestSKR`` obtains its own MAA token, and Key Vault
    evaluates the key's release policy against that token before releasing
    anything.  See core/keys/azure_skr_tool.py.
    """
    import subprocess

    res = subprocess.run(
        ["tpm2_nvread", _AZURE_HCL_NV_INDEX, "-C", "o", "-s", "2600"],
        capture_output=True, timeout=30,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"tpm2_nvread {_AZURE_HCL_NV_INDEX} failed: "
            + res.stderr.decode(errors="replace").strip()[:300])
    hcl = res.stdout
    need = _HCL_HEADER_SIZE + _SNP_REPORT_SIZE
    if len(hcl) < need:
        raise RuntimeError(
            f"HCL report too small: {len(hcl)} bytes (need {need})")
    if hcl[:4] != _HCL_MAGIC:
        raise RuntimeError(f"bad HCL magic: {hcl[:4].hex()}")
    report = hcl[_HCL_HEADER_SIZE:_HCL_HEADER_SIZE + _SNP_REPORT_SIZE]
    version = struct.unpack_from("<I", report, 0)[0]
    if version < 2:
        raise RuntimeError(f"unexpected SNP report version: {version}")
    return report


class AzureSnpAttestationProvider(SnpAttestationProvider):
    """SEV-SNP provider for Azure CVMs: same parsing, vTPM-sourced report."""

    def __init__(self, report_reader=None, clock=time.time):
        super().__init__(report_reader=report_reader or _read_snp_report_vtpm,
                         clock=clock)


#: Map tee_platform -> the provider class that reads its report.
_PROVIDER_BY_PLATFORM = {
    "snp-aws": SnpAttestationProvider,
    "snp-azure": AzureSnpAttestationProvider,
    "snp-gcp": SnpAttestationProvider,
    "gpu-cc-aws": SnpAttestationProvider,
    "gpu-cc-azure": AzureSnpAttestationProvider,
    "tdx-azure": TdxAttestationProvider,
    "tdx-gcp": TdxAttestationProvider,
    "gpu-cc-gcp": TdxAttestationProvider,
}


#: Platforms where an ``aws_nitrotpm_recipient`` unwrap selects the NitroTPM
#: provider instead of the SEV-SNP one. Mirrors
#: ``cli.commands.deploy.byok_mode._NITROTPM_CAPABLE_PLATFORMS``.
_NITROTPM_UNWRAP_PLATFORMS = frozenset({"snp-aws", "gpu-cc-aws"})


def build_for_platform(
    tee_platform: str,
    *,
    report_reader: Optional[ReportReader] = None,
    unwrap: str = "",
) -> AttestationProvider:
    """Return the concrete provider for ``tee_platform``.

    ``report_reader`` is forwarded for tests/stubs.  Nitro is handled by the
    in-enclave NSM path (``aws_nitro_recipient`` unwrap) and is intentionally
    not built here; raises ``ValueError`` for unknown / non-CVM platforms.

    **The unwrap mode can change which provider is right.** On ``snp-aws`` and
    ``gpu-cc-aws``, ``unwrap=aws_nitrotpm_recipient`` means KMS is going to
    evaluate a NitroTPM attestation document, so the provider has to produce one
    -- an SEV-SNP report is not what ``kms:Decrypt``'s ``Recipient`` parameter
    accepts, and handing one over would fail the release rather than degrade it.
    The mode is read from ``TEE_CRAFTER_BYOK_UNWRAP``, the same variable the
    runtime bootstrap uses to build the key reference, so the two cannot
    disagree.
    """
    if (tee_platform in _NITROTPM_UNWRAP_PLATFORMS
            and (unwrap or os.environ.get("TEE_CRAFTER_BYOK_UNWRAP", ""))
            == "aws_nitrotpm_recipient"):
        return NitroTpmAttestationProvider()

    cls = _PROVIDER_BY_PLATFORM.get(tee_platform)
    if cls is None:
        raise ValueError(
            f"no host-side attestation provider for platform {tee_platform!r}")
    if report_reader is not None:
        return cls(report_reader=report_reader)
    return cls()


class NitroTpmAttestationProvider(AttestationProvider):
    """AWS NitroTPM provider, for measurement-gated ``kms:Decrypt`` on a CVM.

    It returns a NitroTPM attestation document signed by the Nitro Hypervisor.
    For *key release* the verifier is AWS KMS, which evaluates the document
    against ``kms:RecipientAttestation:NitroTPMPCR<n>`` conditions before it
    will decrypt -- that is the point of this provider.

    An earlier version of this docstring added that the document could *only*
    be verified that way, because ``certs/nitro-root.pem`` is the Nitro
    *Enclaves* root and "a different key hierarchy".  That was wrong.  Measured
    2026-08-24 against a real document: the ``cabundle`` roots at
    ``CN=aws.nitro-enclaves``, byte-for-byte the certificate this repository
    already pins, and the chain plus the COSE_Sign1 signature verify locally.
    See :func:`tee_crafter.core.keys.nitrotpm.verify_document_locally`, which is
    what ``gpu-cc-aws`` uses to verify CPU evidence client-side.

    Two consequences that make this class shaped differently from its siblings:

    * **It owns an RSA keypair.**  The public half goes inside the document and
      KMS encrypts its response to it, so the same object has to be available
      afterwards to unwrap ``CiphertextForRecipient``.  Hence
      :attr:`recipient_private_key`.
    * **The nonce is not bound.**  AWS documents ``nitro-tpm-attest``'s
      ``--nonce`` and ``--user-data`` as "Not used for attestation with AWS
      KMS", so passing a nonce would imply a freshness binding KMS does not
      enforce.  What replaces it is the keypair: the response is encrypted to a
      key generated in this process, so a replayed document cannot be paired
      with a plaintext anyone else can read.  Freshness therefore comes from
      possession, not from a challenge.

    ``measurement_sha256`` is ``SHA-256(PCR4 || PCR7)`` read locally with
    ``tpm2_pcrread``, and it is **advisory**: it feeds the release policy's
    allowlist, but the enforcing check is the one KMS performs against the
    signed document.  Reading it locally rather than parsing the document's CBOR
    keeps this class free of a CBOR dependency the baked image would otherwise
    need.
    """

    #: PCRs folded into the advisory measurement, matching
    #: ``core.keys.nitrotpm.DEFAULT_PINNED_PCRS``.
    MEASURED_PCRS: Tuple[int, ...] = (4, 7)

    def __init__(self, document_reader=None,
                 pcr_reader=None,
                 clock: Callable[[], float] = time.time,
                 key_size: int = 2048):
        self._document_reader = document_reader
        self._pcr_reader = pcr_reader
        self._clock = clock
        self._key_size = key_size
        self._private_key = None
        self._public_der = b""

    @property
    def recipient_private_key(self):
        """The RSA private half whose public key is inside the document.

        ``None`` until :meth:`fresh` has run: the keypair is generated with the
        document so that a caller cannot unwrap a response for a document this
        provider never issued.
        """
        return self._private_key

    def _ensure_keypair(self):
        if self._private_key is None:
            from tee_crafter.core.keys.nitrotpm import (
                generate_recipient_keypair,
            )
            self._private_key, self._public_der = generate_recipient_keypair(
                self._key_size)
        return self._public_der

    def _read_pcrs(self):
        if self._pcr_reader is not None:
            return self._pcr_reader(self.MEASURED_PCRS)
        from tee_crafter.core.keys.nitrotpm import read_pcrs
        return read_pcrs(self.MEASURED_PCRS)

    def fresh(self, *, purpose: str, nonce: bytes = b"") -> Tuple[bytes, float, str]:
        public_der = self._ensure_keypair()
        if self._document_reader is not None:
            document = self._document_reader(public_der)
        else:
            from tee_crafter.core.keys.nitrotpm import attestation_document
            document = attestation_document(public_der)

        # Advisory only -- see the class docstring. A failure to read PCRs must
        # not stop a release that KMS is about to gate properly anyway, so this
        # degrades to an empty measurement rather than raising.
        try:
            pcrs = self._read_pcrs()
            joined = b"".join(
                bytes.fromhex(pcrs[str(p)]) for p in self.MEASURED_PCRS)
            measurement_sha = hashlib.sha256(joined).hexdigest()
        except Exception:
            measurement_sha = ""

        return document, self._clock(), measurement_sha
