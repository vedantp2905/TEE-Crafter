"""Read a TEE launch measurement from a freshly baked image.

``bake-ami`` boots a throwaway instance from the just-created image (with the
TEE enabled) and runs one of the snippets below over the cloud's remote-exec
channel (SSM / Bastion / IAP).  The snippet prints a single stable line::

    TEE_CRAFTER_MEASUREMENT=<hex>

which :func:`parse_measurement_line` extracts and the caller hands to
:func:`tee_crafter.core.measurements.registry.store`.

The pure parsers (:func:`parse_snp_measurement`, :func:`parse_tdx_mrtd`) are
unit-tested against synthetic reports; the on-instance snippets are emitted as
strings (also test-asserted) so the capture logic is verifiable without a live
TEE.  Reading the report on the instance — rather than recomputing the digest
on the build host — is what makes the captured baseline trustworthy: it is the
firmware's own measurement of the booted image.
"""
from __future__ import annotations

import re
from typing import Optional

# --- AMD SEV-SNP report layout (subset; mirrors the app templates) ----------
_SNP_REPORT_SIZE = 1184
_SNP_OFF_MEASUREMENT = 0x90  # 48-byte SHA-384 launch digest
_SNP_MEASUREMENT_LEN = 48

# --- Intel TDX TDREPORT layout (subset) -------------------------------------
# MRTD is a 48-byte SHA-384 in the TDREPORT's TDINFO structure.  For the
# Azure/GCP vTPM-wrapped or configfs-tsm quote we read MRTD from the parsed
# report the platform tool emits; the snippet normalises it to the hex line.

_MEASUREMENT_LINE_RE = re.compile(
    r"TEE_CRAFTER_MEASUREMENT=([0-9a-fA-F]{32,128})"
)

#: The measuring VM reports its own CPU model, because the CPU generation
#: cannot be inferred from the instance type on every cloud.  Azure schedules
#: ``Standard_DCxas_v5`` on Milan *or* Genoa hosts, so a generation label
#: derived from the ``v5``/``v6`` suffix is a guess: a live ``Standard_DC2as_v5``
#: validated its VCEK against the **Genoa** chain while the suffix says Milan.
#: That matters beyond labelling, because the SEV-SNP launch measurement
#: depends on the host firmware: two probes of the same instance type can
#: legitimately return different digests, and attributing that to the vCPU tier
#: rather than to the host generation produces an allowlist that is missing a
#: digest the platform can genuinely present.
_CPU_MODEL_LINE_RE = re.compile(r"TEE_CRAFTER_CPU_MODEL=(.+)")

#: AMD EPYC model token → generation.  The token is not always four digits:
#: the clouds ship custom SKUs whose model carries a letter (``EPYC 7V13`` is
#: the Milan part Azure reports, ``EPYC 9V84`` a Genoa one), so this reads the
#: leading series digit and the trailing generation digit rather than matching
#: a four-digit number.  9xxx is Genoa-class; otherwise the last digit is the
#: generation (7xx2 Rome, 7xx3 Milan).
_EPYC_MODEL_RE = re.compile(r"epyc\s+([0-9][0-9a-z]*)", re.IGNORECASE)
_EPYC_GEN_BY_LAST_DIGIT = {"2": "rome", "3": "milan", "4": "genoa"}

#: Shell prepended to every capture command.  Printed *before* the readers run,
#: because they exit as soon as one succeeds — appended, it would not run.
_CPU_MODEL_PROBE = (
    "echo \"TEE_CRAFTER_CPU_MODEL=$(sed -n "
    "'s/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1)\"\n"
)


#: Read the NitroTPM measured-boot registers alongside the launch measurement.
#:
#: Folded into the SNP capture rather than given its own throwaway VM, because
#: the VM this runs on is already booted from the image being measured and each
#: extra probe VM is a real instance-hour. PCR4 is the boot manager code and
#: PCR7 the Secure Boot policy -- the two AWS KMS conditions this project pins
#: (see ``core/keys/nitrotpm.py``).
#:
#: ``|| true`` throughout: on a host with no TPM, or an AMI registered without
#: ``TpmSupport``, this prints nothing and the launch-measurement capture must
#: still succeed. An absent PCR is a missing optional capability, not a failure.
_NITROTPM_PCR_PROBE = (
    "( command -v tpm2_pcrread >/dev/null 2>&1 && "
    "tpm2_pcrread sha384:4,7 2>/dev/null | "
    "sed -n 's/^[[:space:]]*\\([47]\\)[[:space:]]*:[[:space:]]*0[xX]\\(.*\\)$/"
    "TEE_CRAFTER_PCR\\1=\\2/p' ) || true\n"
)

#: ``TEE_CRAFTER_PCR4=<hex>`` / ``TEE_CRAFTER_PCR7=<hex>``.
_NITROTPM_PCR_LINE_RE = re.compile(r"TEE_CRAFTER_PCR([0-9]{1,2})=([0-9a-fA-F]+)")


#: vTPM PCR probe for ``gpu-cc-gcp``, whose RA-TLS certificate publishes a
#: PCR bundle that its client compares against a pinned set (``verify_vtpm_pcrs``
#: fails closed when nothing is pinned, so without this capture the platform
#: cannot deploy without an explicit opt-out).
#:
#: ``sha256`` here, unlike the NitroTPM probe's ``sha384``: this is a GCP vTPM,
#: and the server reads the same bank (``_get_vtpm_pcrs`` in
#: ``templates/gpu_cc/gcp/app.template.py``). Comparing across banks would fail
#: every time.
#:
#: Emitted under a distinct prefix from ``TEE_CRAFTER_PCR<n>`` so a transcript
#: that happens to contain both cannot be cross-parsed.
_VTPM_PCR_PROBE = (
    "( command -v tpm2_pcrread >/dev/null 2>&1 && "
    "tpm2_pcrread sha256:0,1,2,3,4,5,6,7 2>/dev/null | "
    "sed -n 's/^[[:space:]]*\\([0-7]\\)[[:space:]]*:[[:space:]]*0[xX]\\(.*\\)$/"
    "TEE_CRAFTER_VTPM_PCR\\1=\\2/p' ) || true\n"
)

_VTPM_PCR_LINE_RE = re.compile(r"TEE_CRAFTER_VTPM_PCR([0-7])=([0-9a-fA-F]+)")


def parse_vtpm_pcrs(text: str) -> dict:
    """Return ``{"0": "<hex>", ...}`` of vTPM PCRs from a capture transcript."""
    out = {}
    for match in _VTPM_PCR_LINE_RE.finditer(text or ""):
        out[match.group(1)] = match.group(2).lower()
    return out


def nitrotpm_pcr_command() -> str:
    """Just the NitroTPM PCR probe, with nothing else attached.

    ``snp_capture_command`` prepends the same probe to a SEV-SNP report read,
    which is right for ``snp-aws``.  ``gpu-cc-aws`` has no launch measurement to
    read at all -- its CPU evidence *is* measured boot -- so it needs the probe
    on its own rather than bundled with a report reader that would find no
    ``/dev/sev-guest``.
    """
    return _NITROTPM_PCR_PROBE


def parse_nitrotpm_pcrs(text: str) -> dict:
    """Return ``{"4": "<hex>", "7": "<hex>"}`` from a capture transcript.

    Empty dict when the instance reported none, which is the expected result on
    an AMI that was never registered with ``TpmSupport=v2.0``.
    """
    out = {}
    for match in _NITROTPM_PCR_LINE_RE.finditer(text or ""):
        out[match.group(1)] = match.group(2).lower()
    return out


def parse_cpu_model_line(text: str) -> Optional[str]:
    """Return the CPU model string the measuring instance reported, if any."""
    if not text:
        return None
    m = _CPU_MODEL_LINE_RE.search(text)
    return m.group(1).strip() or None if m else None


def gen_from_cpu_model(cpu_model: Optional[str]) -> Optional[str]:
    """Map a reported CPU model to an AMD generation, or ``None``.

    ``None`` on anything unrecognised, deliberately: a guessed label is
    indistinguishable from an observed one, which is the exact failure this
    function exists to remove.  A caller that gets ``None`` must record no
    generation rather than fall back to the instance type.
    """
    if not cpu_model:
        return None
    m = _EPYC_MODEL_RE.search(cpu_model)
    if not m:
        return None
    model = m.group(1)
    if model.startswith("9"):
        return "genoa"
    return _EPYC_GEN_BY_LAST_DIGIT.get(model[-1])


def parse_snp_measurement(report: bytes) -> str:
    """Extract the 48-byte SNP launch MEASUREMENT from a raw report -> hex."""
    if len(report) < _SNP_OFF_MEASUREMENT + _SNP_MEASUREMENT_LEN:
        raise ValueError(
            f"SNP report too short ({len(report)} bytes; need "
            f"{_SNP_OFF_MEASUREMENT + _SNP_MEASUREMENT_LEN})"
        )
    raw = report[_SNP_OFF_MEASUREMENT:_SNP_OFF_MEASUREMENT + _SNP_MEASUREMENT_LEN]
    return raw.hex()


# MRTD offset inside a TDX *quote* (header 48 + TD-quote-body lead-in 136).
# This matches the proven ``_read_mrtd_from_quote`` in the TDX app templates;
# the on-instance snippet below reads a quote via configfs-tsm, so capture and
# the runtime client agree on the exact framing.
_TDX_QUOTE_MRTD_OFFSET = 48 + 136  # 184


def parse_tdx_mrtd(report: bytes, *, offset: int = _TDX_QUOTE_MRTD_OFFSET) -> str:
    """Extract the 48-byte MRTD from a TDX quote -> hex.

    The default offset matches the configfs-tsm quote framing used by the
    runtime TDX client (and by :data:`TDX_READER_SNIPPET`); callers that obtain
    a differently-framed report/quote can pass an explicit offset.
    """
    if len(report) < offset + 48:
        raise ValueError(
            f"TDX report too short ({len(report)} bytes; need {offset + 48})"
        )
    return report[offset:offset + 48].hex()


def parse_measurement_line(text: str) -> Optional[str]:
    """Return the hex measurement from a ``TEE_CRAFTER_MEASUREMENT=`` line."""
    if not text:
        return None
    m = _MEASUREMENT_LINE_RE.search(text)
    return m.group(1).lower() if m else None


# --- On-instance reader snippets -------------------------------------------
# These run with the platform Python (3.10+) available on the baked image.
# They print exactly one ``TEE_CRAFTER_MEASUREMENT=<hex>`` line on success.

#: AMD SEV-SNP: read a report via the /dev/sev-guest ioctl and slice the
#: 48-byte MEASUREMENT at offset 0x90.  Used on snp-aws / gpu-cc-aws (SNP).
SNP_READER_SNIPPET = r'''
import fcntl, struct, ctypes, os, sys

DEV = "/dev/sev-guest"
SNP_GET_REPORT = 0xC0205300  # _IOWR('S', 0, snp_guest_request_ioctl)

class ReportReq(ctypes.Structure):
    _fields_ = [("user_data", ctypes.c_uint8 * 64),
                ("vmpl", ctypes.c_uint32),
                ("rsvd", ctypes.c_uint8 * 28)]

class ReportResp(ctypes.Structure):
    _fields_ = [("data", ctypes.c_uint8 * 4000)]

class GuestReq(ctypes.Structure):
    _fields_ = [("msg_version", ctypes.c_uint8),
                ("req_data", ctypes.c_uint64),
                ("resp_data", ctypes.c_uint64),
                ("fw_err", ctypes.c_uint64)]

try:
    req = ReportReq(); resp = ReportResp()
    g = GuestReq(); g.msg_version = 1
    g.req_data = ctypes.addressof(req); g.resp_data = ctypes.addressof(resp)
    with open(DEV, "rb") as fh:
        fcntl.ioctl(fh, SNP_GET_REPORT, g)
    blob = bytes(resp.data)
    # resp layout: 32-byte header then the 1184-byte report.
    report = blob[32:32 + 1184]
    meas = report[0x90:0x90 + 48]
    print("TEE_CRAFTER_MEASUREMENT=" + meas.hex())
except Exception as e:
    print("TEE_CRAFTER_MEASUREMENT_ERROR=" + repr(e), file=sys.stderr)
    sys.exit(3)
'''

#: AMD SEV-SNP via the snpguest CLI (fallback when the ioctl layout differs by
#: kernel).  Parses ``Measurement:`` from ``snpguest report``.
SNP_SNPGUEST_SNIPPET = r'''
set -e
TMP=$(mktemp -d)
snpguest report "$TMP/report.bin" "$TMP/request.bin" --random >/dev/null 2>&1 || \
  snpguest report "$TMP/report.bin" --random >/dev/null 2>&1
python3 - "$TMP/report.bin" <<'PY'
import sys
report = open(sys.argv[1], "rb").read()
meas = report[0x90:0x90+48]
print("TEE_CRAFTER_MEASUREMENT=" + meas.hex())
PY
'''


#: AMD SEV-SNP via the Azure vTPM.  Azure Hyper-V CVMs do **not** expose
#: ``/dev/sev-guest`` (that device is the KVM guest driver), so both snippets
#: above fail with ENOENT there and every Azure SNP bake used to finish with the
#: image unpinned.  Azure instead publishes a pre-made HCL (Hyper-V Compatibility
#: Layer) report in vTPM NV index 0x01400001: a 32-byte header whose magic is
#: ``HCLA``, followed by the standard 1184-byte AMD SNP report.  MEASUREMENT sits
#: at the same 0x90 offset inside it, so the captured baseline is still the
#: firmware's own digest of the booted image.
#:
#: Framing mirrors ``_get_snp_report_via_vtpm`` in
#: ``templates/snp/azure/app.template.py`` — the reader the runtime already uses
#: on this platform — so capture and verification agree by construction.
#: ``tpm2_nvread`` comes from ``tpm2-tools``, installed by both
#: ``scripts/snp_azure/setup_snp_azure.sh`` and
#: ``scripts/gpu_cc_azure/setup_gpu_cc_azure.sh``.
SNP_VTPM_HCL_SNIPPET = r'''
import subprocess, struct, sys

HCL_HEADER_SIZE = 32
HCL_MAGIC = b"HCLA"
SNP_REPORT_SIZE = 1184

try:
    res = subprocess.run(
        ["tpm2_nvread", "0x01400001", "-C", "o", "-s", "2600"],
        capture_output=True, timeout=30,
    )
    if res.returncode != 0:
        raise RuntimeError(
            "tpm2_nvread 0x01400001 failed: "
            + res.stderr.decode(errors="replace").strip()[:300])
    hcl = res.stdout
    need = HCL_HEADER_SIZE + SNP_REPORT_SIZE
    if len(hcl) < need:
        raise RuntimeError("HCL report too small: %d bytes (need %d)" % (len(hcl), need))
    if hcl[:4] != HCL_MAGIC:
        raise RuntimeError("bad HCL magic: %s" % hcl[:4].hex())
    report = hcl[HCL_HEADER_SIZE:HCL_HEADER_SIZE + SNP_REPORT_SIZE]
    version = struct.unpack_from("<I", report, 0)[0]
    if version < 2:
        raise RuntimeError("unexpected SNP report version: %d" % version)
    meas = report[0x90:0x90 + 48]
    if len(meas) != 48:
        raise RuntimeError("report too short for MEASUREMENT")
    print("TEE_CRAFTER_MEASUREMENT=" + meas.hex())
except Exception as e:
    print("TEE_CRAFTER_MEASUREMENT_ERROR=" + repr(e), file=sys.stderr)
    sys.exit(3)
'''


#: Intel TDX: read a quote via configfs-tsm (Linux 6.7+) and slice the 48-byte
#: MRTD at offset 184.  Mirrors ``_get_tdx_quote_configfs`` /
#: ``_read_mrtd_from_quote`` in the TDX app templates so the captured baseline
#: is framed identically to what the runtime client verifies.  Used on
#: tdx-azure / tdx-gcp / gpu-cc-gcp.
TDX_READER_SNIPPET = r'''
import os, sys, time, uuid

TSM = "/sys/kernel/config/tsm/report"
MRTD_OFF = 48 + 136  # MRTD offset inside the TDX quote (matches app template)

def _get_quote(report_data):
    entry = os.path.join(TSM, "teecrafter_%d_%s" % (os.getpid(), uuid.uuid4().hex[:12]))
    os.makedirs(entry)
    try:
        for _ in range(10):
            if os.path.exists(os.path.join(entry, "inblob")):
                break
            time.sleep(0.01)
        with open(os.path.join(entry, "inblob"), "wb") as fh:
            fh.write(report_data)
        for _ in range(10):
            try:
                with open(os.path.join(entry, "outblob"), "rb") as fh:
                    q = fh.read()
                if q:
                    return q
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("configfs-tsm outblob empty/unreadable")
    finally:
        try:
            os.rmdir(entry)
        except OSError:
            pass

try:
    if not os.path.isdir(TSM):
        raise RuntimeError("configfs-tsm (/sys/kernel/config/tsm/report) not available")
    quote = _get_quote(b"\x00" * 64)
    mrtd = quote[MRTD_OFF:MRTD_OFF + 48]
    if len(mrtd) != 48:
        raise RuntimeError("quote too short for MRTD")
    print("TEE_CRAFTER_MEASUREMENT=" + mrtd.hex())
except Exception as e:
    print("TEE_CRAFTER_MEASUREMENT_ERROR=" + repr(e), file=sys.stderr)
    sys.exit(3)
'''


#: Azure TDX via the vTPM.  ``tdx-azure`` bakes were failing capture with
#: ``OSError(6, 'No such device or address')`` — ENXIO — because on Azure
#: ``/sys/kernel/config/tsm/report`` *exists* (so the "not available" guard in
#: ``TDX_READER_SNIPPET`` does not fire) but the TSM provider cannot service a
#: quote request. Observed on a real ``Standard_DC2es_v6`` on 2026-08-22.
#:
#: Azure publishes the evidence in the same vTPM NV index as the SNP case, in
#: HCLA framing, but the **offsets differ from a DCAP quote** and that is the
#: trap here:
#:
#: * DCAP quote  — TD report body at 48, MRTD at body+136  → **184**
#: * Azure HCLA  — TDREPORT at 32,       MRTD at report+528 → **560**
#:
#: Reading an HCLA blob at 184 yields 48 bytes of some other field: a pin that
#: is well-formed, stored and enforced, and that nothing will ever match. Both
#: offsets are taken from ``_read_mrtd_from_quote`` in
#: ``templates/tdx/azure/app.template.py``, which is the reader the runtime
#: verifies against, so capture and verification cannot drift apart.
#:
#: The three auth hierarchies are tried in the same order as
#: ``_get_tdx_evidence_azure_vtpm``: owner, then the NV index's own auth, then
#: platform. Azure CVMs normally leave the owner password empty, but the
#: fallbacks are kept because that is what the runtime does.
TDX_VTPM_HCL_SNIPPET = r'''
import subprocess, sys

HCLA = b"HCLA"
AZURE_MRTD_OFF = 32 + 528   # TDREPORT at 32, MRTD at TDREPORT+528
DCAP_MRTD_OFF = 48 + 136    # standard DCAP quote framing

def _read_nv():
    size = 2600
    try:
        pub = subprocess.run(["tpm2_nvreadpublic", "0x01400001"],
                             capture_output=True, timeout=15)
        if pub.returncode == 0:
            for line in pub.stdout.decode(errors="replace").splitlines():
                if "size" in line.lower() and ":" in line:
                    try:
                        size = int(line.split(":")[-1].strip())
                    except ValueError:
                        pass
    except Exception:
        pass
    last = ""
    for auth in (["-C", "o"], [], ["-C", "p"]):
        r = subprocess.run(["tpm2_nvread"] + auth + ["0x01400001", "-s", str(size)],
                           capture_output=True, timeout=30)
        if r.returncode == 0 and len(r.stdout) >= 32:
            return r.stdout
        last = r.stderr.decode(errors="replace").strip()[:200]
    raise RuntimeError("tpm2_nvread 0x01400001 failed with every auth hierarchy: " + last)

try:
    blob = _read_nv()
    if blob[:4] == HCLA:
        off, framing = AZURE_MRTD_OFF, "azure-hcla"
    else:
        off, framing = DCAP_MRTD_OFF, "dcap"
    if len(blob) < off + 48:
        raise RuntimeError("evidence too short for MRTD (%d bytes, %s framing, need %d)"
                           % (len(blob), framing, off + 48))
    mrtd = blob[off:off + 48]
    if mrtd == b"\x00" * 48:
        raise RuntimeError("MRTD is all zero at the %s offset; framing is wrong" % framing)
    print("TEE_CRAFTER_MEASUREMENT_FRAMING=" + framing, file=sys.stderr)
    print("TEE_CRAFTER_MEASUREMENT=" + mrtd.hex())
except Exception as e:
    print("TEE_CRAFTER_MEASUREMENT_ERROR=" + repr(e), file=sys.stderr)
    sys.exit(3)
'''


#: AMD SEV-SNP family: the launch digest lives in the SNP report MEASUREMENT.
#: (``gpu-cc-aws`` is NitroTPM, not SEV-SNP, so it is intentionally excluded.)
SNP_PLATFORMS = frozenset(
    {"snp-aws", "snp-azure", "snp-gcp", "gpu-cc-azure"}
)
#: Intel TDX family: the launch digest is the TD's MRTD.
TDX_PLATFORMS = frozenset({"tdx-azure", "tdx-gcp", "gpu-cc-gcp"})


def snp_capture_command(*, sudo: bool = False) -> str:
    """Shell command that prints TEE_CRAFTER_MEASUREMENT for an SNP guest.

    ``sudo`` prefixes the privileged reads for channels that do not already run
    as root (SSH/IAP); the AWS SSM channel runs as root so leaves it ``False``.

    Three readers are tried in order, and the command exits 0 as soon as one
    prints the measurement line:

    1. the ``/dev/sev-guest`` ioctl — the KVM guest driver, so this is the
       working path on AWS and GCP;
    2. the Azure vTPM HCL report — the *only* path on Azure Hyper-V CVMs, which
       do not expose ``/dev/sev-guest`` at all;
    3. the ``snpguest`` CLI — a layout-independent fallback for kernels whose
       ioctl struct differs, and which also needs ``/dev/sev-guest``.

    The vTPM reader goes second rather than last on purpose: it is a real
    platform API, whereas (3) scrapes a CLI, and putting it second means Azure
    resolves in two attempts instead of three. Each attempt runs in a subshell —
    (3) sets ``set -e``, which without the subshell leaked into this script and
    aborted it, so nothing after ``snpguest`` could ever have run.
    """
    py = "sudo python3" if sudo else "python3"
    snpguest = SNP_SNPGUEST_SNIPPET
    if sudo:
        snpguest = snpguest.replace("snpguest report", "sudo snpguest report")
    return (
        _CPU_MODEL_PROBE +
        _NITROTPM_PCR_PROBE +
        f"( {py} - <<'PYEOF'\n" + SNP_READER_SNIPPET + "\nPYEOF\n"
        ")\nrc=$?\n"
        "if [ $rc -ne 0 ]; then\n"
        f"( {py} - <<'PYEOF'\n" + SNP_VTPM_HCL_SNIPPET + "\nPYEOF\n"
        ")\nrc=$?\nfi\n"
        "if [ $rc -ne 0 ]; then\n"
        "(\n" + snpguest + "\n)\nrc=$?\nfi\n"
        "exit $rc\n"
    )


def tdx_capture_command(*, sudo: bool = False) -> str:
    """Shell command that prints TEE_CRAFTER_MEASUREMENT for a TDX guest.

    Two readers, first success wins:

    1. configfs-tsm — the working path on GCP C3;
    2. the Azure vTPM HCLA report — needed on Azure, where ``/sys/kernel/config
       /tsm/report`` *exists* but the provider cannot service a request.

    Order matters only for speed here, but the framing difference between them
    is a correctness trap: MRTD sits at a **different offset** in each (184 in a
    DCAP quote, 560 in an HCLA report), so a reader that guessed one framing
    would pin 48 bytes of the wrong field. That pin would look perfectly valid —
    96 hex chars, stored, enforced — and then fail every verification with no
    hint as to why. See ``TDX_VTPM_HCL_SNIPPET``.
    """
    py = "sudo python3" if sudo else "python3"
    return (
        _CPU_MODEL_PROBE +
        f"( {py} - <<'PYEOF'\n" + TDX_READER_SNIPPET + "\nPYEOF\n"
        ")\nrc=$?\n"
        "if [ $rc -ne 0 ]; then\n"
        f"( {py} - <<'PYEOF'\n" + TDX_VTPM_HCL_SNIPPET + "\nPYEOF\n"
        ")\nrc=$?\nfi\n"
        "exit $rc\n"
    )


def capture_command(platform: str, *, sudo: bool = False) -> str:
    """Return the on-instance reader command for ``platform``.

    Dispatches to the SNP or TDX reader by platform family.  Raises
    ``ValueError`` for platforms with no launch-measurement reader (Nitro PCR0
    and SGX MRENCLAVE are build-time deterministic and pinned by the builder,
    not read from a booted instance).
    """
    if platform in TDX_PLATFORMS:
        cmd = tdx_capture_command(sudo=sudo)
        if platform == "gpu-cc-gcp":
            # Only this platform publishes a vTPM PCR bundle in its RA-TLS
            # certificate, so only this one records the reference. tdx-azure and
            # tdx-gcp have vTPMs that would answer the probe, but nothing
            # consumes their values -- recording them under this name would be a
            # lie of labelling, the same reasoning applied to the NitroTPM PCRs.
            cmd = _VTPM_PCR_PROBE + cmd
        return cmd
    if platform in SNP_PLATFORMS:
        return snp_capture_command(sudo=sudo)
    raise ValueError(f"no launch-measurement reader for platform {platform!r}")
