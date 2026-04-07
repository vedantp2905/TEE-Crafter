"""Platform-specific render + stage functions (SGX, TDX, SNP-AWS/Azure/GCP, TDX-GCP)."""
import datetime
import json
import logging
import os
import shutil
import uuid
from typing import List, Optional

logger = logging.getLogger(__name__)

from tee_crafter.core.builder.runtime_modules import (
    RUNTIME_MODULES,
    copy_source_tree,
    copy_runtime_modules,
)


def _load_template(filename: str) -> str:
    tpl = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates", filename)
    with open(tpl, "r", encoding="utf-8") as f:
        return f.read()


class MissingTrustAnchor(RuntimeError):
    """A vendor root/intermediate CA needed for attestation is not available.

    This is always fatal.  A generated client that carries an empty trust
    anchor cannot verify any attestation evidence, but *looks* like a working
    client — it would print PASSED on a forged report.  Failing the build is
    the only safe behaviour.

    The usual cause is an installed wheel built without ``certs/*.pem`` in
    ``[tool.setuptools.package-data]``; that omission is invisible in a source
    checkout, which is why this check exists.
    """


def _load_trust_anchor(filename: str) -> str:
    """Read a pinned vendor CA from ``certs/``.  Never returns empty."""
    p = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "certs", filename,
    )
    try:
        with open(p, "r", encoding="utf-8") as f:
            pem = f.read().strip()
    except OSError as exc:
        raise MissingTrustAnchor(
            f"Attestation trust anchor {filename!r} is missing from the "
            f"installation ({p}). Reinstall tee-crafter, or restore the file "
            f"from the repository. Refusing to generate a client with no root "
            f"of trust."
        ) from exc
    if "BEGIN CERTIFICATE" not in pem:
        raise MissingTrustAnchor(
            f"Attestation trust anchor {filename!r} at {p} is not a PEM "
            f"certificate. Refusing to generate a client with an invalid root "
            f"of trust."
        )
    return pem


def _load_intel_root_ca() -> str:
    # Intel SGX Root CA — the DCAP provisioning root that PCK certificates
    # chain to.  This is NOT the legacy "SGX Attestation Report Signing CA"
    # (the retired EPID/IAS root), which was previously shipped here and
    # could never validate a DCAP PCK chain.
    return _load_trust_anchor("intel-sgx-dcap-root.pem")


def _load_amd_root_ca(processor_family: str = "milan") -> str:
    return _load_trust_anchor(f"amd-ark-{processor_family}.pem")


def _load_amd_ask_ca(processor_family: str = "milan") -> str:
    """The VCEK-signing chain: ``[SEV-<Family> (ASK), ARK-<Family>]``.

    AMD signs a **VCEK** with the ASK (``CN=SEV-Milan``) and a **VLEK** with a
    separate intermediate (``CN=SEV-VLEK-Milan``).  ``amd-ark-milan.pem`` ships
    the *VLEK* one, which is what AWS hands back — so on Milan hosts that
    return a VCEK, as GCP does, the client had no intermediate that could have
    signed the endorsement and chain verification could only fail.  Confirmed on
    real GCP SEV-SNP hardware 2026-08-21: the host cert table reported
    ``VCEK=yes, ASK=yes, ARK=no`` and the client aborted with "does not chain to
    a trusted AMD root".

    Both bundles carry the **same** ARK (identical SPKI digest, checked against
    AMD KDS), so adding this one widens which endorsements verify without
    changing the pinned root of trust.  ``amd-ark-genoa.pem`` already contains
    the ASK, which is why only Milan needs a second file.
    """
    return _load_trust_anchor(f"amd-ask-{processor_family}.pem")


def _primary_measurement(measurement: str = "", measurements: Optional[List[str]] = None) -> str:
    vals = list(measurements or [])
    if vals:
        return vals[0]
    return measurement or "unknown"


def _measurements_json(measurement: str = "", measurements: Optional[List[str]] = None) -> str:
    vals = list(measurements or [])
    if not vals and measurement and measurement != "unknown":
        vals = [measurement]
    return json.dumps(vals)


# Canonical copy lists live in runtime_modules (SOURCE_IGNORE /
# SOURCE_SKIP_DIRS) so builder.py and this module cannot diverge.


def _copy_source(source_dir: str, app_path: str):
    """Copy the user's source into the build.

    Thin wrapper over :func:`runtime_modules.copy_source_tree`, the single
    implementation shared with ``builder.py``.  See that function for why
    there is only one: five hand-rolled copies of this loop each let a
    top-level ``.env`` through into the measured image.
    """
    copy_source_tree(source_dir, app_path)


def _common_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates", "common")


# Shared with ``builder.py`` — see ``runtime_modules`` for the fail-open bug
# that having two divergent copies of this list and this loop caused.
_RUNTIME_MODULES = RUNTIME_MODULES


def _copy_runtime_modules(dest_dir: str) -> None:
    """Copy runtime audit/attestation modules into the build (fail-closed)."""
    copy_runtime_modules(dest_dir)


def _stage_platform(source_dir, code, app_filename, label, existing_build_dir, extra_files=None):
    """Generic platform artifact staging (source copy + runtime modules).

    Container-orchestrated model: no application output_schema.json is read or
    embedded. The in-TEE ``_OUTPUT_SCHEMA`` placeholder is left ``None`` (inert);
    the confidentiality boundary is attestation + default-deny network egress.
    """
    if existing_build_dir:
        bp = os.path.abspath(existing_build_dir)
        ap = os.path.join(bp, "app")
        os.makedirs(ap, exist_ok=True)
        with open(os.path.join(ap, app_filename), "w", encoding="utf-8") as f:
            f.write(code)
        if extra_files:
            for name, content in extra_files.items():
                with open(os.path.join(bp, name), "w", encoding="utf-8") as f:
                    f.write(content)
        _copy_runtime_modules(ap)
        return bp
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    deploy_id = uuid.uuid4().hex[:8]
    sname = os.path.basename(os.path.abspath(source_dir)) or "app"
    bp = os.path.abspath(os.path.join("builds", f"{sname}_{label}_build_{ts}_{deploy_id}"))
    ap = os.path.join(bp, "app")
    os.makedirs(ap, exist_ok=True)
    _copy_source(source_dir, ap)
    with open(os.path.join(ap, app_filename), "w", encoding="utf-8") as f:
        f.write(code)
    if extra_files:
        for name, content in extra_files.items():
            with open(os.path.join(bp, name), "w", encoding="utf-8") as f:
                f.write(content)
    _copy_runtime_modules(ap)
    return bp


# ---- Render functions ----

def render_gramine_manifest(python_path="/usr/bin/python3", arch_libdir="/lib/x86_64-linux-gnu",
                            enclave_size="512M", max_threads=8) -> str:
    return (_load_template(os.path.join("sgx", "manifest.template.toml"))
            .replace("{python_path}", python_path).replace("{arch_libdir}", arch_libdir)
            .replace("{enclave_size}", enclave_size).replace("{max_threads}", str(max_threads)))


def render_sgx_client_template(
    mrenclave: str = "",
    mrsigner: str = "",
) -> str:
    """Render the SGX client template.

    The former ``min_isv_svn`` (SGX-4) and ``min_tcb_eval_date`` (SGX-5)
    parameters have been removed along with the checks they fed.  Both were
    dead: no caller ever passed a value, so every rendered client defaulted
    permissive, and they could not simply be wired up — the Gramine manifest
    sets no ``sgx.isvsvn``, so Gramine signs at 0 and any floor above 0 would
    have rejected our own enclaves.  The ``{min_isv_svn}`` /
    ``{min_tcb_eval_date}`` placeholders no longer exist in the template, so
    the substitutions were no-ops kept alive only by this docstring.

    TCB *status* evaluation (Intel PCS collateral, ``tcbStatus``, QEIdentity,
    PCK CRLs) **is** implemented now, in
    :mod:`tee_crafter.core.attestation.tcb_collateral` on the build side and
    ``templates/common/tee_crafter_tcb_eval.py`` on the client side; every Intel
    client calls ``enforce_platform_tcb_status``.  Do not reintroduce an ISV-SVN
    floor here as a substitute for it — that was the original point of this note
    and it still holds.
    """
    return (_load_template(os.path.join("sgx", "client.template.py"))
            .replace("{mrenclave}", mrenclave or "unknown")
            .replace("{mrsigner}", mrsigner or "unknown")
            .replace("{intel_sgx_root_ca}", _load_intel_root_ca()))


#: Evidence formats the ``tdx-azure`` app produces and its client verifies.
#:
#: ``dcap`` is rooted in Intel's CA: the TD quotes itself, the client checks the
#: ECDSA signature and the PCK chain, and the session is bound into the
#: hardware-signed ``report_data``.  Strictly the stronger of the two, and
#: available wherever a TD can reach a Quoting Enclave — ``tdx-gcp``, bare metal.
#:
#: ``azure-guest`` is rooted in Microsoft Azure Attestation, and on an Azure
#: paravisor CVM it is the *only* option rather than a preference.  The guest
#: there cannot obtain a quote at all: vTPM NV ``0x01400001`` yields a raw
#: 1024-byte ``TDREPORT`` whose ``REPORTMACSTRUCT`` only the TDX module and the
#: Quoting Enclave can verify, so ``/attest/TdxVm`` rejects it (three live runs
#: proved this, at cost).  Evidence becomes an ``/attest/AzureGuest`` token and
#: the session binding moves to the client-payload nonce, because ``report_data``
#: belongs to the paravisor on that platform.
#:
#: The client accepts exactly one, fixed here rather than inferred from the
#: blob, so a compromised server cannot pick its own verifier.
TDX_EVIDENCE_FORMATS = ("dcap", "azure-guest")

#: Override with ``TEE_CRAFTER_TDX_EVIDENCE_FORMAT``.
#:
#: The default stays ``dcap`` — the stronger trust root — because moving to a
#: Microsoft-rooted, nonce-bound attestation is a deliberate downgrade an
#: operator should have to ask for, even on the platform where it is the only
#: thing that works.  ``tdx-azure`` on Azure needs ``azure-guest``; ``tdx-gcp``
#: must stay on ``dcap``.
TDX_EVIDENCE_FORMAT_ENV = "TEE_CRAFTER_TDX_EVIDENCE_FORMAT"

#: Retired spelling of ``azure-guest``, kept only to reject it by name.
#:
#: ``hcla`` named the *blob* rather than the verifier, and under that name the
#: code posted the raw Azure envelope to ``/attest/TdxVm`` — a combination that
#: cannot work and that the old name made look reasonable.  Anyone still
#: carrying it in a ``.env`` gets told what changed instead of a bare "not one
#: of".
_RETIRED_TDX_EVIDENCE_FORMATS = {
    "hcla": (
        "'hcla' has been renamed to 'azure-guest'. The old name described the "
        "vTPM blob, and the code behind it POSTed that blob to /attest/TdxVm, "
        "which only verifies Intel DCAP quotes — so it could never succeed. "
        "The replacement exchanges the vTPM evidence for an MAA "
        "/attest/AzureGuest token via Microsoft's guest-attestation library."
    ),
}


def tdx_evidence_format() -> str:
    """Resolve the ``tdx-azure`` evidence format for app and client alike.

    Rejects anything outside :data:`TDX_EVIDENCE_FORMATS` rather than falling
    back to the default: a typo silently reverting to ``dcap`` would look
    exactly like the operator's choice having been applied, and on Azure that
    reversion produces a VM that cannot attest at all.
    """
    raw = (os.environ.get(TDX_EVIDENCE_FORMAT_ENV) or "dcap").strip().lower()
    if raw in _RETIRED_TDX_EVIDENCE_FORMATS:
        raise ValueError(
            f"{TDX_EVIDENCE_FORMAT_ENV}={raw!r}: "
            f"{_RETIRED_TDX_EVIDENCE_FORMATS[raw]}")
    if raw not in TDX_EVIDENCE_FORMATS:
        raise ValueError(
            f"{TDX_EVIDENCE_FORMAT_ENV}={raw!r} is not one of "
            f"{list(TDX_EVIDENCE_FORMATS)}. 'dcap' verifies an Intel DCAP quote "
            "against Intel's root CA and binds the session into "
            "hardware-signed report_data; 'azure-guest' exchanges Azure vTPM "
            "evidence for an MAA token (needs TEE_CRAFTER_MAA_ENDPOINT) and is "
            "the only path that works on an Azure paravisor CVM.")
    return raw


def render_tdx_client_template(mrtd="", container_digest="") -> str:
    return (_load_template(os.path.join("tdx", "azure", "client.template.py"))
            .replace("{mrtd}", mrtd or "unknown")
            .replace("{container_digest}", container_digest or "")
            .replace("{evidence_format}", tdx_evidence_format())
            .replace("{intel_root_ca}", _load_intel_root_ca()))


def render_snp_aws_client_template(
    measurement="", measurements=None, container_digest="",
) -> str:
    # SNP-2: bake both Milan and Genoa chains so the client can
    # auto-select at runtime by attempting each chain in turn.  The
    # {amd_root_ca} placeholder remains populated with the primary
    # (Milan) chain for backwards compatibility.
    primary = _primary_measurement(measurement, measurements)
    return (_load_template(os.path.join("snp", "aws", "client.template.py"))
            .replace("{measurement}", primary)
            .replace("{measurements_json}", _measurements_json(measurement, measurements))
            .replace("{container_digest}", container_digest or "")
            .replace("{amd_root_ca_milan}", _load_amd_root_ca("milan"))
            .replace("{amd_ask_ca_milan}", _load_amd_ask_ca("milan"))
            .replace("{amd_root_ca_genoa}", _load_amd_root_ca("genoa"))
            .replace("{amd_root_ca}", _load_amd_root_ca("milan")))


def render_snp_azure_client_template(
    measurement="", measurements=None, processor_family="milan", container_digest="",
) -> str:
    primary = _primary_measurement(measurement, measurements)
    return (_load_template(os.path.join("snp", "azure", "client.template.py"))
            .replace("{measurement}", primary)
            .replace("{measurements_json}", _measurements_json(measurement, measurements))
            .replace("{container_digest}", container_digest or "")
            .replace("{amd_root_ca_milan}", _load_amd_root_ca("milan"))
            .replace("{amd_ask_ca_milan}", _load_amd_ask_ca("milan"))
            .replace("{amd_root_ca_genoa}", _load_amd_root_ca("genoa"))
            .replace("{amd_root_ca}", _load_amd_root_ca(processor_family)))


def render_snp_gcp_client_template(
    measurement="", measurements=None, processor_family="milan", container_digest="",
) -> str:
    primary = _primary_measurement(measurement, measurements)
    return (_load_template(os.path.join("snp", "gcp", "client.template.py"))
            .replace("{measurement}", primary)
            .replace("{measurements_json}", _measurements_json(measurement, measurements))
            .replace("{container_digest}", container_digest or "")
            .replace("{amd_root_ca_milan}", _load_amd_root_ca("milan"))
            .replace("{amd_ask_ca_milan}", _load_amd_ask_ca("milan"))
            .replace("{amd_root_ca_genoa}", _load_amd_root_ca("genoa"))
            .replace("{amd_root_ca}", _load_amd_root_ca(processor_family)))


def render_tdx_gcp_client_template(mrtd="", container_digest="") -> str:
    return (_load_template(os.path.join("tdx", "gcp", "client.template.py"))
            .replace("{mrtd}", mrtd or "unknown")
            .replace("{container_digest}", container_digest or "")
            .replace("{intel_root_ca}", _load_intel_root_ca()))


def render_sgx_setup_script() -> str:
    """The SGX host setup script, ready to upload.

    This used to take ``aws_region`` and ``enclave_size`` and pass them to
    ``str.format()``.  Both were vestigial — they appear in ``setup_sgx.sh``
    only inside its header comment — and the ``.format()`` call could never
    succeed against a template full of literal shell braces.  See
    :func:`tee_crafter.cli.loaders.render_sgx_setup_script`, which owns the
    convention that the bake path has always used.
    """
    from tee_crafter.cli.loaders import render_sgx_setup_script as _render
    return _render()


# ---- Stage functions (thin wrappers around _stage_platform) ----

def stage_sgx_artifacts(source_dir, gramine_code, manifest_content=None,
                        base_build_dir="build", existing_build_dir=None) -> str:
    extra = {"app_gramine.manifest.toml": manifest_content} if manifest_content else None
    return _stage_platform(source_dir, gramine_code, "app_gramine.py", "sgx", existing_build_dir, extra)


def stage_tdx_artifacts(source_dir, tdx_code, base_build_dir="build", existing_build_dir=None) -> str:
    return _stage_platform(source_dir, tdx_code, "app_tdx.py", "tdx", existing_build_dir)


def stage_snp_aws_artifacts(source_dir, snp_code, base_build_dir="build", existing_build_dir=None) -> str:
    return _stage_platform(source_dir, snp_code, "app_snp.py", "snp_aws", existing_build_dir)


def stage_snp_azure_artifacts(source_dir, snp_code, base_build_dir="build", existing_build_dir=None) -> str:
    return _stage_platform(source_dir, snp_code, "app_snp.py", "snp_azure", existing_build_dir)


def stage_snp_gcp_artifacts(source_dir, snp_code, base_build_dir="build", existing_build_dir=None) -> str:
    return _stage_platform(source_dir, snp_code, "app_snp_gcp.py", "snp_gcp", existing_build_dir)


def stage_tdx_gcp_artifacts(source_dir, tdx_code, base_build_dir="build", existing_build_dir=None) -> str:
    return _stage_platform(source_dir, tdx_code, "app_tdx_gcp.py", "tdx_gcp", existing_build_dir)


def _load_nvidia_root_ca() -> str:
    return _load_trust_anchor("nvidia-nras-intermediate.pem")


def render_gpu_cc_gcp_client_template(
    mrtd: str = "",
    container_digest: str = "",
    expected_vtpm_pcrs: str = "",
) -> str:
    """Render the GCP GPU CC client template.

    ``expected_vtpm_pcrs`` is an F-8 pinning string in
    ``"idx:hex,idx:hex"`` form; it can always be overridden at runtime
    via ``TEE_CRAFTER_EXPECTED_VTPM_PCRS``.  The empty default enables
    self-pinning.
    """
    return (_load_template(os.path.join("gpu_cc", "gcp", "client.template.py"))
            .replace("{mrtd}", mrtd or "unknown")
            .replace("{container_digest}", container_digest or "")
            .replace("{expected_vtpm_pcrs}", expected_vtpm_pcrs or "")
            .replace("{intel_root_ca}", _load_intel_root_ca())
            .replace("{nvidia_root_ca}", _load_nvidia_root_ca()))


def render_gpu_cc_azure_client_template(
    measurement="", measurements=None, processor_family="genoa", container_digest="",
) -> str:
    primary = _primary_measurement(measurement, measurements)
    return (_load_template(os.path.join("gpu_cc", "azure", "client.template.py"))
            .replace("{measurement}", primary)
            .replace("{measurements_json}", _measurements_json(measurement, measurements))
            .replace("{container_digest}", container_digest or "")
            .replace("{amd_root_ca}", _load_amd_root_ca(processor_family))
            .replace("{nvidia_root_ca}", _load_nvidia_root_ca()))


def render_gpu_cc_aws_client_template(measurement="", container_digest="",
                                      expected_nitrotpm_pcrs="") -> str:
    """Render the ``gpu-cc-aws`` verifier client.

    *expected_nitrotpm_pcrs* is an ``"idx:hex,idx:hex"`` string of reference
    PCR values recorded at bake.  The client verifies the instance's NitroTPM
    attestation document against the pinned AWS Nitro root and then compares
    these values; an empty string means no reference was captured, and the
    client says so rather than pretending the comparison happened.

    *measurement* is accepted and **not** baked in.  A SEV-SNP-style launch
    measurement does not exist on this platform -- the CPU evidence is measured
    boot (PCR4/PCR7), not memory encryption -- so a caller passing one still
    gets a warning; the two are not interchangeable.
    """
    if measurement and measurement != "unknown":
        logger.warning(
            "gpu-cc-aws: ignoring pinned CPU measurement %s… — this platform's "
            "CPU evidence is a NitroTPM measured-boot document (PCR4/PCR7), "
            "not a launch measurement, so this value has nothing to compare "
            "against. Pass expected_nitrotpm_pcrs instead.", measurement[:16],
        )
    return (_load_template(os.path.join("gpu_cc", "aws", "client.template.py"))
            .replace("{container_digest}", container_digest or "")
            .replace("{expected_nitrotpm_pcrs}", expected_nitrotpm_pcrs or "")
            .replace("{nitro_root_ca}", _load_trust_anchor("nitro-root.pem"))
            .replace("{nvidia_root_ca}", _load_nvidia_root_ca()))


def _copy_nvidia_attestation(dest_dir: str) -> None:
    """Copy nvidia_attestation.py into GPU-CC builds."""
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gpu", "nvidia_attestation.py")
    if os.path.isfile(src):
        shutil.copy2(src, os.path.join(dest_dir, "nvidia_attestation.py"))


def stage_gpu_cc_gcp_artifacts(source_dir, tdx_code, base_build_dir="build", existing_build_dir=None) -> str:
    bp = _stage_platform(source_dir, tdx_code, "app_gpu_cc_gcp.py", "gpu_cc_gcp", existing_build_dir)
    _copy_nvidia_attestation(os.path.join(bp, "app"))
    return bp


def stage_gpu_cc_azure_artifacts(source_dir, snp_code, base_build_dir="build", existing_build_dir=None) -> str:
    bp = _stage_platform(source_dir, snp_code, "app_gpu_cc_azure.py", "gpu_cc_azure", existing_build_dir)
    _copy_nvidia_attestation(os.path.join(bp, "app"))
    return bp


def stage_gpu_cc_aws_artifacts(source_dir, snp_code, base_build_dir="build", existing_build_dir=None) -> str:
    bp = _stage_platform(source_dir, snp_code, "app_gpu_cc_aws.py", "gpu_cc_aws", existing_build_dir)
    _copy_nvidia_attestation(os.path.join(bp, "app"))
    return bp
