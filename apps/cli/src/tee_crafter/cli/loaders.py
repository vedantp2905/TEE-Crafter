"""Load template and resource files from the package."""

import hashlib
import os

from tee_crafter.resources import (
    load_unit, load_container_unit,
    load_container_batch_unit,
    load_secrets_unit,
)

_TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "templates", "common",
)


def _inject_security_profiles(content: str) -> str:
    """Replace ``__SECCOMP_PROFILE__``, ``__APPARMOR_PROFILE__`` and
    ``__APPARMOR_BATCH_PROFILE__`` placeholders with the real file contents.

    The batch profile (``apparmor-batch-container``) is loaded alongside the
    strict ``apparmor-container`` profile so the batch oneshot unit can
    pin user containers to a meaningful AppArmor confinement without
    requiring path-allowlisting of arbitrary user images.
    """
    if "__SECCOMP_PROFILE__" in content:
        seccomp_path = os.path.join(_TEMPLATES_DIR, "seccomp-container.json")
        with open(seccomp_path, "r", encoding="utf-8") as f:
            content = content.replace("__SECCOMP_PROFILE__", f.read())
    if "__APPARMOR_PROFILE__" in content:
        apparmor_path = os.path.join(_TEMPLATES_DIR, "apparmor-container")
        with open(apparmor_path, "r", encoding="utf-8") as f:
            content = content.replace("__APPARMOR_PROFILE__", f.read())
    if "__APPARMOR_BATCH_PROFILE__" in content:
        apparmor_batch_path = os.path.join(
            _TEMPLATES_DIR, "apparmor-batch-container",
        )
        with open(apparmor_batch_path, "r", encoding="utf-8") as f:
            content = content.replace("__APPARMOR_BATCH_PROFILE__", f.read())
    return content


_SECURE_BOOT_ENROLL_PLACEHOLDER = "__SECURE_BOOT_ENROLL__"
_SECURE_BOOT_DISABLED_NOOP = (
    "echo '[SB-AWS] Secure Boot enrollment skipped "
    "(bake-ami invoked without --enable-secure-boot)'"
)


def _load_secure_boot_enroll_block() -> str:
    """Load the shared AWS Secure Boot enrollment shell fragment."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "scripts", "common", "secure_boot_enroll_aws.sh")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def inject_secure_boot_block(content: str, enable: bool) -> str:
    """Substitute the ``__SECURE_BOOT_ENROLL__`` placeholder in *content*.

    When *enable* is True, the placeholder is replaced with the contents of
    ``scripts/common/secure_boot_enroll_aws.sh`` (which enrolls UEFI PK/KEK/db
    via ``efi-updatevar`` and refuses to continue if Secure Boot does not
    become enforcing).  When False, the placeholder is replaced with a
    single-line ``echo`` so the bake script still parses correctly.

    Scripts that do not contain the placeholder (every non-AWS platform) are
    returned unchanged.  This is called post-``.format()`` so the injected
    shell block may use any curly-brace characters freely.
    """
    if _SECURE_BOOT_ENROLL_PLACEHOLDER not in content:
        return content
    if enable:
        block = _load_secure_boot_enroll_block()
    else:
        block = _SECURE_BOOT_DISABLED_NOOP
    return content.replace(_SECURE_BOOT_ENROLL_PLACEHOLDER, block)


def _inject_systemd_units(content: str, platform: str, **unit_kwargs: str) -> str:
    """Replace __SYSTEMD_UNIT__ / __CONTAINER_UNIT__ / batch placeholders."""
    if "__SYSTEMD_UNIT__" in content:
        content = content.replace("__SYSTEMD_UNIT__", load_unit(platform, **unit_kwargs).rstrip("\n"))
    if "__CONTAINER_UNIT__" in content:
        content = content.replace("__CONTAINER_UNIT__", load_container_unit(platform).rstrip("\n"))
    if "__SECRETS_UNIT__" in content:
        content = content.replace("__SECRETS_UNIT__", load_secrets_unit(platform).rstrip("\n"))
    if "__CONTAINER_BATCH_UNIT__" in content:
        content = content.replace(
            "__CONTAINER_BATCH_UNIT__",
            load_container_batch_unit(platform).rstrip("\n"),
        )
    if "__CAPTURE_CONTAINER_SCRIPT__" in content:
        cur = os.path.dirname(os.path.abspath(__file__))
        cap_path = os.path.join(cur, "..", "scripts", "common",
                                "tee_crafter_capture_container.sh")
        with open(cap_path, "r", encoding="utf-8") as f:
            content = content.replace("__CAPTURE_CONTAINER_SCRIPT__", f.read().rstrip("\n"))
    return content


#: Placeholder -> path (relative to ``scripts/``) of a helper program that is
#: inlined into a setup script.  These run on a freshly provisioned VM that has
#: no checkout to copy from, so the only way to ship them is inside the script
#: that is already being uploaded.
_INLINED_HELPERS = {
    "__GSC_DEBIAN_PATCH_SCRIPT__": ("sgx_azure", "patch_gsc_debian_template.py"),
    # Shared by all three Azure confidential-VM bakes.  One copy, because the
    # alternative was three: it was present only in ``setup_tdx.sh``, which is
    # why ``--byok azure-skr`` had no binary to call on ``snp-azure`` and
    # ``gpu-cc-azure``.
    "__AZURE_GUEST_ATTESTATION__": ("common", "azure_guest_attestation.sh"),
    # Shared by the two AWS bakes that need a NitroTPM attestation document:
    # snp-aws for measurement-gated key release, gpu-cc-aws for CPU-side
    # evidence in the RA-TLS certificate.  gpu-cc-aws had no installer at all,
    # which is why that platform could only self-assert its PCRs.
    "__NITRO_TPM_ATTEST_INSTALL__": ("common", "nitro_tpm_attest_install.sh"),
}


def _inject_helper_scripts(content: str) -> str:
    """Inline helper programs referenced by placeholder.

    ``setup_nitro.sh`` is rendered with ``str.format()``, and
    ``render_sgx_setup_script`` un-doubles braces in ``setup_sgx.sh``, so a
    helper inlined into either must be written brace-free — the GSC patch script
    is, and ``tests/cli/test_gsc_debian_template_patch.py`` holds it to that.
    The Azure guest-attestation fragment has shell braces and is safe because
    the three scripts that include it (``setup_tdx.sh``,
    ``setup_snp_azure.sh``, ``setup_gpu_cc_azure.sh``) are neither formatted nor
    un-doubled; ``tests/cli/test_azure_guest_attestation_shared.py`` asserts
    that stays true.
    """
    for placeholder, parts in _INLINED_HELPERS.items():
        if placeholder not in content:
            continue
        cur = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(cur, "..", "scripts", *parts)
        with open(path, "r", encoding="utf-8") as f:
            content = content.replace(placeholder, f.read().rstrip("\n"))
    return content


def _load_script(*relative_parts: str, platform: str = "", **unit_kwargs: str) -> str:
    """Helper to load a script from the packaged ``scripts/`` directory."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(current_dir, "..", "scripts", *relative_parts)
    with open(script_path, "r", encoding="utf-8") as f:
        content = _inject_security_profiles(f.read())
    content = _inject_helper_scripts(content)
    if platform:
        content = _inject_systemd_units(content, platform, **unit_kwargs)
    return content


def load_nitro_setup_template() -> str:
    """Load the Nitro remote host setup script template."""
    return _load_script("nitro_aws", "setup_nitro.sh", platform="nitro-aws")


def load_sgx_setup_template() -> str:
    """Load the SGX/Gramine host setup script template, braces still doubled."""
    return _load_script("sgx_azure", "setup_sgx.sh", platform="sgx-azure",
                        remote_base="/home/azureuser/sgx-app")


def render_sgx_setup_script() -> str:
    """The SGX host setup script as it should actually be run.

    ``setup_sgx.sh`` writes every literal shell brace doubled, so a caller could
    render it with ``str.format()``.  No caller supplies a substitution any more
    — the two placeholders the header advertises, ``aws_region`` and
    ``enclave_size``, survive only in that header comment — so the doubling is
    simply undone here.

    Undoing it in exactly one place is the point.  The convention used to be
    open-coded in the bake path only, while
    ``core.builder.platforms.render_sgx_setup_script`` called ``.format()`` on
    the same template; the template contains 49 unescaped braces (an
    ``awk '{print $1}'`` at line 76, the injected seccomp JSON, and more), so
    that second path raised ``KeyError: 'print $1'`` for as long as it existed.
    It went unnoticed because it is unreachable today: ``sgx-azure`` is
    batch-only, and ``--batch`` returns before it while ``--persistent`` is
    refused at parse time.
    """
    return load_sgx_setup_template().replace("{{", "{").replace("}}", "}")


def load_tdx_setup_template() -> str:
    """Load the TDX host setup script template."""
    return _load_script("tdx_azure", "setup_tdx.sh", platform="tdx-azure")


def load_nitro_root_ca() -> str:
    """Load the AWS Nitro Root CA PEM from the package.

    Fatal if absent — see :class:`MissingTrustAnchor`.  An empty trust anchor
    produces a client that accepts any attestation document.
    """
    from tee_crafter.core.builder.platforms import _load_trust_anchor
    return _load_trust_anchor("nitro-root.pem")




def load_snp_aws_setup_template() -> str:
    """Load the SNP AWS host setup script template."""
    return _load_script("snp_aws", "setup_snp_aws.sh", platform="snp-aws")


def load_snp_azure_setup_template() -> str:
    """Load the SNP Azure host setup script template."""
    return _load_script("snp_azure", "setup_snp_azure.sh", platform="snp-azure")


def load_gpu_cc_aws_setup_template() -> str:
    """Load the GPU CC AWS host setup script."""
    return _load_script("gpu_cc_aws", "setup_gpu_cc_aws.sh", platform="gpu-cc-aws")


def load_gpu_cc_gcp_setup_template() -> str:
    """Load the GPU CC GCP host setup script."""
    return _load_script("gpu_cc_gcp", "setup_gpu_cc_gcp.sh", platform="gpu-cc-gcp")


def load_gpu_cc_azure_setup_template() -> str:
    """Load the GPU CC Azure host setup script."""
    return _load_script("gpu_cc_azure", "setup_gpu_cc_azure.sh", platform="gpu-cc-azure")


#: Loader per platform for the script that is executed **at bake time** and
#: whose effects therefore live inside the baked image rather than being
#: re-uploaded on every deploy.
_BAKE_SETUP_LOADERS = {
    "nitro-aws": load_nitro_setup_template,
    "sgx-azure": render_sgx_setup_script,
    "tdx-azure": load_tdx_setup_template,
    "snp-aws": load_snp_aws_setup_template,
    "snp-azure": load_snp_azure_setup_template,
    "snp-gcp": lambda: _load_script("snp_gcp", "setup_snp_gcp.sh",
                                    platform="snp-gcp"),
    "tdx-gcp": lambda: _load_script("tdx_gcp", "setup_tdx_gcp.sh",
                                    platform="tdx-gcp"),
    "gpu-cc-aws": load_gpu_cc_aws_setup_template,
    "gpu-cc-gcp": load_gpu_cc_gcp_setup_template,
    "gpu-cc-azure": load_gpu_cc_azure_setup_template,
}


def bake_inputs_digest(platform: str) -> str:
    """SHA-256 of everything this platform bakes *into* its image, or ``""``.

    The point is to tell a baked image apart from the code that would bake it
    today. ``stale_image_check`` already covers the CLI image versus the
    checkout, but it cannot see this: a VM image is baked once and then used for
    weeks, so a fix to a bake-time input silently does not apply to it.

    That is not hypothetical. On 2026-08-24 an ``sgx-azure --batch`` run failed
    with Gramine unable to mount its root filesystem, because AppArmor denied
    ``open("/")`` -- a bug whose fix (``/ rwlkmix,`` in
    ``apparmor-batch-container``) was already in the repo *and* covered by a
    test, but the image being deployed had been baked before it landed. Nothing
    in the run said so; it read like a fresh regression, and diagnosing it cost
    a VM, a Bastion and an hour.

    Hashing the *rendered* setup script is what makes this exact rather than
    approximate: the security profiles, the systemd units and the helper
    scripts are all substituted into that text before it is uploaded, so one
    digest covers every input whose effect is baked in. Deploy-time templates
    are deliberately excluded -- they ship on every deploy, so they cannot go
    stale this way.

    Returns ``""`` for an unknown platform rather than raising: this is a
    diagnostic, and failing a bake over it would be the wrong trade.
    """
    loader = _BAKE_SETUP_LOADERS.get(platform or "")
    if loader is None:
        return ""
    try:
        rendered = loader()
    except Exception:
        return ""
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()
