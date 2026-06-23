"""Every module the in-enclave app imports must be COPYed into the image.

On Nitro the container *is* the enclave, so `/tee-crafter-runtime` is the whole
world `app_vsock.py` can import from: `tee_entrypoint.sh` runs
`python3 /tee-crafter-runtime/app_vsock.py`, which makes that directory
`sys.path[0]`, and neither the Dockerfile nor the entrypoint sets `PYTHONPATH`.

`core/builder/runtime_modules.py` already makes a *missing* module fatal when
staging into the build directory. Nothing carried them the last hop into the
image, and because every import in the app template is
`except ImportError: pass`, the result was silent: on a live deploy the
audit-log wrapper, the SIEM-SEC-4 freshness gate, the BYOK release gate and the
SIEM-SEC-5 per-request sandbox were all inert, and the enclave published an
empty `chain_key_commitment`.

Measured on real hardware (2026-08-20, `c6a.xlarge`): enclave `State: RUNNING`
with valid PCR0/1/2, a 6120-byte COSE_Sign1 attestation document, and
`chain_key_commitment: len=0`. The client refused, which is the only reason
this presented as a failed deploy instead of a TEE serving traffic with four
gates switched off.

This test pins the invariant at the level that broke: the set of sibling
modules the app template imports must be a subset of what the Dockerfile
copies.
"""

import pathlib
import re

import pytest

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "tee_crafter"
TEMPLATES = SRC / "templates"
DOCKERFILE = TEMPLATES / "common" / "Dockerfile.container.template"

#: Platform app templates that run *inside* a container-as-enclave.
IN_CONTAINER_APP_TEMPLATES = ["nitro/app_vsock.template.py"]

#: Imported by the app but deliberately NOT in the image: these run on the VM
#: host, not inside the enclave.
HOST_SIDE_ONLY: set[str] = set()

_SIBLING_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+((?:tee_crafter_|siem_|byok_)[a-z0-9_]+)",
    re.MULTILINE,
)


def _copied_modules() -> set[str]:
    """Module names (no .py) the Dockerfile copies into /tee-crafter-runtime."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    found = set()
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("COPY ") or "--from=" in line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        src, dest = parts[1], parts[2]
        if src.endswith(".py") and dest.startswith("/tee-crafter-runtime/"):
            found.add(src[:-3])
    return found


def _imported_siblings(rel: str) -> set[str]:
    text = (TEMPLATES / rel).read_text(encoding="utf-8")
    # The app imports itself nowhere, but a module may reference its own name in
    # a docstring or a nested import; drop the app's own stem defensively.
    own = pathlib.Path(rel).name.replace(".template.py", "")
    return {m for m in _SIBLING_IMPORT.findall(text) if m != own}


class TestEnclaveRuntimeModulesAreCopied:
    def test_dockerfile_copies_something(self):
        """Guard the parser itself: an empty set would make everything pass."""
        assert len(_copied_modules()) >= 5, _copied_modules()

    def test_app_template_imports_are_detected(self):
        """Guard the regex: zero imports would make the real test vacuous."""
        found = _imported_siblings(IN_CONTAINER_APP_TEMPLATES[0])
        assert "tee_crafter_audit_logger" in found
        assert "tee_crafter_runtime_bootstrap" in found
        assert len(found) >= 5, found

    @pytest.mark.parametrize("rel", IN_CONTAINER_APP_TEMPLATES)
    def test_every_imported_module_is_copied(self, rel):
        imported = _imported_siblings(rel)
        copied = _copied_modules()
        missing = sorted(imported - copied - HOST_SIDE_ONLY)
        assert not missing, (
            f"{rel} imports {missing} but Dockerfile.container.template does not "
            "COPY them into /tee-crafter-runtime. Because those imports are "
            "`except ImportError: pass`, the gates they install would be "
            "silently inert inside the enclave."
        )

    def test_transitive_sibling_imports_are_copied(self):
        """A copied module's own sibling imports must be satisfied too.

        `tee_crafter_runtime_bootstrap` imports `tee_crafter_audit_logger`; if
        only the former were copied, `bootstrap_chain_commitment()` would fail
        at runtime for a second, less obvious reason.
        """
        copied = _copied_modules()
        common = TEMPLATES / "common"
        missing = {}
        for name in sorted(copied):
            path = common / f"{name}.py"
            if not path.is_file():
                continue
            deps = {m for m in _SIBLING_IMPORT.findall(path.read_text(encoding="utf-8"))
                    if m != name}
            gap = sorted(deps - copied - HOST_SIDE_ONLY)
            if gap:
                missing[name] = gap
        assert not missing, f"transitive imports not copied into the image: {missing}"

    def test_copied_modules_exist_in_the_package(self):
        """A COPY of a file that isn't staged would fail the docker build.

        `app_vsock.py` is exempt: it is rendered from the platform template
        into the build directory at build time rather than shipped in
        `templates/common/`.
        """
        generated = {"app_vsock"}
        common = TEMPLATES / "common"
        absent = [n for n in sorted(_copied_modules() - generated)
                  if not (common / f"{n}.py").is_file()]
        assert not absent, f"Dockerfile COPYs modules that do not exist: {absent}"
