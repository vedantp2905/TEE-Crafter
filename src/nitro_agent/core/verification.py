import os
import shutil
import subprocess
import tempfile
import datetime
from typing import Tuple

try:
    from pyflakes.api import check as pyflakes_check
    from pyflakes.reporter import Reporter as PyflakesReporter
except ImportError:
    pyflakes_check = None
    PyflakesReporter = None


def verify_python_compile(code: str) -> Tuple[bool, str]:
    """
    Validates vsock Python code using pyflakes (syntax + undefined names).
    Catches e.g. missing `from typing import Any`. Error message is fed back to the LLM.
    Requires pyflakes to be installed; raises ValueError if not.
    """
    if pyflakes_check is None or PyflakesReporter is None:
        raise ValueError(
            "pyflakes is required for vsock validation. Install with: pip install pyflakes"
        )
    from io import StringIO
    err_stream = StringIO()
    warn_stream = StringIO()
    reporter = PyflakesReporter(warn_stream, err_stream)
    count = pyflakes_check(code, "app_vsock.py", reporter)
    if count == 0:
        return True, ""
    out = (warn_stream.getvalue() + " " + err_stream.getvalue()).strip()

    # Allow certain non-fatal style warnings (like unused imports/variables)
    if out:
        lines = [ln for ln in out.splitlines() if ln.strip()]
        def _is_non_fatal(line: str) -> bool:
            return (" imported but unused" in line) or (" assigned to but never used" in line)
        if lines and all(_is_non_fatal(ln) for ln in lines):
            return True, ""

    return False, out or "pyflakes reported issues"


def verify_dockerfile_build(
    dockerfile_content: str,
    source_dir: str | None = None,
    vsock_content: str | None = None,
) -> Tuple[bool, str]:
    """
    Validates Dockerfile content by running `docker build`.

    If source_dir and vsock_content are provided, the build context is a copy of
    source_dir with app_vsock.py and Dockerfile written in (so COPY domain/, COPY io/, etc.
    succeed). Otherwise uses a minimal context with stub files only.
    Returns (True, stdout) if build succeeds, or (False, error_message) if it fails.
    """
    if not shutil.which("docker"):
        return False, "Docker is not installed or not in PATH."

    ignore_patterns = shutil.ignore_patterns(
        "venv", ".venv", ".git", "__pycache__", "*.pyc", ".cursor", "node_modules", "build_*", ".env"
    )
    tmpdir = tempfile.mkdtemp(prefix=".nitro_dockerfile_verify_")
    try:
        if source_dir and os.path.isdir(source_dir) and vsock_content is not None:
            # Full context: copy source tree so COPY domain/, COPY io/, etc. exist
            for item in os.listdir(source_dir):
                s = os.path.join(source_dir, item)
                d = os.path.join(tmpdir, item)
                if os.path.isdir(s) and item not in (".git", "__pycache__", ".cursor", "node_modules", "venv", ".venv"):
                    shutil.copytree(s, d, ignore=ignore_patterns)
                elif os.path.isfile(s):
                    shutil.copy2(s, d)
            with open(os.path.join(tmpdir, "app_vsock.py"), "w", encoding="utf-8") as f:
                f.write(vsock_content)
            if not os.path.isfile(os.path.join(tmpdir, "requirements.txt")):
                with open(os.path.join(tmpdir, "requirements.txt"), "w", encoding="utf-8") as f:
                    f.write("")
        else:
            # Minimal context: stubs only
            with open(os.path.join(tmpdir, "app_vsock.py"), "w", encoding="utf-8") as f:
                f.write("# stub for Dockerfile build verification\nprint('ok')\n")
            with open(os.path.join(tmpdir, "app.py"), "w", encoding="utf-8") as f:
                f.write("# stub for Dockerfile build verification\n")
            with open(os.path.join(tmpdir, "requirements.txt"), "w", encoding="utf-8") as f:
                f.write("")

        with open(os.path.join(tmpdir, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write(dockerfile_content)

        tag_name = f"nitro-dockerfile-verify-{datetime.datetime.now().strftime('%H%M%S')}"
        result = subprocess.run(
            ["docker", "build", "-t", tag_name, "."],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            check=True,
        )
        subprocess.run(["docker", "rmi", tag_name], capture_output=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, f"Docker Build Failed:\n{e.stderr or ''}\n{e.stdout or ''}"
    except Exception as e:
        return False, str(e)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def verify_docker_build(build_dir: str) -> Tuple[bool, str]:
    """
    Attempts to build the Dockerfile in the specified directory.
    This acts as a 'dry run' to verify dependencies and Dockerfile syntax.
    Returns (True, build_output) or (False, error_output).
    """
    if not shutil.which("docker"):
        return False, "Docker is not installed or not in PATH."

    timestamp = datetime.datetime.now().strftime("%H%M%S")
    tag_name = f"nitro-verify-{timestamp}"

    try:
        result = subprocess.run(
            ["docker", "build", "-t", tag_name, "."],
            cwd=build_dir,
            capture_output=True,
            text=True,
            check=True
        )
        subprocess.run(["docker", "rmi", tag_name], capture_output=True)
        return True, result.stdout

    except subprocess.CalledProcessError as e:
        return False, f"Docker Build Failed:\n{e.stderr}\n{e.stdout}"
    except Exception as e:
        return False, f"Verification Error: {str(e)}"


def verify_app_is_not_server(source_dir: str) -> Tuple[bool, str]:
    """
    Best-effort heuristic to ensure the user's app looks like a
    batch-style script with a main entrypoint, not a long-running server.

    We do NOT try to be perfect here; we just guard against obvious cases
    like FastAPI/Flask/uvicorn-style servers.
    """
    forbidden_markers = [
        "FastAPI(",
        "flask.",
        "Flask(",
        "uvicorn.run",
        "app.run(",
        "HTTPServer(",
        "TCPServer(",
        "web.run_app(",
    ]

    has_main_guard = False

    for root, _, files in os.walk(source_dir):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            path = os.path.join(root, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except OSError:
                continue

            # Check for an explicit `if __name__ == "__main__":` block anywhere
            if "__name__ == \"__main__\"" in content or "__name__ == '__main__'" in content:
                has_main_guard = True

            # Guard against obviously server-like frameworks
            if any(marker in content for marker in forbidden_markers):
                return False, (
                    f"Detected server-like code in {path}. "
                    "Phase 1 expects a batch-style script with a main entrypoint, not an HTTP server."
                )

    if not has_main_guard:
        return False, (
            "Could not find an `if __name__ == \"__main__\"` style entrypoint. "
            "Phase 1 expects a script-style app with a clear main entry function."
        )

    return True, ""
