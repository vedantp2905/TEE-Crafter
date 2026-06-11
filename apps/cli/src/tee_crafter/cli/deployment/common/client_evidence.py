"""Persist what the verifier actually reasoned, not just its verdict.

Every generated client prints its verification chain to **stderr** -- which
binding mode held, whether the NRAS nonce echo matched, whether the attestation
key chained to AMD-signed evidence, which measurement it compared against -- and
its result to stdout.  Six deploy paths ran a client and saved only stdout.

That is the wrong way round for this project.  The product is verifiable
evidence, so the verifier's reasoning is the interesting artefact; a bare
``client_output.json`` plus exit code 0 means a *successful* run is harder to
audit after the fact than a failing one, because a failure at least prints its
reason into the abort message.  Worse, the stderr was already being parsed in
memory for the attestation report and then dropped, so the information existed
and was deliberately discarded.

This module is the single place that writes it down, so the six call sites cannot
drift apart again.
"""
from __future__ import annotations

import json
import os
from typing import Optional

#: Written next to ``client_output.json`` in the build directory.
STDERR_FILENAME = "client_stderr.log"


def save_client_evidence(
    build_dir: str,
    stdout: str,
    stderr: str,
    *,
    success: bool = True,
    console=None,
    pretty_json: bool = True,
) -> dict:
    """Write the client's streams into *build_dir*.

    Returns ``{"stdout": <path or "">, "stderr": <path or "">}``.

    Saves on failure as well as success. A failed verification is exactly when
    the reasoning matters most, and the console panel that currently shows it
    scrolls away.

    Never raises. This runs after a deploy has already succeeded or failed, and
    an unwritable build directory must not change that outcome -- it downgrades
    to a console note instead.
    """
    paths = {"stdout": "", "stderr": ""}

    if stdout:
        # Keep the existing shape: pretty JSON when it parses, raw text when it
        # does not, so downstream readers of client_output.json are unaffected.
        target = os.path.join(build_dir, "client_output.json")
        payload = stdout
        if pretty_json:
            try:
                payload = json.dumps(json.loads(stdout), indent=2)
            except (ValueError, TypeError):
                target = os.path.join(build_dir, "client_output.txt")
        try:
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(payload)
            paths["stdout"] = target
        except OSError as exc:
            if console:
                console.print(f"[yellow]Could not save client output: {exc}[/yellow]")

    if stderr:
        target = os.path.join(build_dir, STDERR_FILENAME)
        try:
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(stderr)
            paths["stderr"] = target
        except OSError as exc:
            if console:
                console.print(
                    f"[yellow]Could not save client verification log: {exc}[/yellow]")

    if console:
        if paths["stdout"]:
            console.print(f"[dim]Client output saved to: {paths['stdout']}[/dim]")
        if paths["stderr"]:
            label = "verification log" if success else "failure log"
            console.print(
                f"[dim]Client {label} saved to: {paths['stderr']}[/dim]")
        elif not stderr:
            # Silence from a verifier is worth a line: it means either the client
            # logged nothing, or it was not the client this project generated.
            console.print(
                "[dim]Client produced no stderr, so no verification reasoning "
                "was recorded.[/dim]")

    return paths


def record_client_evidence_paths(audit, paths: dict,
                                 phase: str = "Phase 5: Post-Deploy",
                                 note: Optional[str] = None) -> None:
    """Bind the artefact paths into the audit chain, if there is one."""
    if not audit or not (paths.get("stdout") or paths.get("stderr")):
        return
    audit.record(
        phase, "Client verification evidence retained", "pass",
        client_output=os.path.basename(paths.get("stdout") or ""),
        client_stderr=os.path.basename(paths.get("stderr") or ""),
        note=note or ("The verifier's own reasoning, not just its verdict. "
                      "Replay it against the attestation report to see which "
                      "checks ran."),
    )


__all__ = ["STDERR_FILENAME", "record_client_evidence_paths",
           "save_client_evidence"]
