"""CLI constants and plain stdout output (no Rich)."""

from __future__ import annotations

import re
import sys
from typing import Any, TextIO

PIPELINE_VERSION = "0.1.0"

#: Set by ``deploy --keep-on-failure`` / ``deploy-from-build --keep-on-failure``.
#: When unset (the default) every deployment phase tears its infrastructure down
#: after a failed ``terraform apply`` or a failed post-deploy automation run,
#: instead of leaving the instance — and any NAT gateway — billing until an
#: operator notices and runs ``tee-crafter destroy``.  It is an environment
#: variable rather than a plumbed-through argument because the phase modules are
#: also driven by the SaaS orchestrator, which does not go through Click.
KEEP_ON_FAILURE_ENV = "TEE_CRAFTER_KEEP_ON_FAILURE"


def keep_on_failure() -> bool:
    """Whether failed deployments should leave their infrastructure running."""
    import os
    return os.environ.get(KEEP_ON_FAILURE_ENV, "").strip().lower() in (
        "1", "true", "yes", "y", "on")

#: Style words that may appear inside a markup tag.  Anything bracketed that is
#: *not* built only from these is left alone — see :func:`strip_rich_markup`.
_STYLE_WORDS = frozenset({
    # colours (and their bright_/on- forms, handled below)
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
    "grey", "gray",
    # attributes
    "bold", "dim", "italic", "underline", "underline2", "strike", "reverse",
    "blink", "blink2", "conceal", "frame", "encircle", "overline", "none",
    # modifiers
    "on", "not", "default",
})

#: Hex and ``color(N)`` literals count as style tokens.  A **bare** number does
#: not, even though rich would read ``[3]`` as colour 3: nothing in this
#: codebase emits a numeric colour tag, while 24 call sites format messages like
#: ``event[3]: digest mismatch`` — and silently turning those into ``event:``
#: loses the index that says *which* event failed.
_COLOUR_LITERAL_RE = re.compile(r"^(?:#[0-9a-fA-F]{3,8}|color\(\d{1,3}\))$")


def _is_markup_tag(body: str) -> bool:
    """Whether ``[body]`` is a style tag rather than ordinary bracketed text.

    A tag is a closing marker (``/``, ``/green``), a ``link=…``, or a run of
    whitespace-separated style words / colour literals (``bold red``,
    ``on #ff0000``).  Everything else — ``[tee-crafter-batch.service]``,
    ``[azurerm_linux_virtual_machine]``, ``[3]`` — is content.
    """
    body = body.strip()
    if not body:
        return False
    if body.startswith("/"):
        rest = body[1:].strip()
        return not rest or _is_markup_tag(rest)
    if body.startswith("link=") or body == "link":
        return True
    tokens = body.split()
    if not tokens:
        return False
    return all(
        tok.lower() in _STYLE_WORDS
        or tok.lower().startswith(("bright_", "on_"))
        or _COLOUR_LITERAL_RE.match(tok)
        for tok in tokens
    )


_BRACKETED_RE = re.compile(r"\[([^\[\]]*)\]")


def strip_rich_markup(text: str) -> str:
    """Remove markup tags such as [bold], [/green], [link=…].

    Only *style* tags are removed.  The previous implementation stripped every
    bracketed run (``\\[[^\\]]*\\]``), which silently deleted ordinary content
    from operator-facing output: ``Running batch [{unit_name}] on the VM``
    printed as ``Running batch  on the VM``, losing the exact systemd unit an
    operator needs for ``journalctl -u``, and the residency report dropped each
    resource's ``[{type}]``.  Anything bracketed that is not built purely from
    style words is now left intact — see :func:`_is_markup_tag`.

    Kept iterative so nested leftovers still collapse.
    """
    prev = None
    cur = text
    while prev != cur:
        prev = cur
        cur = _BRACKETED_RE.sub(
            lambda m: "" if _is_markup_tag(m.group(1)) else m.group(0), cur,
        )
    return cur


class CliConsole:
    """Minimal stdout console for CLI messages."""

    def __init__(self, *args: Any, file: TextIO | None = None, **kwargs: Any) -> None:
        _ = args
        _ = kwargs
        # None → resolve sys.stdout at print time (Click CliRunner patches stdout per invoke).
        self._file = file

    def print(self, *objects: Any, **kwargs: Any) -> None:
        sep = str(kwargs.pop("sep", " "))
        end = str(kwargs.pop("end", "\n"))
        for key in (
            "highlight", "overflow", "crop", "soft_wrap", "emoji",
            "markup", "style", "justify",
        ):
            kwargs.pop(key, None)
        _ = kwargs
        chunks: list[str] = []
        for obj in objects:
            chunks.append(strip_rich_markup(str(obj)))
        msg = sep.join(chunks)
        if msg:
            out = self._file if self._file is not None else sys.stdout
            print(msg, file=out, end=end)


console = CliConsole()

# Type alias / constructor name used in annotations throughout the CLI.
Console = CliConsole


class Panel:
    """Plain-text panel rendered via ``console.print``."""

    def __init__(
        self,
        renderable: Any,
        *,
        title: str | None = None,
        subtitle: str | None = None,
        border_style: str | None = None,
        **kwargs: Any,
    ) -> None:
        _ = border_style
        _ = kwargs
        body = strip_rich_markup(str(renderable))
        title_text = strip_rich_markup(str(title)) if title else ""
        subtitle_text = strip_rich_markup(str(subtitle)) if subtitle else ""
        parts: list[str] = []
        if title_text:
            parts.append(title_text)
            parts.append("-" * max(len(title_text), 1))
        parts.append(body)
        if subtitle_text:
            parts.append("-" * max(len(subtitle_text), 1))
            parts.append(subtitle_text)
        self._text = "\n".join(parts)

    @classmethod
    def fit(cls, renderable: Any, **kwargs: Any) -> Panel:
        return cls(renderable, **kwargs)

    def __str__(self) -> str:
        return self._text

    def __repr__(self) -> str:
        return self._text


class Table:
    """Minimal plain-text table for CLI listings."""

    def __init__(self, *args: Any, title: str | None = None, **kwargs: Any) -> None:
        _ = args
        _ = kwargs
        self._title = strip_rich_markup(str(title)) if title else None
        self._columns: list[str] = []
        self._rows: list[list[str]] = []

    def add_column(self, header: str, **kwargs: Any) -> None:
        _ = kwargs
        self._columns.append(strip_rich_markup(str(header)))

    def add_row(self, *cells: Any) -> None:
        self._rows.append([strip_rich_markup(str(c)) for c in cells])

    def __str__(self) -> str:
        lines: list[str] = []
        if self._title:
            lines.append(self._title)
        if not self._columns:
            return "\n".join(lines)
        header = " | ".join(self._columns)
        lines.append(header)
        lines.append("-" * max(len(header), 1))
        for row in self._rows:
            lines.append(" | ".join(row))
        return "\n".join(lines)


class SpinnerColumn:
    """Ignored placeholder (progress compatibility)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _ = args
        _ = kwargs


class TextColumn:
    """Ignored placeholder (progress compatibility)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _ = args
        _ = kwargs


class Progress:
    """Logs deployment steps to stdout instead of rendering spinners."""

    def __init__(
        self,
        *columns: Any,
        console: CliConsole | None = None,
        transient: bool = True,
        **kwargs: Any,
    ) -> None:
        _ = columns
        _ = transient
        _ = kwargs
        self._console = console or CliConsole()

    def __enter__(self) -> Progress:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def add_task(
        self,
        description: str = "",
        *,
        total: int | float | None = None,
        **kwargs: Any,
    ) -> int:
        _ = total
        _ = kwargs
        msg = strip_rich_markup(description)
        if msg:
            self._console.print(msg)
        return 0

    def update(
        self,
        task_id: int,
        *,
        description: str | None = None,
        **kwargs: Any,
    ) -> None:
        _ = task_id
        _ = kwargs
        if description:
            self._console.print(strip_rich_markup(description))
