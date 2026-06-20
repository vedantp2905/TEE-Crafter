"""One interpretation of boolean environment variables.

Four different truthy sets had grown up independently across the tree --
``("1","true","yes")``, that plus ``"on"``, that plus ``"y"``, and
``("1","true","y","yes")``.  The consequence was that ``on`` was honoured at
some call sites and silently ignored at others, so the same spelling meant
opposite things depending on which module happened to read it.

The direction of the mistake is what matters.  Two categories of flag exist and
they need opposite treatment of a value nobody anticipated:

``env_gate_enabled``
    A protection that is ON by default and may be switched off deliberately --
    ``TEE_CRAFTER_STRICT_TSM``, ``TEE_CRAFTER_NRAS_STRICT``,
    ``TEE_CRAFTER_HANDLER_SANDBOX``.  Only a *recognised falsy* value disables
    it.  A typo, a synonym nobody listed, a stray quote: the protection stays
    on.  Writing ``=true`` here must never be the thing that turns a check off,
    which is precisely what an ``== "1"`` comparison used to do.

``env_hatch_open``
    An opt-in escape hatch that is OFF by default -- ``TEE_CRAFTER_ALLOW_*``,
    ``TEE_CRAFTER_SKIP_*``, ``TEE_CRAFTER_*_FAIL_OPEN``.  Only a *recognised
    truthy* value opens it, so an unrecognised value leaves the safe behaviour
    in place.

Both therefore resolve an unrecognised value to the safe state, but "safe" is
the opposite constant in each case, which is why one function cannot serve both.

``env_flag`` is for genuinely neutral settings where neither state is safer
(``TEE_CRAFTER_KEEPALIVE``, ``TEE_CRAFTER_SPOT``): an unrecognised value falls
back to the caller's stated default.

Templates under ``tee_crafter/templates`` cannot import this module.  They are
rendered and copied onto the instance -- and the ``client.template.py``
verifiers are handed to whoever checks the attestation -- so they carry no
dependency on the installed package.  Those files repeat the tuples locally and
must stay in step; ``tests/core/test_env_flag_consistency.py`` asserts that they
do.
"""
from __future__ import annotations

import os
from typing import Optional

__all__ = [
    "TRUTHY",
    "FALSY",
    "env_flag",
    "env_gate_enabled",
    "env_hatch_open",
    "interpret",
]

#: Spellings accepted as true.  Extend both tuples together, never one alone.
TRUTHY = ("1", "true", "yes", "y", "on")

#: Spellings accepted as false.
FALSY = ("0", "false", "no", "n", "off")


def interpret(raw: Optional[str]) -> Optional[bool]:
    """``True`` / ``False`` for a recognised spelling, ``None`` otherwise.

    ``None`` covers both "unset" and "set to something we do not understand",
    because the caller wants the same treatment for each: fall back to whatever
    is safe for that particular flag.
    """
    if raw is None:
        return None
    v = raw.strip().lower()
    if v in TRUTHY:
        return True
    if v in FALSY:
        return False
    return None


def env_flag(name: str, *, default: bool) -> bool:
    """A neutral setting: unset or unrecognised yields *default*."""
    got = interpret(os.environ.get(name))
    return default if got is None else got


def env_gate_enabled(name: str) -> bool:
    """A protection that is on unless explicitly switched off.

    Returns ``False`` only for a recognised falsy spelling.
    """
    return interpret(os.environ.get(name)) is not False


def env_hatch_open(name: str) -> bool:
    """An opt-in hatch that stays shut unless explicitly opened.

    Returns ``True`` only for a recognised truthy spelling.
    """
    return interpret(os.environ.get(name)) is True
