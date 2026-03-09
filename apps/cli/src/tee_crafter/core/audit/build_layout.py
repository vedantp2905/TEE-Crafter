"""Centralised build-directory layout.

Every TEE-Crafter build writes (and later reads) a forest of artefacts
into the same per-build directory.  Historically these all lived
flat at the top of ``builds/<id>/`` which made it hard for an operator
to see at a glance what was what.

This module is the single source of truth for the on-disk layout::

    builds/<id>/
    ├── audit/                  audit evidence ledger (json/txt/md/html + sig)
    ├── provenance/             hash-chained build provenance (json/txt + sig + pubkey)
    ├── slsa/                   SLSA in-toto statement + DSSE envelope + pubkey
    ├── siem/                   SIEM config (json + sanitised env + egress allowlist)
    ├── byok/                   BYOK config (json + sanitised env)
    ├── compliance/             rendered compliance reports (existing)
    ├── probes/                 post-deploy probe stdout/stderr (existing)
    └── ... runtime + terraform staging stay at the top level so the
            terraform/uploader code-paths don't need to chdir.

All read-paths fall back to the legacy top-level filename when the
subdir copy isn't present, so older builds keep verifying with
``tee-crafter verify-provenance`` without any migration step.

Use these helpers wherever you would otherwise call
``os.path.join(build_dir, "audit_evidence.json")`` etc.
"""
from __future__ import annotations

import os
from typing import Iterable

# Subdirectory names.  Exposed as module-level constants so call-sites
# never literal-string a path twice (and so the layout doc above is
# the only place an operator has to look).
AUDIT_DIR = "audit"
PROVENANCE_DIR = "provenance"
SLSA_DIR = "slsa"
SIEM_DIR = "siem"
BYOK_DIR = "byok"
COMPLIANCE_DIR = "compliance"
PROBES_DIR = "probes"

_ALL_SUBDIRS: tuple[str, ...] = (
    AUDIT_DIR, PROVENANCE_DIR, SLSA_DIR, SIEM_DIR, BYOK_DIR,
    COMPLIANCE_DIR, PROBES_DIR,
)


# --------------------------------------------------------------------------- #
# Directory accessors
# --------------------------------------------------------------------------- #

def audit_dir(build_dir: str) -> str:
    return os.path.join(build_dir, AUDIT_DIR)


def provenance_dir(build_dir: str) -> str:
    return os.path.join(build_dir, PROVENANCE_DIR)


def slsa_dir(build_dir: str) -> str:
    return os.path.join(build_dir, SLSA_DIR)


def siem_dir(build_dir: str) -> str:
    return os.path.join(build_dir, SIEM_DIR)


def byok_dir(build_dir: str) -> str:
    return os.path.join(build_dir, BYOK_DIR)


def ensure_dirs(build_dir: str) -> None:
    """Create every layout subdir under *build_dir* (idempotent)."""
    for sub in _ALL_SUBDIRS:
        try:
            os.makedirs(os.path.join(build_dir, sub), exist_ok=True)
        except OSError:
            # Permission/IO issues are surfaced when we actually try to
            # write a file; ``ensure_dirs`` is best-effort.
            pass


# --------------------------------------------------------------------------- #
# Individual artefact paths (writers use these)
# --------------------------------------------------------------------------- #

# ── Audit evidence ledger ────────────────────────────────────────────────── #
def audit_evidence_json(build_dir: str) -> str:
    return os.path.join(audit_dir(build_dir), "audit_evidence.json")


def audit_evidence_txt(build_dir: str) -> str:
    return os.path.join(audit_dir(build_dir), "audit_evidence.txt")


def audit_evidence_md(build_dir: str) -> str:
    return os.path.join(audit_dir(build_dir), "audit_evidence.md")


def audit_evidence_html(build_dir: str) -> str:
    return os.path.join(audit_dir(build_dir), "audit_evidence.html")


def audit_evidence_sig(build_dir: str) -> str:
    return os.path.join(audit_dir(build_dir), "audit_evidence.sig")


def audit_evidence_key_kind(build_dir: str) -> str:
    return os.path.join(audit_dir(build_dir), "audit_evidence.key_kind.txt")


def audit_evidence_signing_error(build_dir: str) -> str:
    return os.path.join(audit_dir(build_dir), "audit_evidence.signing_error.txt")


# ── Build provenance hash chain ──────────────────────────────────────────── #
def provenance_json(build_dir: str) -> str:
    return os.path.join(provenance_dir(build_dir), "build_provenance.json")


def provenance_txt(build_dir: str) -> str:
    return os.path.join(provenance_dir(build_dir), "build_provenance.txt")


def provenance_sig(build_dir: str) -> str:
    return os.path.join(provenance_dir(build_dir), "build_provenance.sig")


def provenance_pub(build_dir: str) -> str:
    return os.path.join(provenance_dir(build_dir), "build_provenance.pub")


def provenance_pub_fpr(build_dir: str) -> str:
    return os.path.join(provenance_dir(build_dir), "build_provenance.pub.sha256")


def provenance_key_kind(build_dir: str) -> str:
    return os.path.join(provenance_dir(build_dir), "build_provenance.key_kind.txt")


def provenance_signing_error(build_dir: str) -> str:
    return os.path.join(
        provenance_dir(build_dir), "build_provenance.signing_error.txt")


# ── SLSA in-toto statement + DSSE envelope ──────────────────────────────── #
def slsa_intoto(build_dir: str) -> str:
    return os.path.join(slsa_dir(build_dir), "slsa_provenance.intoto.json")


def slsa_dsse(build_dir: str) -> str:
    return os.path.join(slsa_dir(build_dir), "slsa_provenance.dsse.json")


def slsa_pub(build_dir: str) -> str:
    return os.path.join(slsa_dir(build_dir), "slsa_provenance.pub")


# ── SIEM ───────────────────────────────────────────────────────────────── #
def siem_json(build_dir: str) -> str:
    return os.path.join(siem_dir(build_dir), "siem.json")


def siem_env(build_dir: str) -> str:
    """Secret-bearing SIEM env file.  Always shredded post-teardown."""
    return os.path.join(siem_dir(build_dir), "siem.env")


def siem_env_public(build_dir: str) -> str:
    return os.path.join(siem_dir(build_dir), "siem.env.public")


def siem_egress_json(build_dir: str) -> str:
    return os.path.join(siem_dir(build_dir), "siem_egress.json")


# ── BYOK ───────────────────────────────────────────────────────────────── #
def byok_json(build_dir: str) -> str:
    return os.path.join(byok_dir(build_dir), "byok.json")


def byok_env(build_dir: str) -> str:
    """Secret-bearing BYOK env file.  Always shredded post-teardown."""
    return os.path.join(byok_dir(build_dir), "byok.env")


def byok_env_public(build_dir: str) -> str:
    return os.path.join(byok_dir(build_dir), "byok.env.public")


# --------------------------------------------------------------------------- #
# Back-compat readers
# --------------------------------------------------------------------------- #

def resolve(
    build_dir: str,
    *candidate_relpaths: str,
) -> str:
    """Return the first *candidate_relpath* that exists under *build_dir*.

    Used by every reader so an old (flat) build directory keeps working
    after we land the new layout.  Pass new layout first, then the
    legacy path::

        prov = resolve(build_dir,
                       "provenance/build_provenance.json",
                       "build_provenance.json")

    Returns the resolved absolute path, or the *last* candidate joined
    onto *build_dir* (so callers still get a deterministic path for
    error messages when nothing exists).
    """
    fallback = build_dir
    for rel in candidate_relpaths:
        p = os.path.join(build_dir, rel)
        if os.path.exists(p):
            return p
        fallback = p
    return fallback


def resolve_provenance_json(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(PROVENANCE_DIR, "build_provenance.json"),
                   "build_provenance.json")


def resolve_provenance_sig(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(PROVENANCE_DIR, "build_provenance.sig"),
                   "build_provenance.sig")


def resolve_provenance_pub(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(PROVENANCE_DIR, "build_provenance.pub"),
                   "build_provenance.pub")


def resolve_provenance_pub_fpr(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(PROVENANCE_DIR, "build_provenance.pub.sha256"),
                   "build_provenance.pub.sha256")


def resolve_provenance_key_kind(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(PROVENANCE_DIR, "build_provenance.key_kind.txt"),
                   "build_provenance.key_kind.txt")


def resolve_audit_evidence_json(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(AUDIT_DIR, "audit_evidence.json"),
                   "audit_evidence.json")


def resolve_audit_evidence_sig(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(AUDIT_DIR, "audit_evidence.sig"),
                   "audit_evidence.sig")


def resolve_audit_evidence_key_kind(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(AUDIT_DIR, "audit_evidence.key_kind.txt"),
                   "audit_evidence.key_kind.txt")


def resolve_slsa_intoto(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(SLSA_DIR, "slsa_provenance.intoto.json"),
                   "slsa_provenance.intoto.json")


def resolve_slsa_dsse(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(SLSA_DIR, "slsa_provenance.dsse.json"),
                   "slsa_provenance.dsse.json")


def resolve_siem_json(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(SIEM_DIR, "siem.json"),
                   "siem.json")


def resolve_siem_env(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(SIEM_DIR, "siem.env"),
                   "siem.env")


def resolve_siem_env_public(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(SIEM_DIR, "siem.env.public"),
                   "siem.env.public")


def resolve_byok_json(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(BYOK_DIR, "byok.json"),
                   "byok.json")


def resolve_byok_env(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(BYOK_DIR, "byok.env"),
                   "byok.env")


def resolve_byok_env_public(build_dir: str) -> str:
    return resolve(build_dir,
                   os.path.join(BYOK_DIR, "byok.env.public"),
                   "byok.env.public")


# --------------------------------------------------------------------------- #
# Evidence pointers (relative paths recorded into the audit ledger)
# --------------------------------------------------------------------------- #

EVIDENCE_PROVENANCE_JSON = f"{PROVENANCE_DIR}/build_provenance.json"
EVIDENCE_PROVENANCE_SIG = f"{PROVENANCE_DIR}/build_provenance.sig"
EVIDENCE_PROVENANCE_PUB = f"{PROVENANCE_DIR}/build_provenance.pub"
EVIDENCE_PROVENANCE_KEY_KIND = f"{PROVENANCE_DIR}/build_provenance.key_kind.txt"
EVIDENCE_PROVENANCE_TXT = f"{PROVENANCE_DIR}/build_provenance.txt"
EVIDENCE_AUDIT_JSON = f"{AUDIT_DIR}/audit_evidence.json"
EVIDENCE_AUDIT_SIG = f"{AUDIT_DIR}/audit_evidence.sig"
EVIDENCE_SLSA_INTOTO = f"{SLSA_DIR}/slsa_provenance.intoto.json"
EVIDENCE_SLSA_DSSE = f"{SLSA_DIR}/slsa_provenance.dsse.json"
EVIDENCE_SIEM_JSON = f"{SIEM_DIR}/siem.json"
EVIDENCE_SIEM_EGRESS = f"{SIEM_DIR}/siem_egress.json"
EVIDENCE_BYOK_JSON = f"{BYOK_DIR}/byok.json"


# --------------------------------------------------------------------------- #
# Shredding helpers
# --------------------------------------------------------------------------- #

def secret_files_to_shred(build_dir: str) -> Iterable[str]:
    """Yield every secret file under *build_dir* the post-destroy
    shredder must overwrite/unlink.  Includes both the new subdir
    locations and the legacy top-level + app-staging copies so a
    half-migrated build dir still gets cleaned up properly.
    """
    rels = [
        # New layout
        os.path.join(SIEM_DIR, "siem.env"),
        os.path.join(BYOK_DIR, "byok.env"),
        # Legacy top-level (pre-layout-refactor builds)
        "siem.env",
        "byok.env",
        # In-TEE bundle staging (still flat by design)
        os.path.join("app", "siem.env"),
        os.path.join("app", "byok.env"),
    ]
    for rel in rels:
        yield os.path.join(build_dir, rel)


__all__ = [
    # constants
    "AUDIT_DIR", "PROVENANCE_DIR", "SLSA_DIR", "SIEM_DIR", "BYOK_DIR",
    "COMPLIANCE_DIR", "PROBES_DIR",
    # dirs
    "audit_dir", "provenance_dir", "slsa_dir", "siem_dir", "byok_dir",
    "ensure_dirs",
    # writers
    "audit_evidence_json", "audit_evidence_txt", "audit_evidence_md",
    "audit_evidence_html", "audit_evidence_sig", "audit_evidence_key_kind",
    "audit_evidence_signing_error",
    "provenance_json", "provenance_txt", "provenance_sig",
    "provenance_pub", "provenance_pub_fpr", "provenance_key_kind",
    "provenance_signing_error",
    "slsa_intoto", "slsa_dsse", "slsa_pub",
    "siem_json", "siem_env", "siem_env_public", "siem_egress_json",
    "byok_json", "byok_env", "byok_env_public",
    # readers
    "resolve",
    "resolve_provenance_json", "resolve_provenance_sig",
    "resolve_provenance_pub", "resolve_provenance_pub_fpr",
    "resolve_provenance_key_kind",
    "resolve_audit_evidence_json", "resolve_audit_evidence_sig",
    "resolve_audit_evidence_key_kind",
    "resolve_slsa_intoto", "resolve_slsa_dsse",
    "resolve_siem_json", "resolve_siem_env", "resolve_siem_env_public",
    "resolve_byok_json", "resolve_byok_env", "resolve_byok_env_public",
    # evidence pointers
    "EVIDENCE_PROVENANCE_JSON", "EVIDENCE_PROVENANCE_SIG",
    "EVIDENCE_PROVENANCE_PUB", "EVIDENCE_PROVENANCE_KEY_KIND",
    "EVIDENCE_PROVENANCE_TXT",
    "EVIDENCE_AUDIT_JSON", "EVIDENCE_AUDIT_SIG",
    "EVIDENCE_SLSA_INTOTO", "EVIDENCE_SLSA_DSSE",
    "EVIDENCE_SIEM_JSON", "EVIDENCE_SIEM_EGRESS",
    "EVIDENCE_BYOK_JSON",
    # shredder
    "secret_files_to_shred",
]
