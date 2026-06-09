"""``tee-crafter verify-siem-chain`` — verify a SIEM-exported event chain.

The continuous-attestation sidecar emits AttestationEvent records that
form a forward-linked hash chain with per-boot Ed25519 signatures.
This command lets a SOC operator pull a window of events out of their
SIEM (Splunk / Datadog / Sentinel / CloudWatch) as a newline-delimited
JSON file and prove that:

* every event declares a wire-format version this build understands
  (unknown versions are rejected, never mis-verified);
* the chain is unbroken — a ``seq``-0 event carries the documented
  genesis ``prev_digest``, every later event's ``prev_digest`` equals
  its predecessor's ``digest``, and ``seq`` is strictly monotonic with
  no gaps;
* each event's signature over its own digest verifies against an
  **out-of-band** Ed25519 public key (``--pubkey`` / ``--pubkey-file`` /
  ``--pinned-pubkey-sha256``), and the key embedded in the event matches
  it.  Verifying against ``event["public_key_pem"]`` alone proves only
  internal consistency: anyone able to inject into the SIEM stream can
  present a self-consistent chain signed by their own key, so this
  command refuses to run without a trust anchor;
* every event carries the workload's runtime-audit-log chain-key
  commitment, constant across the window and optionally pinned to the
  value the enclave published in its attestation ``report_data``;
* the per-window ``measurement_sha256`` value (and optionally a list of
  pinned-expected ones) matches what the operator expects.

Any failure — including an empty event list — exits 2, so the command
can be plugged into a cron / GitHub-Action / Splunk-saved-search that
pages on drift.  A vacuous pass is the worst outcome here.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List, Optional, Tuple

import click

from tee_crafter.cli.constants import Panel, console
from tee_crafter.templates.common.siem_export import (
    GENESIS_PREV_DIGEST,
    SUPPORTED_SCHEMA_VERSIONS,
    compute_digest as _compute_digest_from_dict,
)


def _load_events(path: str) -> Tuple[List[Dict], List[str]]:
    """Parse newline-delimited JSON events.

    Returns ``(events, problems)`` rather than raising, so a malformed or
    empty export lands in the same exit-2 path as a broken chain instead
    of a different (or, for an empty file, a *passing*) one.
    """
    out: List[Dict] = []
    problems: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for ln_no, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError as e:
                problems.append(f"{path}:{ln_no}: not valid JSON ({e})")
                continue
            # Splunk HEC wraps the original event under "event": {...}.
            if isinstance(ev, dict) and isinstance(ev.get("event"), dict):
                ev = ev["event"]
            if not isinstance(ev, dict) or "digest" not in ev:
                problems.append(
                    f"{path}:{ln_no}: not an AttestationEvent "
                    f"(missing 'digest')")
                continue
            out.append(ev)
    return out, problems


#: Fields the producer always emits but a SIEM may drop when they are empty.
#: Only defaults that cannot change meaning belong here — an absent ``extra``
#: and an ``extra`` of ``{}`` are the same statement; an absent ``status`` is
#: not the same as ``"pass"``, so nothing like that may be added.
_EMPTY_DEFAULTS = {"extra": {}}


def _restore_dropped_empties(ev: Dict) -> Dict:
    """Put back fields the SIEM elided because they were empty.

    Datadog's Logs intake omits empty objects, so an event whose ``extra`` is
    ``{}`` — which is every host-sidecar event, since ``chain_key_commitment``
    is only attached when a workload process shares the sidecar's namespace —
    comes back out of the API without the key at all. The producer hashed
    ``"extra":{}`` into the digest, so recomputing without it fails on a stream
    that is in fact perfectly intact.

    Caught reading real ``nitro-aws`` events back out of Datadog on 2026-08-23:
    the hash chain linked correctly and every signature was over a digest the
    verifier could not reproduce. Restoring the default makes digests and
    signatures verify; nothing else is touched, so a genuinely altered event
    still fails.
    """
    out = dict(ev)
    for key, default in _EMPTY_DEFAULTS.items():
        if key not in out:
            out[key] = default
    return out


def _compute_digest(ev: Dict) -> str:
    """Recompute an event's digest using the producer's canonicalisation."""
    return _compute_digest_from_dict(_restore_dropped_empties(ev))


def _load_pubkey_pem(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# NOTE: there used to be a ``_default_pubkey_path`` here that picked up any
# ``build_provenance.pub`` sitting next to the events file or in the CWD and
# used it as the signing key. It is gone, and deliberately not replaced.
#
# That file holds the long-lived *build provenance* key. SIEM events are signed
# by a different key entirely — one the exporter generates per process
# (``siem_export.AttestationLoop.__init__``; ``_Ed25519Signer`` for the in-TEE
# path) — so the auto-discovered key was guaranteed to be the wrong one on every
# platform. It also outranked an explicit ``--pinned-pubkey-sha256``, so the
# natural operator move of dropping a SIEM export into its own build directory
# turned a passing verification into ``InvalidSignature`` on every event, naming
# neither the cause nor the file it had loaded.
#
# The right anchor is discovered from the signed ledger instead — see
# :func:`discover_recorded_signing_key`.


#: Signed build ledger the deploy pipeline writes.  Both layouts are searched:
#: the flat name (older artefacts) and the ``provenance/`` subdirectory the
#: current ``core.audit.build_layout`` uses.
_PROVENANCE_JSON_NAME = "build_provenance.json"
_PROVENANCE_RELPATHS = (
    _PROVENANCE_JSON_NAME,
    os.path.join("provenance", _PROVENANCE_JSON_NAME),
)


def _provenance_candidates(events_file: str) -> List[str]:
    """Every place a build ledger might sit relative to *events_file*.

    The directory holding the exported events, then the CWD — so an operator
    who drops a SIEM export next to the build artefacts gets both the recorded
    signing key and the attested commitment discovered by the same rule.

    Note this is now the *only* discovery path. It used to sit alongside a
    ``_default_pubkey_path`` that loaded a bare ``build_provenance.pub`` from
    the same two roots; that key never signs SIEM events, so it was removed —
    see the note where it used to live.
    """
    out: List[str] = []
    for base in (os.path.dirname(events_file), os.getcwd()):
        for rel in _PROVENANCE_RELPATHS:
            candidate = os.path.join(base, rel)
            if os.path.isfile(candidate) and candidate not in out:
                out.append(candidate)
    return out


def _commitments_in_provenance(doc: Dict) -> List[str]:
    """Distinct ``chain_key_commitment`` values recorded in a build ledger.

    The deploy pipeline funnels the verifier's ``ATTESTATION_REPORT`` fields
    through ``BuildAuditTrail.record(**measurement_fields)``, so the attested
    commitment lands in an entry's ``details``.  Returns every *distinct*
    value rather than the first one, because "which of these did you mean"
    is a question the caller has to refuse, not guess.
    """
    seen: List[str] = []
    entries = doc.get("entries")
    if not isinstance(entries, list):
        return seen
    for entry in entries:
        details = entry.get("details") if isinstance(entry, dict) else None
        if not isinstance(details, dict):
            continue
        val = details.get("chain_key_commitment")
        if not isinstance(val, str):
            continue
        val = val.strip().lower()
        # Same 64-hex discipline the clients and the report extractor apply;
        # a short or non-hex value is a malformed ledger, not a commitment.
        if len(val) != 64 or any(c not in "0123456789abcdef" for c in val):
            continue
        if val not in seen:
            seen.append(val)
    return seen


def _provenance_is_signed(provenance_path: str) -> bool:
    """True when a signature *and* a public key sit next to *provenance_path*.

    Distinguishing "never signed" from "signed and the signature is wrong"
    matters: the first is an unsigned development build, the second is
    tampering, and they deserve different outcomes.
    """
    from tee_crafter.core.audit import build_layout as _layout

    prov_dir = os.path.dirname(provenance_path)
    build_dir = (os.path.dirname(prov_dir)
                 if os.path.basename(prov_dir) == _layout.PROVENANCE_DIR
                 else prov_dir)
    return (os.path.isfile(_layout.resolve_provenance_sig(build_dir))
            and os.path.isfile(_layout.resolve_provenance_pub(build_dir)))


def _signing_keys_in_provenance(doc: Dict) -> List[str]:
    """Distinct ``siem_signing_key_sha256`` values recorded in a build ledger.

    Written by the deploy's ``SIEM sidecar install`` step
    (``cli/deployment/common/siem_sidecar.install_siem_sidecar``) from the
    fingerprint the exporter publishes in its SIEM-SEC-4 health file.  This is
    the anchor that did *not* arrive inside the events, which is the whole
    point: the exporter's key is generated per process and kept in memory, so
    verifying against the copy embedded in each event proves the stream is
    self-consistent and nothing more.

    Same 64-hex discipline as the commitment reader above — a short or non-hex
    value is a malformed ledger, not a fingerprint.
    """
    seen: List[str] = []
    entries = doc.get("entries")
    if not isinstance(entries, list):
        return seen
    for entry in entries:
        details = entry.get("details") if isinstance(entry, dict) else None
        if not isinstance(details, dict):
            continue
        val = details.get("siem_signing_key_sha256")
        if not isinstance(val, str):
            continue
        val = val.strip().lower()
        if len(val) != 64 or any(c not in "0123456789abcdef" for c in val):
            continue
        if val not in seen:
            seen.append(val)
    return seen


def discover_attested_chain_commitment(
    events_file: str,
) -> Tuple[Optional[str], str, str]:
    """Find the attested chain-key commitment in a nearby signed build ledger.

    Returns ``(commitment_hex, source_path, warning)``. ``commitment_hex`` is
    ``None`` when nothing usable was found, in which case the caller behaves as
    it did before this lookup existed. ``warning``, when non-empty, is a line
    the caller must show the operator.

    Three outcomes, because collapsing them is how this goes wrong:

    * **Signed and valid** — the commitment is returned and pinned.
    * **Never signed** (no ``build_provenance.sig``/``.pub`` alongside) — the
      commitment is *not* used, and a warning explains why. Trusting it would
      be worthless: an attacker who can rewrite the ledger to match forged
      events can also delete the signature, so "unsigned means trust it" is a
      bypass rather than a convenience. Failing hard instead would break every
      development build, where provenance is legitimately unsigned.
    * **Signed but invalid**, or a broken hash chain — :class:`click.ClickException`.
      Quietly falling back to "no expected value" would let tampering with the
      ledger *weaken* the check the ledger exists to strengthen, which is the
      fail-open shape this codebase keeps getting bitten by.

    Two ledgers that disagree, or one recording two different commitments, also
    raise: picking either silently would produce a pass that means nothing.
    """
    return _discover_ledger_value(
        events_file,
        extract=_commitments_in_provenance,
        noun="attested chain-key commitment",
        flag="--expect-chain-commitment <hex>",
    )


def _discover_ledger_value(
    events_file: str, *, extract, noun: str, flag: str,
) -> Tuple[Optional[str], str, str]:
    """Shared lookup behind the two ledger-discovered anchors.

    ``extract`` pulls the candidate values out of a parsed ledger; *noun*
    and *flag* only shape the operator-facing messages.  One implementation
    because the security-relevant part -- refuse a tampered ledger, ignore an
    unsigned one, never guess between two -- must not drift between the
    chain-key commitment and the SIEM signing key.
    """
    from tee_crafter.core.audit import BuildAuditTrail

    found: List[Tuple[str, str]] = []  # (commitment, source)
    warnings: List[str] = []
    for path in _provenance_candidates(events_file):
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            # An unreadable file in a search path is not evidence of anything;
            # keep looking.  A *readable* one that fails verification is not
            # the same thing and is handled below.
            continue
        if not isinstance(doc, dict):
            continue
        values = extract(doc)
        if not values:
            continue
        chain_ok, chain_reason = BuildAuditTrail.verify_chain(path)
        if not chain_ok:
            raise click.ClickException(
                f"{path} records a {noun} but its "
                f"hash chain does not verify: {chain_reason}\n"
                "Refusing to pin against a tampered ledger. Fix the artefact, "
                f"or pass {flag} explicitly.")
        if not _provenance_is_signed(path):
            warnings.append(
                f"{os.path.relpath(path)} records a {noun} "
                "but is UNSIGNED, so it is not being used. The "
                "events will only be checked for internal consistency. Sign "
                "the build provenance (see `tee-crafter audit-gen-signing-key`), "
                f"or pass {flag} explicitly.")
            continue
        sig_ok, sig_reason = BuildAuditTrail.verify_signature(path)
        if not sig_ok:
            raise click.ClickException(
                f"{path} records a {noun} and carries "
                f"a signature, but that signature does not verify: "
                f"{sig_reason}\n"
                "Refusing to pin against a ledger whose signature is wrong. "
                f"Pass {flag} explicitly if you have "
                "another reason to trust this value.")
        for c in values:
            found.append((c, path))

    distinct = sorted({c for c, _ in found})
    if not distinct:
        return None, "", "; ".join(warnings)
    if len(distinct) > 1:
        detail = "\n".join(f"  - {c} ({src})" for c, src in found)
        raise click.ClickException(
            f"found more than one {noun} near "
            f"{events_file}:\n{detail}\n"
            "These describe different workload instances, so no single value "
            f"can be pinned automatically. Pass {flag} to say which one "
            "this export belongs to.")
    return found[0][0], found[0][1], "; ".join(warnings)


def discover_recorded_signing_key(
    events_file: str,
) -> Tuple[Optional[str], str, str]:
    """Find the SIEM exporter's key fingerprint in a nearby signed ledger.

    Same three outcomes and the same refusals as
    :func:`discover_attested_chain_commitment` — see that docstring.

    This exists because the command's central promise was unmeetable. It
    refuses to check signatures without an out-of-band key, correctly, but
    nothing in the pipeline produced one: the exporter's Ed25519 key is
    generated per process and its only published copy rode inside the events
    it signed. The documented answer, ``--pubkey-file build_provenance.pub``,
    named the *build* signing key, which never signs an event and fails all of
    them. The deploy now records the fingerprint at sidecar-install time and
    this reads it back.
    """
    return _discover_ledger_value(
        events_file,
        extract=_signing_keys_in_provenance,
        noun="recorded SIEM signing-key fingerprint",
        flag="--pinned-pubkey-sha256 <hex>",
    )




#: Shown as the commitment's provenance when the operator named it explicitly.
OPERATOR_FLAG_SOURCE = "operator flag"


def resolve_expected_commitment(
    events_file: str,
    explicit: Optional[str],
    *,
    no_auto: bool = False,
    no_require: bool = False,
) -> Tuple[Optional[str], str, str]:
    """Decide which chain-key commitment the run should compare against.

    Split out of the Click callback so the precedence rules are testable
    without driving the whole command: an explicit ``--expect-chain-commitment``
    silently losing to a discovered value would be the worst outcome here, and
    that is not observable from the command's output on a failing run.

    Returns ``(commitment, source, warning)``.
    """
    if explicit:
        return explicit, OPERATOR_FLAG_SOURCE, ""
    # Nothing to pin against when the requirement itself was dropped, and
    # searching anyway would produce a confusing refusal on a tampered ledger
    # the operator never asked this command to read.
    if no_auto or no_require:
        return None, "", ""
    discovered, source, warning = discover_attested_chain_commitment(events_file)
    if not discovered:
        return None, "", warning
    return discovered, os.path.relpath(source), warning


def _verify_signature(ev: Dict, trusted_pem: Optional[str]) -> Tuple[bool, str]:
    """Verify ``ev["signature"]`` over ``ev["digest"]``.

    *trusted_pem*, when supplied, is the operator's out-of-band key and is
    the ONLY key the signature is checked against — the event's own
    ``public_key_pem`` is treated as an untrusted claim to be compared,
    not as a verification key.
    """
    sig_hex = ev.get("signature", "")
    pem = trusted_pem or ev.get("public_key_pem", "")
    if not pem or not sig_hex:
        return False, "missing signing key or signature"
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        pub = serialization.load_pem_public_key(pem.encode("ascii"))
        if not isinstance(pub, Ed25519PublicKey):
            return False, "public key is not Ed25519"
        pub.verify(bytes.fromhex(sig_hex), ev["digest"].encode("ascii"))
        return True, ""
    except Exception as e:
        return False, f"signature verification failed: {type(e).__name__}: {e}"


def pubkey_sha256(pem: str) -> Optional[str]:
    """SHA-256 of the DER ``SubjectPublicKeyInfo`` for a PEM Ed25519 key.

    Normalising through DER makes the digest insensitive to PEM whitespace
    / line-wrapping, so an operator-pinned value matches regardless of how
    the SIEM stored the ``public_key_pem`` string.  Returns ``None`` if the
    PEM cannot be parsed.
    """
    if not pem:
        return None
    try:
        from cryptography.hazmat.primitives import serialization
        pub = serialization.load_pem_public_key(pem.encode("ascii"))
        der = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()
    except Exception:
        return None


def verify_chain(
    events: List[Dict],
    *,
    trusted_pubkey_pem: Optional[str] = None,
    expected_measurements: Optional[List[str]] = None,
    expected_platform: Optional[str] = None,
    expected_instance_id: Optional[str] = None,
    pinned_pubkey_sha256: Optional[List[str]] = None,
    expected_first_seq: Optional[int] = None,
    allow_seq_gaps: bool = False,
    skip_signature: bool = False,
    require_chain_commitment: bool = True,
    expected_chain_commitment: Optional[str] = None,
) -> Tuple[bool, List[str]]:
    """Pure function so tests can drive it without Click.

    Returns ``(ok, problems)`` where ``problems`` is a list of
    human-readable diagnostic strings.  ``ok`` is ``True`` iff
    ``problems`` is empty — and an empty *events* list is itself a
    problem, because a vacuous pass is indistinguishable from a
    successful audit.

    *trusted_pubkey_pem* is the operator's out-of-band copy of the TEE's
    per-boot signing key.  When supplied it is the only key signatures
    are checked against, and every event's embedded ``public_key_pem``
    must match it.  Signature checking without either
    *trusted_pubkey_pem* or *pinned_pubkey_sha256* proves internal
    consistency but not authorship, so that combination is rejected
    rather than warned about.
    """
    problems: List[str] = []
    if not events:
        problems.append(
            "no events to verify — an empty window cannot demonstrate "
            "anything about the workload")
        return False, problems

    # Compare keys through their DER fingerprint rather than the raw PEM
    # string, so PEM whitespace / line-wrapping introduced by whichever
    # SIEM stored the event does not look like a key change.
    trusted_fpr = pubkey_sha256(trusted_pubkey_pem) if trusted_pubkey_pem else None
    if trusted_pubkey_pem and trusted_fpr is None:
        problems.append("trusted public key could not be parsed as a PEM key")
        return False, problems

    pinned_set = {p.lower() for p in (pinned_pubkey_sha256 or [])}
    if trusted_fpr:
        pinned_set.add(trusted_fpr)
    if not skip_signature and not pinned_set:
        problems.append(
            "no out-of-band signing key supplied (--pubkey / --pubkey-file / "
            "--pinned-pubkey-sha256): verifying against the key embedded in "
            "each event proves internal consistency, not authorship")
        return False, problems

    prev_digest_expected = ""
    first_pubkey: Optional[str] = None
    first_commitment: Optional[str] = None
    prev_seq: Optional[int] = None
    for i, ev in enumerate(events):
        # Wire-format gate.  Everything below assumes schema 2 semantics
        # (digest excludes digest+signature, genesis prev_digest is 64
        # zeros); running those rules against an unknown version would
        # mis-verify rather than fail, so we stop at the version check.
        version = ev.get("schema_version")
        if version not in SUPPORTED_SCHEMA_VERSIONS:
            problems.append(
                f"event[{i}] (seq={ev.get('seq')}): unsupported "
                f"schema_version {version!r} (supported: "
                f"{sorted(SUPPORTED_SCHEMA_VERSIONS)})")
            prev_digest_expected = ev.get("digest", "")
            continue
        # Digest recompute.
        if "digest" not in ev:
            problems.append(f"event[{i}]: missing 'digest'")
            continue
        recomputed = _compute_digest(ev)
        if recomputed != ev["digest"]:
            problems.append(
                f"event[{i}] (seq={ev.get('seq')}): digest mismatch "
                f"(stored={ev['digest'][:16]}…, recomputed={recomputed[:16]}…)")
        # Sequence: strictly monotonic, incrementing by exactly 1.  An
        # unparseable seq is a failure, not something to skip past.
        try:
            cur_seq = int(ev.get("seq"))
        except (TypeError, ValueError):
            cur_seq = None
            problems.append(
                f"event[{i}]: 'seq' is missing or not an integer "
                f"({ev.get('seq')!r})")
        if cur_seq is not None and prev_seq is not None:
            if cur_seq <= prev_seq:
                problems.append(
                    f"event[{i}]: seq is not increasing "
                    f"({prev_seq} -> {cur_seq}); events reordered or replayed")
            elif cur_seq != prev_seq + 1 and not allow_seq_gaps:
                problems.append(
                    f"event[{i}]: seq jumped {prev_seq} -> {cur_seq} "
                    f"({cur_seq - prev_seq - 1} event(s) missing)")
        if cur_seq is not None:
            prev_seq = cur_seq
        # Chain linkage.  A seq-0 event MUST carry the documented genesis
        # value; anything else means the chain was re-anchored.
        if cur_seq == 0 and ev.get("prev_digest") != GENESIS_PREV_DIGEST:
            problems.append(
                f"event[{i}]: seq 0 carries prev_digest "
                f"{(ev.get('prev_digest') or '')[:16]}…, expected the genesis "
                f"value {GENESIS_PREV_DIGEST[:16]}…")
        if i == 0:
            # Head-truncation guard: assert the window starts where the
            # operator expects (e.g. seq 0 == from genesis). Without this a
            # prefix of the chain can be silently dropped and re-anchored.
            if expected_first_seq is not None and cur_seq != expected_first_seq:
                problems.append(
                    f"event[0]: first seq is {ev.get('seq')!r}, expected "
                    f"{expected_first_seq} (possible head truncation)")
        else:
            if ev.get("prev_digest") != prev_digest_expected:
                problems.append(
                    f"event[{i}] (seq={ev.get('seq')}): prev_digest break "
                    f"(expected={prev_digest_expected[:16]}…, "
                    f"got={(ev.get('prev_digest') or '')[:16]}…)")
        prev_digest_expected = ev.get("digest", "")
        # Signature, always against the operator's key when we have one.
        if not skip_signature:
            ok, reason = _verify_signature(ev, trusted_pubkey_pem)
            if not ok:
                problems.append(
                    f"event[{i}] (seq={ev.get('seq')}): {reason}")
        # Per-boot key stability.
        if first_pubkey is None:
            first_pubkey = ev.get("public_key_pem", "")
        elif ev.get("public_key_pem", "") != first_pubkey:
            problems.append(
                f"event[{i}] (seq={ev.get('seq')}): public_key_pem changed "
                "mid-stream; expected key rotation only across boot")
        # The key the event claims must match the operator's allowlist —
        # otherwise a forged-but-self-consistent chain would verify.
        if pinned_set:
            kh = pubkey_sha256(ev.get("public_key_pem", "") or "")
            if kh is None:
                problems.append(
                    f"event[{i}] (seq={ev.get('seq')}): public_key_pem unparseable; "
                    "cannot match the pinned signing key")
            elif kh.lower() not in pinned_set:
                problems.append(
                    f"event[{i}] (seq={ev.get('seq')}): embedded signing key "
                    f"{kh[:16]}… is not the pinned key")
        # AUD-3 genesis commitment: the workload's runtime-audit-log HMAC
        # key commitment, echoed on every event so wholesale log
        # replacement is externally observable.
        commitment = str(
            (ev.get("extra") or {}).get("chain_key_commitment") or "").lower()
        if require_chain_commitment and not commitment:
            problems.append(
                f"event[{i}] (seq={ev.get('seq')}): no "
                "extra.chain_key_commitment — the runtime audit log's genesis "
                "commitment was never published, so a replaced log is "
                "undetectable")
        if commitment:
            if first_commitment is None:
                first_commitment = commitment
            elif commitment != first_commitment:
                problems.append(
                    f"event[{i}] (seq={ev.get('seq')}): chain_key_commitment "
                    "changed mid-stream; the runtime audit log was restarted "
                    "or replaced")
            if (expected_chain_commitment
                    and commitment != expected_chain_commitment.strip().lower()):
                problems.append(
                    f"event[{i}] (seq={ev.get('seq')}): chain_key_commitment "
                    f"{commitment[:16]}… != expected "
                    f"{expected_chain_commitment.strip().lower()[:16]}…")
        # Cross-fields.
        if expected_platform and ev.get("tee_platform") != expected_platform:
            problems.append(
                f"event[{i}]: tee_platform {ev.get('tee_platform')!r} != "
                f"expected {expected_platform!r}")
        if expected_instance_id and ev.get("instance_id") != expected_instance_id:
            problems.append(
                f"event[{i}]: instance_id {ev.get('instance_id')!r} != "
                f"expected {expected_instance_id!r}")
        if expected_measurements:
            # Same shape as core.keys.release: when a measurement
            # allowlist is in force, an *absent* measurement is a
            # failure, not a free pass.
            m = (ev.get("measurement_sha256") or "").lower()
            if not m:
                problems.append(
                    f"event[{i}] (seq={ev.get('seq')}): --expect-measurement "
                    "was given but the event carries no measurement_sha256")
            elif m not in [x.lower() for x in expected_measurements]:
                problems.append(
                    f"event[{i}] (seq={ev.get('seq')}): unexpected measurement "
                    f"{m[:16]}… — not in --expect-measurement list")
    return (len(problems) == 0), problems


def register(cli):
    @cli.command("verify-siem-chain")
    @click.option("--file", "events_file", required=True,
                  type=click.Path(exists=True, dir_okay=False),
                  help="Newline-delimited JSON events exported from your SIEM.")
    @click.option("--expect-measurement", "expected_measurements", multiple=True,
                  help="SHA-256 measurement(s) that events MUST report. May be "
                       "repeated.  Fail on any other measurement.")
    @click.option("--expect-platform", default=None,
                  help="If set, every event must report this tee_platform "
                       "(e.g. 'snp-aws').")
    @click.option("--expect-instance-id", default=None,
                  help="If set, every event must report this instance_id.")
    @click.option("--pinned-pubkey-sha256", "pinned_pubkey_sha256", multiple=True,
                  help="SHA-256 (hex) of the DER SubjectPublicKeyInfo of the "
                       "TEE's per-boot signing key. May be repeated (one per "
                       "boot/rotation). When set, every event's embedded key "
                       "MUST match — this is what makes the chain "
                       "forgery-resistant. STRONGLY recommended in production.")
    @click.option("--pubkey", "pubkey_path", default=None,
                  type=click.Path(exists=True, dir_okay=False),
                  help="PEM file holding the TEE's per-boot signing key. Every "
                       "event's signature is verified against THIS key and any "
                       "event whose embedded public_key_pem differs is "
                       "rejected. Defaults to build_provenance.pub next to the "
                       "events file or in the current directory when present.")
    @click.option("--pubkey-file", "pubkey_files", multiple=True,
                  type=click.Path(exists=True, dir_okay=False),
                  help="Additional PEM file(s) of accepted signing keys (one "
                       "per boot/rotation); hashed and added to the "
                       "--pinned-pubkey-sha256 allowlist.")
    @click.option("--expect-chain-commitment", "expected_chain_commitment",
                  default=None,
                  help="SHA-256 (hex) of the workload's runtime-audit-log HMAC "
                       "key, as published in the attestation report_data. Every "
                       "event's extra.chain_key_commitment must match. When "
                       "omitted, the value is read from a signed "
                       "build_provenance.json found next to the events file or "
                       "in the CWD (chain + Ed25519 signature must verify); "
                       "pass it explicitly to override that.")
    @click.option("--no-auto-chain-commitment", "no_auto_commitment",
                  is_flag=True, default=False,
                  help="Do not look for the attested commitment in a nearby "
                       "build_provenance.json. The chain is then only checked "
                       "for internal consistency of the commitment field.")
    @click.option("--no-require-chain-commitment", "no_require_commitment",
                  is_flag=True, default=False,
                  help="Do not require extra.chain_key_commitment on every "
                       "event. Needed for the Nitro / SGX host-side heartbeat "
                       "sidecar, which runs outside the workload's namespace "
                       "and therefore cannot read the published commitment.")
    @click.option("--expect-first-seq", "expected_first_seq", default=None, type=int,
                  help="Assert the first event's seq (use 0 to require the "
                       "export to start at genesis — defends against silent "
                       "head truncation).")
    @click.option("--allow-seq-gaps", is_flag=True, default=False,
                  help="Do not fail on non-contiguous seq numbers (default is "
                       "to flag missing events). Audit-only escape hatch.")
    @click.option("--skip-signature", is_flag=True, default=False,
                  help="Verify chain only — do NOT verify Ed25519 signatures. "
                       "Audit-only escape hatch.  Production cron jobs MUST "
                       "omit this flag.")
    @click.option("--quiet", "quiet", is_flag=True, default=False,
                  help="On success print nothing; only emit problems on failure.")
    def verify_siem_chain(events_file, expected_measurements, expect_platform,
                          expect_instance_id, pinned_pubkey_sha256, pubkey_path,
                          pubkey_files, expected_chain_commitment,
                          no_auto_commitment, no_require_commitment,
                          expected_first_seq, allow_seq_gaps, skip_signature,
                          quiet):
        """Verify a SIEM-exported AttestationEvent chain end-to-end."""
        events_file = os.path.abspath(events_file)
        events, problems = _load_events(events_file)

        # Auto-discover the attested commitment so the common case needs no
        # flag.  Precedence lives in resolve_expected_commitment().
        expected_chain_commitment, commitment_source, warning = (
            resolve_expected_commitment(
                events_file, expected_chain_commitment,
                no_auto=no_auto_commitment,
                no_require=no_require_commitment,
            ))
        if warning:
            console.print(f"[yellow]⚠ {warning}[/yellow]")

        pinned = [p.strip().lower() for p in pinned_pubkey_sha256 if p.strip()]
        for pf in pubkey_files:
            kh = pubkey_sha256(_load_pubkey_pem(pf))
            if kh is None:
                raise click.ClickException(f"{pf}: could not parse a PEM public key")
            pinned.append(kh)

        resolved_pubkey = pubkey_path
        trusted_pem = (_load_pubkey_pem(resolved_pubkey)
                       if resolved_pubkey else None)

        # No anchor from the operator: fall back to the fingerprint the deploy
        # recorded at sidecar-install time.  Only consulted when nothing was
        # passed explicitly, so an operator's own key always wins — the reverse
        # precedence is what made the old build_provenance.pub auto-discovery a
        # trap rather than a convenience.
        key_source = ""
        if not trusted_pem and not pinned:
            discovered_key, key_source, key_warning = (
                discover_recorded_signing_key(events_file))
            if key_warning:
                console.print(f"[yellow]⚠ {key_warning}[/yellow]")
            if discovered_key:
                pinned.append(discovered_key)
                key_source = os.path.relpath(key_source)

        ok, chain_problems = verify_chain(
            events,
            trusted_pubkey_pem=trusted_pem,
            expected_measurements=list(expected_measurements) or None,
            expected_platform=expect_platform,
            expected_instance_id=expect_instance_id,
            pinned_pubkey_sha256=pinned or None,
            expected_first_seq=expected_first_seq,
            allow_seq_gaps=allow_seq_gaps,
            skip_signature=skip_signature,
            require_chain_commitment=not no_require_commitment,
            expected_chain_commitment=expected_chain_commitment,
        )
        problems.extend(chain_problems)
        ok = ok and not problems

        if not ok:
            console.print(Panel(
                "\n".join(f"  • {p}" for p in problems[:25]) +
                (f"\n\n  ... and {len(problems) - 25} more" if len(problems) > 25 else ""),
                title=f"[bold red]SIEM chain FAILED — {len(problems)} problem(s)[/bold red]",
                border_style="red",
            ))
            raise SystemExit(2)
        if not quiet:
            first = events[0]
            last = events[-1]
            console.print(Panel(
                f"  Events verified  : [green]{len(events)}[/green]\n"
                f"  First seq        : {first.get('seq')}  ({first.get('timestamp')})\n"
                f"  Last seq         : {last.get('seq')}  ({last.get('timestamp')})\n"
                f"  Last digest      : {last.get('digest', '')[:32]}…\n"
                f"  Platform         : {last.get('tee_platform')}\n"
                f"  Instance id      : {last.get('instance_id')}\n"
                f"  Measurement      : {last.get('measurement_sha256', '')[:16]}…\n"
                f"  Schema version   : {last.get('schema_version')}\n"
                f"  Signing key      : "
                + (f"[green]{os.path.basename(resolved_pubkey)}[/green]"
                   if resolved_pubkey
                   else (f"[green]recorded at deploy ({key_source})[/green]"
                         if key_source
                         else "[green]pinned by fingerprint[/green]"))
                + "\n  Signatures       : "
                + ("[yellow]SKIPPED[/yellow]" if skip_signature
                   else "[green]VALID (out-of-band key)[/green]")
                # State what the commitment was compared against, not just
                # that the run passed: "pinned to an attested value" and
                # "the events agreed with themselves" are very different
                # results and used to be indistinguishable in this output.
                + "\n  Chain commitment : "
                + (f"[green]pinned {expected_chain_commitment[:16]}…[/green] "
                   f"(from {commitment_source})"
                   if expected_chain_commitment
                   else "[yellow]not pinned — events checked for internal "
                        "consistency only[/yellow]"),
                title="[bold green]SIEM chain VERIFIED[/bold green]",
                border_style="green",
            ))
