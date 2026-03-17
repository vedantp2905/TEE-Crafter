"""SIEM-SEC-6: SLSA-style in-toto build provenance attestation.

The existing :class:`tee_crafter.core.audit.audit.BuildAuditTrail`
captures a rich, hash-chained log of every build step and signs the
log with an Ed25519 key.  That's good for *forensic reconstruction*
("here is everything we did, signed") but is not a *standard format*
— a third-party Sigstore / SLSA tool can't ingest it.

This module emits a parallel artifact: an
[in-toto SLSA Provenance v1] statement (predicateType
``https://slsa.dev/provenance/v1``) DSSE-wrapped with the same
Ed25519 key the rest of TEE-Crafter uses.  The statement covers:

* ``subject``         — the artifact tarball + its SHA-256
* ``builder.id``      — the tee-crafter version + git SHA
* ``buildType``       — ``https://tee-crafter.dev/build/v1``
* ``invocation``      — the CLI args + environment digest
* ``buildConfig``     — TEE platform, instance type, CPU/RAM, image
                        digests, base AMI / VM image, requirements
                        lock hash
* ``metadata``        — start/finish timestamps + reproducibility flags
* ``materials``       — every input the build depended on (source git
                        tree SHA, base image, wheel cache hash, root
                        CA bundles), so a verifier can reproduce or
                        bisect the build

The intent is **not** to compete with full SLSA-3 (that requires
hermetic, isolated builders + provenance signed *by the builder
infra* with a key the developer can't access).  We produce SLSA-1
provenance — "the developer claims the following inputs" — that a
downstream `slsa-verifier` / `cosign attest --type slsaprovenance` /
`policy-controller` can consume in CI.

[in-toto SLSA Provenance v1]: https://slsa.dev/spec/v1.0/provenance
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import platform as _py_platform
import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional

from tee_crafter.core.audit import audit as _audit_module  # noqa: F401 — ensure module loadable


SLSA_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
TEE_CRAFTER_BUILD_TYPE = "https://tee-crafter.dev/build/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _tee_crafter_version() -> str:
    try:
        from tee_crafter import __version__
        return __version__
    except Exception:
        return "0.0.0"


def _git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=3,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def _git_status_clean() -> bool:
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain"],
            check=True, capture_output=True, text=True, timeout=3,
        )
        return out.stdout.strip() == ""
    except Exception:
        return False


def _redact_env() -> Dict[str, str]:
    """Hash all env vars containing secrets so the predicate doesn't
    embed them, but the hash still witnesses the build environment.
    """
    redacted = {}
    for k, v in os.environ.items():
        lk = k.lower()
        if any(s in lk for s in ("token", "secret", "key", "password",
                                  "credential", "auth")):
            redacted[k] = "sha256:" + hashlib.sha256(v.encode()).hexdigest()
        elif k.startswith(("TF_VAR_", "TEE_CRAFTER_", "AWS_", "AZURE_",
                            "GCP_", "GOOGLE_")):
            redacted[k] = v[:128]
    return redacted


def collect_materials(build_dir: str) -> List[Dict[str, Any]]:
    """Enumerate everything the build pulled in, with content digests."""
    materials: List[Dict[str, Any]] = []
    git_sha = _git_sha()
    if git_sha:
        materials.append({
            "uri": "git+https://github.com/your-org/tee-crafter@HEAD",
            "digest": {"sha1": git_sha},
            "annotations": {"clean_worktree": _git_status_clean()},
        })
    # Each candidate is (relative-path-list, label).  The first existing
    # path in the list wins.  We probe the new layout first so a build
    # that already uses ``provenance/``/``siem/``/``byok/`` records the
    # subdir path in the SLSA statement; legacy flat paths and the
    # ``app/`` staging copies are kept for back-compat / in-TEE bundles.
    from tee_crafter.core.audit import build_layout as _layout
    candidates = [
        (["requirements.txt", "app/requirements.txt"], "requirements"),
        (["requirements.lock", "app/requirements.lock"], "requirements-lock"),
        (["Dockerfile", "app/Dockerfile"], "dockerfile"),
        (
            [_layout.EVIDENCE_PROVENANCE_JSON, "build_provenance.json",
             "app/build_provenance.json"],
            "build-provenance",
        ),
        (
            [_layout.EVIDENCE_SIEM_JSON, "siem.json", "app/siem.json"],
            "siem-public-config",
        ),
        (
            [_layout.EVIDENCE_BYOK_JSON, "byok.json", "app/byok.json"],
            "byok-config",
        ),
        (
            ["workload_egress.json", "app/workload_egress.json"],
            "workload-egress",
        ),
    ]
    for rel_paths, label in candidates:
        for rel in rel_paths:
            p = os.path.join(build_dir, rel)
            if os.path.isfile(p):
                d = _sha256_file(p)
                if d:
                    materials.append({
                        "uri": f"file://{os.path.relpath(p, build_dir)}",
                        "digest": {"sha256": d},
                        "annotations": {"label": label},
                    })
                break
    return materials


def collect_subjects(build_dir: str) -> List[Dict[str, Any]]:
    """The set of build outputs the statement attests to."""
    from tee_crafter.core.audit import build_layout as _layout
    subjects: List[Dict[str, Any]] = []
    candidates = [
        "tee-crafter.tar",
        "snp_app.tar.gz", "tdx_app.tar.gz", "gpu_cc_app.tar.gz",
        "nitro-enclave.eif",
        "sgx-manifest.sgx",
        # Provenance subject: new layout first, then app-staging, then
        # legacy top-level.
        _layout.EVIDENCE_PROVENANCE_JSON,
        "app/build_provenance.json",
        "build_provenance.json",
    ]
    for cand in candidates:
        p = os.path.join(build_dir, cand)
        if os.path.isfile(p):
            d = _sha256_file(p)
            if d:
                subjects.append({
                    "name": cand,
                    "digest": {"sha256": d},
                })
    return subjects


def build_predicate(
    *,
    build_dir: str,
    tee_platform: str,
    invocation_args: Optional[List[str]] = None,
    build_config: Optional[Dict[str, Any]] = None,
    started_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct the SLSA Provenance v1 predicate dict."""
    started = started_at or _now_iso()
    finished = _now_iso()
    return {
        "buildDefinition": {
            "buildType": TEE_CRAFTER_BUILD_TYPE,
            "externalParameters": {
                "tee_platform": tee_platform,
                "cli_args": list(invocation_args or sys.argv),
            },
            "internalParameters": {
                "env_digest": redacted_env_digest(),
                "host": {
                    "os": _py_platform.platform(),
                    "python": _py_platform.python_version(),
                    "hostname": socket.gethostname(),
                },
            },
            "resolvedDependencies": collect_materials(build_dir),
        },
        "runDetails": {
            "builder": {
                "id": f"https://tee-crafter.dev/builder/v{_tee_crafter_version()}",
                "version": {
                    "tee-crafter": _tee_crafter_version(),
                    "git": _git_sha() or "unknown",
                },
            },
            "metadata": {
                "invocationId": hashlib.sha256(
                    f"{tee_platform}:{started}:{_git_sha()}".encode()
                ).hexdigest()[:16],
                "startedOn": started,
                "finishedOn": finished,
                # We are NOT a hermetic, isolated builder.
                "reproducible": False,
            },
            "byproducts": [
                {"name": "tee_platform", "value": tee_platform},
                {"name": "build_config",
                 "value": json.dumps(build_config or {}, sort_keys=True)},
            ],
        },
    }


def redacted_env_digest() -> str:
    redacted = _redact_env()
    canonical = json.dumps(redacted, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def build_statement(
    *,
    build_dir: str,
    tee_platform: str,
    invocation_args: Optional[List[str]] = None,
    build_config: Optional[Dict[str, Any]] = None,
    started_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct the in-toto Statement v1 envelope (unsigned)."""
    return {
        "_type": SLSA_STATEMENT_TYPE,
        "subject": collect_subjects(build_dir),
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": build_predicate(
            build_dir=build_dir,
            tee_platform=tee_platform,
            invocation_args=invocation_args,
            build_config=build_config,
            started_at=started_at,
        ),
    }


def _dsse_pae(payload: bytes, payload_type: str) -> bytes:
    """Pre-Authentication Encoding per DSSE spec.

    DSSE-PAE: "DSSEv1" SP <len(type)> SP <type> SP <len(payload)> SP <payload>
    """
    return (
        f"DSSEv1 {len(payload_type)} {payload_type} "
        f"{len(payload)} ".encode("utf-8") + payload
    )


def emit_attestation(
    *,
    build_dir: str,
    tee_platform: str,
    invocation_args: Optional[List[str]] = None,
    build_config: Optional[Dict[str, Any]] = None,
    started_at: Optional[str] = None,
) -> Dict[str, str]:
    """Generate, sign, and persist an in-toto SLSA Provenance attestation.

    Returns ``{"statement": path, "envelope": path, "predicate_sha256": ...}``.
    """
    statement = build_statement(
        build_dir=build_dir,
        tee_platform=tee_platform,
        invocation_args=invocation_args,
        build_config=build_config,
        started_at=started_at,
    )
    statement_json = json.dumps(statement, sort_keys=True,
                                 separators=(",", ":")).encode("utf-8")

    # Reuse the same Ed25519 signing key TEE-Crafter already uses for
    # ``build_provenance.json`` — keeps the SBOM operator's trust
    # anchor singular.  ``load_signing_key`` honours
    # TEE_CRAFTER_PROVENANCE_SIGNING_KEY / _FILE / OS keyring.
    from tee_crafter.core.audit.signing import (
        load_signing_key,
        public_key_fingerprint,
        public_key_pem,
    )
    loaded = load_signing_key()

    pae = _dsse_pae(statement_json, DSSE_PAYLOAD_TYPE)
    sig = loaded.key.sign(pae)
    pub_pem = public_key_pem(loaded.key.public_key())
    pub_fpr = public_key_fingerprint(loaded.key.public_key())

    # DSSE envelope.
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(statement_json).decode("ascii"),
        "signatures": [
            {
                "keyid": f"sha256:{pub_fpr}",
                "sig": base64.b64encode(sig).decode("ascii"),
            }
        ],
    }

    from tee_crafter.core.audit import build_layout as _layout
    _layout.ensure_dirs(build_dir)
    out: Dict[str, str] = {}
    statement_path = _layout.slsa_intoto(build_dir)
    with open(statement_path, "w", encoding="utf-8") as f:
        json.dump(statement, f, indent=2, sort_keys=True)
    out["statement"] = os.path.abspath(statement_path)

    envelope_path = _layout.slsa_dsse(build_dir)
    with open(envelope_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)
    out["envelope"] = os.path.abspath(envelope_path)

    pem_path = _layout.slsa_pub(build_dir)
    with open(pem_path, "wb") as f:
        f.write(pub_pem)
    out["pub"] = os.path.abspath(pem_path)

    out["predicate_sha256"] = hashlib.sha256(statement_json).hexdigest()
    out["key_fingerprint"] = pub_fpr
    out["key_kind"] = loaded.kind
    return out


def verify_envelope(envelope_path: str,
                    *, pinned_pubkey_sha256: Optional[str] = None
                    ) -> tuple[bool, str]:
    """Verify a DSSE envelope produced by :func:`emit_attestation`.

    Returns ``(ok, message)``.  If ``pinned_pubkey_sha256`` is set,
    additionally require that the signing key matches that fingerprint.
    """
    try:
        with open(envelope_path, "r", encoding="utf-8") as f:
            env = json.load(f)
        payload = base64.b64decode(env["payload"])
        pae = _dsse_pae(payload, env["payloadType"])
        # The envelope ships only the key fingerprint; the public key
        # lives in slsa_provenance.pub alongside it (either in the same
        # slsa/ subdir or, for legacy builds, at the top level).
        from tee_crafter.core.audit import build_layout as _layout
        env_dir = os.path.dirname(envelope_path)
        build_dir = (os.path.dirname(env_dir)
                     if os.path.basename(env_dir) == _layout.SLSA_DIR
                     else env_dir)
        pem_path = _layout.resolve(
            build_dir,
            os.path.join(_layout.SLSA_DIR, "slsa_provenance.pub"),
            "slsa_provenance.pub",
        )
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        with open(pem_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        if not isinstance(pub, Ed25519PublicKey):
            return False, "public key is not Ed25519"
        # Allow multiple signatures, accept first that verifies.
        verified = False
        for sig_entry in env.get("signatures", []):
            try:
                pub.verify(base64.b64decode(sig_entry["sig"]), pae)
                verified = True
                break
            except Exception:
                continue
        if not verified:
            return False, "no signature verified against the public key"
        if pinned_pubkey_sha256:
            from tee_crafter.core.audit.signing import public_key_fingerprint
            actual = public_key_fingerprint(pub)
            if actual.lower() != pinned_pubkey_sha256.strip().lower():
                return False, (
                    f"pubkey fingerprint mismatch: build={actual}, "
                    f"pinned={pinned_pubkey_sha256}")
        return True, ""
    except Exception as e:
        return False, str(e)
