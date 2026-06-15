"""Per-image launch-measurement registry (auto-pinning).

The registry is a directory of small JSON files shipped *inside* the package::

    measurements/<platform>/<sanitized-image-id>.json

Each file records the TEE launch measurement captured for one baked image::

    {
      "platform": "snp-aws",
      "image_id": "ami-0123...",
      "field": "measurement",
      "measurement": "b756dd...e107",
      "captured_at": "2026-06-01T07:00:00Z",
      "source": "bake-ami"
    }

``deploy`` resolves the image id (``--ami-id`` / pinned env) and calls
:func:`measurement_value` to obtain the vetted baseline.  When sealed-``.env``
or BYOK is requested and the lookup misses, the deploy path fails closed
(unless ``TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT`` is set) so an unattested /
unpinned image can never gate a key release.

This module lives under ``tee_crafter.core`` and must not import anything from
``tee_crafter.cli`` so the GUI / library consumers can use it standalone.
"""
from __future__ import annotations

import datetime
import json
import os
import re
from typing import Any, Dict, List, Optional

# The packaged registry root: ``tee_crafter/measurements`` (this file is at
# ``tee_crafter/core/measurements/registry.py``).
_PACKAGED_REGISTRY_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "measurements",
)


def _resolve_registry_dir() -> str:
    """Registry root, honouring ``TEE_CRAFTER_MEASUREMENTS_DIR``.

    The CLI re-execs inside a ``--rm`` Docker container where the packaged
    location (``/opt/tee-crafter/src/tee_crafter/measurements``) is discarded on
    exit, so bake-time pins would never reach the operator's repo.  The Docker
    wrapper bind-mounts the host's packaged measurements dir and points this env
    var at it so pins persist (same pattern as the audit signing key).

    Whitespace-only is treated as unset, so a blank export falls back to the
    packaged directory rather than resolving to ``""`` and writing pins relative
    to the process working directory.
    """
    override = os.environ.get("TEE_CRAFTER_MEASUREMENTS_DIR", "").strip()
    return override or _PACKAGED_REGISTRY_DIR


#: Explicit override seam, and the *highest* precedence source.  ``None`` means
#: "resolve from the environment on every call".
#:
#: This used to hold the resolved path, assigned once at import.  That made
#: ``TEE_CRAFTER_MEASUREMENTS_DIR`` a no-op for anything that set it after this
#: module was first imported -- a wrapper script, an embedding application, a
#: test -- and for a *measurement pin* registry the failure mode is silent:
#: pins land in the packaged directory while the reader looks elsewhere, or vice
#: versa.  Production never noticed because the Docker wrapper exports the var
#: with ``docker run -e`` before the interpreter starts.
#:
#: It outranks the environment deliberately.  Tests assign it a tmpdir and must
#: keep working on a developer machine that happens to export
#: ``TEE_CRAFTER_MEASUREMENTS_DIR``; if the environment won, that export would
#: silently redirect every such test at the real registry.
_REGISTRY_DIR: Optional[str] = None

#: Primary measurement field name per platform family.  The launch digest is
#: called different things on each TEE: AMD SEV-SNP ``MEASUREMENT``, Intel TDX
#: ``MRTD``, Nitro ``PCR0``, SGX ``MRENCLAVE``.
PLATFORM_MEASUREMENT_FIELD: Dict[str, str] = {
    "snp-aws": "measurement",
    "snp-azure": "measurement",
    "snp-gcp": "measurement",
    "gpu-cc-aws": "measurement",
    "gpu-cc-azure": "measurement",
    "tdx-azure": "mrtd",
    "tdx-gcp": "mrtd",
    "gpu-cc-gcp": "mrtd",
    "nitro-aws": "pcr0",
    "sgx-azure": "mrenclave",
}


def registry_dir() -> str:
    """Absolute path of the measurement registry root.

    Precedence: :data:`_REGISTRY_DIR` if a caller set it, then
    ``TEE_CRAFTER_MEASUREMENTS_DIR``, then the packaged
    ``tee_crafter/measurements`` directory.  Resolved per call, so the
    environment variable takes effect whenever it is set.
    """
    return _REGISTRY_DIR or _resolve_registry_dir()


def _sanitize(image_id: str) -> str:
    """Make an image id safe to use as a filename.

    Azure/GCP image ids are full resource paths with ``/`` and ``:`` — collapse
    every non ``[A-Za-z0-9._-]`` run to a single ``_`` so the registry layout is
    one flat file per image regardless of cloud.

    The result is **lower-cased**, because an Azure resource id is
    case-insensitive but a filename is not. The bake takes the image id from the
    Azure API and the deploy takes it from ``.env`` or ``--ami-id``, and those
    genuinely disagree: on 2026-08-22 ``az`` returned the resource group as
    ``TEE-CRAFTER-IMAGES-SNP-RG`` while ``.env`` carried
    ``tee-crafter-images-snp-rg``. Case-sensitively those are two registry keys
    for one image, so ``lookup`` misses and ``deploy`` refuses sealed
    ``--secrets-env`` and BYOK on an image that *is* pinned. It would also have
    hidden here indefinitely: macOS is case-insensitive by default, so the miss
    only appears on Linux — CI and the CLI's own container.

    Lower-casing is safe for the other two clouds: AWS AMI ids are lowercase by
    construction, and GCP image URIs may not contain uppercase at all.

    The alternative was a case-insensitive fallback scan of the platform
    directory when the exact path misses. Rejected: it makes the result
    order-dependent if two differently-cased files both exist, and it keeps the
    ambiguity alive instead of removing it. Normalising on the way in means
    there is only ever one key.
    """
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", (image_id or "").strip())
    return s.strip("_").lower() or "unknown"


def _path(platform: str, image_id: str) -> str:
    return os.path.join(registry_dir(), platform, _sanitize(image_id) + ".json")


def lookup(platform: str, image_id: str) -> Optional[Dict[str, Any]]:
    """Return the stored record for ``(platform, image_id)`` or ``None``."""
    if not platform or not image_id:
        return None
    path = _path(platform, image_id)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    return rec if isinstance(rec, dict) else None


def records_for_platform(platform: str) -> List[Dict[str, Any]]:
    """Every stored record for ``platform``, oldest ``captured_at`` first.

    Used to compare bakes of the same platform against each other: whether two
    images built from different disks share a launch digest is a property of the
    TEE, not something to assume, and it has to be checked per platform because
    the firmware path differs by cloud.

    Unreadable and non-dict files are skipped rather than raising — the registry
    is data the bake writes, and one bad file must not make the whole comparison
    unavailable.
    """
    if not platform:
        return []
    directory = os.path.join(registry_dir(), platform)
    out: List[Dict[str, Any]] = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(directory, name), "r", encoding="utf-8") as fh:
                rec = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(rec, dict):
            rec.setdefault("_file", name)
            out.append(rec)
    out.sort(key=lambda r: str(r.get("captured_at") or ""))
    return out


def _normalise_measurement_hex(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    val = value.strip().lower()
    if not val or val == "unknown":
        return None
    return val


def measurement_values(platform: str, image_id: str) -> List[str]:
    """Return all pinned measurement hex values for ``(platform, image_id)``.

    SNP images store one digest per vCPU tier captured at bake time; TDX /
    Nitro / SGX records contain a single entry.  Returns ``[]`` on miss.
    """
    rec = lookup(platform, image_id)
    if not rec:
        return []
    field = PLATFORM_MEASUREMENT_FIELD.get(platform, "measurement")
    out: List[str] = []
    raw_list = rec.get("measurements")
    if isinstance(raw_list, list):
        for item in raw_list:
            val = _normalise_measurement_hex(item)
            if val and val not in out:
                out.append(val)
    if out:
        return out
    val = _normalise_measurement_hex(rec.get(field) or rec.get("measurement"))
    return [val] if val else []


def measurement_value(platform: str, image_id: str) -> Optional[str]:
    """Return the primary pinned measurement hex (first allowlist entry)."""
    vals = measurement_values(platform, image_id)
    return vals[0] if vals else None


def captured_variants(platform: str, image_id: str) -> List[Dict[str, Any]]:
    """Return the per-shape variants captured at bake (cpu_gen, vcpu, …)."""
    rec = lookup(platform, image_id)
    return list(rec.get("variants") or []) if rec else []


def captured_gens(platform: str, image_id: str) -> List[str]:
    """Return the CPU generations captured at bake (from ``variants``)."""
    out: List[str] = []
    for variant in captured_variants(platform, image_id):
        gen = variant.get("cpu_gen")
        if gen and gen not in out:
            out.append(gen)
    return out


def vcpu_independent_gens(platform: str, image_id: str) -> List[str]:
    """Generations whose launch digest does not vary with vCPU count.

    A generation lands here when the two smallest captured tiers produced an
    identical digest (e.g. IGVM-launched CVMs, all Intel TDX).  A legacy record
    with the old boolean ``vcpu_independent`` is treated as independent for its
    (unlabelled) generation, represented by ``None``.
    """
    rec = lookup(platform, image_id)
    if not rec:
        return []
    gens = rec.get("vcpu_independent_gens")
    if isinstance(gens, list):
        return [g for g in gens if isinstance(g, str)]
    if rec.get("vcpu_independent"):
        return [None]  # legacy single-gen flag
    return []


def accepts_shape(platform: str, image_id: str, cpu_gen: Optional[str],
                  vcpu: Optional[int],
                  instance_type: Optional[str] = None) -> bool:
    """True when a (cpu_gen, vcpu) shape is covered by the pinned measurements.

    *instance_type* is optional and only consulted where the shape carries
    information the other two arguments throw away -- on Azure, the ``_v5`` /
    ``_v6`` SKU version. Callers that omit it get the older, looser behaviour.

    Used by deploy to gate a chosen instance type:

    * a generation not captured at all is **rejected** (no vetted digest);
    * a captured generation flagged vCPU-independent accepts any vCPU;
    * otherwise the exact (cpu_gen, vcpu) tier must have been captured.

    Records with no per-shape ``variants`` (e.g. a bare manual pin) return True
    so legacy single-digest pins are not retroactively blocked.

    On a platform where the host generation is **not** selectable by instance
    type, ``cpu_gen`` is ignored and matching falls back to vCPU alone. The
    caller's ``cpu_gen`` there is what the instance type *implies*, while the
    stored one is what a booted VM *reported*, and on Azure those genuinely
    disagree — so comparing them rejects images that work. See
    :func:`tee_crafter.core.measurements.shapes.host_gen_is_selectable`.

    Note what this gate is for: it exists to stop a deploy that is certain to
    fail from spending money, not to be a security boundary. The client's
    ``EXPECTED_MEASUREMENTS`` allowlist is the boundary, and it still refuses any
    digest that was not captured. Widening this gate can waste a deploy; it
    cannot accept an unpinned measurement.
    """
    variants = captured_variants(platform, image_id)
    if not variants:
        return True
    indep = vcpu_independent_gens(platform, image_id)
    if None in indep:
        return True  # legacy boolean independence covers everything
    captured_gen_list = captured_gens(platform, image_id)
    from tee_crafter.core.measurements.shapes import host_gen_is_selectable
    if not host_gen_is_selectable(platform):
        # An earlier version of this refused a shape whose SKU *version* had no
        # captured variant -- a `_v6` request against `_v5`-only pins.  The
        # reasoning was that v5 and v6 are different SKU families on different
        # firmware, so their launch digests could differ.
        #
        # Measured on hardware 2026-08-24, they do not.  A single snp-azure bake
        # captured Standard_DC2as_v5, DC4as_v5 and DC4as_v6 and all three
        # produced the same digest (b2b53ada...), with cpu_gen observed as
        # `genoa` for each.  The determinant is the host CPU generation, which is
        # exactly the thing an instance type does not select here; the version
        # suffix is not one.  So refusing on it rejected deploys that would have
        # worked, which is the failure mode this gate is supposed to prevent
        # rather than cause.
        #
        # `shape_series` is kept because the deploy still *warns* on an
        # uncaptured series -- worth saying, not worth blocking.
        # Any captured generation being vCPU-independent is enough: we cannot
        # steer which one we get, so the pessimistic reading (reject unless
        # *every* generation is independent) would refuse shapes that are very
        # likely fine, for a gate whose only job is avoiding certain failure.
        if indep:
            return True
        if vcpu is None:
            return True
        return any(v.get("vcpu") == vcpu for v in variants)
    # If variants carry no generation labels, fall back to vCPU-only matching.
    if not captured_gen_list:
        if vcpu is None:
            return True
        vcpus = {v.get("vcpu") for v in variants if isinstance(v.get("vcpu"), int)}
        return (not vcpus) or vcpu in vcpus
    if cpu_gen not in captured_gen_list:
        return False
    if cpu_gen in indep:
        return True
    for v in variants:
        if v.get("cpu_gen") == cpu_gen and v.get("vcpu") == vcpu:
            return True
    return False


def store(
    platform: str,
    image_id: str,
    measurement: str,
    *,
    field: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
    source: str = "bake-ami",
) -> str:
    """Write/overwrite the registry record with a single measurement."""
    return store_many(
        platform, image_id, [measurement],
        field=field, extra=extra, source=source,
    )


def store_many(
    platform: str,
    image_id: str,
    measurements: List[str],
    *,
    field: Optional[str] = None,
    variants: Optional[List[Dict[str, Any]]] = None,
    vcpu_independent_gens: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
    source: str = "bake-ami",
) -> str:
    """Write/overwrite the registry record for ``(platform, image_id)``.

    ``measurements`` is de-duplicated in order.  The first value is also written
    to the platform's primary field for backward compatibility.  Optional
    ``variants`` records per-shape metadata (instance type, vCPU, cpu_gen →
    measurement).  ``vcpu_independent_gens`` lists CPU generations whose digest
    covers every vCPU size of that generation.

    Returns the path written.  Raises ``ValueError`` on missing inputs.
    """
    if not platform:
        raise ValueError("store_many() requires a platform")
    if not image_id:
        raise ValueError("store_many() requires an image_id")
    normalised: List[str] = []
    for raw in measurements or []:
        val = _normalise_measurement_hex(raw)
        if val and val not in normalised:
            normalised.append(val)
    if not normalised:
        raise ValueError("store_many() requires at least one measurement")

    field = field or PLATFORM_MEASUREMENT_FIELD.get(platform, "measurement")
    primary = normalised[0]
    rec: Dict[str, Any] = {
        "platform": platform,
        "image_id": image_id,
        "field": field,
        field: primary,
        "measurements": normalised,
        "captured_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "source": source,
    }
    if variants:
        rec["variants"] = variants
    if vcpu_independent_gens:
        rec["vcpu_independent_gens"] = list(vcpu_independent_gens)
    if extra:
        for k, v in extra.items():
            rec.setdefault(k, v)

    path = _path(platform, image_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)
    return path
