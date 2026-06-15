"""Compare launch measurements across bakes of the same platform.

There is a claim this project makes about AMD SEV-SNP: two bakes of the same
platform, with materially different disk contents, produce the *same* launch
measurement, because the launch digest covers initial guest memory (firmware,
boot configuration, one VMSA per vCPU) rather than the OS disk. The workload is
bound separately, by the container digest inside ``report_data``.

That claim was established on ``snp-azure`` and it must not be assumed to
transfer. ``snp-aws`` and ``snp-gcp`` boot through different firmware, so the
experiment has to be repeated per platform: bake twice with a deliberate
software change, then compare.

This module is the compare half. Doing it by hand is how the ``snp-azure``
registry ended up with two entries disagreeing about the same image — three
bakes, two digests, and a difference that looked like a vCPU-tier effect but was
a host-generation effect. So the comparison here is deliberately narrow:

* Two digests are only compared when they come from the **same shape** — the
  same CPU generation and the same vCPU count. Different shapes are expected to
  differ and say nothing about the disk.
* A generation only counts when it was **observed** on the booted VM, never when
  it was inferred from the instance type. That inference is what produced the
  wrong conclusion the first time; see
  :func:`tee_crafter.core.measurements.shapes.host_gen_is_selectable`.

What this module cannot check is the precondition: whether the two bakes really
did differ in software. Nothing in the registry records that. The caller has to
know it, and the CLI says so.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tee_crafter.core.measurements.registry import (
    PLATFORM_MEASUREMENT_FIELD,
    records_for_platform,
)
from tee_crafter.core.measurements.shapes import (
    SNP_VCPU_SENSITIVE_PLATFORMS,
    host_gen_is_selectable,
)

#: Verdicts :func:`compare_bakes` can return.
VERDICT_DISK_INDEPENDENT = "disk_independent"
VERDICT_DISK_DEPENDENT = "disk_dependent"
VERDICT_CONTRADICTORY = "contradictory"
#: Some bakes agree and at least one does not. Distinct from
#: ``disk_dependent``: bakes that agree had different disks, so the disk is not
#: what moved the digest.
VERDICT_SPLIT = "split_host_side"
VERDICT_INSUFFICIENT = "insufficient_data"

#: Shape key: ``(cpu_gen or None, vcpu or None)``.
ShapeKey = Tuple[Optional[str], Optional[int]]


def _comparable_shapes(record: Dict[str, Any], platform: str,
                       field: str) -> Dict[ShapeKey, str]:
    """Digest per comparable shape for one record.

    A variant is comparable when its digest is present and its CPU-generation
    label can be trusted. What makes a label trustworthy depends on the platform,
    and getting this wrong in either direction is a real failure:

    * Where the instance type does **not** determine the host generation — Azure,
      where ``DCas_v5`` has been seen on two — only a generation read off the
      booted CPU counts. An inferred label there has been observed to be wrong,
      and a wrong label silently reclassifies a host-generation difference as
      something else, which is exactly how the disagreeing ``snp-azure`` entries
      were produced.
    * Where it **does** determine it — ``snp-aws`` (``m6a`` is Milan, ``m7a`` is
      Genoa: different hardware families) and ``snp-gcp`` (bake and deploy both
      pin ``min_cpu_platform``) — an inferred label is correct by construction,
      and refusing it would make this comparison permanently unanswerable on
      those platforms for no gain in soundness.

    Platforms whose measurement does not depend on the shape at all are a third
    case, and they need one because they store no variants to compare. Intel TDX
    ``MRTD`` covers the initial TD image, and Nitro ``PCR0`` / SGX ``MRENCLAVE``
    are build-time deterministic — for those, the record's single digest is
    compared under an unspecified shape. That fallback is deliberately **not**
    extended to the SEV-SNP platforms: their digest does vary by generation and
    vCPU count, so comparing two of them without knowing the shape is how a
    host-generation difference gets mistaken for something else.
    """
    out: Dict[ShapeKey, str] = {}
    if platform not in SNP_VCPU_SENSITIVE_PLATFORMS:
        primary = record.get(field) or record.get("measurement")
        if isinstance(primary, str) and primary.strip():
            out[(None, None)] = primary.strip().lower()
        return out
    for variant in record.get("variants") or []:
        if not isinstance(variant, dict):
            continue
        measurement = variant.get("measurement")
        if not isinstance(measurement, str) or not measurement.strip():
            continue
        gen = variant.get("cpu_gen")
        if gen is not None and variant.get("cpu_gen_source") != "observed" \
                and not host_gen_is_selectable(platform):
            continue
        vcpu = variant.get("vcpu")
        key: ShapeKey = (gen, vcpu if isinstance(vcpu, int) else None)
        out.setdefault(key, measurement.strip().lower())
    return out


def _image_summary(record: Dict[str, Any], platform: str,
                   field: str) -> Dict[str, Any]:
    measurements = [
        m.strip().lower() for m in (record.get("measurements") or [])
        if isinstance(m, str) and m.strip()
    ]
    if not measurements:
        primary = record.get(field) or record.get("measurement")
        if isinstance(primary, str) and primary.strip():
            measurements = [primary.strip().lower()]
    gens: List[str] = []
    inferred_gens: List[str] = []
    for variant in record.get("variants") or []:
        if not isinstance(variant, dict):
            continue
        gen = variant.get("cpu_gen")
        if not isinstance(gen, str):
            continue
        bucket = gens if variant.get("cpu_gen_source") == "observed" else inferred_gens
        if gen not in bucket:
            bucket.append(gen)
    return {
        "image_id": record.get("image_id") or "",
        "captured_at": record.get("captured_at") or "",
        "source": record.get("source") or "",
        "file": record.get("_file") or "",
        "measurements": measurements,
        "observed_gens": gens,
        "inferred_gens": inferred_gens,
    }


def compare_bakes(platform: str) -> Dict[str, Any]:
    """Compare every stored bake of ``platform`` shape-for-shape.

    Returns a dict with ``platform``, ``images`` (one summary each),
    ``comparisons`` (one per shape present in two or more images), ``verdict``
    and ``reason``.

    The verdict describes what the *data* shows, not what the platform is
    guaranteed to do:

    ``disk_independent``
        At least one shape produced the same digest in two different images, and
        no shape contradicted it.
    ``disk_dependent``
        Every bake produced a different digest on the shapes compared — no two
        agreed anywhere. Only this justifies "a re-bake changes the measurement".
    ``split_host_side``
        On some shape, two or more bakes agreed exactly and at least one differed.
        Since the agreeing bakes had different disks, the disk is not the
        variable; the outlier landed on something host-side. Investigate what,
        rather than concluding either way.
    ``contradictory``
        Both happened. That is a real signal, not a bug in the comparison —
        follow the per-shape detail.
    ``insufficient_data``
        Fewer than two images, or no shape captured in more than one of them
        with an observed generation. This is the common case early on and is not
        a failure; it means the experiment has not been run yet.
    """
    field = PLATFORM_MEASUREMENT_FIELD.get(platform, "measurement")
    records = records_for_platform(platform)
    images = [_image_summary(r, platform, field) for r in records]

    result: Dict[str, Any] = {
        "platform": platform,
        "images": images,
        "comparisons": [],
        # Always present, so a consumer of --json never has to distinguish
        # "no outliers" from "this run returned early".
        "outlier_images": [],
        "verdict": VERDICT_INSUFFICIENT,
        "reason": "",
    }

    if len(images) < 2:
        result["reason"] = (
            f"only {len(images)} bake recorded for {platform}; the comparison "
            "needs two images built from deliberately different software"
        )
        return result

    # Group digests by shape across images.  The shape map is keyed by a tuple
    # and stays local: it is plumbing for the grouping below, and putting it in
    # the returned summary made the whole result unserialisable to JSON, which
    # the ``--json`` flag needs.
    by_shape: Dict[ShapeKey, List[Tuple[str, str]]] = {}
    for record, img in zip(records, images):
        for key, digest in _comparable_shapes(record, platform, field).items():
            by_shape.setdefault(key, []).append((img["image_id"], digest))

    agreed = 0
    disagreed = 0
    split = 0
    for key in sorted(by_shape, key=lambda k: (str(k[0]), k[1] or 0)):
        entries = by_shape[key]
        distinct_images = {img for img, _ in entries}
        if len(distinct_images) < 2:
            continue
        # Partition the images by digest rather than collapsing to a set of
        # digests. The set loses the multiplicity, and the multiplicity is the
        # whole signal: three bakes where two agree and one differs is evidence
        # *for* disk-independence plus one odd host, but a set of two digests is
        # indistinguishable from three bakes that all disagree. Reporting the
        # latter as "a re-bake changes the measurement" is wrong, and it is the
        # same over-coarse reading this module exists to prevent.
        groups: Dict[str, List[str]] = {}
        for img_id, digest in entries:
            if img_id not in groups.setdefault(digest, []):
                groups[digest].append(img_id)
        ranked = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        largest = len(ranked[0][1])
        same = len(ranked) == 1
        if same:
            agreed += 1
        elif largest >= 2:
            # Some bakes agree exactly and at least one does not. Not a disk
            # effect: bakes that agree had different disks too.
            split += 1
        else:
            disagreed += 1
        result["comparisons"].append({
            "cpu_gen": key[0],
            "vcpu": key[1],
            "images": sorted(distinct_images),
            "digests": [d for d, _ in ranked],
            "groups": [{"digest": d, "images": sorted(imgs)} for d, imgs in ranked],
            "largest_agreeing": largest,
            "same": same,
        })

    # A single anomalous bake distorts every verdict it participates in. On
    # `snp-gcp` one bake disagreed with a two-bake consensus at both tiers where
    # all three were captured -- and at a third tier, where only that bake and
    # one other existed, the pair simply "differed". Counting that third tier as
    # independent evidence of disk-dependence would be double-counting the same
    # anomaly, and it flipped the verdict.
    #
    # So: an image that lands outside the majority on any shape is marked an
    # outlier, and the verdict is recomputed from the shapes where every
    # participating image is non-outlier. The outliers are reported, never
    # silently dropped -- an anomalous bake is a finding, not noise.
    minority_count: Dict[str, int] = {}
    for cmp_ in result["comparisons"]:
        if cmp_["same"] or cmp_["largest_agreeing"] < 2:
            continue
        for grp in cmp_["groups"][1:]:
            for img_id in grp["images"]:
                minority_count[img_id] = minority_count.get(img_id, 0) + 1
    outliers = sorted(minority_count)
    result["outlier_images"] = [
        {"image_id": i, "shapes_in_minority": minority_count[i]} for i in outliers
    ]
    if outliers:
        # Re-derive agreement per shape with the outlier *rows* removed, not by
        # discarding any shape an outlier appears in -- that left nothing to
        # judge, because the outlier appeared everywhere. What matters is
        # whether the remaining, mutually-consistent bakes agree with each
        # other; a shape that drops below two such bakes is simply not evidence.
        trusted = []
        for cmp_ in result["comparisons"]:
            kept = [
                {"digest": g["digest"],
                 "images": [i for i in g["images"] if i not in minority_count]}
                for g in cmp_["groups"]
            ]
            kept = [g for g in kept if g["images"]]
            n_images = sum(len(g["images"]) for g in kept)
            cmp_["trusted_agreement"] = (
                None if n_images < 2 else len(kept) == 1
            )
            if n_images >= 2:
                trusted.append(cmp_)
        if trusted and all(c["trusted_agreement"] for c in trusted):
            result["verdict"] = VERDICT_DISK_INDEPENDENT
            result["reason"] = (
                f"{len(trusted)} shape(s) produced an identical digest across "
                f"every bake that is mutually consistent, so the disk is not "
                f"what moves the digest here. {len(outliers)} bake(s) disagreed "
                f"with that consensus and are reported separately -- something "
                f"host-side differed for them (host firmware or microcode "
                f"revision are the usual causes). Do not pin from an outlier "
                f"without establishing what it landed on"
            )
            return result

    if split and not disagreed:
        result["verdict"] = VERDICT_SPLIT
        result["reason"] = (
            f"on {split} shape(s) some bakes produced an identical digest and at "
            "least one produced a different one. The bakes that agree had "
            "different disk contents, so this is not the disk changing the "
            "measurement — something host-side differed for the odd bake (host "
            "firmware or microcode revision are the usual causes). Identify what "
            "the outlier bake landed on before pinning from it"
        )
    elif split and disagreed:
        result["verdict"] = VERDICT_CONTRADICTORY
        result["reason"] = (
            f"{split} shape(s) had some bakes agree and some differ, while "
            f"{disagreed} shape(s) had every bake differ; the launch digest is "
            "not uniformly disk-independent here"
        )
    elif agreed and disagreed:
        result["verdict"] = VERDICT_CONTRADICTORY
        result["reason"] = (
            f"{agreed} shape(s) matched across bakes and {disagreed} did not; "
            "the launch digest is not uniformly disk-independent here"
        )
    elif agreed:
        result["verdict"] = VERDICT_DISK_INDEPENDENT
        result["reason"] = (
            f"{agreed} shape(s) produced an identical digest in two or more "
            "images — consistent with the launch measurement covering initial "
            "guest memory rather than the OS disk"
        )
    elif disagreed:
        result["verdict"] = VERDICT_DISK_DEPENDENT
        result["reason"] = (
            f"{disagreed} shape(s) produced different digests across bakes; on "
            "this platform a re-bake changes the launch measurement"
        )
    else:
        result["reason"] = (
            "no shape was captured in more than one image with a usable CPU "
            "generation label; bake again on a matching shape. On a platform "
            "where the instance type does not fix the generation (Azure SEV-SNP) "
            "the label must have been read off the booted CPU — check that "
            "capture recorded cpu_gen_source=observed"
        )
    return result
