"""``internal pin-measurement`` — record a launch measurement into the registry.

Bake-time auto-capture is automated for the CVM families on AWS/Azure/GCP
(see ``baking/common/measurement_capture.py``).  This command is the portable
fallback that works for **every** cloud and TEE:

* clouds/TEEs where auto-capture could not run (e.g. it warned and left the
  image unpinned, or an air-gapped operator read the measurement out of band);
* Nitro (PCR0) and SGX (MRENCLAVE), whose measurements are build-time
  deterministic rather than read from a booted instance.

Once a measurement is pinned here, ``deploy`` uses it exactly as if it had been
captured at bake time: it feeds the client verifier, the BYOK
``allowed_measurement_sha256`` policy, and the sealed-``.env`` gate, and the
deploy-time fail-closed check passes.
"""
from __future__ import annotations

import re

import click

from tee_crafter.cli.constants import console
from tee_crafter.core.measurements import registry as _registry

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def register(cli):
    @cli.command("pin-measurement")
    @click.option(
        "--tee-platform", "platform", required=True,
        type=click.Choice(sorted(_registry.PLATFORM_MEASUREMENT_FIELD), case_sensitive=False),
        help="Platform the image belongs to.",
    )
    @click.option(
        "--image-id", required=True,
        help="Image identifier used at deploy time (AMI id / Azure gallery image "
             "resource id / GCP image URI).",
    )
    @click.option(
        "--measurement", required=True,
        help="Launch measurement as hex (SNP MEASUREMENT / TDX MRTD = 96 hex; "
             "Nitro PCR0 = 96 hex; SGX MRENCLAVE = 64 hex).",
    )
    @click.option(
        "--field", default=None,
        help="Override the stored field name (default: the platform's primary "
             "field — measurement / mrtd / pcr0 / mrenclave).",
    )
    @click.option(
        "--instance-type", default=None,
        help="Instance type this measurement was read on (AMD SEV-SNP only). "
             "Records the vCPU tier so deploy accepts that size.",
    )
    @click.option(
        "--merge/--replace", "merge", default=True,
        help="Append to the existing allowlist (default) or overwrite it.",
    )
    def pin_measurement(platform, image_id, measurement, field, instance_type, merge):
        """Record a launch measurement so deploy can auto-pin it (any cloud/TEE)."""
        from tee_crafter.core.measurements.shapes import instance_gen, instance_vcpu

        platform = platform.lower()
        value = measurement.strip().lower()
        if not _HEX_RE.match(value) or len(value) % 2 != 0:
            raise click.ClickException(
                "--measurement must be an even-length hexadecimal string.")

        measurements = [value]
        variants = []
        if instance_type:
            vcpu = instance_vcpu(platform, instance_type)
            gen = instance_gen(platform, instance_type)
            variant = {"instance_type": instance_type, "measurement": value}
            if vcpu is not None:
                variant["vcpu"] = vcpu
            if gen is not None:
                variant["cpu_gen"] = gen
                # There is no VM here to ask, so this generation is whatever the
                # instance type implies. Label it, because a bake-time variant
                # carries a generation that was read off the booted CPU and the
                # two must not look alike: on Azure the implied value has been
                # observed to be wrong.
                variant["cpu_gen_source"] = "instance_type"
            variants.append(variant)

        if merge:
            existing = _registry.lookup(platform, image_id) or {}
            for prior in existing.get("measurements") or []:
                if prior not in measurements:
                    measurements.append(prior)
            for prior_variant in existing.get("variants") or []:
                if prior_variant not in variants:
                    variants.append(prior_variant)

        try:
            path = _registry.store_many(
                platform, image_id, measurements, field=field,
                variants=variants or None, source="manual")
        except ValueError as exc:
            raise click.ClickException(str(exc))
        console.print(
            f"[green]✓ pinned {platform} measurement for {image_id}:[/green] "
            f"{value[:16]}… [dim]({path})[/dim]")
