"""Bake-time launch-measurement capture (auto-pin), all clouds + CVM TEEs.

After ``create_image`` produces a CVM image, we boot one throwaway instance
*from that image* (with the TEE enabled), read the firmware's launch
measurement over the cloud's remote-exec channel, persist it to the packaged
registry (:mod:`tee_crafter.core.measurements.registry`), and tear the instance
down.  The reader snippet is platform-aware
(:func:`tee_crafter.core.measurements.capture.capture_command`): SNP reads the
report MEASUREMENT (offset 0x90); TDX reads the quote MRTD (offset 184) via
configfs-tsm, identical framing to the runtime client.

Capture is **best-effort with a loud warning**: a bake never fails because the
measurement could not be read.  SNP-family bakes boot one throwaway VM per
(CPU generation, vCPU tier) (see :mod:`tee_crafter.core.measurements.shapes`)
and store every unique digest in the registry allowlist so any size in the
supported family works after a single bake.  TDX captures once (MRTD is
generation/vCPU-independent).
``deploy`` fails closed when sealed-``.env`` / BYOK is requested for an image
that has no registry entry (unless ``TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT``),
and an operator can always pin manually with
``tee-crafter internal pin-measurement``.

Remote-exec channel per cloud:

* **AWS** (``snp-aws`` / ``gpu-cc-aws``): SSM — agentless, keyless, runs as
  root, so no inbound SSH is opened.
* **Azure** (``snp-azure`` / ``tdx-azure`` / ``gpu-cc-azure``): a throwaway
  Confidential VM in a scratch resource group, read over SSH (``sudo``).
* **GCP** (``snp-gcp`` / ``tdx-gcp`` / ``gpu-cc-gcp``): a throwaway Confidential
  VM, read over an IAP tunnel (``sudo``).

Nitro (PCR0) and SGX (MRENCLAVE) are *build-time deterministic* — the builder
derives and pins them directly — so they are not captured from a booted
instance here.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from tee_crafter.cli.constants import console
from tee_crafter.core.measurements import capture as _capture
from tee_crafter.core.measurements import registry as _registry
from tee_crafter.core.measurements.shapes import (
    SELF_PIN_PLATFORMS,
    SNP_VCPU_SENSITIVE_PLATFORMS,
    TDX_SINGLE_CAPTURE_PLATFORMS,
    capture_shapes,
    instance_gen,
    instance_vcpu,
)


def _warn(msg: str) -> None:
    console.print(f"[yellow]⚠ measurement capture: {msg}[/yellow]")


def _bake_inputs_extra(platform: str) -> Dict[str, Any]:
    """Stamp the bake-time input digest onto the registry record.

    Lets a later deploy notice that this image was baked from different setup
    inputs than the code now in the tree -- the failure mode that made an
    already-fixed AppArmor bug look like a fresh regression. See
    ``cli/loaders.bake_inputs_digest``.
    """
    try:
        from tee_crafter.cli.loaders import bake_inputs_digest
        digest = bake_inputs_digest(platform)
    except Exception:
        return {}
    return {"bake_inputs_sha256": digest} if digest else {}


def _record(platform: str, image_id: str, measurement: str) -> str:
    path = _registry.store(platform, image_id, measurement,
                           extra=_bake_inputs_extra(platform))
    console.print(
        f"[green]✓ pinned measurement for {image_id}: {measurement[:16]}…[/green] "
        f"[dim]({path})[/dim]"
    )
    return path


def _record_many(
    platform: str,
    image_id: str,
    measurements: List[str],
    *,
    variants: Optional[List[Dict[str, Any]]] = None,
    vcpu_independent_gens: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    merged: Dict[str, Any] = dict(_bake_inputs_extra(platform))
    if extra:
        merged.update(extra)
    path = _registry.store_many(
        platform, image_id, measurements,
        variants=variants, vcpu_independent_gens=vcpu_independent_gens,
        extra=merged,
    )
    console.print(
        f"[green]✓ pinned {len(measurements)} measurement(s) for {image_id}[/green] "
        f"[dim]({path})[/dim]"
    )
    for gen in vcpu_independent_gens or []:
        console.print(
            f"  [dim]{gen}: vCPU-independent launch digest — every supported "
            "instance size of this generation is covered.[/dim]"
        )
    for variant in variants or []:
        shape = variant.get("instance_type") or variant.get("vm_size") or variant.get("machine_type")
        meas = variant.get("measurement", "")
        if shape and meas:
            console.print(f"  [dim]{shape}[/dim] → {meas[:16]}…")
    return path


def capture_platform_measurements(
    platform: str,
    image_id: str,
    *,
    region: Optional[str] = None,
    location: Optional[str] = None,
    zone: Optional[str] = None,
    confidential_type: Optional[str] = None,
    min_cpu_platform: Optional[str] = None,
) -> Optional[List[str]]:
    """Capture all launch measurements for ``platform`` after a bake.

    SNP-family platforms boot one throwaway VM per (CPU generation, vCPU tier)
    (see :mod:`tee_crafter.core.measurements.shapes`) so any size in the
    supported family works after a single bake.  TDX platforms capture once.
    Returns the list of unique hex measurements stored, or ``None`` when
    nothing was captured.
    """
    shapes = capture_shapes(platform)
    if not shapes:
        if platform in SELF_PIN_PLATFORMS:
            _warn(
                f"{platform} self-pins its measurement at runtime; not captured "
                "at bake (use `tee-crafter internal pin-measurement` to pin)."
            )
        else:
            _warn(f"no capture shapes configured for {platform}")
        return None

    if platform in SNP_VCPU_SENSITIVE_PLATFORMS:
        # Walk shapes grouped by CPU generation (Milan, Genoa) and, within a
        # generation, vCPU tiers ascending.  After the two smallest tiers of a
        # generation, if the digests match, that generation is vCPU-independent
        # (e.g. IGVM CVMs that start APs post-measurement) — we mark the gen and
        # skip its larger tiers.  If they differ, we keep walking the gen,
        # storing one digest per tier.  Each generation produces its own
        # firmware/microcode digest, so all are kept in the allowlist.
        variants: List[Dict[str, Any]] = []
        distinct: List[str] = []
        indep_gens: List[str] = []
        per_gen_digests: Dict[Optional[str], List[str]] = {}
        skip_gens: set = set()
        skipped: List[str] = []
        # PCR4/PCR7 are a property of the image, not of a vCPU tier, so a
        # single record-level copy is what the deploy reads. Kept per-variant
        # too, so a tier that somehow disagreed would be visible rather than
        # silently overwritten.
        nitrotpm_pcrs: Dict[str, str] = {}
        for shape in shapes:
            gen = instance_gen(platform, shape)
            if gen in skip_gens:
                continue
            meas: Optional[str] = None
            # What the VM reports about itself, where we can get it.  On Azure
            # the generation inferred from the size is unreliable, and grouping
            # by it is what let a host-generation difference be recorded as a
            # vCPU-tier difference.
            seen: Dict[str, Any] = {}
            variant_key = "instance_type"
            if platform == "snp-aws":
                if not region:
                    _warn(f"region required for {platform} capture")
                    return None
                meas = capture_snp_aws_measurement(
                    image_id, region, instance_type=shape, platform=platform,
                    store=False, observed=seen,
                )
            elif platform in ("snp-azure", "gpu-cc-azure"):
                if not location:
                    _warn(f"location required for {platform} capture")
                    return None
                meas = capture_azure_cvm_measurement(
                    image_id, location, vm_size=shape, platform=platform,
                    store=False, observed=seen,
                )
                variant_key = "vm_size"
            elif platform == "snp-gcp":
                if not zone:
                    _warn(f"zone required for {platform} capture")
                    return None
                ct = confidential_type or "SEV_SNP"
                meas = capture_gcp_cvm_measurement(
                    image_id, zone, machine_type=shape, platform=platform,
                    confidential_type=ct,
                    min_cpu_platform=min_cpu_platform,
                    store=False, observed=seen,
                )
                variant_key = "machine_type"
            else:
                _warn(f"unsupported SNP capture platform {platform!r}")
                return None
            if not meas:
                # Best-effort: a tier that fails to boot (e.g. vCPU quota) is
                # skipped, and smaller tiers still pin.
                #
                # Record which ones, because the absence is otherwise invisible.
                # `snp-azure` sat for weeks with no `_v6` measurement purely
                # because `standardDCasv6Family` quota was 0 at bake time, and
                # nothing in the resulting record said so -- it just looked like
                # a platform whose v6 SKUs had never been asked for.
                skipped.append(shape)
                continue
            vcpu = instance_vcpu(platform, shape)
            variant: Dict[str, Any] = {variant_key: shape, "measurement": meas}
            if vcpu is not None:
                variant["vcpu"] = vcpu
            # Prefer what the VM said over what the instance type implies, and
            # record which it was: a label that might be a guess must not be
            # indistinguishable from one that was read off the CPU.
            obs_gen = seen.get("cpu_gen")
            eff_gen = obs_gen or gen
            if eff_gen is not None:
                variant["cpu_gen"] = eff_gen
                variant["cpu_gen_source"] = "observed" if obs_gen else "instance_type"
            if seen.get("cpu_model"):
                variant["cpu_model"] = seen["cpu_model"]
            if seen.get("nitrotpm_pcrs"):
                variant["nitrotpm_pcrs"] = seen["nitrotpm_pcrs"]
                nitrotpm_pcrs.update(seen["nitrotpm_pcrs"])
            variants.append(variant)
            if meas not in distinct:
                distinct.append(meas)
            # Group by the effective generation, so two probes that landed on
            # different host generations are not compared against each other.
            gd = per_gen_digests.setdefault(eff_gen, [])
            if meas not in gd:
                gd.append(meas)
            # Early stop, and the independence *claim*, are two decisions.
            #
            # Stopping is cost control: after two tiers of a generation agree,
            # booting the larger ones is unlikely to teach us anything, and each
            # one is a real VM. That decision keys on the inferred generation,
            # because that is what the remaining shapes are grouped by.
            #
            # Recording `vcpu_independent_gens` is a claim about the platform,
            # and it is only made when the generation was *observed* for every
            # sample in the group. Two equal digests under two guessed labels do
            # not establish independence from the vCPU tier — they are equally
            # consistent with both probes having landed on the same host
            # generation, which is what actually happened on snp-azure.
            gen_variants = [v for v in variants if v.get("cpu_gen") == eff_gen]
            if len(gen_variants) >= 2 and len(gd) == 1:
                all_observed = all(
                    v.get("cpu_gen_source") == "observed" for v in gen_variants)
                if all_observed and eff_gen is not None \
                        and eff_gen not in indep_gens:
                    indep_gens.append(eff_gen)
                skip_gens.add(gen)
        if not variants:
            _warn(
                f"no measurements captured for {platform} image {image_id}; "
                "deploy will refuse sealed/BYOK until pinned manually."
            )
            return None
        if skipped:
            # Loud, because the operator can usually fix it -- and because the
            # cheapest moment to notice is now, while the bake output is still
            # on screen, rather than when a deploy is refused weeks later.
            covered = sorted({s for s in (
                variant.get("vm_size") or variant.get("instance_type")
                or variant.get("machine_type") for variant in variants) if s})
            _warn(
                f"{platform}: {len(skipped)} of {len(shapes)} capture shapes did "
                f"not boot and were not measured: {', '.join(skipped)}. "
                f"Measured: {', '.join(covered) or '(none)'}. A deploy of an "
                f"unmeasured shape is refused up front, so if you need one of "
                f"these, clear the blocker (usually vCPU quota for that SKU "
                f"family) and re-bake."
            )
        _record_many(
            platform, image_id, distinct,
            variants=variants, vcpu_independent_gens=indep_gens or None,
            extra={k: v for k, v in (
                ("capture_skipped_shapes", skipped),
                ("nitrotpm_pcrs", nitrotpm_pcrs),
            ) if v} or None,
        )
        return distinct

    if platform in TDX_SINGLE_CAPTURE_PLATFORMS:
        # MRTD is vCPU-independent: one capture on the default shape covers
        # every supported size for this platform.
        shape = shapes[0]
        meas: Optional[str] = None
        single_observed: Dict[str, Any] = {}
        if platform == "tdx-azure":
            if not location:
                _warn("location required for tdx-azure capture")
                return None
            meas = capture_azure_cvm_measurement(
                image_id, location, vm_size=shape,
                platform=platform, store=False,
            )
        elif platform in ("tdx-gcp", "gpu-cc-gcp"):
            if not zone:
                _warn(f"zone required for {platform} capture")
                return None
            meas = capture_gcp_cvm_measurement(
                image_id, zone, machine_type=shape,
                platform=platform, confidential_type="TDX",
                min_cpu_platform=min_cpu_platform or "Intel Sapphire Rapids",
                store=False, observed=single_observed,
            )
        if not meas:
            return None
        vtpm_pcrs = single_observed.get("vtpm_pcrs") or {}
        if vtpm_pcrs:
            _record_many(platform, image_id, [meas],
                         extra={"vtpm_pcrs": vtpm_pcrs})
            for idx in sorted(vtpm_pcrs, key=int):
                console.print(f"  [dim]vTPM PCR{idx}[/dim] → {vtpm_pcrs[idx][:16]}…")
        else:
            _record(platform, image_id, meas)
            if platform == "gpu-cc-gcp":
                _warn(
                    "no vTPM PCRs captured for gpu-cc-gcp. Its client compares "
                    "the server's PCR bundle against a pinned set and fails "
                    "closed when none is pinned, so a deploy from this image "
                    "will be refused unless TEE_CRAFTER_EXPECTED_VTPM_PCRS or "
                    "TEE_CRAFTER_ALLOW_UNPINNED_MEASUREMENT is set. The usual "
                    "cause is tpm2-tools missing from the image.")
        return [meas]

    _warn(f"no capture orchestrator for platform {platform!r}")
    return None


def capture_snp_aws_measurement(
    ami_id: str, region: str, *, instance_type: str, platform: str = "snp-aws",
    store: bool = True, observed: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Boot a throwaway SNP instance from ``ami_id`` and read its MEASUREMENT.

    Used by both ``snp-aws`` and ``gpu-cc-aws`` (both AMD SEV-SNP under the
    hood).  Returns the hex measurement on success (also stored in the registry
    under ``platform``), or ``None`` if anything went wrong (warning printed;
    bake continues).
    """
    import boto3

    from tee_crafter.cli.commands.baking.common.helpers import (
        get_default_subnet,
        get_ssm_instance_profile,
    )
    from tee_crafter.core.remote.ssm import run_ssm_command, wait_for_ssm

    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam", region_name=region)
    instance_id = None
    try:
        profile_name = get_ssm_instance_profile(iam)
        subnet = get_default_subnet(ec2)
        subnet_info = ec2.describe_subnets(SubnetIds=[subnet])["Subnets"][0]
        vpc_id = subnet_info["VpcId"]
        default_sg = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                     {"Name": "group-name", "Values": ["default"]}],
        )["SecurityGroups"][0]["GroupId"]
        resp = ec2.run_instances(
            ImageId=ami_id, InstanceType=instance_type, MinCount=1, MaxCount=1,
            IamInstanceProfile={"Name": profile_name},
            CpuOptions={"AmdSevSnp": "enabled"},
            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet,
                                "Groups": [default_sg], "AssociatePublicIpAddress": True}],
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            TagSpecifications=[{"ResourceType": "instance",
                                "Tags": [{"Key": "Name", "Value": "tee-crafter-measure-snp"},
                                         {"Key": "Project", "Value": "tee-crafter"}]}],
        )
        instance_id = resp["Instances"][0]["InstanceId"]
        ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
        if not wait_for_ssm(instance_id, region, timeout=300):
            _warn("SSM agent did not come online; image left unpinned.")
            return None
        ok, stdout, stderr = run_ssm_command(
            instance_id, _capture.capture_command(platform), region, timeout=120,
        )
        combined = (stdout or "") + (stderr or "")
        # Record what the CPU said about itself, not only what the instance type
        # implies. On AWS the two agree -- m6a is Milan, m7a is Genoa, different
        # hardware families -- so this is corroboration rather than a
        # correction. Worth having anyway: it is the only thing that would
        # notice if that ever stopped being true.
        if observed is not None:
            cpu_model = _capture.parse_cpu_model_line(combined)
            if cpu_model:
                observed["cpu_model"] = cpu_model
                gen = _capture.gen_from_cpu_model(cpu_model)
                if gen:
                    observed["cpu_gen"] = gen
            # NitroTPM measured-boot registers. Parsed here and not in the Azure
            # or GCP capture paths even though the probe is shared: those CVMs
            # have vTPMs and would answer tpm2_pcrread, but their PCRs are not
            # NitroTPM PCRs and nothing consumes them, so recording them under
            # this name would be a lie of labelling.
            #
            # These are what the deploy writes into the BYOK key policy as
            # kms:RecipientAttestation:NitroTPMPCR{4,7}; without them key release
            # on this platform stays identity-gated.
            pcrs = _capture.parse_nitrotpm_pcrs(combined)
            if pcrs:
                observed["nitrotpm_pcrs"] = pcrs
        measurement = _capture.parse_measurement_line(combined)
        if not ok or not measurement:
            _warn(
                "could not read SNP MEASUREMENT from the baked image; "
                f"deploy will refuse sealed/BYOK for {ami_id} until pinned.\n"
                f"{((stdout or '') + (stderr or ''))[-800:]}"
            )
            return None
        if store:
            _record(platform, ami_id, measurement)
        return measurement
    except Exception as exc:  # noqa: BLE001 - best-effort, never fail the bake
        _warn(f"unexpected error capturing measurement ({exc!r}); image left unpinned.")
        return None
    finally:
        if instance_id:
            try:
                ec2.terminate_instances(InstanceIds=[instance_id])
            except Exception:  # noqa: BLE001
                _warn(f"could not terminate measurement instance {instance_id}; clean up manually.")


def capture_nitrotpm_pcrs(
    ami_id: str, region: str, *, platform: str = "gpu-cc-aws",
    instance_type: str = "m6a.large", store: bool = True,
) -> Dict[str, str]:
    """Boot a cheap probe from ``ami_id`` and record its NitroTPM PCRs.

    For platforms whose CPU evidence is measured boot rather than a launch
    measurement -- ``gpu-cc-aws`` -- there is no SEV-SNP MEASUREMENT to read,
    so :func:`capture_snp_aws_measurement` does not apply.  What the verifier
    needs instead is PCR4 (boot manager code) and PCR7 (Secure Boot policy)
    from the finished AMI, which is what this captures.

    **Why a cheap instance type is correct here, and not a shortcut.**  PCR4
    hashes the binaries UEFI executed and PCR7 hashes the Secure Boot policy;
    both are properties of the AMI's boot chain and its ``UefiData``, neither
    depends on whether the host has a GPU attached.  Booting the real
    ``p5.4xlarge`` to read two registers would cost roughly two orders of
    magnitude more per bake and answer the same question.  The NVIDIA driver
    fails to load on a non-GPU shape, which does not matter: nothing in the
    boot measurement depends on it.

    The bake instance cannot be used for this even though it is already
    running, because it booted the *base* AMI -- its PCR4 measures the boot
    chain we are replacing, not the one being baked.

    Returns ``{"4": hex, "7": hex}``, or ``{}`` on any failure (warning
    printed, bake continues).  An empty result is honest: the client then
    verifies the attestation document's authenticity but has no reference to
    compare its PCRs against, and says so.
    """
    import boto3

    from tee_crafter.cli.commands.baking.common.helpers import (
        get_default_subnet,
        get_ssm_instance_profile,
    )
    from tee_crafter.core.remote.ssm import run_ssm_command, wait_for_ssm

    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam", region_name=region)
    instance_id = None
    try:
        profile_name = get_ssm_instance_profile(iam)
        subnet = get_default_subnet(ec2)
        subnet_info = ec2.describe_subnets(SubnetIds=[subnet])["Subnets"][0]
        default_sg = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [subnet_info["VpcId"]]},
                     {"Name": "group-name", "Values": ["default"]}],
        )["SecurityGroups"][0]["GroupId"]
        resp = ec2.run_instances(
            ImageId=ami_id, InstanceType=instance_type, MinCount=1, MaxCount=1,
            IamInstanceProfile={"Name": profile_name},
            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet,
                                "Groups": [default_sg],
                                "AssociatePublicIpAddress": True}],
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            TagSpecifications=[{"ResourceType": "instance",
                                "Tags": [{"Key": "Name",
                                          "Value": "tee-crafter-measure-nitrotpm"},
                                         {"Key": "Project", "Value": "tee-crafter"}]}],
        )
        instance_id = resp["Instances"][0]["InstanceId"]
        ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
        if not wait_for_ssm(instance_id, region, timeout=300):
            _warn("SSM agent did not come online; NitroTPM PCRs not captured.")
            return {}
        ok, stdout, stderr = run_ssm_command(
            instance_id, _capture.nitrotpm_pcr_command(), region, timeout=120)
        pcrs = _capture.parse_nitrotpm_pcrs((stdout or "") + (stderr or ""))
        if not pcrs:
            _warn(
                f"no NitroTPM PCRs read from {ami_id}. The usual cause is an "
                "AMI registered without TpmSupport=v2.0 -- CreateImage cannot "
                "set it, only RegisterImage can. The client will verify the "
                "attestation document but have no reference PCRs to compare.\n"
                f"{((stdout or '') + (stderr or ''))[-600:]}")
            return {}
        if store:
            path = _registry.store_many(
                platform, ami_id, [], field="nitrotpm_pcrs",
                extra={**_bake_inputs_extra(platform), "nitrotpm_pcrs": pcrs,
                       "nitrotpm_pcr_probe_instance_type": instance_type},
            )
            console.print(
                f"[green]✓ pinned NitroTPM PCRs for {ami_id}[/green] "
                f"[dim]({path})[/dim]")
            for idx in sorted(pcrs, key=int):
                console.print(f"  [dim]PCR{idx}[/dim] → {pcrs[idx][:16]}…")
        return pcrs
    except Exception as exc:  # noqa: BLE001 - best-effort, never fail the bake
        _warn(f"unexpected error capturing NitroTPM PCRs ({exc!r}).")
        return {}
    finally:
        if instance_id:
            try:
                ec2.terminate_instances(InstanceIds=[instance_id])
            except Exception:  # noqa: BLE001
                _warn(f"could not terminate PCR probe instance {instance_id}; "
                      "clean up manually.")


def capture_azure_cvm_measurement(
    image_id: str, location: str, *, vm_size: str, platform: str,
    store: bool = True, observed: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Boot a throwaway Azure Confidential VM from ``image_id`` and read its
    launch measurement (SNP MEASUREMENT or TDX MRTD, by ``platform``).

    Used by snp-azure / tdx-azure / gpu-cc-azure.  Best-effort: returns the hex
    measurement (also stored in the registry) or ``None`` (warning printed; the
    bake continues).

    ``observed`` is an optional out-dict.  When given it receives what the VM
    reported about *itself* — ``cpu_model`` and the ``cpu_gen`` derived from it.
    That exists because Azure is the one cloud where the CPU generation cannot
    be read off the instance type: ``Standard_DCxas_v5`` is scheduled on Milan
    or Genoa, and the SEV-SNP launch measurement depends on the host firmware,
    so two probes of the same size can legitimately differ. It is an out-param
    rather than a wider return type so the existing callers and their tests keep
    treating the return value as the measurement.
    """
    import os
    import shutil
    import subprocess
    import tempfile
    import uuid

    import click

    from tee_crafter.cli.commands.baking.common.azure_cvm import create_azure_cvm
    from tee_crafter.cli.commands.baking.common.helpers import az_cli
    from tee_crafter.core.remote.azure_ssh import run_ssh_command, wait_for_ssh

    try:
        command = _capture.capture_command(platform, sudo=True)
    except ValueError as exc:
        _warn(str(exc))
        return None

    rg = f"tee-crafter-measure-{uuid.uuid4().hex[:8]}"
    ssh_dir = None
    try:
        ssh_dir = tempfile.mkdtemp(prefix="tee_crafter_measure_")
        key = os.path.join(ssh_dir, "key")
        subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", key, "-N", ""],
                       capture_output=True, check=True)
        os.chmod(key, 0o600)
        az_cli("group", "create", "--name", rg, "--location", location)
        # Reuse the bake path's creator rather than calling `az vm create`
        # directly.  A raw call here was losing every measurement to the same
        # Azure CLI defect the bake already survives: azure-cli 2.89.1 on
        # Python 3.14 intermittently fails a successful `vm create` with
        # "The content for this response was already consumed", and
        # create_azure_cvm's recovery re-checks with `vm show` and retries
        # instead of giving up.  Observed on 2026-08-22: the snp-azure bake VM
        # came up fine via that recovery while the measurement VM three lines
        # later failed 3/3 and left the image unpinned.
        public_ip = create_azure_cvm(
            None, None, rg, "measure-vm", location, vm_size, f"{key}.pub",
            platform_label=platform, image=image_id,
        )
        if not public_ip or not wait_for_ssh(key, timeout=240, host=public_ip):
            _warn("Azure measurement VM SSH not reachable; image left unpinned.")
            return None
        ok, stdout, stderr = run_ssh_command(command, key, timeout=180, host=public_ip)
        combined = (stdout or "") + (stderr or "")
        if observed is not None:
            cpu_model = _capture.parse_cpu_model_line(combined)
            if cpu_model:
                observed["cpu_model"] = cpu_model
                gen = _capture.gen_from_cpu_model(cpu_model)
                if gen:
                    observed["cpu_gen"] = gen
        measurement = _capture.parse_measurement_line(combined)
        if not ok or not measurement:
            _warn(
                f"could not read measurement; deploy will refuse sealed/BYOK for "
                f"{image_id} until pinned.\n{((stdout or '') + (stderr or ''))[-600:]}"
            )
            return None
        if store:
            _record(platform, image_id, measurement)
        return measurement
    except click.ClickException as exc:
        # create_azure_cvm signals give-up (quota, non-retriable rejection, or
        # retries exhausted) by raising.  Capture stays best-effort, so surface
        # its message and leave the image unpinned rather than failing the bake.
        _warn(f"could not launch Azure measurement VM; image left unpinned.\n"
              f"{exc.format_message()[:600]}")
        return None
    except Exception as exc:  # noqa: BLE001 - best-effort, never fail the bake
        _warn(f"unexpected error capturing measurement ({exc!r}); image left unpinned.")
        return None
    finally:
        az_cli("group", "delete", "--name", rg, "--yes", "--no-wait", check=False)
        if ssh_dir:
            shutil.rmtree(ssh_dir, ignore_errors=True)


def capture_gcp_cvm_measurement(
    image_uri: str, zone: str, *, machine_type: str, platform: str,
    confidential_type: str, min_cpu_platform: Optional[str] = None,
    store: bool = True, observed: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Boot a throwaway GCP Confidential VM from ``image_uri`` and read its
    launch measurement (SNP MEASUREMENT or TDX MRTD, by ``platform``).

    Used by snp-gcp / tdx-gcp / gpu-cc-gcp.  ``image_uri`` is the
    ``projects/<p>/global/images/<name>`` URI returned by the bake.
    Best-effort: returns the hex measurement or ``None``.
    """
    import os
    import shutil
    import subprocess
    import tempfile
    import time

    try:
        command = _capture.capture_command(platform, sudo=True)
    except ValueError as exc:
        _warn(str(exc))
        return None

    parts = image_uri.strip("/").split("/")
    image_name = parts[-1]
    if "projects" in parts:
        project = parts[parts.index("projects") + 1]
    else:
        proj = subprocess.run(["gcloud", "config", "get-value", "project"],
                              capture_output=True, text=True)
        project = proj.stdout.strip()
    if not project:
        _warn("no GCP project resolvable for measurement capture; image left unpinned.")
        return None

    def _gcloud(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(["gcloud", *args, "--format=json"],
                              capture_output=True, text=True)

    instance = f"tee-crafter-measure-{int(time.time())}"
    ssh_dir = None
    created = False
    try:
        ssh_dir = tempfile.mkdtemp(prefix="tee_crafter_measure_")
        key = os.path.join(ssh_dir, "key")
        subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", key, "-N", ""],
                       capture_output=True, check=True)
        os.chmod(key, 0o600)
        with open(f"{key}.pub", "r", encoding="utf-8") as fh:
            pub = fh.read().strip()
        create_args = [
            "compute", "instances", "create", instance,
            f"--project={project}", f"--zone={zone}", f"--machine-type={machine_type}",
            f"--image={image_name}", f"--image-project={project}",
            "--boot-disk-size=30GB", "--boot-disk-type=pd-ssd",
            f"--confidential-compute-type={confidential_type}",
            "--maintenance-policy=TERMINATE",
            f"--metadata=ssh-keys=tee_bake:{pub}",
            "--shielded-secure-boot", "--shielded-vtpm",
            "--shielded-integrity-monitoring", "--scopes=cloud-platform",
        ]
        if min_cpu_platform:
            create_args.append(f"--min-cpu-platform={min_cpu_platform}")
        res = _gcloud(*create_args)
        if res.returncode != 0:
            _warn(f"could not launch GCP measurement VM; image left unpinned.\n{res.stderr[:600]}")
            return None
        created = True
        time.sleep(30)
        from tee_crafter.core.remote.gcp_ssh import IAPTunnel, run_ssh_command, wait_for_ssh
        with IAPTunnel(instance, zone, project, 22) as tunnel:
            if not wait_for_ssh(key, user="tee_bake", timeout=300,
                                host="localhost", port=tunnel.local_port):
                _warn("GCP measurement VM SSH not reachable; image left unpinned.")
                return None
            ok, stdout, stderr = run_ssh_command(
                command, key, user="tee_bake", timeout=180,
                host="localhost", port=tunnel.local_port,
            )
        combined = (stdout or "") + (stderr or "")
        # As on AWS this corroborates rather than corrects: one n2d name spans
        # generations, but the bake and the deploy both pin `min_cpu_platform`,
        # which is what makes the generation determined here.
        if observed is not None:
            # gpu-cc-gcp publishes a vTPM PCR bundle in its RA-TLS certificate
            # and its client fails closed unless a reference set is pinned, so
            # without this the platform cannot deploy without an explicit
            # opt-out. Read on the probe VM that is already running for the
            # MRTD capture -- no extra instance, no extra cost.
            vtpm = _capture.parse_vtpm_pcrs(combined)
            if vtpm:
                observed["vtpm_pcrs"] = vtpm

            cpu_model = _capture.parse_cpu_model_line(combined)
            if cpu_model:
                observed["cpu_model"] = cpu_model
                gen = _capture.gen_from_cpu_model(cpu_model)
                if gen:
                    observed["cpu_gen"] = gen
        measurement = _capture.parse_measurement_line(combined)
        if not ok or not measurement:
            _warn(
                f"could not read measurement; deploy will refuse sealed/BYOK for "
                f"{image_uri} until pinned.\n{((stdout or '') + (stderr or ''))[-600:]}"
            )
            return None
        if store:
            _record(platform, image_uri, measurement)
        return measurement
    except Exception as exc:  # noqa: BLE001 - best-effort, never fail the bake
        _warn(f"unexpected error capturing measurement ({exc!r}); image left unpinned.")
        return None
    finally:
        if created:
            _gcloud("compute", "instances", "delete", instance,
                    f"--zone={zone}", f"--project={project}", "--quiet", check=False)
        if ssh_dir:
            shutil.rmtree(ssh_dir, ignore_errors=True)
