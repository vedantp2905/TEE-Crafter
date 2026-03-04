"""Deploy flow Steps 5–6: Docker verify, enclave build, client template, Terraform."""

import os
from nitro_agent.core.builder import render_client_template
from nitro_agent.core.verification import verify_docker_build
from nitro_agent.core.enclave import build_enclave
from nitro_agent.llm.iac import generate_terraform_code
from nitro_agent.core.iac import stage_terraform, verify_terraform_syntax
from nitro_agent.core.audit import BuildAuditTrail, sha256_file, sha256_hex
from nitro_agent.cli.loaders import load_root_ca
from nitro_agent.cli.audit_helpers import save_audit_trail
from nitro_agent.cli.constants import console


def _template_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "templates")


def run_phases_5_to_6(progress, audit, build_dir, cpu, ram, prompt_iac):
    """Steps 5a–6: Docker verify, enclave build, client template, Terraform. Returns hashes or None."""
    valid, msg = verify_docker_build(build_dir)
    if not valid:
        console.print(f"\n[bold red]Warning: Docker build check failed:[/bold red]\n{msg}")
    audit.record("Phase 2: Packaging", "Docker build dry-run", "pass" if valid else "fail")
    task_enclave = progress.add_task("[yellow]Step 5a: Compiling Enclave Image File (.eif)...[/yellow]", total=None)
    success, hashes, message = build_enclave(build_dir)
    if not success:
        progress.update(task_enclave, description="[bold red]✗ Step 5a Failed.[/bold red]")
        console.print(f"[red]Enclave Build Error:[/red]\n{message}")
        audit.record("Phase 2: Packaging", "EIF build (nitro-cli build-enclave)", "fail", error=message[:500])
        save_audit_trail(audit, build_dir, console)
        return None
    progress.update(task_enclave, description="[green]✓ Step 5a: Enclave built successfully.[/green]")
    eif_path = os.path.join(build_dir, "app.eif")
    audit.record("Phase 2: Packaging", "EIF build (nitro-cli build-enclave)", "pass",
                 eif_sha256=sha256_file(eif_path), PCR0=hashes.get("PCR0", ""), PCR1=hashes.get("PCR1", ""),
                 PCR2=hashes.get("PCR2", ""), platform="linux/arm64")
    task_client = progress.add_task("[yellow]Step 5b: Injecting PCRs into client script...[/yellow]", total=None)
    template_dir = _template_dir()
    audit.record_file_hash("Phase 2: Packaging", "client template (TCB)", os.path.join(template_dir, "client.template.py"))
    root_ca_pem = load_root_ca()
    try:
        client_script = render_client_template(pcr_hashes=hashes, root_ca=root_ca_pem)
        with open(os.path.join(build_dir, "client.py"), "w", encoding="utf-8") as f:
            f.write(client_script)
        progress.update(task_client, description="[green]✓ Step 5b: Secure client script configured.[/green]")
        audit.record("Phase 2: Packaging", "Client script rendered with PCRs", "pass",
                     client_py_sha256=sha256_hex(client_script), root_ca_sha256=sha256_hex(root_ca_pem) if root_ca_pem else "", pcr_values_injected=True)
    except Exception as e:
        import traceback
        progress.update(task_client, description=f"[bold red]✗ Step 5b Failed: {str(e)}[/bold red]")
        console.print(f"[red]{traceback.format_exc()}[/red]")
        audit.record("Phase 2: Packaging", "Client script rendering", "fail", error=str(e))
        save_audit_trail(audit, build_dir, console)
        return None
    task_iac = progress.add_task("[yellow]Step 6: Generating Terraform...[/yellow]", total=None)
    audit.record_file_hash("Phase 3: IaC Generation", "Terraform template (TCB)", os.path.join(template_dir, "main.template.tf"))
    try:
        terraform_code = generate_terraform_code(cpu=cpu, ram=ram, pcr_hashes=hashes, prompt_iac=prompt_iac or "", debug_build_dir=build_dir)
        stage_terraform(build_dir, terraform_code, pcr_hashes=hashes)
        main_tf_path = os.path.join(build_dir, "main.tf")
        main_tf_content = open(main_tf_path, "r", encoding="utf-8").read() if os.path.isfile(main_tf_path) else ""
        pcr_bound = all(hashes.get(f"PCR{i}", "") and hashes[f"PCR{i}"] in main_tf_content for i in range(3))
        https_only = ":443" in main_tf_content or "443" in main_tf_content
        vpc_endpoint = "aws_vpc_endpoint" in main_tf_content
        no_ssh = ":22" not in main_tf_content
        audit.record("Phase 3: IaC Generation", "Terraform config generated", "pass",
                     main_tf_sha256=sha256_hex(main_tf_content), kms_policy_pcr_bound=pcr_bound,
                     security_group_https_only=https_only, vpc_endpoint_for_kms=vpc_endpoint, no_ssh_ingress=no_ssh)
        tf_ok, tf_msg = verify_terraform_syntax(build_dir)
        if not tf_ok:
            console.print(f"\n[bold yellow]Warning: Terraform syntax:[/bold yellow]\n{tf_msg}\n")
            progress.update(task_iac, description="[yellow]! Step 6: Terraform generated but not fully validated.[/yellow]")
            audit.record("Phase 3: IaC Generation", "Terraform validate", "fail")
        else:
            progress.update(task_iac, description="[green]✓ Step 6: Terraform infrastructure code generated.[/green]")
            audit.record("Phase 3: IaC Generation", "Terraform validate", "pass")
    except Exception as e:
        import traceback
        progress.update(task_iac, description=f"[bold red]✗ Step 6 Failed: {str(e)}[/bold red]")
        console.print(f"[red]{traceback.format_exc()}[/red]")
        audit.record("Phase 3: IaC Generation", "Terraform generation", "fail", error=str(e))
        save_audit_trail(audit, build_dir, console)
        return None
    return hashes
