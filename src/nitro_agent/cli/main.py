import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import os
import sys
from dotenv import load_dotenv
from rich.repr import T

# Load environment variables from .env if present
load_dotenv()

from nitro_agent.core.ingestion import ingest_directory
from nitro_agent.llm.chains import generate_vsock_wrapper
from nitro_agent.core.builder import stage_artifacts, render_dockerfile_template, render_client_template
from nitro_agent.core.verification import verify_docker_build, verify_app_is_not_server
from nitro_agent.core.enclave import build_enclave, parse_enclave_cid, get_enclave_hashes
from nitro_agent.llm.iac import generate_terraform_code
from nitro_agent.core.iac import stage_terraform, verify_terraform_syntax, run_terraform_apply, get_terraform_outputs, run_terraform_destroy
from nitro_agent.core.ssm import wait_for_ssm, upload_file_via_s3, run_ssm_command

console = Console()


def _load_remote_setup_template() -> str:
    """Load the remote host setup script template from templates dir."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, "..", "templates", "remote_setup_script.sh")
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()

def _load_root_ca() -> str:
    """Load the AWS Nitro Root CA PEM from the package."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Assuming root.pem is in src/nitro_agent/resources/root.pem, so up one level from cli/
    root_path = os.path.join(current_dir, "..", "resources", "root.pem")
    if os.path.exists(root_path):
        with open(root_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

def run_deployment_phase(
    console,
    build_dir,
    cpu,
    ram,
    hashes,
    prompt_iac,
    auto_approve,
    teardown,
    source_code=None,
    prompt_vsock=None,
    data_sample_str=None
):
    """
    Executes the deployment phase: Terraform apply, self-healing, and post-deployment verification.
    """
    # Step 7: Terraform apply (single Progress block - must exit before starting another)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task_apply = progress.add_task("[yellow]Step 7: Executing Terraform apply (infrastructure)...[/yellow]", total=None)
        
        max_retries = int(os.getenv("NITRO_AGENT_PHASE4_MAX_RETRIES", "3"))
        env_auto_approve = os.getenv("NITRO_AGENT_TF_AUTO_APPROVE", "").lower() in {"1", "true", "yes"}
        should_auto_approve = auto_approve or env_auto_approve

        # No longer using SSH keys, we rely entirely on AWS credentials and SSM
        if "TF_VAR_key_name" in os.environ:
             console.print(f"[dim]Using AWS Key Pair (for manual debug only): {os.environ['TF_VAR_key_name']}[/dim]")

        apply_success = False
        last_error_msg = ""

        for attempt in range(max_retries):
            progress.update(task_apply, description=f"[yellow]Step 7: Terraform apply (Attempt {attempt+1}/{max_retries})...[/yellow]")
            
            success, stdout, stderr = run_terraform_apply(build_dir, auto_approve=should_auto_approve)
            
            if success:
                apply_success = True
                progress.update(task_apply, description="[green]✓ Step 7: Deployment successful![/green]")
                break
            
            # If failed, log and retry (transient errors)
            error_summary = (stderr.strip() or stdout.strip())[-1000:] 
            last_error_msg = error_summary
            console.print(f"[bold red]Terraform Apply Failed (Attempt {attempt+1}):[/bold red]\n{error_summary}")
            
            if attempt < max_retries - 1:
                progress.update(task_apply, description=f"[red]! Apply failed. Retrying in case of transient errors...[/red]")
                import time
                time.sleep(5) # Wait 5s before retry

    # Outer Progress has exited - safe to start a new one for Step 8
    if not apply_success:
        console.print(f"\n[bold red]Deployment failed after {max_retries} Terraform apply attempts.[/bold red]")
        console.print(f"[red]Last Error:[/red] {last_error_msg}\n")
        # We still proceed to optional teardown so that any partially-created
        # infrastructure managed by Terraform is cleaned up when requested.
    else:
        console.print(f"\n[bold green]Step 7 complete.[/bold green] Infrastructure successfully deployed via Terraform.\n")

        # Post-deployment Automation (Step 8): wait for SSM then run setup
        outputs = get_terraform_outputs(build_dir)
        public_ip = outputs.get("public_ip", "N/A")
        instance_id = outputs.get("instance_id", "N/A")
        bucket_name = outputs.get("deployment_bucket", "N/A")
        
        console.print(Panel(
            f"[cyan]Instance ID:[/cyan] {instance_id}\n"
            f"[cyan]Public IP:[/cyan] {public_ip}\n"
            f"[cyan]S3 Bucket:[/cyan] {bucket_name}",
            title="[bold green]Deployment Outputs[/bold green]",
            border_style="green"
        ))
        automation_success = False

        if instance_id != "N/A" and bucket_name != "N/A":
            with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                        transient=False,
                    ) as progress:
                        task_ssm = progress.add_task("[yellow]Step 8a: Waiting for AWS Systems Manager (SSM) agent to come online...[/yellow]", total=None)
                        
                        # 1. Wait for SSM
                        import boto3
                        boto3_region = boto3.Session().region_name
                        aws_region = os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION") or boto3_region or "us-east-2"
                        if wait_for_ssm(instance_id, aws_region):
                            progress.update(task_ssm, description="[green]✓ Step 8a: SSM connected to host.[/green]")

                            # 2. Wait for cloud-init / user_data to finish so Nitro Enclaves
                            #    packages (including nitro-cli) are fully installed.
                            task_cloud_init = progress.add_task("[yellow]Step 8b: Waiting for cloud-init (user_data) to complete...[/yellow]", total=None)
                            ci_cmd = "cloud-init status --wait || true"
                            ci_ok, ci_out, ci_err = run_ssm_command(instance_id, ci_cmd, aws_region)
                            if ci_ok:
                                progress.update(task_cloud_init, description="[green]✓ Step 8b: cloud-init completed on host.[/green]")
                            else:
                                # We continue even if this check fails; logs will show details if needed.
                                progress.update(task_cloud_init, description="[yellow]! Step 8b: cloud-init wait failed; continuing anyway.[/yellow]")
                                console.print(f"[dim yellow]cloud-init status output:[/dim yellow]\n{ci_out}\n[dim yellow]cloud-init status error:[/dim yellow]\n{ci_err}")

                            # 2b. Self-heal: ensure Nitro Enclaves host prerequisites are present
                            #     (nitro-cli, allocator, vsock proxy, docker) via template script.
                            task_nitro = progress.add_task("[yellow]Step 8c: Verifying Nitro Enclaves host setup...[/yellow]", total=None)
                            enclave_memory = max(512, ram)
                            allocator_mb = enclave_memory + 1024
                            import boto3
                            boto3_region = boto3.Session().region_name
                            aws_region = os.getenv("TF_VAR_aws_region") or os.getenv("AWS_REGION") or boto3_region or "us-east-2"
                            setup_template = _load_remote_setup_template()
                            setup_body = setup_template.format(
                                allocator_mb=allocator_mb,
                                cpu=cpu,
                                aws_region=aws_region
                            )
                            
                            # Create a temporary local script file
                            setup_script_path = os.path.join(build_dir, "remote_setup_script.sh")
                            with open(setup_script_path, "w", encoding="utf-8") as f:
                                f.write(setup_body)
                                
                            # Upload via S3 and execute
                            s3_ok, s3_msg = upload_file_via_s3(setup_script_path, bucket_name, "remote_setup_script.sh", instance_id, "/home/ec2-user/remote_setup_script.sh", aws_region)
                            
                            if s3_ok:
                                run_ssm_command(instance_id, "chmod +x /home/ec2-user/remote_setup_script.sh", aws_region)
                                setup_ok, setup_out, setup_err = run_ssm_command(instance_id, "sudo /home/ec2-user/remote_setup_script.sh", aws_region)
                                
                                if not setup_ok:
                                    console.print(f"[bold red]Host setup script failed with exit code[/bold red]")
                                    console.print(f"[red]STDOUT:[/red]\n{setup_out}\n[red]STDERR:[/red]\n{setup_err}")

                                # Finally, verify nitro-cli exists.
                                check_nitro_cmd = "if command -v nitro-cli >/dev/null 2>&1; then echo nitro_ok; else echo nitro_missing; fi"
                                nitro_ok, nitro_out, nitro_err = run_ssm_command(instance_id, check_nitro_cmd, aws_region)
                                if nitro_ok and "nitro_ok" in nitro_out:
                                    progress.update(task_nitro, description="[green]✓ Step 8c: Nitro Enclaves host environment ready.[/green]")
                                else:
                                    progress.update(task_nitro, description="[bold red]✗ Step 8c Failed: Nitro Enclaves CLI not available on host.[/bold red]")
                                    console.print(f"[red]Nitro CLI Check STDOUT:[/red] {nitro_out}\n[red]Nitro CLI Check STDERR:[/red] {nitro_err}")
                            else:
                                progress.update(task_nitro, description=f"[bold red]✗ Step 8c Failed: Could not upload setup script: {s3_msg}[/bold red]")

                            # 3. Upload EIF
                            task_upload = progress.add_task("[yellow]Step 8d: Uploading Enclave Image...[/yellow]", total=None)
                            # build_enclave() writes app.eif into build_dir
                            eif_local = os.path.join(build_dir, "app.eif")
                            
                            if os.path.exists(eif_local):
                                success, msg = upload_file_via_s3(eif_local, bucket_name, "app.eif", instance_id, "/home/ec2-user/app.eif", aws_region)
                                if success:
                                    progress.update(task_upload, description="[green]✓ Step 8d: EIF uploaded to host.[/green]")
                                    
                                    # 4. Run Enclave
                                    task_run = progress.add_task("[yellow]Step 8e: Starting enclave...[/yellow]", total=None)
                                    enclave_memory = max(512, ram)
                                    run_cmd = f"sudo /usr/bin/nitro-cli run-enclave --cpu-count {cpu} --memory {enclave_memory} --eif-path /home/ec2-user/app.eif --enclave-cid 16"
                                    success, stdout, stderr = run_ssm_command(instance_id, run_cmd, aws_region)
                                    
                                    if success:
                                            progress.update(task_run, description="[green]✓ Step 8e: Enclave started.[/green]")
                                            
                                            # If stdout doesn't have the EnclaveCID natively because of SSM output parsing limits,
                                            # run a second command to describe it.
                                            cid = parse_enclave_cid(stdout)
                                            if not cid:
                                                desc_success, desc_out, desc_err = run_ssm_command(instance_id, "nitro-cli describe-enclaves", aws_region)
                                                if desc_success:
                                                    import json
                                                    try:
                                                        enclaves = json.loads(desc_out)
                                                        if enclaves and isinstance(enclaves, list):
                                                            cid = str(enclaves[0].get("EnclaveCID", ""))
                                                    except Exception:
                                                        pass
                                                        
                                            if cid:
                                                task_proxy = progress.add_task("[yellow]Step 8f: Starting host proxy service...[/yellow]", total=None)
                                                
                                                # Upload host_proxy.py and start it
                                                host_proxy_local = os.path.join(build_dir, "host_proxy.py")
                                                upload_file_via_s3(host_proxy_local, bucket_name, "host_proxy.py", instance_id, "/home/ec2-user/host_proxy.py", aws_region)
                                                hp_success, hp_out, hp_err = run_ssm_command(instance_id, "sudo systemctl restart host-proxy.service", aws_region)
                                                if hp_success:
                                                    progress.update(task_proxy, description="[green]✓ Step 8f: Host proxy service started.[/green]")
                                                else:
                                                    progress.update(task_proxy, description="[bold red]✗ Step 8f Failed: Failed to start host proxy service.[/bold red]")
                                                    console.print(f"[red]Host Proxy Restart STDOUT:[/red]\n{hp_out}\n[red]Host Proxy Restart STDERR:[/red]\n{hp_err}")
                                                
                                                # Small delay to allow the Uvicorn proxy to fully start and bind to port 443
                                                import time
                                                time.sleep(10)
                                                
                                                # Run client locally on our own machine!
                                                import subprocess
                                                task_client_run = progress.add_task(f"[yellow]Step 8g: Running local client against proxy ({public_ip})...[/yellow]", total=None)
                                                
                                                try:
                                                    c_res = subprocess.run(
                                                        [sys.executable, os.path.join(build_dir, "client.py"), public_ip, outputs.get('kms_key_arn', '')],
                                                        cwd=build_dir,
                                                        capture_output=True,
                                                        text=True,
                                                        timeout=120
                                                    )
                                                    success = c_res.returncode == 0
                                                    c_out = c_res.stdout
                                                    c_err = c_res.stderr
                                                except Exception as e:
                                                    success = False
                                                    c_err = str(e)
                                                    c_out = ""
                                                
                                                if success:
                                                    progress.update(task_client_run, description="[green]✓ Step 8g: Client execution successful.[/green]")
                                                    console.print(Panel(c_out, title="[bold blue]Client Response[/bold blue]", border_style="blue"))
                                                    
                                                    # Save output to file (JSON if valid, else TXT)
                                                    import json
                                                    try:
                                                        json_obj = json.loads(c_out)
                                                        out_path = os.path.join(build_dir, "client_output.json")
                                                        with open(out_path, "w", encoding="utf-8") as f:
                                                            json.dump(json_obj, f, indent=2)
                                                        console.print(f"[dim]Client output saved to: {out_path}[/dim]")
                                                    except json.JSONDecodeError:
                                                        out_path = os.path.join(build_dir, "client_output.txt")
                                                        with open(out_path, "w", encoding="utf-8") as f:
                                                            f.write(c_out)
                                                        console.print(f"[dim]Client output saved to: {out_path}[/dim]")
                                                    except Exception as e:
                                                        console.print(f"[red]Failed to save output to file: {e}[/red]")
                                                    
                                                    automation_success = True
                                                else:
                                                    progress.update(task_client_run, description=f"[bold red]✗ Step 8g Failed: Client Execution Failed.[/bold red]")
                                                    error_output = f"STDOUT:\n{c_out}\nSTDERR:\n{c_err}" if c_out and c_err else (c_err or c_out)
                                                    console.print(Panel(error_output, title="[bold red]Client Error[/bold red]", border_style="red"))
                                                    
                                                    # Fetch proxy logs for debugging
                                                    console.print("[yellow]Fetching host proxy logs for debugging...[/yellow]")
                                                    log_success, log_out, log_err = run_ssm_command(instance_id, "sudo journalctl -u host-proxy.service -n 100 --no-pager", aws_region)
                                                    if log_success:
                                                        console.print(Panel(log_out, title="[bold yellow]host-proxy.service logs[/bold yellow]", border_style="yellow"))
                                                    else:
                                                        console.print(f"[red]Failed to fetch proxy logs: {log_err}[/red]")
                                                    
                                                    # Also fetch vsock proxy logs
                                                    console.print("[yellow]Fetching vsock-proxy logs for debugging...[/yellow]")
                                                    vsock_success, vsock_out, vsock_err = run_ssm_command(instance_id, "sudo journalctl -u nitro-enclaves-vsock-proxy.service -n 100 --no-pager", aws_region)
                                                    if vsock_success:
                                                        console.print(Panel(vsock_out, title="[bold yellow]nitro-enclaves-vsock-proxy.service logs[/bold yellow]", border_style="yellow"))
                                                    
                                                    # Fetch enclave console output (contains app_vsock.py debug logs)
                                                    console.print("[yellow]Fetching enclave console logs...[/yellow]")
                                                    enclave_console_cmd = "ENCLAVE_ID=$(nitro-cli describe-enclaves | python3 -c \"import sys,json;d=json.load(sys.stdin);print(d[0]['EnclaveID'] if d else '')\" 2>/dev/null); if [ -n \"$ENCLAVE_ID\" ]; then timeout 3 nitro-cli console --enclave-id $ENCLAVE_ID 2>/dev/null || echo '(console read timed out)'; else echo '(no enclave found)'; fi"
                                                    enc_success, enc_out, enc_err = run_ssm_command(instance_id, enclave_console_cmd, aws_region)
                                                    if enc_success and enc_out.strip():
                                                        console.print(Panel(enc_out, title="[bold yellow]Enclave Console (app_vsock.py logs)[/bold yellow]", border_style="yellow"))
                                                    else:
                                                        console.print(f"[dim]Enclave console not available: {enc_err or 'empty'}[/dim]")
                                            else:
                                                console.print("[yellow]Could not parse Enclave CID from output. Skipping client run.[/yellow]")

                                    else:
                                            progress.update(task_run, description=f"[bold red]✗ Step 8e Failed:[/bold red] Failed to start enclave.")
                                            console.print(f"[red]Enclave Start STDOUT:[/red]\n{stdout}\n[red]Enclave Start STDERR:[/red]\n{stderr}")
                                else:
                                    progress.update(task_upload, description=f"[bold red]✗ Step 8d Failed (Upload):[/bold red] {msg}")
                            else:
                                progress.update(task_upload, description=f"[bold red]✗ Step 8d Failed:[/bold red] Local EIF not found at {eif_local}")
                        else:
                            progress.update(task_ssm, description="[bold red]✗ Step 8a Failed: SSM timed out.[/bold red]")

        # Report overall pipeline status before teardown
        if automation_success:
            console.print("\n[bold green]Deployment pipeline complete.[/bold green] Enclave and client automation finished successfully.\n")
        else:
            console.print("\n[bold yellow]Infrastructure is deployed, but post-deployment automation did not fully succeed.[/bold yellow]\nSee logs above for details.\n")

    # Step 9: Teardown (optional, always attempts to clean up Terraform-managed resources)
    if teardown:
        console.print("[yellow]Step 9: Executing Terraform destroy (teardown)...[/yellow]")
        d_success, d_msg = run_terraform_destroy(build_dir)
        if d_success:
            console.print("[green]✓ Step 9: Resources destroyed successfully.[/green]")
        else:
            console.print(f"[bold red]✗ Step 9 Failed (destroy):[/bold red] {d_msg}")
    else:
        console.print(f"\n[dim]To tear down when done (Step 9): [bold]nitro-agent destroy --build-dir {os.path.abspath(build_dir)}[/bold][/dim]")

@click.group()
def cli():
    """Nitro-Agent: AI-powered AWS Nitro Enclave deployer."""
    pass

@cli.command()
@click.option('--build-dir', required=True, type=click.Path(exists=True, file_okay=False, dir_okay=True), help='Path to the build directory containing Terraform files')
def destroy(build_dir):
    """Destroy infrastructure created by a deployment."""
    build_dir = os.path.abspath(build_dir)
    console.print(f"[yellow]Destroying resources in: {build_dir}[/yellow]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("[yellow]Running terraform destroy...[/yellow]", total=None)
        
        success, msg = run_terraform_destroy(build_dir)
        
        if success:
             progress.update(task, description="[green]✓ Resources destroyed successfully.[/green]")
        else:
             progress.update(task, description=f"[bold red]✗ Destroy failed:[/bold red] {msg}")

@cli.command()
@click.option('--build-dir', required=True, type=click.Path(exists=True, file_okay=False, dir_okay=True), help='Path to the existing build directory')
@click.option('--enclave-cpu', required=True, type=int, help='Number of vCPUs for the enclave')
@click.option('--enclave-ram', required=True, type=int, help='RAM in MB for the enclave')
@click.option('--auto-approve', is_flag=True, default=False, help='Skip interactive approval for Terraform apply.')
@click.option('--teardown', is_flag=True, default=False, help='Automatically destroy resources after successful client run.')
@click.option('--instance-type', default=None, type=str, help='Override EC2 instance type for the host (e.g. c6g.xlarge).')
@click.option('--no-spot', is_flag=True, default=False, help='Use an On-Demand Instance instead of a Spot Instance.')
def deploy_from_build(build_dir, enclave_cpu, enclave_ram, auto_approve, teardown, instance_type, no_spot):
    """Deploy from an existing build directory (skips ingestion and build)."""
    build_dir = os.path.abspath(build_dir)
    console.print(Panel.fit(f"[bold blue]Nitro-Agent Deploy from Build[/bold blue]\n\nSource: [green]{build_dir}[/green]\nResources: {enclave_cpu} vCPU, {enclave_ram} MB RAM", border_style="blue"))

    # Set Terraform variables for instance type and spot vs on-demand from flags
    os.environ["TF_VAR_use_spot_instance"] = "false" if no_spot else "true"
    # Let .env / existing TF_VAR_instance_type override the CLI argument
    if instance_type and "TF_VAR_instance_type" not in os.environ:
        os.environ["TF_VAR_instance_type"] = instance_type

    # 1. Validate build artifacts
    eif_path = os.path.join(build_dir, "app.eif")
    main_tf_path = os.path.join(build_dir, "main.tf")
    
    if not os.path.exists(eif_path):
        console.print(f"[bold red]Error: app.eif not found in {build_dir}[/bold red]")
        return
    
    if not os.path.exists(main_tf_path):
        console.print(f"[bold red]Error: main.tf not found in {build_dir}[/bold red]")
        return

    # 2. Get PCR hashes
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=False) as progress:
        task_hash = progress.add_task("[yellow]Extracting PCR hashes from EIF...[/yellow]", total=None)
        success, hashes, msg = get_enclave_hashes(eif_path)
        if not success:
            progress.update(task_hash, description=f"[bold red]✗ Failed to get hashes.[/bold red]")
            console.print(f"[red]Error:[/red]\n{msg}")
            return
        progress.update(task_hash, description="[green]✓ PCR hashes extracted.[/green]")

    # 3. Run deployment
    try:
        run_deployment_phase(
            console=console,
            build_dir=build_dir,
            cpu=enclave_cpu,
            ram=enclave_ram,
            hashes=hashes,
            prompt_iac=None,
            auto_approve=auto_approve,
            teardown=teardown
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Received Ctrl+C. Attempting Terraform destroy (teardown)...[/bold yellow]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=False,
        ) as progress:
            task_destroy = progress.add_task("[yellow]Running terraform destroy after interrupt...[/yellow]", total=None)
            d_success, d_msg = run_terraform_destroy(build_dir)
            if d_success:
                progress.update(task_destroy, description="[green]✓ Resources destroyed successfully after interrupt.[/green]")
            else:
                progress.update(task_destroy, description=f"[bold red]✗ Destroy failed after interrupt:[/bold red] {d_msg}")
        raise click.Abort()

@cli.command()
@click.option('--source', required=True, type=click.Path(exists=True, file_okay=False, dir_okay=True), help='Path to the directory containing your Python app')
@click.option('--enclave-cpu', required=True, type=int, help='Number of vCPUs for the enclave')
@click.option('--enclave-ram', required=True, type=int, help='RAM in MB for the enclave')
@click.option('--prompt-vsock', default=None, type=str, help='Optional: description of what your script does to help the AI translate it to vsock')
@click.option('--prompt-iac', default=None, type=str, help='Optional: infrastructure preferences (e.g. region, instance type, tags) for Terraform')
@click.option('--deploy', is_flag=True, default=False, help='Run Phase 4: Execute Terraform apply to deploy resources.')
@click.option('--auto-approve', is_flag=True, default=False, help='Skip interactive approval for Terraform apply.')
@click.option('--data-file', default=None, type=click.Path(exists=True, dir_okay=False), help='Path to the JSON data file. If not set, uses <source>/data.json if present.')
@click.option('--teardown', is_flag=True, default=False, help='Automatically destroy resources after successful client run.')
@click.option('--instance-type', default=None, type=str, help='Override EC2 instance type for the host (e.g. c6g.xlarge).')
@click.option('--no-spot', is_flag=True, default=False, help='Use an On-Demand Instance instead of a Spot Instance.')
@click.option('--llm-provider', default='local', type=click.Choice(['local', 'openai', 'anthropic', 'gemini'], case_sensitive=False), help='LLM provider to use for code generation (default: local).')
def deploy(source, enclave_cpu, enclave_ram, prompt_vsock, prompt_iac, deploy, auto_approve, data_file, teardown, instance_type, no_spot, llm_provider):
    """Deploy a Python application to an AWS Nitro Enclave."""

    from nitro_agent.llm.engine import set_provider, _PROVIDER_DISPLAY
    try:
        set_provider(llm_provider)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return

    console.print(
        Panel.fit(
            f"[bold blue]Nitro-Agent Deploy[/bold blue]\n\n"
            f"Source: [green]{os.path.abspath(source)}[/green]\n"
            f"Resources: {enclave_cpu} vCPU, {enclave_ram} MB RAM\n"
            f"LLM Provider: [cyan]{_PROVIDER_DISPLAY.get(llm_provider.lower(), llm_provider)}[/cyan]",
            border_style="blue",
        )
    )

    if llm_provider.lower() != "local":
        provider_name = _PROVIDER_DISPLAY.get(llm_provider.lower(), llm_provider)
        console.print(
            Panel.fit(
                f"[bold yellow]Third-party LLM in use[/bold yellow]\n\n"
                f"Your source code will be sent to [cyan]{provider_name}[/cyan]'s API for code generation.\n"
                f"Do not use for sensitive or proprietary code unless you accept their data and privacy policy.",
                border_style="yellow",
            )
        )

    # Alias enclave_* options to internal cpu/ram variables
    cpu = enclave_cpu
    ram = enclave_ram

    # Set Terraform variables for instance type and spot vs on-demand from flags
    os.environ["TF_VAR_use_spot_instance"] = "false" if no_spot else "true"
    # Let .env / existing TF_VAR_instance_type override the CLI argument
    if instance_type and "TF_VAR_instance_type" not in os.environ:
        os.environ["TF_VAR_instance_type"] = instance_type

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task_ingest = progress.add_task("[yellow]Step 1: Ingesting code...[/yellow]", total=None)
        
        # 1. Ingestion Phase
        source_path = os.path.abspath(source)
        ingested_data = ingest_directory(source_path)
        
        if not ingested_data:
            console.print("[bold red]Error: No Python files found in the source directory.[/bold red]")
            return

        # Sanity-check that the user's app looks like a script with a main,
        # not a long-running HTTP server. This is a heuristic guardrail only.
        ok, reason = verify_app_is_not_server(source_path)
        if not ok:
            console.print(f"[bold red]Error: Source app does not meet Phase 1 contract.[/bold red]\n{reason}")
            return

        source_code = ingested_data["python_code"]
        dependencies = ingested_data["dependencies"]

        progress.update(task_ingest, description="[green]✓ Step 1: Code ingested.[/green]")

        # Prepare data sample early so the vsock logic knows what data format to expect
        data_file_path = data_file or os.path.join(source_path, "data.json")
        data_content = ""
        data_sample_str = ""
        
        if os.path.isfile(data_file_path):
            import json as _json
            try:
                with open(data_file_path, "r", encoding="utf-8") as f:
                    data_content = f.read()
                parsed_data = _json.loads(data_content)
                
                # Create a smaller sample for the LLM to avoid context limits with huge datasets
                if isinstance(parsed_data, list) and len(parsed_data) > 0:
                    sample_data = parsed_data[:2]
                else:
                    sample_data = parsed_data
                    
                data_sample_str = _json.dumps(sample_data, indent=2)
                if len(data_sample_str) > 2000:
                    data_sample_str = data_sample_str[:2000] + "\n... (truncated for context)"
            except Exception as e:
                console.print(f"[bold red]Warning:[/bold red] Data file is not valid JSON: {e}. Vsock server will be generated without data context.")

        # 2. Vsock Translation (Includes self-healing syntax check)
        task_vsock = progress.add_task("[yellow]Step 2: AI translating standard I/O to vsock proxy...[/yellow]", total=None)
        
        try:
            # Note: generate_vsock_wrapper now includes an internal retry loop for syntax errors
            vsock_wrapper = generate_vsock_wrapper(
                app_description=prompt_vsock or "",
                source_code=source_code,
                data_content=data_sample_str,
            )
        except Exception as e:
             import traceback
             progress.update(task_vsock, description=f"[bold red]✗ Step 2 Failed: {str(e)}[/bold red]")
             console.print(f"[red]{traceback.format_exc()}[/red]")
             return
            
        progress.update(task_vsock, description="[green]✓ Step 2: vsock translation complete.[/green]")

        # 3. Dockerfile Generation
        task_docker = progress.add_task("[yellow]Step 3: Generating optimized Dockerfile...[/yellow]", total=None)
        
        try:
            dockerfile_content = render_dockerfile_template()
        except Exception as e:
             import traceback
             progress.update(task_docker, description=f"[bold red]✗ Step 3 Failed: {str(e)}[/bold red]")
             console.print(f"[red]{traceback.format_exc()}[/red]")
             return
            
        progress.update(task_docker, description="[green]✓ Step 3: Dockerfile generated.[/green]")

        # 4. Artifact Staging
        task_stage = progress.add_task("[yellow]Step 4: Staging artifacts...[/yellow]", total=None)
        
        build_dir = stage_artifacts(
            source_dir=source_path,
            vsock_code=vsock_wrapper,
            dockerfile_content=dockerfile_content
        )
        
        # We extract just the base folder name for cleaner output
        build_folder_name = os.path.basename(build_dir)
        progress.update(task_stage, description=f"[green]✓ Step 4: Artifacts staged in [bold]{build_folder_name}[/bold].[/green]")
        
        # Copy data file early
        if not os.path.isfile(data_file_path):
            console.print(
                "[bold red]Error:[/bold red] No data file. "
                "Provide --data-file <path> or place data.json in your source directory."
            )
            return

        with open(os.path.join(build_dir, "data.json"), "w", encoding="utf-8") as f:
            f.write(data_content)


    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        # Implicit Verification Step (Docker Build Check)
        valid, msg = verify_docker_build(build_dir)
        if not valid:
            console.print(
                f"\n[bold red]Warning: Docker build check failed for the generated artifacts:[/bold red]\n{msg}"
            )
        
        # Phase 2: Local Cryptographic Packaging (EIF Generation)
        task_enclave = progress.add_task("[yellow]Step 5a: Compiling Enclave Image File (.eif)...[/yellow]", total=None)
        
        success, hashes, message = build_enclave(build_dir)
        if not success:
            progress.update(task_enclave, description=f"[bold red]✗ Step 5a Failed.[/bold red]")
            console.print(f"[red]Enclave Build Error:[/red]\n{message}")
            return
            
        progress.update(task_enclave, description=f"[green]✓ Step 5a: Enclave built successfully.[/green]")
        
        # 5b. Inject PCRs into Client Script Template
        task_client = progress.add_task("[yellow]Step 5b: Injecting PCRs into client script template...[/yellow]", total=None)
        try:
            client_script = render_client_template(
                pcr_hashes=hashes,  # Pass the PCRs for attestation verification
                root_ca=_load_root_ca()
            )
            with open(os.path.join(build_dir, "client.py"), "w", encoding="utf-8") as f:
                f.write(client_script)
            progress.update(task_client, description="[green]✓ Step 5b: Secure client script configured.[/green]")
        except Exception as e:
            import traceback
            progress.update(task_client, description=f"[bold red]✗ Step 5b Failed: {str(e)}[/bold red]")
            console.print(f"[red]{traceback.format_exc()}[/red]")
            return
        # Phase 3: Infrastructure-as-Code (IaC) Generation
        task_iac = progress.add_task("[yellow]Step 6: Generating Terraform deployment scripts...[/yellow]", total=None)
        
        try:
            terraform_code = generate_terraform_code(
                cpu=cpu,
                ram=ram,
                pcr_hashes=hashes,
                prompt_iac=prompt_iac or "",
                debug_build_dir=build_dir,
            )
            # Save the main.tf
            # PCR hashes are concretely injected so we never depend on variable placeholders
            stage_terraform(build_dir, terraform_code, pcr_hashes=hashes)

            # Final syntax check with the user's actual build directory.
            tf_ok, tf_msg = verify_terraform_syntax(build_dir)
            if not tf_ok:
                console.print(
                    f"\n[bold yellow]Warning:[/bold yellow] Unable to fully verify Terraform syntax:\n{tf_msg}\n"
                )
                progress.update(task_iac, description="[yellow]! Step 6: Terraform code generated but not fully validated.[/yellow]")
            else:
                progress.update(task_iac, description="[green]✓ Step 6: Terraform infrastructure code generated.[/green]")
        except Exception as e:
            import traceback
            progress.update(task_iac, description=f"[bold red]✗ Step 6 Failed: {str(e)}[/bold red]")
            console.print(f"[red]{traceback.format_exc()}[/red]")
            return

    if deploy:
        try:
            run_deployment_phase(
                console=console,
                build_dir=build_dir,
                cpu=cpu,
                ram=ram,
                hashes=hashes,
                prompt_iac=prompt_iac,
                auto_approve=auto_approve,
                teardown=teardown,
                source_code=source_code,
                prompt_vsock=prompt_vsock,
                data_sample_str=data_sample_str
            )
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Received Ctrl+C. Attempting Terraform destroy (teardown)...[/bold yellow]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=False,
            ) as progress:
                task_destroy = progress.add_task("[yellow]Running terraform destroy after interrupt...[/yellow]", total=None)
                d_success, d_msg = run_terraform_destroy(build_dir)
                if d_success:
                    progress.update(task_destroy, description="[green]✓ Resources destroyed successfully after interrupt.[/green]")
                else:
                    progress.update(task_destroy, description=f"[bold red]✗ Destroy failed after interrupt:[/bold red] {d_msg}")
            raise click.Abort()

    if not deploy:
        console.print(
            f"\n[bold green]Phases 1–3 complete (no deployment).[/bold green]\n"
            f"All generated files are in: [cyan]{os.path.abspath(build_dir)}[/cyan]\n"
            f"Contents: app_vsock.py, Dockerfile, app.eif, client.py, data.json, main.tf. Run with [bold]--deploy --auto-approve[/bold] to apply Terraform.\n"
        )

def main():
    cli()

if __name__ == '__main__':
    main()
