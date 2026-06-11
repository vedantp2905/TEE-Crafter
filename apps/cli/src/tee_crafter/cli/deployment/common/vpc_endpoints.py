"""VPC endpoint preflight for AWS deployments (skip duplicate endpoints in default VPC)."""
import os
from tee_crafter.cli.constants import Console



def detect_and_skip_existing_vpc_endpoints(
    console: Console,
    build_dir: str,
    aws_region: str | None = None,
) -> bool:
    """Check if VPC Interface endpoints already exist in the default VPC.

    If SSM/SSMMessages/EC2Messages endpoints are detected, writes
    ``skip_vpc_endpoints = true`` to ``terraform.tfvars`` in *build_dir*
    so Terraform will not attempt to create duplicates (which would fail
    with "conflicting DNS domain" errors).

    Returns True if the skip was applied, False otherwise.
    """
    try:
        import boto3

        region = (
            aws_region
            or os.getenv("TF_VAR_aws_region")
            or os.getenv("AWS_REGION")
            or boto3.Session().region_name
            or "us-east-2"
        )
        ec2 = boto3.client("ec2", region_name=region)

        vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])
        if not vpcs.get("Vpcs"):
            return False
        vpc_id = vpcs["Vpcs"][0]["VpcId"]

        required_services = {
            f"com.amazonaws.{region}.ssm",
            f"com.amazonaws.{region}.ssmmessages",
            f"com.amazonaws.{region}.ec2messages",
        }

        resp = ec2.describe_vpc_endpoints(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "vpc-endpoint-type", "Values": ["Interface"]},
                {"Name": "vpc-endpoint-state", "Values": ["available", "pending"]},
            ]
        )
        existing_services = {
            ep["ServiceName"] for ep in resp.get("VpcEndpoints", [])
        }

        found = required_services & existing_services

        tfvars_path = os.path.join(build_dir, "terraform.tfvars")
        existing_content = ""
        if os.path.exists(tfvars_path):
            with open(tfvars_path) as f:
                existing_content = f.read()

        if found:
            console.print(
                f"[dim]VPC endpoint preflight: found existing Interface endpoints "
                f"({', '.join(sorted(s.rsplit('.', 1)[-1] for s in found))}). "
                f"Setting skip_vpc_endpoints=true.[/dim]"
            )
            if "skip_vpc_endpoints" not in existing_content:
                with open(tfvars_path, "a") as f:
                    f.write("\nskip_vpc_endpoints = true\n")
                existing_content += "\nskip_vpc_endpoints = true\n"

        gw_resp = ec2.describe_vpc_endpoints(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "vpc-endpoint-type", "Values": ["Gateway"]},
                {"Name": "vpc-endpoint-state", "Values": ["available", "pending"]},
                {"Name": "service-name", "Values": [f"com.amazonaws.{region}.s3"]},
            ]
        )
        if gw_resp.get("VpcEndpoints"):
            console.print("[dim]VPC endpoint preflight: S3 Gateway endpoint exists.[/dim]")
            if "create_s3_gateway_endpoint" not in existing_content:
                with open(tfvars_path, "a") as f:
                    f.write("\ncreate_s3_gateway_endpoint = false\n")
                existing_content += "\ncreate_s3_gateway_endpoint = false\n"

        kms_resp = ec2.describe_vpc_endpoints(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "vpc-endpoint-type", "Values": ["Interface"]},
                {"Name": "vpc-endpoint-state", "Values": ["available", "pending"]},
                {"Name": "service-name", "Values": [f"com.amazonaws.{region}.kms"]},
            ]
        )
        if kms_resp.get("VpcEndpoints"):
            console.print("[dim]VPC endpoint preflight: KMS Interface endpoint exists.[/dim]")
            if "create_kms_vpc_endpoint" not in existing_content:
                with open(tfvars_path, "a") as f:
                    f.write("\ncreate_kms_vpc_endpoint = false\n")
                existing_content += "\ncreate_kms_vpc_endpoint = false\n"

        if found:
            return True

        console.print(
            "[dim]VPC endpoint preflight: no existing Interface endpoints found; "
            "Terraform will create them.[/dim]"
        )
        return False

    except Exception:
        console.print(
            "[dim]VPC endpoint preflight skipped. Terraform will attempt normal creation.[/dim]"
        )
        return False
