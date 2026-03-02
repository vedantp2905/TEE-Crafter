import time
import logging
import os
import boto3
from botocore.exceptions import ClientError
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

def wait_for_ssm(instance_id: str, region: str, timeout: int = 300) -> bool:
    """
    Waits for the EC2 instance to become online and registered with SSM.
    """
    ssm = boto3.client('ssm', region_name=region)
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            response = ssm.describe_instance_information(
                InstanceInformationFilterList=[
                    {'key': 'InstanceIds', 'valueSet': [instance_id]}
                ]
            )
            info_list = response.get('InstanceInformationList', [])
            if info_list and info_list[0].get('PingStatus') == 'Online':
                return True
        except ClientError as e:
            pass
            
        time.sleep(10)
        
    return False

def upload_file_via_s3(local_path: str, bucket_name: str, object_name: str, instance_id: str, remote_path: str, region: str) -> Tuple[bool, str]:
    """
    Uploads a local file to an S3 bucket, then uses SSM to tell the instance to download it.
    """
    s3 = boto3.client('s3', region_name=region)
    try:
        s3.upload_file(local_path, bucket_name, object_name)
    except Exception as e:
        return False, f"Failed to upload to S3: {e}"

    download_cmd = f"aws s3 cp s3://{bucket_name}/{object_name} {remote_path}"
    success, stdout, stderr = run_ssm_command(instance_id, download_cmd, region)
    if not success:
        return False, f"Failed to download from S3 to instance: {stderr}"
        
    return True, "Success"

def run_ssm_command(instance_id: str, command: str, region: str, timeout: int = 120) -> Tuple[bool, str, str]:
    """
    Executes a shell command on the EC2 instance via AWS Systems Manager.
    Returns (success, stdout, stderr)
    """
    ssm = boto3.client('ssm', region_name=region)
    
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [command]},
            TimeoutSeconds=timeout
        )
        command_id = response['Command']['CommandId']
        
        # Wait for command to complete
        start_time = time.time()
        while time.time() - start_time < timeout + 10:
            try:
                invocations = ssm.list_command_invocations(
                    CommandId=command_id,
                    InstanceId=instance_id,
                    Details=True
                )['CommandInvocations']
                
                if invocations:
                    status = invocations[0]['Status']
                    if status in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                        stdout = invocations[0].get('CommandPlugins', [{}])[0].get('Output', '')
                        # SSM doesn't cleanly separate stderr in the standard API response, 
                        # so we treat failure output as stderr or just parse the output string.
                        stderr = "" if status == 'Success' else stdout
                        return (status == 'Success', stdout, stderr)
            except ClientError:
                pass
            time.sleep(2)
            
        return False, "", "Command timed out while polling SSM."
        
    except Exception as e:
        return False, "", str(e)
