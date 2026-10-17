"""Run shell commands on the demo hosts through SSM Run Command (no SSH, no open port 22)."""

import json
import os
import time

import boto3

from demo.aws import estate

REGION = os.environ.get("AWS_REGION", "ap-southeast-2")


def state() -> dict:
    return json.loads(estate.STATE.read_text())


def client(session=None):
    return (session or boto3.Session(region_name=REGION)).client("ssm")


def run(ssm, instance_id: str, commands: list[str], comment: str, wait: bool = True, timeout: int = 600) -> dict:
    """Send AWS-RunShellScript and (optionally) wait for it; returns status + output tail."""
    cmd = ssm.send_command(InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
                           Parameters={"commands": commands}, Comment=comment[:100],
                           TimeoutSeconds=timeout)["Command"]["CommandId"]
    if not wait:
        return {"command_id": cmd, "status": "Sent"}
    deadline = time.time() + timeout
    while True:
        time.sleep(2)
        try:
            inv = ssm.get_command_invocation(CommandId=cmd, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] not in ("Pending", "InProgress", "Delayed") or time.time() > deadline:
            return {"command_id": cmd, "status": inv["Status"],
                    "stdout": inv.get("StandardOutputContent", "")[-2000:],
                    "stderr": inv.get("StandardErrorContent", "")[-2000:]}
