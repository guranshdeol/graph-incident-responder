"""Put the estate back by hand if the agent didn't (re-adds rule A if missing).
Run: AWS_PROFILE=rootgraph-admin uv run python -m demo.faults.restore_all"""

import json
import os
from pathlib import Path

import boto3

st = json.loads((Path(__file__).resolve().parents[1] / "aws/state.json").read_text())
ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION", "ap-south-1"))
live = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [st["sg_db"]]}])["SecurityGroupRules"]
if any(not r["IsEgress"] and r.get("FromPort") == 5432 and (r.get("ReferencedGroupInfo") or {}).get("GroupId") == st["sg_host1"]
       for r in live):
    print("rule A is present; nothing to restore")
else:
    ec2.authorize_security_group_ingress(GroupId=st["sg_db"], IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
        "UserIdGroupPairs": [{"GroupId": st["sg_host1"], "Description": "rule A: host-1 to orders-db"}]}])
    print("rule A restored")
