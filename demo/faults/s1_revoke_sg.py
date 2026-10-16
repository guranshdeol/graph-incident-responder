"""S1 fault: revoke rule A (host-1 -> orders-db:5432) with YOUR credentials (you play the human
who makes the bad change). Run: AWS_PROFILE=rootgraph-admin uv run python -m demo.faults.s1_revoke_sg"""

import json
import os
from pathlib import Path

import boto3

st = json.loads((Path(__file__).resolve().parents[1] / "aws/state.json").read_text())
ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION", "ap-south-1"))
rule_a = st["sg_rules"]["rule_a"]
live = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [st["sg_db"]]}])["SecurityGroupRules"]
if not any(r["SecurityGroupRuleId"] == rule_a for r in live):
    # after the agent restored it, the rule has a new id: revoke whatever now allows sg-host1 on 5432
    rule_a = next(r["SecurityGroupRuleId"] for r in live if not r["IsEgress"] and r.get("FromPort") == 5432
                  and (r.get("ReferencedGroupInfo") or {}).get("GroupId") == st["sg_host1"])
ec2.revoke_security_group_ingress(GroupId=st["sg_db"], SecurityGroupRuleIds=[rule_a])
print(f"revoked {rule_a} on {st['sg_db']}: host-1 can no longer reach orders-db")
