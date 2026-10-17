"""Put the estate back by hand if the agent didn't. Undoes every fault the demo uses:
a removed or edited rule A, a detached security group (instances or orders-db), a stopped
instance, a stopped container. Safe to run any time: it only changes what is wrong.
Run: AWS_PROFILE=rootgraph-admin uv run python -m demo.faults.restore_all"""

import json
import os
from pathlib import Path

import boto3

st = json.loads((Path(__file__).resolve().parents[1] / "aws/state.json").read_text())
region = os.environ.get("AWS_REGION", "ap-southeast-2")
ec2, rds, ssm = (boto3.client(s, region_name=region) for s in ("ec2", "rds", "ssm"))

# rule A: host-1 -> orders-db:5432. An edited copy (wrong port) is replaced by the right one.
live = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [st["sg_db"]]}])["SecurityGroupRules"]
from_h1 = [r for r in live if not r["IsEgress"] and (r.get("ReferencedGroupInfo") or {}).get("GroupId") == st["sg_host1"]]
if any(r.get("FromPort") == 5432 for r in from_h1):
    print("rule A is present")
else:
    edited = [r["SecurityGroupRuleId"] for r in from_h1]
    if edited:
        ec2.revoke_security_group_ingress(GroupId=st["sg_db"], SecurityGroupRuleIds=edited)
        print("removed edited copies of rule A:", edited)
    ec2.authorize_security_group_ingress(GroupId=st["sg_db"], IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
        "UserIdGroupPairs": [{"GroupId": st["sg_host1"], "Description": "rule A: host-1 to orders-db"}]}])
    print("rule A restored")

# security groups still attached
db = rds.describe_db_instances(DBInstanceIdentifier="orders-db")["DBInstances"][0]
if st["sg_db"] in [g["VpcSecurityGroupId"] for g in db["VpcSecurityGroups"] if g["Status"] in ("active", "adding")]:
    print("orders-db has its security group")
else:
    rds.modify_db_instance(DBInstanceIdentifier="orders-db", VpcSecurityGroupIds=[st["sg_db"]], ApplyImmediately=True)
    print("orders-db: re-attached", st["sg_db"])

hosts = {st["host1"]: st["sg_host1"], st["host2"]: st["sg_host2"]}
res = ec2.describe_instances(InstanceIds=list(hosts))["Reservations"]
for inst in (i for r in res for i in r["Instances"]):
    iid = inst["InstanceId"]
    if hosts[iid] not in [g["GroupId"] for g in inst["SecurityGroups"]]:
        ec2.modify_instance_attribute(InstanceId=iid, Groups=[hosts[iid]])
        print(iid, "re-attached", hosts[iid])
    if inst["State"]["Name"] in ("stopped", "stopping"):
        ec2.get_waiter("instance_stopped").wait(InstanceIds=[iid])
        ec2.start_instances(InstanceIds=[iid])
        ec2.get_waiter("instance_running").wait(InstanceIds=[iid])
        print(iid, "started")

# containers: bring every demo service back up (a no-op for running ones)
cmd = ssm.send_command(InstanceIds=list(hosts), DocumentName="AWS-RunShellScript",
                       Parameters={"commands": ["cd /opt/rootgraph-demo && docker compose up -d 2>&1 | tail -3"]})
print("containers: `docker compose up -d` sent to both hosts")
