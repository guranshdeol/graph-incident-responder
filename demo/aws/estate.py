"""Create / tear down the demo AWS estate (plan §9, §6.3, §7.7).

    uv run python -m demo.aws.estate up --email you@example.com --control-plane-cidr 172.232.86.149/32
    uv run python -m demo.aws.estate status
    uv run python -m demo.aws.estate down

Run with an ADMIN profile (your own credentials, e.g. AWS_PROFILE=...). It creates:
  budget alarm ($10)  VPC + 2 public subnets + IGW  rootgraph-host1 / -host2 / -db SGs (rules A, B)
  host-1 + host-2 (AL2023, t3.small, SSM role, Docker)  orders-db (Postgres, db.t4g.micro, private)
  CloudTrail trail + S3 bucket  EventBridge rule -> SQS rootgraph-changes
  IAM users rootgraph-discovery / -ingester / -executor with access keys

Every id goes into demo/aws/state.json and the keys + queue URL into
demo/aws/credentials.env (chmod 600, gitignored): append that file to the server's .env.
`down` deletes exactly what state.json lists, in reverse order. No NAT gateway, on purpose (cost).
"""

import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

HERE = Path(__file__).resolve().parent
STATE = HERE / "state.json"
CREDS = HERE / "credentials.env"
PATTERN = json.loads((HERE / "eventbridge-pattern.json").read_text())
REGION = os.environ.get("AWS_REGION", "ap-south-1")
TAG = {"Key": "rootgraph", "Value": "demo"}
SECRET_KEYS = {"db_password", "users"}  # never printed
AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
COMPOSE_VERSION = "v2.29.7"

USER_DATA = f"""#!/bin/bash
set -eux
dnf install -y docker
systemctl enable --now docker
mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL https://github.com/docker/compose/releases/download/{COMPOSE_VERSION}/docker-compose-linux-x86_64 \\
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
"""


def tags(name: str) -> list:
    return [{"Key": "Name", "Value": name}, TAG]


def spec(resource: str, name: str) -> list:
    return [{"ResourceType": resource, "Tags": tags(name)}]


def load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def save_state(st: dict) -> None:
    # holds the RDS password and the IAM secret keys: owner-only, written that way from the start
    fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(st, indent=2))
    STATE.chmod(0o600)


def step(st: dict, key: str, fn):
    """Run fn once; remember its result so `up` can be re-run after a failure."""
    if key not in st:
        st[key] = fn()
        save_state(st)
        shown = "(secret, see credentials.env)" if key in SECRET_KEYS else (st[key] if not isinstance(st[key], dict) else "...")
        print(f"  created {key}: {shown}")
    return st[key]


class Estate:
    def __init__(self, session: boto3.Session, wait: bool = True):
        self.s, self.wait = session, wait
        self.ec2, self.rds, self.iam = session.client("ec2"), session.client("rds"), session.client("iam")
        self.sqs, self.events, self.ct = session.client("sqs"), session.client("events"), session.client("cloudtrail")
        self.s3, self.ssm, self.sts = session.client("s3"), session.client("ssm"), session.client("sts")
        self.budgets = session.client("budgets", region_name="us-east-1")
        self.account = self.sts.get_caller_identity()["Account"]

    # -- up --------------------------------------------------------------------------

    def up(self, email: str | None, control_plane_cidr: str) -> dict:
        st = load_state()
        e = self.ec2
        if email:
            step(st, "budget", lambda: self._budget(email))
        vpc = step(st, "vpc", lambda: e.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=spec("vpc", "rootgraph-vpc"))["Vpc"]["VpcId"])
        e.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})
        azs = [z["ZoneName"] for z in e.describe_availability_zones()["AvailabilityZones"]][:2]
        sub_a = step(st, "subnet_a", lambda: e.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=azs[0],
                                                             TagSpecifications=spec("subnet", "rootgraph-a"))["Subnet"]["SubnetId"])
        sub_b = step(st, "subnet_b", lambda: e.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone=azs[1],
                                                             TagSpecifications=spec("subnet", "rootgraph-b"))["Subnet"]["SubnetId"])
        for sub in (sub_a, sub_b):
            e.modify_subnet_attribute(SubnetId=sub, MapPublicIpOnLaunch={"Value": True})
        igw = step(st, "igw", lambda: e.create_internet_gateway(TagSpecifications=spec("internet-gateway", "rootgraph-igw"))["InternetGateway"]["InternetGatewayId"])
        step(st, "igw_attached", lambda: e.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc) and True)
        rt = step(st, "route_table", lambda: e.create_route_table(VpcId=vpc, TagSpecifications=spec("route-table", "rootgraph-rt"))["RouteTable"]["RouteTableId"])
        step(st, "route", lambda: e.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw) and True)
        step(st, "rt_assoc", lambda: [e.associate_route_table(RouteTableId=rt, SubnetId=s)["AssociationId"] for s in (sub_a, sub_b)])

        sg = lambda name, desc: e.create_security_group(GroupName=name, Description=desc, VpcId=vpc,
                                                        TagSpecifications=spec("security-group", name))["GroupId"]
        sg_h1 = step(st, "sg_host1", lambda: sg("rootgraph-host1", "rootgraph host-1"))
        sg_h2 = step(st, "sg_host2", lambda: sg("rootgraph-host2", "rootgraph host-2"))
        sg_db = step(st, "sg_db", lambda: sg("rootgraph-db", "rootgraph orders-db (sg-db in the plan)"))
        step(st, "sg_rules", lambda: self._rules(sg_h1, sg_h2, sg_db, control_plane_cidr))

        profile = step(st, "instance_profile", self._instance_role)
        ami = self._ami()
        for key, name, sub, grp in (("host1", "host-1", sub_a, sg_h1), ("host2", "host-2", sub_b, sg_h2)):
            step(st, key, lambda name=name, sub=sub, grp=grp: self._instance(ami, name, sub, grp, profile))

        step(st, "db_subnet_group", lambda: self.rds.create_db_subnet_group(
            DBSubnetGroupName="rootgraph-db", DBSubnetGroupDescription="rootgraph", SubnetIds=[sub_a, sub_b],
            Tags=[TAG])["DBSubnetGroup"]["DBSubnetGroupName"])
        db_pw = step(st, "db_password", lambda: secrets.token_urlsafe(24))
        step(st, "db", lambda: self.rds.create_db_instance(
            DBInstanceIdentifier="orders-db", Engine="postgres", DBInstanceClass="db.t4g.micro", AllocatedStorage=20,
            MasterUsername="rootgraph", MasterUserPassword=db_pw, DBName="orders", VpcSecurityGroupIds=[sg_db],
            DBSubnetGroupName="rootgraph-db", PubliclyAccessible=False, MultiAZ=False, BackupRetentionPeriod=0,
            DeletionProtection=False, Tags=[TAG])["DBInstance"]["DBInstanceIdentifier"])

        bucket = step(st, "trail_bucket", self._trail_bucket)
        step(st, "trail", lambda: self._trail(bucket))
        queue = step(st, "queue", self._queue)
        step(st, "rule", lambda: self._rule(queue))

        users = step(st, "users", lambda: self._users(sg_db, queue))
        self._write_credentials(st, users, queue)
        if self.wait:
            print("waiting for instances and orders-db (RDS takes ~10 min)...")
            e.get_waiter("instance_running").wait(InstanceIds=[st["host1"], st["host2"]])
            self.rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier="orders-db")
        print(f"done. Append {CREDS.relative_to(Path.cwd()) if CREDS.is_relative_to(Path.cwd()) else CREDS} to the server's .env")
        return st

    def _budget(self, email: str) -> str:
        self.budgets.create_budget(
            AccountId=self.account,
            Budget={"BudgetName": "rootgraph-demo", "BudgetLimit": {"Amount": "10", "Unit": "USD"},
                    "TimeUnit": "MONTHLY", "BudgetType": "COST"},
            NotificationsWithSubscribers=[{
                "Notification": {"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN",
                                 "Threshold": 80, "ThresholdType": "PERCENTAGE"},
                "Subscribers": [{"SubscriptionType": "EMAIL", "Address": email}]}])
        return "rootgraph-demo"

    def _rules(self, h1: str, h2: str, db: str, cp: str) -> dict:
        e = self.ec2
        def allow(group, ports, desc, src_group=None, cidr=None):
            perm = {"IpProtocol": "tcp", "FromPort": ports[0], "ToPort": ports[1]}
            if src_group:
                perm["UserIdGroupPairs"] = [{"GroupId": src_group, "Description": desc}]
            else:
                perm["IpRanges"] = [{"CidrIp": cidr, "Description": desc}]
            r = e.authorize_security_group_ingress(GroupId=group, IpPermissions=[perm])
            return r["SecurityGroupRules"][0]["SecurityGroupRuleId"]
        return {
            # the S1 rule: payments on host-1 -> orders-db
            "rule_a": allow(db, (5432, 5432), "rule A: host-1 to orders-db", src_group=h1),
            "rule_b": allow(db, (5432, 5432), "rule B: host-2 to orders-db", src_group=h2),
            # host-1 runs Prometheus/Alertmanager; host-2 services + exporters are scraped from host-1
            "h2_from_h1": allow(h2, (8080, 9115), "services + exporters from host-1", src_group=h1),
            # the control plane (Linode) queries PromQL and reaches nothing else
            "h1_prom_cp": allow(h1, (9090, 9090), "Prometheus from rootgraph control plane", cidr=cp),
        }

    def _instance_role(self) -> str:
        name = "rootgraph-demo-ec2"
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                                         "Action": "sts:AssumeRole"}]}
        self.iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[TAG])
        self.iam.attach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
        self.iam.create_instance_profile(InstanceProfileName=name)
        self.iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
        if self.wait:
            time.sleep(10)  # instance profiles take a moment to become usable by EC2
        return name

    def _ami(self) -> str:
        try:
            return self.ssm.get_parameter(Name=AMI_PARAM)["Parameter"]["Value"]
        except ClientError:
            imgs = self.ec2.describe_images(Owners=["amazon"])["Images"]
            return sorted(imgs, key=lambda i: i.get("CreationDate", ""))[-1]["ImageId"]

    def _instance(self, ami, name, subnet, group, profile) -> str:
        r = self.ec2.run_instances(ImageId=ami, InstanceType="t3.small", MinCount=1, MaxCount=1, SubnetId=subnet,
                                   SecurityGroupIds=[group], IamInstanceProfile={"Name": profile},
                                   UserData=USER_DATA, TagSpecifications=spec("instance", name),
                                   MetadataOptions={"HttpTokens": "required"})
        return r["Instances"][0]["InstanceId"]

    def _trail_bucket(self) -> str:
        bucket = f"rootgraph-trail-{self.account}-{REGION}"
        kw = {} if REGION == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": REGION}}
        self.s3.create_bucket(Bucket=bucket, **kw)
        policy = {"Version": "2012-10-17", "Statement": [
            {"Sid": "AclCheck", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}"},
            {"Sid": "Write", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{self.account}/*",
             "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}}]}
        self.s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
        return bucket

    def _trail(self, bucket: str) -> str:
        # EventBridge only gets "AWS API Call via CloudTrail" events while a trail is logging (§6.3)
        self.ct.create_trail(Name="rootgraph", S3BucketName=bucket, IsMultiRegionTrail=False, TagsList=[TAG])
        self.ct.start_logging(Name="rootgraph")
        return "rootgraph"

    def _queue(self) -> dict:
        url = self.sqs.create_queue(QueueName="rootgraph-changes", Attributes={"MessageRetentionPeriod": "86400"})["QueueUrl"]
        arn = self.sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        return {"url": url, "arn": arn}

    def _rule(self, queue: dict) -> str:
        arn = self.events.put_rule(Name="rootgraph-changes", EventPattern=json.dumps(PATTERN), State="ENABLED")["RuleArn"]
        policy = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
            "Resource": queue["arn"], "Condition": {"ArnEquals": {"aws:SourceArn": arn}}}]}
        self.sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})
        self.events.put_targets(Rule="rootgraph-changes", Targets=[{"Id": "sqs", "Arn": queue["arn"]}])
        return arn

    def _users(self, sg_db: str, queue: dict) -> dict:
        region, acct = REGION, self.account
        policies = {
            "rootgraph-discovery": [{"Effect": "Allow", "Action": ["ec2:Describe*", "rds:Describe*"], "Resource": "*"}],
            "rootgraph-ingester": [{"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage",
                                                                   "sqs:GetQueueAttributes"], "Resource": queue["arn"]}],
            "rootgraph-executor": [
                {"Effect": "Allow", "Action": "ec2:AuthorizeSecurityGroupIngress",
                 "Resource": f"arn:aws:ec2:{region}:{acct}:security-group/{sg_db}"},
                {"Effect": "Allow", "Action": "ssm:SendCommand",
                 "Resource": f"arn:aws:ec2:{region}:{acct}:instance/*",
                 "Condition": {"StringEquals": {"ssm:resourceTag/rootgraph": "demo"}}},
                {"Effect": "Allow", "Action": "ssm:SendCommand",
                 "Resource": f"arn:aws:ssm:{region}::document/AWS-RunShellScript"}],
        }
        out = {}
        for user, statements in policies.items():
            self.iam.create_user(UserName=user, Tags=[TAG])
            self.iam.put_user_policy(UserName=user, PolicyName=user,
                                     PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
            key = self.iam.create_access_key(UserName=user)["AccessKey"]
            out[user] = {"id": key["AccessKeyId"], "secret": key["SecretAccessKey"]}
        return out

    def _write_credentials(self, st: dict, users: dict, queue: dict) -> None:
        lines = ["# rootgraph live AWS (from demo/aws/estate.py up). Append to the server's .env. Never commit.",
                 f"AWS_REGION={REGION}", f"CHANGES_QUEUE_URL={queue['url']}"]
        for user, prefix in (("rootgraph-discovery", "DISCOVERY"), ("rootgraph-ingester", "INGESTER"),
                             ("rootgraph-executor", "EXECUTOR")):
            lines += [f"{prefix}_AWS_ACCESS_KEY_ID={users[user]['id']}", f"{prefix}_AWS_SECRET_ACCESS_KEY={users[user]['secret']}"]
        lines.append(f"ORDERS_DB_PASSWORD={st['db_password']}")
        CREDS.write_text("\n".join(lines) + "\n")
        CREDS.chmod(0o600)

    # -- status / down ------------------------------------------------------------------

    def status(self) -> dict:
        st = load_state()
        out = {k: v for k, v in st.items() if k not in ("users", "db_password")}
        if "host1" in st:
            res = self.ec2.describe_instances(InstanceIds=[st["host1"], st["host2"]])["Reservations"]
            out["instances"] = {i["InstanceId"]: (i["State"]["Name"], i.get("PublicIpAddress"))
                                for r in res for i in r["Instances"]}
        if "db" in st:
            d = self.rds.describe_db_instances(DBInstanceIdentifier="orders-db")["DBInstances"][0]
            out["orders-db"] = (d["DBInstanceStatus"], (d.get("Endpoint") or {}).get("Address"))
        return out

    def down(self) -> None:
        st = load_state()
        if not st:
            print("nothing in state.json")
            return
        def attempt(label, fn):
            try:
                fn()
                print(f"  deleted {label}")
            except ClientError as exc:
                print(f"  {label}: {exc.response['Error']['Code']}")
        for user in st.get("users", {}):
            for k in self.iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
                attempt(f"key {user}", lambda k=k: self.iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"]))
            attempt(f"policy {user}", lambda u=user: self.iam.delete_user_policy(UserName=u, PolicyName=u))
            attempt(f"user {user}", lambda u=user: self.iam.delete_user(UserName=u))
        if "rule" in st:
            attempt("rule targets", lambda: self.events.remove_targets(Rule="rootgraph-changes", Ids=["sqs"]))
            attempt("rule", lambda: self.events.delete_rule(Name="rootgraph-changes"))
        if "queue" in st:
            attempt("queue", lambda: self.sqs.delete_queue(QueueUrl=st["queue"]["url"]))
        if "trail" in st:
            attempt("trail", lambda: self.ct.delete_trail(Name="rootgraph"))
        if "trail_bucket" in st:
            b = st["trail_bucket"]
            def empty_and_delete():
                for page in self.s3.get_paginator("list_object_versions").paginate(Bucket=b):
                    objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                    if objs:
                        self.s3.delete_objects(Bucket=b, Delete={"Objects": objs})
                self.s3.delete_bucket(Bucket=b)
            attempt("trail bucket", empty_and_delete)
        if "db" in st:
            attempt("orders-db", lambda: self.rds.delete_db_instance(DBInstanceIdentifier="orders-db",
                                                                     SkipFinalSnapshot=True, DeleteAutomatedBackups=True))
            if self.wait:
                print("waiting for orders-db to be deleted (~5-10 min)...")
                self.rds.get_waiter("db_instance_deleted").wait(DBInstanceIdentifier="orders-db")
        if "db_subnet_group" in st:
            attempt("db subnet group", lambda: self.rds.delete_db_subnet_group(DBSubnetGroupName="rootgraph-db"))
        ids = [st[k] for k in ("host1", "host2") if k in st]
        if ids:
            attempt("instances", lambda: self.ec2.terminate_instances(InstanceIds=ids))
            if self.wait:
                self.ec2.get_waiter("instance_terminated").wait(InstanceIds=ids)
        if "instance_profile" in st:
            n = st["instance_profile"]
            attempt("profile role", lambda: self.iam.remove_role_from_instance_profile(InstanceProfileName=n, RoleName=n))
            attempt("instance profile", lambda: self.iam.delete_instance_profile(InstanceProfileName=n))
            attempt("role policy", lambda: self.iam.detach_role_policy(RoleName=n, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"))
            attempt("role", lambda: self.iam.delete_role(RoleName=n))
        groups = [st[k] for k in ("sg_db", "sg_host2", "sg_host1") if k in st]
        for gid in groups:  # drop SG-to-SG references first, or the groups can't be deleted
            perms = self.ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0].get("IpPermissions", [])
            if perms:
                attempt(f"rules {gid}", lambda gid=gid, perms=perms: self.ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=perms))
        for gid in groups:
            attempt(f"sg {gid}", lambda gid=gid: self.ec2.delete_security_group(GroupId=gid))
        for assoc in st.get("rt_assoc", []):
            attempt("rt association", lambda a=assoc: self.ec2.disassociate_route_table(AssociationId=a))
        if "route_table" in st:
            attempt("route table", lambda: self.ec2.delete_route_table(RouteTableId=st["route_table"]))
        if "igw" in st:
            attempt("igw detach", lambda: self.ec2.detach_internet_gateway(InternetGatewayId=st["igw"], VpcId=st["vpc"]))
            attempt("igw", lambda: self.ec2.delete_internet_gateway(InternetGatewayId=st["igw"]))
        for k in ("subnet_a", "subnet_b"):
            if k in st:
                attempt(k, lambda k=k: self.ec2.delete_subnet(SubnetId=st[k]))
        if "vpc" in st:
            attempt("vpc", lambda: self.ec2.delete_vpc(VpcId=st["vpc"]))
        if "budget" in st:
            attempt("budget", lambda: self.budgets.delete_budget(AccountId=self.account, BudgetName=st["budget"]))
        STATE.unlink(missing_ok=True)
        CREDS.unlink(missing_ok=True)
        print("estate removed; rotate any keys you copied elsewhere")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="rootgraph demo AWS estate")
    ap.add_argument("cmd", choices=["up", "status", "down"])
    ap.add_argument("--email", help="budget alert email (creates a $10/month budget at 80%)")
    ap.add_argument("--control-plane-cidr", default="172.232.86.149/32",
                    help="the rootgraph server's IP/32, allowed to query Prometheus on host-1")
    a = ap.parse_args(argv)
    estate = Estate(boto3.Session(region_name=REGION))
    if a.cmd == "up":
        estate.up(a.email, a.control_plane_cidr)
    elif a.cmd == "status":
        print(json.dumps(estate.status(), indent=2, default=str))
    else:
        estate.down()


if __name__ == "__main__":
    main(sys.argv[1:])
