"""Live-AWS code against moto (a local fake of the AWS APIs): estate up/down, discovery + diff,
the executor, and the CloudTrail ingester. Nothing here touches a real account.

Run: set -a; . ./.env; set +a; FALKORDB_HOST=localhost uv run pytest
"""

import copy
import json
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from agent import actions
from agent.tools import Tools
from demo.aws import estate as estate_mod
from graph import db
from ingest import cloudtrail_stream, discovery_aws

REGION = "ap-south-1"
SAMPLE = json.loads((Path(__file__).resolve().parents[1] / "ingest/fixtures/cloudtrail_revoke_sg.json").read_text())


@pytest.fixture
def aws(monkeypatch, tmp_path):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing",
                 "AWS_DEFAULT_REGION": REGION, "AWS_REGION": REGION,
                 "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setattr(estate_mod, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(estate_mod, "CREDS", tmp_path / "credentials.env")
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        est = estate_mod.Estate(session, wait=False)
        st = est.up("oncall@example.com", "172.232.86.149/32")
        yield {"session": session, "estate": est, "state": st, "tmp": tmp_path,
               "ec2": session.client("ec2"), "rds": session.client("rds")}


@pytest.fixture
def g():
    graph = db.graph("ops_test")
    try:
        graph.delete()
    except Exception:
        pass
    db.apply_schema(graph)
    yield graph
    graph.delete()


def discover(aws, g, snap=None, ts=None):
    snap = snap or discovery_aws.collect(aws["ec2"], aws["rds"])
    return discovery_aws.sync(g, snap, discovery_aws.load_services(), sync_ts=ts)


def test_estate_up_writes_state_and_credentials(aws):
    st, creds = aws["state"], (aws["tmp"] / "credentials.env").read_text()
    assert {"vpc", "sg_db", "host1", "host2", "db", "queue", "rule", "trail", "users", "budget"} <= set(st)
    for prefix in ("DISCOVERY", "INGESTER", "EXECUTOR"):
        assert f"{prefix}_AWS_ACCESS_KEY_ID=" in creds
    assert "CHANGES_QUEUE_URL=" in creds and oct((aws["tmp"] / "credentials.env").stat().st_mode)[-3:] == "600"
    assert oct((aws["tmp"] / "state.json").stat().st_mode)[-3:] == "600"  # holds the db password + IAM keys
    doc = aws["session"].client("iam").get_user_policy(UserName="rootgraph-executor",
                                                       PolicyName="rootgraph-executor")["PolicyDocument"]
    policy = json.loads(doc) if isinstance(doc, str) else doc
    assert any(st["sg_db"] in s["Resource"] for s in policy["Statement"])  # executor scoped to sg-db only


def test_discovery_builds_the_estate(aws, g):
    out = discover(aws, g, ts=1000)
    st = aws["state"]
    assert out["unresolved_dependencies"] == [] and out["changes"] == []
    t = Tools(g)
    assert t.resolve("host-1")["rows"][0]["rid"] == st["host1"]
    assert t.resolve("orders-db")["rows"][0]["rid"] == "rds:orders-db"
    env = t.check_path("svc:payments", "rds:orders-db")
    assert env["rows"][0]["permitted"] is True and env["rows"][0]["host"] == st["host1"]
    assert {r["candidate"] for r in t.correlate_alerts(["svc:orders", "svc:reports"], k=3)["rows"]} >= {st["host2"], "rds:orders-db"}
    # the rule edge carries the real AWS rule id
    rid_a = st["sg_rules"]["rule_a"]
    res = g.query("MATCH (:Firewall {rid: $fw})-[r:ALLOWS_FROM {rule_id: $id}]->(src) RETURN r.active, src.rid",
                  {"fw": st["sg_db"], "id": rid_a}).result_set
    assert res == [[True, st["sg_host1"]]]


def test_revoke_then_executor_restore(aws, g):
    st, ec2 = aws["state"], aws["ec2"]
    discover(aws, g, ts=1000)
    ec2.revoke_security_group_ingress(GroupId=st["sg_db"], SecurityGroupRuleIds=[st["sg_rules"]["rule_a"]])
    out = discover(aws, g, ts=2000)
    assert out["changes"] == [{"event_name": "SecurityGroupRuleRemoved", "firewall": st["sg_db"],
                               "rule_id": st["sg_rules"]["rule_a"]}]
    t = Tools(g)
    assert t.check_path("svc:payments", "rds:orders-db")["rows"][0]["permitted"] is False
    culprit = t.removed_rules("svc:payments", "rds:orders-db", minutes=30, now=2000)["rows"][0]
    assert culprit["firewall"] == st["sg_db"] and culprit["source"] == st["sg_host1"]

    action = {"id": "ACT-test", "kind": "restore_firewall_rule",
              "params": {"firewall": st["sg_db"], "rule": {k: culprit[k] for k in
                         ("original_rule_id", "proto", "port_from", "port_to", "source")}}}
    detail = actions.AwsExecutor(ec2, aws["session"].client("ssm")).run(g, action, now=2100)
    assert detail.startswith(f"authorized on {st['sg_db']}")
    discover(aws, g, ts=3000)
    assert t.check_path("svc:payments", "rds:orders-db")["rows"][0]["permitted"] is True


def test_modified_rule_is_detected_and_history_kept(aws, g):
    snap = discovery_aws.collect(aws["ec2"], aws["rds"])
    discover(aws, g, snap, ts=1000)
    edited = copy.deepcopy(snap)
    rule_b = aws["state"]["sg_rules"]["rule_b"]
    for r in edited["rules"]:
        if r["SecurityGroupRuleId"] == rule_b:
            r["FromPort"] = r["ToPort"] = 6543  # ModifySecurityGroupRules keeps the sgr- id
    out = discover(aws, g, edited, ts=2000)
    assert {"event_name": "SecurityGroupRuleModified", "firewall": aws["state"]["sg_db"], "rule_id": rule_b} in out["changes"]
    res = g.query("MATCH (:Firewall {rid: $fw})-[r:ALLOWS_FROM]->() WHERE coalesce(r.original_rule_id, r.rule_id) = $id "
                  "RETURN r.active, r.port_from ORDER BY r.active", {"fw": aws["state"]["sg_db"], "id": rule_b}).result_set
    assert res == [[False, 5432], [True, 6543]]  # old spec kept inactive for restore


def test_missing_instance_is_marked_not_deleted(aws, g):
    discover(aws, g, ts=1000)
    aws["ec2"].terminate_instances(InstanceIds=[aws["state"]["host2"]])
    out = discover(aws, g, ts=2000)
    assert aws["state"]["host2"] in out["missing"]
    assert g.query("MATCH (c:Compute {rid: $r}) RETURN c.state", {"r": aws["state"]["host2"]}).result_set == [["missing"]]


def test_restart_service_via_ssm_and_refuses_bad_names(aws, g):
    ex = actions.AwsExecutor(aws["ec2"], aws["session"].client("ssm"))
    ok = ex.run(g, {"id": "ACT-1", "kind": "restart_service",
                    "params": {"service": "svc:payments", "host": aws["state"]["host1"]}}, now=1)
    assert "docker start payments" in ok
    with pytest.raises(actions.PreconditionFailed):
        ex.run(g, {"id": "ACT-2", "kind": "restart_service",
                   "params": {"service": "svc:x; rm -rf /", "host": aws["state"]["host1"]}}, now=1)


def _event(group, rule, actor=None, error=None, event_id=None):
    ev = json.loads(json.dumps(SAMPLE).replace("GROUP_ID", group).replace("RULE_ID", rule))
    if event_id:
        ev["detail"]["eventID"] = event_id
    if actor:
        ev["detail"]["userIdentity"]["arn"] = actor
    if error:
        ev["detail"]["errorCode"] = error
    return ev


def test_cloudtrail_event_becomes_change(aws, g):
    discover(aws, g, ts=1000)
    st = aws["state"]
    out = cloudtrail_stream.ingest(g, _event(st["sg_db"], st["sg_rules"]["rule_a"]))
    assert out["linked"] == [st["sg_db"]] and out["unlinked"] == [] and out["by_agent"] is False
    rows = Tools(g).recent_changes(st["sg_db"], minutes=60, now=out["at"] + 60)["rows"]
    assert rows[0]["ch.event_name"] == "RevokeSecurityGroupIngress" and rows[0]["ch.actor"].endswith("user/alice")

    agent = cloudtrail_stream.ingest(g, _event(st["sg_db"], "x", event_id="ev-agent",
                                               actor="arn:aws:iam::123456789012:user/rootgraph-executor"))
    assert agent["by_agent"] is True
    unknown = cloudtrail_stream.ingest(g, _event("sg-0notinthegraph", "x", event_id="ev-unknown"))
    assert unknown["unlinked"] == ["sg-0notinthegraph"]
    failed = cloudtrail_stream.ingest(g, _event(st["sg_db"], "x", error="Client.UnauthorizedOperation"))
    assert failed["skipped"].startswith("error")
    assert cloudtrail_stream.parse({"detail": {"eventName": "DescribeInstances"}}) is None


def test_ingester_loop_reads_and_deletes_sqs(aws, g):
    discover(aws, g, ts=1000)
    st, sqs = aws["state"], aws["session"].client("sqs")
    sqs.send_message(QueueUrl=st["queue"]["url"], MessageBody=json.dumps(_event(st["sg_db"], st["sg_rules"]["rule_a"])))
    calls = iter([False, True])
    cloudtrail_stream.run(sqs, st["queue"]["url"], g, stop=lambda: next(calls), wait_seconds=0)
    assert g.query("MATCH (c:Change {event_name: 'RevokeSecurityGroupIngress'}) RETURN count(c)").result_set == [[1]]
    left = sqs.receive_message(QueueUrl=st["queue"]["url"], WaitTimeSeconds=0).get("Messages", [])
    assert left == []


def test_estate_down_removes_everything(aws):
    aws["estate"].down()
    ec2 = aws["ec2"]
    assert ec2.describe_vpcs(Filters=[{"Name": "tag:rootgraph", "Values": ["demo"]}])["Vpcs"] == []
    assert aws["rds"].describe_db_instances()["DBInstances"] == [] or \
        all(d["DBInstanceStatus"] == "deleting" for d in aws["rds"].describe_db_instances()["DBInstances"])
    assert not (aws["tmp"] / "state.json").exists() and not (aws["tmp"] / "credentials.env").exists()
    iam_users = [u["UserName"] for u in aws["session"].client("iam").list_users()["Users"]]
    assert not any(u.startswith("rootgraph-") for u in iam_users)


def test_deploy_hosts_ships_rendered_stacks_over_ssm(aws, monkeypatch, tmp_path):
    import base64
    import io
    import re
    import tarfile

    import yaml

    from demo import render
    from demo.aws import deploy_hosts

    monkeypatch.setattr(render, "BUILD", tmp_path / "build")
    monkeypatch.setenv("WEBHOOK_TOKEN", "test-token")
    results = deploy_hosts.deploy(aws["session"], wait=False)
    assert set(results) == {"host1", "host2"}

    ssm = aws["session"].client("ssm")
    # keyed by comment: moto lists every instance under each command
    sent = {c["Comment"]: c["Parameters"]["commands"] for c in ssm.list_commands()["Commands"]}
    st = aws["state"]
    files = {}
    for host in ("host1", "host2"):
        cmds = sent[f"rootgraph deploy {host}"]
        payload = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d", " ".join(cmds)).group(1)
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(payload)), mode="r:gz") as tar:
            files[host] = {m.name: tar.extractfile(m).read().decode() for m in tar.getmembers() if m.isfile()}
        assert any("docker compose up -d --build" in c for c in cmds)
    assert {"compose.yml", "prometheus.yml", "alertmanager.yml", "rules.yml", "service/app.py"} <= set(files["host1"])
    assert "alertmanager.yml" not in files["host2"] and "prometheus.yml" not in files["host2"]
    am = yaml.safe_load(files["host1"]["alertmanager.yml"])["receivers"][0]["webhook_configs"][0]
    assert am["url"].endswith("/live/hooks/alertmanager") and am["http_config"]["authorization"]["credentials"] == "test-token"
    h1 = yaml.safe_load(files["host1"]["compose.yml"])["services"]
    assert h1["payments"]["container_name"] == "payments"  # what restart_service and the S3 script target
    prom = yaml.safe_load(files["host1"]["prometheus.yml"])
    node_rids = {c["labels"]["rid"] for c in prom["scrape_configs"][1]["static_configs"]}
    assert node_rids == {st["host1"], st["host2"]}  # real instance ids = graph rids


def test_fault_scripts_send_the_right_commands(aws):
    from demo.aws import ssm as ssm_mod
    from demo.faults import s2_cpu_hog, s3_stop_payments
    ssm = aws["session"].client("ssm")
    ssm_mod.run(ssm, aws["state"]["host2"], [s2_cpu_hog.HOG], "S2", wait=False)
    ssm_mod.run(ssm, aws["state"]["host1"], [f"docker stop {s3_stop_payments.CONTAINER}"], "S3", wait=False)
    sent = {c["Comment"]: c["Parameters"]["commands"][0] for c in ssm.list_commands()["Commands"]}
    assert "timeout 300" in sent["S2"] and sent["S3"] == "docker stop payments"
