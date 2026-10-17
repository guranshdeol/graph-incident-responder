"""Action catalogue (§7.6) and the approval state machine.

    proposed -> approved | rejected -> executed -> verified | failed

The pipeline (and later the LLM) can only PROPOSE. Only an authenticated human,
through the UI, calls approve(). execute() refuses anything not approved.

Executors:
  SandboxExecutor  graph-only: re-activates the rule / records the restart as a
                   by_agent Change. Used by ops_sandbox and the tests.
  live AWS         P2 work (ec2.authorize_security_group_ingress, SSM docker start).
"""

import json
import re
import time
import uuid

from agent import probe as probe_mod
from graph import db

EXECUTOR_ACTOR = "arn:aws:iam::000000000000:role/rootgraph-executor"  # by_agent marker (risk #7)
WINDOW_MINUTES = 30

CATALOGUE = {   # each fix undoes one kind of change found in the graph
    "restore_firewall_rule": {"target_kind": ("Firewall",)},          # a rule was removed: re-add it
    "revert_rule_edit": {"target_kind": ("Firewall",)},               # a rule was edited in place: edit it back
    "reattach_security_group": {"target_kind": ("Compute", "Database")},  # a security group was detached: re-attach
    "start_instance": {"target_kind": ("Compute",)},                  # an instance was stopped: start it
    "restart_service": {"target_kind": ("Service",)},                 # a container is down: start it
}


def state_of(g, rid: str) -> str | None:
    _, rows = db.run(g, "q26_resource_state", {"rid": rid})
    return rows[0]["state"] if rows else None


def _peer(src: str) -> dict:
    if src.startswith("sg-"):
        return {"ReferencedGroupId": src}
    if src == "internet":
        return {"CidrIpv4": "0.0.0.0/0"}
    if src.startswith("cidr:"):
        return {"CidrIpv4": src.removeprefix("cidr:")}
    raise PreconditionFailed(f"editing back a rule whose source is {src} is not supported yet")


class PreconditionFailed(Exception):
    pass


def ip_permission(spec: dict) -> dict:
    """The exact rule to re-add, as boto3 IpPermissions. Compute (/32) sources aren't supported in v1."""
    src = spec["source"]
    perm = {"IpProtocol": "-1" if spec["proto"] == "all" else spec["proto"]}
    if spec["proto"] != "all":
        perm |= {"FromPort": int(spec["port_from"]), "ToPort": int(spec["port_to"])}
    if src.startswith("sg-"):
        perm["UserIdGroupPairs"] = [{"GroupId": src, "Description": "restored by rootgraph"}]
    elif src == "internet":
        perm["IpRanges"] = [{"CidrIp": "0.0.0.0/0", "Description": "restored by rootgraph"}]
    elif src.startswith("cidr:"):
        perm["IpRanges"] = [{"CidrIp": src.removeprefix("cidr:"), "Description": "restored by rootgraph"}]
    else:
        raise PreconditionFailed(f"restoring a rule whose source is {src} is not supported yet")
    return perm


def _aws_cli(fw: str, spec: dict) -> str | None:
    src = spec["source"]
    if src.startswith("sg-"):
        peer = f"UserIdGroupPairs=[{{GroupId={src}}}]"
    elif src == "internet":
        peer = "IpRanges=[{CidrIp=0.0.0.0/0}]"
    elif src.startswith("cidr:"):
        peer = f"IpRanges=[{{CidrIp={src.removeprefix('cidr:')}}}]"
    else:
        return None
    return (f"aws ec2 authorize-security-group-ingress --group-id {fw} --ip-permissions "
            f"IpProtocol={spec['proto']},FromPort={spec['port_from']},ToPort={spec['port_to']},{peer}")


def propose(g, tools, probe_source, incident_id: str, kind: str, target_rid: str,
            now: int, hint: dict | None = None) -> dict:
    """Check preconditions, build the exact spec + blast radius + rollback, write Action{proposed}."""
    if kind not in CATALOGUE:
        raise PreconditionFailed(f"{kind!r} is not in the action catalogue")
    resolved = tools.resolve(target_rid)
    if resolved["outcome"] != "answered_with_path":
        raise PreconditionFailed(f"unknown target {target_rid!r}")
    target_rid, kinds = resolved["rows"][0]["rid"], resolved["rows"][0]["kinds"]
    if not set(CATALOGUE[kind]["target_kind"]) & set(kinds):
        raise PreconditionFailed(f"{kind} needs a {' or '.join(CATALOGUE[kind]['target_kind'])}, {target_rid} is {kinds}")
    since = now - WINDOW_MINUTES * 60

    if kind == "restore_firewall_rule":
        _, rules = db.run(g, "q11_removed_rules_on_firewall", {"fw": target_rid, "since": since})
        rules = [r for r in rules if "@" not in r["rule_id"]] or rules   # edited rules are reverted, not re-added
        if hint and hint.get("rule_id"):
            rules = [r for r in rules if r["rule_id"] == hint["rule_id"]] or rules
        if not rules:
            raise PreconditionFailed(f"no rule on {target_rid} was removed in the last {WINDOW_MINUTES} min")
        spec = rules[0]
        params = {
            "firewall": target_rid,
            "rule": {k: spec[k] for k in ("original_rule_id", "proto", "port_from", "port_to", "source")},
            "retired_rule_id": spec["rule_id"],
            "removed_at": spec["removed_at"],
            "gains_access": spec["source"],
            "rollback": f"revoke the re-added rule ({spec['proto']} {spec['port_from']}-{spec['port_to']} from {spec['source']})",
            "aws_cli": _aws_cli(target_rid, spec),
            "verify_path": (hint or {}).get("path"),
        }
    elif kind == "revert_rule_edit":
        _, rules = db.run(g, "q11_removed_rules_on_firewall", {"fw": target_rid, "since": since})
        rules = [r for r in rules if "@" in r["rule_id"] and (not hint or not hint.get("rule_id") or r["rule_id"] == hint["rule_id"])]
        if not rules:
            raise PreconditionFailed(f"no rule on {target_rid} was edited in the last {WINDOW_MINUTES} min")
        old = rules[0]
        _, active = db.run(g, "q15_active_rules_on_firewall", {"fw": target_rid})
        now_rule = next((r for r in active if r["rule_id"] == old["original_rule_id"]), None)
        spec = {k: old[k] for k in ("proto", "port_from", "port_to", "source")}
        cur = f"{now_rule['proto']} {now_rule['port_from']}-{now_rule['port_to']} from {now_rule['source']}" if now_rule else "(rule no longer present)"
        peer = _peer(spec["source"]); flag = "ReferencedGroupId" if "ReferencedGroupId" in peer else "CidrIpv4"
        params = {
            "firewall": target_rid, "rule_id": old["original_rule_id"], "rule": spec,
            "before": f"{spec['proto']} {spec['port_from']}-{spec['port_to']} from {spec['source']}", "now": cur,
            "gains_access": spec["source"],
            "rollback": f"edit rule {old['original_rule_id']} back to {cur}",
            "aws_cli": (f"aws ec2 modify-security-group-rules --group-id {target_rid} --security-group-rules "
                        f"SecurityGroupRuleId={old['original_rule_id']},SecurityGroupRule={{IpProtocol={spec['proto']},"
                        f"FromPort={spec['port_from']},ToPort={spec['port_to']},{flag}={peer[flag]}}}"),
            "verify_path": (hint or {}).get("path"),
        }
    elif kind == "reattach_security_group":
        _, gone = db.run(g, "q27_detached_from", {"rid": target_rid, "since": since})
        gone = [r for r in gone if not hint or not hint.get("firewall") or r["firewall"] == hint["firewall"]]
        if not gone:
            raise PreconditionFailed(f"no security group was detached from {target_rid} in the last {WINDOW_MINUTES} min")
        fw = gone[0]["firewall"]
        _, cur = db.run(g, "q25_active_firewalls_of", {"rid": target_rid})
        groups = sorted({r["firewall"] for r in cur} | {fw})
        is_db = "Database" in kinds
        params = {
            "target": target_rid, "target_kind": "Database" if is_db else "Compute", "firewall": fw,
            "groups_after": groups, "groups_now": sorted(r["firewall"] for r in cur),
            "gains_access": f"{target_rid} gets {fw}'s rules back",
            "rollback": f"detach {fw} from {target_rid} again",
            "aws_cli": (f"aws rds modify-db-instance --db-instance-identifier {target_rid.removeprefix('rds:')} "
                        f"--vpc-security-group-ids {' '.join(groups)} --apply-immediately") if is_db else
                       f"aws ec2 modify-instance-attribute --instance-id {target_rid} --groups {' '.join(groups)}",
            "verify_path": (hint or {}).get("path"),
        }
    elif kind == "start_instance":
        st = state_of(g, target_rid)
        if st not in ("stopped", "stopping"):
            raise PreconditionFailed(f"{target_rid} is {st}, not stopped")
        blast = tools.blast_radius(target_rid, 4)
        params = {
            "instance": target_rid, "state": st,
            "blast_radius": [r["affected"] for r in blast["rows"]],
            "rollback": f"stop {target_rid} again",
            "aws_cli": f"aws ec2 start-instances --instance-ids {target_rid}",
        }
    else:  # restart_service
        env = probe_mod.probe(tools, probe_source, target_rid)
        if env["rows"] and env["rows"][0].get("state") != "unhealthy":
            raise PreconditionFailed(f"{target_rid} is not down (probe: {env['rows'][0].get('state')})")
        _, hosts = db.run(g, "q16_service_host", {"rid": target_rid})
        blast = tools.blast_radius(target_rid, 4)
        params = {
            "service": target_rid,
            "host": hosts[0]["host"] if hosts else None,
            "command": f"docker start {target_rid.removeprefix('svc:')}",
            "blast_radius": [r["affected"] for r in blast["rows"]],
            "rollback": "n/a (dependents may blip while it starts)",
        }

    _, existing = db.run(g, "q21_open_action_for", {"incident_id": incident_id, "kind": kind, "target_rid": target_rid})
    if existing:  # a re-investigation of the same incident: keep the one proposal
        return {"id": existing[0]["id"], "kind": kind, "target_rid": target_rid, "status": existing[0]["status"], "params": params}
    action_id = f"ACT-{uuid.uuid4().hex[:8]}"
    db.run(g, "w8_create_action", {"id": action_id, "kind": kind, "params": json.dumps(params),
                                   "now": now, "incident_id": incident_id, "target_rid": target_rid})
    return {"id": action_id, "kind": kind, "target_rid": target_rid, "status": "proposed", "params": params}


def get(g, action_id: str) -> dict | None:
    _, rows = db.run(g, "q14_get_action", {"id": action_id})
    if not rows:
        return None
    row = dict(rows[0])
    row["params"] = json.loads(row["params"]) if row["params"] else {}
    return row


def _transition(g, action_id, frm, to, now, actor=None, detail=None) -> bool:
    _, rows = db.run(g, "w9_transition_action",
                     {"id": action_id, "from": frm, "to": to, "now": now, "actor": actor, "detail": detail})
    return bool(rows)


def approve(g, action_id: str, actor: str, now: int) -> bool:
    """UI only: an authenticated human. Never exposed to the LLM."""
    return _transition(g, action_id, ["proposed"], "approved", now, actor=actor)


def reject(g, action_id: str, actor: str, now: int) -> bool:
    return _transition(g, action_id, ["proposed"], "rejected", now, actor=actor)


class SandboxExecutor:
    """Graph-only effects, recorded as by_agent Changes so they are never suspects."""

    def run(self, g, action: dict, now: int) -> str:
        p = action["params"]
        if action["kind"] == "restore_firewall_rule":
            rule = p["rule"]
            db.run(g, "w1_upsert_rule", {"fw": p["firewall"], "src_rid": rule["source"],
                                         "rule_id": rule["original_rule_id"], "proto": rule["proto"],
                                         "from_port": rule["port_from"], "to_port": rule["port_to"],
                                         "sync_ts": now})
            event, rids = "AuthorizeSecurityGroupIngress", [p["firewall"]]
        elif action["kind"] == "revert_rule_edit":
            r = p["rule"]   # same rule id, original spec: MERGE lands on the edited edge and sets it back
            db.run(g, "w1_upsert_rule", {"fw": p["firewall"], "src_rid": r["source"], "rule_id": p["rule_id"], "proto": r["proto"],
                                         "from_port": r["port_from"], "to_port": r["port_to"], "sync_ts": now})
            event, rids = "ModifySecurityGroupRules", [p["firewall"]]
        elif action["kind"] == "reattach_security_group":
            db.run(g, "w27_set_protects", {"fw": p["firewall"], "target": p["target"], "active": True, "ts": now})
            event, rids = ("ModifyDBInstance" if p["target_kind"] == "Database" else "ModifyInstanceAttribute"), [p["target"]]
        elif action["kind"] == "start_instance":
            db.run(g, "w26_set_state", {"rid": p["instance"], "state": "running"})
            event, rids = "StartInstances", [p["instance"]]
        else:
            event, rids = "SSM:RunCommand docker start", [p["service"]]
        db.run(g, "w3_ingest_change", {"event_id": f"agent:{action['id']}", "event_name": event,
                                       "actor": EXECUTOR_ACTOR, "at": now, "by_agent": True,
                                       "request_json": json.dumps(p), "rids": rids})
        return f"sandbox: {event} on {', '.join(rids)}"


SERVICE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class AwsExecutor:
    """Live effects with the scoped executor principal (§7.7): ec2:AuthorizeSecurityGroupIngress
    on the demo SG, ssm:SendCommand on instances tagged rootgraph=demo. CloudTrail records
    these under the executor's ARN, so the ingester marks them by_agent."""

    def __init__(self, ec2, ssm, rds=None):
        self.ec2, self.ssm, self.rds = ec2, ssm, rds

    def run(self, g, action: dict, now: int) -> str:
        p = action["params"]
        if action["kind"] == "restore_firewall_rule":
            resp = self.ec2.authorize_security_group_ingress(GroupId=p["firewall"], IpPermissions=[ip_permission(p["rule"])])
            ids = [r.get("SecurityGroupRuleId") for r in resp.get("SecurityGroupRules", [])]
            return f"authorized on {p['firewall']}: {', '.join(i for i in ids if i) or 'ok'}"
        if action["kind"] == "revert_rule_edit":
            r = p["rule"]
            rule = {"IpProtocol": "-1" if r["proto"] == "all" else r["proto"], **_peer(r["source"]), "Description": "edited back by rootgraph"}
            if r["proto"] != "all":
                rule |= {"FromPort": int(r["port_from"]), "ToPort": int(r["port_to"])}
            self.ec2.modify_security_group_rules(GroupId=p["firewall"], SecurityGroupRules=[{"SecurityGroupRuleId": p["rule_id"], "SecurityGroupRule": rule}])
            return f"rule {p['rule_id']} on {p['firewall']} edited back to {p['before']}"
        if action["kind"] == "reattach_security_group":
            if p["target_kind"] == "Database":
                self.rds.modify_db_instance(DBInstanceIdentifier=p["target"].removeprefix("rds:"),
                                            VpcSecurityGroupIds=p["groups_after"], ApplyImmediately=True)
            else:
                self.ec2.modify_instance_attribute(InstanceId=p["target"], Groups=p["groups_after"])
            return f"{p['firewall']} re-attached to {p['target']} (groups now {', '.join(p['groups_after'])})"
        if action["kind"] == "start_instance":
            self.ec2.start_instances(InstanceIds=[p["instance"]])
            return f"started {p['instance']}"
        name = p["service"].removeprefix("svc:")
        if not SERVICE_NAME.match(name) or not p.get("host"):
            raise PreconditionFailed(f"refusing to build a command for service {p['service']!r} on {p.get('host')!r}")
        resp = self.ssm.send_command(InstanceIds=[p["host"]], DocumentName="AWS-RunShellScript",
                                     Parameters={"commands": [f"docker start {name}"]},
                                     Comment=f"rootgraph {action['id']}"[:100])
        return f"ssm command {resp['Command']['CommandId']} on {p['host']}: docker start {name}"


def execute(g, action_id: str, executor, now: int) -> dict:
    action = get(g, action_id)
    if action is None:
        raise PreconditionFailed(f"no action {action_id}")
    if action["status"] != "approved":
        raise PreconditionFailed(f"action {action_id} is {action['status']}, not approved")
    try:
        detail = executor.run(g, action, now)
    except Exception as exc:
        _transition(g, action_id, ["approved"], "failed", now, detail=f"executor error: {exc}")
        raise
    _transition(g, action_id, ["approved"], "executed", now, detail=detail)
    return get(g, action_id)


def _fixed(g, tools, probe_source, action: dict) -> tuple[bool, str]:
    _, alerts = db.run(g, "q13_incident_alerts", {"id": action["incident_id"]})
    still = [a["alertname"] + "@" + str(a["rid"]) for a in alerts if a["status"] != "resolved"]
    if still:
        return False, "still firing: " + ", ".join(still)
    p = action["params"]
    if action["kind"] in ("restore_firewall_rule", "revert_rule_edit", "reattach_security_group") and p.get("verify_path"):
        env = tools.check_path(*p["verify_path"])
        if not (env["rows"] and env["rows"][0]["permitted"]):
            return False, "path still blocked"
    if action["kind"] == "start_instance":
        env = probe_mod.probe(tools, probe_source, p["instance"])
        if env["rows"] and env["rows"][0].get("state") not in ("healthy", "unknown"):
            return False, f"instance probe {env['rows'][0].get('state')}"
    if action["kind"] == "restart_service":
        env = probe_mod.probe(tools, probe_source, p["service"])
        if env["rows"][0]["state"] != "healthy":
            return False, f"probe {env['rows'][0]['state']}"
    return True, "alerts resolved and checks healthy"


def verify(g, tools, probe_source, action_id: str, now=time.time, timeout: int = 120,
           interval: int = 5, sleep=time.sleep) -> dict:
    """Poll until the incident's alerts resolve and the target checks out, or time out."""
    action = get(g, action_id)
    deadline = now() + timeout
    while True:
        ok, why = _fixed(g, tools, probe_source, action)
        if ok or now() >= deadline:
            _transition(g, action_id, ["executed"], "verified" if ok else "failed", int(now()), detail=why)
            return {"verified": ok, "detail": why}
        sleep(interval)
