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

CATALOGUE = {
    "restore_firewall_rule": {"target_kind": "Firewall"},
    "restart_service": {"target_kind": "Service"},
}


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
    if CATALOGUE[kind]["target_kind"] not in kinds:
        raise PreconditionFailed(f"{kind} needs a {CATALOGUE[kind]['target_kind']}, {target_rid} is {kinds}")

    if kind == "restore_firewall_rule":
        _, rules = db.run(g, "q11_removed_rules_on_firewall",
                          {"fw": target_rid, "since": now - WINDOW_MINUTES * 60})
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
        return {"id": existing[0]["id"], "kind": kind, "target_rid": target_rid, "status": "proposed", "params": params}
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

    def __init__(self, ec2, ssm):
        self.ec2, self.ssm = ec2, ssm

    def run(self, g, action: dict, now: int) -> str:
        p = action["params"]
        if action["kind"] == "restore_firewall_rule":
            resp = self.ec2.authorize_security_group_ingress(GroupId=p["firewall"], IpPermissions=[ip_permission(p["rule"])])
            ids = [r.get("SecurityGroupRuleId") for r in resp.get("SecurityGroupRules", [])]
            return f"authorized on {p['firewall']}: {', '.join(i for i in ids if i) or 'ok'}"
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
    if action["kind"] == "restore_firewall_rule" and p.get("verify_path"):
        env = tools.check_path(*p["verify_path"])
        if not (env["rows"] and env["rows"][0]["permitted"]):
            return False, "path still blocked"
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
