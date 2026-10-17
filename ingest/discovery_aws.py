"""AWS discovery into FalkorDB (§6.1) plus the graph diff (§6.2).

    collect(ec2, rds)            raw describe_* responses (read-only IAM: ec2:Describe*, rds:Describe*)
    sync(g, snapshot, services)  write them; returns the Changes the diff produced

Per security group, every ingress rule goes through W1b (detect an in-place edit,
retire the old edge, record SecurityGroupRuleModified) then W1 (upsert). After the
group's rules, W2 retires rules that were not seen (SecurityGroupRuleRemoved).
Removed rules are never deleted: their history is what restore_firewall_rule uses.
The same goes for security-group attachments (W24: SecurityGroupDetached) and instance states
(W25: InstanceStateChanged, e.g. running -> stopped): each becomes a Change with before/after.
Resources not seen at all are marked state='missing' (W21), never deleted.

Rule sources (§5): SG reference -> that Firewall; 0.0.0.0/0 -> Internet;
a /32 equal to a known instance IP -> that Compute; any other CIDR -> CidrBlock.
IPv6 and prefix-list rules are skipped in v1.
"""

import time
from pathlib import Path

import yaml

from graph import db

SERVICES_FILE = Path(__file__).resolve().parent / "services.yaml"


def _pages(client, op: str, key: str, **kw) -> list:
    out = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def collect(ec2, rds) -> dict:
    reservations = _pages(ec2, "describe_instances", "Reservations")
    return {
        "vpcs": _pages(ec2, "describe_vpcs", "Vpcs"),
        "subnets": _pages(ec2, "describe_subnets", "Subnets"),
        "instances": [i for r in reservations for i in r.get("Instances", [])],
        "security_groups": _pages(ec2, "describe_security_groups", "SecurityGroups"),
        "rules": _pages(ec2, "describe_security_group_rules", "SecurityGroupRules"),
        "db_instances": _pages(rds, "describe_db_instances", "DBInstances"),
    }


def _name(tags: list | None, default: str) -> str:
    return next((t["Value"] for t in tags or [] if t.get("Key") == "Name"), default)


def _rule_source(rule: dict, ip_to_instance: dict) -> tuple[str, str] | None:
    """-> (kind, rid) of the traffic source, or None for rules v1 doesn't model."""
    ref = (rule.get("ReferencedGroupInfo") or {}).get("GroupId")
    if ref:
        return "firewall", ref
    cidr = rule.get("CidrIpv4")
    if not cidr:
        return None  # IPv6 / prefix list
    if cidr == "0.0.0.0/0":
        return "internet", "internet"
    if cidr.endswith("/32") and cidr[:-3] in ip_to_instance:
        return "compute", ip_to_instance[cidr[:-3]]
    return "cidr", f"cidr:{cidr}"


def _ports(rule: dict) -> tuple[str, int, int]:
    proto = str(rule.get("IpProtocol", "-1"))
    lo, hi = rule.get("FromPort", -1), rule.get("ToPort", -1)
    if proto == "-1":
        return "all", 0, 65535
    if lo is None or lo < 0:
        lo, hi = 0, 65535
    return proto, int(lo), int(hi)


def load_services(path: Path = SERVICES_FILE) -> dict:
    return yaml.safe_load(path.read_text()) if path.is_file() else {"services": {}}


def sync(g, snap: dict, services: dict | None = None, sync_ts: int | None = None) -> dict:
    ts = int(time.time()) if sync_ts is None else int(sync_ts)
    changes, skipped = [], []

    # networks
    for v in snap["vpcs"]:
        db.run(g, "w12_upsert_network", {"rid": v["VpcId"], "name": _name(v.get("Tags"), v["VpcId"]), "kind": "vpc",
                                         "cidr": v.get("CidrBlock"), "parent_rid": None, "sync_ts": ts})
    for s in snap["subnets"]:
        db.run(g, "w12_upsert_network", {"rid": s["SubnetId"], "name": _name(s.get("Tags"), s["SubnetId"]),
                                         "kind": "subnet", "cidr": s.get("CidrBlock"), "parent_rid": s.get("VpcId"),
                                         "sync_ts": ts})

    # security groups first, so PROTECTS and SG-reference rules can attach
    sg_ids = {sg["GroupId"] for sg in snap["security_groups"]}
    for sg in snap["security_groups"]:
        db.run(g, "w15_upsert_firewall", {"rid": sg["GroupId"], "name": sg.get("GroupName", sg["GroupId"]), "sync_ts": ts})

    # compute
    ip_to_instance, name_to_instance = {}, {}
    for i in snap["instances"]:
        state = (i.get("State") or {}).get("Name", "unknown")
        if state == "terminated":
            continue
        rid, name = i["InstanceId"], _name(i.get("Tags"), i["InstanceId"])
        name_to_instance[name] = rid
        for ip in (i.get("PrivateIpAddress"), i.get("PublicIpAddress")):
            if ip:
                ip_to_instance[ip] = rid
        _, st_ch = db.run(g, "w25_state_change", {"rid": rid, "state": state, "sync_ts": ts})
        changes += [{"event_name": "InstanceStateChanged", "resource": rid, "before": r["before"], "after": state} for r in st_ch]
        db.run(g, "w13_upsert_compute", {"rid": rid, "name": name, "private_ip": i.get("PrivateIpAddress"),
                                         "public_ip": i.get("PublicIpAddress"), "state": state,
                                         "instance_type": i.get("InstanceType"), "subnet_rid": i.get("SubnetId"),
                                         "sync_ts": ts})
        for sg in i.get("SecurityGroups", []):
            db.run(g, "w16_protects", {"fw": sg["GroupId"], "target": rid, "sync_ts": ts})

    # databases
    for d in snap["db_instances"]:
        rid = f"rds:{d['DBInstanceIdentifier']}"
        endpoint = d.get("Endpoint") or {}
        subnets = [s["SubnetIdentifier"] for s in (d.get("DBSubnetGroup") or {}).get("Subnets", [])]
        db.run(g, "w14_upsert_database", {"rid": rid, "name": d["DBInstanceIdentifier"], "engine": d.get("Engine"),
                                          "endpoint": endpoint.get("Address"), "port": endpoint.get("Port"),
                                          "status": d.get("DBInstanceStatus"), "subnet_rids": subnets, "sync_ts": ts})
        for sg in d.get("VpcSecurityGroups", []):
            db.run(g, "w16_protects", {"fw": sg["VpcSecurityGroupId"], "target": rid, "sync_ts": ts})

    # security groups detached from an instance or database since the last sync (W24)
    _, det = db.run(g, "w24_diff_detached", {"sync_ts": ts})
    changes += [{"event_name": "SecurityGroupDetached", "firewall": r["firewall"], "resource": r["target"]} for r in det]

    # rules: W1b (modified?) then W1 (upsert), per group; then W2 (removed)
    by_group: dict[str, list] = {gid: [] for gid in sg_ids}
    for r in snap["rules"]:
        if not r.get("IsEgress"):
            by_group.setdefault(r["GroupId"], []).append(r)
    for gid, rules in by_group.items():
        for r in rules:
            src = _rule_source(r, ip_to_instance)
            if src is None:
                skipped.append(r.get("SecurityGroupRuleId"))
                continue
            kind, src_rid = src
            if kind == "firewall" and src_rid not in sg_ids:  # SG from another VPC/account
                db.run(g, "w15_upsert_firewall", {"rid": src_rid, "name": src_rid, "sync_ts": ts})
            elif kind == "internet":
                db.run(g, "w18_upsert_internet", {"sync_ts": ts})
            elif kind == "cidr":
                db.run(g, "w17_upsert_cidr", {"rid": src_rid, "cidr": src_rid.removeprefix("cidr:"), "sync_ts": ts})
            proto, lo, hi = _ports(r)
            params = {"fw": gid, "rule_id": r["SecurityGroupRuleId"], "proto": proto, "from_port": lo,
                      "to_port": hi, "src_rid": src_rid, "sync_ts": ts}
            _, mod = db.run(g, "w1b_detect_modified_rule", params)
            changes += [{"event_name": "SecurityGroupRuleModified", "firewall": gid, "rule_id": r["SecurityGroupRuleId"]}
                        for _ in mod]
            db.run(g, "w1_upsert_rule", params)
        _, gone = db.run(g, "w2_diff_removed_rules", {"fw": gid, "sync_ts": ts})
        changes += [{"event_name": "SecurityGroupRuleRemoved", "firewall": gid, "rule_id": row["r.rule_id"]}
                    for row in gone]

    # declared services (services.yaml): host by Name tag or instance id
    unresolved = []
    for name, svc in ((services or {}).get("services") or {}).items():
        host = name_to_instance.get(svc.get("host"), svc.get("host"))
        db.run(g, "w19_upsert_service", {"rid": f"svc:{name}", "name": name, "port": svc.get("port"),
                                         "host_rid": host, "sync_ts": ts})
    for name, svc in ((services or {}).get("services") or {}).items():
        for dep in svc.get("depends_on", []):
            to = dep["to"] if ":" in dep["to"] else f"svc:{dep['to']}"
            _, ok = db.run(g, "w20_depends_on", {"from": f"svc:{name}", "to": to, "kind": dep.get("kind", "http"),
                                                 "port": dep.get("port"), "sync_ts": ts})
            if not ok:
                unresolved.append(f"svc:{name}->{to}")

    _, missing = db.run(g, "w21_mark_missing", {"sync_ts": ts})
    return {"sync_ts": ts, "changes": changes, "missing": [m["rid"] for m in missing],
            "skipped_rules": skipped, "unresolved_dependencies": unresolved}


def resync(g, ec2, rds, services: dict | None = None) -> dict:
    """Targeted resync = a full sync: the demo estate is small enough that it takes well under a second."""
    return sync(g, collect(ec2, rds), services if services is not None else load_services())
