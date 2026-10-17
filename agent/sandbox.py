"""Replayable scenarios for ops_sandbox and the tests (graph/fixtures/scenarios/*.yaml).

A scenario injects its faults the way the live system would see them:
  revoke_rule  -> a discovery sync of the firewall in which the rule is gone (W1 + W2 diff)
  cloudtrail   -> a CloudTrail Change linked to the resources (W3)
then posts an Alertmanager-shaped payload through ingest.alerts, exactly like the
webhook. recover() posts the matching "resolved" payload and flips probes to
their post-fix values, which is what verification then observes.
"""

import json
from pathlib import Path

import yaml

from agent.probe import FixtureProbe
from graph import db
from ingest import alerts as alert_ingest

SCENARIOS_DIR = db.FIXTURES_DIR / "scenarios"
ALERT_AGE_SECONDS = 60


def load(name: str) -> dict:
    spec = yaml.safe_load((SCENARIOS_DIR / f"{name}.yaml").read_text())
    if spec.get("repeat_of"):
        base = load(spec["repeat_of"])
        spec = {**base, **spec}
    return spec


def names() -> list[str]:
    return sorted(p.stem for p in SCENARIOS_DIR.glob("*.yaml"))


def _iso(epoch: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Scenario:
    def __init__(self, g, name: str, now: int):
        self.g, self.spec, self.now = g, load(name), now
        self.probes = FixtureProbe(self.spec.get("probes", {}), self.spec.get("probes_after_fix", {}))
        self.group_key = f"{{}}:{{env=\"sandbox\",scenario=\"{self.spec['id']}\"}}"
        self.starts_at = now - ALERT_AGE_SECONDS

    # -- faults ---------------------------------------------------------------

    def _revoke_rule(self, fw: str, rule_id: str, at_offset: int = 0):
        # Discovery notices the removal at injection time. (Not now + at_offset: if the
        # agent restored this rule moments ago, its last_seen is newer than an
        # offset in the past and the W2 diff would not see the rule as gone.)
        ts = self.now
        _, rules = db.run(self.g, "q15_active_rules_on_firewall", {"fw": fw})
        for r in rules:
            if r["rule_id"] != rule_id:
                db.run(self.g, "w1_upsert_rule", {"fw": fw, "src_rid": r["source"], "rule_id": r["rule_id"],
                                                  "proto": r["proto"], "from_port": r["port_from"],
                                                  "to_port": r["port_to"], "sync_ts": ts})
        db.run(self.g, "w2_diff_removed_rules", {"fw": fw, "sync_ts": ts})

    def _cloudtrail(self, event_name, actor, rids, at_offset=0, request=None):
        at = self.now + at_offset
        db.run(self.g, "w3_ingest_change", {
            "event_id": f"ct:{self.spec['id']}:{event_name}:{at}", "event_name": event_name,
            "actor": actor, "at": at, "by_agent": False,
            "request_json": json.dumps(request or {}), "rids": rids})

    def _modify_rule(self, fw: str, rule_id: str, port_from: int, port_to: int, source: str | None = None):
        """Someone edits a rule in place (same id, new port/source): discovery's W1b + W1, as on live."""
        _, rules = db.run(self.g, "q15_active_rules_on_firewall", {"fw": fw})
        for r in rules:
            new = r["rule_id"] == rule_id
            params = {"fw": fw, "rule_id": r["rule_id"], "proto": r["proto"], "from_port": port_from if new else r["port_from"],
                      "to_port": port_to if new else r["port_to"], "src_rid": (source or r["source"]) if new else r["source"], "sync_ts": self.now}
            db.run(self.g, "w1b_detect_modified_rule", params); db.run(self.g, "w1_upsert_rule", params)

    def _detach_sg(self, fw: str, target: str):
        """Someone removes a security group from an instance/database: discovery's W24 diff."""
        db.run(self.g, "w27_set_protects", {"fw": fw, "target": target, "active": False, "ts": self.now})
        db.run(self.g, "w3_ingest_change", {"event_id": f"diff:detach:{fw}:{target}:{self.now}", "event_name": "SecurityGroupDetached",
                                            "actor": None, "at": self.now, "by_agent": False, "request_json": "{}", "rids": [target, fw]})

    def _stop_instance(self, rid: str):
        """Someone stops an instance: discovery's W25 state diff."""
        db.run(self.g, "w25_state_change", {"rid": rid, "state": "stopped", "sync_ts": self.now})
        db.run(self.g, "w26_set_state", {"rid": rid, "state": "stopped"})

    def inject_faults(self):
        for fault in self.spec.get("faults", []):
            (kind, args), = fault.items()
            {"revoke_rule": self._revoke_rule, "cloudtrail": self._cloudtrail, "modify_rule": self._modify_rule,
             "detach_sg": self._detach_sg, "stop_instance": self._stop_instance}[kind](**args)

    # -- alerts ---------------------------------------------------------------

    def payload(self, status: str = "firing") -> dict:
        alerts = []
        for a in self.spec["alerts"]:
            labels = {"alertname": a["alertname"], "rid": a["rid"], "severity": a.get("severity", "page"),
                      "env": "sandbox"}
            if a.get("target_rid"):
                labels["target_rid"] = a["target_rid"]
            fp = f"{self.spec['id']}-{a['alertname']}-{a['rid']}".replace(":", "_")
            alerts.append({"status": status, "labels": labels, "annotations": {},
                           "startsAt": _iso(self.starts_at),
                           "endsAt": _iso(self.now) if status == "resolved" else "0001-01-01T00:00:00Z",
                           "fingerprint": fp})
        return {"version": "4", "groupKey": self.group_key, "status": status, "receiver": "rootgraph",
                "groupLabels": {"env": "sandbox"}, "commonLabels": {"env": "sandbox"}, "alerts": alerts}

    def inject(self) -> dict:
        """Faults, then the firing webhook. Returns ingest's result (incident id)."""
        self.inject_faults()
        return alert_ingest.ingest(self.g, self.payload("firing"), now=self.now)

    def recover(self, now: int | None = None) -> dict:
        """What the world looks like after a successful fix."""
        self.probes.fixed = True
        return alert_ingest.ingest(self.g, self.payload("resolved"), now=now or self.now)
