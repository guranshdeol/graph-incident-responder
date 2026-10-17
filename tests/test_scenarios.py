"""Scenario oracles (§7.4, §10): replay S1-S5 into ops_test and check the investigation.

    S1 SG rule revoked        top sg-db; host-1 covers most but probes healthy; payments is a victim
    S2 CPU hog on host-2      top i-host2; no catalogued action
    S3 payments stopped       top svc:payments; restart_service with blast radius
    S4 repeat of S1           sg-db again, recalled from S1's memory, fix pre-filled
    S5 two faults at once     sg-db and payments both in the top 2, "multiple likely causes"

Run: set -a; . ./.env; set +a; FALKORDB_HOST=localhost uv run pytest
"""

import json

import pytest

from agent import actions, memory
from agent.investigate import Investigator
from agent.sandbox import Scenario
from agent.tools import Tools
from graph import db
from ingest import alerts as alert_ingest

GRAPH = "ops_test"
NOW = 1792200000


@pytest.fixture
def g():
    graph = db.graph(GRAPH)
    db.load_fixture(graph)
    yield graph
    graph.delete()


def investigate(g, name, now=NOW):
    sc = Scenario(g, name, now)
    res = sc.inject()
    assert res["opened"] and not res["unlinked_rids"]
    report = Investigator(g, sc.probes, now=lambda: now).run(res["incident_id"])
    return sc, report


def row(report, rid):
    return next(r for r in report["scorecard"] if r["rid"] == rid)


def resolve_s1(g, sc, report, now=NOW):
    """Human approves, sandbox executes, world recovers, verify, write memory."""
    act = report["proposals"][0]["action"]
    assert actions.approve(g, act["id"], actor="oncall@team", now=now + 10)
    actions.execute(g, act["id"], actions.SandboxExecutor(), now=now + 20)
    sc.recover(now=now + 40)
    tools = Tools(g)
    out = actions.verify(g, tools, sc.probes, act["id"], now=lambda: now + 60, timeout=0)
    assert out["verified"], out
    memory.close_incident(g, report["incident_id"], report["top"], act["id"], report["root_change_id"],
                          report["explanation"], now=now + 60)
    memory.record_finding(g, tools, report["incident_id"], report["explanation"], [report["top"]], now=now + 60)
    return act


# -- S1 ------------------------------------------------------------------------

def test_s1_sg_rule_revoked(g):
    _, rep = investigate(g, "s1")
    assert rep["top"] == "sg-db"
    assert not rep["multiple_causes"]
    sg = row(rep, "sg-db")
    assert sg["components"]["broken_path"] == 1 and sg["components"]["change_in_window"] == 1
    assert sg["components"]["coverage_ratio"] == 1.0  # inherits payments' chain + host-1's blackbox alert
    # coverage alone blamed host-1; the probe overturned it
    host1 = row(rep, "i-host1")
    assert host1["explains"] == sorted(rep["alerting"]) and host1["probe"] == "healthy"
    assert host1["score"] < sg["score"]
    # the DB is fine: reachable from host-2 (sibling evidence)
    assert row(rep, "rds:orders-db")["probe"] == "healthy"
    # payments is a victim: degraded, not down, no direct evidence
    assert row(rep, "svc:payments")["probe"] == "degraded"
    # the second SG on orders-db never allowed host-1, so it is not blamed (risk #18)
    assert "sg-db-admin" not in [r["rid"] for r in rep["scorecard"]]
    assert rep["broken_paths"] == [{
        "from": "svc:payments", "to": "rds:orders-db", "host": "i-host1", "port": 5432, "firewalls": ["sg-db"],
        "culprit_rules": rep["broken_paths"][0]["culprit_rules"]}]
    assert rep["root_change_id"]


def test_s1_proposes_exact_rule(g):
    _, rep = investigate(g, "s1")
    act = rep["proposals"][0]["action"]
    assert act["kind"] == "restore_firewall_rule" and act["target_rid"] == "sg-db"
    p = act["params"]
    assert p["rule"] == {"original_rule_id": "sgr-a", "proto": "tcp", "port_from": 5432, "port_to": 5432,
                         "source": "sg-host1"}
    assert p["gains_access"] == "sg-host1" and p["verify_path"] == ["svc:payments", "rds:orders-db"]
    assert "--group-id sg-db" in p["aws_cli"] and "GroupId=sg-host1" in p["aws_cli"]
    assert actions.get(g, act["id"])["status"] == "proposed"


def test_s1_trace_is_all_cypher_tools(g):
    _, rep = investigate(g, "s1")
    tools_used = {e["tool"] for e in rep["trace"]}
    assert {"correlate_alerts", "dependencies", "check_path", "removed_rules", "probe",
            "recent_changes", "recall_incidents"} <= tools_used
    assert all(e["by"] == "pipeline" for e in rep["trace"])
    assert all(e["cypher"] for e in rep["trace"] if e["tool"] != "probe")


def test_s1_report_and_suspects_stored_in_graph(g):
    _, rep = investigate(g, "s1")
    res = g.query("MATCH (i:Incident {id: $id}) RETURN i.report", {"id": rep["incident_id"]}).result_set
    assert json.loads(res[0][0])["top"] == "sg-db"
    res = g.query("MATCH (:Incident {id: $id})-[s:SUSPECTS]->(r) WHERE s.rank = 1 RETURN r.rid",
                  {"id": rep["incident_id"]}).result_set
    assert res[0][0] == "sg-db"


def test_s1_full_lifecycle(g):
    sc, rep = investigate(g, "s1")
    act = resolve_s1(g, sc, rep)
    assert actions.get(g, act["id"])["status"] == "verified"
    assert Tools(g).check_path("svc:payments", "rds:orders-db")["rows"][0]["permitted"] is True
    res = g.query("MATCH (i:Incident {id: $id})-[:ROOT_CAUSE]->(r) "
                  "MATCH (i)-[:EXPLAINED_BY]->(ch:Change) MATCH (:Action {id: $a})-[:RESOLVED]->(i) "
                  "MATCH (:Finding)-[:ABOUT]->(i) RETURN i.status, r.rid, ch.event_name, i.ttr_seconds",
                  {"id": rep["incident_id"], "a": act["id"]}).result_set
    assert res[0][0] == "resolved" and res[0][1] == "sg-db" and res[0][3] == 60
    # the agent's own fix is in the graph as a by_agent Change and is never a suspect
    res = g.query("MATCH (c:Change {by_agent: true})-[:MODIFIED]->(:Firewall {rid: 'sg-db'}) RETURN count(c)").result_set
    assert res[0][0] == 1


def test_execute_requires_approval(g):
    _, rep = investigate(g, "s1")
    act = rep["proposals"][0]["action"]
    with pytest.raises(actions.PreconditionFailed):
        actions.execute(g, act["id"], actions.SandboxExecutor(), now=NOW)
    assert actions.reject(g, act["id"], actor="oncall@team", now=NOW)
    assert not actions.approve(g, act["id"], actor="oncall@team", now=NOW)  # rejected is final


def test_verify_fails_when_alerts_keep_firing(g):
    sc, rep = investigate(g, "s1")
    act = rep["proposals"][0]["action"]
    actions.approve(g, act["id"], "oncall@team", NOW)
    actions.execute(g, act["id"], actions.SandboxExecutor(), NOW)
    out = actions.verify(g, Tools(g), sc.probes, act["id"], now=lambda: NOW, timeout=0)  # no recover()
    assert not out["verified"] and "still firing" in out["detail"]
    assert actions.get(g, act["id"])["status"] == "failed"


# -- S2 ------------------------------------------------------------------------

def test_s2_shared_host(g):
    _, rep = investigate(g, "s2")
    assert rep["top"] == "i-host2" and not rep["multiple_causes"]
    assert row(rep, "i-host2")["probe"] == "unhealthy"
    assert row(rep, "svc:orders")["score"] < row(rep, "i-host2")["score"]  # explains only part of the set
    assert rep["proposals"] == [{"rid": "i-host2", "action": None, "reason": rep["proposals"][0]["reason"]}]
    assert "no catalogued safe action" in rep["proposals"][0]["reason"]
    assert rep["broken_paths"] == []


# -- S3 ------------------------------------------------------------------------

def test_s3_plain_service_failure(g):
    _, rep = investigate(g, "s3")
    assert rep["top"] == "svc:payments" and not rep["multiple_causes"]
    top = row(rep, "svc:payments")
    assert top["probe"] == "unhealthy" and top["components"]["change_in_window"] == 0
    assert row(rep, "i-host1")["probe"] == "healthy"
    act = rep["proposals"][0]["action"]
    assert act["kind"] == "restart_service" and act["params"]["host"] == "i-host1"
    assert {"svc:checkout", "svc:web"} <= set(act["params"]["blast_radius"])


def test_s3_restart_lifecycle(g):
    sc, rep = investigate(g, "s3")
    act = rep["proposals"][0]["action"]
    actions.approve(g, act["id"], "oncall@team", NOW)
    actions.execute(g, act["id"], actions.SandboxExecutor(), NOW + 5)
    sc.recover(NOW + 10)
    assert actions.verify(g, Tools(g), sc.probes, act["id"], now=lambda: NOW + 15, timeout=0)["verified"]


# -- S4 ------------------------------------------------------------------------

def test_s4_memory_recall(g):
    sc1, rep1 = investigate(g, "s1", now=NOW)
    resolve_s1(g, sc1, rep1, now=NOW)
    _, rep = investigate(g, "s4", now=NOW + 3600)
    assert rep["incident_id"] != rep1["incident_id"]
    assert rep["top"] == "sg-db"
    sg = row(rep, "sg-db")
    assert sg["components"]["prior_incident_match"] == 1
    assert sg["score"] == row(rep1, "sg-db")["score"] + 1.0
    assert rep["recalled"][0]["root_cause"] == "sg-db" and rep["recalled"][0]["fix"] == "restore_firewall_rule"
    assert rep["proposals"][0]["prefilled_from"]["incident"] == rep1["incident_id"]
    assert rep["proposals"][0]["action"]["params"]["rule"]["original_rule_id"] == "sgr-a"


# -- S5 ------------------------------------------------------------------------

def test_s5_two_faults_reported_honestly(g):
    _, rep = investigate(g, "s5")
    assert {r["rid"] for r in rep["scorecard"][:2]} == {"sg-db", "svc:payments"}
    assert rep["multiple_causes"]
    assert "Multiple likely causes" in rep["explanation"]
    kinds = {p["action"]["kind"] for p in rep["proposals"] if p["action"]}
    assert kinds == {"restore_firewall_rule", "restart_service"}


# -- alert ingestion -------------------------------------------------------------

def test_alert_timestamps():
    assert alert_ingest.to_epoch("0001-01-01T00:00:00Z") == 0
    assert alert_ingest.to_epoch("2026-10-16T18:00:00.123456789Z") == 1792173600
    assert alert_ingest.to_epoch("2026-10-16T23:30:00+05:30") == 1792173600


def test_grouping_attaches_then_resolved_opens_nothing(g):
    sc = Scenario(g, "s3", NOW)
    first = alert_ingest.ingest(g, sc.payload("firing"), now=NOW)
    later = Scenario(g, "s2", NOW + 120)
    later.group_key = sc.group_key
    second = alert_ingest.ingest(g, later.payload("firing"), now=NOW + 120)
    assert second["incident_id"] == first["incident_id"] and not second["opened"]
    _, alerts = db.run(g, "q13_incident_alerts", {"id": first["incident_id"]})
    assert len(alerts) == 7
    resolved = alert_ingest.ingest(g, sc.payload("resolved"), now=NOW + 200)
    assert resolved["incident_id"] is None and resolved["firing"] == 0


def test_unknown_rid_is_reported(g):
    payload = {"groupKey": "x", "status": "firing", "alerts": [
        {"status": "firing", "labels": {"alertname": "ServiceDown", "rid": "svc:ghost"},
         "startsAt": "2026-10-16T18:00:00Z", "endsAt": "0001-01-01T00:00:00Z", "fingerprint": "f1"}]}
    assert alert_ingest.ingest(g, payload, now=NOW)["unlinked_rids"] == ["svc:ghost"]


def test_finding_validator_rejects_unknown_resources(g):
    with pytest.raises(memory.InvalidFinding):
        memory.validate_text(Tools(g), "sg-nonexistent blocked svc:payments")
    assert memory.validate_text(Tools(g), "sg-db blocked svc:payments") == ["sg-db", "svc:payments"]


def test_repeated_notifications_never_open_a_second_incident(g):
    sc = Scenario(g, "s1", NOW)
    first = alert_ingest.ingest(g, sc.payload("firing"), now=NOW)
    assert first["opened"] and first["new_firing"] == 4
    again = alert_ingest.ingest(g, sc.payload("firing"), now=NOW + 20)        # Alertmanager repeats the group
    assert again["incident_id"] == first["incident_id"] and not again["opened"] and again["new_firing"] == 0
    g.query("MATCH (i:Incident {id: $id}) SET i.status = 'failed'", {"id": first["incident_id"]})
    late = alert_ingest.ingest(g, sc.payload("firing"), now=NOW + 400)        # incident failed, same alerts still firing
    assert late["incident_id"] == first["incident_id"] and not late["opened"]
