"""Every §8 query, through the agent tools, against the §9 estate fixture in ops_test.

Run on the host:
    set -a; . ./.env; set +a; FALKORDB_HOST=localhost uv run pytest
"""

import pytest

from agent.tools import Tools
from graph import db

GRAPH = "ops_test"
T0 = 1792100000  # fixture last_seen
ENVELOPE_KEYS = {"tool", "args", "outcome", "rows", "paths", "cypher", "ms"}

S1_ALERTS = ["svc:web", "svc:checkout", "svc:payments", "i-host1"]
S2_ALERTS = ["svc:orders", "svc:reports", "svc:web", "i-host2"]


@pytest.fixture(scope="session")
def g():
    graph = db.graph(GRAPH)
    db.load_fixture(graph)
    yield graph
    graph.delete()


@pytest.fixture(scope="session")
def tools(g):
    return Tools(g)


@pytest.fixture
def mutable(g, tools):
    """For tests that write: reload the clean fixture afterwards."""
    yield tools
    db.load_fixture(g)


def assert_envelope(env, tool, outcome):
    assert set(env) == ENVELOPE_KEYS
    assert env["tool"] == tool
    assert env["outcome"] == outcome, env
    assert isinstance(env["ms"], int)
    if outcome == "unknown_resource" and tool != "resolve":  # resolve's own query is Q1
        assert env["cypher"] is None
    else:
        assert env["cypher"].startswith(("MATCH", "UNWIND", "CALL"))


def revoke_rule_a(g, ts):
    """Simulate a discovery resync of sg-db in which rule A has vanished: W1 for the
    rules still present, then W2 marks the missing one inactive and records a Change."""
    db.run(g, "w1_upsert_rule", {"fw": "sg-db", "src_rid": "sg-host2", "rule_id": "sgr-b", "proto": "tcp",
                                 "from_port": 5432, "to_port": 5432, "sync_ts": ts})
    _, rows = db.run(g, "w2_diff_removed_rules", {"fw": "sg-db", "sync_ts": ts})
    return rows


# -- fixture sanity -----------------------------------------------------------

def test_fixture_loaded(g):
    res = g.query("MATCH (r:Resource) RETURN count(r)").result_set
    assert res[0][0] == 17
    res = g.query("MATCH (:Firewall)-[:PROTECTS]->(d:Database {rid: 'rds:orders-db'}) RETURN count(*)").result_set
    assert res[0][0] == 2  # risk #18: two SGs on orders-db


def test_every_query_file_loads():
    names = db.query_names()
    for q in ["q1_resolve", "q2_correlate_alerts", "q3_path_between", "q4_check_path", "q5_recent_changes",
              "q6_blast_radius", "q7_recall_incidents", "q8_load_bearing", "w1_upsert_rule",
              "w1b_detect_modified_rule", "w2_diff_removed_rules", "w3_ingest_change", "w4_ingest_alert",
              "w5_open_incident", "w6_close_incident"]:
        assert q in names
        assert "//" not in db.query(q)


# -- resolve ------------------------------------------------------------------

def test_resolve_by_rid_and_name(tools):
    env = tools.resolve("rds:orders-db")
    assert_envelope(env, "resolve", "answered_with_path")
    assert env["rows"] == [{"rid": "rds:orders-db", "kinds": ["Resource", "Database"]}]
    assert tools.resolve("host-1")["rows"][0]["rid"] == "i-host1"


def test_resolve_unknown(tools):
    env = tools.resolve("nope-db")
    assert_envelope(env, "resolve", "unknown_resource")
    assert env["rows"] == [{"unknown": "nope-db"}]


# -- correlate_alerts -----------------------------------------------------------

def test_correlate_s1_host1_tops_coverage(tools):
    env = tools.correlate_alerts(S1_ALERTS, k=5)
    assert_envelope(env, "correlate_alerts", "answered_with_path")
    top = env["rows"][0]
    assert top["candidate"] == "i-host1" and top["coverage"] == 4
    by = {r["candidate"]: r for r in env["rows"]}
    assert by["rds:orders-db"]["coverage"] == 3 and by["rds:orders-db"]["min_hops"] == 1
    assert len(env["rows"]) == 5


def test_correlate_s2_shared_host(tools):
    env = tools.correlate_alerts(S2_ALERTS, k=3)
    top = env["rows"][0]
    assert top["candidate"] == "i-host2" and top["coverage"] == 4
    assert sorted(top["explains"]) == sorted(S2_ALERTS)


def test_correlate_accepts_names(tools):
    env = tools.correlate_alerts(["payments", "orders"], k=1)
    assert env["rows"][0]["candidate"] == "rds:orders-db"


def test_correlate_unknown_runs_no_query(tools):
    env = tools.correlate_alerts(["svc:web", "svc:ghost"])
    assert_envelope(env, "correlate_alerts", "unknown_resource")
    assert env["rows"] == [{"unknown": "svc:ghost"}]


# -- check_path -----------------------------------------------------------------

def test_check_path_permitted(tools):
    env = tools.check_path("svc:payments", "rds:orders-db")
    assert_envelope(env, "check_path", "answered_with_path")
    [row] = env["rows"]
    assert row["permitted"] is True and row["host"] == "i-host1" and row["port"] == 5432
    per_fw = {f["firewall"]: f["rules"] for f in row["per_firewall"]}
    assert per_fw == {"sg-db": ["sgr-a"], "sg-db-admin": []}
    assert ["svc:payments", "i-host1", "sg-db"] in env["paths"]


def test_check_path_broken_after_rule_a_removed(g, mutable):
    removed = revoke_rule_a(g, T0 + 600)
    assert removed == [{"r.rule_id": "sgr-a", "src.rid": "sg-host1"}]

    env = mutable.check_path("svc:payments", "rds:orders-db")
    assert_envelope(env, "check_path", "answered_with_path")
    [row] = env["rows"]
    # sg-db-admin still allows 5432, but only from the admin CIDR: must not count.
    assert row["permitted"] is False
    assert {f["firewall"]: f["rules"] for f in row["per_firewall"]} == {"sg-db": [], "sg-db-admin": []}

    # sibling evidence: host-2 still reaches the DB through rule B
    sib = mutable.check_path("svc:orders", "rds:orders-db")["rows"][0]
    assert sib["permitted"] is True
    assert {f["firewall"]: f["rules"] for f in sib["per_firewall"]}["sg-db"] == ["sgr-b"]

    # the retired edge is kept as history, not deleted
    res = g.query("MATCH (:Firewall {rid:'sg-db'})-[r:ALLOWS_FROM {rule_id:'sgr-a'}]->() "
                  "RETURN r.active, r.removed_at").result_set
    assert res == [[False, T0 + 600]]


def test_check_path_restored_by_w1(g, mutable):
    revoke_rule_a(g, T0 + 600)
    db.run(g, "w1_upsert_rule", {"fw": "sg-db", "src_rid": "sg-host1", "rule_id": "sgr-a", "proto": "tcp",
                                 "from_port": 5432, "to_port": 5432, "sync_ts": T0 + 900})
    assert mutable.check_path("svc:payments", "rds:orders-db")["rows"][0]["permitted"] is True
    res = g.query("MATCH ()-[r:ALLOWS_FROM {rule_id:'sgr-a'}]->() RETURN r.active, r.removed_at").result_set
    assert res == [[True, None]]


def test_check_path_not_in_graph_when_no_firewall_modelled(tools):
    # services are not protected by SGs directly; Q4 returns no rows
    env = tools.check_path("svc:web", "svc:checkout")
    assert_envelope(env, "check_path", "not_in_graph")
    assert env["rows"] == [] and env["paths"] == []


def test_check_path_unknown(tools):
    env = tools.check_path("svc:payments", "rds:ghost-db")
    assert_envelope(env, "check_path", "unknown_resource")
    assert env["rows"] == [{"unknown": "rds:ghost-db"}]


# -- W1b: rule modified in place ---------------------------------------------------

def test_w1b_unchanged_rule_is_noop(g, mutable):
    _, rows = db.run(g, "w1b_detect_modified_rule",
                     {"fw": "sg-db", "src_rid": "sg-host1", "rule_id": "sgr-a", "proto": "tcp",
                      "from_port": 5432, "to_port": 5432, "sync_ts": T0 + 60})
    assert rows == []
    assert g.query("MATCH (c:Change) RETURN count(c)").result_set[0][0] == 0


def test_w1b_port_change_retires_old_edge_and_breaks_path(g, mutable):
    ts = T0 + 1200
    new = {"fw": "sg-db", "src_rid": "sg-host1", "rule_id": "sgr-a", "proto": "tcp",
           "from_port": 6432, "to_port": 6432, "sync_ts": ts}
    _, rows = db.run(g, "w1b_detect_modified_rule", new)
    assert rows == [{"r.rule_id": f"sgr-a@{ts}"}]
    db.run(g, "w1_upsert_rule", new)

    edges = g.query("MATCH (:Firewall {rid:'sg-db'})-[r:ALLOWS_FROM]->(s:Firewall {rid:'sg-host1'}) "
                    "RETURN r.rule_id, r.active, r.port_from, r.removed_at, r.original_rule_id "
                    "ORDER BY r.rule_id").result_set
    assert edges == [["sgr-a", True, 6432, None, None],
                     [f"sgr-a@{ts}", False, 5432, ts, "sgr-a"]]

    ch = g.query("MATCH (c:Change {event_name:'SecurityGroupRuleModified'})-[:MODIFIED]->(f) "
                 "RETURN c.event_id, c.before, c.after, f.rid").result_set
    assert ch == [[f"diff:mod:sgr-a:{ts}", "tcp 5432-5432 from sg-host1", "tcp 6432-6432 from sg-host1", "sg-db"]]

    # 6432 no longer covers the 5432 dependency
    assert mutable.check_path("svc:payments", "rds:orders-db")["rows"][0]["permitted"] is False

    # re-running the same sync is a no-op
    _, rows = db.run(g, "w1b_detect_modified_rule", new)
    assert rows == []


def test_w1b_source_change(g, mutable):
    ts = T0 + 1300
    new = {"fw": "sg-db", "src_rid": "cidr:203.0.113.0/24", "rule_id": "sgr-a", "proto": "tcp",
           "from_port": 5432, "to_port": 5432, "sync_ts": ts}
    _, rows = db.run(g, "w1b_detect_modified_rule", new)
    assert rows == [{"r.rule_id": f"sgr-a@{ts}"}]
    db.run(g, "w1_upsert_rule", new)
    res = g.query("MATCH (:Firewall {rid:'sg-db'})-[r:ALLOWS_FROM]->(s) WHERE r.rule_id STARTS WITH 'sgr-a' "
                  "RETURN r.rule_id, r.active, s.rid ORDER BY r.rule_id").result_set
    assert res == [["sgr-a", True, "cidr:203.0.113.0/24"], [f"sgr-a@{ts}", False, "sg-host1"]]
    assert mutable.check_path("svc:payments", "rds:orders-db")["rows"][0]["permitted"] is False


# -- recent_changes -------------------------------------------------------------

def test_recent_changes_after_revoke(g, mutable):
    revoke_rule_a(g, T0 + 600)
    db.run(g, "w3_ingest_change", {"event_id": "ct-0001", "event_name": "RevokeSecurityGroupIngress",
                                   "actor": "arn:aws:iam::000000000000:user/demo-human", "at": T0 + 630,
                                   "by_agent": False, "request_json": '{"groupId":"sg-db"}', "rids": ["sg-db"]})

    env = mutable.recent_changes("sg-db", minutes=30, now=T0 + 700)
    assert_envelope(env, "recent_changes", "answered_with_path")
    assert [r["ch.event_name"] for r in env["rows"]] == ["RevokeSecurityGroupIngress", "SecurityGroupRuleRemoved"]
    assert env["rows"][0]["ch.actor"].endswith("user/demo-human")
    assert {r["on_resource"] for r in env["rows"]} == {"sg-db"}

    # 2-hop neighbourhood: payments -DEPENDS_ON-> orders-db <-PROTECTS- sg-db
    near = mutable.recent_changes("svc:payments", minutes=30, now=T0 + 700)
    assert len(near["rows"]) == 2

    # outside the window
    old = mutable.recent_changes("sg-db", minutes=1, now=T0 + 3600)
    assert_envelope(old, "recent_changes", "not_in_graph")


def test_recent_changes_none(tools):
    assert_envelope(tools.recent_changes("sg-db", now=T0), "recent_changes", "not_in_graph")


def test_recent_changes_unknown(tools):
    assert_envelope(tools.recent_changes("sg-ghost"), "recent_changes", "unknown_resource")


# -- blast_radius ---------------------------------------------------------------

def test_blast_radius_depth(tools):
    env = tools.blast_radius("rds:orders-db", depth=1)
    assert_envelope(env, "blast_radius", "answered_with_path")
    assert [r["affected"] for r in env["rows"]] == ["svc:orders", "svc:payments", "svc:reports"]
    assert all(r["hops"] == 1 for r in env["rows"])

    env = tools.blast_radius("orders-db", depth=2)
    assert {r["affected"]: r["hops"] for r in env["rows"]} == {
        "svc:orders": 1, "svc:payments": 1, "svc:reports": 1, "svc:checkout": 2, "svc:web": 2}
    assert ["svc:checkout", "svc:payments", "rds:orders-db"] in env["paths"]


def test_blast_radius_host(tools):
    env = tools.blast_radius("i-host1", depth=1)
    assert [r["affected"] for r in env["rows"]] == ["svc:checkout", "svc:payments", "svc:web"]


def test_blast_radius_depth_clamped(tools):
    env = tools.blast_radius("rds:orders-db", depth=99)
    assert {r["affected"] for r in env["rows"]} == {
        "svc:orders", "svc:payments", "svc:reports", "svc:checkout", "svc:web"}


def test_blast_radius_leaf_and_unknown(tools):
    assert_envelope(tools.blast_radius("svc:web"), "blast_radius", "not_in_graph")
    assert_envelope(tools.blast_radius("svc:ghost"), "blast_radius", "unknown_resource")


# -- path_between ---------------------------------------------------------------

def test_path_between(tools):
    env = tools.path_between("svc:checkout", "rds:orders-db")
    assert_envelope(env, "path_between", "answered_with_path")
    assert env["paths"] == [["svc:checkout", "svc:payments", "rds:orders-db"]]
    assert env["rows"][0]["pathWeight"] == 2

    env = tools.path_between("svc:web", "i-host2")
    assert env["paths"] == [["svc:web", "svc:orders", "i-host2"]]


def test_path_between_directed_and_unknown(tools):
    assert_envelope(tools.path_between("rds:orders-db", "svc:web"), "path_between", "not_in_graph")
    assert_envelope(tools.path_between("svc:web", "svc:ghost"), "path_between", "unknown_resource")


# -- recall_incidents (W4, W5, W6 write the memory it reads) ------------------------

def _remember_s1(g):
    revoke_rule_a(g, T0 + 600)
    db.run(g, "w3_ingest_change", {"event_id": "ct-0001", "event_name": "RevokeSecurityGroupIngress",
                                   "actor": "arn:aws:iam::000000000000:user/demo-human", "at": T0 + 630,
                                   "by_agent": False, "request_json": "{}", "rids": ["sg-db"]})
    alerts = [("fp-err-pay", "HighErrorRate", "svc:payments"),
              ("fp-dep-h1", "DependencyUnreachable", "i-host1")]
    for fp, name, rid in alerts:
        db.run(g, "w4_ingest_alert", {"id": f"{fp}:{T0 + 610}", "fp": fp, "alertname": name, "status": "firing",
                                      "severity": "page", "starts_at": T0 + 610, "ends_at": None, "rid": rid})
    db.run(g, "w5_open_incident", {"id": "INC-1", "group_key": "{}:{env=\"demo\"}", "now": T0 + 620,
                                   "alert_ids": [f"{fp}:{T0 + 610}" for fp, _, _ in alerts]})
    # Action creation belongs to propose_action (not in this task); seed one directly.
    g.query("CREATE (:Action {id: 'ACT-1', kind: 'restore_firewall_rule', status: 'verified', "
            "params: '{\"rule_id\":\"sgr-a\"}'})")
    db.run(g, "w6_close_incident", {"id": "INC-1", "root_rid": "sg-db", "action_id": "ACT-1",
                                    "now": T0 + 920, "summary": "rule A revoked on sg-db", "change_id": "ct-0001"})


def test_recall_empty_memory(tools):
    env = tools.recall_incidents(["HighErrorRate"], ["sg-db"])
    assert_envelope(env, "recall_incidents", "not_in_graph")


def test_recall_after_resolved_incident(g, mutable):
    _remember_s1(g)
    assert g.query("MATCH (:Incident {id:'INC-1'})-[:HAS_ALERT]->(a) RETURN count(a)").result_set[0][0] == 2

    env = mutable.recall_incidents(["HighErrorRate", "DependencyUnreachable"], ["i-host1", "sg-db"])
    assert_envelope(env, "recall_incidents", "answered_from_memory")
    [row] = env["rows"]
    assert row["i.id"] == "INC-1" and row["root_cause"] == "sg-db"
    assert row["i.ttr_seconds"] == 300
    assert row["change"] == "RevokeSecurityGroupIngress"
    assert row["fix"] == "restore_firewall_rule" and "sgr-a" in row["fix_params"]
    assert row["alert_overlap"] == 2 and row["same_cause"] == 1

    # cue by alert name only
    env = mutable.recall_incidents(["HighErrorRate"], ["i-host2"])
    assert env["rows"][0]["same_cause"] == 0 and env["rows"][0]["alert_overlap"] == 1

    # no overlapping cue
    assert_envelope(mutable.recall_incidents(["HostCpuSaturated"], ["i-host2"]),
                    "recall_incidents", "not_in_graph")


def test_w6_without_change(g, mutable):
    db.run(g, "w5_open_incident", {"id": "INC-2", "group_key": "k", "now": T0, "alert_ids": []})
    g.query("CREATE (:Action {id: 'ACT-2', kind: 'restart_service', status: 'verified'})")
    db.run(g, "w6_close_incident", {"id": "INC-2", "root_rid": "svc:payments", "action_id": "ACT-2",
                                    "now": T0 + 60, "summary": "payments stopped", "change_id": "missing"})
    res = g.query("MATCH (i:Incident {id:'INC-2'}) OPTIONAL MATCH (i)-[:EXPLAINED_BY]->(c) "
                  "RETURN i.status, i.ttr_seconds, count(c)").result_set
    assert res == [["resolved", 60, 0]]


def test_recall_unknown(tools):
    assert_envelope(tools.recall_incidents(["HighErrorRate"], ["sg-ghost"]), "recall_incidents", "unknown_resource")


# -- load_bearing ---------------------------------------------------------------

def test_load_bearing(tools):
    env = tools.load_bearing(limit=3)
    assert_envelope(env, "load_bearing", "answered_with_path")
    assert len(env["rows"]) == 3
    assert env["rows"][0]["resource"] == "rds:orders-db"
    scores = [r["score"] for r in env["rows"]]
    assert scores == sorted(scores, reverse=True)
