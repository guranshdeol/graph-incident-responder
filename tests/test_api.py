"""API end to end on ops_test: inject -> investigate -> approve -> verify -> memory, webhook auth.

Run: set -a; . ./.env; set +a; FALKORDB_HOST=localhost uv run pytest
"""

import importlib

import pytest
from fastapi.testclient import TestClient

from agent.sandbox import Scenario
from graph import db

TOKEN = "test-webhook-token"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("WEBHOOK_TOKEN", TOKEN)
    monkeypatch.setenv("GRAPH_NAME", "ops_test")
    monkeypatch.setenv("SANDBOX_MODE", "true")
    monkeypatch.setenv("HOOKS_DIR", str(tmp_path))
    monkeypatch.delenv("PROMETHEUS_URL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("INJECT_MIN_INTERVAL", "0")
    import api.app as app_mod
    app_mod = importlib.reload(app_mod)
    # each API call happens at a distinct, later second, like a human clicking through
    clock = iter(range(1792300000, 1792400000, 100))
    monkeypatch.setattr(app_mod, "now", lambda: next(clock))
    g = db.graph("ops_test")
    db.load_fixture(g)
    yield TestClient(app_mod.app)
    g.delete()


def test_ui_and_health(client):
    assert client.get("/healthz").json()["falkordb"] is True
    r = client.get("/")
    assert r.status_code == 200 and "cytoscape" in r.text
    graph = client.get("/api/graph").json()
    assert len(graph["nodes"]) == 17 and any(e["type"] == "ALLOWS_FROM" for e in graph["edges"])


def test_s1_inject_approve_resolves(client):
    r = client.post("/api/scenarios/s1/inject").json()
    assert r["investigating"] is True
    inc = client.get(f"/api/incidents/{r['incident_id']}").json()  # TestClient ran the background task
    assert inc["report"]["top"] == "sg-db"
    assert inc["status"] == "open" and inc["report"]["scenario"]["name"] == "s1"
    action_id = inc["report"]["proposals"][0]["action"]["id"]
    out = client.post(f"/api/actions/{action_id}/approve", json={"actor": "judge"}).json()
    assert out["verify"]["verified"] is True and out["action"]["status"] == "verified"
    assert out["action"]["approved_by"] == "judge"
    inc = client.get(f"/api/incidents/{r['incident_id']}").json()
    assert inc["status"] == "resolved" and inc["ttr_seconds"] is not None
    listed = client.get("/api/incidents").json()
    assert listed[0]["id"] == r["incident_id"] and listed[0]["top"] == "sg-db"
    # approving twice is refused
    assert client.post(f"/api/actions/{action_id}/approve", json={}).status_code == 409


def test_s4_after_s1_recalls_memory(client):
    s1 = client.post("/api/scenarios/s1/inject").json()
    aid = client.get(f"/api/incidents/{s1['incident_id']}").json()["report"]["proposals"][0]["action"]["id"]
    client.post(f"/api/actions/{aid}/approve", json={"actor": "judge"})
    s4 = client.post("/api/scenarios/s4/inject").json()
    rep = client.get(f"/api/incidents/{s4['incident_id']}").json()["report"]
    assert rep["top"] == "sg-db" and rep["recalled"][0]["root_cause"] == "sg-db"
    assert rep["proposals"][0]["prefilled_from"]["incident"] == s1["incident_id"]


def test_s5_waits_for_both_fixes(client):
    r = client.post("/api/scenarios/s5/inject").json()
    rep = client.get(f"/api/incidents/{r['incident_id']}").json()["report"]
    ids = [p["action"]["id"] for p in rep["proposals"]]
    assert len(ids) == 2
    first = client.post(f"/api/actions/{ids[0]}/approve", json={"actor": "judge"}).json()
    assert first["verify"]["verified"] is None and "waiting" in first["verify"]["detail"]
    second = client.post(f"/api/actions/{ids[1]}/approve", json={"actor": "judge"}).json()
    assert second["verify"]["verified"] is True
    inc = client.get(f"/api/incidents/{r['incident_id']}").json()
    assert inc["status"] == "resolved" and {a["status"] for a in inc["actions"]} == {"verified"}


def test_reject(client):
    r = client.post("/api/scenarios/s3/inject").json()
    aid = client.get(f"/api/incidents/{r['incident_id']}").json()["report"]["proposals"][0]["action"]["id"]
    assert client.post(f"/api/actions/{aid}/reject", json={"actor": "judge"}).json()["action"]["status"] == "rejected"
    assert client.post(f"/api/actions/{aid}/approve", json={}).status_code == 409


def test_webhook_auth_and_investigation(client, tmp_path):
    payload = Scenario(db.graph("ops_test"), "s3", 1792200000).payload("firing")
    assert client.post("/hooks/alertmanager", json=payload).status_code == 401
    assert client.post("/hooks/alertmanager", json=payload,
                       headers={"Authorization": "Bearer nope"}).status_code == 401
    r = client.post("/hooks/alertmanager", json=payload, headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert r["opened"] and r["firing"] == 3 and (tmp_path / r["saved"]).exists()
    # background investigation has run (TestClient runs background tasks before returning)
    rep = client.get(f"/api/incidents/{r['incident_id']}").json()["report"]
    assert rep is not None and "scenario" not in rep
    assert all(row["probe"] == "unknown" for row in rep["scorecard"])  # no Prometheus wired yet


def test_unknown_things_404(client):
    assert client.get("/api/incidents/INC-nope").status_code == 404
    assert client.post("/api/scenarios/s9/inject").status_code == 404
    assert client.post("/api/actions/ACT-nope/approve", json={}).status_code == 404


def test_inject_is_rate_limited(client, monkeypatch):
    import api.app as app_mod
    monkeypatch.setattr(app_mod, "INJECT_MIN_INTERVAL", 60.0)
    assert client.post("/api/scenarios/s3/inject").status_code == 200
    r = client.post("/api/scenarios/s3/inject")
    assert r.status_code == 429 and "wait" in r.json()["detail"]


def test_failed_execution_triggers_a_fresh_look(client, monkeypatch):
    """Live S6 lesson: if the executor is refused (IAM), the action is 'failed', the API says 502, and the
    incident is investigated again so a new proposal appears; the failed action does not block that."""
    import types

    import api.app as app_mod
    from agent import actions
    r = client.post("/api/scenarios/s1/inject").json()
    action_id = client.get(f"/api/incidents/{r['incident_id']}").json()["report"]["proposals"][0]["action"]["id"]
    def refused(self, g, action):
        raise RuntimeError("UnauthorizedOperation")
    monkeypatch.setattr(actions.SandboxExecutor, "run", refused)
    looked, investigated = [], []
    class NowThread:
        def __init__(self, target, args, daemon):
            self.go = lambda: target(*args)
        def start(self):
            self.go()
    monkeypatch.setattr(app_mod, "threading", types.SimpleNamespace(Thread=NowThread))
    monkeypatch.setattr(app_mod, "_investigate", lambda inc, *a, **k: investigated.append(inc))
    real_bg = app_mod._investigate_bg
    monkeypatch.setattr(app_mod, "_investigate_bg", lambda inc: (looked.append(inc), real_bg(inc)))
    assert client.post(f"/api/actions/{action_id}/approve", json={}).status_code == 502
    assert looked == investigated == [r["incident_id"]]
    assert client.get(f"/api/incidents/{r['incident_id']}").json()["actions"][0]["status"] == "failed"
