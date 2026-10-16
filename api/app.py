"""rootgraph API + UI.

  GET  /                              incident UI (api/static/index.html)
  GET  /healthz                       liveness + FalkorDB reachability
  POST /hooks/alertmanager            bearer WEBHOOK_TOKEN; saves the raw payload, ingests it
                                      into the graph and investigates newly opened incidents
  GET  /api/incidents                 newest incidents with their top suspect (Q19)
  GET  /api/incidents/{id}            stored report + actions (Q20)
  GET  /api/graph                     resource nodes + edges for the graph panel (Q17, Q18)
  GET  /api/scenarios                 replayable scenarios
  POST /api/scenarios/{name}/inject   sandbox: inject faults + firing alerts, investigate
  POST /api/sandbox/reset             sandbox: reload the fixture estate (wipes incidents)
  POST /api/actions/{id}/approve      the human approval gate (body: {"actor": "..."})
  POST /api/actions/{id}/reject

SANDBOX_MODE=true (public demo on ops_sandbox): sandbox controls and approval are open,
and executing an action only writes to the graph. Otherwise those endpoints need
`Authorization: Bearer $ADMIN_TOKEN`, and live executors (P2) are not wired yet.
"""

import hmac
import json
import logging
import os
import threading
import time
from pathlib import Path

from fastapi import BackgroundTasks, Body, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse

from agent import actions, memory, sandbox
from agent.investigate import Investigator
from agent.probe import FixtureProbe, PrometheusProbe
from agent.tools import Tools
from graph import db
from ingest import alerts as alert_ingest

log = logging.getLogger("rootgraph.api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

WEBHOOK_TOKEN = os.environ["WEBHOOK_TOKEN"]
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SANDBOX_MODE = os.environ.get("SANDBOX_MODE", "true").lower() == "true"
GRAPH_NAME = os.environ.get("GRAPH_NAME") or os.environ.get("GRAPH_SANDBOX", "ops_sandbox")
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "")
HOOKS_DIR = Path(os.environ.get("HOOKS_DIR", "/data/hooks"))
HOOKS_DIR.mkdir(parents=True, exist_ok=True)
STATIC = Path(__file__).resolve().parent / "static"

# One writer at a time: injections, investigations and approvals are short, and
# serialising them keeps the public sandbox consistent.
LOCK = threading.Lock()

app = FastAPI(title="rootgraph", docs_url=None, redoc_url=None, openapi_url=None)


def g():
    return db.graph(GRAPH_NAME)


def now() -> int:
    return int(time.time())


def _bearer_ok(authorization: str | None, token: str) -> bool:
    if not token or not authorization or not authorization.startswith("Bearer "):
        return False
    return hmac.compare_digest(authorization.removeprefix("Bearer ").encode(), token.encode())


def _require_operator(authorization: str | None) -> None:
    """Sandbox: open (graph-only effects). Live: admin bearer token."""
    if not SANDBOX_MODE and not _bearer_ok(authorization, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="operator token required")


def _probe_source_for(report: dict | None, after_fix: bool = False):
    scen = (report or {}).get("scenario")
    if scen:
        sc = sandbox.Scenario(g(), scen["name"], scen["now"])
        sc.probes.fixed = after_fix
        return sc.probes, sc
    if PROMETHEUS_URL:
        return PrometheusProbe(PROMETHEUS_URL), None
    return FixtureProbe({}), None  # no probes yet: every probe reports "unknown"


def _investigate(incident_id: str, probe_source, scenario: dict | None = None) -> dict:
    report = Investigator(g(), probe_source, now=lambda: now()).run(incident_id)
    if scenario:
        report["scenario"] = scenario
        db.run(g(), "w11_update_incident", {"id": incident_id, "report": json.dumps(report), "status": None})
    log.info("investigated %s: top=%s multiple=%s", incident_id, report["top"], report["multiple_causes"])
    return report


# -- health + webhook -----------------------------------------------------------

@app.get("/healthz")
def healthz():
    try:
        db.client().connection.ping()
        ok = True
    except Exception as exc:
        log.warning("falkordb ping failed: %s", exc)
        ok = False
    return {"status": "ok" if ok else "degraded", "falkordb": ok, "graph": GRAPH_NAME, "sandbox": SANDBOX_MODE}


def _investigate_bg(incident_id: str):
    with LOCK:
        try:
            _investigate(incident_id, _probe_source_for(None)[0])
        except Exception:
            log.exception("investigation of %s failed", incident_id)


@app.post("/hooks/alertmanager")
async def alertmanager_hook(request: Request, background: BackgroundTasks,
                            authorization: str | None = Header(default=None)):
    if not _bearer_ok(authorization, WEBHOOK_TOKEN):
        raise HTTPException(status_code=401, detail="missing or bad bearer token")
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="body is not JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="expected an Alertmanager webhook object")

    path = HOOKS_DIR / f"alertmanager-{time.time_ns()}.json"
    path.write_text(json.dumps(payload, indent=2))
    with LOCK:
        result = alert_ingest.ingest(g(), payload, now=now())
    if result["opened"]:
        background.add_task(_investigate_bg, result["incident_id"])
    log.info("alertmanager hook: %s saved=%s", result, path.name)
    return {**result, "saved": path.name}


# -- read API ---------------------------------------------------------------------

@app.get("/api/incidents")
def list_incidents(limit: int = 50):
    _, rows = db.run(g(), "q19_list_incidents", {"limit": max(1, min(limit, 200))})
    return rows


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    _, rows = db.run(g(), "q20_get_incident", {"id": incident_id})
    if not rows:
        raise HTTPException(status_code=404, detail="no such incident")
    row = rows[0]
    report = json.loads(row["report"]) if row["report"] else None
    return {"id": row["id"], "status": row["status"], "opened_at": row["opened_at"],
            "ttr_seconds": row["ttr_seconds"], "report": report,
            "actions": [dict(a) for a in row["actions"] if a]}


@app.get("/api/graph")
def graph_view():
    _, nodes = db.run(g(), "q17_resource_nodes")
    _, edges = db.run(g(), "q18_resource_edges")
    return {"graph": GRAPH_NAME, "nodes": nodes, "edges": edges}


@app.get("/api/scenarios")
def list_scenarios():
    out = []
    for name in sandbox.names():
        spec = sandbox.load(name)
        out.append({"name": name, "title": spec.get("title", name)})
    return {"sandbox": SANDBOX_MODE, "scenarios": out}


# -- sandbox controls ---------------------------------------------------------------

@app.post("/api/scenarios/{name}/inject")
def inject(name: str, authorization: str | None = Header(default=None)):
    _require_operator(authorization)
    if not SANDBOX_MODE:
        raise HTTPException(status_code=409, detail="scenarios only run in sandbox mode")
    if name not in sandbox.names():
        raise HTTPException(status_code=404, detail="no such scenario")
    with LOCK:
        t = now()
        sc = sandbox.Scenario(g(), name, t)
        res = sc.inject()
        if not res["incident_id"]:
            raise HTTPException(status_code=500, detail="scenario opened no incident")
        report = _investigate(res["incident_id"], sc.probes, scenario={"name": name, "now": t})
    return {"incident_id": res["incident_id"], "top": report["top"], "opened": res["opened"]}


@app.post("/api/sandbox/reset")
def reset(authorization: str | None = Header(default=None)):
    _require_operator(authorization)
    if not SANDBOX_MODE:
        raise HTTPException(status_code=409, detail="reset only in sandbox mode")
    with LOCK:
        db.load_fixture(g())
    return {"reset": GRAPH_NAME}


# -- approval gate -------------------------------------------------------------------

def _actor(body: dict | None) -> str:
    actor = str((body or {}).get("actor") or "").strip()[:64]
    return actor or "anonymous"


@app.post("/api/actions/{action_id}/approve")
def approve(action_id: str, body: dict | None = Body(default=None),
            authorization: str | None = Header(default=None)):
    """Human approval -> execute -> (sandbox: world recovers) -> verify -> memory."""
    _require_operator(authorization)
    if not SANDBOX_MODE:
        raise HTTPException(status_code=501, detail="live executors are not wired yet (P2)")
    with LOCK:
        graph, t = g(), now()
        action = actions.get(graph, action_id)
        if action is None:
            raise HTTPException(status_code=404, detail="no such action")
        if not actions.approve(graph, action_id, actor=_actor(body), now=t):
            raise HTTPException(status_code=409, detail=f"action is {action['status']}, not proposed")
        actions.execute(graph, action_id, actions.SandboxExecutor(), now=t)

        incident = get_incident(action["incident_id"])
        pending = [a for a in incident["actions"] if a["status"] in ("proposed", "approved")]
        if pending:  # multiple causes: verify once every proposed fix has run
            out = {"verified": None, "detail": f"waiting for {len(pending)} other proposed action(s)"}
            return {"action": actions.get(graph, action_id), "verify": out}

        report = incident["report"] or {}
        probes, sc = _probe_source_for(report, after_fix=True)
        if sc:
            sc.recover(now=t)
        executed = [a for a in incident["actions"] if a["status"] == "executed"]
        results = {a["id"]: actions.verify(graph, Tools(graph), probes, a["id"], now=lambda: now(), timeout=0)
                   for a in executed}
        out = results.get(action_id, {"verified": False, "detail": "not executed"})
        if executed and all(r["verified"] for r in results.values()):
            tools = Tools(graph)
            for a in executed:
                done = actions.get(graph, a["id"])
                memory.close_incident(graph, action["incident_id"], done["target_rid"], a["id"],
                                      report.get("root_change_id") if done["target_rid"] == report.get("top") else None,
                                      report.get("explanation", ""), now=t)
            try:
                memory.record_finding(graph, tools, action["incident_id"], report.get("explanation", ""),
                                      [actions.get(graph, a["id"])["target_rid"] for a in executed], now=t)
            except memory.InvalidFinding as exc:
                log.warning("finding not recorded: %s", exc)
        else:
            memory.fail_incident(graph, action["incident_id"])
    return {"action": actions.get(graph, action_id), "verify": out}


@app.post("/api/actions/{action_id}/reject")
def reject(action_id: str, body: dict | None = Body(default=None),
           authorization: str | None = Header(default=None)):
    _require_operator(authorization)
    with LOCK:
        graph = g()
        if actions.get(graph, action_id) is None:
            raise HTTPException(status_code=404, detail="no such action")
        if not actions.reject(graph, action_id, actor=_actor(body), now=now()):
            raise HTTPException(status_code=409, detail="action is not proposed")
        return {"action": actions.get(graph, action_id)}


# -- UI ----------------------------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
