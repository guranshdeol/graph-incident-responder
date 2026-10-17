"""rootgraph API + UI.

  GET  /                              incident UI (api/static/index.html)
  GET  /healthz                       liveness + FalkorDB reachability
  POST /hooks/alertmanager            bearer WEBHOOK_TOKEN; saves the raw payload, ingests it
                                      into the graph and (re)investigates the incident it opened or grew
  GET  /api/incidents                 newest incidents with their top suspect (Q19)
  GET  /api/incidents/{id}            stored report + actions (Q20)
  GET  /api/graph                     resource nodes + edges for the graph panel (Q17, Q18)
  GET  /api/scenarios                 replayable scenarios
  POST /api/scenarios/{name}/inject   sandbox: inject faults + firing alerts, investigate
  POST /api/sandbox/reset             sandbox: reload the fixture estate (wipes incidents)
  POST /api/live/break                live: revoke rule A with the revoke-only chaos IAM user (operator token)
  POST /api/actions/{id}/approve      the human approval gate (body: {"actor": "..."})
  POST /api/actions/{id}/reject

SANDBOX_MODE=true (public demo on ops_sandbox): sandbox controls and approval are open,
and executing an action only writes to the graph. Otherwise those endpoints need
`Authorization: Bearer $ADMIN_TOKEN`, approval runs agent.actions.AwsExecutor, and
each new incident gets a discovery resync before it is investigated.
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

from agent import actions, llm, memory, sandbox
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
# Investigations are slow (resync + LLM, up to minutes): their own lock, never held by the webhook,
# so "resolved" notifications are ingested immediately even while an investigation runs.
INVEST_LOCK = threading.Lock()
LIVE_VERIFY_TIMEOUT = int(os.environ.get("LIVE_VERIFY_TIMEOUT", "300"))

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


_live_clients: dict = {}


def _live(name: str):
    """Lazily built boto3 clients for live mode, each with its own principal (ingest/worker.py)."""
    if name not in _live_clients:
        from ingest.worker import session  # boto3 only needed in live mode
        prefix, service = {"executor_ec2": ("EXECUTOR", "ec2"), "executor_ssm": ("EXECUTOR", "ssm"), "executor_rds": ("EXECUTOR", "rds"),
                           "discovery_ec2": ("DISCOVERY", "ec2"), "discovery_rds": ("DISCOVERY", "rds")}[name]
        _live_clients[name] = session(prefix).client(service)
    return _live_clients[name]


def _resync_live() -> None:
    """§7.3 step 1: re-discover before investigating so the graph-diff Change is there even if CloudTrail lags."""
    if SANDBOX_MODE:
        return
    from ingest import discovery_aws
    try:
        out = discovery_aws.resync(g(), _live("discovery_ec2"), _live("discovery_rds"))
        log.info("resync: %d changes %s", len(out["changes"]), out["changes"])
    except Exception:
        log.exception("resync before investigation failed; investigating the graph as it is")


def _investigate(incident_id: str, probe_source, scenario: dict | None = None) -> dict:
    _resync_live()
    client = llm.client_from_env()
    agent = llm.Agent(client, Tools(g()), probe_source, now=lambda: now()) if client else None
    report = Investigator(g(), probe_source, now=lambda: now(), explain=agent).run(incident_id)
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
    with INVEST_LOCK:
        try:
            acts = get_incident(incident_id)["actions"]
            if any(a["status"] != "proposed" for a in acts):   # a human already acted: keep the report that led to it
                log.info("not re-investigating %s: an action is already %s", incident_id, [a["status"] for a in acts])
                return
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
    result = alert_ingest.ingest(g(), payload, now=now())     # never waits on an investigation
    # Alertmanager delivers a group in batches: investigate when an incident opens and again
    # whenever NEW firing alerts join it, so the report always covers the whole group.
    if result["incident_id"] and (result["opened"] or result["new_firing"]):
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

_inject_state = {"busy": False, "last": 0.0}
INJECT_MIN_INTERVAL = float(os.environ.get("INJECT_MIN_INTERVAL", "15"))


def _investigate_scenario_bg(incident_id: str, name: str, t: int):
    try:
        with LOCK:
            sc = sandbox.Scenario(g(), name, t)
            _investigate(incident_id, sc.probes, scenario={"name": name, "now": t})
    except Exception:
        log.exception("investigation of %s failed", incident_id)
    finally:
        _inject_state["busy"] = False


@app.post("/api/scenarios/{name}/inject")
def inject(name: str, background: BackgroundTasks, authorization: str | None = Header(default=None)):
    """Faults + firing alerts go in now; the investigation (and LLM step) runs in the background.
    The UI polls the incident until its report appears. One injection at a time, at most one per
    INJECT_MIN_INTERVAL seconds, so the public sandbox can't be used to burn LLM quota."""
    _require_operator(authorization)
    if not SANDBOX_MODE:
        raise HTTPException(status_code=409, detail="scenarios only run in sandbox mode")
    if name not in sandbox.names():
        raise HTTPException(status_code=404, detail="no such scenario")
    wait = INJECT_MIN_INTERVAL - (time.time() - _inject_state["last"])
    if _inject_state["busy"] or wait > 0:
        raise HTTPException(status_code=429, detail="An investigation is running or just ran; try again in a few seconds."
                            if _inject_state["busy"] else f"Please wait {int(wait) + 1}s before the next scenario.")
    with LOCK:
        _inject_state.update(busy=True, last=time.time())
        try:
            t = now()
            res = sandbox.Scenario(g(), name, t).inject()
            if not res["incident_id"]:
                raise HTTPException(status_code=500, detail="scenario opened no incident")
        except Exception:
            _inject_state["busy"] = False
            raise
    background.add_task(_investigate_scenario_bg, res["incident_id"], name, t)
    return {"incident_id": res["incident_id"], "opened": res["opened"], "investigating": True}


_break_state = {"last": 0.0}


@app.post("/api/live/break")
def live_break(authorization: str | None = Header(default=None)):
    """Live only: play the human who makes the bad change. Revokes rule A (host-1 → orders-db:5432) with the
    revoke-only 'rootgraph-chaos' IAM user. rootgraph then has to find it; a person approves the fix."""
    _require_operator(authorization)
    if SANDBOX_MODE:
        raise HTTPException(status_code=409, detail="the break button is only for the live estate")
    if any(r["status"] == "open" for r in list_incidents(20)):
        raise HTTPException(status_code=409, detail="an incident is still open; approve or wait for it first")
    if time.time() - _break_state["last"] < 300:
        raise HTTPException(status_code=429, detail="one real fault every 5 minutes")
    import boto3
    from ingest.worker import REGION
    sg_db, sg_h1 = os.environ.get("SG_DB"), os.environ.get("SG_HOST1")
    key, secret = os.environ.get("CHAOS_AWS_ACCESS_KEY_ID"), os.environ.get("CHAOS_AWS_SECRET_ACCESS_KEY")
    if not (sg_db and sg_h1 and key and secret):
        raise HTTPException(status_code=501, detail="chaos credentials not configured")
    ec2 = boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret, region_name=REGION).client("ec2")
    rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [sg_db]}])["SecurityGroupRules"]
    rule_a = next((r for r in rules if not r["IsEgress"] and r.get("FromPort") == 5432
                   and (r.get("ReferencedGroupInfo") or {}).get("GroupId") == sg_h1), None)
    if rule_a is None:
        raise HTTPException(status_code=409, detail="rule A is already removed")
    ec2.revoke_security_group_ingress(GroupId=sg_db, SecurityGroupRuleIds=[rule_a["SecurityGroupRuleId"]])
    _break_state["last"] = time.time()
    log.info("live break: revoked %s on %s", rule_a["SecurityGroupRuleId"], sg_db)
    return {"revoked": rule_a["SecurityGroupRuleId"], "group": sg_db, "at": now(),
            "next": "real alerts arrive in ~30-40 s; the incident appears in the list"}


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


def _finish(graph, action: dict, t: int, verify_timeout: int, sleep=time.sleep) -> dict:
    """After execution: once every proposed fix ran, verify them all, then write memory or fail."""
    incident = get_incident(action["incident_id"])
    pending = [a for a in incident["actions"] if a["status"] in ("proposed", "approved")]
    if pending:  # multiple causes: verify once every proposed fix has run
        return {"verified": None, "detail": f"waiting for {len(pending)} other proposed action(s)"}

    report = incident["report"] or {}
    probes, sc = _probe_source_for(report, after_fix=True)
    if sc:
        sc.recover(now=t)
    executed = [a for a in incident["actions"] if a["status"] == "executed"]
    results = {a["id"]: actions.verify(graph, Tools(graph), probes, a["id"], now=lambda: now(),
                                       timeout=verify_timeout, sleep=sleep) for a in executed}
    out = results.get(action["id"], {"verified": False, "detail": "not executed"})
    if executed and all(r["verified"] for r in results.values()):
        tools = Tools(graph)
        for a in executed:
            done = actions.get(graph, a["id"])
            memory.close_incident(graph, action["incident_id"], done["target_rid"], a["id"],
                                  report.get("root_change_id") if done["target_rid"] == report.get("top") else None,
                                  report.get("explanation", ""), now=now())
        try:
            memory.record_finding(graph, tools, action["incident_id"], report.get("explanation", ""),
                                  [actions.get(graph, a["id"])["target_rid"] for a in executed], now=now())
        except memory.InvalidFinding as exc:
            log.warning("finding not recorded: %s", exc)
    else:
        memory.fail_incident(graph, action["incident_id"])
    return out


def _finish_live_bg(action: dict, t: int):
    """Live: real alerts take minutes to resolve (rate windows, Alertmanager group interval), so verification
    polls every 5 s for up to LIVE_VERIFY_TIMEOUT (300 s) off the request."""
    graph = g()
    try:
        out = _finish(graph, action, t, verify_timeout=LIVE_VERIFY_TIMEOUT)
        log.info("verification of %s: %s", action["id"], out)
    except Exception:
        log.exception("verification of %s failed", action["id"])


@app.post("/api/actions/{action_id}/approve")
def approve(action_id: str, background: BackgroundTasks, body: dict | None = Body(default=None),
            authorization: str | None = Header(default=None)):
    """The human approval gate -> execute -> verify -> memory."""
    _require_operator(authorization)
    with LOCK:
        graph, t = g(), now()
        action = actions.get(graph, action_id)
        if action is None:
            raise HTTPException(status_code=404, detail="no such action")
        if not actions.approve(graph, action_id, actor=_actor(body), now=t):
            raise HTTPException(status_code=409, detail=f"action is {action['status']}, not proposed")
        executor = (actions.SandboxExecutor() if SANDBOX_MODE
                    else actions.AwsExecutor(_live("executor_ec2"), _live("executor_ssm"), _live("executor_rds")))
        try:
            actions.execute(graph, action_id, executor, now=t)
        except Exception as exc:
            log.exception("execution of %s failed", action_id)
            raise HTTPException(status_code=502, detail=f"execution failed: {exc}")
        if SANDBOX_MODE:
            out = _finish(graph, action, t, verify_timeout=0)
        else:
            background.add_task(_finish_live_bg, action, t)
            out = {"verified": None, "detail": f"executed; verifying in the background (up to {LIVE_VERIFY_TIMEOUT}s)"}
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
