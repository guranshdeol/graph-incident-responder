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

  POST /auth/login | /auth/logout, GET /auth/me    console sign-in (api/auth.py)
  GET  /api/env | /api/overview | /api/actions | /api/memory | /api/resources/{rid} | /api/integrations
                                      console pages

Every /api/* call needs a signed-in user (session cookie) or `Authorization: Bearer $ADMIN_TOKEN`;
anything that changes state needs the operator role. SANDBOX_MODE=true is the Staging
environment (ops_sandbox): executing an action only writes to the graph. Otherwise it is
Production: approval runs agent.actions.AwsExecutor, and each new incident gets a discovery
resync before it is investigated.
"""

import hmac
import json
import logging
import os
import threading
import time
from pathlib import Path

from fastapi import BackgroundTasks, Body, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from agent import actions, llm, memory, sandbox
from api import auth
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


COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
_login_limit = auth.LoginLimiter()


def _user(request: Request) -> dict | None:
    if _bearer_ok(request.headers.get("authorization"), ADMIN_TOKEN):
        return {"name": "operator-token", "role": "operator"}
    return auth.read_session(request.cookies.get(auth.COOKIE))


@app.middleware("http")
async def require_sign_in(request: Request, call_next):
    """Sign-in for everything under /api; /healthz, /hooks (own token), /auth and the page itself stay open."""
    if request.url.path.startswith("/api/"):
        user = _user(request)
        if user is None:
            return JSONResponse({"detail": "sign in required"}, status_code=401)
        request.state.user = user
    return await call_next(request)


def _require_operator(request: Request) -> dict:
    user = getattr(request.state, "user", None) or _user(request)
    if not user or user["role"] != "operator":
        raise HTTPException(status_code=403, detail="needs the operator role")
    return user


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


# -- sign-in ---------------------------------------------------------------------

@app.post("/auth/login")
def login(request: Request, body: dict = Body(...)):
    client = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "?")).split(",")[0].strip()
    if _login_limit.blocked(client):
        raise HTTPException(status_code=429, detail="too many failed sign-ins; try again in a few minutes")
    user = auth.check_password(str(body.get("username", ""))[:64], str(body.get("password", ""))[:256])
    if user is None:
        _login_limit.failed(client)
        raise HTTPException(status_code=401, detail="wrong username or password")
    resp = JSONResponse(user)
    resp.set_cookie(auth.COOKIE, auth.make_session(user), max_age=auth.SESSION_HOURS * 3600, path="/",
                    httponly=True, secure=COOKIE_SECURE, samesite="lax")
    return resp


@app.post("/auth/logout")
def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@app.get("/auth/me")
def me(request: Request):
    user = _user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="not signed in")
    return user


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
            if any(a["status"] not in ("proposed", "failed", "rejected") for a in acts):   # a human acted and it stands
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


# -- monitoring watchdog (live) -----------------------------------------------------
# Prometheus and Alertmanager run on host-1. If that host stops, nothing can alert, so rootgraph sees
# the change but opens no incident (found on the live estate, 18 Oct). The control plane is outside the
# estate, so it watches the watcher: after MONITOR_FAILS failed readiness checks it files a synthetic
# MonitoringUnreachable alert on the Prometheus host, which opens an incident like any other alert,
# and resolves it once Prometheus answers again (that is what lets verification pass).

MONITOR_INTERVAL = int(os.environ.get("MONITOR_INTERVAL", "20"))
MONITOR_FAILS = int(os.environ.get("MONITOR_FAILS", "3"))
_watch: dict = {"fails": 0, "firing": None}


def _iso(t: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _monitor_host() -> str | None:
    from urllib.parse import urlparse
    rid = os.environ.get("PROMETHEUS_HOST_RID")
    if rid:
        return rid
    _, rows = db.run(g(), "q33_compute_by_ip", {"ip": urlparse(PROMETHEUS_URL).hostname or ""})
    return rows[0]["rid"] if rows else None


def _watchdog_alert(rid: str, status: str, starts_at: int, t: int) -> dict:
    payload = {"receiver": "rootgraph-watchdog", "status": status, "groupKey": f"rootgraph-watchdog:{rid}",
               "alerts": [{"status": status, "fingerprint": f"watchdog-{rid}",
                           "labels": {"alertname": "MonitoringUnreachable", "rid": rid, "severity": "page"},
                           "startsAt": _iso(starts_at), "endsAt": _iso(t) if status == "resolved" else "0001-01-01T00:00:00Z"}]}
    (HOOKS_DIR / f"watchdog-{time.time_ns()}.json").write_text(json.dumps(payload, indent=2))
    return alert_ingest.ingest(g(), payload, now=t)


def watchdog_tick(ready: bool | None = None, t: int | None = None) -> dict | None:
    """One readiness check. Returns the ingest result when it fired or resolved the alert."""
    ready = _prometheus_ready() if ready is None else ready
    t = now() if t is None else t
    if ready:
        _watch["fails"] = 0
        if _watch["firing"]:
            rid, starts = _watch["firing"]
            _watch["firing"] = None
            log.info("watchdog: Prometheus answers again; resolving MonitoringUnreachable on %s", rid)
            return _watchdog_alert(rid, "resolved", starts, t)
        return None
    _watch["fails"] += 1
    if _watch["fails"] < MONITOR_FAILS or _watch["firing"]:
        return None
    rid = _monitor_host()
    if not rid:
        log.warning("watchdog: Prometheus unreachable but its host is not in the graph")
        return None
    starts = t - _watch["fails"] * MONITOR_INTERVAL
    _watch["firing"] = (rid, starts)
    log.warning("watchdog: Prometheus unreachable for %d checks; MonitoringUnreachable on %s", _watch["fails"], rid)
    result = _watchdog_alert(rid, "firing", starts, t)
    if result["incident_id"] and (result["opened"] or result["new_firing"]):
        threading.Thread(target=_investigate_bg, args=(result["incident_id"],), daemon=True).start()
    return result


def _watchdog_loop():
    while True:
        time.sleep(MONITOR_INTERVAL)
        try:
            watchdog_tick()
        except Exception:
            log.exception("watchdog tick failed")


@app.on_event("startup")
def _start_watchdog():
    if not SANDBOX_MODE and PROMETHEUS_URL and MONITOR_INTERVAL > 0:
        threading.Thread(target=_watchdog_loop, daemon=True, name="watchdog").start()
        log.info("watchdog: checking %s every %ds", PROMETHEUS_URL, MONITOR_INTERVAL)


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


@app.get("/api/changes")
def changes(minutes: int = 120, limit: int = 40):
    """The 'what changed in your account' feed: CloudTrail + discovery diff, newest first."""
    env = Tools(g()).changes_since(max(1, min(minutes, 7 * 24 * 60)), limit=max(1, min(limit, 200)), now=now())
    return {"graph": GRAPH_NAME, "changes": env["rows"]}


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
def inject(name: str, background: BackgroundTasks, request: Request):
    """Faults + firing alerts go in now; the investigation (and LLM step) runs in the background.
    The UI polls the incident until its report appears. One injection at a time, at most one per
    INJECT_MIN_INTERVAL seconds, so the public sandbox can't be used to burn LLM quota."""
    user = _require_operator(request)
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
def live_break(request: Request):
    """Live only: play the human who makes the bad change. Revokes rule A (host-1 → orders-db:5432) with the
    revoke-only 'rootgraph-chaos' IAM user. rootgraph then has to find it; a person approves the fix."""
    user = _require_operator(request)
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
def reset(request: Request):
    user = _require_operator(request)
    if not SANDBOX_MODE:
        raise HTTPException(status_code=409, detail="reset only in sandbox mode")
    with LOCK:
        db.load_fixture(g())
    return {"reset": GRAPH_NAME}


# -- approval gate -------------------------------------------------------------------

def _actor(body: dict | None, user: dict | None = None) -> str:
    """The signed-in user approves; a script on the operator token may name itself."""
    if user and user["name"] != "operator-token":
        return user["name"]
    actor = str((body or {}).get("actor") or "").strip()[:64]
    return actor or "operator-token"


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
def approve(action_id: str, background: BackgroundTasks, request: Request, body: dict | None = Body(default=None)):
    """The human approval gate -> execute -> verify -> memory."""
    user = _require_operator(request)
    with LOCK:
        graph, t = g(), now()
        action = actions.get(graph, action_id)
        if action is None:
            raise HTTPException(status_code=404, detail="no such action")
        if not actions.approve(graph, action_id, actor=_actor(body, user), now=t):
            raise HTTPException(status_code=409, detail=f"action is {action['status']}, not proposed")
        executor = (actions.SandboxExecutor() if SANDBOX_MODE
                    else actions.AwsExecutor(_live("executor_ec2"), _live("executor_ssm"), _live("executor_rds")))
        try:
            actions.execute(graph, action_id, executor, now=t)
        except Exception as exc:
            log.exception("execution of %s failed", action_id)
            # an error response drops BackgroundTasks, so use a thread: look again and propose afresh
            threading.Thread(target=_investigate_bg, args=(action["incident_id"],), daemon=True).start()
            raise HTTPException(status_code=502, detail=f"execution failed: {exc}")
        if SANDBOX_MODE:
            out = _finish(graph, action, t, verify_timeout=0)
        else:
            background.add_task(_finish_live_bg, action, t)
            out = {"verified": None, "detail": f"executed; verifying in the background (up to {LIVE_VERIFY_TIMEOUT}s)"}
    return {"action": actions.get(graph, action_id), "verify": out}


@app.post("/api/actions/{action_id}/reject")
def reject(action_id: str, request: Request, body: dict | None = Body(default=None)):
    user = _require_operator(request)
    with LOCK:
        graph = g()
        if actions.get(graph, action_id) is None:
            raise HTTPException(status_code=404, detail="no such action")
        if not actions.reject(graph, action_id, actor=_actor(body, user), now=now()):
            raise HTTPException(status_code=409, detail="action is not proposed")
        return {"action": actions.get(graph, action_id)}


# -- console pages ---------------------------------------------------------------------

REGION = os.environ.get("AWS_REGION", "ap-southeast-2")


@app.get("/api/env")
def env_info(request: Request):
    return {"sandbox": SANDBOX_MODE, "graph": GRAPH_NAME, "user": request.state.user,
            "name": "Staging" if SANDBOX_MODE else "Production",
            "detail": "simulated estate" if SANDBOX_MODE else f"AWS {REGION}"}


def _names() -> dict[str, str]:
    _, nodes = db.run(g(), "q17_resource_nodes")
    return {n["rid"]: n["name"] or n["rid"] for n in nodes}


@app.get("/api/overview")
def overview():
    graph, t = g(), now()
    names = _names()
    _, incs = db.run(graph, "q19_list_incidents", {"limit": 200})
    _, acts = db.run(graph, "q28_list_actions", {"limit": 200})
    ttrs = sorted(i["ttr_seconds"] for i in incs if i["status"] == "resolved" and i["ttr_seconds"] is not None)
    day = 86400
    daily = [{"day": t - (13 - k) * day, "count": sum(1 for i in incs if 0 <= t - i["opened_at"] - (13 - k) * day < day)}
             for k in range(14)]
    feed = Tools(graph).changes_since(24 * 60, limit=50, now=t)["rows"]
    lb = Tools(graph).load_bearing(6)["rows"]
    _, nodes = db.run(graph, "q17_resource_nodes")
    kinds: dict[str, int] = {}
    for n in nodes:
        k = next((k for k in ("Service", "Compute", "Database", "Firewall", "Network") if k in n["kinds"]), "Other")
        kinds[k] = kinds.get(k, 0) + 1
    return {
        "open": sum(1 for i in incs if i["status"] == "open"),
        "resolved": sum(1 for i in incs if i["status"] == "resolved"),
        "failed": sum(1 for i in incs if i["status"] == "failed"),
        "median_ttr": ttrs[len(ttrs) // 2] if ttrs else None,
        "awaiting_approval": [a for a in acts if a["status"] == "proposed"],
        "daily": daily,
        "changes_24h": len(feed), "changes_by_people": sum(1 for c in feed if c["actor"] and not c["by_agent"]),
        "load_bearing": [{"rid": r["resource"], "name": names.get(r["resource"], r["resource"]), "score": round(r["score"], 3)} for r in lb],
        "estate": kinds,
        "recent": [{**i, "top_name": names.get(i["top"], i["top"]) if i["top"] else None} for i in incs[:6]],
    }


@app.get("/api/actions")
def list_actions(limit: int = 100):
    _, rows = db.run(g(), "q28_list_actions", {"limit": max(1, min(limit, 500))})
    return rows


@app.get("/api/memory")
def memory_view():
    """Resolved incidents the agent recalls from, and how often each one was reused by a later incident."""
    graph = g()
    _, rows = db.run(graph, "q29_memory", {"limit": 100})
    _, reports = db.run(graph, "q30_incident_reports", {"limit": 500})
    recalled, prefilled = {}, {}
    for r in reports:
        rep = json.loads(r["report"])
        for x in rep.get("recalled", []):
            recalled.setdefault(x.get("i.id"), []).append(r["id"])
        for p in rep.get("proposals", []):
            src = (p.get("prefilled_from") or {}).get("incident")
            if src:
                prefilled.setdefault(src, []).append(r["id"])
    return [{**m, "recalled_by": sorted(set(recalled.get(m["id"], []))), "fix_reused_by": sorted(set(prefilled.get(m["id"], [])))}
            for m in rows]


@app.get("/api/resources/{rid:path}")
def resource(rid: str):
    tools, graph = Tools(g()), g()
    found = tools.resolve(rid)
    if found["outcome"] != "answered_with_path":
        raise HTTPException(status_code=404, detail="no such resource")
    rid = found["rows"][0]["rid"]
    _, state = db.run(graph, "q26_resource_state", {"rid": rid})
    _, fws = db.run(graph, "q25_active_firewalls_of", {"rid": rid})
    _, incs = db.run(graph, "q32_resource_incidents", {"rid": rid, "limit": 10})
    return {"rid": rid, **(state[0] if state else {}),
            "depends_on": tools.dependencies(rid)["rows"],
            "blast_radius": tools.blast_radius(rid, 4)["rows"],
            "firewalls": [f["firewall"] for f in fws],
            "changes": tools.recent_changes(rid, 7 * 24 * 60, now=now())["rows"][:20],
            "incidents": incs}


def _prometheus_ready() -> bool | None:
    if not PROMETHEUS_URL:
        return None
    import urllib.request
    try:
        with urllib.request.urlopen(PROMETHEUS_URL.rstrip("/") + "/-/ready", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


@app.get("/api/integrations")
def integrations():
    graph = g()
    _, st = db.run(graph, "q31_estate_status")
    st = st[0] if st else {}
    _, last = db.run(graph, "q30_incident_reports", {"limit": 1})
    explained_by = json.loads(last[0]["report"]).get("explained_by") if last else None
    models = [m.strip() for m in os.environ.get("LLM_MODEL", "").split(",") if m.strip()]
    try:
        db.client().connection.ping()
        falkor = True
    except Exception:
        falkor = False
    return {
        "environment": {"name": "Staging" if SANDBOX_MODE else "Production", "graph": GRAPH_NAME,
                        "detail": "simulated copy of the production estate" if SANDBOX_MODE else f"AWS account, region {REGION}"},
        "falkordb": {"ok": falkor, "graph": GRAPH_NAME, "resources": st.get("resources"), "edges": st.get("edges")},
        "discovery": {"mode": "fixture (no AWS calls)" if SANDBOX_MODE else "EC2 + RDS describe, every 60 s, read-only IAM user",
                      "last_sync": st.get("last_sync")},
        "cloudtrail": {"configured": bool(os.environ.get("CHANGES_QUEUE_URL")) and not SANDBOX_MODE,
                       "path": "CloudTrail → EventBridge → SQS → ingester", "last_event": st.get("last_trail"),
                       "events": int(st.get("trail_events") or 0), "changes": st.get("changes")},
        "alerts": {"source": "simulated alerts" if SANDBOX_MODE else "Prometheus + Alertmanager webhook",
                   "prometheus_ready": None if SANDBOX_MODE else _prometheus_ready(),
                   "last_alert": st.get("last_alert"), "alerts": st.get("alerts")},
        "ai": {"provider": "OpenRouter", "models": models, "configured": bool(os.environ.get("LLM_API_KEY") and models),
               "last_explained_by": explained_by,
               "guardrails": "picks among fixed read-only tools, max 6 calls, a reason for each, validator checks the answer"},
        "executor": {"principal": "graph only (staging)" if SANDBOX_MODE else "IAM user rootgraph-executor (undo-only)",
                     "approval": "a signed-in operator approves every action",
                     "actions": [{"kind": k, "targets": list(v["target_kind"])} for k, v in actions.CATALOGUE.items()]},
    }


# -- UI ----------------------------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
