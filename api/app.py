"""rootgraph API — stub.

For now it does two things:
- GET  /healthz              liveness + FalkorDB reachability
- POST /hooks/alertmanager   bearer-token check, then saves the raw payload
                             to /data/hooks so we can replay it later
                             (demo/replay/recorded/).
Investigation, UI and sandbox controls come later.
"""

import hmac
import json
import logging
import os
import time
from pathlib import Path

from falkordb import FalkorDB
from fastapi import FastAPI, Header, HTTPException, Request

log = logging.getLogger("rootgraph.api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

WEBHOOK_TOKEN = os.environ["WEBHOOK_TOKEN"]
HOOKS_DIR = Path(os.environ.get("HOOKS_DIR", "/data/hooks"))
HOOKS_DIR.mkdir(parents=True, exist_ok=True)

db = FalkorDB(
    host=os.environ.get("FALKORDB_HOST", "falkordb"),
    port=int(os.environ.get("FALKORDB_PORT", "6379")),
    password=os.environ["FALKORDB_PASSWORD"],
)

app = FastAPI(title="rootgraph", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz():
    try:
        db.connection.ping()
        falkordb_ok = True
    except Exception as exc:  # report, don't crash the health check
        log.warning("falkordb ping failed: %s", exc)
        falkordb_ok = False
    return {"status": "ok" if falkordb_ok else "degraded", "falkordb": falkordb_ok}


def _check_bearer(authorization: str | None) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    if not hmac.compare_digest(authorization.removeprefix("Bearer ").encode(), WEBHOOK_TOKEN.encode()):
        raise HTTPException(status_code=401, detail="bad token")


@app.post("/hooks/alertmanager")
async def alertmanager_hook(request: Request, authorization: str | None = Header(default=None)):
    _check_bearer(authorization)
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="body is not JSON")

    alerts = payload.get("alerts", []) if isinstance(payload, dict) else []
    path = HOOKS_DIR / f"alertmanager-{time.time_ns()}.json"
    path.write_text(json.dumps(payload, indent=2))
    log.info(
        "alertmanager hook: status=%s alerts=%d groupKey=%s saved=%s",
        payload.get("status") if isinstance(payload, dict) else None,
        len(alerts),
        payload.get("groupKey") if isinstance(payload, dict) else None,
        path.name,
    )
    return {"received": len(alerts), "saved": path.name}
