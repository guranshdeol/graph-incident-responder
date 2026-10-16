"""The one demo service (plan §9.2). Five instances, configured by env:

    SERVICE_RID   rid label on every metric, e.g. svc:payments (the alert <-> graph contract)
    DEPS          comma list of kind:target_rid=address, e.g.
                  "http:svc:checkout=http://checkout:8081/,db:rds:orders-db=orders-db:5432"
    WORK_MS       CPU work per request (so a CPU hog on the host shows up as latency)
    MODE          "service" (default) or "loadgen" (hits every URL in LOAD_TARGET, comma list, forever)

GET / calls every dependency; any failure -> 500. A db dependency is a TCP connect with a
1s timeout, which is exactly what a revoked security-group rule breaks.
No restart policy is set in compose, so a stopped service stays down until fixed (S3).
"""

import hashlib
import os
import socket
import threading
import time

import httpx
from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

RID = os.environ.get("SERVICE_RID", "svc:unknown")
WORK_MS = float(os.environ.get("WORK_MS", "15"))
DEPS = []
for item in filter(None, (os.environ.get("DEPS") or "").split(",")):
    head, addr = item.split("=", 1)
    kind, target = head.split(":", 1)
    DEPS.append((kind, target, addr))

REQS = Counter("http_requests_total", "Requests served", ["rid", "code"])
LAT = Histogram("http_request_duration_seconds", "Request latency", ["rid"],
                buckets=(0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5))
HTTP_CLIENT = Counter("http_client_requests_total", "Calls to HTTP dependencies", ["rid", "target_rid", "outcome"])
DB_CLIENT = Counter("db_client_queries_total", "Calls to database dependencies", ["rid", "target_rid", "outcome"])
for code in ("200", "500"):
    REQS.labels(RID, code)  # export zeros so rate() has a series from the start

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
client = httpx.Client(timeout=2.0)


def _work():
    end = time.perf_counter() + WORK_MS / 1000
    h = b"x"
    while time.perf_counter() < end:
        h = hashlib.sha256(h).digest()


def _call(kind: str, target: str, addr: str) -> bool:
    try:
        if kind == "db":
            host, port = addr.rsplit(":", 1)
            with socket.create_connection((host, int(port)), timeout=1.0):
                pass
            DB_CLIENT.labels(RID, target, "ok").inc()
        else:
            client.get(addr).raise_for_status()
            HTTP_CLIENT.labels(RID, target, "ok").inc()
        return True
    except Exception:
        (DB_CLIENT if kind == "db" else HTTP_CLIENT).labels(RID, target, "error").inc()
        return False


@app.get("/")
def handle():
    t0 = time.perf_counter()
    _work()
    ok = all([_call(*d) for d in DEPS])
    code = "200" if ok else "500"
    REQS.labels(RID, code).inc()
    LAT.labels(RID).observe(time.perf_counter() - t0)
    return Response(content=f"{RID} {code}\n", status_code=int(code), media_type="text/plain")


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _loadgen():
    targets = [t for t in os.environ["LOAD_TARGET"].split(",") if t]
    delay = float(os.environ.get("LOAD_INTERVAL", "0.2"))
    while True:
        for target in targets:
            try:
                client.get(target)
            except Exception:
                pass
        time.sleep(delay)


if os.environ.get("MODE") == "loadgen":
    threading.Thread(target=_loadgen, daemon=True).start()
