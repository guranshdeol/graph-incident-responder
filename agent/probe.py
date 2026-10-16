"""probe(rid): fixed health checks per node kind (§7.1). The LLM never writes PromQL.

Two sources share one classification:
  PrometheusProbe  live: runs the fixed PromQL below against Prometheus
  FixtureProbe     sandbox/tests: canned metrics from a scenario file

Metrics shape per kind:
  Service   {up, error_rate, p95}
  Compute   {up, cpu}
  Database  {reachable_from: {host_rid: 0|1}}   blackbox tcp_connect from every host
  Firewall  (no probe: state "unknown")

States: healthy | unhealthy | degraded | unknown.
  Service   unhealthy if down; healthy if error rate < 5% and p95 < 1s; else degraded
            (degraded = showing symptoms, which a victim of a downstream fault also does)
  Compute   unhealthy if down or CPU > 90%; else healthy
  Database  healthy if ANY host reaches it (sibling evidence: the DB itself is fine);
            unhealthy if no host does
"""

import json
import time
import urllib.parse
import urllib.request

from agent.tools import ANSWERED, NOT_IN_GRAPH, UNKNOWN, _envelope

ERROR_RATE_OK = 0.05
P95_OK_SECONDS = 1.0
CPU_SATURATED = 90

PROMQL = {
    "Service": {
        "up": 'up{{job="services",rid="{rid}"}}',
        "error_rate": 'sum(rate(http_requests_total{{rid="{rid}",code=~"5.."}}[1m])) / sum(rate(http_requests_total{{rid="{rid}"}}[1m]))',
        "p95": 'histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{{rid="{rid}"}}[1m])))',
    },
    "Compute": {
        "up": 'up{{job="node",rid="{rid}"}}',
        "cpu": '100 * (1 - avg(rate(node_cpu_seconds_total{{rid="{rid}",mode="idle"}}[1m])))',
    },
    "Database": {
        "reachable_from": 'probe_success{{job="blackbox_db",target_rid="{rid}"}}',
    },
}


def kind_of(kinds: list[str]) -> str | None:
    for k in ("Service", "Compute", "Database", "Firewall"):
        if k in kinds:
            return k
    return None


def classify(kind: str | None, m: dict | None) -> str:
    if not m:
        return "unknown"
    if kind == "Service":
        if m.get("up") == 0:
            return "unhealthy"
        if m.get("up") is None:
            return "unknown"
        err, p95 = m.get("error_rate") or 0.0, m.get("p95") or 0.0
        return "healthy" if err < ERROR_RATE_OK and p95 < P95_OK_SECONDS else "degraded"
    if kind == "Compute":
        if m.get("up") == 0 or (m.get("cpu") or 0) > CPU_SATURATED:
            return "unhealthy"
        return "healthy" if m.get("up") == 1 else "unknown"
    if kind == "Database":
        reach = m.get("reachable_from") or {}
        if not reach:
            return "unknown"
        return "healthy" if any(v == 1 for v in reach.values()) else "unhealthy"
    return "unknown"


def _label_value(rid: str) -> str:
    return rid.replace("\\", "\\\\").replace('"', '\\"')


class FixtureProbe:
    """Canned metrics, switchable to the post-fix state by the sandbox."""

    def __init__(self, before: dict, after: dict | None = None):
        self.before, self.after, self.fixed = before or {}, after or {}, False

    def metrics(self, rid: str, kind: str | None) -> dict | None:
        if self.fixed and rid in self.after:
            return self.after[rid]
        return self.before.get(rid)


class PrometheusProbe:
    def __init__(self, base_url: str, timeout: float = 3.0):
        self.base_url, self.timeout = base_url.rstrip("/"), timeout

    def _query(self, promql: str) -> list:
        url = f"{self.base_url}/api/v1/query?" + urllib.parse.urlencode({"query": promql})
        with urllib.request.urlopen(url, timeout=self.timeout) as resp:
            body = json.load(resp)
        return body.get("data", {}).get("result", []) if body.get("status") == "success" else []

    def metrics(self, rid: str, kind: str | None) -> dict | None:
        queries = PROMQL.get(kind or "")
        if not queries:
            return None
        out = {}
        for name, template in queries.items():
            result = self._query(template.format(rid=_label_value(rid)))
            if name == "reachable_from":
                out[name] = {r["metric"].get("rid", "?"): int(float(r["value"][1])) for r in result}
            elif result:
                value = float(result[0]["value"][1])
                out[name] = value if value == value else None  # NaN (no traffic) -> None
        return out or None


def probe(tools, source, rid: str) -> dict:
    """The probe tool: resolve rid in the graph, then run the fixed checks for its kind."""
    args = {"rid": rid}
    resolved = tools.resolve(rid)
    if resolved["outcome"] != ANSWERED:
        return _envelope("probe", args, UNKNOWN, rows=[{"unknown": rid}])
    canon, kinds = resolved["rows"][0]["rid"], resolved["rows"][0]["kinds"]
    kind = kind_of(kinds)
    t0 = time.perf_counter()
    m = source.metrics(canon, kind)
    ms = int((time.perf_counter() - t0) * 1000)
    promql = [q.format(rid=_label_value(canon)) for q in PROMQL.get(kind or "", {}).values()]
    row = {"rid": canon, "kind": kind, "state": classify(kind, m), "metrics": m or {}, "promql": promql}
    return _envelope("probe", args, ANSWERED if m else NOT_IN_GRAPH, rows=[row], ms=ms)
