"""Typed read tools for the agent (§7.1), returning the §7.2 envelope.

Every tool runs one fixed, human-reviewed query from graph/queries/. The LLM
picks tools and arguments; it never writes Cypher (D4).

Envelope:
    {"tool", "args", "outcome", "rows", "paths", "cypher", "ms"}

outcome is one of:
    answered_with_path    the query returned rows
    answered_from_memory  recall_incidents matched a past incident
    not_in_graph          the query returned nothing: the graph does not model
                          it. NOT the same as "healthy"; the UI must say so.
    unknown_resource      a rid argument did not resolve; no tool query ran,
                          cypher is None and rows lists the unresolved inputs
    error                 the query raised; rows = [{"error": message}]
"""

import time
from collections.abc import Mapping

from falkordb import Graph

from graph import db

ANSWERED = "answered_with_path"
FROM_MEMORY = "answered_from_memory"
NOT_IN_GRAPH = "not_in_graph"
UNKNOWN = "unknown_resource"
ERROR = "error"

MAX_DEPTH = 4  # Q6 has a fixed *1..4 bound; $depth only filters below it


def _plain(value):
    """OrderedDicts from map projections -> dicts, recursively, so envelopes are JSON-ready."""
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def _envelope(tool, args, outcome, rows=None, paths=None, cypher=None, ms=0):
    return {
        "tool": tool,
        "args": args,
        "outcome": outcome,
        "rows": rows or [],
        "paths": paths or [],
        "cypher": cypher,
        "ms": ms,
    }


class Tools:
    def __init__(self, g: Graph):
        self.g = g

    # -- plumbing -----------------------------------------------------------

    def _resolve_one(self, x: str) -> str | None:
        _, rows = db.run(self.g, "q1_resolve", {"x": x})
        return rows[0]["rid"] if rows else None

    def _resolve_all(self, xs: list[str]) -> tuple[list[str], list[str]]:
        """Return (canonical rids, unresolved inputs)."""
        rids, unknown = [], []
        for x in xs:
            rid = self._resolve_one(x)
            if rid is None:
                unknown.append(x)
            else:
                rids.append(rid)
        return rids, unknown

    def _run(self, tool, args, query, params, *, paths_from=None, hit=ANSWERED):
        cypher = db.query(query)
        t0 = time.perf_counter()
        try:
            _, rows = db.run(self.g, query, params)
        except Exception as exc:
            ms = int((time.perf_counter() - t0) * 1000)
            return _envelope(tool, args, ERROR, rows=[{"error": str(exc)}], cypher=cypher, ms=ms)
        ms = int((time.perf_counter() - t0) * 1000)
        rows = _plain(rows)
        paths = paths_from(rows) if (paths_from and rows) else []
        return _envelope(tool, args, hit if rows else NOT_IN_GRAPH, rows=rows, paths=paths, cypher=cypher, ms=ms)

    # -- tools --------------------------------------------------------------

    def resolve(self, name_or_rid: str) -> dict:
        args = {"name_or_rid": name_or_rid}
        env = self._run("resolve", args, "q1_resolve", {"x": name_or_rid})
        if env["outcome"] == NOT_IN_GRAPH:
            env["outcome"] = UNKNOWN
            env["rows"] = [{"unknown": name_or_rid}]
        return env

    def correlate_alerts(self, alert_rids: list[str], k: int = 5) -> dict:
        args = {"alert_rids": list(alert_rids), "k": k}
        rids, unknown = self._resolve_all(alert_rids)
        if unknown:
            return _envelope("correlate_alerts", args, UNKNOWN, rows=[{"unknown": u} for u in unknown])
        return self._run("correlate_alerts", args, "q2_correlate_alerts", {"alert_rids": rids, "k": int(k)})

    def check_path(self, from_svc: str, to_rid: str) -> dict:
        args = {"from_svc": from_svc, "to_rid": to_rid}
        rids, unknown = self._resolve_all([from_svc, to_rid])
        if unknown:
            return _envelope("check_path", args, UNKNOWN, rows=[{"unknown": u} for u in unknown])
        src, dst = rids

        def paths(rows):
            # service -> host -> each firewall on the target (the hop that permits or blocks)
            return [[src, r["host"], fw["firewall"]] for r in rows for fw in r["per_firewall"]]

        return self._run("check_path", args, "q4_check_path", {"from": src, "to": dst}, paths_from=paths)

    def recent_changes(self, rid: str, minutes: int = 30, now: int | None = None) -> dict:
        args = {"rid": rid, "minutes": minutes}
        canon = self._resolve_one(rid)
        if canon is None:
            return _envelope("recent_changes", args, UNKNOWN, rows=[{"unknown": rid}])
        now = int(time.time()) if now is None else int(now)
        since = now - int(minutes) * 60
        return self._run("recent_changes", args, "q5_recent_changes", {"rid": canon, "since": since})

    def blast_radius(self, rid: str, depth: int = 2) -> dict:
        args = {"rid": rid, "depth": depth}
        canon = self._resolve_one(rid)
        if canon is None:
            return _envelope("blast_radius", args, UNKNOWN, rows=[{"unknown": rid}])
        depth = max(1, min(int(depth), MAX_DEPTH))
        return self._run(
            "blast_radius", args, "q6_blast_radius", {"rid": canon, "depth": depth},
            paths_from=lambda rows: [r["via"] for r in rows],
        )

    def path_between(self, from_rid: str, to_rid: str) -> dict:
        args = {"from": from_rid, "to": to_rid}
        rids, unknown = self._resolve_all([from_rid, to_rid])
        if unknown:
            return _envelope("path_between", args, UNKNOWN, rows=[{"unknown": u} for u in unknown])
        return self._run(
            "path_between", args, "q3_path_between", {"from": rids[0], "to": rids[1]},
            paths_from=lambda rows: [r["hops"] for r in rows],
        )

    def recall_incidents(self, alertnames: list[str], candidate_rids: list[str]) -> dict:
        args = {"alertnames": list(alertnames), "candidate_rids": list(candidate_rids)}
        rids, unknown = self._resolve_all(candidate_rids)
        if unknown:
            return _envelope("recall_incidents", args, UNKNOWN, rows=[{"unknown": u} for u in unknown])
        return self._run(
            "recall_incidents", args, "q7_recall_incidents",
            {"alertnames": list(alertnames), "candidate_rids": rids}, hit=FROM_MEMORY,
        )

    def load_bearing(self, limit: int = 10) -> dict:
        args = {"limit": limit}
        return self._run("load_bearing", args, "q8_load_bearing", {"limit": max(1, int(limit))})

    def dependencies(self, rid: str) -> dict:
        args = {"rid": rid}
        canon = self._resolve_one(rid)
        if canon is None:
            return _envelope("dependencies", args, UNKNOWN, rows=[{"unknown": rid}])
        return self._run(
            "dependencies", args, "q9_dependencies", {"rid": canon},
            paths_from=lambda rows: [[canon, r["target"]] for r in rows],
        )

    def removed_rules(self, from_svc: str, to_rid: str, minutes: int = 30, now: int | None = None) -> dict:
        """On a broken path: which firewall on the target lost a rule that used to permit it."""
        args = {"from_svc": from_svc, "to_rid": to_rid, "minutes": minutes}
        rids, unknown = self._resolve_all([from_svc, to_rid])
        if unknown:
            return _envelope("removed_rules", args, UNKNOWN, rows=[{"unknown": u} for u in unknown])
        now = int(time.time()) if now is None else int(now)
        return self._run(
            "removed_rules", args, "q10_removed_path_rules",
            {"from": rids[0], "to": rids[1], "since": now - int(minutes) * 60},
            paths_from=lambda rows: [[rids[0], rids[1], r["firewall"]] for r in rows],
        )


    def detached_on_path(self, from_svc: str, to_rid: str, minutes: int = 30, now: int | None = None) -> dict:
        """On a broken path: was a security group detached from the dependency's host or target?"""
        args = {"from_svc": from_svc, "to_rid": to_rid, "minutes": minutes}
        rids, unknown = self._resolve_all([from_svc, to_rid])
        if unknown:
            return _envelope("detached_on_path", args, UNKNOWN, rows=[{"unknown": u} for u in unknown])
        now = int(time.time()) if now is None else int(now)
        return self._run("detached_on_path", args, "q23_detached_on_path",
                         {"from": rids[0], "to": rids[1], "since": now - int(minutes) * 60},
                         paths_from=lambda rows: [[r["firewall"], r["target"]] for r in rows])

    def changes_since(self, minutes: int = 30, limit: int = 20, now: int | None = None) -> dict:
        """Every change anywhere in the estate (CloudTrail + graph diff) in the last `minutes`, newest first."""
        args = {"minutes": minutes}
        now = int(time.time()) if now is None else int(now)
        return self._run("changes_since", args, "q24_changes_since",
                         {"since": now - int(minutes) * 60, "limit": max(1, min(int(limit), 50))})

def tools_for(graph_name: str | None = None) -> Tools:
    return Tools(db.graph(graph_name))
