"""Deterministic scorecard (§7.4). Shown in the UI column by column.

    score = 3.0 * coverage_ratio          alerting nodes explained / total alerting nodes
          + 2.0 * probe_unhealthy         candidate's own probe fails
          - 2.0 * probe_healthy           candidate positively healthy (incl. sibling evidence)
          + 2.0 * broken_path             candidate is the firewall on a broken dependency path
          + 2.0 * change_in_window        a (non-agent) Change MODIFIED it in the last 30 min
          + 1.0 * prior_incident_match    a resolved incident had this root cause
          - 0.25 * min_hops

The weights are heuristic and tuned only against tests/test_scenarios.py.
"""

from dataclasses import dataclass, field

WEIGHTS = {
    "coverage_ratio": 3.0,
    "probe_unhealthy": 2.0,
    "probe_healthy": -2.0,
    "broken_path": 2.0,
    "change_in_window": 2.0,
    "prior_incident_match": 1.0,
    "min_hops": -0.25,
}
CLOSE_GAP = 1.0  # top two within this -> "multiple likely causes"


@dataclass
class Candidate:
    rid: str
    kinds: list[str]
    explains: set[str] = field(default_factory=set)
    min_hops: int = 0
    probe: str = "unknown"            # healthy | unhealthy | degraded | unknown
    broken_path: bool = False
    change_in_window: bool = False
    prior_incident_match: bool = False
    evidence: list[str] = field(default_factory=list)   # human-readable reasons, for the UI and template text


def components(c: Candidate, total_alerting: int) -> dict:
    return {
        "coverage_ratio": round(len(c.explains) / total_alerting, 3) if total_alerting else 0.0,
        "probe_unhealthy": int(c.probe == "unhealthy"),
        "probe_healthy": int(c.probe == "healthy"),
        "broken_path": int(c.broken_path),
        "change_in_window": int(c.change_in_window),
        "prior_incident_match": int(c.prior_incident_match),
        "min_hops": c.min_hops,
    }


def scorecard(cands: list[Candidate], total_alerting: int) -> list[dict]:
    rows = []
    for c in cands:
        comp = components(c, total_alerting)
        score = round(sum(WEIGHTS[k] * v for k, v in comp.items()), 2)
        rows.append({
            "rid": c.rid, "kinds": c.kinds, "score": score, "probe": c.probe,
            "explains": sorted(c.explains), "components": comp, "evidence": c.evidence,
        })
    rows.sort(key=lambda r: (-r["score"], r["components"]["min_hops"], r["rid"]))
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    return rows


def direct_evidence(row: dict) -> bool:
    """Evidence about the candidate itself, not inherited from what it explains."""
    c = row["components"]
    return bool(c["probe_unhealthy"] or c["broken_path"] or c["change_in_window"])


def multiple_causes(rows: list[dict], victims: set[str] = frozenset()) -> bool:
    """Top two are close, or the runner-up has its own direct evidence of failure.

    The second rule is what flags S5: payments being down is direct evidence
    even though sg-db scores higher. A victim (degraded service, healthy host)
    has no direct evidence, so S1-S3 stay single-cause. `victims` are candidates
    whose failure the top cause explains physically (a service running on a
    stopped host, S7): they never count as a second cause.
    """
    rest = [r for r in rows[1:] if r["rid"] not in victims]
    if not rows or not rest or rest[0]["score"] <= 0:
        return False
    return rows[0]["score"] - rest[0]["score"] < CLOSE_GAP or direct_evidence(rest[0])
