"""Memory written back to the graph (§7.3 step 11).

A verified fix closes the incident with ROOT_CAUSE, EXPLAINED_BY and
Action-[:RESOLVED]-> (W6), plus a Finding. Q7 recalls these by alert cues.
In Track 02 terms: Incident = episodic, Finding = semantic, the verified
Action recalled with its exact params = procedural memory.
"""

import re
import uuid

from graph import db

# rid-like tokens (§5 formats). Every one in a finding must exist in the graph.
RID_TOKEN = re.compile(r"\b(?:svc:[\w-]+|rds:[\w-]+|sg-[\w-]+|i-[\w-]+|vpc-[\w-]+|subnet-[\w-]+|cidr:[\d./]+)")


class InvalidFinding(Exception):
    pass


def validate_text(tools, text: str) -> list[str]:
    """Return the rid tokens in text; raise if any does not resolve in the graph."""
    tokens = sorted(set(RID_TOKEN.findall(text)))
    unknown = [t for t in tokens if tools.resolve(t)["outcome"] != "answered_with_path"]
    if unknown:
        raise InvalidFinding(f"unknown resources in finding: {unknown}")
    return tokens


def record_finding(g, tools, incident_id: str, text: str, about_rids: list[str],
                   now: int, confidence: float = 1.0) -> str:
    validate_text(tools, text)
    finding_id = f"FND-{uuid.uuid4().hex[:8]}"
    db.run(g, "w10_record_finding", {"id": finding_id, "text": text, "now": now, "confidence": confidence,
                                     "incident_id": incident_id, "about_rids": about_rids})
    return finding_id


def close_incident(g, incident_id: str, root_rid: str, action_id: str, change_id: str | None,
                   summary: str, now: int) -> None:
    db.run(g, "w6_close_incident", {"id": incident_id, "root_rid": root_rid, "action_id": action_id,
                                    "change_id": change_id, "summary": summary, "now": now})


def fail_incident(g, incident_id: str) -> None:
    db.run(g, "w11_update_incident", {"id": incident_id, "report": None, "status": "failed"})
