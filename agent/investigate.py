"""Investigation pipeline (§7.3). Every conclusion comes out of a fixed Cypher query.

 1 open      the incident's firing alerts (Q13); optional resync hook (live discovery, P2)
 2 suspects  correlate_alerts walks upward from the alerting nodes (Q2)
 3 paths     for every DEPENDS_ON edge leaving an alerting service or suspect: check_path (Q4).
             A broken path makes the firewall that lost a matching rule (Q10) a candidate;
             if none lost one, every firewall on the target is.
 4 evidence  probe (fixed PromQL / fixtures) + recent_changes (Q5) per candidate
 5 memory    recall_incidents (Q7) with alert names + candidate rids
 6 score     §7.4 scorecard, written as SUSPECTS edges (W7)
 7 explain   LLM hook (Phase 3). Until then, and whenever validation fails, a template
             sentence built from the top row.
 8 propose   an action from the catalogue for the top cause (both, if multiple causes)

Every tool call lands in the trace with by="pipeline"; agent-chosen calls (Phase 3)
will carry by="agent" and a reason.
"""

import json
import time

from agent import actions, scoring
from agent import probe as probe_mod
from agent.tools import ANSWERED, FROM_MEMORY, Tools
from graph import db

WINDOW_MINUTES = 30
SUSPECT_K = 5
CORRELATE_K = 25  # all rows kept for coverage lookups; top SUSPECT_K are the suspects


class Investigator:
    def __init__(self, g, probe_source, now=time.time, resync=None, explain=None):
        self.g, self.tools, self.probes = g, Tools(g), probe_source
        self.now, self.resync, self.explain = now, resync, explain
        self.trace: list[dict] = []

    def _call(self, env: dict) -> dict:
        env["by"] = "pipeline"
        self.trace.append(env)
        return env

    # -- steps ------------------------------------------------------------------

    def run(self, incident_id: str) -> dict:
        now = int(self.now())
        self.trace = []

        # 1 open
        _, alerts = db.run(self.g, "q13_incident_alerts", {"id": incident_id})
        firing = [a for a in alerts if a["status"] == "firing" and a["rid"]]
        alerting = list(dict.fromkeys(a["rid"] for a in firing))
        alertnames = sorted({a["alertname"] for a in firing})
        if self.resync:
            for rid in alerting:
                self._call(self.resync(rid))

        # 2 suspects
        corr = self._call(self.tools.correlate_alerts(alerting, k=CORRELATE_K))
        by_rid = {r["candidate"]: r for r in corr["rows"]} if corr["outcome"] == ANSWERED else {}
        cands: dict[str, scoring.Candidate] = {}
        for r in corr["rows"][:SUSPECT_K] if by_rid else []:
            cands[r["candidate"]] = scoring.Candidate(
                rid=r["candidate"], kinds=r["kinds"], explains=set(r["explains"]), min_hops=r["min_hops"],
                evidence=[f"explains {r['coverage']}/{len(alerting)} alerting resources"])

        # 3 paths
        broken_paths = []
        sources = [rid for rid in dict.fromkeys(alerting + list(cands))
                   if "Service" in (by_rid.get(rid, {}).get("kinds") or [])]
        checked = set()
        for src in sources:
            deps = self._call(self.tools.dependencies(src))
            for dep in deps["rows"] if deps["outcome"] == ANSWERED else []:
                pair = (src, dep["target"])
                if pair in checked:
                    continue
                checked.add(pair)
                cp = self._call(self.tools.check_path(*pair))
                if cp["outcome"] != ANSWERED or cp["rows"][0]["permitted"]:
                    continue
                row = cp["rows"][0]
                rm = self._call(self.tools.removed_rules(*pair, minutes=WINDOW_MINUTES, now=now))
                culprits = {r["firewall"]: r for r in rm["rows"]} if rm["outcome"] == ANSWERED else {}
                fws = list(culprits) or [f["firewall"] for f in row["per_firewall"]]
                src_row = by_rid.get(src, {"explains": [src] if src in alerting else [], "min_hops": 0})
                # the source's host also suffers if an alert there targets the dependency (blackbox)
                host_alerts = {a["rid"] for a in firing if a["rid"] == row["host"] and a["target_rid"] == dep["target"]}
                broken_paths.append({"from": src, "to": dep["target"], "host": row["host"], "port": row["port"],
                                     "firewalls": fws, "culprit_rules": list(culprits.values())})
                for fw in fws:
                    c = cands.setdefault(fw, scoring.Candidate(rid=fw, kinds=["Resource", "Firewall"],
                                                               min_hops=src_row["min_hops"] + 1))
                    c.broken_path = True
                    c.explains |= set(src_row["explains"]) | host_alerts
                    c.min_hops = min(c.min_hops, src_row["min_hops"] + 1)
                    rule = culprits.get(fw)
                    c.evidence.append(
                        f"path {src} -> {dep['target']}:{row['port']} blocked at {fw}"
                        + (f"; rule {rule['original_rule_id']} ({rule['proto']} {rule['port_from']} from "
                           f"{rule['source']}) removed" if rule else ""))

        # 4 evidence
        change_ids: dict[str, str] = {}
        for c in cands.values():
            pr = self._call(probe_mod.probe(self.tools, self.probes, c.rid))
            if pr["rows"] and "state" in pr["rows"][0]:
                c.probe = pr["rows"][0]["state"]
                if c.probe != "unknown":
                    c.evidence.append(f"probe {c.probe}")
            ch = self._call(self.tools.recent_changes(c.rid, WINDOW_MINUTES, now=now))
            own = [r for r in ch["rows"] if r.get("on_resource") == c.rid and not r.get("ch.by_agent")]
            if ch["outcome"] == ANSWERED and own:
                c.change_in_window = True
                change_ids[c.rid] = own[0]["ch.event_id"]
                c.evidence.append("changed: " + "; ".join(dict.fromkeys(
                    f"{r['ch.event_name']} by {r['ch.actor'] or r['ch.source']}" for r in own[:3])))

        # 5 memory
        recall = self._call(self.tools.recall_incidents(alertnames, list(dict.fromkeys(list(cands) + alerting))))
        recalled = recall["rows"] if recall["outcome"] == FROM_MEMORY else []
        for r in recalled:
            c = cands.get(r["root_cause"])
            if c and not c.prior_incident_match:
                c.prior_incident_match = True
                c.evidence.append(f"root cause of {r['i.id']} before, fixed by {r['fix'] or 'unknown'}")

        # 6 score
        rows = scoring.scorecard(list(cands.values()), len(alerting))
        db.run(self.g, "w7_write_suspects",
               {"id": incident_id, "rows": [{"rid": r["rid"], "score": r["score"], "rank": r["rank"]} for r in rows]})
        multiple = scoring.multiple_causes(rows)
        causes = rows[:2] if multiple else rows[:1]

        # 7 explain (LLM in Phase 3; template now and as the validator fallback)
        explanation, explained_by = template_explanation(rows, len(alerting), multiple), "template"
        if self.explain:
            explanation, explained_by = self.explain(rows, self.trace, explanation)

        # 8 propose
        proposals = []
        for cause in causes:
            proposals.append(self._propose(incident_id, cause, broken_paths, recalled, now))

        report = {
            "incident_id": incident_id, "at": now, "alerting": alerting, "alertnames": alertnames,
            "scorecard": rows, "top": rows[0]["rid"] if rows else None, "multiple_causes": multiple,
            "root_change_id": change_ids.get(rows[0]["rid"]) if rows else None,
            "broken_paths": broken_paths, "recalled": recalled,
            "explanation": explanation, "explained_by": explained_by,
            "proposals": proposals, "trace": self.trace,
        }
        db.run(self.g, "w11_update_incident", {"id": incident_id, "report": json.dumps(report), "status": None})
        return report

    def _propose(self, incident_id, cause, broken_paths, recalled, now) -> dict:
        kinds = cause["kinds"]
        prior = next((r for r in recalled if r["root_cause"] == cause["rid"] and r["fix"]), None)
        if "Firewall" in kinds:
            kind = "restore_firewall_rule"
            bp = next((b for b in broken_paths if cause["rid"] in b["firewalls"]), None)
            rule = next((r for r in (bp or {}).get("culprit_rules", []) if r["firewall"] == cause["rid"]), None)
            hint = {"rule_id": rule["rule_id"] if rule else None, "path": [bp["from"], bp["to"]] if bp else None}
        elif "Service" in kinds:
            kind, hint = "restart_service", None
        else:
            return {"rid": cause["rid"], "action": None,
                    "reason": f"no catalogued safe action for {cause['rid']} ({', '.join(k for k in kinds if k != 'Resource')}); a human should look"}
        try:
            act = actions.propose(self.g, self.tools, self.probes, incident_id, kind, cause["rid"], now, hint=hint)
        except actions.PreconditionFailed as exc:
            return {"rid": cause["rid"], "action": None, "reason": str(exc)}
        out = {"rid": cause["rid"], "action": act, "reason": None}
        if prior:
            out["prefilled_from"] = {"incident": prior["i.id"], "fix": prior["fix"],
                                     "ttr_seconds": prior["i.ttr_seconds"]}
        return out


def template_explanation(rows: list[dict], total: int, multiple: bool) -> str:
    """Built only from scorecard rows, so it can never mention anything the graph didn't return."""
    if not rows:
        return "No candidate explains these alerts in the graph."
    top = rows[0]
    text = (f"{top['rid']} is the most likely root cause (score {top['score']}): "
            + "; ".join(top["evidence"]) + ".")
    if multiple and len(rows) > 1:
        sec = rows[1]
        text += (f" Multiple likely causes: {sec['rid']} (score {sec['score']}) also has direct evidence: "
                 + "; ".join(sec["evidence"]) + ".")
    return text
