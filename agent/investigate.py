"""Investigation pipeline (§7.3). Every conclusion comes out of a fixed Cypher query.

 1 open      the incident's firing alerts (Q13); optional resync hook (live discovery, P2)
 2 suspects  correlate_alerts walks upward from the alerting nodes (Q2)
 3 paths     for every DEPENDS_ON edge leaving an alerting service or suspect: check_path (Q4).
             A broken path makes the firewall that lost a matching rule (Q10) a candidate;
             if none lost one, every firewall on the target is.
 4 evidence  probe (fixed PromQL / fixtures) + recent_changes (Q5) per candidate
 5 memory    recall_incidents (Q7) with alert names + candidate rids
 6 score     §7.4 scorecard, written as SUSPECTS edges (W7)
 7 explain   agent/llm.py: the LLM runs up to 6 read tools of its own (each with a reason),
             answers in JSON, and agent/validator.py accepts or rejects it; the template
             sentence built from the top row is the fallback.
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
        env["call_id"] = f"p{len(self.trace) + 1}"  # the LLM cites evidence by call_id
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
                culprits = {}
                for r in (rm["rows"] if rm["outcome"] == ANSWERED else []):   # Q10 is newest first: keep each firewall's latest removal
                    culprits.setdefault(r["firewall"], r)
                detached = []
                if not culprits:   # no rule went away: was a security group detached from the host or the target?
                    dt = self._call(self.tools.detached_on_path(*pair, minutes=WINDOW_MINUTES, now=now))
                    detached = dt["rows"] if dt["outcome"] == ANSWERED else []
                fws = list(culprits) or ([] if detached else [f["firewall"] for f in row["per_firewall"]])
                src_row = by_rid.get(src, {"explains": [src] if src in alerting else [], "min_hops": 0})
                # the source's host also suffers if an alert there targets the dependency (blackbox)
                host_alerts = {a["rid"] for a in firing if a["rid"] == row["host"] and a["target_rid"] == dep["target"]}
                broken_paths.append({"from": src, "to": dep["target"], "host": row["host"], "port": row["port"],
                                     "firewalls": fws, "culprit_rules": list(culprits.values()), "detached": detached})
                for fw in fws:
                    c = cands.setdefault(fw, scoring.Candidate(rid=fw, kinds=["Resource", "Firewall"],
                                                               min_hops=src_row["min_hops"] + 1))
                    c.broken_path = True
                    c.explains |= set(src_row["explains"]) | host_alerts
                    c.min_hops = min(c.min_hops, src_row["min_hops"] + 1)
                    rule = culprits.get(fw)
                    if rule and "@" in rule["rule_id"]:
                        what = f"; rule {rule['original_rule_id']} was edited (it allowed {rule['proto']} {rule['port_from']} from {rule['source']})"
                    elif rule:
                        what = f"; rule {rule['original_rule_id']} ({rule['proto']} {rule['port_from']} from {rule['source']}) removed"
                    else:
                        what = ""
                    c.evidence.append(f"path {src} -> {dep['target']}:{row['port']} blocked at {fw}" + what)
                for d in detached:   # the culprit is the instance/database that lost its security group
                    hops = src_row["min_hops"] + (0 if d["target"] == row["host"] else 1)
                    c = cands.setdefault(d["target"], scoring.Candidate(rid=d["target"], kinds=d["target_kinds"], min_hops=hops))
                    c.broken_path = True
                    c.explains |= set(src_row["explains"]) | host_alerts
                    c.min_hops = min(c.min_hops, hops)
                    c.evidence.append(f"path {src} -> {dep['target']}:{row['port']} blocked: security group {d['firewall']} was detached from {d['target']}")

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

        # 4b search the whole account: what changed recently, anywhere? (also the incident timeline)
        feed = self._call(self.tools.changes_since(WINDOW_MINUTES, limit=20, now=now))
        timeline = [{"at": r["at"], "kind": "change", "event": r["event_name"], "actor": r["actor"], "source": r["source"],
                     "resources": r["resources"], "names": r["names"], "before": r["before"], "after": r["after"]}
                    for r in feed["rows"] if not r.get("by_agent")] if feed["outcome"] == ANSWERED else []
        starts = [a["starts_at"] for a in firing if a.get("starts_at")]
        if starts:
            timeline.append({"at": min(starts), "kind": "alerts", "event": f"{len(firing)} alerts firing", "names": alertnames})

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
        db.run(self.g, "w7a_clear_suspects", {"id": incident_id})
        db.run(self.g, "w7_write_suspects",
               {"id": incident_id, "rows": [{"rid": r["rid"], "score": r["score"], "rank": r["rank"]} for r in rows]})
        # services that run on a down top-ranked host are its victims, not a second cause
        victims = set()
        if rows and "Compute" in rows[0]["kinds"] and rows[0]["probe"] == "unhealthy":
            for r in rows[1:]:
                if "Service" in r["kinds"]:
                    _, hs = db.run(self.g, "q16_service_host", {"rid": r["rid"]})
                    if hs and hs[0]["host"] == rows[0]["rid"]:
                        victims.add(r["rid"])
        multiple = scoring.multiple_causes(rows, victims)
        causes = rows[:2] if multiple else rows[:1]

        # 7 explain: the LLM agent may run its own read tools (with reasons) and re-rank only
        # with new evidence the validator accepts; the template is the fallback
        explanation, explained_by = template_explanation(rows, len(alerting), multiple), "template"
        top = rows[0]["rid"] if rows else None
        llm = {"tokens_in": 0, "tokens_out": 0, "agent_calls": 0, "llm_answer": None}
        if self.explain and rows:
            try:
                res = self.explain.explain(rows, self.trace, explanation, alerting)
            except Exception as exc:  # provider down, timeout, bad response: the pipeline answer stands
                res = {"explanation": explanation, "explained_by": f"template (llm error: {str(exc)[:200]})",
                       "root_cause_rid": None, "agent_trace": [], "tokens_in": 0, "tokens_out": 0,
                       "agent_calls": 0, "llm_answer": None}
            self.trace.extend(res["agent_trace"])
            explanation, explained_by = res["explanation"], res["explained_by"]
            llm = {k: res[k] for k in ("tokens_in", "tokens_out", "agent_calls", "llm_answer")}
            db.run(self.g, "w23_incident_llm_stats", {"id": incident_id, **{k: llm[k] for k in ("tokens_in", "tokens_out", "agent_calls")}})
            if res["root_cause_rid"] and res["root_cause_rid"] != top:
                top = res["root_cause_rid"]  # validated re-rank: agent-chosen evidence backed it
                causes = [r for r in rows if r["rid"] == top] + [r for r in causes if r["rid"] != top][: 1 if multiple else 0]

        # 8 propose
        proposals = []
        for cause in causes:
            proposals.append(self._propose(incident_id, cause, broken_paths, recalled, now))

        report = {
            "incident_id": incident_id, "at": now, "alerting": alerting, "alertnames": alertnames,
            "scorecard": rows, "top": top, "scorecard_top": rows[0]["rid"] if rows else None,
            "multiple_causes": multiple, "root_change_id": change_ids.get(top) if top else None,
            "broken_paths": broken_paths, "recalled": recalled,
            "explanation": explanation, "explained_by": explained_by,
            "proposals": proposals, "trace": self.trace, "llm": llm,
            "timeline": sorted(timeline + [{"at": now, "kind": "decided", "event": f"root cause: {top}"}], key=lambda e: e["at"]),
        }
        db.run(self.g, "w11_update_incident", {"id": incident_id, "report": json.dumps(report), "status": None})
        return report

    def _propose(self, incident_id, cause, broken_paths, recalled, now) -> dict:
        kinds = cause["kinds"]
        prior = next((r for r in recalled if r["root_cause"] == cause["rid"] and r["fix"]), None)
        # the fix undoes the change that was found: a removed rule is re-added, an edited rule is edited back,
        # a detached security group is re-attached, a stopped instance is started, a stopped container restarted
        det = next(((b, d) for b in broken_paths for d in b.get("detached", []) if d["target"] == cause["rid"]), None)
        if "Firewall" in kinds:
            bp = next((b for b in broken_paths if cause["rid"] in b["firewalls"]), None)
            rule = next((r for r in (bp or {}).get("culprit_rules", []) if r["firewall"] == cause["rid"]), None)
            kind = "revert_rule_edit" if rule and "@" in rule["rule_id"] else "restore_firewall_rule"
            hint = {"rule_id": rule["rule_id"] if rule else None, "path": [bp["from"], bp["to"]] if bp else None}
        elif "Service" in kinds:
            kind, hint = "restart_service", None
        elif det and ("Compute" in kinds or "Database" in kinds):
            b, d = det
            kind, hint = "reattach_security_group", {"firewall": d["firewall"], "path": [b["from"], b["to"]]}
        elif "Compute" in kinds and actions.state_of(self.g, cause["rid"]) in ("stopped", "stopping"):
            kind, hint = "start_instance", None
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
