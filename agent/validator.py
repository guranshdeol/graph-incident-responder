"""Validator for the LLM's final answer (§7.5), modelled on the organiser blog's accepts().

The LLM may re-rank only by producing new evidence the validator accepts:
  1 root_cause_rid is one of the scored candidates
  2 every rid-like token in the explanation appears in the evidence (scorecard + tool rows)
  3 proposed_action.kind is in the catalogue (or null) and targets the root cause
  4 evidence_tools names at least one tool call that returned rows
  5 if root_cause_rid differs from the scorecard's top, at least one cited call is agent-chosen
Any failure -> the template explanation built from the top scorecard row goes out instead.
"""

import json

from agent.actions import CATALOGUE
from agent.memory import RID_TOKEN

ROWS_OUTCOMES = {"answered_with_path", "answered_from_memory"}


def evidence_tokens(scorecard: list[dict], trace: list[dict]) -> set[str]:
    blob = json.dumps(scorecard) + json.dumps([{"args": t["args"], "rows": t["rows"], "paths": t["paths"]} for t in trace])
    return set(RID_TOKEN.findall(blob))


def validate(answer: dict, scorecard: list[dict], trace: list[dict]) -> list[str]:
    """Return a list of problems; empty means accepted."""
    problems = []
    if not isinstance(answer, dict):
        return ["answer is not a JSON object"]
    candidates = [r["rid"] for r in scorecard]
    root = answer.get("root_cause_rid")
    if root not in candidates:
        problems.append(f"root_cause_rid {root!r} is not a scored candidate")
    text = answer.get("explanation") or ""
    if not text.strip():
        problems.append("empty explanation")
    known = evidence_tokens(scorecard, trace)
    unknown = sorted(set(RID_TOKEN.findall(text)) - known)
    if unknown:
        problems.append(f"explanation mentions resources not in the evidence: {unknown}")
    act = answer.get("proposed_action")
    if act:
        if act.get("kind") not in CATALOGUE:
            problems.append(f"proposed_action.kind {act.get('kind')!r} is not in the catalogue")
        if act.get("target_rid") != root:
            problems.append("proposed_action must target the root cause")
    by_id = {t.get("call_id"): t for t in trace if t.get("call_id")}
    cited = [by_id.get(c) or next((t for t in trace if t["tool"] == c), None) for c in answer.get("evidence_tools") or []]
    with_rows = [t for t in cited if t and t["outcome"] in ROWS_OUTCOMES and t["rows"]]
    if not with_rows:
        problems.append("evidence_tools must cite at least one tool call that returned rows")
    if candidates and root != candidates[0] and not any(t.get("by") == "agent" for t in with_rows):
        problems.append("re-ranking needs new evidence from an agent-chosen call")
    return problems
