"""The LLM step (§7.5): the graph decides, the agent investigates and explains, a human acts.

Provider: OpenRouter (OpenAI-compatible /chat/completions with tool calling), behind one
adapter so swapping providers is a config change (D10):
    LLM_API_KEY    OpenRouter key (empty -> LLM step off, template explanation)
    LLM_MODEL      e.g. an OpenRouter model id that supports tool calling
    LLM_BASE_URL   default https://openrouter.ai/api/v1

What makes it an agent, not a summariser:
  - it gets the scorecard + evidence bundle (never the whole graph) and may call up to
    MAX_AGENT_CALLS read tools of its own choosing;
  - every call must carry a `reason`, or it is rejected and not run;
  - its calls land in the trace as by="agent" with the reason, shown "agent-chosen" in the UI;
  - its final JSON answer goes through agent/validator.py; on failure the template wins.
It never writes Cypher, never proposes outside the catalogue, never approves.
"""

import json
import os
import re
import time
import urllib.request

from agent import probe as probe_mod
from agent import validator
from agent.tools import Tools

MAX_AGENT_CALLS = 6
ROW_LIMIT = 8  # rows per tool result sent back to the model (context stays small)

READ_TOOLS = {
    "check_path": ({"from_svc": "string", "to_rid": "string"},
                   "Is the network route for the dependency from_svc -> to_rid permitted? Which firewall rule permits it, or which hop blocks it."),
    "recent_changes": ({"rid": "string", "minutes": "integer"},
                       "Change nodes (CloudTrail or graph diff) on the resource and its 2-hop infrastructure neighbourhood."),
    "probe": ({"rid": "string"},
              "Fixed health checks for the resource: up/error rate/p95 for services, up/CPU for hosts, reachability from every host for databases."),
    "blast_radius": ({"rid": "string", "depth": "integer"}, "Everything upstream that depends on this resource."),
    "path_between": ({"from_rid": "string", "to_rid": "string"}, "Shortest dependency path between two resources."),
    "recall_incidents": ({"alertnames": "array", "candidate_rids": "array"},
                         "Past resolved incidents matched by alert names or root cause."),
    "removed_rules": ({"from_svc": "string", "to_rid": "string"},
                      "On a broken path: which firewall on the target lost a rule that used to permit it (last 30 min)."),
}

SYSTEM = """You are rootgraph's incident investigator. A deterministic pipeline has already walked a
FalkorDB infrastructure graph upward from the alerting resources and scored candidate root causes.
You receive that scorecard and the evidence (each tool call has a call_id).

You may call up to 6 read-only tools to test the ranking, for example to check whether a
high-coverage candidate is actually healthy, or whether a dependency path is blocked. Every tool
call MUST include a short `reason` saying what you are checking and why. You cannot write Cypher,
change anything, or approve fixes.

Finish with ONLY a JSON object, no prose around it:
{"root_cause_rid": "<one of the scored candidates>",
 "explanation": "<2-4 sentences for the on-call engineer; name only resources that appear in the evidence>",
 "evidence_tools": ["<call_id>", ...],
 "proposed_action": {"kind": "restore_firewall_rule" | "restart_service", "target_rid": "<root_cause_rid>"} or null}
Keep the scorecard's top candidate unless a tool result gives clear new evidence against it."""


def _tool_schema(name, params, desc):
    props = {k: ({"type": "array", "items": {"type": "string"}} if t == "array" else {"type": t}) for k, t in params.items()}
    props["reason"] = {"type": "string", "description": "What you are checking and why (required)."}
    required = [k for k, t in params.items() if t != "integer"] + ["reason"]
    return {"type": "function", "function": {"name": name, "description": desc,
                                             "parameters": {"type": "object", "properties": props, "required": required}}}


TOOL_SCHEMAS = [_tool_schema(n, p, d) for n, (p, d) in READ_TOOLS.items()]


class OpenRouterClient:
    def __init__(self, api_key: str, model: str, base_url: str = "https://openrouter.ai/api/v1", timeout: float = 60):
        self.api_key, self.model, self.base_url, self.timeout = api_key, model, base_url.rstrip("/"), timeout

    def chat(self, messages: list, tools: list | None = None, tool_choice: str | None = None) -> dict:
        body = {"model": self.model, "messages": messages, "temperature": 0}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice or "auto"
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=json.dumps(body).encode(), method="POST",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json",
                     "HTTP-Referer": "https://github.com/guranshdeol/graph-incident-responder", "X-Title": "rootgraph"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.load(resp)


def client_from_env():
    key = os.environ.get("LLM_API_KEY", "").strip()
    model = os.environ.get("LLM_MODEL", "").strip()
    if not key or not model:
        return None
    return OpenRouterClient(key, model, os.environ.get("LLM_BASE_URL", "https://openrouter.ai/api/v1"))


def _compact(env: dict) -> dict:
    return {"call_id": env.get("call_id"), "tool": env["tool"], "args": env["args"], "outcome": env["outcome"],
            "rows": env["rows"][:ROW_LIMIT], "paths": env["paths"][:ROW_LIMIT]}


def _bundle(rows: list[dict], trace: list[dict], alerting: list[str]) -> str:
    score = [{k: r[k] for k in ("rank", "rid", "score", "probe", "explains", "evidence", "components")} for r in rows[:6]]
    return json.dumps({"alerting": alerting, "scorecard": score, "evidence": [_compact(t) for t in trace]})


def _parse_final(text: str) -> dict | None:
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


class Agent:
    """One bounded investigation turn. Returns the explain() result the Investigator expects."""

    def __init__(self, client, tools: Tools, probe_source, now=time.time):
        self.client, self.tools, self.probes, self.now = client, tools, probe_source, now

    def _run_tool(self, name: str, args: dict) -> dict:
        a = {k: v for k, v in args.items() if k != "reason"}
        t = self.tools
        if name == "probe":
            return probe_mod.probe(t, self.probes, a["rid"])
        if name == "recent_changes":
            return t.recent_changes(a["rid"], int(a.get("minutes") or 30), now=int(self.now()))
        if name == "removed_rules":
            return t.removed_rules(a["from_svc"], a["to_rid"], now=int(self.now()))
        if name == "blast_radius":
            return t.blast_radius(a["rid"], int(a.get("depth") or 2))
        if name == "path_between":
            return t.path_between(a["from_rid"], a["to_rid"])
        if name == "recall_incidents":
            return t.recall_incidents(list(a.get("alertnames") or []), list(a.get("candidate_rids") or []))
        if name == "check_path":
            return t.check_path(a["from_svc"], a["to_rid"])
        raise KeyError(name)

    def explain(self, rows: list[dict], trace: list[dict], template: str, alerting: list[str]) -> dict:
        tokens_in = tokens_out = 0
        agent_trace: list[dict] = []
        messages = [{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": _bundle(rows, trace, alerting)}]
        final = None
        for _turn in range(MAX_AGENT_CALLS + 2):
            calls_left = MAX_AGENT_CALLS - len(agent_trace)
            resp = self.client.chat(messages, TOOL_SCHEMAS if calls_left > 0 else None)
            usage = resp.get("usage") or {}
            tokens_in += usage.get("prompt_tokens", 0)
            tokens_out += usage.get("completion_tokens", 0)
            msg = resp["choices"][0]["message"]
            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                final = _parse_final(msg.get("content") or "")
                break
            messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": tool_calls})
            for tc in tool_calls:
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                reason = str(args.get("reason") or "").strip()
                if name not in READ_TOOLS:
                    result = {"error": f"unknown tool {name}"}
                elif not reason:
                    result = {"error": "rejected: every tool call needs a `reason`"}
                elif len(agent_trace) >= MAX_AGENT_CALLS:
                    result = {"error": f"limit of {MAX_AGENT_CALLS} tool calls reached; give your final answer"}
                else:
                    try:
                        env = self._run_tool(name, args)
                    except Exception as exc:
                        env = {"tool": name, "args": args, "outcome": "error", "rows": [{"error": str(exc)}],
                               "paths": [], "cypher": None, "ms": 0}
                    env.update({"by": "agent", "reason": reason[:300], "call_id": f"a{len(agent_trace) + 1}"})
                    agent_trace.append(env)
                    result = _compact(env)
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": json.dumps(result)})
        full_trace = trace + agent_trace
        problems = validator.validate(final, rows, full_trace) if final is not None else ["no parsable JSON answer"]
        accepted = not problems
        return {
            "explanation": final["explanation"] if accepted else template,
            "explained_by": "llm" if accepted else "template (validator: " + "; ".join(problems)[:300] + ")",
            "root_cause_rid": final["root_cause_rid"] if accepted else None,
            "agent_trace": agent_trace,
            "tokens_in": tokens_in, "tokens_out": tokens_out, "agent_calls": len(agent_trace),
            "llm_answer": final,
        }
