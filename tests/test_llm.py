"""The LLM agent loop with a scripted fake model: agent-chosen calls need a reason, are capped,
show in the trace, and the validator decides whether the LLM's answer or the template goes out.

Run: set -a; . ./.env; set +a; FALKORDB_HOST=localhost uv run pytest
"""

import json

import pytest

from agent import llm
from agent.investigate import Investigator
from agent.sandbox import Scenario
from agent.tools import Tools
from graph import db

NOW = 1792200000


class FakeModel:
    """Replays scripted assistant messages; records what it was sent."""

    def __init__(self, script):
        self.script, self.sent = list(script), []

    def chat(self, messages, tools=None, tool_choice=None):
        self.sent.append({"messages": json.loads(json.dumps(messages)), "tools": tools})
        msg = self.script.pop(0)
        return {"choices": [{"message": msg}], "usage": {"prompt_tokens": 1000, "completion_tokens": 50}}


def call(name, **args):
    return {"role": "assistant", "content": "", "tool_calls": [
        {"id": f"tc-{name}-{len(args)}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


def final(**answer):
    return {"role": "assistant", "content": json.dumps(answer)}


@pytest.fixture
def g():
    graph = db.graph("ops_test")
    db.load_fixture(graph)
    yield graph
    graph.delete()


def run_s1(g, script):
    sc = Scenario(g, "s1", NOW)
    inc = sc.inject()["incident_id"]
    model = FakeModel(script)
    agent = llm.Agent(model, Tools(g), sc.probes, now=lambda: NOW)
    rep = Investigator(g, sc.probes, now=lambda: NOW, explain=agent).run(inc)
    return rep, model, inc


GOOD = dict(root_cause_rid="sg-db",
            explanation="sg-db lost the rule that let host i-host1 reach rds:orders-db on 5432, so svc:payments fails.",
            evidence_tools=["a1"], proposed_action={"kind": "restore_firewall_rule", "target_rid": "sg-db"})


def test_agent_call_with_reason_is_traced_and_answer_accepted(g):
    rep, model, inc = run_s1(g, [
        call("probe", rid="i-host1", reason="host-1 covers the most alerts; is it actually healthy?"),
        final(**GOOD)])
    assert rep["explained_by"] == "llm" and rep["explanation"] == GOOD["explanation"]
    agent_calls = [t for t in rep["trace"] if t["by"] == "agent"]
    assert len(agent_calls) == 1 and agent_calls[0]["tool"] == "probe"
    assert agent_calls[0]["reason"].startswith("host-1 covers") and agent_calls[0]["call_id"] == "a1"
    assert rep["llm"]["tokens_in"] == 2000 and rep["llm"]["tokens_out"] == 100 and rep["llm"]["agent_calls"] == 1
    res = g.query("MATCH (i:Incident {id: $id}) RETURN i.tokens_in, i.agent_calls", {"id": inc}).result_set
    assert res == [[2000, 1]]
    # the model got the scorecard, not the graph, and every pipeline call has a citable id
    bundle = json.loads(model.sent[0]["messages"][1]["content"])
    assert bundle["scorecard"][0]["rid"] == "sg-db" and all(e["call_id"].startswith("p") for e in bundle["evidence"])


def test_call_without_reason_is_rejected_and_not_run(g):
    rep, model, _ = run_s1(g, [call("probe", rid="i-host1"), final(**{**GOOD, "evidence_tools": ["p5"]})])
    assert [t for t in rep["trace"] if t["by"] == "agent"] == []
    tool_reply = model.sent[1]["messages"][-1]
    assert tool_reply["role"] == "tool" and "needs a `reason`" in tool_reply["content"]


def test_unknown_resource_in_explanation_falls_back_to_template(g):
    rep, _, _ = run_s1(g, [call("probe", rid="i-host1", reason="check host"),
                           final(**{**GOOD, "explanation": "sg-0deadbeef dropped the traffic."})])
    assert rep["explained_by"].startswith("template (validator:") and "sg-0deadbeef" in rep["explained_by"]
    assert rep["explanation"].startswith("sg-db is the most likely root cause")


def test_rerank_without_agent_evidence_is_rejected(g):
    rep, _, _ = run_s1(g, [final(root_cause_rid="i-host1", explanation="i-host1 is the cause.",
                                 evidence_tools=["p1"], proposed_action=None)])
    assert "re-ranking needs new evidence" in rep["explained_by"] and rep["top"] == "sg-db"


def test_tool_calls_are_capped(g):
    script = [call("probe", rid="i-host1", reason=f"look {i}") for i in range(llm.MAX_AGENT_CALLS + 1)] + [final(**GOOD)]
    rep, model, _ = run_s1(g, script)
    assert rep["llm"]["agent_calls"] == llm.MAX_AGENT_CALLS
    assert model.sent[-1]["tools"] is None  # after the cap the model is not offered tools any more


def test_provider_error_keeps_pipeline_answer(g):
    class Down:
        def chat(self, *a, **k):
            raise TimeoutError("openrouter timed out")
    sc = Scenario(g, "s1", NOW)
    inc = sc.inject()["incident_id"]
    rep = Investigator(g, sc.probes, now=lambda: NOW, explain=llm.Agent(Down(), Tools(g), sc.probes)).run(inc)
    assert rep["top"] == "sg-db" and rep["explained_by"].startswith("template (llm error")
    assert rep["proposals"][0]["action"]["kind"] == "restore_firewall_rule"


def test_client_from_env_needs_key_and_model(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "k")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    assert llm.client_from_env() is None
    monkeypatch.setenv("LLM_MODEL", "some/model")
    assert isinstance(llm.client_from_env(), llm.OpenRouterClient)
