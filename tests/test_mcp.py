"""The MCP server exposes only read tools, and they answer from the graph.

Run: set -a; . ./.env; set +a; FALKORDB_HOST=localhost uv run pytest
"""

import asyncio
import importlib
import json

import pytest

from graph import db

EXPECTED = {"resolve", "correlate_alerts", "check_path", "removed_rules", "recent_changes", "blast_radius",
            "path_between", "dependencies", "recall_incidents", "load_bearing", "changes_since", "detached_on_path"}


@pytest.fixture
def mcp_mod(monkeypatch):
    monkeypatch.setenv("MCP_GRAPH", "ops_test")
    g = db.graph("ops_test")
    db.load_fixture(g)
    import agent.mcp_server as m
    yield importlib.reload(m)
    g.delete()


def test_only_read_tools(mcp_mod):
    tools = asyncio.run(mcp_mod.server.list_tools())
    assert {t.name for t in tools} == EXPECTED
    assert all(t.annotations.read_only_hint and not t.annotations.destructive_hint for t in tools)


def test_tool_answers_from_graph(mcp_mod):
    res = asyncio.run(mcp_mod.server.call_tool("check_path", {"from_svc": "svc:payments", "to_rid": "rds:orders-db"}))
    env = json.loads(res.content[0].text)
    assert env["tool"] == "check_path" and env["rows"][0]["permitted"] is True and env["cypher"].startswith("MATCH")
    res = asyncio.run(mcp_mod.server.call_tool("correlate_alerts", {"alert_rids": ["svc:orders", "svc:reports"], "k": 1}))
    assert json.loads(res.content[0].text)["rows"][0]["candidate"] in {"i-host2", "rds:orders-db"}
