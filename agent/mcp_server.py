"""rootgraph's read tools over MCP (Track 01: "tool selection through MCP").

Any MCP client (Claude Desktop, Claude Code, ...) can investigate the same FalkorDB graph
with the same fixed, human-written Cypher the pipeline uses. Every tool is read-only and
returns the §7.2 envelope (tool, args, outcome, rows, paths, cypher, ms). There is no
write, no free-form Cypher and no approval tool here: that is what separates this from the
official FalkorDB MCP server (decision D8).

    uv run python -m agent.mcp_server          stdio (default)
    MCP_GRAPH=ops_live uv run python -m agent.mcp_server

Needs FALKORDB_HOST / FALKORDB_PORT / FALKORDB_PASSWORD (e.g. through the SSH tunnel).
"""

import json
import os

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from agent.tools import Tools
from graph import db

GRAPH = os.environ.get("MCP_GRAPH") or os.environ.get("GRAPH_SANDBOX", "ops_sandbox")
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

server = MCPServer(
    name="rootgraph",
    instructions=("Read-only tools over rootgraph's FalkorDB infrastructure graph. Start with "
                  "correlate_alerts on the alerting resources, then check_path / removed_rules / "
                  "recent_changes on the top candidates. outcome 'not_in_graph' means the graph does "
                  "not model it, NOT that it is healthy."),
)


def _tools() -> Tools:
    return Tools(db.graph(GRAPH))


def _out(env: dict) -> str:
    return json.dumps(env, default=str)


@server.tool(annotations=READ_ONLY)
def resolve(name_or_rid: str) -> str:
    """Does this resource exist in the graph? Returns its canonical rid and kind labels."""
    return _out(_tools().resolve(name_or_rid))


@server.tool(annotations=READ_ONLY)
def correlate_alerts(alert_rids: list[str], k: int = 5) -> str:
    """Walk upward from the alerting resources: candidates ranked by how many alerting nodes they explain."""
    return _out(_tools().correlate_alerts(alert_rids, k))


@server.tool(annotations=READ_ONLY)
def check_path(from_svc: str, to_rid: str) -> str:
    """Is the network route for the dependency from_svc -> to_rid permitted by the target's security groups?"""
    return _out(_tools().check_path(from_svc, to_rid))


@server.tool(annotations=READ_ONLY)
def removed_rules(from_svc: str, to_rid: str, minutes: int = 30) -> str:
    """On a broken path: which firewall on the target lost a rule that used to permit it, and when."""
    return _out(_tools().removed_rules(from_svc, to_rid, minutes))


@server.tool(annotations=READ_ONLY)
def recent_changes(rid: str, minutes: int = 30) -> str:
    """CloudTrail and graph-diff changes on the resource and its 2-hop infrastructure neighbourhood."""
    return _out(_tools().recent_changes(rid, minutes))


@server.tool(annotations=READ_ONLY)
def blast_radius(rid: str, depth: int = 2) -> str:
    """Everything upstream that depends on this resource (depth 1-4)."""
    return _out(_tools().blast_radius(rid, depth))


@server.tool(annotations=READ_ONLY)
def path_between(from_rid: str, to_rid: str) -> str:
    """Shortest dependency path between two resources (algo.SPpaths)."""
    return _out(_tools().path_between(from_rid, to_rid))


@server.tool(annotations=READ_ONLY)
def dependencies(rid: str) -> str:
    """What this service calls (declared DEPENDS_ON edges)."""
    return _out(_tools().dependencies(rid))


@server.tool(annotations=READ_ONLY)
def recall_incidents(alertnames: list[str], candidate_rids: list[str]) -> str:
    """Past resolved incidents matched by alert names or root cause, with the fix that worked."""
    return _out(_tools().recall_incidents(alertnames, candidate_rids))


@server.tool(annotations=READ_ONLY)
def changes_since(minutes: int = 30) -> str:
    """Every infrastructure change in the account (CloudTrail + discovery diff) in the last N minutes, with who made it."""
    return _out(_tools().changes_since(minutes))


@server.tool(annotations=READ_ONLY)
def detached_on_path(from_svc: str, to_rid: str, minutes: int = 30) -> str:
    """On a broken path: was a security group detached from the dependency's host or target?"""
    return _out(_tools().detached_on_path(from_svc, to_rid, minutes))


@server.tool(annotations=READ_ONLY)
def load_bearing(limit: int = 10) -> str:
    """The most load-bearing resources by PageRank over DEPENDS_ON."""
    return _out(_tools().load_bearing(limit))


if __name__ == "__main__":
    server.run("stdio")
