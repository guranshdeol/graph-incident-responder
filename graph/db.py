"""FalkorDB client, graph selection and the Cypher query loader.

Connection comes from the environment:
  FALKORDB_HOST (default localhost; compose sets "falkordb" for the api container)
  FALKORDB_PORT (default 6379)
  FALKORDB_PASSWORD

Every query the agent runs lives in graph/queries/<name>.cypher and is loaded
by name. Nothing here builds Cypher from strings (D4).
"""

import os
from functools import cache
from pathlib import Path

from falkordb import FalkorDB, Graph

GRAPH_DIR = Path(__file__).resolve().parent
QUERIES_DIR = GRAPH_DIR / "queries"
SCHEMA_FILE = GRAPH_DIR / "schema.cypher"
FIXTURES_DIR = GRAPH_DIR / "fixtures"

# Only these graph names may be selected. ops_synthetic is a stretch goal.
GRAPHS = {"ops_live", "ops_sandbox", "ops_synthetic", "ops_test"}


@cache
def client() -> FalkorDB:
    return FalkorDB(
        host=os.environ.get("FALKORDB_HOST", "localhost"),
        port=int(os.environ.get("FALKORDB_PORT", "6379")),
        password=os.environ.get("FALKORDB_PASSWORD") or None,
    )


def graph(name: str | None = None) -> Graph:
    """Select a graph. Defaults to GRAPH_NAME, else the sandbox graph."""
    name = name or os.environ.get("GRAPH_NAME") or os.environ.get("GRAPH_SANDBOX", "ops_sandbox")
    if name not in GRAPHS:
        raise ValueError(f"unknown graph {name!r}; expected one of {sorted(GRAPHS)}")
    return client().select_graph(name)


def _strip_comments(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))


def statements(path: Path) -> list[str]:
    """Split a multi-statement .cypher file (schema, fixtures) on ';'."""
    return [s.strip() for s in _strip_comments(path.read_text()).split(";") if s.strip()]


@cache
def query(name: str) -> str:
    """Load graph/queries/<name>.cypher with comment lines removed."""
    path = QUERIES_DIR / f"{name}.cypher"
    if not path.is_file():
        raise KeyError(f"no query named {name!r} in {QUERIES_DIR}")
    return _strip_comments(path.read_text()).strip()


def query_names() -> list[str]:
    return sorted(p.stem for p in QUERIES_DIR.glob("*.cypher"))


def run(g: Graph, name: str, params: dict | None = None):
    """Run a named query; returns (header, rows) with rows as dicts."""
    res = g.query(query(name), params or {})
    header = [h[1] if isinstance(h, (list, tuple)) else h for h in res.header]
    return header, [dict(zip(header, row)) for row in res.result_set]


def apply_schema(g: Graph) -> None:
    for stmt in statements(SCHEMA_FILE):
        try:
            g.query(stmt)
        except Exception as exc:  # index already exists on a reused graph
            if "already indexed" not in str(exc).lower() and "already exists" not in str(exc).lower():
                raise


def load_fixture(g: Graph, name: str = "estate") -> None:
    """Wipe the graph and load graph/fixtures/<name>.cypher plus the schema."""
    try:
        g.delete()
    except Exception:  # graph didn't exist yet
        pass
    for stmt in statements(FIXTURES_DIR / f"{name}.cypher"):
        g.query(stmt)
    apply_schema(g)
