# Working on rootgraph (read this first)

Hackathon project: incident responder over a FalkorDB graph (WeMakeDevs × FalkorDB, deadline **Sun 18 Oct 2026 23:59 IST, submit by 22:00**).
Read `STATUS.md` for where things stand, `DECISIONS.md` for why things are the way they are, `plan.md` for the original plan.

## Where things are

- This server (Linode, Mumbai, 172.232.86.149) is the control plane and the only dev machine. Agents work one at a time, directly in `/opt/rootgraph/app` on `main`.
- Public sandbox: https://172-232-86-149.sslip.io (API container `app-api-1`, graph `ops_sandbox`). Live estate: `/live/` (`api-live`, compose profile `aws`, graph `ops_live`).
- GitHub: `guranshdeol/graph-incident-responder` (public). The server pushes with a repo-only deploy key.

## Rules

- **Never print or commit secrets.** `.env`, `demo/aws/credentials.env`, `demo/aws/state.json`, `demo/build/` hold tokens and keys; they are gitignored. Show env files only with values masked. gitleaks runs on every commit and push; don't bypass it.
- **Don't edit `.env` with an editor left open**: it was nearly truncated once by stale vim sessions. Back it up first (`install -m 600 .env /root/env.backup-$(date -u +%Y%m%dT%H%M%S)`).
- **All Cypher lives in `graph/queries/*.cypher`** (one file per query, a `//` header with purpose and params). The LLM never writes Cypher. A new query also goes into `docs/graph.md` (the submission requires every query listed).
- **Tests before every commit** (FalkorDB must be running; the suite uses the `ops_test` graph only):
  `set -a; . ./.env; set +a; FALKORDB_HOST=localhost PROMETHEUS_URL= LLM_API_KEY= uv run pytest -q`
- **Deploy after code changes:** `docker compose up -d --build api` (add `--profile aws ... api-live discovery ingester` when live is up). Changing `.env` recreates containers; that is fine.
- After deploying, reset the public sandbox so judges start clean: `curl -X POST https://172-232-86-149.sslip.io/api/sandbox/reset`.
- One line per non-obvious decision in `DECISIONS.md`. Commit messages end with the Co-Authored-By line the session provides.
- Don't touch AWS without the team's admin profile; the runbook is `demo/aws/setup.md`.

## Map

`graph/` queries, schema, fixtures + scenarios · `agent/` tools, investigate, scoring, actions, memory, llm, validator, probe, sandbox, mcp_server · `ingest/` alerts, AWS discovery, CloudTrail ingester, worker · `api/` FastAPI + `static/index.html` (UI, follows `docs/DESIGN.md`) · `demo/` service, Prometheus rules, render, AWS estate/deploy, faults · `eval/` baseline · `ops/` backup · `tests/`.
