# How to check rootgraph on the site

Two pages, same UI:

| Page | URL | What it is |
|---|---|---|
| Public sandbox | https://172-232-86-149.sslip.io | Synthetic estate, open to anyone (judges). Fixes only change the graph. |
| Live AWS | https://172-232-86-149.sslip.io/live/ | The real AWS estate in Sydney. Needs the operator token (`ADMIN_TOKEN` in the server's `.env`). Fixes run on real AWS. |

## 1. Sandbox (2 minutes, no token)

1. Open https://172-232-86-149.sslip.io.
2. Click **S1 Security-group rule revoked**. "Investigating…" shows at once; the result lands in ~25 s (the free LLM verifies the ranking).
3. Read, top to bottom: the dark **root cause** card (`sg-db`, with the LLM explanation), **Proposed fix** (exact rule, who gains access, rollback, AWS CLI), **Graph evidence** (broken path in coral, top suspect in marigold), **Scorecard** (host-1 covers every alert but is healthy, so it scores 1.0), **Tool trace** (every Cypher query; the two `agent-chosen` rows show the LLM's own calls and its reasons).
4. Click **Approve and execute** → the incident turns **resolved**.
5. Click **S4 Repeat of S1 (memory)** → the root cause card says "Seen before in INC-…", sg-db scores +1, and the fix card says "the same fix resolved INC-… in N s".
6. Try **S5 Two faults at once** → "Multiple likely causes" banner and one proposal per cause. **Reset sandbox** starts over.

## 2. Live AWS (5 minutes, operator token)

1. Open https://172-232-86-149.sslip.io/live/ and paste the operator token into the field in the top bar (it is remembered in that browser).
2. You'll see the real past incidents (resolved ones are the live memory).
3. Click **LIVE Break it for real: revoke rule A** and confirm. A revoke-only IAM user (`rootgraph-chaos`) removes the rule that lets host-1 reach the RDS database; it is the "human who makes the bad change". The button refuses while an incident is open, and allows one fault per 5 minutes.
4. Within ~40 s a new incident appears (real Prometheus/Alertmanager alerts). Click it. It says "Investigating…" until the whole alert group is in and the LLM has checked it (~1 minute).
5. Check: root cause = the db security group (`sg-09a1…`), host-1 healthy at 1.0, "Seen before in INC-…" (memory from earlier runs), and the proposed fix restoring the exact removed rule.
6. Type your name and click **Approve and execute**. The scoped executor re-adds the rule on AWS; the page turns **resolved** when the alerts clear and the checks pass (usually 1–2 minutes).
7. If anything gets stuck, put the rule back by hand from the server: `AWS_PROFILE=rootgraph-admin uv run python -m demo.faults.restore_all`.

## 3. Under the hood (optional, server)

- Graph in FalkorDB Browser: `ssh -L 3000:localhost:3000 root@172.232.86.149`, open http://localhost:3000, graph `ops_live` or `ops_sandbox`.
- Logs: `docker compose logs -f api-live discovery ingester` in `/opt/rootgraph/app`.
- Real Prometheus: http://13.211.114.247:9090 is reachable only from the server (security group), e.g. `curl http://13.211.114.247:9090/api/v1/alerts`.
- Tests: `set -a; . ./.env; set +a; FALKORDB_HOST=localhost PROMETHEUS_URL= LLM_API_KEY= uv run pytest -q`.

## 4. Cost and teardown

The AWS estate costs about **$0.10/hour** (2× t3.small, db.t4g.micro RDS, 2 public IPv4, storage), from the $100 Free-plan credit; a $10 budget alert emails the team at $8. Tear down after judging:

```bash
AWS_PROFILE=rootgraph-admin uv run python -m demo.aws.estate down
```

Then delete the `rootgraph-admin` access key in IAM. The Linode sandbox can stay up for judging.
