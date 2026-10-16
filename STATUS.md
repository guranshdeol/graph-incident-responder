# Status (updated Sat 17 Oct 2026, ~02:00 IST)

## Done and running

- Control plane on the Linode: Docker, ufw (22/80/443) + Linode Cloud Firewall, Caddy TLS on `172-232-86-149.sslip.io`, FalkorDB (password, localhost only), nightly backup (03:00 IST, `/opt/rootgraph/backups`, keep 14).
- Investigation pipeline, scoring, action catalogue + approval gate, memory, validator; S1–S5 fixture oracles pass. Baseline: coverage-only 2/5, scorecard 5/5 (`docs/evaluation.md`).
- Public sandbox UI (Notion-style design, `docs/DESIGN.md`): inject S1–S5, approve, memory recall. Inject runs in the background; rate limited (15 s).
- LLM step via OpenRouter: `LLM_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free,nvidia/nemotron-3-super-120b-a12b:free`. Ultra's provider was down on 17 Oct, so Super answers; ~25 s per investigation, 2 agent-chosen calls on S1.
- Live-AWS code, all tested against moto (not yet against a real account): `demo/aws/estate.py up|status|down`, discovery + graph diff, CloudTrail → SQS ingester, AWS executor, SSM host deploy, S1/S2/S3 fault scripts, `api-live` at `/live/`.
- Demo stack verified for real on this server (local): stopping payments produced real alerts → incident → payments top with a live unhealthy probe.
- MCP server (`agent/mcp_server.py`, 10 read-only tools, stdio verified). README, `docs/graph.md` (all queries), `docs/evaluation.md`.
- 75 tests pass.

## Next: live AWS (needs the teammate with the AWS account)

Follow `demo/aws/setup.md`. In short:
1. `aws configure --profile rootgraph-admin` on the server (their admin keys; stays in `~/.aws`).
2. `AWS_PROFILE=rootgraph-admin uv run python -m demo.aws.estate up --email <email>` (~15 min).
3. `cat demo/aws/credentials.env >> .env`.
4. Wait ~3 min, then `AWS_PROFILE=rootgraph-admin uv run python -m demo.aws.deploy_hosts`.
5. Set `PROMETHEUS_URL_LIVE=http://<host-1 public IP>:9090` in `.env`; `docker compose --profile aws up -d --build api-live discovery ingester`.
6. Check `ops_live` in FalkorDB Browser; run S1 for real (`python -m demo.faults.s1_revoke_sg`), approve in `/live/` with `ADMIN_TOKEN`; record the real CloudTrail SQS message into `ingest/fixtures/`.
7. Record the demo video from a real run (plan §14 outline).

Things that may differ from moto on a real account: CloudTrail→EventBridge latency (the graph diff covers it), exact event payload shapes, Docker install time on the hosts, SSM agent registration delay.

## Still open

- SSH hardening: teammates' public keys into `/root/.ssh/authorized_keys`, then `PasswordAuthentication no`.
- Blog post draft: `docs/blog.md` (facts checked; review the wording before publishing; side prize).
- Submission: demo video, submission form (name both tracks), AI-assistance disclosure is in the README.
- After submitting: `python -m demo.aws.estate down`, delete the admin key, rotate `WEBHOOK_TOKEN`/`ADMIN_TOKEN`/OpenRouter key; keep the Linode sandbox up for judging.
