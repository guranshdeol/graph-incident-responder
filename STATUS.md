# Status (updated Sat 17 Oct 2026, ~19:30 IST)

## Done and running

- **Control plane (Linode, Mumbai):** Caddy TLS `172-232-86-149.sslip.io`, FalkorDB (password, localhost only), nightly backup (03:00 IST).
  - `/` public sandbox (`api`, `ops_sandbox`).
  - `/live/` live AWS (`api-live`, `ops_live`, operator token), plus `discovery` + `ingester` workers (compose profile `aws`).
- **Live AWS estate (Sydney, ap-southeast-2; the team's AWS Organization allows only this region):** VPC, 3 SGs (rules A/B), host-1 + host-2 (EC2, demo stack via SSM), orders-db (RDS), CloudTrail → EventBridge → SQS, IAM users discovery / ingester / executor / chaos (revoke-only, for the site's Break-it button). Budget: $10/month, alert at 80 % to shahbhavyasp@gmail.com and guranshdeol01@gmail.com. Cost ≈ $0.10/h from the $100 Free-plan credit.
- **Real S1 runs** (README "Live on real AWS"): root cause correct (7.75 with memory), executor fix verified, 162 s from incident open to resolved. Five live-only bugs found and fixed (DECISIONS.md).
- **Changes made by hand, verified on real AWS:** container stopped (93 s), security group detached from RDS (52 s), host-2 stopped (64 s), rule edited 5432→5433 (verified). The live page shows every change in the account and a per-incident timeline marking the change that caused it. Sandbox has the same as S6–S8.
- Pipeline, scoring, memory, LLM agent (OpenRouter Nemotron, Ultra → Super fallback), validator, MCP server, evaluation (coverage-only 2/5 vs scorecard 5/5). 86 tests pass.
- Docs: README, docs/graph.md (all queries), docs/evaluation.md, docs/CHECKING.md (how to check on the site), docs/blog.md (draft).

## How to check it

docs/CHECKING.md. Console at https://172-232-86-149.sslip.io, sign-in required (accounts in `demo/accounts.txt` on the server: guransh, bhavya, judge). Staging: Simulate incident → approve. Production: change the AWS account by hand (or Fault drill) → approve.

## Still open

- **Submission:** give judges the `judge` account (from `demo/accounts.txt`) in the submission form, not in the repo.
- **Video:** record on the new console (S14 stills and any UI shots must be recaptured; old capture scripts target the old page).

- **Demo video (last, by team decision):** project in `/opt/rootgraph/video/rootgraph-demo` (skill `deol-youtube-explainer-video`, `. /opt/rootgraph/video/env.sh` first). 16 scenes built incl. S14 from real AWS screenshots; lint clean at ~6:45. Left: S14 voice (needs the host's Voicebox tunnel: `ssh -N -R 17493:127.0.0.1:17493 root@172.232.86.149` on the laptop), cut-d render, Opus critic round, 60 fps master (~45 min CPU), thumbnail/chapters/copy.
- SSH hardening (teammates' public keys, then `PasswordAuthentication no`); bots are guessing the root password.
- Replace the hand-written CloudTrail sample in `ingest/fixtures/` with a recorded event (the real ones parse correctly; the ingester doesn't keep raw bodies).
- Submission form: both tracks, video link, repo, sandbox URL.
- After judging: `AWS_PROFILE=rootgraph-admin uv run python -m demo.aws.estate down`, delete the admin access key, rotate WEBHOOK_TOKEN / ADMIN_TOKEN / OpenRouter key.
