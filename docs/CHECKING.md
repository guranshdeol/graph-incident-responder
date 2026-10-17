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

## 2. Live AWS: break it by hand (operator token)

The point: nobody tells rootgraph what was changed. Someone changes the real AWS account the way people
really do (console click, CLI, `docker stop`), and rootgraph has to find **that** change on its own:
CloudTrail and the discovery diff land in the graph, alerts arrive from Prometheus, and the agent works
out which change explains them.

1. Open https://172-232-86-149.sslip.io/live/ and paste the operator token into the top bar (remembered in that browser).
2. Keep the page open. The left column, **What changed in the account**, lists every change from CloudTrail and discovery in the last 3 hours, with who made it.
3. Make **one** change in the AWS console (account 360908956947, region **Sydney ap-southeast-2**). Pick any:

| Fault | Where in the console | What rootgraph should conclude | Its fix |
|---|---|---|---|
| Edit a rule | EC2 → Security Groups → `rootgraph-db` → Inbound rules → Edit: change the 5432 rule whose source is `rootgraph-host1` to **5433** → Save | root cause `rootgraph-db`; "rule edited 5432 → 5433" | put the rule back to 5432 |
| Delete a rule | same screen, delete that 5432 rule | root cause `rootgraph-db`; the exact removed rule | re-add that rule |
| Detach a security group | RDS → `orders-db` → Modify → Security groups: remove `rootgraph-db`, add `default` → Apply immediately | root cause `orders-db`; "security group detached" | re-attach `rootgraph-db` |
| Stop a server | EC2 → Instances → `rootgraph-host2` → Instance state → Stop. (**Never host-1**: it runs Prometheus.) | root cause host-2, stopped; its services are victims, not causes | start the instance |
| Stop a container | On a host: `docker stop payments` (or from the server, see below) | root cause `payments`; it is down, not a network fault | `docker start payments` |

   To stop a container from the server: `cd /opt/rootgraph/app && AWS_PROFILE=rootgraph-admin uv run python -c "import boto3,json;st=json.load(open('demo/aws/state.json'));boto3.client('ssm','ap-southeast-2').send_command(InstanceIds=[st['host1']],DocumentName='AWS-RunShellScript',Parameters={'commands':['docker stop payments']})"`

4. Within 1–3 minutes the change appears under **What changed** (CloudTrail takes 1–3 min; discovery polls every 60 s) and a new incident opens from the real alerts. Click it.
5. Read the **What happened** timeline (change → alerts → root cause), then the root-cause card, the scorecard and the tool trace. The proposed fix undoes exactly the change you made.
6. Type your name and click **Approve and execute**. rootgraph's executor can only undo (re-add a rule, revert an edit, re-attach a group, start an instance, start a container). The page turns **resolved** once the alerts clear and the checks pass: 1–2 minutes for rules and containers, 2–5 minutes for RDS and a stopped server.
7. Backup if no console is handy: the **BACKUP Break it for me** button deletes rule A with a revoke-only IAM user. It refuses while an incident is open and allows one fault per 5 minutes.
8. If anything gets stuck, put everything back from the server: `AWS_PROFILE=rootgraph-admin uv run python -m demo.faults.restore_all` (undoes all of the above; safe to run any time).

One change at a time; let each incident resolve before the next.

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
