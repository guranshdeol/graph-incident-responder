# How to check rootgraph

One console: https://172-232-86-149.sslip.io. Sign in with your account (team: `demo/accounts.txt` on the server; judges: the account in the submission). Everything is behind sign-in.

Two environments, switcher at the top left:

| Environment | What it is | What approving a fix does |
|---|---|---|
| **Production** | The real AWS estate in Sydney (2 EC2 hosts, RDS, security groups, CloudTrail, Prometheus) | Runs the undo on AWS with the undo-only executor IAM user |
| **Staging** | A simulated copy of the same estate, for fault drills | Changes the graph only |

## 1. Look around (2 minutes)

- **Overview:** open incidents, fixes awaiting approval, median time to resolve, changes in the last 24 h, the most load-bearing resources (PageRank over the graph).
- **Incidents:** open one. **Summary** has the root cause in one sentence, the proposed fix and the timeline. The other tabs: **Timeline** (the change that caused it is marked), **Evidence** (the scorecard), **Graph** (this incident or the whole estate; click a node), **Agent trace** (every fixed query; filter to the AI's own calls).
- **Changes:** every change in the account, with who made it (people, rootgraph, discovery).
- **Actions:** the audit log of every proposed fix, who approved it and whether verification passed.
- **Topology:** the infrastructure graph. Click a resource for its blast radius, dependencies, security groups, recent changes and past incidents.
- **Memory:** resolved incidents rootgraph learned from, and how often later incidents recalled them.
- **Integrations:** FalkorDB, AWS discovery, CloudTrail, Prometheus, the AI models and what the executor may and may not do.

## 2. Staging: run a fault drill (2 minutes)

1. Switch to **Staging**. Click **Simulate incident**, then **Security-group rule revoked**, then **Run drill**.
2. The incident opens and fills in within ~30 s. Read the Summary, then click **Approve and execute**: the dialog shows the exact AWS CLI and rollback. Approve.
3. The incident turns **resolved** and appears under **Memory**. Run **Repeat of S1** next: the root cause card says "Seen before" and the fix is pre-filled.
4. **Simulate incident → Reset staging** starts over.

## 3. Production: break the real account by hand (5 minutes)

Make **one** change in the AWS console (account 360908956947, region **Sydney ap-southeast-2**):

| Fault | Where in the console | What rootgraph should conclude | Its fix |
|---|---|---|---|
| Edit a rule | EC2 → Security Groups → `rootgraph-db` → Inbound rules → Edit: change the 5432 rule whose source is `rootgraph-host1` to **5433** → Save | root cause `rootgraph-db`; "rule edited 5432 → 5433" | edit it back |
| Delete a rule | same screen, delete that 5432 rule | root cause `rootgraph-db`; the exact removed rule | re-add that rule |
| Detach a security group | RDS → `orders-db` → Modify → Security groups: remove `rootgraph-db`, add `default` → Apply immediately | root cause `orders-db`; "security group detached" | re-attach `rootgraph-db` |
| Stop a server | EC2 → Instances → `rootgraph-host2` → Instance state → Stop. (**Never host-1**: it runs Prometheus.) | root cause host-2, stopped; its services are victims | start the instance |
| Stop a container | On a host: `docker stop payments` (from the server, see below) | root cause `payments`; it is down, not a network fault | `docker start payments` |

To stop a container from the server: `cd /opt/rootgraph/app && AWS_PROFILE=rootgraph-admin uv run python -c "import boto3,json;st=json.load(open('demo/aws/state.json'));boto3.client('ssm','ap-southeast-2').send_command(InstanceIds=[st['host1']],DocumentName='AWS-RunShellScript',Parameters={'commands':['docker stop payments']})"`

1. Within 1–3 minutes the change shows under **Changes** and an incident opens under **Incidents** (the sidebar badge counts open ones).
2. Open it: the Summary names the cause and the Timeline marks your change. Approve the fix; Production verification waits for the real alerts to clear (1–5 minutes).
3. No console handy? **Fault drill** (top right, Production) revokes rule A with a revoke-only IAM user. One drill per 5 minutes, and not while an incident is open.
4. If anything gets stuck: `AWS_PROFILE=rootgraph-admin uv run python -m demo.faults.restore_all` on the server undoes all of the above.

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
