# Live AWS setup (runbook)

Everything below runs **on the rootgraph server** in `/opt/rootgraph/app`. Region: `ap-south-1`.
Expected cost: well under $5 for the weekend (2× t3.small, 1× db.t4g.micro, no NAT gateway).
The code is already tested against moto (`tests/test_aws.py`); today is only credentials and running.

## 0. One-time: admin credentials for the setup script

Use **your own** IAM user with admin rights (this is the "human" who also plays the person making the bad change in S1). On the server:

```bash
uv run --with awscli aws configure --profile rootgraph-admin
```

Enter the access key, the secret, region `ap-south-1` and output `json`. These stay in `~/.aws/` on the server and are never put in `.env` or the repo.

## 1. Create the estate (~15 min, mostly waiting for RDS)

```bash
AWS_PROFILE=rootgraph-admin uv run python -m demo.aws.estate up --email YOUR_EMAIL --control-plane-cidr 172.232.86.149/32
```

What it creates: a $10 budget alarm, the VPC and 2 public subnets, 3 security groups (rule A = host-1 → orders-db:5432, rule B = host-2 → orders-db:5432), host-1 and host-2 (Docker, SSM), orders-db (Postgres, private), a CloudTrail trail → EventBridge rule → SQS `rootgraph-changes`, and 3 IAM users with least-privilege policies.

If it fails part-way, fix the cause and run the same command again: finished steps are recorded in `demo/aws/state.json` and skipped.

## 2. Give the control plane its keys

```bash
cat demo/aws/credentials.env >> .env
```

Then set `PROMETHEUS_URL=http://<host-1 public IP>:9090` in `.env` once the demo stack is running on host-1 (step 4).

## 3. Start the live workers and check the graph

```bash
docker compose --profile aws up -d --build discovery ingester
```

```bash
docker compose logs -f discovery
```

Within a minute you should see `sync ok ... 0 changes`. In FalkorDB Browser (SSH tunnel to port 3000), `ops_live` should hold host-1, host-2, orders-db, the three SGs, the five services and their DEPENDS_ON edges.

## 4. Demo services + Prometheus on the hosts

Covered by `demo/README` (demo stack). Each host runs its compose file through SSM or SSH; Alertmanager on host-1 posts to `https://172-232-86-149.sslip.io/hooks/alertmanager` with `WEBHOOK_TOKEN`.

## 5. Start the live API next to the public sandbox

Set `PROMETHEUS_URL_LIVE=http://<host-1 public IP>:9090` in `.env`, then:

```bash
docker compose --profile aws up -d --build api-live discovery ingester
```

The live UI is `https://172-232-86-149.sslip.io/live/` (graph `ops_live`). Paste `ADMIN_TOKEN` into the token field in its top bar; approvals there run the real AWS executor. The public sandbox at `/` keeps working for judges. Alertmanager on host-1 posts to `/live/hooks/alertmanager` (rendered by `demo.render aws`).

## 6. Record a real CloudTrail event (plan §6.3)

```bash
AWS_PROFILE=rootgraph-admin uv run python demo/faults/s1_revoke_sg.py
```

Copy the SQS message body the ingester logs into `ingest/fixtures/` to replace the hand-written sample.

## Teardown (after submitting)

```bash
AWS_PROFILE=rootgraph-admin uv run python -m demo.aws.estate down
```

Then delete the admin key you used in step 0, and remove the `*_AWS_*` lines from `.env`.
