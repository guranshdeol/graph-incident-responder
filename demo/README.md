# Demo stack

One FastAPI image (`demo/service/`) runs as web, checkout, payments, orders and reports; `loadgen`
hits web and reports. Prometheus scrapes everything every 5 s with a static `rid` label equal to the
graph rid, evaluates `demo/prometheus/rules.yml`, and Alertmanager posts to the rootgraph webhook
(`https://172-232-86-149.sslip.io/hooks/alertmanager`, bearer `WEBHOOK_TOKEN`).

## Local (on the rootgraph server, fixture rids → ops_sandbox)

```bash
uv run python -m demo.render local
```

```bash
docker compose -f demo/build/local/compose.yml up -d --build
```

The API reaches this Prometheus as `http://demo-prometheus:9090` (`PROMETHEUS_URL` in `.env`).
Try S3 for real: `docker stop payments`, wait ~40 s, open the UI. Bring it back
with `docker start payments`. Stop the stack with `docker compose -f demo/build/local/compose.yml down`.

Recorded payloads from such a run are in `demo/replay/recorded/`.

## AWS (host-1 and host-2)

After `demo.aws.estate up`:

```bash
uv run python -m demo.render aws
```

This writes `demo/build/aws/host1/` and `host2/` with real instance ids, host-2's private IP and the
orders-db endpoint. Copy each folder to its host (SSM) and run `docker compose up -d --build` there.
Then set `PROMETHEUS_URL=http://<host-1 public IP>:9090` on the server (the SG allows only the server).
