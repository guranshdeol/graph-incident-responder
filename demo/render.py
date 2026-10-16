"""Render the demo stack's compose + Prometheus + Alertmanager files (plan §9).

    uv run python -m demo.render local   one stack on this server, fixture rids (i-host1, rds:orders-db...)
                                         so its alerts land on the ops_sandbox graph
    uv run python -m demo.render aws     host-1 and host-2 stacks from demo/aws/state.json (real ids/IPs)

Output: demo/build/<target>/ (gitignored: alertmanager.yml contains the webhook token).
Every scrape target gets a static `rid` label equal to the graph rid; the blackbox
probe to orders-db runs from each host with rid=<host> and target_rid=rds:orders-db.
"""

import json
import os
import shutil
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILD = HERE / "build"
BASE_URL = os.environ.get("ROOTGRAPH_URL", "https://172-232-86-149.sslip.io")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", f"{BASE_URL}/hooks/alertmanager")          # local -> sandbox API
WEBHOOK_URL_LIVE = os.environ.get("WEBHOOK_URL_LIVE", f"{BASE_URL}/live/hooks/alertmanager")  # aws -> api-live

IMAGES = {
    "prometheus": "prom/prometheus:v2.55.1",
    "alertmanager": "prom/alertmanager:v0.27.0",
    "blackbox": "prom/blackbox-exporter:v0.25.0",
    "node": "prom/node-exporter:v1.8.2",
    "postgres": "postgres:16-alpine",
}
SERVICES = {  # name: (port, host, deps as (kind, target_rid, logical target))
    "web": (8080, "host1", [("http", "svc:checkout", "checkout"), ("http", "svc:orders", "orders")]),
    "checkout": (8081, "host1", [("http", "svc:payments", "payments")]),
    "payments": (8082, "host1", [("db", "rds:orders-db", "db")]),
    "orders": (8083, "host2", [("db", "rds:orders-db", "db")]),
    "reports": (8084, "host2", [("db", "rds:orders-db", "db")]),
}


def env_token() -> str:
    token = os.environ.get("WEBHOOK_TOKEN")
    if not token:
        env = ROOT / ".env"
        for line in env.read_text().splitlines() if env.exists() else []:
            if line.startswith("WEBHOOK_TOKEN="):
                token = line.split("=", 1)[1].strip()
    if not token:
        sys.exit("WEBHOOK_TOKEN not set and not found in .env")
    return token


def service_def(name, addr_of, image_build, ports_published):
    port, _, deps = SERVICES[name]
    dep_s = ",".join(f"{k}:{t}=" + (f"http://{addr_of(target)}/" if k == "http" else addr_of(target))
                     for k, t, target in deps)
    d = {**image_build, "container_name": name,  # the restart executor runs `docker start <name>`
         "environment": {"SERVICE_RID": f"svc:{name}", "PORT": str(port), "DEPS": dep_s},
         "restart": "no"}  # no restart policy: a stopped service stays down (S3)
    if ports_published:
        d["ports"] = [f"0.0.0.0:{port}:{port}"]
    return d


def prometheus_cfg(env_label, service_targets, node_targets, blackbox_targets, db_addr):
    return {
        "global": {"scrape_interval": "5s", "evaluation_interval": "5s", "external_labels": {"env": env_label}},
        "rule_files": ["/etc/prometheus/rules.yml"],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": ["alertmanager:9093"]}]}]},
        "scrape_configs": [
            {"job_name": "services", "honor_labels": True,
             "static_configs": [{"targets": [addr], "labels": {"rid": rid}} for rid, addr in service_targets]},
            {"job_name": "node",
             "static_configs": [{"targets": [addr], "labels": {"rid": rid}} for rid, addr in node_targets]},
            {"job_name": "blackbox_db", "metrics_path": "/probe", "params": {"module": ["tcp_connect"]},
             "static_configs": [{"targets": [db_addr], "labels": {"rid": rid, "target_rid": "rds:orders-db",
                                                                  "__tmp_blackbox": bb}}
                                for rid, bb in blackbox_targets],
             "relabel_configs": [
                 {"source_labels": ["__address__"], "target_label": "__param_target"},
                 {"source_labels": ["__tmp_blackbox"], "target_label": "__address__"}]},
        ],
    }


def alertmanager_cfg(token, url=None):
    return {
        "route": {"receiver": "rootgraph", "group_by": ["env"], "group_wait": "10s",
                  "group_interval": "10s", "repeat_interval": "1h"},
        "receivers": [{"name": "rootgraph", "webhook_configs": [{
            "url": url or WEBHOOK_URL, "send_resolved": True,
            "http_config": {"authorization": {"type": "Bearer", "credentials": token}}}]}],
    }


def monitoring(prom_port_publish):
    return {
        "prometheus": {"image": IMAGES["prometheus"], "restart": "unless-stopped",
                       "command": ["--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.retention.time=2d",
                                   "--web.enable-lifecycle"],
                       "volumes": ["./prometheus.yml:/etc/prometheus/prometheus.yml:ro",
                                   "./rules.yml:/etc/prometheus/rules.yml:ro"],
                       "ports": [prom_port_publish]},
        "alertmanager": {"image": IMAGES["alertmanager"], "restart": "unless-stopped",
                         "volumes": ["./alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro"]},
    }


def exporters(suffix=""):
    return {
        f"blackbox{suffix}": {"image": IMAGES["blackbox"], "restart": "unless-stopped",
                              "command": ["--config.file=/etc/blackbox/blackbox.yml"],
                              "volumes": ["./blackbox.yml:/etc/blackbox/blackbox.yml:ro"]},
        f"node-exporter{suffix}": {"image": IMAGES["node"], "restart": "unless-stopped", "pid": "host",
                                   "command": ["--path.rootfs=/host"], "volumes": ["/:/host:ro,rslave"]},
    }


def write(out: Path, files: dict):
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        p = out / name
        p.write_text(content if isinstance(content, str) else yaml.safe_dump(content, sort_keys=False))
    am = out / "alertmanager.yml"
    am.chmod(0o600)  # holds the webhook token
    if os.geteuid() == 0:  # the alertmanager image runs as nobody (65534)
        os.chown(am, 65534, 65534)
    shutil.copy(HERE / "prometheus/rules.yml", out / "rules.yml")
    shutil.copy(HERE / "blackbox/blackbox.yml", out / "blackbox.yml")


def render_local(token):
    """One machine plays both hosts. orders-db is a Postgres container. Fixture rids, env=local."""
    build = {"build": str(HERE / "service"), "image": "rootgraph-demo-service:dev"}
    addr = lambda t: "orders-db:5432" if t == "db" else f"{t}:{SERVICES[t][0]}"
    svcs = {"orders-db": {"image": IMAGES["postgres"], "restart": "unless-stopped",
                          "environment": {"POSTGRES_PASSWORD": "demo-local-only"}}}
    for name in SERVICES:
        svcs[name] = service_def(name, addr, build, ports_published=False)
    svcs["loadgen"] = {**build, "restart": "unless-stopped",
                       "environment": {"MODE": "loadgen", "LOAD_TARGET": "http://web:8080/,http://reports:8084/", "PORT": "8099"}}
    svcs |= monitoring("127.0.0.1:9091:9090") | exporters("-host1") | exporters("-host2")
    del svcs["node-exporter-host2"]  # one machine: scrape the same node exporter as both hosts
    prom = prometheus_cfg(
        "local",
        [(f"svc:{n}", f"{n}:{SERVICES[n][0]}") for n in SERVICES],
        [("i-host1", "node-exporter-host1:9100"), ("i-host2", "node-exporter-host1:9100")],
        [("i-host1", "blackbox-host1:9115"), ("i-host2", "blackbox-host2:9115")],
        "orders-db:5432")
    # the API (compose project "app") reaches this Prometheus as http://demo-prometheus:9090
    svcs["prometheus"]["networks"] = {"default": {}, "controlplane": {"aliases": ["demo-prometheus"]}}
    write(BUILD / "local", {"compose.yml": {"name": "rootgraph-demo", "services": svcs,
                                            "networks": {"controlplane": {"external": True, "name": "app_default"}}},
                            "prometheus.yml": prom, "alertmanager.yml": alertmanager_cfg(token)})
    return BUILD / "local"


def render_aws(token):
    from demo.aws import estate  # state.json path lives there (tests point it elsewhere)
    st = json.loads(estate.STATE.read_text())
    import boto3  # only needed for the real ids/IPs
    s = boto3.Session(region_name=os.environ.get("AWS_REGION", "ap-south-1"))
    inst = {i["InstanceId"]: i for r in s.client("ec2").describe_instances(InstanceIds=[st["host1"], st["host2"]])["Reservations"]
            for i in r["Instances"]}
    h1, h2 = inst[st["host1"]], inst[st["host2"]]
    db_ep = s.client("rds").describe_db_instances(DBInstanceIdentifier="orders-db")["DBInstances"][0]["Endpoint"]
    db_addr = f"{db_ep['Address']}:{db_ep['Port']}"
    ip2 = h2["PrivateIpAddress"]
    build = {"build": "./service", "image": "rootgraph-demo-service:aws"}

    def addr(t):
        if t == "db":
            return db_addr
        return f"{t}:{SERVICES[t][0]}" if SERVICES[t][1] == "host1" else f"{ip2}:{SERVICES[t][0]}"

    host1 = {n: service_def(n, addr, build, ports_published=False) for n, v in SERVICES.items() if v[1] == "host1"}
    host1["loadgen"] = {**build, "restart": "unless-stopped",
                        "environment": {"MODE": "loadgen", "LOAD_TARGET": f"http://web:8080/,http://{ip2}:8084/", "PORT": "8099"}}
    host1 |= monitoring("0.0.0.0:9090:9090") | exporters()
    host2 = {n: service_def(n, addr, build, ports_published=True) for n, v in SERVICES.items() if v[1] == "host2"}
    host2 |= exporters()
    for svc in ("blackbox", "node-exporter"):
        host2[svc]["ports"] = [f"0.0.0.0:{9115 if svc == 'blackbox' else 9100}:{9115 if svc == 'blackbox' else 9100}"]
    prom = prometheus_cfg(
        "aws",
        [(f"svc:{n}", addr(n)) for n in SERVICES],
        [(st["host1"], "node-exporter:9100"), (st["host2"], f"{ip2}:9100")],
        [(st["host1"], "blackbox:9115"), (st["host2"], f"{ip2}:9115")],
        db_addr)
    for name, svcs, extra in (("host1", host1, {"prometheus.yml": prom, "alertmanager.yml": alertmanager_cfg(token, WEBHOOK_URL_LIVE)}),
                              ("host2", host2, {})):
        out = BUILD / "aws" / name
        out.mkdir(parents=True, exist_ok=True)
        (out / "alertmanager.yml").write_text("")  # placeholder so write() can chmod; host2 has none
        write(out, {"compose.yml": {"name": "rootgraph-demo", "services": svcs}, **extra})
        if name == "host2":
            (out / "alertmanager.yml").unlink()
        shutil.copytree(HERE / "service", out / "service", dirs_exist_ok=True)
    return BUILD / "aws"


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if target not in ("local", "aws"):
        sys.exit("usage: python -m demo.render local|aws")
    out = (render_local if target == "local" else render_aws)(env_token())
    print(f"rendered {out}")
