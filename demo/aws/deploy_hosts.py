"""Ship the rendered demo stack to host-1 and host-2 over SSM and start it.

    AWS_PROFILE=rootgraph-admin uv run python -m demo.aws.deploy_hosts

Renders demo/build/aws/ (demo.render aws), packs each host's folder into a gzipped tar,
and sends it inline in an SSM Run Command that unpacks it into /opt/rootgraph-demo and
runs `docker compose up -d --build`. Note: SSM keeps command parameters in its history,
so the webhook token in alertmanager.yml is visible to admins of this AWS account.
"""

import base64
import io
import sys
import tarfile
from pathlib import Path

from demo import render
from demo.aws import ssm as ssm_mod

REMOTE_DIR = "/opt/rootgraph-demo"
MAX_PAYLOAD = 48_000  # stay well under SSM's command size limit


def pack(folder: Path) -> str:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in sorted(folder.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                tar.add(p, arcname=str(p.relative_to(folder)))
    data = base64.b64encode(buf.getvalue()).decode()
    if len(data) > MAX_PAYLOAD:
        raise SystemExit(f"{folder} packs to {len(data)} bytes; too big for one SSM command")
    return data


def commands(payload: str, has_alertmanager: bool) -> list[str]:
    cmds = [
        "set -euo pipefail",
        f"mkdir -p {REMOTE_DIR}",
        f"echo '{payload}' | base64 -d | tar xz -C {REMOTE_DIR}",
        f"chmod 644 {REMOTE_DIR}/prometheus.yml {REMOTE_DIR}/rules.yml {REMOTE_DIR}/blackbox.yml 2>/dev/null || true",
    ]
    if has_alertmanager:  # holds the webhook token; the alertmanager image runs as nobody
        cmds.append(f"chown 65534:65534 {REMOTE_DIR}/alertmanager.yml && chmod 600 {REMOTE_DIR}/alertmanager.yml")
    cmds += [f"cd {REMOTE_DIR} && docker compose up -d --build 2>&1 | tail -20", "docker ps --format '{{.Names}} {{.Status}}'"]
    return cmds


def deploy(session=None, wait: bool = True) -> dict:
    out_dir = render.render_aws(render.env_token())
    st, ssm = ssm_mod.state(), ssm_mod.client(session)
    results = {}
    for host_key, folder in (("host2", "host2"), ("host1", "host1")):  # host-2 first: host-1's web calls it
        path = out_dir / folder
        payload = pack(path)
        results[host_key] = ssm_mod.run(ssm, st[host_key], commands(payload, (path / "alertmanager.yml").exists()),
                                        f"rootgraph deploy {folder}", wait=wait)
        print(f"{folder} ({st[host_key]}): {results[host_key]['status']}")
        if results[host_key].get("stdout"):
            print(results[host_key]["stdout"])
    return results


if __name__ == "__main__":
    res = deploy()
    sys.exit(0 if all(r["status"] in ("Success", "Sent") for r in res.values()) else 1)
