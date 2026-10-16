"""S3 fault: stop the payments container on host-1 (no restart policy, so it stays down).
Run: AWS_PROFILE=rootgraph-admin uv run python -m demo.faults.s3_stop_payments
The agent proposes restart_service; approving it runs `docker start payments` via SSM."""

from demo.aws import ssm as ssm_mod

CONTAINER = "payments"  # container_name set by demo.render

if __name__ == "__main__":
    st = ssm_mod.state()
    r = ssm_mod.run(ssm_mod.client(), st["host1"], [f"docker stop {CONTAINER}"], "rootgraph S3 stop payments")
    print(r["status"], r.get("stdout", "").strip())
