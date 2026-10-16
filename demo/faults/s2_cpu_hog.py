"""S2 fault: saturate host-2's CPU for 5 minutes (orders + reports slow down together).
Run: AWS_PROFILE=rootgraph-admin uv run python -m demo.faults.s2_cpu_hog
It stops by itself after 300 s; there is no catalogued fix (the agent says so)."""

from demo.aws import ssm as ssm_mod

HOG = ("nohup timeout 300 sh -c 'for i in $(seq $(nproc)); do (while :; do :; done) & done; wait' "
       ">/dev/null 2>&1 &")

if __name__ == "__main__":
    st = ssm_mod.state()
    r = ssm_mod.run(ssm_mod.client(), st["host2"], [HOG, "echo started cpu hog for 300s on $(nproc) cores"], "rootgraph S2 cpu hog")
    print(r["status"], r.get("stdout", "").strip())
