"""Long-running workers for the live estate (compose profile "aws").

    python -m ingest.worker discovery   full AWS sync into ops_live every DISCOVERY_INTERVAL seconds
    python -m ingest.worker ingester    long-poll the CloudTrail SQS queue into Change nodes

Each component uses its own least-privilege principal (§7.7):
    DISCOVERY_AWS_ACCESS_KEY_ID / DISCOVERY_AWS_SECRET_ACCESS_KEY   ec2:Describe*, rds:Describe*
    INGESTER_AWS_ACCESS_KEY_ID  / INGESTER_AWS_SECRET_ACCESS_KEY    sqs:ReceiveMessage, sqs:DeleteMessage
    EXECUTOR_AWS_ACCESS_KEY_ID  / EXECUTOR_AWS_SECRET_ACCESS_KEY    (used by the API, see api/app.py)
If a component's keys are unset, boto3's default credential chain is used (local dev).
"""

import logging
import os
import sys
import time

import boto3

from graph import db
from ingest import cloudtrail_stream, discovery_aws

log = logging.getLogger("rootgraph.worker")
REGION = os.environ.get("AWS_REGION", "ap-south-1")


def session(prefix: str) -> boto3.Session:
    key, secret = os.environ.get(f"{prefix}_AWS_ACCESS_KEY_ID"), os.environ.get(f"{prefix}_AWS_SECRET_ACCESS_KEY")
    if key and secret:
        return boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret, region_name=REGION)
    return boto3.Session(region_name=REGION)


def live_graph():
    return db.graph(os.environ.get("GRAPH_LIVE", "ops_live"))


def discovery_loop(interval: int) -> None:
    s = session("DISCOVERY")
    ec2, rds, g = s.client("ec2"), s.client("rds"), live_graph()
    db.apply_schema(g)
    while True:
        t0 = time.time()
        try:
            out = discovery_aws.sync(g, discovery_aws.collect(ec2, rds), discovery_aws.load_services())
            log.info("sync ok in %.1fs: %d changes %s, missing %s, skipped rules %s, unresolved deps %s",
                     time.time() - t0, len(out["changes"]), out["changes"], out["missing"],
                     out["skipped_rules"], out["unresolved_dependencies"])
        except Exception:
            log.exception("discovery sync failed")
        time.sleep(max(1.0, interval - (time.time() - t0)))


def ingester_loop() -> None:
    queue_url = os.environ["CHANGES_QUEUE_URL"]
    sqs, g = session("INGESTER").client("sqs"), live_graph()
    db.apply_schema(g)
    log.info("listening on %s", queue_url)
    cloudtrail_stream.run(sqs, queue_url, g)


def main(argv: list[str]) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    mode = argv[1] if len(argv) > 1 else ""
    if mode == "discovery":
        discovery_loop(int(os.environ.get("DISCOVERY_INTERVAL", "60")))
    elif mode == "ingester":
        ingester_loop()
    else:
        sys.exit("usage: python -m ingest.worker discovery|ingester")


if __name__ == "__main__":
    main(sys.argv)
