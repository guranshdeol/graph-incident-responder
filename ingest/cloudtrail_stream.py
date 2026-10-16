"""CloudTrail -> EventBridge -> SQS -> Change nodes (§6.3, decision D2).

The agent never queries CloudTrail: it reads Change nodes linked MODIFIED to the
resources they touched. Each SQS message body is one EventBridge event
("detail-type": "AWS API Call via CloudTrail").

  actor    = detail.userIdentity.arn
  at       = detail.eventTime -> epoch
  by_agent = the actor is the rootgraph executor (its own fixes must never become suspects)

Resource ids come from requestParameters through the EXTRACTORS table. Ids the
graph doesn't know yet are kept on the Change as unlinked_rids, and the caller
triggers a resync. NOTE: sample payloads in ingest/fixtures/ are hand-written
from the documented shapes; replace them with recorded events (plan §6.3).
"""

import json
import logging
import time

from graph import db
from ingest.alerts import to_epoch

log = logging.getLogger("rootgraph.cloudtrail")

EXECUTOR_MARKER = "rootgraph-executor"  # IAM user / role name of the executor principal
REQUEST_MAX_CHARS = 2000


def _sg(p):
    gid = p.get("groupId") or (p.get("ModifySecurityGroupRulesRequest") or {}).get("GroupId")
    return [gid] if gid else []


def _instances(p):
    items = ((p.get("instancesSet") or {}).get("items")) or []
    ids = [i.get("instanceId") for i in items if i.get("instanceId")]
    return ids or ([p["instanceId"]] if p.get("instanceId") else [])


def _rds(p):
    ident = p.get("dBInstanceIdentifier")
    return [f"rds:{ident}"] if ident else []


EXTRACTORS = {
    "RevokeSecurityGroupIngress": _sg, "AuthorizeSecurityGroupIngress": _sg, "ModifySecurityGroupRules": _sg,
    "StopInstances": _instances, "StartInstances": _instances, "RebootInstances": _instances,
    "TerminateInstances": _instances, "ModifyInstanceAttribute": _instances,
    "ModifyDBInstance": _rds, "RebootDBInstance": _rds, "StopDBInstance": _rds,
}


def parse(event: dict) -> dict | None:
    """EventBridge event -> Change fields, or None if it is not a call we track."""
    d = event.get("detail") or {}
    name = d.get("eventName")
    if name not in EXTRACTORS:
        return None
    params = d.get("requestParameters") or {}
    actor = (d.get("userIdentity") or {}).get("arn") or "unknown"
    request = json.dumps(params, separators=(",", ":"))
    return {
        "event_id": d.get("eventID") or event.get("id"),
        "event_name": name,
        "actor": actor,
        "at": to_epoch(d.get("eventTime")) or int(time.time()),
        "by_agent": EXECUTOR_MARKER in actor,
        "request_json": request[:REQUEST_MAX_CHARS],
        "rids": EXTRACTORS[name](params),
        "error": d.get("errorCode"),
    }


def ingest(g, event: dict) -> dict | None:
    ch = parse(event)
    if ch is None:
        return None
    if ch["error"]:  # a failed call changed nothing
        return {**ch, "linked": [], "unlinked": [], "skipped": "error " + ch["error"]}
    known = [r for r in ch["rids"] if db.run(g, "q1_resolve", {"x": r})[1]]
    unlinked = [r for r in ch["rids"] if r not in known]
    db.run(g, "w3_ingest_change", {k: ch[k] for k in
           ("event_id", "event_name", "actor", "at", "by_agent", "request_json")} | {"rids": known})
    if unlinked:
        db.run(g, "w22_change_unlinked", {"event_id": ch["event_id"], "rids": unlinked})
    return {**ch, "linked": known, "unlinked": unlinked}


def run(sqs, queue_url: str, g, resync=None, stop=lambda: False, wait_seconds: int = 20) -> None:
    """Long-poll SQS forever: ingest, resync if the change named unknown resources, delete."""
    while not stop():
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_seconds)
        for msg in resp.get("Messages", []):
            try:
                result = ingest(g, json.loads(msg["Body"]))
                if result:
                    log.info("change %s %s on %s (unlinked %s)", result["event_name"], result["actor"],
                             result["linked"], result["unlinked"])
                    if resync and result["unlinked"]:
                        resync()
            except Exception:
                log.exception("could not ingest message %s; leaving it for redelivery", msg.get("MessageId"))
                continue
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
