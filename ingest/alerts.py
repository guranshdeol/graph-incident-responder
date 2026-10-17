"""Alertmanager webhook payload -> Alert nodes -> Incident (§6.5).

- Each alert becomes an Alert node (W4) linked FIRING_ON its `rid` label and,
  for blackbox probes, TARGET its `target_rid` label (W4b).
- Alert id = fingerprint + ":" + starts_at, so a repeat of the same alert later
  (scenario S4) is a new node instead of reusing the old one.
- Grouping: one Alertmanager group = one Incident. Firing alerts attach to an
  open incident of the same groupKey opened in the last 10 minutes (Q12, W5b);
  otherwise a new incident is opened (W5). Alerts already filed in any incident
  (Q22) are never filed again, so repeats of the group open nothing new.
- Resolved notifications only update alert status; they drive verification.
"""

import time
import uuid
from datetime import datetime

from graph import db

GROUP_WINDOW_SECONDS = 600


def to_epoch(ts: str | None) -> int:
    """RFC3339 from Alertmanager -> epoch seconds. Alertmanager's 'unset' (0001-01-01) -> 0."""
    if not ts or ts.startswith("0001-"):
        return 0
    ts = ts.replace("Z", "+00:00")
    if "." in ts:  # Go may emit nanoseconds; Python takes at most microseconds
        head, rest = ts.split(".", 1)
        digits = "".join(c for c in rest if c.isdigit())
        tz = rest[len(digits):]
        ts = f"{head}.{digits[:6]}{tz}"
    return int(datetime.fromisoformat(ts).timestamp())


def parse(payload: dict) -> list[dict]:
    out = []
    for a in payload.get("alerts", []):
        labels = a.get("labels", {})
        starts_at = to_epoch(a.get("startsAt"))
        fp = a.get("fingerprint") or labels.get("alertname", "?")
        out.append({
            "id": f"{fp}:{starts_at}",
            "fp": fp,
            "alertname": labels.get("alertname", "unknown"),
            "status": a.get("status", payload.get("status", "firing")),
            "severity": labels.get("severity", "none"),
            "starts_at": starts_at,
            "ends_at": to_epoch(a.get("endsAt")),
            "rid": labels.get("rid"),
            "target_rid": labels.get("target_rid"),
        })
    return out


def ingest(g, payload: dict, now: int | None = None) -> dict:
    """Write the payload's alerts; open or extend the incident. Returns what happened."""
    now = int(time.time()) if now is None else int(now)
    alerts = parse(payload)
    unlinked = []
    for a in alerts:
        db.run(g, "w4_ingest_alert", {k: a[k] for k in
               ("id", "fp", "alertname", "status", "severity", "starts_at", "ends_at", "rid")})
        _, hit = db.run(g, "q1_resolve", {"x": a["rid"] or ""})
        if not hit:
            unlinked.append(a["rid"])
        if a["target_rid"]:
            db.run(g, "w4b_alert_target", {"id": a["id"], "target_rid": a["target_rid"]})

    firing = [a["id"] for a in alerts if a["status"] == "firing"]
    group_key = payload.get("groupKey", "default")
    incident_id, opened, new = None, False, []
    if firing:
        # alerts we already filed (Alertmanager repeats the whole group in every notification)
        _, held = db.run(g, "q22_incident_of_alerts", {"ids": firing})
        filed = {aid for r in held for aid in r["alert_ids"]}
        new = [a for a in firing if a not in filed]
        _, rows = db.run(g, "q12_open_incident_for_group",
                         {"group_key": group_key, "since": now - GROUP_WINDOW_SECONDS})
        if rows:
            incident_id = rows[0]["id"]
            if new:
                db.run(g, "w5b_attach_alerts", {"id": incident_id, "alert_ids": new})
        elif new:
            incident_id, opened = f"INC-{uuid.uuid4().hex[:8]}", True
            db.run(g, "w5_open_incident",
                   {"id": incident_id, "group_key": group_key, "now": now, "alert_ids": new})
        else:   # every firing alert is already filed (e.g. its incident failed verification): no new incident
            incident_id = held[0]["id"]
    return {"incident_id": incident_id, "opened": opened, "alerts": len(alerts),
            "firing": len(firing), "new_firing": len(new), "unlinked_rids": unlinked}
