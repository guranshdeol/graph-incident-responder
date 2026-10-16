// W4 ingest alert. Params: $id, $fp, $alertname, $status, $severity, $starts_at, $ends_at, $rid
MERGE (a:Alert {id: $id})
SET a.fingerprint = $fp, a.alertname = $alertname, a.status = $status,
    a.severity = $severity, a.starts_at = $starts_at, a.ends_at = $ends_at
WITH a
MATCH (r:Resource {rid: $rid})
MERGE (a)-[:FIRING_ON]->(r)
