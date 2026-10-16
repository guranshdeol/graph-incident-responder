// W6 close incident with memory. Params: $id, $root_rid, $action_id, $now, $summary, $change_id
MATCH (i:Incident {id: $id}), (rc:Resource {rid: $root_rid}), (act:Action {id: $action_id})
SET i.status = 'resolved', i.closed_at = $now, i.ttr_seconds = $now - i.opened_at, i.summary = $summary
MERGE (i)-[:ROOT_CAUSE]->(rc)
MERGE (act)-[:RESOLVED]->(i)
WITH i
OPTIONAL MATCH (ch:Change {event_id: $change_id})
FOREACH (_ IN CASE WHEN ch IS NULL THEN [] ELSE [1] END | MERGE (i)-[:EXPLAINED_BY]->(ch))
