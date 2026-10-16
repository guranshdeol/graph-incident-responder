// W3 ingest CloudTrail change. Params: $event_id, $event_name, $actor, $at, $by_agent, $request_json, $rids
MERGE (ch:Change {event_id: $event_id})
ON CREATE SET ch.source = 'cloudtrail', ch.event_name = $event_name, ch.actor = $actor,
              ch.at = $at, ch.by_agent = $by_agent, ch.request = $request_json
WITH ch
UNWIND $rids AS rid
MATCH (r:Resource {rid: rid})
MERGE (ch)-[:MODIFIED]->(r)
