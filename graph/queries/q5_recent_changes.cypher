// Q5 recent_changes: resource + 2-hop infrastructure neighbourhood. Params: $rid, $since
MATCH (r:Resource {rid: $rid})-[:RUNS_ON|PROTECTS|DEPENDS_ON|IN*0..2]-(n:Resource)
WITH DISTINCT n
MATCH (ch:Change)-[:MODIFIED]->(n)
WHERE ch.at >= $since
RETURN ch.event_id, ch.source, ch.event_name, ch.actor, ch.at, ch.by_agent, n.rid AS on_resource
ORDER BY ch.at DESC LIMIT 10
