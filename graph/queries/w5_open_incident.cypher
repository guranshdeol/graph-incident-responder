// W5 open incident. Params: $id, $group_key, $now, $alert_ids
CREATE (i:Incident {id: $id, group_key: $group_key, opened_at: $now, status: 'open'})
WITH i
UNWIND $alert_ids AS aid
MATCH (a:Alert {id: aid})
MERGE (i)-[:HAS_ALERT]->(a)
