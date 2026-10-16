// W5b attach alerts to an already-open incident (§6.5 grouping). Params: $id, $alert_ids
MATCH (i:Incident {id: $id})
UNWIND $alert_ids AS aid
MATCH (a:Alert {id: aid})
MERGE (i)-[:HAS_ALERT]->(a)
