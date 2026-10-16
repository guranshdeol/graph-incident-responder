// Q13 incident_alerts: the alerts of an incident, with what they fire on and target. Params: $id
MATCH (i:Incident {id: $id})-[:HAS_ALERT]->(a:Alert)
OPTIONAL MATCH (a)-[:FIRING_ON]->(r:Resource)
OPTIONAL MATCH (a)-[:TARGET]->(t:Resource)
RETURN a.id AS id, a.alertname AS alertname, a.status AS status, a.starts_at AS starts_at,
       r.rid AS rid, t.rid AS target_rid
ORDER BY starts_at, id
