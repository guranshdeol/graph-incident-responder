// Q22 incident_of_alerts: which incident already holds these alerts (any status), so a later
// notification for the same alerts never opens a second incident. Params: $ids
MATCH (i:Incident)-[:HAS_ALERT]->(a:Alert)
WHERE a.id IN $ids
RETURN i.id AS id, i.status AS status, collect(a.id) AS alert_ids
ORDER BY size(alert_ids) DESC
