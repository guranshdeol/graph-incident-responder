// Q7 recall_incidents: cue-triggered memory. Params: $alertnames, $candidate_rids
MATCH (i:Incident {status: 'resolved'})-[:ROOT_CAUSE]->(rc:Resource)
OPTIONAL MATCH (i)-[:HAS_ALERT]->(al:Alert)
WITH i, rc, collect(DISTINCT al.alertname) AS past_alerts
WITH i, rc, size([a IN past_alerts WHERE a IN $alertnames]) AS alert_overlap,
     CASE WHEN rc.rid IN $candidate_rids THEN 1 ELSE 0 END AS same_cause
WHERE alert_overlap > 0 OR same_cause = 1
OPTIONAL MATCH (i)-[:EXPLAINED_BY]->(ch:Change)
OPTIONAL MATCH (act:Action {status: 'verified'})-[:RESOLVED]->(i)
RETURN i.id, i.opened_at, i.ttr_seconds, rc.rid AS root_cause, ch.event_name AS change,
       act.kind AS fix, act.params AS fix_params, alert_overlap, same_cause
ORDER BY same_cause DESC, alert_overlap DESC, i.opened_at DESC
LIMIT 3
