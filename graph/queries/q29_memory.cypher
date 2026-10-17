// Q29 memory: resolved incidents as the agent remembers them: root cause, the change that explained it,
// the verified fix and who approved it (what Q7 recalls from). Params: $limit
MATCH (i:Incident {status: 'resolved'})-[:ROOT_CAUSE]->(rc:Resource)
OPTIONAL MATCH (i)-[:HAS_ALERT]->(al:Alert)
OPTIONAL MATCH (i)-[:EXPLAINED_BY]->(ch:Change)
OPTIONAL MATCH (act:Action {status: 'verified'})-[:RESOLVED]->(i)
RETURN i.id AS id, i.opened_at AS opened_at, i.ttr_seconds AS ttr_seconds, rc.rid AS root_cause,
       rc.name AS root_name, labels(rc) AS root_kinds, collect(DISTINCT al.alertname) AS alertnames,
       ch.event_name AS change, ch.actor AS actor, act.kind AS fix, act.approved_by AS approved_by
ORDER BY opened_at DESC
LIMIT $limit
