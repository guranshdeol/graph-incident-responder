// Q28 list_actions: every proposed fix with its incident, target and approval trail, newest first: the
// console's audit log. Params: $limit
MATCH (x:Action)-[:FOR]->(i:Incident)
OPTIONAL MATCH (x)-[:TARGETS]->(t:Resource)
RETURN x.id AS id, x.kind AS kind, x.status AS status, x.proposed_at AS proposed_at, x.updated_at AS updated_at,
       x.executed_at AS executed_at, x.approved_by AS approved_by, x.detail AS detail,
       i.id AS incident, t.rid AS target, t.name AS target_name
ORDER BY proposed_at DESC
LIMIT $limit
