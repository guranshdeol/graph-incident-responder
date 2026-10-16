// Q14 get_action: an action with its incident and target. Params: $id
MATCH (x:Action {id: $id})-[:FOR]->(i:Incident)
OPTIONAL MATCH (x)-[:TARGETS]->(t:Resource)
RETURN x.id AS id, x.kind AS kind, x.params AS params, x.status AS status,
       x.proposed_at AS proposed_at, x.approved_by AS approved_by, i.id AS incident_id, t.rid AS target_rid
