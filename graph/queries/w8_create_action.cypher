// W8 create a proposed action (§7.6). Params: $id, $kind, $params (JSON), $now, $incident_id, $target_rid
MATCH (i:Incident {id: $incident_id}), (t:Resource {rid: $target_rid})
CREATE (x:Action {id: $id, kind: $kind, params: $params, status: 'proposed', proposed_at: $now})
CREATE (x)-[:FOR]->(i)
CREATE (x)-[:TARGETS]->(t)
RETURN x.id AS id
