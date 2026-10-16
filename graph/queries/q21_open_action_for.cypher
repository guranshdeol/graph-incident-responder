// Q21 open_action_for: an action already proposed for this incident, kind and target,
// so a re-investigation reuses it instead of proposing twice. Params: $incident_id, $kind, $target_rid
MATCH (x:Action {kind: $kind, status: 'proposed'})-[:FOR]->(:Incident {id: $incident_id})
MATCH (x)-[:TARGETS]->(:Resource {rid: $target_rid})
RETURN x.id AS id
LIMIT 1
