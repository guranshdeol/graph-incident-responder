// Q21 open_action_for: an action already proposed (or approved, executed, verified) for this incident, kind and
// target, so a re-investigation reuses it instead of proposing twice, even if it finished after the approval.
// Params: $incident_id, $kind, $target_rid
MATCH (x:Action {kind: $kind})-[:FOR]->(:Incident {id: $incident_id})
WHERE x.status IN ['proposed', 'approved', 'executed', 'verified']
MATCH (x)-[:TARGETS]->(:Resource {rid: $target_rid})
RETURN x.id AS id, x.status AS status
ORDER BY x.proposed_at DESC
LIMIT 1
