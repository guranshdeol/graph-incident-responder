// W9 move an action along its state machine, only from an allowed state.
// proposed -> approved|rejected -> executed -> verified|failed. Params: $id, $from (list), $to, $now, $actor, $detail
MATCH (x:Action {id: $id})
WHERE x.status IN $from
SET x.status = $to, x.updated_at = $now, x.detail = $detail,
    x.approved_by = CASE WHEN $to = 'approved' THEN $actor ELSE x.approved_by END,
    x.executed_at = CASE WHEN $to = 'executed' THEN $now ELSE x.executed_at END
RETURN x.id AS id, x.status AS status
