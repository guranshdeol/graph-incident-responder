// W11 store the investigation report (JSON) and optionally a new status. Params: $id, $report, $status
MATCH (i:Incident {id: $id})
SET i.report = coalesce($report, i.report), i.status = coalesce($status, i.status)
RETURN i.id AS id, i.status AS status
