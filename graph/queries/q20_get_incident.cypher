// Q20 get_incident: one incident's stored report, status and its actions. Params: $id
MATCH (i:Incident {id: $id})
OPTIONAL MATCH (x:Action)-[:FOR]->(i)
RETURN i.id AS id, i.status AS status, i.opened_at AS opened_at, i.ttr_seconds AS ttr_seconds,
       i.report AS report,
       collect(CASE WHEN x IS NULL THEN null ELSE {id: x.id, kind: x.kind, status: x.status, approved_by: x.approved_by, detail: x.detail} END) AS actions
