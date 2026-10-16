// Q19 list_incidents: newest incidents with their top suspect. Params: $limit
MATCH (i:Incident)
OPTIONAL MATCH (i)-[s:SUSPECTS]->(r:Resource)
WHERE s.rank = 1
RETURN i.id AS id, i.status AS status, i.opened_at AS opened_at, i.closed_at AS closed_at,
       i.ttr_seconds AS ttr_seconds, r.rid AS top
ORDER BY opened_at DESC
LIMIT $limit
