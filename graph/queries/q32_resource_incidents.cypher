// Q32 resource_incidents: incidents that suspected this resource, with its rank in each. Params: $rid, $limit
MATCH (i:Incident)-[s:SUSPECTS]->(:Resource {rid: $rid})
RETURN i.id AS id, i.status AS status, i.opened_at AS opened_at, s.rank AS rank, s.score AS score
ORDER BY opened_at DESC
LIMIT $limit
