// Q26 resource_state: an instance's or database's last discovered state. Params: $rid
MATCH (r:Resource {rid: $rid})
RETURN r.rid AS rid, labels(r) AS kinds, r.state AS state, r.status AS status, r.name AS name
