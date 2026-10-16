// Q9 dependencies: what does this service call? Drives the check_path sweep. Params: $rid
MATCH (s:Resource {rid: $rid})-[d:DEPENDS_ON]->(t:Resource)
RETURN t.rid AS target, d.kind AS kind, d.port AS port
ORDER BY target
