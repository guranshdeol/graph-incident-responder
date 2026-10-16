// Q6 blast_radius (v2): fixed upper bound 4, $depth filters. Params: $rid, $depth
MATCH p = (up:Resource)-[:DEPENDS_ON|RUNS_ON*1..4]->(t:Resource {rid: $rid})
WHERE length(p) <= $depth
WITH up, min(length(p)) AS hops, collect([n IN nodes(p) | n.rid])[0] AS via
RETURN up.rid AS affected, hops, via
ORDER BY hops, affected
