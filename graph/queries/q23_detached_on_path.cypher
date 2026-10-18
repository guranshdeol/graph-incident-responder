// Q23 detached_on_path: on a broken path, was a security group detached since $since from the
// dependency's host or from its target? (The other way a path breaks besides a removed rule.) Params: $from, $to, $since
MATCH (x:Service {rid: $from})-[:RUNS_ON]->(h:Compute)
MATCH (x)-[:DEPENDS_ON]->(y:Resource {rid: $to})
OPTIONAL MATCH (y)-[:RUNS_ON]->(yh:Compute)
WITH h, y, yh
MATCH (fw:Firewall)-[p:PROTECTS]->(n:Resource)
WHERE (n = h OR n = y OR (yh IS NOT NULL AND n = yh)) AND p.active = false AND p.removed_at >= $since
RETURN fw.rid AS firewall, n.rid AS target, labels(n) AS target_kinds, p.removed_at AS removed_at
ORDER BY removed_at DESC
