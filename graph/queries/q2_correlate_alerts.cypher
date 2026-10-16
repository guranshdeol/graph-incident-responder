// Q2 correlate_alerts: walk upward from symptoms. Params: $alert_rids, $k
UNWIND $alert_rids AS rid
MATCH p = (s:Resource {rid: rid})-[:DEPENDS_ON|RUNS_ON*0..4]->(c:Resource)
WITH c, rid, min(length(p)) AS hops
WITH c, collect(rid) AS explains, min(hops) AS min_hops
RETURN c.rid AS candidate, labels(c) AS kinds, size(explains) AS coverage, explains, min_hops
ORDER BY coverage DESC, min_hops ASC
LIMIT $k
