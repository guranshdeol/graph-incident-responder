// Q10 removed_path_rules: on a broken path (Q4 permitted = false), which firewall on the
// target lost a rule since $since that used to let $from's host through on the dependency
// port? Same matching as Q4, but over inactive rules. Params: $from, $to, $since
MATCH (x:Service {rid: $from})-[:RUNS_ON]->(h:Compute)
MATCH (x)-[d:DEPENDS_ON]->(y:Resource {rid: $to})
MATCH (fw:Firewall)-[pt:PROTECTS]->(y)
WHERE coalesce(pt.active, true)
OPTIONAL MATCH (hfw:Firewall)-[ph:PROTECTS]->(h)
WHERE coalesce(ph.active, true)
WITH h, d, fw, collect(DISTINCT hfw) AS host_fws
MATCH (fw)-[r:ALLOWS_FROM]->(src)
WHERE r.active = false AND r.removed_at >= $since
  AND r.port_from <= d.port AND d.port <= r.port_to
  AND (src = h OR src:Internet OR src IN host_fws)
RETURN fw.rid AS firewall, r.rule_id AS rule_id, coalesce(r.original_rule_id, r.rule_id) AS original_rule_id,
       r.proto AS proto, r.port_from AS port_from, r.port_to AS port_to, src.rid AS source, r.removed_at AS removed_at
ORDER BY removed_at DESC
