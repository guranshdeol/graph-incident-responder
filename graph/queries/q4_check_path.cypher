// Q4 check_path (v2): verdict across ALL firewalls on the target. Params: $from, $to
MATCH (x:Service {rid: $from})-[:RUNS_ON]->(h:Compute)
MATCH (x)-[d:DEPENDS_ON]->(y:Resource {rid: $to})
MATCH (fw:Firewall)-[:PROTECTS]->(y)
OPTIONAL MATCH (hfw:Firewall)-[:PROTECTS]->(h)
WITH h, d, collect(DISTINCT fw) AS target_fws, collect(DISTINCT hfw) AS host_fws
UNWIND target_fws AS fw
OPTIONAL MATCH (fw)-[r:ALLOWS_FROM]->(src)
  WHERE r.active = true
    AND r.port_from <= d.port AND d.port <= r.port_to
    AND (src = h OR src:Internet OR src IN host_fws)
WITH h, d, fw, collect(r.rule_id) AS rules
RETURN h.rid AS host, d.port AS port,
       collect({firewall: fw.rid, rules: rules}) AS per_firewall,
       sum(size(rules)) > 0 AS permitted
