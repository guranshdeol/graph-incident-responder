// Q4 check_path (v3): verdict across ALL firewalls guarding the target. Params: $from, $to
// The guarded node is the target itself (a database), or the host it runs on when the target is a service
// on another host (web -> orders crosses into host-2's security group). Same-host calls never cross a firewall.
// Only ACTIVE attachments count: a security group detached from the host or target no longer protects or permits it.
MATCH (x:Service {rid: $from})-[:RUNS_ON]->(h:Compute)
MATCH (x)-[d:DEPENDS_ON]->(y:Resource {rid: $to})
OPTIONAL MATCH (y)-[:RUNS_ON]->(yh:Compute)
WITH h, d, coalesce(yh, y) AS t
WHERE t <> h
MATCH (fw:Firewall)-[pt:PROTECTS]->(t)
WHERE coalesce(pt.active, true)
OPTIONAL MATCH (hfw:Firewall)-[ph:PROTECTS]->(h)
WHERE coalesce(ph.active, true)
WITH h, d, t, collect(DISTINCT fw) AS target_fws, collect(DISTINCT hfw) AS host_fws
UNWIND target_fws AS fw
OPTIONAL MATCH (fw)-[r:ALLOWS_FROM]->(src)
  WHERE r.active = true
    AND r.port_from <= d.port AND d.port <= r.port_to
    AND (src = h OR src:Internet OR src IN host_fws)
WITH h, d, t, fw, collect(r.rule_id) AS rules
RETURN h.rid AS host, d.port AS port, t.rid AS guarded,
       collect({firewall: fw.rid, rules: rules}) AS per_firewall,
       sum(size(rules)) > 0 AS permitted
