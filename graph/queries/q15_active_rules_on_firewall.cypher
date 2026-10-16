// Q15 active_rules_on_firewall: current rules of one firewall (sandbox fault injection replays a discovery sync with it). Params: $fw
MATCH (fw:Firewall {rid: $fw})-[r:ALLOWS_FROM]->(src)
WHERE r.active = true
RETURN r.rule_id AS rule_id, r.proto AS proto, r.port_from AS port_from, r.port_to AS port_to, src.rid AS source
ORDER BY rule_id
