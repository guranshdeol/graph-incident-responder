// Q11 removed_rules_on_firewall: inactive rules on one firewall removed since $since.
// Precondition + exact spec for restore_firewall_rule (§7.6). Params: $fw, $since
MATCH (fw:Firewall {rid: $fw})-[r:ALLOWS_FROM]->(src)
WHERE r.active = false AND r.removed_at >= $since
RETURN r.rule_id AS rule_id, coalesce(r.original_rule_id, r.rule_id) AS original_rule_id,
       r.proto AS proto, r.port_from AS port_from, r.port_to AS port_to, src.rid AS source, r.removed_at AS removed_at
ORDER BY removed_at DESC
