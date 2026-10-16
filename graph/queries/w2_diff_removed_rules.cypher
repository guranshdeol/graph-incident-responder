// W2 graph diff: active rules not seen in this sync were removed. Params: $fw, $sync_ts
MATCH (fw:Firewall {rid: $fw})-[r:ALLOWS_FROM]->(src)
WHERE r.active = true AND r.last_seen < $sync_ts
SET r.active = false, r.removed_at = $sync_ts
CREATE (ch:Change {event_id: 'diff:' + r.rule_id + ':' + toString($sync_ts), source: 'graph_diff',
                   event_name: 'SecurityGroupRuleRemoved', at: $sync_ts, rule_id: r.rule_id})
CREATE (ch)-[:MODIFIED]->(fw)
RETURN r.rule_id, src.rid
