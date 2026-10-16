// W1b detect a modified rule (v2, runs BEFORE W1 for each rule). Same params as W1.
// Retires the old edge under a suffixed rule_id and records before/after on a Change.
MATCH (fw:Firewall {rid: $fw})-[r:ALLOWS_FROM {rule_id: $rule_id}]->(src)
WHERE r.active = true
  AND (r.proto <> $proto OR r.port_from <> $from_port OR r.port_to <> $to_port OR src.rid <> $src_rid)
SET r.active = false, r.removed_at = $sync_ts,
    r.rule_id = $rule_id + '@' + toString($sync_ts), r.original_rule_id = $rule_id
CREATE (ch:Change {event_id: 'diff:mod:' + $rule_id + ':' + toString($sync_ts), source: 'graph_diff',
                   event_name: 'SecurityGroupRuleModified', at: $sync_ts, rule_id: $rule_id,
                   before: r.proto + ' ' + toString(r.port_from) + '-' + toString(r.port_to) + ' from ' + src.rid,
                   after: $proto + ' ' + toString($from_port) + '-' + toString($to_port) + ' from ' + $src_rid})
CREATE (ch)-[:MODIFIED]->(fw)
RETURN r.rule_id
