// W1 upsert SG rule (discovery). Params: $fw, $src_rid, $rule_id, $proto, $from_port, $to_port, $sync_ts
MATCH (fw:Firewall {rid: $fw}), (src:Resource {rid: $src_rid})
MERGE (fw)-[r:ALLOWS_FROM {rule_id: $rule_id}]->(src)
SET r.proto = $proto, r.port_from = $from_port, r.port_to = $to_port,
    r.active = true, r.last_seen = $sync_ts, r.removed_at = null
