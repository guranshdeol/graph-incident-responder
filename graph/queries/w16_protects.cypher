// W16 a security group PROTECTS an instance or database. Params: $fw, $target, $sync_ts
MATCH (f:Firewall {rid: $fw}), (t:Resource {rid: $target})
MERGE (f)-[e:PROTECTS]->(t)
SET e.source = 'aws_api', e.last_seen = $sync_ts, e.active = true, e.removed_at = null
