// W13 upsert an EC2 instance, IN its subnet. Params: $rid, $name, $private_ip, $public_ip, $state, $instance_type, $subnet_rid, $sync_ts
MERGE (c:Resource:Compute {rid: $rid})
SET c.name = $name, c.private_ip = $private_ip, c.public_ip = $public_ip, c.state = $state,
    c.instance_type = $instance_type, c.source = 'aws_api', c.last_seen = $sync_ts
WITH c
OPTIONAL MATCH (s:Network {rid: $subnet_rid})
FOREACH (_ IN CASE WHEN s IS NULL THEN [] ELSE [1] END |
  MERGE (c)-[e:IN]->(s) SET e.source = 'aws_api', e.last_seen = $sync_ts)
