// W12 upsert a VPC or subnet; a subnet is linked IN its VPC. Params: $rid, $name, $kind, $cidr, $parent_rid (null for a VPC), $sync_ts
MERGE (n:Resource:Network {rid: $rid})
SET n.name = $name, n.kind = $kind, n.cidr = $cidr, n.source = 'aws_api', n.last_seen = $sync_ts, n.state = 'present'
WITH n
OPTIONAL MATCH (p:Network {rid: $parent_rid})
FOREACH (_ IN CASE WHEN p IS NULL THEN [] ELSE [1] END |
  MERGE (n)-[e:IN]->(p) SET e.source = 'aws_api', e.last_seen = $sync_ts)
