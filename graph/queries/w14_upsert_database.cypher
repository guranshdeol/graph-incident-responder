// W14 upsert an RDS instance, IN each subnet of its subnet group. Params: $rid, $name, $engine, $endpoint, $port, $status, $subnet_rids, $sync_ts
MERGE (d:Resource:Database {rid: $rid})
SET d.name = $name, d.engine = $engine, d.endpoint = $endpoint, d.port = $port, d.status = $status,
    d.source = 'aws_api', d.last_seen = $sync_ts, d.state = 'present'
WITH d
UNWIND (CASE WHEN size($subnet_rids) = 0 THEN [null] ELSE $subnet_rids END) AS srid
OPTIONAL MATCH (s:Network {rid: srid})
FOREACH (_ IN CASE WHEN s IS NULL THEN [] ELSE [1] END |
  MERGE (d)-[e:IN]->(s) SET e.source = 'aws_api', e.last_seen = $sync_ts)
