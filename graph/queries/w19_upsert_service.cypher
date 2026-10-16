// W19 upsert a declared service (services.yaml) and where it runs. Params: $rid, $name, $port, $host_rid, $sync_ts
MERGE (s:Resource:Service {rid: $rid})
SET s.name = $name, s.port = $port, s.source = 'declared', s.last_seen = $sync_ts
WITH s
OPTIONAL MATCH (h:Compute {rid: $host_rid})
FOREACH (_ IN CASE WHEN h IS NULL THEN [] ELSE [1] END |
  MERGE (s)-[e:RUNS_ON]->(h) SET e.weight = 1, e.source = 'declared', e.last_seen = $sync_ts)
