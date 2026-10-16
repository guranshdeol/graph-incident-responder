// W20 a declared dependency (services.yaml). Params: $from, $to, $kind, $port, $sync_ts
MATCH (a:Service {rid: $from}), (b:Resource {rid: $to})
MERGE (a)-[d:DEPENDS_ON]->(b)
SET d.kind = $kind, d.port = $port, d.weight = 1, d.source = 'declared', d.last_seen = $sync_ts
RETURN b.rid AS target
