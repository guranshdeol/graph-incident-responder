// W17 upsert a CIDR traffic source (not a known host /32, not 0.0.0.0/0). Params: $rid, $cidr, $sync_ts
MERGE (c:Resource:CidrBlock {rid: $rid})
SET c.name = $cidr, c.cidr = $cidr, c.source = 'aws_api', c.last_seen = $sync_ts
