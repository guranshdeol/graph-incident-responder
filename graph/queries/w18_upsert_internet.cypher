// W18 the 0.0.0.0/0 traffic source. Params: $sync_ts
MERGE (i:Resource:Internet {rid: 'internet'})
SET i.name = 'internet', i.cidr = '0.0.0.0/0', i.source = 'aws_api', i.last_seen = $sync_ts
