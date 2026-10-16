// W15 upsert a security group. Params: $rid, $name, $sync_ts
MERGE (f:Resource:Firewall {rid: $rid})
SET f.name = $name, f.kind = 'security_group', f.source = 'aws_api', f.last_seen = $sync_ts, f.state = 'present'
