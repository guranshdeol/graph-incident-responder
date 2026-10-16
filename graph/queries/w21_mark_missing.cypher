// W21 discovered resources not seen in this sync are marked missing, never deleted (§6.1). Params: $sync_ts
MATCH (r:Resource)
WHERE r.source = 'aws_api' AND r.last_seen < $sync_ts AND coalesce(r.state, '') <> 'missing'
  AND (r:Compute OR r:Database OR r:Firewall OR r:Network)
SET r.state = 'missing'
RETURN r.rid AS rid
