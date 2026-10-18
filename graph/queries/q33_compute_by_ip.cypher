// Q33 compute_by_ip: the instance that owns this public IP (the watchdog finds the monitoring host from
// PROMETHEUS_URL). Params: $ip
MATCH (c:Compute {public_ip: $ip})
RETURN c.rid AS rid, c.name AS name, c.state AS state
LIMIT 1
