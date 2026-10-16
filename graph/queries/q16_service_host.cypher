// Q16 service_host: where a service runs (restart_service needs the host for SSM). Params: $rid
MATCH (s:Service {rid: $rid})-[:RUNS_ON]->(h:Compute)
RETURN h.rid AS host, h.name AS host_name
