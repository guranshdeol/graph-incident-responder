// Q1 resolve: does this exist? canonical rid. Params: $x
MATCH (r:Resource) WHERE r.rid = $x OR r.name = $x
RETURN r.rid AS rid, labels(r) AS kinds LIMIT 1
