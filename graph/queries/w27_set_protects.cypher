// W27 (re)attach or detach a security group in the graph (sandbox executor + sandbox fault injection).
// Params: $fw, $target, $active, $ts
MATCH (f:Firewall {rid: $fw}), (t:Resource {rid: $target})
MERGE (f)-[p:PROTECTS]->(t)
SET p.active = $active, p.removed_at = CASE WHEN $active THEN null ELSE $ts END
RETURN f.rid AS firewall
