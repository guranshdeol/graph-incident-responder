// Q27 detached_from: security groups detached from this resource since $since (precondition for
// reattach_security_group). Params: $rid, $since
MATCH (fw:Firewall)-[p:PROTECTS]->(:Resource {rid: $rid})
WHERE p.active = false AND p.removed_at >= $since
RETURN fw.rid AS firewall, p.removed_at AS removed_at
ORDER BY removed_at DESC
