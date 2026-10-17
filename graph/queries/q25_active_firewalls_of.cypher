// Q25 active_firewalls_of: the security groups currently attached to an instance or database
// (reattach_security_group sends the full list back to AWS). Params: $rid
MATCH (fw:Firewall)-[p:PROTECTS]->(:Resource {rid: $rid})
WHERE coalesce(p.active, true)
RETURN fw.rid AS firewall
ORDER BY firewall
