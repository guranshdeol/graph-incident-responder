// Q12 open_incident_for_group: an open incident for this Alertmanager group opened since $since (§6.5). Params: $group_key, $since
MATCH (i:Incident {group_key: $group_key, status: 'open'})
WHERE i.opened_at >= $since
RETURN i.id AS id, i.opened_at AS opened_at
ORDER BY opened_at DESC LIMIT 1
