// Q30 incident_reports: every stored investigation report (the console counts how often memory was reused).
// Params: $limit
MATCH (i:Incident)
WHERE i.report IS NOT NULL
RETURN i.id AS id, i.report AS report
ORDER BY i.opened_at DESC
LIMIT $limit
