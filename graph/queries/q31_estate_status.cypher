// Q31 estate_status: what the graph holds and how fresh it is: resources and edges, last discovery
// sync, last CloudTrail event, last alert (the console's Integrations page). Params: none
MATCH (r:Resource)
WITH count(r) AS resources, max(r.last_seen) AS last_sync
OPTIONAL MATCH (:Resource)-[e]->(:Resource)
WITH resources, last_sync, count(e) AS edges
OPTIONAL MATCH (c:Change)
WITH resources, last_sync, edges, max(CASE WHEN c.source = 'cloudtrail' THEN c.at END) AS last_trail,
     sum(CASE WHEN c.source = 'cloudtrail' THEN 1 ELSE 0 END) AS trail_events, count(c) AS changes
OPTIONAL MATCH (a:Alert)
RETURN resources, edges, last_sync, last_trail, trail_events, changes, max(a.starts_at) AS last_alert, count(a) AS alerts
