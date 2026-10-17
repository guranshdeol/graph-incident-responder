// W24 graph diff: a security group still recorded as attached to an instance/database seen in this sync,
// but no longer attached in AWS, was detached. Keep the edge (inactive, with the time) and record a Change.
// Params: $sync_ts
MATCH (f:Firewall)-[p:PROTECTS]->(t:Resource)
WHERE coalesce(p.active, true) AND p.source = 'aws_api' AND p.last_seen < $sync_ts AND t.last_seen = $sync_ts
SET p.active = false, p.removed_at = $sync_ts
CREATE (ch:Change {event_id: 'diff:detach:' + f.rid + ':' + t.rid + ':' + toString($sync_ts), source: 'graph_diff',
                   event_name: 'SecurityGroupDetached', at: $sync_ts, before: f.rid + ' attached to ' + t.rid,
                   after: f.rid + ' detached'})
CREATE (ch)-[:MODIFIED]->(t)
CREATE (ch)-[:MODIFIED]->(f)
RETURN f.rid AS firewall, t.rid AS target
