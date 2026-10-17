// W25 graph diff, before W13/W14 overwrite it: an instance or database whose state changed since the last
// sync (e.g. running -> stopped) gets a Change. Params: $rid, $state, $sync_ts
MATCH (r:Resource {rid: $rid})
WHERE r.state IS NOT NULL AND r.state <> $state AND r.state <> 'missing'
CREATE (ch:Change {event_id: 'diff:state:' + $rid + ':' + toString($sync_ts), source: 'graph_diff',
                   event_name: 'InstanceStateChanged', at: $sync_ts, before: r.state, after: $state})
CREATE (ch)-[:MODIFIED]->(r)
RETURN r.state AS before
