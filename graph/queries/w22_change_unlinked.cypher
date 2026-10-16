// W22 remember rids a CloudTrail Change named that the graph doesn't have yet (§6.3). Params: $event_id, $rids
MATCH (ch:Change {event_id: $event_id})
SET ch.unlinked_rids = $rids
