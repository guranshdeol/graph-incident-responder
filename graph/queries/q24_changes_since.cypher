// Q24 changes_since: every change anywhere in the estate since $since, newest first: the "what changed
// in the account" feed, and the agent's tool to search for a change it hasn't been shown. Params: $since, $limit
MATCH (ch:Change)
WHERE ch.at >= $since
OPTIONAL MATCH (ch)-[:MODIFIED]->(r:Resource)
WITH ch, collect(r.rid) AS resources, collect(coalesce(r.name, r.rid)) AS names
RETURN ch.event_id AS event_id, ch.at AS at, ch.source AS source, ch.event_name AS event_name, ch.actor AS actor,
       ch.by_agent AS by_agent, ch.before AS before, ch.after AS after, resources, names
ORDER BY at DESC
LIMIT $limit
