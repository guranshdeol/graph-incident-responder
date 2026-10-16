// W10 record a (validated) finding about an incident and resources. Params: $id, $text, $now, $confidence, $incident_id, $about_rids
MATCH (i:Incident {id: $incident_id})
CREATE (f:Finding {id: $id, text: $text, at: $now, confidence: $confidence})
CREATE (f)-[:ABOUT]->(i)
WITH f
UNWIND $about_rids AS rid
MATCH (r:Resource {rid: rid})
CREATE (f)-[:ABOUT]->(r)
