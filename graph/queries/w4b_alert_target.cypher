// W4b link an alert to what its probe was trying to reach (blackbox target_rid). Params: $id, $target_rid
MATCH (a:Alert {id: $id}), (t:Resource {rid: $target_rid})
MERGE (a)-[:TARGET]->(t)
