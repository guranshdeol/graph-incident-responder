// W7 write the scorecard as SUSPECTS edges. Params: $id, $rows = [{rid, score, rank}]
MATCH (i:Incident {id: $id})
UNWIND $rows AS row
MATCH (r:Resource {rid: row.rid})
MERGE (i)-[s:SUSPECTS]->(r)
SET s.score = row.score, s.rank = row.rank
