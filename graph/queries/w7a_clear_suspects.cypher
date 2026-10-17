// W7a drop an incident's previous scorecard before writing a new one (a re-investigation replaces it). Params: $id
MATCH (:Incident {id: $id})-[s:SUSPECTS]->()
DELETE s
