// Q17 resource_nodes: every infrastructure node, for the UI graph panel. Params: none
MATCH (n:Resource)
RETURN n.rid AS rid, labels(n) AS kinds, n.name AS name
ORDER BY rid
