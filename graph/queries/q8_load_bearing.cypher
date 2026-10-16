// Q8 load_bearing: PageRank over DEPENDS_ON. Params: $limit
CALL algo.pageRank('Resource', 'DEPENDS_ON') YIELD node, score
RETURN node.rid AS resource, score ORDER BY score DESC LIMIT $limit
