// Q3 path_between: shortest dependency path. Params: $from, $to
MATCH (a:Resource {rid: $from}), (b:Resource {rid: $to})
CALL algo.SPpaths({sourceNode: a, targetNode: b, relTypes: ['DEPENDS_ON','RUNS_ON'],
                   relDirection: 'outgoing', weightProp: 'weight', pathCount: 1})
YIELD path, pathWeight
RETURN [n IN nodes(path) | n.rid] AS hops, pathWeight
