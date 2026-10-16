// Q18 resource_edges: infrastructure edges between resources, for the UI graph panel.
// ALLOWS_FROM edges carry active/port so removed rules can be drawn. Params: none
MATCH (a:Resource)-[r:DEPENDS_ON|RUNS_ON|PROTECTS|ALLOWS_FROM]->(b:Resource)
RETURN a.rid AS source, type(r) AS type, b.rid AS target, r.active AS active,
       r.port_from AS port_from, r.port_to AS port_to, r.rule_id AS rule_id
