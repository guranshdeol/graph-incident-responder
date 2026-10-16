// §5 indexes. One statement per ';'. Run once per graph (graph/db.py: apply_schema).
CREATE INDEX FOR (r:Resource) ON (r.rid);
CREATE INDEX FOR (a:Alert) ON (a.id);
CREATE INDEX FOR (c:Change) ON (c.event_id);
CREATE INDEX FOR (i:Incident) ON (i.id);
CREATE INDEX FOR (x:Action) ON (x.id);
