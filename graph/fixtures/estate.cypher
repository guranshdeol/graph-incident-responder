// §9 demo estate, SYNTHETIC FIXTURE (placeholder ids, not real AWS ids).
// Loaded into ops_test by pytest and into ops_sandbox for the public demo.
// last_seen = 1792100000 (2026-10-16). All timestamps are epoch seconds.
//
// host-1 (i-host1): web, checkout, payments    sg-host1
// host-2 (i-host2): orders, reports            sg-host2
// orders-db (rds:orders-db), Postgres 5432     sg-db (rules A, B) + sg-db-admin (risk #18)
CREATE
  // --- network -------------------------------------------------------------
  (vpc:Resource:Network   {rid: 'vpc-demo',     name: 'rootgraph-vpc', kind: 'vpc',    cidr: '10.0.0.0/16', source: 'aws_api', last_seen: 1792100000}),
  (sna:Resource:Network   {rid: 'subnet-a',     name: 'subnet-a',      kind: 'subnet', cidr: '10.0.1.0/24', source: 'aws_api', last_seen: 1792100000}),
  (snb:Resource:Network   {rid: 'subnet-b',     name: 'subnet-b',      kind: 'subnet', cidr: '10.0.2.0/24', source: 'aws_api', last_seen: 1792100000}),
  (inet:Resource:Internet {rid: 'internet',     name: 'internet',      cidr: '0.0.0.0/0',      source: 'aws_api', last_seen: 1792100000}),
  (adm:Resource:CidrBlock {rid: 'cidr:203.0.113.0/24', name: 'admin-vpn', cidr: '203.0.113.0/24', source: 'aws_api', last_seen: 1792100000}),

  // --- compute + database --------------------------------------------------
  (h1:Resource:Compute  {rid: 'i-host1', name: 'host-1', private_ip: '10.0.1.10', public_ip: '198.51.100.11', state: 'running', instance_type: 't3.small', source: 'aws_api', last_seen: 1792100000}),
  (h2:Resource:Compute  {rid: 'i-host2', name: 'host-2', private_ip: '10.0.2.10', public_ip: '198.51.100.12', state: 'running', instance_type: 't3.small', source: 'aws_api', last_seen: 1792100000}),
  (db:Resource:Database {rid: 'rds:orders-db', name: 'orders-db', engine: 'postgres', endpoint: 'orders-db.example.ap-south-1.rds.amazonaws.com', port: 5432, status: 'available', source: 'aws_api', last_seen: 1792100000}),

  (h1)-[:IN {source: 'aws_api', last_seen: 1792100000}]->(sna),
  (h2)-[:IN {source: 'aws_api', last_seen: 1792100000}]->(snb),
  (db)-[:IN {source: 'aws_api', last_seen: 1792100000}]->(snb),
  (sna)-[:IN {source: 'aws_api', last_seen: 1792100000}]->(vpc),
  (snb)-[:IN {source: 'aws_api', last_seen: 1792100000}]->(vpc),

  // --- security groups -----------------------------------------------------
  (fh1:Resource:Firewall {rid: 'sg-host1',    name: 'sg-host1',    kind: 'security_group', source: 'aws_api', last_seen: 1792100000}),
  (fh2:Resource:Firewall {rid: 'sg-host2',    name: 'sg-host2',    kind: 'security_group', source: 'aws_api', last_seen: 1792100000}),
  (fdb:Resource:Firewall {rid: 'sg-db',       name: 'sg-db',       kind: 'security_group', source: 'aws_api', last_seen: 1792100000}),
  (fad:Resource:Firewall {rid: 'sg-db-admin', name: 'sg-db-admin', kind: 'security_group', source: 'aws_api', last_seen: 1792100000}),

  (fh1)-[:PROTECTS {source: 'aws_api', last_seen: 1792100000}]->(h1),
  (fh2)-[:PROTECTS {source: 'aws_api', last_seen: 1792100000}]->(h2),
  (fdb)-[:PROTECTS {source: 'aws_api', last_seen: 1792100000}]->(db),
  (fad)-[:PROTECTS {source: 'aws_api', last_seen: 1792100000}]->(db),

  // ALLOWS_FROM points from the protecting SG to the traffic source.
  // Rule A: sg-db allows 5432 from sg-host1 (S1 revokes this one).
  (fdb)-[:ALLOWS_FROM {rule_id: 'sgr-a', proto: 'tcp', port_from: 5432, port_to: 5432, active: true, source: 'aws_api', last_seen: 1792100000}]->(fh1),
  // Rule B: sg-db allows 5432 from sg-host2.
  (fdb)-[:ALLOWS_FROM {rule_id: 'sgr-b', proto: 'tcp', port_from: 5432, port_to: 5432, active: true, source: 'aws_api', last_seen: 1792100000}]->(fh2),
  // Second SG on orders-db: admin VPN only. Must NOT make payments -> orders-db permitted when rule A is gone.
  (fad)-[:ALLOWS_FROM {rule_id: 'sgr-admin-pg', proto: 'tcp', port_from: 5432, port_to: 5432, active: true, source: 'aws_api', last_seen: 1792100000}]->(adm),
  // Public web on host-1; host-1 may call orders on host-2.
  (fh1)-[:ALLOWS_FROM {rule_id: 'sgr-h1-web',    proto: 'tcp', port_from: 8080, port_to: 8080, active: true, source: 'aws_api', last_seen: 1792100000}]->(inet),
  (fh2)-[:ALLOWS_FROM {rule_id: 'sgr-h2-orders', proto: 'tcp', port_from: 8083, port_to: 8083, active: true, source: 'aws_api', last_seen: 1792100000}]->(fh1),

  // --- services (declared, ingest/services.yaml) ----------------------------
  (web:Resource:Service      {rid: 'svc:web',      name: 'web',      port: 8080, source: 'declared', last_seen: 1792100000}),
  (checkout:Resource:Service {rid: 'svc:checkout', name: 'checkout', port: 8081, source: 'declared', last_seen: 1792100000}),
  (payments:Resource:Service {rid: 'svc:payments', name: 'payments', port: 8082, source: 'declared', last_seen: 1792100000}),
  (orders:Resource:Service   {rid: 'svc:orders',   name: 'orders',   port: 8083, source: 'declared', last_seen: 1792100000}),
  (reports:Resource:Service  {rid: 'svc:reports',  name: 'reports',  port: 8084, source: 'declared', last_seen: 1792100000}),

  (web)-[:RUNS_ON      {weight: 1, source: 'declared', last_seen: 1792100000}]->(h1),
  (checkout)-[:RUNS_ON {weight: 1, source: 'declared', last_seen: 1792100000}]->(h1),
  (payments)-[:RUNS_ON {weight: 1, source: 'declared', last_seen: 1792100000}]->(h1),
  (orders)-[:RUNS_ON   {weight: 1, source: 'declared', last_seen: 1792100000}]->(h2),
  (reports)-[:RUNS_ON  {weight: 1, source: 'declared', last_seen: 1792100000}]->(h2),

  (web)-[:DEPENDS_ON      {kind: 'http', port: 8081, source: 'declared', weight: 1, last_seen: 1792100000}]->(checkout),
  (web)-[:DEPENDS_ON      {kind: 'http', port: 8083, source: 'declared', weight: 1, last_seen: 1792100000}]->(orders),
  (checkout)-[:DEPENDS_ON {kind: 'http', port: 8082, source: 'declared', weight: 1, last_seen: 1792100000}]->(payments),
  (payments)-[:DEPENDS_ON {kind: 'db',   port: 5432, source: 'declared', weight: 1, last_seen: 1792100000}]->(db),
  (orders)-[:DEPENDS_ON   {kind: 'db',   port: 5432, source: 'declared', weight: 1, last_seen: 1792100000}]->(db),
  (reports)-[:DEPENDS_ON  {kind: 'db',   port: 5432, source: 'declared', weight: 1, last_seen: 1792100000}]->(db);
