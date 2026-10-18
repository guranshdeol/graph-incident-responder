Draft — review before publishing.

# Many alerts, one cause: letting a graph decide what an LLM explains

## The on-call problem

An on-call engineer gets four alerts within a minute. Payments, checkout and web report a high error rate, and a blackbox probe from host-1 to `orders-db` on port 5432 fails. The usual first move is to find the one resource that explains the most of them. We call this coverage.

In our S1 scenario, a human revokes the security-group rule that let host-1 reach `orders-db` on 5432. Coverage ranks host-1 first, because host-1 runs web, checkout and payments and is the source of the failing probe. Host-1 is healthy. The cause is a rule on the database's firewall.

The problem is structural. An upward walk follows service dependencies and hosting relationships. A security-group rule is on neither chain, so no walk from the alerts reaches it. Finding it means checking the network path a dependency takes and the infrastructure change that removed the rule.

## The graph model

rootgraph keeps the estate, alerts, changes, incidents and memory in one FalkorDB multigraph per environment. Infrastructure nodes carry the label `Resource`, a kind label (`Service`, `Compute`, `Database`, `Firewall`, `Network`, `Internet`, `CidrBlock`) and a unique `rid` such as `svc:payments`, `i-…` or `sg-…`.

Security groups are `Firewall` nodes, and their rules are `ALLOWS_FROM` edges from the protecting group to the traffic source. Each edge carries `rule_id`, `proto`, `port_from`, `port_to`, `active` and `removed_at`.

Removed rules are never deleted. Discovery sets `active = false` and `removed_at` on the edge and writes a `Change` node. The restore action needs the exact protocol, ports and source, and the inactive edge holds them. CloudTrail changes arrive through EventBridge and SQS, and the graph diff covers the case where CloudTrail is late.

## Walking upward, then proving it

Q2 (`correlate_alerts`) walks upward from the alerting resources. Quoted from `docs/graph.md`:

```cypher
UNWIND $alert_rids AS rid
MATCH p = (s:Resource {rid: rid})-[:DEPENDS_ON|RUNS_ON*0..4]->(c:Resource)
WITH c, rid, min(length(p)) AS hops
WITH c, collect(rid) AS explains, min(hops) AS min_hops
RETURN c.rid AS candidate, labels(c) AS kinds, size(explains) AS coverage, explains, min_hops
ORDER BY coverage DESC, min_hops ASC
LIMIT $k
```

Each alerting resource walks `DEPENDS_ON` or `RUNS_ON` edges upward for up to four hops, and the zero-length case lets it count as its own candidate. The pipeline keeps the top five by coverage. Coverage is the only signal this query gives, so it is the first step, not the last.

Q4 (`check_path`) then asks whether the route for one dependency is permitted. Quoted from `docs/graph.md`:

```cypher
MATCH (x:Service {rid: $from})-[:RUNS_ON]->(h:Compute)
MATCH (x)-[d:DEPENDS_ON]->(y:Resource {rid: $to})
MATCH (fw:Firewall)-[:PROTECTS]->(y)
OPTIONAL MATCH (hfw:Firewall)-[:PROTECTS]->(h)
WITH h, d, collect(DISTINCT fw) AS target_fws, collect(DISTINCT hfw) AS host_fws
UNWIND target_fws AS fw
OPTIONAL MATCH (fw)-[r:ALLOWS_FROM]->(src)
  WHERE r.active = true
    AND r.port_from <= d.port AND d.port <= r.port_to
    AND (src = h OR src:Internet OR src IN host_fws)
WITH h, d, fw, collect(r.rule_id) AS rules
RETURN h.rid AS host, d.port AS port,
       collect({firewall: fw.rid, rules: rules}) AS per_firewall,
       sum(size(rules)) > 0 AS permitted
```

The verdict is taken across all firewalls on the target, because AWS permits a connection if any group allows it. In S1, `check_path` from `svc:payments` to `rds:orders-db` returns `permitted = false`, a broken path.

A broken path does not name the culprit. Q10 (`removed_rules`) does that. It applies the same matching to inactive rules removed in the last 30 minutes. A firewall that lost a rule which used to permit the path becomes the culprit. If none did, every firewall on the target is a candidate. This is how `sg-db` is chosen in S1, and it keeps `sg-db-admin` out, since that group never allowed host-1.

## Scoring you can read

The score is a fixed formula (plan section 7.4), written to the graph as `SUSPECTS` edges and shown in the UI as a scorecard:

```
score = 3.0 * coverage_ratio
      + 2.0 * probe_unhealthy
      - 2.0 * probe_healthy
      + 2.0 * broken_path
      + 2.0 * change_in_window
      + 1.0 * prior_incident_match
      - 0.25 * min_hops
```

Coverage makes a node a suspect. Probes, broken paths, changes and memory move it up or down. A healthy-probing candidate loses 2.0, which is how host-1 falls below `sg-db`.

Fixture results: S1 gives `sg-db` 6.75. Host-1, which explains every alert, drops to 1.0 because its probe is healthy; the runner-up is `svc:payments` at 2.25, a degraded victim. S2 (CPU hog on host-2) gives `i-host2` 5.0. S3 (`payments` stopped) gives `svc:payments` 5.0 with no change found. S4 (S1 repeated) gives `sg-db` 7.75, including the +1.0 from memory. S5 (two faults at once) gives `sg-db` 6.75 and `svc:payments` 4.25. The UI reports "multiple likely causes" when the top two are less than 1.0 apart or the runner-up has direct evidence of its own, as S5 does.

We compared three rankers on the same five scenarios (`python -m eval.baseline`, see `docs/evaluation.md`):

| Ranker | Correct on S1–S5 |
|---|---|
| Coverage only | 2/5 |
| Coverage + hop distance (no evidence) | 2/5 |
| Scorecard (probes, paths, changes, memory) | 5/5 |

Coverage alone blames host-1 in S1 and S4 and misses `sg-db` in S5. It is enough when the cause is on the dependency chain itself, as in S2 and S3.

These are five hand-made scenarios on a 17-node estate, and we tuned the weights on them. The table shows the mechanism working on these cases. It does not show general accuracy. S5 is ranked, not split: both causes are in the top two, but the alerts are not divided between them.

## Where the LLM fits

The pipeline is deterministic and runs without an LLM. The LLM is step 7, the explanation. It receives the scorecard and the evidence so far, never the whole graph. It may call up to six of seven read tools it chooses:

- `check_path`: is a dependency's route permitted, and which rule blocks it?
- `removed_rules`: which firewall lost a rule on a broken path in the last 30 minutes?
- `probe`: is a high-coverage candidate actually healthy?
- `recent_changes`: what changed on the resource and its two-hop neighbourhood?
- `blast_radius`, `path_between`, `recall_incidents`: downstream impact, dependency path, and past matching incidents.

Every call must carry a `reason`, or it is rejected. The UI marks each call as agent-chosen and shows the reason. The model cannot write Cypher, change anything or approve a fix.

The final answer is JSON. A validator checks that the root cause is a scored candidate, every resource id in the explanation appears in the evidence, the action is in the catalogue and aimed at the root cause, the answer cites at least one call that returned rows, and any change of top candidate is backed by an agent-chosen call. If a check fails, or the provider errors, the template answer goes out. The template is built only from scorecard rows. A validated answer can change the top candidate and so the proposed action, but the scorecard is never rewritten.

The provider is OpenRouter with free Nemotron models. `LLM_MODEL` lists `nvidia/nemotron-3-ultra-550b-a55b:free` first and `nvidia/nemotron-3-super-120b-a12b:free` as fallback, sent as OpenRouter's `models` routing. At 01:30 IST on 17 October, Ultra's only provider was down and returned 404 on every call, so Nemotron 3 Super answered. The incident records which model answered.

In the first live run of S1, the agent made two calls: `check_path` from payments to `orders-db`, and `recent_changes` on `sg-db`. The validator accepted the answer. The run used about 17k input and 1.3k output tokens, and took about 30 seconds on the free tier.

The validator checks resource ids, citations and the catalogue, not wording. In that run, the explanation called host-1 "degraded" although its probe was healthy, and the sentence passed. We have not closed this gap.

## Memory as graph

We map three kinds of memory onto nodes:

- Episodic: an `Incident` records its alerts, root cause, linked change, time to resolve and tokens used.
- Semantic: a `Finding` holds validated text, and every resource id in it must resolve in the graph.
- Procedural: a verified `Action` stores its kind and exact parameters.

Recall (Q7) matches resolved incidents by alert-name overlap or shared candidate root cause, and returns the fix with its parameters. In S4, a repeat of S1, recall finds the earlier incident, adds 1.0 to `sg-db`, and pre-fills the restore from the stored action.

## What broke in the first real run

The first real run stopped `payments` (S3). Alertmanager fired ServiceDown and HighErrorRate, the webhook arrived in about 40 seconds, and the investigation ranked `svc:payments` first at 5.0, with a live probe of `up=0`. It proposed `restart_service` with its blast radius. The path worked, and these did not:

- Alertmanager sends a group in batches. The API now re-investigates when firing alerts join an open incident.
- Each re-investigation proposed the same fix again. It now reuses the existing proposal.
- An unreachable Prometheus made the probe raise. It now returns `error` with state `unknown`.
- Compose named the containers `rootgraph-demo-payments-1`, but the restart targeted `payments`. We found this writing the deploy tests and fixed the names.
- `state.json`, which holds the database password and IAM keys, was created with mode 644. It is now 600. `alertmanager.yml` holds the webhook token and is mode 600.

## Limitations and what is next

The README lists these limitations, and none is closed:

- S5 is ranked, not split. The weights are heuristic and were tuned on five fixtures.
- Q4 ignores CIDR containment, and it checks only firewalls that protect the target itself. A service-to-service path such as web to orders returns `not_in_graph`, even when a host firewall guards the target. Fixing that means walking `RUNS_ON` to the host, a schema change the team has not agreed on.
- Discovery skips IPv6 and prefix-list rules. Observed-traffic dependencies are not built.
- `reboot_compute` is not built. The executor refuses to restore a rule whose source is a single instance.
- Live AWS code is tested against moto. Real CloudTrail payloads may differ, since our sample event is hand-written.
- The public sandbox is unauthenticated on purpose, and its effects are graph-only.

The two gaps most relevant to the claims here are the Q4 limits and the lack of a recorded real CloudTrail event.

## Try it

- Sandbox: https://172-232-86-149.sslip.io. Click S1 to inject the fault, approve the proposed restore, then click S4 to see recall pre-fill the fix.
- Repository: https://github.com/guranshdeol/rootgraph-incident-responder. The README covers Docker setup and the tests. The project was built with AI coding assistants, and the README says which ones and for what.
