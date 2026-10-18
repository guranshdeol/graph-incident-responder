![rootgraph: many alerts, one cause](https://raw.githubusercontent.com/guranshdeol/rootgraph-incident-responder/main/docs/img/incident.png)

It's 2 a.m. and four alerts fire within a minute. Web, checkout and payments throw errors, and a probe says host-1 can't reach the orders database. The on-call engineer asks the only question that matters: **which one thing explains all of this?**

For **Graph Hacks** (WeMakeDevs × FalkorDB) we built **rootgraph**, an incident responder that answers that question with a graph. It keeps a live FalkorDB graph of a real AWS account and walks it from the alerts to the change that caused them. It proves the conclusion with the network path and the CloudTrail record of who changed what, then proposes the exact undo. That undo runs only after a person approves it. Then rootgraph checks that the fix worked and remembers it for next time.

This post covers the graph model, the Cypher that does the work, how the AI agent is kept honest, and what broke when we let teammates break the real AWS account by hand.

- **Repository:** https://github.com/guranshdeol/rootgraph-incident-responder
- **Tracks:** Agents That Act on Connected Data, and Agent Memory and Coordination

---

## The problem: the busiest node is not the guilty one

In our headline scenario, someone deletes the security-group rule that lets host-1 reach `orders-db` on port 5432. Four alerts fire.

The obvious first move is to find the resource that explains the most alerts. That is **host-1**, because web, checkout and payments all run on it, and the failing probe starts there. It touches every alert.

But host-1 is perfectly healthy. The cause is a single rule on the database's firewall, and nothing on a normal dashboard points there.

The problem is structural. A firewall rule is not on the dependency chain (service → service → database) or the hosting chain (service → host). No walk along those edges reaches it. Finding it means asking a different kind of question: *is the network path this dependency takes actually open, and if not, what changed?* That is a graph question, so we put everything in a graph.

## The graph model

Everything lives in one FalkorDB graph per environment: topology, firewall rules, alerts, changes, incidents, fixes and memory. There is no side database.

![The incident's graph evidence: broken paths in red, the root cause in ink](https://raw.githubusercontent.com/guranshdeol/rootgraph-incident-responder/main/docs/img/graph.png)

**Infrastructure nodes** carry the label `Resource`, a kind label and a unique `rid`:

| Kind | Example rid | Comes from |
|---|---|---|
| `Service` | `svc:payments` | declared in `services.yaml` |
| `Compute` | `i-0a2b…` (EC2) | AWS discovery |
| `Database` | `rds:orders-db` | AWS discovery |
| `Firewall` | `sg-09a1…` (security group) | AWS discovery |
| `Network`, `Internet`, `CidrBlock` | `subnet-…`, `internet` | AWS discovery |

**The edges that matter:**

```
(Service)-[:DEPENDS_ON {kind, port}]->(Service | Database)
(Service)-[:RUNS_ON]->(Compute)
(Firewall)-[:PROTECTS {active}]->(Compute | Database)
(Firewall)-[:ALLOWS_FROM {rule_id, proto, port_from, port_to, active, removed_at}]->(source)
(Change {event_name, actor, by_agent})-[:MODIFIED]->(Resource)
(Alert)-[:FIRING_ON]->(Resource)
(Incident)-[:HAS_ALERT | SUSPECTS | ROOT_CAUSE | EXPLAINED_BY]->(…)
(Action {kind, params, status})-[:FOR | TARGETS | RESOLVED]->(…)
```

A security-group rule is an `ALLOWS_FROM` edge from the group to the traffic it lets in. That modelling choice is what makes path checks a graph query.

**History is never deleted.** When a rule disappears, discovery doesn't remove the edge. It sets `active = false` and `removed_at`, and writes a `Change` node. The undo needs the exact protocol, ports and source, and the inactive edge still holds them. Detached security groups (`PROTECTS.active = false`) and instance state changes (`running → stopped`) are recorded the same way.

**Keeping it current:**
- **Discovery** reads the AWS account (EC2, RDS, security groups) every 60 seconds with a read-only IAM user, and diffs it against the graph.
- **CloudTrail** events stream in through EventBridge and SQS, carrying who made each change. In our live runs a change reached the graph in about 4 seconds.
- **Alerts** carry a `rid` label equal to a node's `rid`, so an alert is a place in the graph.

## Walk upward, then prove it

### Step 1: walk up from the symptoms

FalkorDB's own "Blast Radius" demo looks *down* from a failure: what breaks if X fails? rootgraph walks *up* from the symptoms instead. Q2, `correlate_alerts`:

```cypher
UNWIND $alert_rids AS rid
MATCH p = (s:Resource {rid: rid})-[:DEPENDS_ON|RUNS_ON*0..4]->(c:Resource)
WITH c, rid, min(length(p)) AS hops
WITH c, collect(rid) AS explains, min(hops) AS min_hops
RETURN c.rid AS candidate, labels(c) AS kinds, size(explains) AS coverage, explains, min_hops
ORDER BY coverage DESC, min_hops ASC
LIMIT $k
```

Each alerting resource follows dependency and hosting edges for up to four hops. The zero-length match lets it count as its own candidate. This gives **coverage**, and coverage alone ranks host-1 first. That's exactly the answer we can't trust yet.

### Step 2: is the path actually open?

Q4, `check_path`, asks whether the network route for one dependency is allowed by every security group on the way:

```cypher
MATCH (x:Service {rid: $from})-[:RUNS_ON]->(h:Compute)
MATCH (x)-[d:DEPENDS_ON]->(y:Resource {rid: $to})
OPTIONAL MATCH (y)-[:RUNS_ON]->(yh:Compute)
WITH h, d, coalesce(yh, y) AS t
WHERE t <> h
MATCH (fw:Firewall)-[pt:PROTECTS]->(t)
WHERE coalesce(pt.active, true)
OPTIONAL MATCH (hfw:Firewall)-[ph:PROTECTS]->(h)
WHERE coalesce(ph.active, true)
WITH h, d, t, collect(DISTINCT fw) AS target_fws, collect(DISTINCT hfw) AS host_fws
UNWIND target_fws AS fw
OPTIONAL MATCH (fw)-[r:ALLOWS_FROM]->(src)
  WHERE r.active = true
    AND r.port_from <= d.port AND d.port <= r.port_to
    AND (src = h OR src:Internet OR src IN host_fws)
WITH h, d, t, fw, collect(r.rule_id) AS rules
RETURN h.rid AS host, d.port AS port, t.rid AS guarded,
       collect({firewall: fw.rid, rules: rules}) AS per_firewall,
       sum(size(rules)) > 0 AS permitted
```

A few details carry the logic:
- **The guarded node** is the target itself (a database), or the host the target runs on when it's a service on another host. Calls between services on the same host never cross a firewall.
- **Only active attachments count.** A detached security group no longer protects or permits anything.
- **The verdict spans all firewalls on the target,** because AWS allows a connection if any attached group allows it.

In the headline scenario, `check_path(payments → orders-db)` returns `permitted = false`: a broken path.

### Step 3: who broke it?

A broken path doesn't name the culprit. Q10 applies the same matching to **inactive** rules removed in the last 30 minutes. The firewall that lost a rule which used to allow the path becomes the culprit. If no rule was removed, Q23 asks whether a security group was *detached* from the host or the target instead. Q5 then pulls the `Change` nodes on the candidate's neighbourhood, with the CloudTrail actor.

## Scoring you can read

Every candidate gets a deterministic score, written to the graph as `SUSPECTS` edges and shown in the console as a scorecard:

```
score = 3.0 × coverage   (share of alerting resources it explains)
      + 2.0 × unhealthy  (its own probe fails)
      − 2.0 × healthy    (its own probe is fine)
      + 2.0 × broken path
      + 2.0 × changed in the last 30 min (by a person, not by rootgraph)
      + 1.0 × seen before (memory)
      − 0.25 × hops
```

Coverage makes a node a suspect, and the evidence decides. In the headline scenario, host-1 explains every alert but probes healthy, so it drops. The database's security group sits on a broken path and changed two minutes earlier, so it rises to the top.

Does the graph evidence actually matter? We compared rankers on the five headline scenarios ([docs/evaluation.md](https://github.com/guranshdeol/rootgraph-incident-responder/blob/main/docs/evaluation.md)):

| Ranker | Correct |
|---|---|
| Coverage only (the busiest node) | 2 / 5 |
| Coverage + hop distance | 2 / 5 |
| rootgraph scorecard (paths, changes, health, memory) | **5 / 5** |

These are hand-made scenarios on a small estate, and we tuned the weights on them, so this shows the mechanism working, not general accuracy. It does show the point: **without the graph, you blame the wrong thing.**

## Where the AI agent fits, and how it's kept honest

The pipeline is deterministic and works without an LLM. The agent's job is to **double-check the ranking and explain it**, using the same graph:

- **Typed tools only.** It chooses among 12 read-only tools (`check_path`, `removed_rules`, `detached_on_path`, `changes_since`, `recent_changes`, `blast_radius`, `path_between`, `recall_incidents`, and others). Each tool is one fixed, human-written Cypher query. **The model never writes Cypher.**
- **A reason for every call.** Calls without a reason are rejected. The console's Agent trace shows each call the AI chose, its reason, the Cypher and the rows it got back.
- **A validator on the answer.** The root cause must be a scored candidate, every resource it names must appear in the evidence, and the fix must come from the catalogue. If any check fails, a template answer built from the scorecard goes out instead. The diagnosis never depends on the AI.
- **No hands.** The agent can't approve or execute anything.

We used OpenRouter with free NVIDIA Nemotron models (Ultra, falling back to Super, then 3.5 Super VL). The same 12 tools are exposed over **MCP**, so Claude Desktop or Claude Code can investigate the same graph.

## Acting: the exact undo, only with a person's approval

Every fix in the catalogue undoes one kind of change found in the graph:

| Change found in the graph | Fix |
|---|---|
| A rule removed (`ALLOWS_FROM.active = false`) | re-add that exact rule |
| A rule edited in place (port 5432 → 5433) | edit it back |
| A security group detached (`PROTECTS.active = false`) | re-attach it |
| An instance stopped (`running → stopped`) | start it |
| A container down, with no infrastructure change | start the container over SSM |

Before approval, the console shows the exact AWS CLI command, the blast radius (what depends on the target) and the rollback. The approval is recorded under the signed-in operator's name. The executor runs as an **undo-only IAM user**: it can re-add, re-attach and start, but it cannot delete or stop anything. Its own changes are tagged `by_agent = true`, so a fix is never mistaken for a new cause.

Then **verification**. rootgraph polls until the incident's alerts resolve and the path or probe checks out. Only then is the incident closed.

## Memory lives in the graph too

When an incident resolves, it stays in the graph, linked to the infrastructure it was about:

- **Episodic:** the `Incident` with its alerts, root cause, the `Change` that explained it, and the time to resolve.
- **Procedural:** the verified `Action` with its kind and **exact parameters**.
- **Semantic:** a `Finding` with the validated explanation. Every resource it names must resolve in the graph.

Recall (Q7) matches past incidents by alert-name overlap or by the same root cause:

```cypher
MATCH (i:Incident {status: 'resolved'})-[:ROOT_CAUSE]->(rc:Resource)
OPTIONAL MATCH (i)-[:HAS_ALERT]->(al:Alert)
WITH i, rc, collect(DISTINCT al.alertname) AS past_alerts
WITH i, rc, size([a IN past_alerts WHERE a IN $alertnames]) AS alert_overlap,
     CASE WHEN rc.rid IN $candidate_rids THEN 1 ELSE 0 END AS same_cause
WHERE alert_overlap > 0 OR same_cause = 1
OPTIONAL MATCH (i)-[:EXPLAINED_BY]->(ch:Change)
OPTIONAL MATCH (act:Action {status: 'verified'})-[:RESOLVED]->(i)
RETURN i.id, i.opened_at, i.ttr_seconds, rc.rid AS root_cause, ch.event_name AS change,
       act.kind AS fix, act.params AS fix_params, alert_overlap, same_cause
ORDER BY same_cause DESC, alert_overlap DESC, i.opened_at DESC
LIMIT 3
```

When the same fault returns, the root-cause card says **"Seen before: INC-…"**, the cause gains +1, and the fix is pre-filled: "the same fix resolved INC-… in 52 s". The console's **Memory** page shows everything rootgraph has learned, and how often later incidents recalled it.

![Memory: what rootgraph learned and how often it was recalled](https://raw.githubusercontent.com/guranshdeol/rootgraph-incident-responder/main/docs/img/memory.png)

## We broke a real AWS account by hand

Fixtures are easy. The real test was letting teammates change our real AWS estate in the AWS console, without telling rootgraph what they did. The estate runs in Sydney: two EC2 hosts, an RDS Postgres database, security groups, CloudTrail, and Prometheus with Alertmanager.

| Change made by hand | rootgraph's conclusion | Undo | Fixed in |
|---|---|---|---|
| Database security group detached in the RDS console | `orders-db` lost its security group; 12 alerts across both hosts, one cause | re-attach | **52 s** |
| host-2 stopped in the EC2 console | host-2 went running → stopped; its services are victims, not causes | start it | 64 s – 3 min |
| A firewall rule revoked | the exact rule, and who removed it | re-add it | 92 – 140 s |
| `docker stop payments` | payments is down; the network is fine | start it | 93 s |
| A rule edited from port 5432 to 5433 | "rule edited", with old and new values | edit it back | verified |
| host-1 stopped (it runs the monitoring) | the watchdog fired; host-1 was stopped | start it | **69 s** |

The times run from incident open to verified fix, and they include a person reading the proposal and clicking Approve.

### What broke when reality hit

The live runs found bugs the fake-AWS tests never could. Our favourite three:

1. **Stopping the monitoring host opened no incident.** host-1 runs Prometheus and Alertmanager. With it down, *nothing could alert*. The graph recorded `running → stopped`, but changes alone don't open incidents. The fix is a **watchdog** outside the estate: the control plane checks Prometheus every 20 s, and after three failures it files a `MonitoringUnreachable` alert on the Prometheus host. That alert opens an incident like any other, and the watchdog resolves it once Prometheus answers again. Verified live: resolved in 69 s.
2. **The monitoring host's IP changed on restart.** Without an Elastic IP, every probe after a restart went to a dead address, so the evidence was all "unknown" and verification couldn't see recovery. The fix was a fixed address for host-1.
3. **A rule removed on a *host's* security group was missed.** Our path check only looked at security groups on the dependency target, so `web → orders` (a service on another host) was never checked. That's the `coalesce(yh, y)` in Q4 above: the guarded node is now the target service's host. A teammate found it by doing two things at once (removing host-2's rule *and* stopping host-2). rootgraph found only the stop, so verification failed. That was the right outcome: it refused to call the incident fixed while alerts still fired.

Other bugs: an Alertmanager webhook waiting behind a slow investigation, a 120 s verification window too short for real alert lag, an IAM policy that needed permission on a rule's *source* group, and a failed fix that left the incident stuck instead of investigating again. Each one is fixed with a regression test (88 tests in total).

## The console

We started with a demo page and threw it away. Judges, and real teams, want a product, not a landing page. rootgraph is now a sign-in-protected **operations console** with two environments: **Production** (the real AWS account) and **Staging** (a simulated copy for fault drills).

![The rootgraph console overview](https://raw.githubusercontent.com/guranshdeol/rootgraph-incident-responder/main/docs/img/overview.png)

- **Overview:** open incidents, fixes awaiting approval, time to resolve, and the most load-bearing resources (FalkorDB's `algo.pageRank` over the dependency graph).
- **Incidents:** Summary (the cause in one sentence, the fix, a timeline that marks the change that caused it), Evidence (the scorecard), Graph, and Agent trace.
- **Changes:** every change in the account, by person, rootgraph or discovery.
- **Actions:** the approval audit log.
- **Topology:** click any resource for its blast radius, dependencies, security groups and changes.
- **Memory** and **Integrations**: what it learned, and what is connected and allowed.

The design is deliberately quiet: ink on paper, hairlines, and one chartreuse colour reserved for whatever needs a person.

## Why FalkorDB

Take FalkorDB out and rootgraph doesn't work:
- **The questions are graph questions.** Which resource do ten alerts share is a variable-length upward traversal (Q2). Is this dependency allowed is a multi-hop join over services, hosts, security groups and rules (Q4). What else breaks is a reverse traversal (Q6). What's load-bearing is `algo.pageRank` (Q8), and the shortest dependency path is `algo.SPpaths` (Q3).
- **One store for everything.** Topology, history, incidents, fixes and memory are connected, so "what changed near this resource?" and "have we fixed this before?" are one hop away.
- **It's fast.** The graph queries in the agent trace run in 0–2 ms each. That's what makes it cheap to check every dependency of every suspect on each investigation.
- **Operations were easy.** One Docker container on our Linode, password-protected and bound to localhost. `GRAPH.COPY` gave us an instant backup before we cleaned up test data.

There are 64 fixed query files in the repo (33 read, 31 write), each documented with its Cypher in `docs/graph.md`.

## Limitations

- The scoring weights are heuristic, tuned on nine fixture scenarios.
- With two simultaneous causes, both are ranked and each gets a fix, but the alerts aren't split between them.
- Service dependencies are declared, not learned from traffic.
- Discovery models IPv4 ingress rules only.

## Try it

- **Repository:** https://github.com/guranshdeol/rootgraph-incident-responder. The README has a judges' checklist, the graph model, every core query, and 4-command Docker setup. Staging needs no cloud account.
- **Live console:** https://172-232-86-149.sslip.io (sign-in required).

**Built with AI assistance.** We used Claude Code (Anthropic's Claude models) throughout, for code, tests and documentation. We chose the problem, the graph model and the design, broke the system on real AWS ourselves, and fed every failure back as a fix. `DECISIONS.md` in the repo records why each non-obvious choice was made.

*Many alerts, one cause. The graph decides, the agent explains, and a human acts.*
