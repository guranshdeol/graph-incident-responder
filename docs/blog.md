![Many alerts. One cause.](https://raw.githubusercontent.com/guranshdeol/rootgraph-incident-responder/main/docs/img/blog-cover.png)

At 8:03 on a Sunday night, one of us opened the AWS console and stopped the server that watches everything.

We were testing our own incident responder, rootgraph, three days into a hackathon. It had already caught a deleted firewall rule on a real AWS account, a detached security group and a stopped container. We wanted to see what it would do with something bigger.

It did nothing. No alert. No incident. Nothing on the screen moved.

That silence turned out to be the most useful thing that happened all weekend, and it's a good place to start the story of what we built, why it runs on a graph, and what a real AWS account taught us that our 88 tests never did.

✍️ [YOUR WORDS: one or two lines on what that moment felt like, or what you said out loud when nothing happened.]

---

## Four alerts at 2 a.m.

Here's the problem we set out to solve.

Four alerts arrive within a minute. Web, checkout and payments are throwing errors, and a probe says host-1 can't reach the orders database. You're on call, half awake, and there is only one question: *which one thing explains all of this?*

The obvious answer is host-1. Every failing service runs on it, and the broken probe starts there. It's connected to all four alerts.

It's also completely healthy.

What actually happened is that someone deleted a single rule from the database's security group, the rule that let host-1 talk to Postgres on port 5432. Nothing on a dashboard points there, because a firewall rule doesn't sit on any of the lines you'd normally follow. It isn't a service another service calls, and it isn't the machine anything runs on. It's a condition on the path *between* them.

So the question isn't "what's broken?" It's "**is the path this dependency takes actually open, and if not, what changed?**" That's not a log search. That's a graph question.

## Putting the whole estate in one graph

rootgraph keeps a live FalkorDB graph of an AWS account. Services, EC2 hosts, the RDS database and the security groups are nodes. A service calling another is a `DEPENDS_ON` edge with a port, and a service sits on its host through `RUNS_ON`. A security group `PROTECTS` the instances it's attached to, and each of its rules becomes an edge from the group to the traffic it lets in:

```
(Firewall)-[:ALLOWS_FROM {rule_id, proto, port_from, port_to, active, removed_at}]->(source)
```

That one modelling choice is what makes "is this path open?" a query instead of a guess.

The graph doesn't just hold the current state. Every minute a discovery worker reads the account with a read-only IAM user and diffs it against the graph. When a rule disappears, we **don't delete the edge**. We set `active = false` and stamp `removed_at`, and we write a `Change` node. CloudTrail events arrive through EventBridge and SQS in about four seconds, carrying the name of whoever made the change. Alerts carry the same `rid` as the node they're about, so an alert isn't a line in a log. It's a place in the graph.

Keeping the deleted rule turned out to matter more than anything else we did. When it's time to fix things, the graph still knows the exact protocol, port range and source of the rule that vanished. The fix isn't "add something that looks right". It's "put back exactly what was there".

![Graph evidence for an incident: broken paths in red, the root cause in black](https://raw.githubusercontent.com/guranshdeol/rootgraph-incident-responder/main/docs/img/graph.png)

## Walk up first, then make it prove itself

When alerts fire, rootgraph starts at the alerting nodes and walks **upward**, the opposite direction of a blast-radius view:

```cypher
UNWIND $alert_rids AS rid
MATCH p = (s:Resource {rid: rid})-[:DEPENDS_ON|RUNS_ON*0..4]->(c:Resource)
WITH c, rid, min(length(p)) AS hops
WITH c, collect(rid) AS explains, min(hops) AS min_hops
RETURN c.rid AS candidate, labels(c) AS kinds, size(explains) AS coverage, explains, min_hops
ORDER BY coverage DESC, min_hops ASC
LIMIT $k
```

This finds what the alerts have in common. On its own it confidently picks host-1, the wrong answer. So every candidate has to survive evidence.

The most important piece is the path check. For a dependency like `payments → orders-db:5432`, one query walks from the service to its host, from the target to every security group guarding it, and looks for an active rule that admits the host on that port:

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

If the path is closed, a sibling query looks at the *inactive* rules on the same path, and the security group that lost one in the last half hour becomes the prime suspect. CloudTrail tells us who removed it and when. (Hold on to that `coalesce(yh, y)` line; it comes back later in the story, and it wasn't there until Sunday night.)

Then everything is scored in the open:

```
3 × how many alerts it explains   + 2 × its own health check fails   − 2 × its health check passes
+ 2 × it's on a broken path        + 2 × a person changed it just now   + 1 × we've fixed this cause before
```

host-1 explains everything, but it's healthy, so it drops. The security group sits on a broken path and changed two minutes ago, so it rises. We checked how much this matters: ranking by "explains the most alerts" alone gets two of our five headline scenarios right. The full scorecard gets all five.

## An AI agent that isn't allowed to write queries

We use an LLM, but on a short leash. After the deterministic pipeline ranks the suspects, an agent double-checks the ranking and explains it in plain English. It can only call **12 read-only tools**, and every one of them is a fixed Cypher query a person wrote and reviewed. It has to give a reason for every call. It cannot write Cypher, cannot approve anything and cannot touch AWS.

A validator then checks the answer. The root cause has to be a scored candidate, and every resource it mentions has to appear in the evidence. If anything fails, a plain template built from the scorecard goes out instead. We ran on free NVIDIA Nemotron models through OpenRouter. When the free tier ran out of requests on Saturday, the explanations quietly switched to the template, and the diagnosis didn't change at all. That's the point: the graph decides, the agent explains.

The same 12 tools are exposed over MCP, so you can point Claude Desktop at the graph and investigate it yourself.

## The fix, and the human

Every fix rootgraph can propose is the exact undo of a change it found in the graph: re-add the rule that was removed, edit back the rule that was changed, re-attach the security group that was detached, start the instance that was stopped. Before anyone approves, the console shows the precise AWS CLI command, what else depends on the thing being changed, and how to roll it back.

Nothing runs until a signed-in person clicks **Approve**, and the approval is recorded under their name. The executor's IAM user can only undo: it can add, re-attach and start, never delete or stop. Then rootgraph waits until the alerts actually clear before it calls the incident resolved.

And it remembers. A resolved incident stays in the graph, linked to its root cause, the change that explained it and the verified fix with its exact parameters. When the same fault comes back, the incident page says *"Seen before"* and the fix arrives pre-filled: *"the same fix resolved INC-… in 52 s."*

![rootgraph's memory: what it learned, and how often later incidents recalled it](https://raw.githubusercontent.com/guranshdeol/rootgraph-incident-responder/main/docs/img/memory.png)

## Saturday: the first real run

We built the first version against a simulated estate through Friday night, then pointed it at a real AWS account on Saturday morning. The first surprise had nothing to do with graphs: our AWS organisation only allowed one region, so the whole estate went to Sydney. Two EC2 hosts, a Postgres RDS instance, security groups, CloudTrail, and Prometheus with Alertmanager on host-1.

The first run worked, slowly. Then it failed in ways no mock could have shown us. A "resolved" notification sat waiting behind a slow investigation for three minutes, so verification timed out. A late notification for alerts we'd already filed opened a second incident. Two minutes wasn't long enough to see real alerts clear. We fixed each one and added a test for it.

The clean run looked like this:

| Time (UTC) | What happened |
|---|---|
| 06:58:23 | A rule is revoked: host-1 can no longer reach the database |
| 06:58:59 | Real alerts open an incident (+36 s) |
| 06:59:55 | Root cause: the database's security group. It also remembered fixing the same cause ten minutes earlier |
| 07:00:37 | A person approves; the exact rule goes back |
| 07:01:40 | Alerts clear, the incident closes as verified (162 s from open) |

✍️ [YOUR WORDS: a line about watching the first real incident close.]

## "It looks simulated"

Here's the feedback that changed the project. Up to then, we broke things by clicking a button in our own UI. One of us said it plainly: *this looks simulated. Let us break it ourselves, the way people actually break things, and make rootgraph find it.*

So we did. We stopped telling rootgraph anything. From the AWS console and the CLI we edited rules, detached a security group from the database, stopped a server, and stopped a container on a host. rootgraph had to work out what changed on its own, from CloudTrail and its own graph diff.

| What we changed by hand | What rootgraph concluded | Fixed in |
|---|---|---|
| Detached the database's security group | `orders-db` lost its security group: 12 alerts, one cause | **52 s** |
| Stopped host-2 | host-2 went running → stopped; its services are victims, not causes | 64 s |
| Revoked a firewall rule | The exact rule, and who removed it | 92 s |
| Stopped the payments container | payments is down; the network is fine | 93 s |
| Changed a rule's port from 5432 to 5433 | "Rule edited", with the old and new values | verified |

Those times run from the incident opening to a verified fix, and they include a person reading the proposal and clicking Approve.

That brings us back to Sunday night.

## Sunday, 8:03 p.m.: the silence

We stopped host-1. And nothing happened.

It took us a minute to see why, and it's embarrassing in hindsight: **host-1 runs Prometheus and Alertmanager.** We had stopped the thing that raises the alarms. The graph knew perfectly well; discovery had recorded `running → stopped`. But a change on its own doesn't open an incident, and there was no longer anything left to send an alert.

Then it got worse. Next, someone removed the inbound rule on host-2's security group and stopped host-2 at the same time: two faults at once. rootgraph saw the stopped instance and proposed starting it. We approved. host-2 came back up, and the alerts kept firing. After five minutes rootgraph marked the incident as **failed**.

That was honestly the right call. It refused to say "resolved" while the alarms were still going. But it had missed the rule, and we had to know why. Three things had gone wrong, and none of them showed up in a single test:

1. **The watcher was inside the thing it watched.** If the monitoring host dies, nothing can alert. We added a **watchdog** outside the estate. The control plane checks Prometheus every 20 seconds, and after three failures it raises a `MonitoringUnreachable` alert on the Prometheus host itself. That alert opens an incident like any other, and the watchdog resolves it as soon as Prometheus answers again.
2. **The monitoring host got a new address.** Stopping and starting an EC2 instance changes its public IP unless you pin it. So since the first restart, every health check rootgraph made had been going to a dead address. Every probe in the failed incident came back "unknown", and it was flying half blind. We gave host-1 an Elastic IP.
3. **The path check couldn't see a host's own firewall.** Our query only checked security groups attached directly to a dependency's target. That's fine for "can payments reach the database?", but `web → orders` crosses into *host-2's* security group, because orders is a service running on host-2. The query never looked there. That's the `coalesce(yh, y)` from earlier: when the target is a service on another host, the node to check is that host. We added a test scenario that reproduces exactly what was done that night.

Then we stopped host-1 again.

At 15:22:48 UTC the instance stopped. At 15:23:52 the watchdog fired and opened an incident on host-1. Seconds later rootgraph had the cause: host-1, stopped, with CloudTrail's `StopInstances` call right there in the timeline. Approve. The instance started, Prometheus answered on its new fixed address, the watchdog resolved its alert, and verification passed.

**Sixty-nine seconds**, for the failure that had been completely invisible an hour earlier.

✍️ [YOUR WORDS: how it felt when that incident turned green.]

## From demo page to console

One more thing we changed late: the look. Our first UI was a landing page with a "Break it" button and a big headline. It looked like a demo, because it was one. We rebuilt it as an operations console: a sign-in page, a Production/Staging switch, an overview, incidents with tabs for evidence, a change feed, an approvals audit log, a topology explorer, memory, and integrations. It's ink on paper with thin lines, and one bright colour reserved for whatever needs a person.

![The rootgraph console](https://raw.githubusercontent.com/guranshdeol/rootgraph-incident-responder/main/docs/img/overview.png)

## Why it had to be a graph

If you took FalkorDB out, rootgraph would stop working. That isn't because we store things in it. It's because every question it asks is a graph question. Which resource do ten alerts share? A variable-length walk. Is this dependency allowed? A join across services, hosts, security groups and rules. What else breaks if this goes down? A reverse walk. What does most of the estate lean on? `algo.pageRank`. Have we fixed this before? One hop from the incident to its root cause and verified action.

It's also fast enough to be careless with. The graph queries in an investigation's trace take 0 to 2 milliseconds each, so we check every dependency of every suspect on every incident without thinking twice. And when we needed to clean up test data before recording our demo, `GRAPH.COPY` gave us a full backup in one command.

## What we'd tell ourselves on Thursday

- **Keep what was deleted.** The most valuable edge in our graph is one that no longer exists in AWS.
- **Don't let the AI write the queries.** Give it good tools, make it explain its choices, and validate what it says.
- **Break the real thing, by hand, with someone who wants to win.** Our tests passed the whole time. The real account found the bugs that mattered.
- **Watch the watcher.** If your monitoring lives on the infrastructure it monitors, you need something outside it.

## Try it

The code, the graph model, every Cypher query and a four-command Docker setup are at **[github.com/guranshdeol/rootgraph-incident-responder](https://github.com/guranshdeol/rootgraph-incident-responder)**. The Staging environment needs no AWS account: run a drill, approve the fix, and watch it land in memory.

*We built rootgraph with AI coding assistants (Claude Code), and we say so in the README. The problem, the graph model, the decisions, and every bug we found by breaking our own AWS account are ours.*

*Many alerts, one cause. The graph decides, the agent explains, and a human acts.*
