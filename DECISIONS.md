# DECISIONS

One line per non-obvious choice (plan §15.4). Newest at the bottom.

## Graph layer and tools (Fri 16 Oct 2026)

- **FalkorDB version checked against:** `falkordb/falkordb:latest`, graph module 4.22.1 (`MODULE LIST` ver 42201), Redis 8.10.2.
- **§8 queries: no rewrites were needed.** Q1–Q8 and W1–W6 run exactly as written in plan §8. FalkorDB returned no error for any of them, so there is no FalkorDB error to log. Each one is tested against the fixture in `tests/test_tools.py`.
  - Phase 0 checklist results: multi-type variable-length `[:A|B*0..4]` works (Q2, Q6); zero-length `*0..` works (Q2, Q5); undirected multi-type `-[:A|B|C|D*0..2]-` works (Q5); `src = h`, `src:Internet` and `src IN host_fws` inside an OPTIONAL MATCH `WHERE` work (Q4); `sum(size(rules))` works (Q4); `collect(...)[0]` works (Q6); `FOREACH (_ IN CASE ... | MERGE ...)` works (W6); `SET r.removed_at = null` removes the property (W1); `algo.SPpaths` and `algo.pageRank('Resource','DEPENDS_ON')` work as written (Q3, Q8).
- **W1b also sets `after`** (`"<proto> <from>-<to> from <src_rid>"`), mirroring `before`. This is an addition, not a FalkorDB workaround, so the Change carries both sides of an in-place edit.
- **Query files** live in `graph/queries/<id>_<name>.cypher`. Lines starting with `//` are comments and `graph/db.py` strips them before sending. Multi-statement files (`schema.cypher`, `fixtures/*.cypher`) are split on `;`.
- **Q7 and Q5 column names** are kept as the queries return them (`i.id`, `ch.event_name`, ...), because the queries are kept verbatim. Tools pass the rows through unchanged.
- **Envelope outcomes:** `answered_with_path` = rows returned; `answered_from_memory` = `recall_incidents` matched; `not_in_graph` = zero rows (this covers "no changes in the window" and "no firewall modelled" alike; per §7.2 it never means healthy); `unknown_resource` = a rid argument didn't resolve via Q1, so the tool query is not run and `cypher` is `null`, except for `resolve`, whose own query is Q1; `error` = the query raised, and the message goes in `rows[0].error`.
- **Rid arguments accept names too.** Each one is resolved through Q1 (`rid` or `name`) and the tool query runs on the canonical rid. `envelope.args` keeps what the caller passed.
- **`check_path` paths** are `[from_svc, host, firewall]`, one per firewall on the target, so the UI can highlight whichever SG blocks or permits the route.
- **`blast_radius` depth** is clamped to 1..4 (Q6's fixed upper bound).
- **Fixture estate** (`graph/fixtures/estate.cypher`) uses placeholder ids. The second SG on `orders-db` is `sg-db-admin`, which allows 5432 only from `cidr:203.0.113.0/24` (an admin VPN). It shows that Q4 aggregates across SGs: with rule A gone, `permitted` must still be false (risk #18). Two extra rules (`sgr-h1-web` 8080 from internet, `sgr-h2-orders` 8083 from sg-host1) make the SG layer realistic.
- **Known Q4 limitation (open):** Q4 only finds firewalls that `PROTECT` the dependency target itself. Service→Service dependencies (e.g. web→orders across hosts) therefore return `not_in_graph`, even though `sg-host2` guards `i-host2`. Fixing this means walking `RUNS_ON` to the target's host. That is a schema/query change for P1 to agree on, so it is not done here.
- **pytest dependency** is in uv's `dev` dependency group (`uv run pytest` installs it by default). Runtime deps are `falkordb` and `pyyaml`.

## Investigation pipeline (Sat 17 Oct 2026)

- **Pipeline is LLM-free for now** (`agent/investigate.py`). Step 7 is an `explain` hook; until the LLM provider is picked (D10 still open) the explanation is a template built only from scorecard rows, which is also the validator fallback.
- **Culprit firewall on a broken path:** new Q10 (`removed_rules` tool) mirrors Q4 over *inactive* rules removed in the 30-min window. Only firewalls that lost a rule which used to permit the path get `broken_path`; if none did, every firewall on the target does. This keeps `sg-db-admin` (never allowed host-1) out of S1/S5.
- **Firewall coverage** = the `explains` list of the broken edge's source service (from Q2) + alerting hosts whose blackbox alert TARGETs the dependency. `min_hops` = source's min_hops + 1. S1: sg-db covers 4/4.
- **Probe states:** healthy / unhealthy / degraded / unknown. A service with high error rate or latency but `up=1` is *degraded* (0 in the score): a victim shows symptoms too. Database is healthy if any host reaches it (sibling evidence). Firewalls have no probe.
- **"Multiple likely causes"** = top-two gap < 1.0 **or** the runner-up has direct evidence of its own (probe unhealthy, broken path or a change). The gap rule alone would not flag S5 (6.75 vs 4.25); the direct-evidence rule does, and S1–S4 stay single-cause. With multiple causes, an action is proposed for each.
- **Scores on fixtures:** S1 sg-db 6.75 (plan said ≈6.2), S2 i-host2 5.0, S3 payments 5.0, S4 sg-db 7.75 (+1 memory), S5 sg-db 6.75 / payments 4.25.
- **Recall runs after the candidates are known** (with candidate + alerting rids), so `prior_incident_match` can't miss the root cause because of Q7's LIMIT 3.
- **Recent changes count only if they MODIFIED the candidate itself** and are not `by_agent`; Q5's 2-hop rows stay in the trace for the UI.
- **Sandbox executor** reactivates the inactive rule through W1 (same rule_id) and writes a `by_agent` Change. Live AWS executors are P2's.
- **New queries:** Q9 dependencies, Q10 removed_path_rules, Q11 removed_rules_on_firewall (action precondition + exact spec), Q12 open_incident_for_group, Q13 incident_alerts, Q14 get_action, Q15 active_rules_on_firewall (sandbox fault injection), Q16 service_host; W4b alert TARGET, W5b attach alerts, W7 SUSPECTS, W8 create action, W9 state transition (guarded by allowed `from` states), W10 finding, W11 incident report/status.
- **Scenario fixtures** are YAML in `graph/fixtures/scenarios/` and are injected exactly like live data: discovery-style diff (W1+W2), CloudTrail Change (W3), Alertmanager payload through `ingest/alerts.py`.

## API + UI (Sat 17 Oct 2026)

- **Webhook → ingest → investigate:** `/hooks/alertmanager` (bearer WEBHOOK_TOKEN) saves the raw payload, ingests into `GRAPH_NAME` (default ops_sandbox) and investigates newly opened incidents in a background task. Without `PROMETHEUS_URL` every probe is "unknown", so live-webhook incidents rank on graph evidence only until P3's Prometheus is reachable.
- **Sandbox mode is open on purpose:** inject / reset / approve / reject need no token while `SANDBOX_MODE=true`, so judges can click through. Effects are graph-only. With `SANDBOX_MODE=false` they need `Bearer $ADMIN_TOKEN`, and approve returns 501 until P2's live executors exist.
- **One writer at a time:** a process-wide lock serialises injections, investigations and approvals (one uvicorn worker).
- **Multiple causes (S5):** approving one of several proposed actions executes it but verification waits until no proposed/approved action remains; then every executed action is verified and the incident closed with each as a ROOT_CAUSE.
- **Sandbox recovery** rebuilds the scenario from `report.scenario` {name, now}, so the resolved payload hits the same alert ids even after an API restart.
- **Rule-removal injection happens at injection time** (not `now + at_offset`): otherwise S4 run within ~2 min of fixing S1 replays the removal at a time older than the agent's restore, and the W2 diff doesn't see it.
- **Graph panel shows the current graph**, not a snapshot at incident time (said in the UI).
- **UI** is one static file (cytoscape 3.30.2 from cdnjs, no build step). All data is inserted with textContent, never innerHTML.
- **New queries:** Q17/Q18 graph panel, Q19 incident list, Q20 incident detail.
- **UI follows docs/DESIGN.md (Notion-style, replaced the earlier editorial-serif design on the team's request).** NotionInter → Inter, Lyon Text → Source Serif 4 (Google Fonts), as the file suggests. Warm #f6f5f4 canvas, white 12px hairline cards, no shadows except the sticky nav. Blue #0075de only on the one primary action (Approve); scenarios are sky-tint ghost buttons. Colour carries status on pills (marigold open/proposed, coral failed/unhealthy, peach degraded, sky healthy, blue resolved). The root cause sits on the single midnight 'dark island' card. In the graph: coral = broken path / removed rule, marigold = top suspect.

## Live AWS code, tested on moto (Sat 17 Oct 2026)

- **Everything AWS is tested against moto** (`tests/test_aws.py`): estate up/down, discovery + diff, revoke → diff Change → executor restore → permitted again, in-place rule edit (W1b), missing instances, SSM restart, CloudTrail ingest and the SQS loop. Real-account differences still possible: CloudTrail/EventBridge delivery latency, exact event payload shapes (the sample in `ingest/fixtures/` is hand-written; replace with a recorded one).
- **One script owns the estate** (`demo/aws/estate.py up|status|down`), idempotent through `demo/aws/state.json`; keys go to `demo/aws/credentials.env` (600, gitignored, dockerignored) to append to `.env`. SG names are `rootgraph-host1/-host2/-db` because AWS forbids names starting with `sg-`; the plan's "sg-db" is the rootgraph-db group.
- **Least privilege per component:** discovery (Describe*), ingester (SQS receive/delete on one queue), executor (AuthorizeSecurityGroupIngress on the db SG only; SendCommand on instances tagged rootgraph=demo + AWS-RunShellScript). The API uses the executor keys; the workers use theirs.
- **Discovery:** full sync every 60s and before each live investigation (resync). Rule sources: SG ref, 0.0.0.0/0 → Internet, /32 of a known instance IP → that Compute, other CIDR → CidrBlock; IPv6/prefix lists skipped; protocol -1 → `all` 0-65535. Unseen resources → `state='missing'`, never deleted. Stale PROTECTS edges (SG detached) are not removed yet.
- **Executor refuses** to restore rules whose source is a single instance (/32 → Compute) in v1, and refuses service names outside `[a-z0-9_-]` for SSM commands.
- **Live approve** executes synchronously, then verifies in a background task (5 s polling, 120 s) and writes memory or marks the incident failed.
- **New queries:** W12–W21 discovery upserts and missing-marking, W22 unlinked CloudTrail rids.

## Demo stack + first real alerts (Sat 17 Oct 2026)

- **One service image, five roles** (`demo/service/app.py`): `rid` label on every metric; db dependency = TCP connect with 1 s timeout (what an SG revoke breaks); CPU work per request so a CPU hog shows as latency; loadgen hits web and reports (nothing else calls reports).
- **Configs are rendered, not hand-copied** (`demo/render.py local|aws`): same rules and labels for the local run and EC2. `alertmanager.yml` holds the webhook token: mode 600, owned by 65534 (Alertmanager runs as nobody), and `demo/build/` is gitignored.
- **Local run reaches the API's network** as `demo-prometheus` (external network `app_default`); no host port is opened.
- **Real S3 run, 17 Oct 01:08 IST:** stop payments → ServiceDown + HighErrorRate ×2 → webhook in ~40 s → top svc:payments 5.0 with live probe `up=0`, restart_service proposed with blast radius checkout + web. Matches the fixture oracle.
- **Found by the real run and fixed:** (1) Alertmanager sends a group in batches, so the API now re-investigates whenever firing alerts join an open incident; (2) re-investigation reuses an existing proposal (Q21) instead of proposing twice; (3) an unreachable Prometheus made `probe` raise; it now returns outcome `error`, state unknown.

## LLM agent loop (Sat 17 Oct 2026)

- **Provider: OpenRouter** (team decision, D10 closed), through `agent/llm.py`'s OpenAI-compatible adapter; no SDK dependency. Off until `LLM_API_KEY` and `LLM_MODEL` are both set; then every investigation runs it.
- **Bounded agent:** sees the scorecard + evidence (6 rows per call max, never the graph), may call up to 6 of 7 read tools; each call must carry a `reason` or it is refused and not run. Calls are traced as `by: agent` with `call_id` a1…, pipeline calls p1….
- **Validator** (`agent/validator.py`): root cause must be a scored candidate; every rid token in the text must occur in the evidence; action kind in catalogue and aimed at the root cause; cites ≥1 call that returned rows; a re-rank needs an agent-chosen call among those. Failure or provider error → template text, pipeline proposals unchanged.
- **Re-rank:** only a validated answer can change `top` (and so the proposal); the scorecard itself is never rewritten (`scorecard_top` kept in the report).
- **Tokens per investigation** (D16) on the Incident (`tokens_in`, `tokens_out`, `agent_calls`, W23) and shown under the explanation.

## MCP server (Sat 17 Oct 2026)

- **`agent/mcp_server.py`** exposes the 10 read tools over MCP (stdio), annotated read-only, same envelopes and the same fixed Cypher as the pipeline. No write, approval or free-form Cypher tool (D8). Built on the MCP Python SDK 2.x (`MCPServer`, the renamed FastMCP). Verified with a real stdio client session.
