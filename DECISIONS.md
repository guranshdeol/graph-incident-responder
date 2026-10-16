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
