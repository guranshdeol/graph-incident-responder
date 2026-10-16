"""The README's evaluation claim stays true: coverage-only ranking misses the security-group
cases, the full scorecard gets all five scenarios."""

from eval import baseline


def test_graph_evidence_beats_coverage_only():
    res = {r["scenario"]: r for r in baseline.run()}
    full = sum(baseline.hit(r["full"], r["expected"]) for r in res.values())
    cov = sum(baseline.hit(r["coverage_only"], r["expected"]) for r in res.values())
    assert full == 5 and cov == 2
    assert res["s1"]["coverage_only"] == ["i-host1"] and res["s1"]["full"] == ["sg-db"]
