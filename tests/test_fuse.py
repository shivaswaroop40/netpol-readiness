"""Fusion + coverage-by-source — the thesis C5 result, in the shipped tool.

Neither configuration nor observation is safe alone; the union is, at no security
cost, because config-declared edges name no attack path. These pin the three
source coverages, the union behaviour, and the safety invariant (declared ∩ A = ∅
at port granularity, with the identity-pair collision surfaced as an artifact).
"""
import json

from npready.cli import main
from npready.score import fuse


def test_config_recovers_an_edge_observation_missed():
    """Bank-of-Anthos shape: observation misses the payment edge, config declares it,
    the union covers everything — and adds no attack."""
    L = [("frontend", "ledger", 8080), ("frontend", "balance", 8080)]
    A = [("attacker", "ledger", 8080)]
    observed = [("frontend", "balance", 8080)]          # sign-up journey only
    declared = [("frontend", "ledger", 8080), ("frontend", "balance", 8080)]

    r = fuse(declared, observed, L, A)
    assert r["coverage"]["observed"] == 0.5
    assert r["coverage"]["config_only"] == 1.0
    assert r["coverage"]["fused"] == 1.0
    assert r["fused_coverage_gain_over_observed"] == 0.5
    assert r["fused"]["over_privilege"] == 0.0
    assert r["declared_intersect_attacks"]["safe"] is True


def test_union_beats_each_source_when_each_covers_different_edges():
    L = [("a", "b", 1), ("c", "d", 2)]
    A = []
    declared = [("a", "b", 1)]      # config declares one
    observed = [("c", "d", 2)]      # observation saw the other
    r = fuse(declared, observed, L, A)
    assert r["coverage"]["config_only"] == 0.5
    assert r["coverage"]["observed"] == 0.5
    assert r["coverage"]["fused"] == 1.0        # neither alone suffices; the union does


def test_inversion_config_zero_observation_recovers():
    """Sock-Shop shape: the app hard-codes its graph, so config declares ~nothing
    and observation is the only source."""
    L = [("user", "userdb", 27017), ("front", "catalogue", 80)]
    A = []
    declared = [("user", "userdb", 27017)]      # one declared edge (6.7%-style)
    observed = [("user", "userdb", 27017), ("front", "catalogue", 80)]
    r = fuse(declared, observed, L, A)
    assert r["coverage"]["config_only"] == 0.5
    assert r["coverage"]["observed"] == 1.0
    assert r["coverage"]["fused"] == 1.0        # union equals the better source


def test_declared_never_admits_an_attack_at_port_granularity():
    """The agent->world case: legit :443, SSRF :80. At port granularity the declared
    set and A are disjoint (safe); dropping the port manufactures a collision."""
    declared = [("agent", "world", 443)]
    A = [("agent", "world", 80)]
    L = [("agent", "world", 443)]

    port_safe = fuse(declared, observed=[], L=L, A=A)
    assert port_safe["declared_intersect_attacks"]["safe"] is True
    assert port_safe["fused"]["over_privilege"] == 0.0

    # same edges projected to identity-pair granularity: the port distinction is gone
    dpair = [("agent", "world", None)]
    apair = [("agent", "world", None)]
    lpair = [("agent", "world", None)]
    pair = fuse(dpair, observed=[], L=lpair, A=apair)
    assert pair["declared_intersect_attacks"]["safe"] is False
    assert pair["declared_intersect_attacks"]["count"] == 1


def test_cli_fuse_from_snapshot_reports_coverage(tmp_path, capsys):
    """End-to-end: derive the declared set from a manifest snapshot, fuse with an
    observed edge set, and confirm the union coverage and safety line print."""
    snap = {"deployments": [
        {"metadata": {"name": "app", "namespace": "s"},
         "spec": {"template": {"metadata": {"labels": {"app": "app"}},
                  "spec": {"containers": [{"name": "c", "env": [
                      {"name": "DB_HOST", "value": "db:5432"}]}]}}}},
        {"metadata": {"name": "db", "namespace": "s"},
         "spec": {"template": {"metadata": {"labels": {"app": "db"}},
                  "spec": {"containers": [{"name": "c"}]}}}}],
        "services": [{"metadata": {"name": "db", "namespace": "s"},
                      "spec": {"selector": {"app": "db"}, "ports": [{"port": 5432}]}}]}
    snap_f = tmp_path / "snap.json"
    snap_f.write_text(json.dumps(snap))
    # ground truth needs the app->db edge; observation never saw it (empty)
    (tmp_path / "L.json").write_text(json.dumps([["s/app", "s/db", 5432]]))
    (tmp_path / "A.json").write_text(json.dumps([["evil", "s/db", 5432]]))
    (tmp_path / "O.json").write_text(json.dumps([]))
    out = tmp_path / "fuse.json"
    rc = main(["fuse", "--snapshot", str(snap_f),
               "--observed", str(tmp_path / "O.json"),
               "--legit", str(tmp_path / "L.json"),
               "--attacks", str(tmp_path / "A.json"),
               "--json", str(out)])
    assert rc == 0
    printed = capsys.readouterr().out
    assert "COVERAGE BY SOURCE" in printed
    assert "FUSED (union)" in printed
    data = json.load(open(out))
    # config recovered the edge observation missed; union covers it; no attack admitted
    assert data["coverage"]["config_only"] == 1.0
    assert data["coverage"]["observed"] == 0.0
    assert data["coverage"]["fused"] == 1.0
    assert data["declared_intersect_attacks"]["safe"] is True
