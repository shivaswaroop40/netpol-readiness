"""Policy parsing + four-quadrant reconciliation + readiness verdict."""
from npready import derive_admitted, derive_needed, reconcile, verdict


def _keys(edges):
    return {(e.src, e.dst, e.port) for e in edges}


def test_admitted_expands_namespace_wide_policy(mini_inventory):
    """podSelector:{} on the db admits every other pod in the namespace on :5432."""
    admitted, protected = derive_admitted(mini_inventory)
    keys = _keys(admitted)
    # every non-db workload -> orders-db:5432
    for src in ("storefront", "orders-api", "orders-cache", "reporting"):
        assert (f"shop/{src}", "shop/orders-db", 5432) in keys
    # the db itself is the protected workload
    assert "shop/orders-db" in protected


def test_reconcile_quadrants(mini_inventory):
    needed = derive_needed(mini_inventory)
    admitted, protected = derive_admitted(mini_inventory)
    res = reconcile(needed, admitted, total_workloads=len(mini_inventory.workloads),
                    protected=protected)

    correct = _keys(res.correct)
    missing = _keys(res.missing)
    unused = _keys(res.unused)

    # CORRECT: the one declared edge the loose policy happens to admit
    assert ("shop/orders-api", "shop/orders-db", 5432) in correct

    # MISSING (would break on enforce): declared but unadmitted
    assert ("shop/storefront", "shop/orders-api", 8080) in missing
    assert ("shop/orders-api", "shop/orders-cache", 6379) in missing
    assert ("ingress-controller", "shop/storefront", 80) in missing

    # UNUSED (over-privilege): admitted but not needed
    assert ("shop/storefront", "shop/orders-db", 5432) in unused
    assert ("shop/reporting", "shop/orders-db", 5432) in unused

    # quadrants are disjoint
    assert not (missing & unused)
    assert not (correct & missing)


def test_verdict_is_shadow_when_edges_would_break(mini_inventory):
    needed = derive_needed(mini_inventory)
    admitted, protected = derive_admitted(mini_inventory)
    res = reconcile(needed, admitted, total_workloads=len(mini_inventory.workloads),
                    protected=protected)
    v = verdict(res, scope="shop")

    assert v.gate == "shadow"                       # missing edges -> not safe to enforce
    assert v.would_break                             # non-empty
    assert 0.0 <= v.readiness_score < 1.0
    d = v.to_dict()
    assert d["would_break_count"] == len(res.missing)


def test_verdict_enforce_when_all_needs_admitted():
    """a policy that admits exactly the needed edges yields ENFORCE."""
    from npready.model import Edge
    needed = [Edge("a", "b", 80), Edge("a", "c", 443)]
    admitted = [Edge("a", "b", 80), Edge("a", "c", 443)]
    res = reconcile(needed, admitted, total_workloads=3, protected={"b", "c"})
    v = verdict(res)
    assert v.gate == "enforce"
    assert v.readiness_score == 1.0
    assert not v.would_break
