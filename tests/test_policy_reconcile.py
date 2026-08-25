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
    unprotected = _keys(res.unprotected)
    unused = _keys(res.unused)
    oos = _keys(res.out_of_scope)

    # CORRECT: the one declared edge the loose policy happens to admit
    assert ("shop/orders-api", "shop/orders-db", 5432) in correct

    # UNPROTECTED (NOT would-break): orders-api / orders-cache have no policy, so these
    # declared deps flow by default-allow — they must be unprotected, never missing.
    assert ("shop/storefront", "shop/orders-api", 8080) in unprotected
    assert ("shop/orders-api", "shop/orders-cache", 6379) in unprotected
    assert not missing                               # nothing reaches a protected+unadmitted dst

    # ENTRY edge is OUT OF SCOPE (synthetic ingress-controller src can't be matched)
    assert ("ingress-controller", "shop/storefront", 80) in oos

    # UNUSED (over-privilege): admitted but not needed
    assert ("shop/storefront", "shop/orders-db", 5432) in unused
    assert ("shop/reporting", "shop/orders-db", 5432) in unused


def test_verdict_is_audit_when_deps_are_unprotected(mini_inventory):
    """Most workloads have no policy, so declared deps flow by default-allow -> AUDIT,
    NOT shadow (nothing actually breaks)."""
    needed = derive_needed(mini_inventory)
    admitted, protected = derive_admitted(mini_inventory)
    res = reconcile(needed, admitted, total_workloads=len(mini_inventory.workloads),
                    protected=protected)
    v = verdict(res, scope="shop")
    assert v.gate == "audit"
    assert v.unprotected                             # declared deps to default-allow dsts
    assert not v.would_break


def test_verdict_is_shadow_when_protected_dep_unadmitted():
    """The real would-break case: a policy DOES protect the destination but denies a
    declared dependency."""
    from npready.model import Edge, EdgeClass, Provenance
    needed = [Edge("a", "b", 5432, EdgeClass.IN_CLUSTER, Provenance.S1_ENV_ENDPOINT)]
    admitted = [Edge("c", "b", 5432, EdgeClass.IN_CLUSTER, Provenance.POLICY)]  # admits c->b, not a->b
    res = reconcile(needed, admitted, total_workloads=3, protected={"b"})       # b IS protected
    v = verdict(res)
    assert v.gate == "shadow"
    assert {(e.src, e.dst, e.port) for e in v.would_break} == {("a", "b", 5432)}


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
