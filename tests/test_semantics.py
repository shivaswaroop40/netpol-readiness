"""Regression tests for the NetworkPolicy-semantics fixes from the code review.
Each test pins one k8s behaviour that, if wrong, flips a readiness verdict."""
from npready import (
    Inventory,
    derive_admitted,
    derive_needed,
    reconcile,
)
from npready.model import Edge, EdgeClass, Provenance


def _deploy(name, ns, labels, sa="default"):
    return {"metadata": {"name": name, "namespace": ns},
            "spec": {"template": {"metadata": {"labels": labels},
                     "spec": {"serviceAccountName": sa, "containers": [{"name": "c"}]}}}}


def _ns(name, labels):
    return {"metadata": {"name": name, "labels": labels}}


# --- Finding 1 (CRITICAL): namespaceSelector must restrict to matching namespaces ---
def test_namespace_selector_restricts_admission():
    """A namespaceSelector must admit pods ONLY from matching namespaces, not all."""
    snap = {
        "namespaces": [_ns("payments", {"team": "payments"}), _ns("other", {})],
        "deployments": [
            _deploy("web", "payments", {"app": "web"}),
            _deploy("web", "other", {"app": "web"}),
            _deploy("db", "shop", {"app": "db"}),
        ],
        "networkpolicies": [{
            "metadata": {"name": "db-from-payments", "namespace": "shop"},
            "spec": {"podSelector": {"matchLabels": {"app": "db"}},
                     "policyTypes": ["Ingress"],
                     "ingress": [{"from": [{
                         "namespaceSelector": {"matchLabels": {"team": "payments"}},
                         "podSelector": {"matchLabels": {"app": "web"}}}],
                         "ports": [{"port": 5432}]}]}}],
    }
    admitted, _ = derive_admitted(Inventory.from_dict(snap))
    keys = {(e.src, e.dst, e.port) for e in admitted}
    assert ("payments/web", "shop/db", 5432) in keys        # matching ns: admitted
    assert ("other/web", "shop/db", 5432) not in keys        # non-matching ns: NOT admitted


def test_empty_namespace_selector_matches_all():
    """An empty namespaceSelector {} matches every namespace (k8s semantics)."""
    snap = {
        "namespaces": [_ns("a", {}), _ns("b", {})],
        "deployments": [_deploy("web", "a", {"app": "web"}),
                        _deploy("web", "b", {"app": "web"}),
                        _deploy("db", "shop", {"app": "db"})],
        "networkpolicies": [{
            "metadata": {"name": "db-open", "namespace": "shop"},
            "spec": {"podSelector": {"matchLabels": {"app": "db"}},
                     "policyTypes": ["Ingress"],
                     "ingress": [{"from": [{"namespaceSelector": {}}], "ports": [{"port": 5432}]}]}}],
    }
    admitted, _ = derive_admitted(Inventory.from_dict(snap))
    keys = {(e.src, e.dst, e.port) for e in admitted}
    assert ("a/web", "shop/db", 5432) in keys
    assert ("b/web", "shop/db", 5432) in keys


# --- Finding 5: policyTypes omitted still affects ingress (protected bookkeeping) ---
def test_policytypes_omitted_marks_protected():
    snap = {"deployments": [_deploy("db", "shop", {"app": "db"})],
            "networkpolicies": [{
                "metadata": {"name": "deny-all-ingress", "namespace": "shop"},
                "spec": {"podSelector": {"matchLabels": {"app": "db"}}}}]}  # no policyTypes, no ingress
    _, protected = derive_admitted(Inventory.from_dict(snap))
    assert "shop/db" in protected                            # default: affects ingress -> protected


def test_egress_only_policy_does_not_protect_ingress():
    snap = {"deployments": [_deploy("db", "shop", {"app": "db"})],
            "networkpolicies": [{
                "metadata": {"name": "egress-only", "namespace": "shop"},
                "spec": {"podSelector": {"matchLabels": {"app": "db"}},
                         "policyTypes": ["Egress"]}}]}
    _, protected = derive_admitted(Inventory.from_dict(snap))
    assert "shop/db" not in protected                        # egress-only: no ingress protection


# --- Finding 4: reconcile must honour the port wildcard (no-ports rule = all ports) ---
def test_reconcile_wildcard_port_satisfies_specific_need():
    needed = [Edge("a", "b", 5432, EdgeClass.IN_CLUSTER, Provenance.S1_ENV_ENDPOINT)]
    admitted = [Edge("a", "b", None, EdgeClass.IN_CLUSTER, Provenance.POLICY)]  # all ports
    res = reconcile(needed, admitted, total_workloads=2, protected={"b"})
    correct = {(e.src, e.dst, e.port) for e in res.correct}
    assert ("a", "b", 5432) in correct                       # wildcard admit satisfies the need
    assert not res.missing
    assert not res.unused                                     # the wildcard admit is used


def test_reconcile_specific_port_does_not_oversatisfy():
    """admitting a->b:443 must NOT satisfy a need for a->b:5432."""
    needed = [Edge("a", "b", 5432, EdgeClass.IN_CLUSTER, Provenance.S1_ENV_ENDPOINT)]
    admitted = [Edge("a", "b", 443, EdgeClass.IN_CLUSTER, Provenance.POLICY)]
    res = reconcile(needed, admitted, total_workloads=2, protected={"b"})
    assert {(e.src, e.dst, e.port) for e in res.missing} == {("a", "b", 5432)}
    assert {(e.src, e.dst, e.port) for e in res.unused} == {("a", "b", 443)}


# --- Finding 2: DNS/apiserver edges are out-of-scope for ingress, not "missing" ---
def test_dns_and_apiserver_are_out_of_scope_not_missing():
    """S4 (DNS) and S5 (apiserver) needs must not force SHADOW; they are out of scope
    for an ingress policy and reported separately."""
    snap = {"deployments": [_deploy("app", "x", {"app": "app"}, sa="app-sa")],
            "rolebindings": [{"metadata": {"name": "rb", "namespace": "x"},
                              "subjects": [{"kind": "ServiceAccount", "name": "app-sa", "namespace": "x"}]}]}
    inv = Inventory.from_dict(snap)
    needed = derive_needed(inv)
    admitted, protected = derive_admitted(inv)
    res = reconcile(needed, admitted, total_workloads=1, protected=protected)
    oos = {(e.src, e.dst) for e in res.out_of_scope}
    assert ("x/app", "kube-dns") in oos
    assert ("x/app", "kube-apiserver") in oos
    assert all(e.dst not in ("kube-dns", "kube-apiserver") for e in res.missing)


# --- S6: a lone StatefulSet's intra-cluster peering is a checkable self-edge ---
def _etcd_snap(with_policy=False):
    snap = {
        "statefulsets": [{"metadata": {"name": "etcd", "namespace": "x"},
                          "spec": {"template": {"metadata": {"labels": {"app": "etcd"}},
                                   "spec": {"containers": [{"name": "c"}]}}}}],
        "services": [{"metadata": {"name": "etcd", "namespace": "x"},
                      "spec": {"clusterIP": "None", "selector": {"app": "etcd"},
                               "ports": [{"port": 2380}]}}],
    }
    if with_policy:
        snap["networkpolicies"] = [{"metadata": {"name": "etcd-peer", "namespace": "x"},
            "spec": {"podSelector": {"matchLabels": {"app": "etcd"}}, "policyTypes": ["Ingress"],
                     "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "etcd"}}}],
                                  "ports": [{"port": 2380}]}]}}]
    return snap


def test_s6_single_statefulset_emits_self_peer_edge():
    edges = derive_needed(Inventory.from_dict(_etcd_snap()))
    peers = [(e.src, e.dst, e.port) for e in edges if e.provenance == Provenance.S6_PEER]
    assert ("x/etcd", "x/etcd", 2380) in peers            # intra-cluster peering IS emitted


def test_s6_peer_edge_satisfied_by_intra_app_policy():
    inv = Inventory.from_dict(_etcd_snap(with_policy=True))
    needed = derive_needed(inv)
    admitted, protected = derive_admitted(inv)
    res = reconcile(needed, admitted, total_workloads=1, protected=protected)
    correct = {(e.src, e.dst, e.port) for e in res.correct}
    assert ("x/etcd", "x/etcd", 2380) in correct          # the peering policy satisfies it
    assert not res.missing


# --- Finding 1 (FALSE-SAFE): a port-unknown need must NOT be cleared by a wrong-port admit ---
def test_port_unknown_need_not_satisfied_by_wrong_port_admit():
    from npready.model import Edge, EdgeClass, Provenance
    need = [Edge("a", "b", None, EdgeClass.IN_CLUSTER, Provenance.S1_ENV_ENDPOINT)]  # port unknown
    admit = [Edge("a", "b", 443, EdgeClass.IN_CLUSTER, Provenance.POLICY)]           # specific port
    res = reconcile(need, admit, total_workloads=2, protected={"b"})
    # conservative: unknown-port need is NOT satisfied by a single wrong-port admit
    assert {(e.src, e.dst, e.port) for e in res.missing} == {("a", "b", None)}
    assert not res.correct


def test_port_unknown_need_satisfied_by_all_ports_admit():
    from npready.model import Edge, EdgeClass, Provenance
    need = [Edge("a", "b", None, EdgeClass.IN_CLUSTER, Provenance.S1_ENV_ENDPOINT)]
    admit = [Edge("a", "b", None, EdgeClass.IN_CLUSTER, Provenance.POLICY)]  # all ports
    res = reconcile(need, admit, total_workloads=2, protected={"b"})
    assert {(e.src, e.dst, e.port) for e in res.correct} == {("a", "b", None)}
    assert not res.missing


def test_score_port_unknown_legit_conservative_but_attack_optimistic():
    from npready import score
    # legit need on unknown port is DENIED by a wrong-port admit (conservative false-deny)
    r = score([("a", "b", 443)], [("a", "b", None)], [("x", "y", 22)])
    assert r["false_deny"] == 1.0
    # attack on unknown port IS flagged admitted by any-port admit (optimistic over-priv)
    r2 = score([("x", "y", 443)], [("a", "b", 80)], [("x", "y", None)])
    assert r2["over_privilege"] == 1.0


# --- additive union: two policies on the same pod, allow-all wins (k8s union semantics) ---
def test_networkpolicies_are_additive():
    snap = {"deployments": [_deploy("db", "shop", {"app": "db"}),
                            _deploy("cli", "shop", {"app": "cli"})],
            "networkpolicies": [
                {"metadata": {"name": "p1", "namespace": "shop"},
                 "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"],
                          "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "cli"}}}],
                                       "ports": [{"port": 5432}]}]}},
                {"metadata": {"name": "p2-allow-all", "namespace": "shop"},
                 "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"],
                          "ingress": [{}]}}]}   # empty rule = allow all sources, all ports
    admitted, _ = derive_admitted(Inventory.from_dict(snap))
    keys = {(e.src, e.dst, e.port) for e in admitted}
    assert ("shop/cli", "shop/db", 5432) in keys       # from p1
    assert ("shop/cli", "shop/db", None) in keys        # from p2 all-ports (union wins)


# --- ipBlock peer admits no workload identity ---
def test_ipblock_from_admits_no_workload_edge():
    snap = {"deployments": [_deploy("db", "shop", {"app": "db"})],
            "networkpolicies": [{"metadata": {"name": "ipb", "namespace": "shop"},
                "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"],
                         "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}],
                                      "ports": [{"port": 5432}]}]}}]}
    admitted, protected = derive_admitted(Inventory.from_dict(snap))
    assert admitted == []                               # no workload identity from an ipBlock
    assert "shop/db" in protected                        # but the pod is still protected


# --- matchExpressions label selector (In/NotIn/Exists) ---
def test_matchexpressions_selector():
    from npready.inventory import labels_match
    labels = {"tier": "data", "app": "db"}
    assert labels_match({"matchExpressions": [{"key": "tier", "operator": "In", "values": ["data", "cache"]}]}, labels)
    assert not labels_match({"matchExpressions": [{"key": "tier", "operator": "NotIn", "values": ["data"]}]}, labels)
    assert labels_match({"matchExpressions": [{"key": "app", "operator": "Exists"}]}, labels)
    assert not labels_match({"matchExpressions": [{"key": "missing", "operator": "Exists"}]}, labels)


# --- egress: ExternalName service -> world; external FQDN env -> world egress ---
def test_externalname_and_external_fqdn_are_egress():
    from npready.model import EdgeClass
    snap = {"deployments": [_deploy("app", "x", {"app": "app"})],
            "services": [{"metadata": {"name": "ext", "namespace": "x"},
                          "spec": {"type": "ExternalName", "externalName": "api.stripe.com"}}]}
    snap["deployments"][0]["spec"]["template"]["spec"]["containers"][0]["env"] = [
        {"name": "PAY_URL", "value": "http://ext:443"},
        {"name": "WEBHOOK_URL", "value": "https://hooks.example.com/x"}]
    edges = derive_needed(Inventory.from_dict(snap))
    egress = [e for e in edges if e.edge_class == EdgeClass.EGRESS]
    dsts = {e.dst for e in egress}
    assert dsts == {"world"}                             # both resolve to the world token
    # Both values mean "leave the cluster on 443": PAY_URL says so explicitly and
    # WEBHOOK_URL says so via its https scheme. They therefore collapse to one
    # (src, world, 443) edge, which is exactly the single rule a NetworkPolicy
    # would need. An earlier version derived a portless second edge instead,
    # because the scheme was discarded rather than consulted for a default port.
    assert {(e.dst, e.port) for e in egress} == {("world", 443)}
    assert len(egress) == 1
