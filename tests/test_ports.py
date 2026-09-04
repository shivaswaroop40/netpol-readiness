"""Pod-port resolution — the DNAT boundary the whole tool must respect.

A NetworkPolicy governs the port the POD listens on (the post-DNAT targetPort);
config, Ingress backends and Service specs speak in the Service's client-facing
port. Every edge that crosses a Service must be translated, or a CORRECT policy
written for the real pod port is reported wrong in both directions (the
satisfied need as "missing", the in-use rule as "unused"). These tests pin that
translation at every crossing, plus named ports and endPort in policy rules.

The mini fixture cannot catch any of this: all its Services happen to use
``port == targetPort``, so the untranslated and translated answers coincide.
"""
from npready import Inventory, derive_admitted, derive_needed, reconcile
from npready.model import Provenance
from npready.score import admits


def _dep(name, ns="s", env=None, labels=None, cports=None):
    c = {"name": "c"}
    if env:
        c["env"] = [{"name": k, "value": v} for k, v in env.items()]
    if cports:
        c["ports"] = [{"name": n, "containerPort": p} for n, p in cports.items()]
    return {"metadata": {"name": name, "namespace": ns},
            "spec": {"template": {"metadata": {"labels": labels or {"app": name}},
                                  "spec": {"containers": [c]}}}}


def _svc(name, ports, ns="s", selector=None, headless=False):
    """ports: list of {port, targetPort?, name?} dicts, verbatim k8s shape."""
    spec = {"selector": selector or {"app": name}, "ports": ports}
    if headless:
        spec["clusterIP"] = "None"
    return {"metadata": {"name": name, "namespace": ns}, "spec": spec}


def _s1(edges):
    return {(e.src, e.dst, e.port) for e in edges
            if e.provenance == Provenance.S1_ENV_ENDPOINT}


# --------------------------------------------------------------- S1 through DNAT
def test_s1_needed_edge_carries_the_pod_port_not_the_service_port():
    snap = {"deployments": [_dep("app", env={"API_URL": "http://api:8080"}), _dep("api")],
            "services": [_svc("api", [{"port": 8080, "targetPort": 9090}])]}
    assert ("s/app", "s/api", 9090) in _s1(derive_needed(Inventory.from_dict(snap)))


def test_correct_policy_on_the_pod_port_reconciles_as_correct():
    """The end-to-end regression: with port != targetPort, a policy written for
    the REAL pod port must land in `correct` — not missing + unused."""
    snap = {"deployments": [_dep("app", env={"API_URL": "http://api:8080"}), _dep("api")],
            "services": [_svc("api", [{"port": 8080, "targetPort": 9090}])],
            "networkpolicies": [{
                "metadata": {"name": "api-allow-app", "namespace": "s"},
                "spec": {"podSelector": {"matchLabels": {"app": "api"}},
                         "policyTypes": ["Ingress"],
                         "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "app"}}}],
                                      "ports": [{"protocol": "TCP", "port": 9090}]}]}}]}
    inv = Inventory.from_dict(snap)
    needed = derive_needed(inv)
    admitted, protected = derive_admitted(inv)
    res = reconcile(needed, admitted, total_workloads=2, protected=protected)
    assert ("s/app", "s/api", 9090) in {(e.src, e.dst, e.port) for e in res.correct}
    assert res.missing == []
    assert res.unused == []


def test_dialing_a_port_the_service_does_not_declare_keeps_it():
    snap = {"deployments": [_dep("app", env={"API": "api:9999"}), _dep("api")],
            "services": [_svc("api", [{"port": 8080, "targetPort": 9090}])]}
    assert ("s/app", "s/api", 9999) in _s1(derive_needed(Inventory.from_dict(snap)))


def test_named_targetport_resolves_via_container_port_names():
    snap = {"deployments": [_dep("app", env={"API_URL": "http://api"}),
                            _dep("api", cports={"web": 8081})],
            "services": [_svc("api", [{"port": 80, "targetPort": "web"}])]}
    assert ("s/app", "s/api", 8081) in _s1(derive_needed(Inventory.from_dict(snap)))


def test_unresolvable_named_targetport_yields_port_unknown():
    """No container declares the name -> port None (conservative: only an
    all-ports admit satisfies a port-unknown need), never a guessed number."""
    snap = {"deployments": [_dep("app", env={"API_URL": "http://api"}), _dep("api")],
            "services": [_svc("api", [{"port": 80, "targetPort": "web"}])]}
    assert ("s/app", "s/api", None) in _s1(derive_needed(Inventory.from_dict(snap)))


# --------------------------------------------------------------- S3 through DNAT
def test_ingress_backend_maps_number_and_name_to_pod_port():
    ing = {"metadata": {"name": "ing", "namespace": "s"},
           "spec": {"rules": [
               {"http": {"paths": [{"path": "/", "pathType": "Prefix",
                                    "backend": {"service": {"name": "api",
                                                            "port": {"number": 80}}}}]}},
               {"http": {"paths": [{"path": "/x", "pathType": "Prefix",
                                    "backend": {"service": {"name": "api",
                                                            "port": {"name": "tls"}}}}]}}]}}
    snap = {"deployments": [_dep("api")],
            "services": [_svc("api", [{"port": 80, "targetPort": 9090},
                                      {"port": 443, "targetPort": 8443, "name": "tls"}])],
            "ingresses": [ing]}
    keys = {(e.src, e.dst, e.port) for e in derive_needed(Inventory.from_dict(snap))
            if e.provenance == Provenance.S3_INGRESS}
    assert ("ingress-controller", "s/api", 9090) in keys
    assert ("ingress-controller", "s/api", 8443) in keys


# --------------------------------------------------------------- S6 / headless
def test_headless_peer_edges_use_the_endpoint_port():
    """Peers find each other via Endpoints, whose port is the resolved targetPort."""
    snap = {"statefulsets": [_dep("db")],
            "services": [_svc("db-headless", [{"port": 5432, "targetPort": 15432}],
                              selector={"app": "db"}, headless=True)]}
    keys = {(e.src, e.dst, e.port) for e in derive_needed(Inventory.from_dict(snap))
            if e.provenance == Provenance.S6_PEER}
    assert ("s/db", "s/db", 15432) in keys


def test_headless_direct_dial_is_not_dnated():
    """A pod-qualified headless dial connects to the pod directly — no kube-proxy,
    no translation: the dialed port IS the pod port."""
    snap = {"deployments": [_dep("app", env={"PRIMARY": "db-0.db-headless:5432"})],
            "statefulsets": [_dep("db")],
            "services": [_svc("db-headless", [{"port": 5432, "targetPort": 15432}],
                              selector={"app": "db"}, headless=True)]}
    assert ("s/app", "s/db", 5432) in _s1(derive_needed(Inventory.from_dict(snap)))


# --------------------------------------------------------------- policy ports
def test_policy_named_port_resolves_per_target_pod():
    """`ports: [{port: metrics}]` names the TARGET container's port; a target
    that does not declare the name is admitted on nothing by that rule."""
    snap = {"deployments": [_dep("scraper"),
                            _dep("api", labels={"app": "api", "scrape": "yes"},
                                 cports={"metrics": 9100}),
                            _dep("api2", labels={"app": "api2", "scrape": "yes"})],
            "networkpolicies": [{
                "metadata": {"name": "allow-scrape", "namespace": "s"},
                "spec": {"podSelector": {"matchLabels": {"scrape": "yes"}},
                         "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "scraper"}}}],
                                      "ports": [{"port": "metrics"}]}]}}]}
    admitted, _ = derive_admitted(Inventory.from_dict(snap))
    keys = {(e.src, e.dst, e.port) for e in admitted}
    assert ("s/scraper", "s/api", 9100) in keys
    assert not any(d == "s/api2" for _, d, _p in keys)


def test_policy_endport_range_satisfies_a_need_inside_it():
    snap = {"deployments": [_dep("app", env={"API": "api:8500"}),
                            _dep("api")],
            "services": [_svc("api", [{"port": 8500}])],
            "networkpolicies": [{
                "metadata": {"name": "api-range", "namespace": "s"},
                "spec": {"podSelector": {"matchLabels": {"app": "api"}},
                         "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "app"}}}],
                                      "ports": [{"port": 8000, "endPort": 9000}]}]}}]}
    inv = Inventory.from_dict(snap)
    admitted, protected = derive_admitted(inv)
    assert ("s/app", "s/api", (8000, 9000)) in {(e.src, e.dst, e.port) for e in admitted}
    res = reconcile(derive_needed(inv), admitted, total_workloads=2, protected=protected)
    assert ("s/app", "s/api", 8500) in {(e.src, e.dst, e.port) for e in res.correct}
    assert res.missing == []
    assert res.unused == []        # the range is in use — must not be flagged removable


def test_admits_understands_ranges_on_both_sides():
    rng = {("a", "b", (8000, 9000))}
    assert admits(("a", "b", 8500), rng, target_is_need=True)
    assert not admits(("a", "b", 9500), rng)
    assert not admits(("a", "b", 9500), rng, target_is_need=True)
    # a range target (an admitted endPort rule checked for use against needs)
    assert admits(("a", "b", (8000, 9000)), {("a", "b", 8500)})
    assert not admits(("a", "b", (8000, 9000)), {("a", "b", 500)})
    # port-unknown need is still only satisfied by an all-ports admit
    assert not admits(("a", "b", None), rng, target_is_need=True)


# --------------------------------------------------------------- CLI --namespace
def test_namespace_flag_filters_offline_sources(tmp_path, capsys):
    """--namespace with --manifests must actually narrow the analysis, not just
    relabel the report header (it used to silently analyse the whole input)."""
    import json

    from npready.cli import main

    m = tmp_path / "two-ns.yaml"
    m.write_text(
        "apiVersion: apps/v1\nkind: Deployment\n"
        "metadata: { name: a, namespace: one }\n"
        "spec: { template: { metadata: { labels: { app: a } },"
        " spec: { containers: [ { name: c } ] } } }\n"
        "---\n"
        "apiVersion: apps/v1\nkind: Deployment\n"
        "metadata: { name: b, namespace: two }\n"
        "spec: { template: { metadata: { labels: { app: b } },"
        " spec: { containers: [ { name: c } ] } } }\n")
    out = tmp_path / "needed.json"
    rc = main(["derive", "--manifests", str(m), "--namespace", "one", "--json", str(out)])
    assert rc == 0
    srcs = {e["src"] for e in json.load(open(out))["needed"]}
    assert srcs == {"one/a"}       # namespace `two` is gone from the analysis


def test_jdbc_url_yields_host_and_port():
    """Spring-style JDBC URLs (Bank of Anthos ledger-db) must resolve to the host, not 'jdbc'."""
    from npready.graph import _parse_endpoint
    assert _parse_endpoint("jdbc:postgresql://ledger-db:5432/postgresdb") == ("ledger-db", 5432)
    assert _parse_endpoint("jdbc:mysql://orders-db:3306/shop") == ("orders-db", 3306)
