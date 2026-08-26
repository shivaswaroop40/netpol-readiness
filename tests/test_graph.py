"""Config-derivation (NEEDED graph) tests — one per source, against known fixture."""
from npready import derive_needed
from npready.model import Provenance


def _keys(edges):
    return {(e.src, e.dst, e.port) for e in edges}


def test_inventory_loads(mini_inventory):
    inv = mini_inventory
    names = {w.name for w in inv.workloads}
    assert names == {"storefront", "orders-api", "orders-db", "orders-cache", "reporting"}
    assert len(inv.networkpolicies) == 1
    assert len(inv.ingresses) == 1
    assert len(inv.rolebindings) == 1


def test_s1_env_endpoints(mini_inventory):
    """env vars name peers -> caller->backend edges on the declared port."""
    keys = _keys(derive_needed(mini_inventory))
    assert ("shop/storefront", "shop/orders-api", 8080) in keys   # ORDERS_API_URL
    assert ("shop/orders-api", "shop/orders-db", 5432) in keys    # POSTGRES_HOST
    assert ("shop/orders-api", "shop/orders-cache", 6379) in keys  # REDIS_ADDR


def test_s3_ingress(mini_inventory):
    keys = _keys(derive_needed(mini_inventory))
    assert ("ingress-controller", "shop/storefront", 80) in keys


def test_s4_dns_invariant(mini_inventory):
    """every non-hostNetwork workload gets a DNS edge."""
    edges = derive_needed(mini_inventory)
    dns = [e for e in edges if e.provenance == Provenance.S4_DNS]
    assert len(dns) == 5
    assert all(e.dst == "kube-dns" and e.port == 53 for e in dns)


def test_s5_apiserver_from_rbac(mini_inventory):
    """only the workload whose SA is bound gets the apiserver edge."""
    edges = derive_needed(mini_inventory)
    api = [e for e in edges if e.provenance == Provenance.S5_APISERVER]
    assert len(api) == 1
    assert api[0].src == "shop/reporting" and api[0].dst == "kube-apiserver"


def test_provenance_is_recorded(mini_inventory):
    """every derived edge carries evidence — auditability is a requirement."""
    for e in derive_needed(mini_inventory):
        assert e.evidence, f"edge {e.src}->{e.dst} has no evidence"


def test_dedup_is_port_aware(mini_inventory):
    """two edges differing only in port must both survive."""
    keys = _keys(derive_needed(mini_inventory))
    db = [(s, d, p) for (s, d, p) in keys if d == "shop/orders-db"]
    cache = [(s, d, p) for (s, d, p) in keys if d == "shop/orders-cache"]
    assert (("shop/orders-api", "shop/orders-db", 5432)) in db
    assert (("shop/orders-api", "shop/orders-cache", 6379)) in cache


def test_s1_evidence_does_not_leak_raw_value(mini_inventory):
    """SECURITY: env values can contain inline credentials; evidence must record
    only the parsed endpoint (name=host:port), never the raw value/scheme."""
    edges = derive_needed(mini_inventory)
    s1 = [e for e in edges if e.provenance == Provenance.S1_ENV_ENDPOINT]
    for e in s1:
        assert "://" not in e.evidence          # scheme (and any user:pass@) stripped
        assert e.evidence.count("=") == 1        # "NAME=host:port" shape


def test_s1_evidence_redacts_credential_url():
    """A DATABASE_URL with inline credentials must not appear in evidence."""
    from npready import Inventory
    snap = {"deployments": [{
        "metadata": {"name": "app", "namespace": "x"},
        "spec": {"template": {"metadata": {"labels": {"app": "app"}},
                 "spec": {"containers": [{"name": "c", "env": [
                     {"name": "DATABASE_URL", "value": "postgres://user:s3cret@db:5432/app"}]}]}}},
    }], "services": [{"metadata": {"name": "db", "namespace": "x"},
                      "spec": {"selector": {"app": "db"}, "ports": [{"port": 5432}]}}]}
    # add the db workload so the edge resolves
    snap["deployments"].append({
        "metadata": {"name": "db", "namespace": "x"},
        "spec": {"template": {"metadata": {"labels": {"app": "db"}},
                 "spec": {"containers": [{"name": "c"}]}}}})
    edges = derive_needed(Inventory.from_dict(snap))
    s1 = [e for e in edges if e.provenance == Provenance.S1_ENV_ENDPOINT]
    assert s1, "expected an S1 edge"
    for e in s1:
        assert "s3cret" not in e.evidence
        assert "user:" not in e.evidence
        # evidence names the surface it came from, then the parsed endpoint only
        assert e.evidence == "env:DATABASE_URL=db:5432"


# --- Generalisation: resolve by VALUE against the Service catalog, not by var NAME ---
def _wl(name, ns, env=None, labels=None, cm_refs=None, argv=None):
    d = {"metadata": {"name": name, "namespace": ns},
         "spec": {"template": {"metadata": {"labels": labels or {"app": name}},
                  "spec": {"containers": [{"name": "c", "env": [
                      {"name": k, "value": v} for k, v in (env or {}).items()]}]}}}}
    if argv:
        d["spec"]["template"]["spec"]["containers"][0]["command"] = argv
    if cm_refs:
        d["spec"]["template"]["spec"]["volumes"] = [
            {"name": "c", "configMap": {"name": n}} for n in cm_refs]
    return d


def _svc(name, ns, port, selector=None):
    return {"metadata": {"name": name, "namespace": ns},
            "spec": {"selector": selector or {"app": name}, "ports": [{"port": port}]}}


def test_resolves_endpoint_regardless_of_variable_name():
    """The dependency is real even when the variable name follows no convention —
    this is the Sock Shop `mongo=user-db:27017` case the name-pattern approach missed."""
    from npready import Inventory
    snap = {"deployments": [_wl("user", "s", {"mongo": "user-db:27017"}), _wl("user-db", "s")],
            "services": [_svc("user-db", "s", 27017)]}
    edges = derive_needed(Inventory.from_dict(snap))
    hit = [e for e in edges if e.dst == "s/user-db"]
    assert hit, "value-based resolution must find the dependency"
    assert hit[0].port == 27017
    assert hit[0].confidence < 1.0        # resolved by value only -> lower confidence


def test_conventional_name_raises_confidence():
    from npready import Inventory
    snap = {"deployments": [_wl("app", "s", {"DB_HOST": "db:5432"}), _wl("db", "s")],
            "services": [_svc("db", "s", 5432)]}
    e = [x for x in derive_needed(Inventory.from_dict(snap)) if x.dst == "s/db"][0]
    assert e.confidence == 1.0            # name corroborates the resolution


def test_unresolvable_values_produce_no_edges():
    """Scanning every value must not invent edges: only catalog hits count."""
    from npready import Inventory
    snap = {"deployments": [_wl("app", "s", {
                "MYSQL_DATABASE": "socksdb", "SESSION_REDIS": "true",
                "JAVA_OPTS": "-Xms64m -Xmx128m -XX:+UseG1GC"})],
            "services": []}
    edges = [e for e in derive_needed(Inventory.from_dict(snap))
             if e.provenance == Provenance.S1_ENV_ENDPOINT]
    assert edges == []


def test_configmap_and_argv_are_scanned():
    from npready import Inventory
    snap = {"deployments": [_wl("app", "s", cm_refs=["appcfg"], argv=["--broker=queue:5672"]),
                            _wl("cache", "s"), _wl("queue", "s")],
            "services": [_svc("cache", "s", 6379), _svc("queue", "s", 5672)],
            "configmaps": [{"metadata": {"name": "appcfg", "namespace": "s"},
                            "data": {"redis": "cache:6379"}}]}
    dsts = {e.dst for e in derive_needed(Inventory.from_dict(snap))
            if e.provenance == Provenance.S1_ENV_ENDPOINT}
    assert "s/cache" in dsts       # from the ConfigMap
    assert "s/queue" in dsts       # from the command line


def test_pod_qualified_headless_host_resolves_in_cluster():
    """`pod-0.svc` (StatefulSet headless form) must resolve in-cluster, not to world."""
    from npready import Inventory
    snap = {"deployments": [_wl("arb", "s", {"PRIMARY_HOST": "db-0.db-headless:27017"})],
            "statefulsets": [_wl("db", "s")],
            "services": [_svc("db-headless", "s", 27017, selector={"app": "db"})]}
    edges = [e for e in derive_needed(Inventory.from_dict(snap)) if e.src == "s/arb"]
    assert any(e.dst == "s/db" for e in edges), "must resolve to the backing workload"
    assert not any(e.dst == "world" for e in edges), "must NOT be classified as egress"


def test_scheme_supplies_port_when_value_has_none():
    """`ANKRA_URL=https://host` is a real egress dependency on :443. Without the
    scheme default it derived a portless edge, which cannot be written as a
    NetworkPolicy rule. Found on a live cluster; an explicit port still wins."""
    from npready.graph import _parse_endpoint

    assert _parse_endpoint("https://platform.thesis.example") == ("platform.thesis.example", 443)
    assert _parse_endpoint("http://svc") == ("svc", 80)
    assert _parse_endpoint("postgres://u:p@db") == ("db", 5432)
    assert _parse_endpoint("nats://gw") == ("gw", 4222)
    # explicit port wins over the scheme default
    assert _parse_endpoint("https://host:8443") == ("host", 8443)
    assert _parse_endpoint("redis://:pw@cache:6379") == ("cache", 6379)
    # no scheme, no port -> still unknown, not guessed
    assert _parse_endpoint("plainhost") == ("plainhost", None)
