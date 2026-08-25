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
        assert e.evidence == "DATABASE_URL=db:5432"
