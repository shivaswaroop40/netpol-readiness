"""Entry edges (S7) and the render command."""
import yaml

from npready import Inventory
from npready.graph import derive_needed
from npready.model import EdgeClass, Provenance
from npready.policy import derive_admitted
from npready.render import ANY_IPV4, render_policies, selected_by

APP = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend, namespace: shop}
spec:
  template:
    metadata: {labels: {app: frontend}}
    spec:
      containers:
      - name: web
        env: [{name: CART_ADDR, value: "cart:7070"}]
        ports: [{containerPort: 8080}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: cart, namespace: shop}
spec:
  template:
    metadata: {labels: {app: cart}}
    spec: {containers: [{name: cart, ports: [{containerPort: 7070}]}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: worker, namespace: shop}
spec:
  template:
    metadata: {labels: {app: worker}}
    spec: {containers: [{name: worker}]}
---
apiVersion: v1
kind: Service
metadata: {name: cart, namespace: shop}
spec: {selector: {app: cart}, ports: [{port: 7070, targetPort: 7070}]}
---
apiVersion: v1
kind: Service
metadata: {name: frontend-external, namespace: shop}
spec:
  type: LoadBalancer
  selector: {app: frontend}
  ports: [{name: http, port: 80, targetPort: 8080}]
"""

INGRESS = """
---
apiVersion: v1
kind: Service
metadata: {name: frontend, namespace: shop}
spec: {selector: {app: frontend}, ports: [{port: 80, targetPort: 8080}]}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: shop}
spec:
  rules:
  - http:
      paths:
      - path: /
        pathType: Prefix
        backend: {service: {name: frontend, port: {number: 80}}}
"""


def _inv(tmp_path, text):
    f = tmp_path / "app.yaml"
    f.write_text(text)
    return Inventory.from_manifests(str(f))


def _policy(policies, name):
    return next(p for p in policies if p["metadata"]["name"] == name)


def test_entry_edges_only_when_asked(tmp_path):
    inv = _inv(tmp_path, APP)
    assert not [e for e in derive_needed(inv) if e.provenance == Provenance.S7_EXPOSED]
    entry = [e for e in derive_needed(inv, entry=True) if e.provenance == Provenance.S7_EXPOSED]
    assert [(e.src, e.dst, e.port, e.edge_class) for e in entry] == \
        [("world", "shop/frontend", 8080, EdgeClass.ENTRY)]          # targetPort, not port 80


def test_render_admits_outside_clients_on_the_target_port(tmp_path):
    inv = _inv(tmp_path, APP)
    pols, _ = render_policies(inv, [e.key() for e in derive_needed(inv, entry=True)])
    rule = [r for r in _policy(pols, "allow-frontend")["spec"]["ingress"] if "ipBlock" in r["from"][0]]
    assert rule == [{"from": [{"ipBlock": {"cidr": ANY_IPV4}}], "ports": [{"port": 8080, "protocol": "TCP"}]}]


def test_render_without_entry_has_no_ipblock(tmp_path):
    inv = _inv(tmp_path, APP)
    pols, _ = render_policies(inv, [e.key() for e in derive_needed(inv)])
    assert "ipBlock" not in yaml.safe_dump_all(pols)


def test_load_balancer_source_ranges_narrow_the_rule(tmp_path):
    text = APP.replace("  type: LoadBalancer\n",
                       "  type: LoadBalancer\n  loadBalancerSourceRanges: [203.0.113.0/24]\n")
    inv = _inv(tmp_path, text)
    pols, _ = render_policies(inv, [e.key() for e in derive_needed(inv, entry=True)])
    assert "203.0.113.0/24" in yaml.safe_dump(_policy(pols, "allow-frontend"))
    assert ANY_IPV4 not in yaml.safe_dump(_policy(pols, "allow-frontend"))


def test_every_workload_is_isolated(tmp_path):
    inv = _inv(tmp_path, APP)
    pols, _ = render_policies(inv, [e.key() for e in derive_needed(inv, entry=True)])
    assert all(selected_by(pols, w) for w in inv.workloads)
    assert _policy(pols, "deny-worker")["spec"]["ingress"] == []     # nothing reaches it


def test_rendered_policies_admit_the_declared_edges(tmp_path):
    inv = _inv(tmp_path, APP)
    declared = [e.key() for e in derive_needed(inv)]
    pols, _ = render_policies(inv, declared)
    inv.networkpolicies = pols
    admitted, protected = derive_admitted(inv)
    assert ("shop/frontend", "shop/cart", 7070) in {e.key() for e in admitted}
    assert protected == {w.id for w in inv.workloads}


def test_observed_edges_are_fused_in(tmp_path):
    inv = _inv(tmp_path, APP)
    edges = [e.key() for e in derive_needed(inv)] + [("shop/worker", "shop/cart", 7070)]
    pols, _ = render_policies(inv, edges)
    srcs = [r["from"][0]["podSelector"]["matchLabels"] for r in _policy(pols, "allow-cart")["spec"]["ingress"]]
    assert {"app": "worker"} in srcs and {"app": "frontend"} in srcs


def test_ingress_route_needs_a_named_controller(tmp_path):
    inv = _inv(tmp_path, APP + INGRESS)
    edges = [e.key() for e in derive_needed(inv)]
    pols, skipped = render_policies(inv, edges)
    assert any(e[0] == "ingress-controller" for e, _ in skipped)
    pols, skipped = render_policies(inv, edges, ingress_controller=("ingress-nginx", {"app": "ingress-nginx"}))
    assert not skipped
    rule = [r for r in _policy(pols, "allow-frontend")["spec"]["ingress"]
            if r["from"][0].get("namespaceSelector")]
    assert rule[0]["from"][0]["namespaceSelector"] == {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}
    assert rule[0]["ports"] == [{"port": 8080, "protocol": "TCP"}]
