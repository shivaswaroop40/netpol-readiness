"""The live-cluster path (from_cluster) — mocked, so the kubectl→Inventory mapping
is exercised without a cluster. It was previously untested."""
import json
from unittest import mock

from npready import Inventory


def _kubectl_output(kind):
    """Fake `kubectl get <kind> -o json` payloads."""
    data = {
        "deployments": {"items": [{
            "metadata": {"name": "web", "namespace": "shop"},
            "spec": {"template": {"metadata": {"labels": {"app": "web"}},
                     "spec": {"serviceAccountName": "web-sa",
                              "containers": [{"name": "c", "env": [
                                  {"name": "DB_HOST", "value": "db:5432"}]}]}}}}]},
        "services": {"items": [{
            "metadata": {"name": "db", "namespace": "shop"},
            "spec": {"selector": {"app": "db"}, "ports": [{"port": 5432}]}}]},
        "namespaces": {"items": [{"metadata": {"name": "shop", "labels": {"team": "x"}}}]},
    }
    return json.dumps(data.get(kind, {"items": []}))


def test_from_cluster_maps_kubectl_json(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout=None):
        # cmd is a list like ["kubectl","--context","c","get","deployments",...]
        kind = cmd[cmd.index("get") + 1]
        return mock.Mock(returncode=0, stdout=_kubectl_output(kind), stderr="")

    monkeypatch.setattr("npready.inventory.subprocess.run", fake_run)
    inv = Inventory.from_cluster(context="c", namespace="shop")

    assert len(inv.workloads) == 1
    w = inv.workloads[0]
    assert w.id == "shop/web" and w.service_account == "web-sa"
    assert ("DB_HOST", "db:5432") in w.env
    # k8s auto-adds kubernetes.io/metadata.name; we synthesise it too, so check subset
    assert inv.namespace_labels.get("shop", {}).get("team") == "x"


def test_from_cluster_forbidden_is_tolerated(monkeypatch):
    """A 403/forbidden on one kind must not crash the load (returns empty for it)."""
    def fake_run(cmd, capture_output, text, timeout=None):
        return mock.Mock(returncode=1, stdout="", stderr="Error: deployments is forbidden")

    monkeypatch.setattr("npready.inventory.subprocess.run", fake_run)
    inv = Inventory.from_cluster(context="c")
    assert inv.workloads == []          # no crash, just empty


def test_from_manifests_unwraps_kubectl_list(tmp_path):
    """`kubectl get ... -o yaml` wraps objects in `kind: List`. The loader must
    unwrap it, otherwise the most common way anyone feeds us manifests yields
    zero workloads. Regression test for that silent-drop bug."""
    manifest = tmp_path / "dump.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: List\n"
        "items:\n"
        "- apiVersion: apps/v1\n"
        "  kind: Deployment\n"
        "  metadata: { name: web, namespace: shop }\n"
        "  spec:\n"
        "    template:\n"
        "      metadata: { labels: { app: web } }\n"
        "      spec:\n"
        "        containers:\n"
        "        - name: c\n"
        "          env:\n"
        "          - { name: DB_HOST, value: 'db:5432' }\n"
        "- apiVersion: v1\n"
        "  kind: Service\n"
        "  metadata: { name: db, namespace: shop }\n"
        "  spec: { selector: { app: db }, ports: [ { port: 5432 } ] }\n"
    )
    inv = Inventory.from_manifests(str(manifest))
    assert len(inv.workloads) == 1
    assert inv.workloads[0].id == "shop/web"
    assert len(inv.services) == 1
    assert ("DB_HOST", "db:5432") in inv.workloads[0].env
