"""Cluster inventory: the read-only inputs every analysis needs.

Three ways to load the same shape, so the tool runs anywhere:
  * from a live cluster  (``from_cluster``)  — read-only ``kubectl get``
  * from a JSON blob     (``from_dict``)     — for tests and cached snapshots
  * from a manifest dir  (``from_manifests``)— analyse before you even deploy

Nothing here mutates a cluster. The live path issues only ``kubectl get``.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

import yaml

CLUSTER_SCOPED = {"clusterrolebindings", "clusterroles"}


@dataclass
class Workload:
    ns: str
    name: str
    kind: str                         # deployment | statefulset | daemonset
    labels: dict = field(default_factory=dict)
    service_account: str = "default"
    env: list = field(default_factory=list)          # list[(name, value)]
    host_network: bool = False
    configmap_refs: set = field(default_factory=set)  # ConfigMap names this workload consumes
    argv: str = ""                                     # container command+args, joined (S7 scan)

    @property
    def id(self) -> str:
        return f"{self.ns}/{self.name}"


@dataclass
class Service:
    ns: str
    name: str
    selector: dict = field(default_factory=dict)
    ports: list = field(default_factory=list)        # list[(port, targetPort)]
    kind: str = "ClusterIP"                            # ClusterIP | NodePort | LoadBalancer | ExternalName | Headless
    external_name: Optional[str] = None

    @property
    def id(self) -> str:
        return f"{self.ns}/{self.name}"


@dataclass
class Inventory:
    """Everything needed for config derivation and policy analysis."""

    workloads: list = field(default_factory=list)     # list[Workload]
    services: list = field(default_factory=list)       # list[Service]
    networkpolicies: list = field(default_factory=list)  # raw dicts
    ingresses: list = field(default_factory=list)       # raw dicts
    rolebindings: list = field(default_factory=list)    # raw dicts (Role + ClusterRole)
    namespace_labels: dict = field(default_factory=dict)  # ns name -> labels (for namespaceSelector)
    configmaps: dict = field(default_factory=dict)      # (ns, name) -> {key: value} (S1 surfaces)

    # ----------------------------------------------------------------- loaders
    @classmethod
    def from_cluster(cls, context: Optional[str] = None, namespace: Optional[str] = None,
                     kubectl: str = "kubectl") -> Inventory:
        """Read-only load from a live cluster via ``kubectl get -o json``."""
        def kget(kind: str) -> list:
            cmd = [kubectl]
            if context:
                cmd += ["--context", context]
            cmd += ["get", kind, "-o", "json"]
            if kind not in CLUSTER_SCOPED:
                cmd += (["-n", namespace] if namespace else ["-A"])
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                if "orbidden" in r.stderr:
                    print(f"  ! no permission to read {kind}", file=sys.stderr)
                return []
            try:
                return json.loads(r.stdout).get("items", [])
            except json.JSONDecodeError:
                return []

        raw = {
            "deployments": kget("deployments"),
            "statefulsets": kget("statefulsets"),
            "daemonsets": kget("daemonsets"),
            "services": kget("services"),
            "networkpolicies": kget("networkpolicies"),
            "ingresses": kget("ingresses"),
            "rolebindings": kget("rolebindings") + kget("clusterrolebindings"),
            "namespaces": kget("namespaces"),
            "configmaps": kget("configmaps"),
        }
        return cls._from_raw(raw)

    @classmethod
    def from_dict(cls, data: dict) -> Inventory:
        """Load from a dict of ``{kind: [k8s objects]}`` — the test/snapshot path."""
        return cls._from_raw(data)

    @classmethod
    def from_manifests(cls, path: str) -> Inventory:
        """Load from a directory (or single file) of YAML manifests."""
        import os
        docs = []
        files = []
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                files += [os.path.join(root, n) for n in names
                          if n.endswith((".yaml", ".yml"))]
        else:
            files = [path]
        def flatten(doc):
            """Yield real objects, unwrapping List envelopes.

            ``kubectl get ... -o yaml`` wraps everything in ``kind: List``, which is
            how most people will hand us manifests. Unwrap recursively so a List of
            Lists also works.
            """
            if not isinstance(doc, dict) or not doc.get("kind"):
                return
            if doc["kind"].endswith("List") and isinstance(doc.get("items"), list):
                for item in doc["items"]:
                    yield from flatten(item)
            else:
                yield doc

        for f in files:
            with open(f) as fh:
                for doc in yaml.safe_load_all(fh):
                    docs.extend(flatten(doc))
        buckets: dict = {k: [] for k in
                         ("deployments", "statefulsets", "daemonsets", "services",
                          "networkpolicies", "ingresses", "rolebindings", "namespaces",
                          "configmaps")}
        kind_map = {
            "Deployment": "deployments", "StatefulSet": "statefulsets",
            "DaemonSet": "daemonsets", "Service": "services",
            "NetworkPolicy": "networkpolicies", "Ingress": "ingresses",
            "RoleBinding": "rolebindings", "ClusterRoleBinding": "rolebindings",
            "Namespace": "namespaces", "ConfigMap": "configmaps",
        }
        for d in docs:
            b = kind_map.get(d["kind"])
            if b:
                buckets[b].append(d)
        return cls._from_raw(buckets)

    # ----------------------------------------------------------------- internal
    @classmethod
    def _from_raw(cls, raw: dict) -> Inventory:
        workloads = []
        for kind in ("deployments", "statefulsets", "daemonsets"):
            for w in raw.get(kind, []):
                meta = w.get("metadata", {})
                spec = w.get("spec", {})
                tmpl = (spec.get("template") or {}).get("spec", {}) or {}
                tmeta = (spec.get("template") or {}).get("metadata", {}) or {}
                env, cm_refs, argv = [], set(), []
                containers = (tmpl.get("containers") or []) + (tmpl.get("initContainers") or [])
                for c in containers:
                    for e in (c.get("env") or []):
                        if isinstance(e, dict) and e.get("value") is not None:
                            env.append((e["name"], str(e["value"])))
                        # envFrom-style single ref
                        ref = ((e or {}).get("valueFrom") or {}).get("configMapKeyRef") or {}
                        if ref.get("name"):
                            cm_refs.add(ref["name"])
                    for ef in (c.get("envFrom") or []):
                        if (ef.get("configMapRef") or {}).get("name"):
                            cm_refs.add(ef["configMapRef"]["name"])
                    argv += [str(x) for x in (c.get("command") or [])]
                    argv += [str(x) for x in (c.get("args") or [])]
                for vol in (tmpl.get("volumes") or []):
                    if (vol.get("configMap") or {}).get("name"):
                        cm_refs.add(vol["configMap"]["name"])
                workloads.append(Workload(
                    ns=meta.get("namespace", "default"),
                    name=meta["name"],
                    kind=kind[:-1],
                    labels=tmeta.get("labels") or {},
                    service_account=tmpl.get("serviceAccountName") or "default",
                    env=env,
                    host_network=bool(tmpl.get("hostNetwork")),
                    configmap_refs=cm_refs,
                    argv=" ".join(argv),
                ))
        services = []
        for s in raw.get("services", []):
            meta = s.get("metadata", {})
            spec = s.get("spec", {})
            stype = spec.get("type", "ClusterIP")
            if stype == "ClusterIP" and spec.get("clusterIP") == "None":
                stype = "Headless"
            services.append(Service(
                ns=meta.get("namespace", "default"),
                name=meta["name"],
                selector=spec.get("selector") or {},
                ports=[(p.get("port"), p.get("targetPort")) for p in (spec.get("ports") or [])],
                kind=stype,
                external_name=spec.get("externalName"),
            ))
        ns_labels = {}
        for n in raw.get("namespaces", []):
            meta = n.get("metadata", {})
            ns_labels[meta.get("name")] = meta.get("labels") or {}
        # Kubernetes auto-labels every namespace with kubernetes.io/metadata.name.
        # Synthesise it for namespaces we saw workloads in but no Namespace object for,
        # so a namespaceSelector on that well-known label still resolves.
        for w in workloads:
            ns_labels.setdefault(w.ns, {})
            ns_labels[w.ns].setdefault("kubernetes.io/metadata.name", w.ns)
        cms = {}
        for cm in raw.get("configmaps", []):
            m = cm.get("metadata", {})
            data = cm.get("data") or {}
            if isinstance(data, dict):
                cms[(m.get("namespace", "default"), m.get("name"))] = data
        return cls(
            workloads=workloads,
            services=services,
            networkpolicies=raw.get("networkpolicies", []),
            ingresses=raw.get("ingresses", []),
            rolebindings=raw.get("rolebindings", []),
            namespace_labels=ns_labels,
            configmaps=cms,
        )

    # ----------------------------------------------------------------- helpers
    def service_index(self) -> dict:
        return {(s.ns, s.name): s for s in self.services}

    def workloads_backing(self, svc: Service) -> list:
        """Workloads a Service selects (same namespace, label-selector match)."""
        if not svc.selector:
            return []
        return [w for w in self.workloads
                if w.ns == svc.ns and labels_match({"matchLabels": svc.selector}, w.labels)]


def labels_match(selector: Optional[dict], labels: dict) -> bool:
    """Evaluate a Kubernetes label selector (matchLabels + matchExpressions)."""
    if selector is None:
        return False
    if selector == {}:
        return True                                   # empty selector = all pods
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for expr in (selector.get("matchExpressions") or []):
        k, op, vals = expr.get("key"), expr.get("operator"), expr.get("values", [])
        got = labels.get(k)
        if op == "In" and got not in vals:
            return False
        if op == "NotIn" and got in vals:
            return False
        if op == "Exists" and k not in labels:
            return False
        if op == "DoesNotExist" and k in labels:
            return False
    return True
