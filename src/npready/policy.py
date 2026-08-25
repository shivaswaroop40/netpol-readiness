"""What the NetworkPolicy objects actually ADMIT.

We expand every ``networking.k8s.io/v1`` NetworkPolicy into the concrete set of
identity-to-identity-on-port edges it permits, so it can be set-compared against
the needed graph. This is deliberately the *ingress* view (who may reach a
selected pod), because ingress is what a segmentation policy is written to
restrict and what the readiness question turns on.

We also return the set of workloads that any ingress policy selects — a workload
with no ingress policy is default-allow and therefore not yet "protected".
"""
from __future__ import annotations

from .inventory import Inventory, labels_match
from .model import Edge, EdgeClass, Provenance


def derive_admitted(inv: Inventory):
    """Return ``(admitted_edges, protected_workload_ids)``.

    An edge (s, d, port) is admitted when some NetworkPolicy selecting d has an
    ingress rule whose ``from`` matches s and whose ports include ``port``
    (``None`` = the rule names no ports, i.e. all ports).
    """
    edges = []
    protected = set()
    wl = inv.workloads
    ns_labels = inv.namespace_labels

    for np in inv.networkpolicies:
        ns = np.get("metadata", {}).get("namespace", "default")
        spec = np.get("spec", {})
        sel = spec.get("podSelector", {})
        targets = [w for w in wl if w.ns == ns and labels_match(sel, w.labels)]

        # policyTypes semantics: if the field is OMITTED, the policy affects Ingress
        # regardless of whether an ingress section is present (k8s default). If it is
        # present, it affects ingress only when it lists "Ingress".
        ptypes = spec.get("policyTypes")
        affects_ingress = ptypes is None or "Ingress" in ptypes
        if affects_ingress:
            for t in targets:
                protected.add(t.id)

        for rule in (spec.get("ingress") or []):
            ports = _rule_ports(rule)
            for f in (rule.get("from") or [{"__all__": True}]):
                srcs = _match_from(f, ns, wl, ns_labels)
                for s in srcs:
                    for p in ports:
                        for t in targets:
                            if s.id != t.id:
                                edges.append(Edge(s.id, t.id, p, EdgeClass.IN_CLUSTER,
                                                  Provenance.POLICY, evidence=np["metadata"]["name"]))
    # de-dup on (src, dst, port)
    best = {}
    for e in edges:
        best.setdefault(e.key(), e)
    return list(best.values()), protected


def _rule_ports(rule: dict):
    ports = []
    for p in (rule.get("ports") or []):
        port = p.get("port")
        ports.append(int(port) if isinstance(port, int) else port)
    return ports or [None]                            # no ports named = all ports


def _match_from(f: dict, ns: str, wl: list, ns_labels: dict):
    """Resolve one ``from`` peer to the workloads it admits.

    Semantics (matching k8s ``NetworkPolicyPeer``):
      * podSelector only            -> pods in the POLICY's namespace matching it
      * namespaceSelector only      -> all pods in namespaces matching it
      * namespaceSelector + podSel  -> pods matching podSel in namespaces matching nsSel
      * an EMPTY namespaceSelector {} matches ALL namespaces
      * ipBlock                     -> no workload identity, admits nothing here
    """
    if f.get("__all__"):
        return list(wl)                               # rule with no `from` = allow-all
    has_ns = "namespaceSelector" in f
    has_pod = "podSelector" in f

    if has_ns and not has_pod:
        matched_ns = _namespaces_matching(f["namespaceSelector"], ns_labels)
        return [w for w in wl if w.ns in matched_ns]
    if has_ns and has_pod:
        matched_ns = _namespaces_matching(f["namespaceSelector"], ns_labels)
        psel = f["podSelector"]
        return [w for w in wl if w.ns in matched_ns and labels_match(psel, w.labels)]
    if has_pod:                                       # podSelector only: policy namespace
        return [w for w in wl if w.ns == ns and labels_match(f["podSelector"], w.labels)]
    return []                                          # ipBlock or unrecognised peer


def _namespaces_matching(ns_selector: dict, ns_labels: dict) -> set:
    """Namespaces whose labels satisfy a namespaceSelector. Empty selector = all."""
    return {name for name, labels in ns_labels.items()
            if labels_match(ns_selector, labels)}
