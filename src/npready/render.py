"""Render an edge set as ingress NetworkPolicies.

One policy per workload. A workload that some edge reaches gets ``allow-<name>``,
listing each source and port; a workload that no edge reaches gets
``deny-<name>``, an empty ingress list, so every workload is isolated. Edges to
destinations that are not workloads (the internet, the API server, DNS) are egress
from their source and are not rendered, since the policies are ingress-only.

Sources that are not workloads:
  ``world``               an entry edge (S7) from outside the cluster; rendered as an
                          ``ipBlock`` with the Service's ``loadBalancerSourceRanges``,
                          or ``0.0.0.0/0`` when the Service sets none.
  ``ingress-controller``  an Ingress route (S3); rendered only when the controller is
                          named with ``ingress_controller=(namespace, labels)``, since
                          the route does not say which pods run the controller.
Any other token is skipped and reported.
"""
from __future__ import annotations

from .inventory import Inventory, labels_match

ANY_IPV4 = "0.0.0.0/0"


def _ports(ports) -> list:
    """NetworkPolicyPort entries for a set of edge ports. ``None`` = all ports."""
    if None in ports:
        return []
    out = []
    for p in sorted(ports, key=lambda x: x if isinstance(x, int) else x[0]):
        if isinstance(p, tuple):
            out.append({"port": p[0], "endPort": p[1], "protocol": "TCP"})
        else:
            out.append({"port": p, "protocol": "TCP"})
    return out


def _entry_cidrs(inv: Inventory, target, port) -> list:
    """Source CIDRs allowed into ``target`` on ``port`` through exposed Services."""
    cidrs = []
    for svc in inv.services:
        if svc.kind not in ("LoadBalancer", "NodePort"):
            continue
        if target not in inv.workloads_backing(svc):
            continue
        if any(inv.endpoint_port(svc, e) == port for e in svc.ports):
            cidrs += svc.source_ranges or [ANY_IPV4]
    return sorted(set(cidrs)) or [ANY_IPV4]


def render_policies(inv: Inventory, edges, ingress_controller=None):
    """Return ``(policies, skipped)``.

    ``edges`` are ``(src, dst, port)`` tuples or :class:`Edge` objects whose src and
    dst are workload ids (``namespace/name``) or tokens. ``ingress_controller`` is an
    optional ``(namespace, labels)`` pair naming the pods that run the Ingress
    controller. ``skipped`` lists the edges that could not be rendered, with a reason.
    """
    by_id = {w.id: w for w in inv.workloads}
    rules: dict = {}                       # dst id -> {peer key: set(ports)}
    skipped = []
    for e in edges:
        src, dst, port = (e.src, e.dst, e.port) if hasattr(e, "src") else (tuple(e) + (None,))[:3]
        tgt = by_id.get(dst)
        if tgt is None or tgt.host_network:
            continue                       # egress or not expressible: not an ingress rule
        if src in by_id:
            peer = ("pod", src)
        elif src == "world":
            peer = ("cidr", tuple(_entry_cidrs(inv, tgt, port)))
        elif src == "ingress-controller" and ingress_controller is not None:
            peer = ("controller",)
        else:
            skipped.append(((src, dst, port), f"source {src!r} has no workload identity to select"))
            continue
        rules.setdefault(dst, {}).setdefault(peer, set()).add(port)

    policies = []
    for w in inv.workloads:
        if w.host_network:
            continue
        meta = {"name": f"{'allow' if w.id in rules else 'deny'}-{w.name}", "namespace": w.ns,
                "labels": {"npready/generated": "true"}}
        spec = {"podSelector": {"matchLabels": dict(w.labels)}, "policyTypes": ["Ingress"]}
        ingress = []
        for peer, ports in sorted(rules.get(w.id, {}).items(), key=lambda kv: str(kv[0])):
            if peer[0] == "pod":
                s = by_id[peer[1]]
                frm = {"podSelector": {"matchLabels": dict(s.labels)}}
                if s.ns != w.ns:
                    frm["namespaceSelector"] = {"matchLabels": {"kubernetes.io/metadata.name": s.ns}}
                froms = [frm]
            elif peer[0] == "cidr":
                froms = [{"ipBlock": {"cidr": c}} for c in peer[1]]
            else:
                ns, labels = ingress_controller
                froms = [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
                          "podSelector": {"matchLabels": dict(labels)}}]
            rule = {"from": froms}
            p = _ports(ports)
            if p:
                rule["ports"] = p
            ingress.append(rule)
        spec["ingress"] = ingress
        policies.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                         "metadata": meta, "spec": spec})
    return policies, skipped


def selected_by(policies, workload) -> bool:
    """Whether any rendered policy selects ``workload`` (used by tests)."""
    return any(p["metadata"]["namespace"] == workload.ns
               and labels_match(p["spec"]["podSelector"], workload.labels) for p in policies)
