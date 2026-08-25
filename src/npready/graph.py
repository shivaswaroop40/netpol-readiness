"""Config-derived dependency graph: the NEEDED edges.

This is the half that observation cannot produce. Each source turns a piece of
declared configuration into reachability edges, every edge carrying its provenance
and the literal evidence that justified it. The union across sources is the set of
edges the application *declares* it needs — including the rare ones that fire on
events a benign observation window never triggers.

Sources (each independent, each auditable):
  S1  workload env endpoints        MYSVC_ADDR=redis:6379            -> caller -> backend
  S3  Ingress / Gateway routes      ingress backend service          -> ingress -> backend
  S4  cluster DNS invariant         every pod resolves names         -> workload -> kube-dns:53
  S5  RBAC bindings                 ServiceAccount bound to a role   -> workload -> kube-apiserver
  S6  headless Service peers        StatefulSet behind headless svc  -> peer <-> peer

(S2 "Service catalog" is the DNS-name -> backing-workload resolver used by S1 and
S3, not a standalone edge source, so it has no emit step of its own.)
"""
from __future__ import annotations

import re
from typing import Optional

from .inventory import Inventory, Service, Workload
from .model import Edge, EdgeClass, Provenance

# Env var names that name a network peer (twelve-factor style).
ENDPOINT_RE = re.compile(
    r"(_HOST|_HOSTNAME|_URL|_URI|_ENDPOINT|_ADDR|_ADDRESS|_SERVER|_BROKER|_BROKERS|_DSN)$")
# Strip an optional scheme (http://, redis://, postgres://, tcp://, nats://, ...).
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://")
# From the remaining "host[:port][/path]" (or "user:pass@host:port"), take host+port.
HOST_RE = re.compile(r"^(?:[^@/]*@)?([a-z0-9][a-z0-9.\-]*[a-z0-9])(?::(\d+))?")
# A hostname with a dot that is NOT a cluster-internal suffix looks like egress.
CLUSTER_SUFFIX = ".svc.cluster.local"


def _parse_endpoint(val: str):
    """Extract (host, port|None) from an endpoint value, scheme-aware.

    'http://orders-api:8080/x' -> ('orders-api', 8080)
    'redis://:pw@cache:6379'   -> ('cache', 6379)
    'orders-db:5432'           -> ('orders-db', 5432)
    """
    v = SCHEME_RE.sub("", val.strip().lower())
    m = HOST_RE.match(v)
    if not m:
        return None, None
    port = int(m.group(2)) if m.group(2) and m.group(2).isdigit() else None
    return m.group(1), port


def _resolve_host(host: str, caller: Workload, svc_index: dict) -> Optional[Service]:
    """DNS name (short or FQDN) -> the Service object it addresses, if in-cluster."""
    host = host.strip().lower()
    host = host.removesuffix(CLUSTER_SUFFIX)
    parts = host.split(".")
    short = parts[0]
    ns = parts[1] if len(parts) > 1 else caller.ns
    return svc_index.get((ns, short)) or svc_index.get((caller.ns, short))


def _looks_external(host: str) -> bool:
    h = host.strip().lower()
    if h.endswith(CLUSTER_SUFFIX):
        return False
    # a public-looking FQDN (has a dot and a TLD-ish tail) with no cluster suffix
    return "." in h and not h.replace(".", "").isdigit() and not h.endswith(".local")


def _safe_evidence(name: str, host: str, port) -> str:
    """Evidence for an S1 edge, WITHOUT echoing the raw env value.

    The S1 signal is only the endpoint (host[:port]) — the raw value can contain
    inline credentials (``DATABASE_URL=postgres://user:pass@host/db``), which must
    not be persisted into logs or --json output. So we record the parsed endpoint
    and the env var name only.
    """
    ep = f"{host}:{port}" if port else host
    return f"{name}={ep}"


# ---------------------------------------------------------------- S1
def s1_env_endpoints(inv: Inventory, svc_index: dict) -> list:
    edges = []
    for w in inv.workloads:
        for name, val in w.env:
            if not ENDPOINT_RE.search(name):
                continue
            host, p = _parse_endpoint(val)
            if not host:
                continue
            svc = _resolve_host(host, w, svc_index)
            if svc is not None:
                if svc.kind == "ExternalName":
                    edges.append(Edge(w.id, "world", p, EdgeClass.EGRESS,
                                      Provenance.S1_ENV_ENDPOINT, evidence=_safe_evidence(name, host, p)))
                    continue
                port_final = p or (svc.ports[0][0] if svc.ports else None)
                for tgt in inv.workloads_backing(svc):
                    if tgt.id != w.id:
                        edges.append(Edge(w.id, tgt.id, port_final, EdgeClass.IN_CLUSTER,
                                          Provenance.S1_ENV_ENDPOINT,
                                          evidence=_safe_evidence(name, host, port_final)))
            elif _looks_external(host):
                edges.append(Edge(w.id, "world", p, EdgeClass.EGRESS,
                                  Provenance.S1_ENV_ENDPOINT, evidence=_safe_evidence(name, host, p)))
    return edges


# ---------------------------------------------------------------- S3
def s3_ingress(inv: Inventory, svc_index: dict) -> list:
    edges = []
    for ing in inv.ingresses:
        ns = ing.get("metadata", {}).get("namespace", "default")
        name = ing.get("metadata", {}).get("name", "?")
        for rule in (ing.get("spec", {}).get("rules") or []):
            for path in ((rule.get("http") or {}).get("paths") or []):
                b = ((path.get("backend") or {}).get("service") or {})
                svc = svc_index.get((ns, b.get("name")))
                port = ((b.get("port") or {}).get("number"))
                if svc is None:
                    continue
                for tgt in inv.workloads_backing(svc):
                    edges.append(Edge("ingress-controller", tgt.id, port, EdgeClass.ENTRY,
                                      Provenance.S3_INGRESS, evidence=f"ingress/{name}"))
    return edges


# ---------------------------------------------------------------- S4
def s4_dns(inv: Inventory) -> list:
    """Every workload resolves DNS. Universal, but rarely written into a policy —
    a classic silent enforcement break (DNS deny -> everything times out)."""
    return [Edge(w.id, "kube-dns", 53, EdgeClass.IN_CLUSTER, Provenance.S4_DNS,
                 evidence="cluster DNS invariant")
            for w in inv.workloads if not w.host_network]


# ---------------------------------------------------------------- S5
def s5_apiserver(inv: Inventory) -> list:
    """A ServiceAccount bound to any Role/ClusterRole implies its workloads talk to
    the kube-apiserver. The apiserver edge is almost never in a NetworkPolicy."""
    bound = set()
    for rb in inv.rolebindings:
        rb_ns = rb.get("metadata", {}).get("namespace")
        for sub in (rb.get("subjects") or []):
            if sub.get("kind") == "ServiceAccount":
                bound.add((sub.get("namespace") or rb_ns, sub.get("name")))
    edges = []
    for w in inv.workloads:
        if (w.ns, w.service_account) in bound:
            edges.append(Edge(w.id, "kube-apiserver", 443, EdgeClass.IN_CLUSTER,
                              Provenance.S5_APISERVER, evidence=f"sa={w.service_account}"))
    return edges


# ---------------------------------------------------------------- S6
def s6_peers(inv: Inventory) -> list:
    """Pods behind a headless Service peer with each other (StatefulSet clustering:
    etcd, postgres replicas, NATS). These intra-set edges are invisible to an
    ingress-only observer that only sees client traffic.

    A StatefulSet's pods peer with each other (etcd, kafka, rabbitmq, postgres
    replicas). At workload-identity granularity that intra-set peering is a SELF-edge
    ``X -> X`` on the cluster port — which a NetworkPolicy expresses as "podSelector X,
    ingress from podSelector X". So for a StatefulSet behind a headless Service we emit
    that self-edge (it is real and checkable), and for multiple distinct workloads
    behind one headless Service we emit the cross edges too. A *non*-StatefulSet
    self-loop is not a clustering relationship and is skipped."""
    edges = []
    for svc in inv.services:
        if svc.kind != "Headless":
            continue
        peers = inv.workloads_backing(svc)
        ports = [p for p, _ in svc.ports] or [None]
        for a in peers:
            for b in peers:
                if a.id == b.id and a.kind != "statefulset":
                    continue                           # only StatefulSets peer with own replicas
                for port in ports:
                    edges.append(Edge(a.id, b.id, port, EdgeClass.PEER,
                                      Provenance.S6_PEER, evidence=f"headless/{svc.name}"))
    return edges


# ---------------------------------------------------------------- union
def derive_needed(inv: Inventory) -> list:
    """Union of all sources, de-duplicated on (src, dst, port). When two sources
    justify the same edge, the more direct provenance and its evidence win."""
    svc_index = inv.service_index()
    raw = (s1_env_endpoints(inv, svc_index)
           + s3_ingress(inv, svc_index)
           + s4_dns(inv)
           + s5_apiserver(inv)
           + s6_peers(inv))
    best: dict = {}
    for e in raw:
        k = e.key()
        if k not in best:
            best[k] = e
    return list(best.values())
