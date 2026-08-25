"""Config-derived dependency graph: the NEEDED edges.

This is the half that observation cannot produce. Each source turns a piece of
declared configuration into reachability edges, every edge carrying its provenance
and the literal evidence that justified it. The union across sources is the set of
edges the application *declares* it needs — including the rare ones that fire on
events a benign observation window never triggers.

Design principle — VERIFY, don't guess.

A dependency exists when a workload's configuration contains a value that RESOLVES to
a Service that actually exists in this cluster. We do not guess from naming
conventions: we tokenise every configuration surface and resolve each candidate
against the live Service catalog. That makes derivation self-configuring per cluster
and independent of language, framework, or variable-naming style. (An early version
only fired on env names matching ``_HOST|_URL|_ADDR|...`` — it missed real
dependencies like ``mongo=user-db:27017`` purely because of how the variable was
named.) The name pattern survives only as a *confidence signal*, never as a filter.

Sources (each independent, each auditable):
  S1  config-surface endpoints      any env/ConfigMap/argv value that resolves to a
                                    Service in the catalog -> caller -> backend
  S3  Ingress / Gateway routes      ingress backend service          -> ingress -> backend
  S4  cluster DNS invariant         every pod resolves names         -> workload -> <dns svc>:53
  S5  RBAC bindings                 ServiceAccount bound to a role   -> workload -> kube-apiserver
  S6  headless Service peers        StatefulSet behind headless svc  -> peer <-> peer

S2 (the Service catalog) is not a separate emitter — it is the resolver that makes
S1 and S3 verification rather than guesswork.
"""
from __future__ import annotations

import re
from typing import Optional

from .inventory import Inventory, Service, Workload
from .model import Edge, EdgeClass, Provenance

# A *confidence signal* only — never a filter. A variable named this way that also
# resolves is near-certain; one named anything else that resolves is still a real edge.
ENDPOINT_RE = re.compile(
    r"(_HOST|_HOSTNAME|_URL|_URI|_ENDPOINT|_ADDR|_ADDRESS|_SERVER|_BROKER|_BROKERS|_DSN)$")
# Values often carry several endpoints (broker lists, comma/space separated).
TOKEN_SPLIT_RE = re.compile(r"[\s,;|]+")
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
    """DNS name -> the Service it addresses, if in-cluster.

    Handles the three in-cluster forms, resolving against the catalog rather than
    assuming a shape:
      ``svc``                          short name in the caller's namespace
      ``svc.ns`` / ``svc.ns.svc...``   namespace-qualified
      ``pod-0.svc`` / ``pod-0.svc.ns`` StatefulSet pod-qualified (headless), where the
                                       FIRST label is a pod, not the Service
    """
    host = host.strip().lower()
    host = host.removesuffix(CLUSTER_SUFFIX)
    parts = [p for p in host.split(".") if p]
    if not parts:
        return None
    # try each label as the Service name, with the next label as its namespace.
    # this covers svc, svc.ns and pod-0.svc / pod-0.svc.ns without special-casing.
    for i, label in enumerate(parts):
        ns = parts[i + 1] if i + 1 < len(parts) else caller.ns
        hit = svc_index.get((ns, label)) or svc_index.get((caller.ns, label))
        if hit is not None:
            return hit
    return None


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
def _candidates(val: str) -> list:
    """Endpoint candidates inside one configuration value.

    A value can be a bare endpoint, a list of them, or carry an assignment prefix
    (``--broker=queue:5672``, ``spring.redis.host=cache``). We yield the token and,
    when present, the part after the last ``=`` — so flag- and property-style config
    is covered without knowing the flag vocabulary.
    """
    out = []
    for token in TOKEN_SPLIT_RE.split(val or ""):
        if not token or len(token) > 253:
            continue
        out.append(token)
        if "=" in token:
            tail = token.rsplit("=", 1)[1]
            if tail:
                out.append(tail)
    return out


def _config_surfaces(w: Workload, configmaps: dict) -> list:
    """Every place a workload can declare an endpoint, as (origin, key, value).

    We scan *all* of them rather than a curated subset, because which surface a team
    uses is a convention we must not assume: env values, the ConfigMaps the workload
    mounts/references, and the container command line.
    """
    out = [("env", k, v) for k, v in w.env]
    for cm in sorted(w.configmap_refs):
        for k, v in (configmaps.get((w.ns, cm)) or {}).items():
            out.append((f"configmap/{cm}", k, str(v)))
    if w.argv:
        out.append(("argv", "command", w.argv))
    return out


def s1_env_endpoints(inv: Inventory, svc_index: dict) -> list:
    """Resolve every configuration value against the Service catalog.

    An edge is emitted only when a parsed host token EXACTLY matches a Service that
    exists in this cluster (or is a clearly external FQDN). Exact-match resolution is
    what keeps this general without becoming noisy: ``MYSQL_DATABASE=socksdb`` resolves
    to nothing and is silently ignored, while ``mongo=user-db:27017`` resolves to the
    real ``user-db`` Service and becomes an edge — despite the variable's name.
    """
    configmaps = getattr(inv, "configmaps", {}) or {}
    edges = []
    for w in inv.workloads:
        for origin, key, val in _config_surfaces(w, configmaps):
            named_like_endpoint = bool(ENDPOINT_RE.search(key))
            for token in _candidates(val):
                host, p = _parse_endpoint(token)
                if not host:
                    continue
                svc = _resolve_host(host, w, svc_index)
                # confidence: the value resolved either way; a conventional variable
                # name is corroborating evidence, not a precondition.
                conf = 1.0 if named_like_endpoint else 0.75
                ev = _safe_evidence(f"{origin}:{key}", host, p)
                if svc is not None:
                    if svc.kind == "ExternalName":
                        edges.append(Edge(w.id, "world", p, EdgeClass.EGRESS,
                                          Provenance.S1_ENV_ENDPOINT, conf, ev))
                        continue
                    port_final = p or (svc.ports[0][0] if svc.ports else None)
                    for tgt in inv.workloads_backing(svc):
                        if tgt.id != w.id:
                            edges.append(Edge(w.id, tgt.id, port_final, EdgeClass.IN_CLUSTER,
                                              Provenance.S1_ENV_ENDPOINT, conf,
                                              _safe_evidence(f"{origin}:{key}", host, port_final)))
                elif named_like_endpoint and _looks_external(host):
                    # only trust an *unresolvable* host as egress when the variable is
                    # conventionally named — otherwise arbitrary text becomes "world".
                    edges.append(Edge(w.id, "world", p, EdgeClass.EGRESS,
                                      Provenance.S1_ENV_ENDPOINT, conf, ev))
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
