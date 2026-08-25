"""Core data model shared across npready.

The whole tool speaks one vocabulary: a directed *edge* between two workload
identities on a port, tagged with where the claim came from (provenance) and how
much we trust it (confidence). Every stage — config derivation, policy parsing,
reconciliation, scoring — reads and writes this vocabulary, so a generator, a
NetworkPolicy, and an attack are all comparable on the same footing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# A workload identity. We use "namespace/name" strings rather than pod IPs so the
# model survives pod churn (the whole point of identity-based policy). Synthetic
# identities that are not workloads — the internet, the apiserver, a node — use a
# bare token ("world", "kube-apiserver", "node") by convention.
Identity = str


class EdgeClass(str, Enum):
    """Where an edge sits relative to the cluster boundary. This decides how a
    NetworkPolicy must express it, and therefore whether observation alone can
    ever produce a correct policy for it."""

    IN_CLUSTER = "in_cluster"      # pod -> pod / pod -> in-cluster service
    ENTRY = "entry"                # external -> pod (Ingress, Gateway, LB, NodePort)
    PEER = "peer"                  # headless/StatefulSet pod <-> pod
    EGRESS = "egress"              # pod -> outside the cluster (ExternalName, world)
    EXCLUDED = "excluded"          # hostNetwork / not expressible by NetworkPolicy


class Provenance(str, Enum):
    """How an edge became known. Ordered loosely by directness of evidence."""

    OBSERVED = "observed"          # seen in real traffic (flow log / socket)
    S1_ENV_ENDPOINT = "s1_env"     # workload env var naming a peer (twelve-factor)
    S2_SERVICE = "s2_service"      # Service selector -> backing workload
    S3_INGRESS = "s3_ingress"      # Ingress/Gateway route -> backend
    S4_DNS = "s4_dns"              # cluster DNS invariant (every pod -> kube-dns)
    S5_APISERVER = "s5_apiserver"  # RBAC binding -> workload uses kube-apiserver
    S6_PEER = "s6_peer"            # headless Service / StatefulSet peer set
    POLICY = "policy"              # admitted by an existing NetworkPolicy
    ATTACK = "attack"              # an adversarial edge (ground-truth A)


class Quadrant(str, Enum):
    """The reconciliation verdict for one edge — the heart of the readiness model.

    Rows = admitted by policy?  Columns = needed by the app?
                    needed              not needed
        admitted    CORRECT             UNUSED (over-privilege; safe to remove)
        denied      MISSING             DENIED (correctly blocked; attacks land here)
                    (would break on
                     enforce!)
    """

    CORRECT = "correct"    # admitted AND needed
    UNUSED = "unused"      # admitted, NOT needed  -> over-privilege
    MISSING = "missing"    # needed, NOT admitted  -> would break on enforce
    DENIED = "denied"      # not admitted, not needed -> correctly denied


@dataclass(frozen=True)
class Edge:
    """A directed reachability claim.

    port is Optional: ``None`` means "any port" (a port-blind observer such as an
    identity mapper produces these; a port-aware one does not). Two edges that
    differ only in port are distinct — port granularity is load-bearing, because
    an SSRF to :80 and a legitimate egress to :443 collapse together if port is
    dropped, which is exactly how port-blind tools hide over-privilege.
    """

    src: Identity
    dst: Identity
    port: Optional[int] = None
    edge_class: EdgeClass = EdgeClass.IN_CLUSTER
    provenance: Provenance = Provenance.OBSERVED
    confidence: float = 1.0
    evidence: str = ""             # human-readable justification, e.g. "REDIS_ADDR=..."

    def key(self) -> EdgeKey:
        """Identity-pair-plus-port key used for set arithmetic across stages."""
        return (self.src, self.dst, self.port)

    def pair(self) -> PairKey:
        """Identity-pair-only key (port dropped). Use only when deliberately
        comparing at identity granularity; prefer key()."""
        return (self.src, self.dst)


# Set-arithmetic keys. Kept as plain tuples so edges from different stages (with
# different provenance/confidence) compare equal when they describe the same reach.
EdgeKey = tuple            # (src, dst, port)
PairKey = tuple            # (src, dst)


@dataclass
class ReconcileResult:
    """Output of reconciling needed vs admitted edges for a scope."""

    correct: list = field(default_factory=list)   # list[Edge] (needed side)
    unused: list = field(default_factory=list)     # list[Edge] (admitted side)
    missing: list = field(default_factory=list)    # list[Edge] (needed side, in-scope)
    out_of_scope: list = field(default_factory=list)  # needed edges an ingress policy can't express
    protected_workloads: set = field(default_factory=set)
    total_workloads: int = 0

    @property
    def counts(self) -> dict:
        return {
            "correct": len(self.correct),
            "unused": len(self.unused),
            "missing": len(self.missing),
            "out_of_scope": len(self.out_of_scope),
            "protected_workloads": len(self.protected_workloads),
            "total_workloads": self.total_workloads,
        }
