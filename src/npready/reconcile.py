"""Reconcile needed vs admitted into the four quadrants, and turn that into an
enforcement-readiness verdict.

This is the analysis no existing scanner performs. Over-privilege scanners see the
``unused`` quadrant; observational audit modes (Cilium ``--policy-audit-mode``,
Calico StagedNetworkPolicy) can see traffic that *did* happen. Neither sees
``missing`` — an edge the application declares it needs that no policy admits, and
that may never appear in a benign observation window. ``missing`` is what breaks
production the moment enforcement is turned on.
"""
from __future__ import annotations

from dataclasses import dataclass

from .model import Edge, EdgeClass, ReconcileResult
from .score import admits

# Destinations a v1 NetworkPolicy *ingress* section cannot govern: cluster infra and
# the outside world. Needing these edges does not mean an ingress policy would break
# on enforce, so they are reported separately rather than counted as "missing".
SYNTHETIC_DSTS = {"kube-dns", "kube-apiserver", "world", "node"}


def _in_scope(edge: Edge) -> bool:
    """True if this needed edge is checkable against an ingress NetworkPolicy: a
    real in-cluster-workload source reaching a real in-cluster-workload destination.

    Out of scope (reported separately, never counted as 'would break'):
      * synthetic infra destinations (kube-dns, kube-apiserver, world, node)
      * egress / hostNetwork-excluded edges (need egress policy / not expressible)
      * ENTRY edges (external -> pod via Ingress/Gateway). Their source is the
        synthetic token "ingress-controller", which never equals a real workload id,
        so we cannot yet match them against admitted edges without resolving the
        ingress controller's actual identity. Reporting them as 'missing' would be a
        false SHADOW on every cluster that has an Ingress; resolving the controller
        identity is roadmap (see docs/ROADMAP.md)."""
    if edge.dst in SYNTHETIC_DSTS:
        return False
    return edge.edge_class in (EdgeClass.IN_CLUSTER, EdgeClass.PEER)


def reconcile(needed, admitted, total_workloads=0, protected=None) -> ReconcileResult:
    """Reconcile needed vs admitted with port-wildcard-aware matching.

    A policy rule with no ``ports`` admits every port on the pair (port=None on the
    admit side), so we match through :func:`score.admits` rather than exact tuples —
    admitting ``a->b`` (all ports) satisfies a need for ``a->b:5432``. We still keep
    port granularity where the policy is specific, so ``a->b:443`` does NOT satisfy a
    need for ``a->b:5432``.

    Needed edges an ingress policy cannot express (egress, DNS, apiserver, world) are
    split into ``out_of_scope`` instead of being counted as ``missing``.
    """
    adm_keys = {e.key() for e in admitted}
    need_keys = {e.key() for e in needed}

    correct, missing, out_of_scope = [], [], []
    for e in needed:
        if not _in_scope(e):
            out_of_scope.append(e)
        elif admits(e.key(), adm_keys, target_is_need=True):   # conservative: a port-unknown
            correct.append(e)                                   # need needs an all-ports admit
        else:
            missing.append(e)

    # unused = admitted edges that satisfy no need. Optimistic here on purpose: do NOT
    # over-flag an admit as removable when a port-unknown need on the pair might use it.
    unused = [e for e in admitted if not admits(e.key(), need_keys)]

    return ReconcileResult(
        correct=correct,
        unused=unused,
        missing=missing,
        out_of_scope=out_of_scope,
        protected_workloads=set(protected or []),
        total_workloads=total_workloads,
    )


class Gate(str):
    """Recommended enforcement stage for a scope."""
    AUDIT = "audit"        # too many unknowns / unprotected — observe first
    SHADOW = "shadow"      # would break: fix the missing edges before enforcing
    ENFORCE = "enforce"    # no missing edges — safe to turn on


@dataclass
class ReadinessVerdict:
    scope: str
    gate: str
    readiness_score: float          # 0..1, higher = safer to enforce
    would_break: list               # list[Edge] — the in-scope missing edges
    over_privilege: list            # list[Edge] — the unused edges
    out_of_scope: list              # list[Edge] — egress/infra deps a policy can't express
    protected_fraction: float
    rationale: str

    def to_dict(self) -> dict:
        return {
            "scope": self.scope,
            "gate": self.gate,
            "readiness_score": round(self.readiness_score, 3),
            "protected_fraction": round(self.protected_fraction, 3),
            "would_break_count": len(self.would_break),
            "over_privilege_count": len(self.over_privilege),
            "out_of_scope_count": len(self.out_of_scope),
            "would_break": [_edge_dict(e) for e in self.would_break],
            "over_privilege": [_edge_dict(e) for e in self.over_privilege],
            "out_of_scope": [_edge_dict(e) for e in self.out_of_scope],
            "rationale": self.rationale,
        }


def _edge_dict(e: Edge) -> dict:
    return {"src": e.src, "dst": e.dst, "port": e.port,
            "class": e.edge_class.value, "provenance": e.provenance.value,
            "evidence": e.evidence}


def verdict(result: ReconcileResult, scope: str = "cluster") -> ReadinessVerdict:
    """Turn a reconciliation into an audit/shadow/enforce recommendation.

    The gate is decided by the two failure modes, in priority order:
      1. any ``missing`` edge  -> SHADOW  (enforcing now would break the app)
      2. low protected fraction -> AUDIT  (most workloads are default-allow; there
                                           is not yet enough policy to enforce)
      3. otherwise              -> ENFORCE (needed edges are admitted; turn it on)

    readiness_score is the fraction of needed edges that are admitted, which is
    exactly ``1 - false_deny`` measured against the config-derived need set.
    """
    needed_total = len(result.correct) + len(result.missing)
    readiness = (len(result.correct) / needed_total) if needed_total else 1.0
    protected_fraction = (
        len(result.protected_workloads) / result.total_workloads
        if result.total_workloads else 0.0
    )

    if result.missing:
        gate = Gate.SHADOW
        rationale = (f"{len(result.missing)} declared dependency edge(s) are not admitted by any "
                     f"policy; enforcing now would deny legitimate traffic. Add them, then re-check.")
    elif protected_fraction < 0.5:
        gate = Gate.AUDIT
        rationale = (f"only {protected_fraction:.0%} of workloads are selected by an ingress policy; "
                     f"most are still default-allow. Observe and write policy before enforcing.")
    else:
        gate = Gate.ENFORCE
        rationale = ("every config-derived dependency is admitted and most workloads are covered; "
                     "safe to enforce.")

    return ReadinessVerdict(
        scope=scope,
        gate=gate,
        readiness_score=readiness,
        would_break=result.missing,
        over_privilege=result.unused,
        out_of_scope=result.out_of_scope,
        protected_fraction=protected_fraction,
        rationale=rationale,
    )
