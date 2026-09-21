"""npready — enforcement-readiness analysis for Kubernetes NetworkPolicies.

Public API:
    Inventory                 load cluster/manifest inputs (read-only)
    derive_needed             config-derived dependency graph (the NEEDED edges)
    derive_admitted           edges permitted by existing NetworkPolicy objects
    reconcile / verdict       four-quadrant reconciliation + audit/shadow/enforce
    score / decompose_false_deny   evaluate a generated policy on the safe-to-enforce axis
"""
from .graph import derive_needed
from .inventory import Inventory, Service, Workload
from .model import Edge, EdgeClass, Provenance, Quadrant, ReconcileResult
from .policy import derive_admitted
from .reconcile import Gate, ReadinessVerdict, reconcile, verdict
from .score import decompose_false_deny, score

__version__ = "0.3.0"
__all__ = [
    "Edge",
    "EdgeClass",
    "Gate",
    "Inventory",
    "Provenance",
    "Quadrant",
    "ReadinessVerdict",
    "ReconcileResult",
    "Service",
    "Workload",
    "decompose_false_deny",
    "derive_admitted",
    "derive_needed",
    "reconcile",
    "score",
    "verdict",
]
