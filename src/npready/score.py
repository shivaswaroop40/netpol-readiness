"""Enforcement-readiness scoring for a generated policy — the evaluation framework.

Given what a policy *admits*, a legitimate-edge universe ``L`` and an attack-edge
universe ``A`` (with ``L`` and ``A`` disjoint), we report the two axes that decide
deployment, plus a decomposition that says *why* a tool false-denies:

  over_privilege = |A admitted| / |A|      risk: attacks the policy lets through
  block_rate     = 1 - over_privilege       the security axis (usually saturated)
  false_deny     = |L denied| / |L|         cost: legitimate traffic it would break

  decomposition of false_deny (needs the observed universe O):
    coverage    = |L never observed| / |L|   edges no observer could have caught
    tool_penalty= |L observed but denied|/|L| edges seen but the mechanism can't encode

This is orthogonal to CNI-conformance suites (cyclonus, the upstream e2e tests):
those check whether the CNI enforces a policy as written; this checks whether the
*generated policy is the right policy* — safe to enforce for a real workload.

Everything is set arithmetic over (src, dst, port) keys. A key with ``port=None``
is a wildcard: a port-blind observer admits every port on a pair, which is exactly
how such tools hide over-privilege — so we make that explicit rather than hiding it.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Optional

Key = tuple            # (src, dst, port|None)


def _as_key(e) -> Key:
    """Accept an Edge, a 3-tuple, or a 2-tuple; normalise to (src, dst, port)."""
    if hasattr(e, "src"):
        return (e.src, e.dst, getattr(e, "port", None))
    if len(e) == 3:
        return (e[0], e[1], e[2])
    return (e[0], e[1], None)


def _keyset(edges: Iterable) -> set:
    return {_as_key(e) for e in edges}


def admits(target: Key, admit: set) -> bool:
    """Does the admit-set permit ``target``? A wildcard (port=None) admit edge on
    the same pair permits any port; an exact match permits that port. Shared by the
    scorer and the reconciler so both treat a no-ports policy rule identically."""
    s, d, p = target
    if (s, d, p) in admit:
        return True
    if (s, d, None) in admit:           # admit-side wildcard covers any port
        return True
    if p is None:                       # target is port-blind: any admit on the pair
        return any(a[0] == s and a[1] == d for a in admit)
    return False


_admits = admits                        # internal alias (back-compat within module)


def score(admitted: Iterable, L: Iterable, A: Iterable,
          L_inscope: Optional[Iterable] = None) -> dict:
    """Score one generated policy against ground truth.

    Returns block_rate, over_privilege, false_deny (+ an in-scope variant that
    excludes edges a NetworkPolicy structurally cannot express, e.g. egress/DNS
    when only ingress policy is in play), and the concrete offending edge lists.
    """
    admit = _keyset(admitted)
    Lk = _keyset(L)
    Ak = _keyset(A)

    admitted_attacks = [a for a in Ak if _admits(a, admit)]
    missed_legit = [x for x in Lk if not _admits(x, admit)]

    over_priv = len(admitted_attacks) / len(Ak) if Ak else 0.0
    false_deny = len(missed_legit) / len(Lk) if Lk else 0.0

    out = {
        "admit_edges": len(admit),
        "block_rate": round(1.0 - over_priv, 6),
        "over_privilege": round(over_priv, 6),
        "false_deny": round(false_deny, 6),
        "admitted_attacks": sorted(f"{s}->{d}:{p}" for s, d, p in admitted_attacks),
        "missed_legit": sorted(f"{s}->{d}:{p}" for s, d, p in missed_legit),
    }
    if L_inscope is not None:
        Lin = _keyset(L_inscope)
        missed_in = [x for x in Lin if not _admits(x, admit)]
        out["false_deny_inscope"] = round(len(missed_in) / len(Lin), 6) if Lin else 0.0
    return out


def decompose_false_deny(admitted: Iterable, L: Iterable, observed: Iterable) -> dict:
    """Split false-deny into the part no observer could fix (coverage) and the part
    a better mechanism could fix (tool_penalty).

    coverage     : legitimate edges that were never observed at all — the
                   observation ceiling; more watching does not help.
    tool_penalty : legitimate edges that WERE observed but the policy still denies —
                   the mechanism could not represent them (e.g. connection-tracing
                   missing a long-lived pool).
    """
    admit = _keyset(admitted)
    Lk = _keyset(L)
    Ok = _keyset(observed)

    denied = [x for x in Lk if not _admits(x, admit)]
    never_observed = [x for x in denied if not _admits(x, Ok)]
    observed_but_denied = [x for x in denied if _admits(x, Ok)]

    n = len(Lk) or 1
    return {
        "false_deny": round(len(denied) / n, 6),
        "coverage_component": round(len(never_observed) / n, 6),
        "tool_penalty": round(len(observed_but_denied) / n, 6),
        "never_observed": sorted(f"{s}->{d}:{p}" for s, d, p in never_observed),
        "observed_but_denied": sorted(f"{s}->{d}:{p}" for s, d, p in observed_but_denied),
    }
