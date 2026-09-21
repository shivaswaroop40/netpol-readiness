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


def fmt_port(p) -> str:
    """Render a port key: number, ``lo-hi`` for an endPort range, the value as-is
    otherwise (``None`` prints as the wildcard it is)."""
    if isinstance(p, tuple):
        return f"{p[0]}-{p[1]}"
    return str(p)


def admits(target: Key, admit: set, *, target_is_need: bool = False) -> bool:
    """Does the admit-set permit ``target``?

    An admit edge with ``port=None`` (a policy rule with no ``ports``) permits any
    port on the pair; an exact ``(s,d,p)`` match permits that port.

    A port on either side may also be an ``(start, end)`` tuple — an ``endPort``
    range from a policy rule. An admit range permits every port it covers; a
    range *target* (an admitted range checked for use against needs) counts as
    admitted when any covered port is.

    The tricky case is a *target* whose port is unknown (``None``). Direction matters:
      * for an ATTACK (default), be pessimistic about security — treat the attack as
        admitted if ANY port on the pair is admitted (``target_is_need=False``);
      * for a NEED (``target_is_need=True``), be pessimistic about breakage — a
        port-unknown dependency is only satisfied by an ALL-PORTS admit, never by a
        single wrong-port admit. Otherwise a need for ``a->b:?`` would be wrongly
        cleared by a policy that only admits ``a->b:443``, flipping SHADOW->ENFORCE
        on traffic that would actually be denied (a false "safe to enforce").
    """
    s, d, p = target
    if (s, d, p) in admit:
        return True
    if (s, d, None) in admit:           # policy admits all ports on the pair
        return True
    if p is not None:
        for a, b, ap in admit:
            if a != s or b != d:
                continue
            if isinstance(p, tuple):    # range target: any overlap admits
                lo, hi = p
                if (isinstance(ap, int) and lo <= ap <= hi) or \
                        (isinstance(ap, tuple) and ap[0] <= hi and lo <= ap[1]):
                    return True
            elif isinstance(ap, tuple) and ap[0] <= p <= ap[1]:
                return True
        return False
    if not target_is_need:
        return any(a[0] == s and a[1] == d for a in admit)   # optimistic (attacks only)
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

    admitted_attacks = [a for a in Ak if _admits(a, admit)]                       # attack: optimistic
    missed_legit = [x for x in Lk if not _admits(x, admit, target_is_need=True)]  # need: conservative

    over_priv = len(admitted_attacks) / len(Ak) if Ak else 0.0
    false_deny = len(missed_legit) / len(Lk) if Lk else 0.0

    out = {
        "admit_edges": len(admit),
        "block_rate": round(1.0 - over_priv, 6),
        "over_privilege": round(over_priv, 6),
        "false_deny": round(false_deny, 6),
        "admitted_attacks": sorted(f"{s}->{d}:{fmt_port(p)}" for s, d, p in admitted_attacks),
        "missed_legit": sorted(f"{s}->{d}:{fmt_port(p)}" for s, d, p in missed_legit),
    }
    if L_inscope is not None:
        Lin = _keyset(L_inscope)
        missed_in = [x for x in Lin if not _admits(x, admit, target_is_need=True)]
        out["false_deny_inscope"] = round(len(missed_in) / len(Lin), 6) if Lin else 0.0
    return out


def fuse(declared: Iterable, observed: Iterable, L: Iterable, A: Iterable) -> dict:
    """Coverage-by-source and the fusion measurement (the thesis C5 result).

    Neither configuration nor observation is safe to rely on alone, and which one
    wins is not knowable in advance: on an app that *declares* its dependencies
    config reaches edges no observation window fires; on one that hard-codes them
    observation is the only source. The resolution is to take the union and never
    to choose. This scores all three sources against the same observation-independent
    ground truth ``L`` (and attack set ``A``):

      config_only : the config-derived (declared) edges alone
      observed    : the observer's edges alone
      fused       : their union — what a policy built from both would admit

    The safety argument is checked, not assumed: ``declared ∩ A`` must be empty, so
    adding config-declared edges to an observation-only policy can never admit an
    attack (fusion costs nothing on the security axis). This is verified at port
    granularity, where it holds exactly; at identity-pair granularity a single
    ``src->dst`` may legitimately need one port while an attack targets another, so
    the intersection there is an artifact of dropping the port, not of fusion.
    """
    dk = _keyset(declared)
    ok = _keyset(observed)
    Ak = _keyset(A)
    fused = dk | ok

    config_only = score(dk, L, A)
    observed_s = score(ok, L, A)
    fused_s = score(fused, L, A)

    declared_attacks = sorted(f"{s}->{d}:{fmt_port(p)}" for (s, d, p) in (dk & Ak))
    return {
        "config_only": config_only,
        "observed": observed_s,
        "fused": fused_s,
        "coverage": {
            "config_only": round(1.0 - config_only["false_deny"], 6),
            "observed": round(1.0 - observed_s["false_deny"], 6),
            "fused": round(1.0 - fused_s["false_deny"], 6),
        },
        "fused_coverage_gain_over_observed": round(
            observed_s["false_deny"] - fused_s["false_deny"], 6),
        "fused_over_privilege_delta": round(
            fused_s["over_privilege"] - observed_s["over_privilege"], 6),
        "declared_intersect_attacks": {
            "edges": declared_attacks,
            "count": len(declared_attacks),
            "safe": len(declared_attacks) == 0,
            "note": "must be empty: config-declared edges name no attack path, "
                    "so fusion cannot raise over-privilege",
        },
    }


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

    denied = [x for x in Lk if not _admits(x, admit, target_is_need=True)]
    never_observed = [x for x in denied if not _admits(x, Ok, target_is_need=True)]
    observed_but_denied = [x for x in denied if _admits(x, Ok, target_is_need=True)]

    n = len(Lk) or 1
    return {
        "false_deny": round(len(denied) / n, 6),
        "coverage_component": round(len(never_observed) / n, 6),
        "tool_penalty": round(len(observed_but_denied) / n, 6),
        "never_observed": sorted(f"{s}->{d}:{fmt_port(p)}" for s, d, p in never_observed),
        "observed_but_denied": sorted(f"{s}->{d}:{fmt_port(p)}"
                                      for s, d, p in observed_but_denied),
    }
