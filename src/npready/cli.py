"""npready command-line interface.

    npready derive      config-derived dependency graph (NEEDED edges)
    npready readiness   needed vs admitted -> quadrants -> audit/shadow/enforce
    npready score       evaluate a generated policy against ground truth
    npready fuse        coverage by source: config vs observation vs their union
    npready attacks     print the ATT&CK-mapped attack roster (deployed via Helm)

All read paths are offline-capable: pass --manifests DIR to analyse without a
cluster, or --context CTX to read a live cluster (read-only kubectl get).
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .graph import derive_needed
from .inventory import Inventory
from .policy import derive_admitted
from .reconcile import reconcile, verdict
from .score import decompose_false_deny, fmt_port, fuse, score


def _load_inventory(args) -> Inventory:
    if args.manifests or args.snapshot:
        if args.manifests:
            inv = Inventory.from_manifests(args.manifests)
        else:
            inv = Inventory.from_dict(json.load(open(args.snapshot)))
        # offline sources are loaded whole; honour --namespace by filtering,
        # so the scope printed on the report is the scope actually analysed.
        return inv.restrict(args.namespace) if args.namespace else inv
    return Inventory.from_cluster(context=args.context, namespace=args.namespace)


def _p(port) -> str:
    return "*" if port is None else fmt_port(port)


def _edges(path) -> list:
    """Load a JSON list of ``[src, dst, port]`` (or ``[src, dst]``) edges as tuples."""
    return [tuple(x) for x in json.load(open(path))]


def _project(edges, granularity: str) -> list:
    """At ``pair`` granularity drop the port, so an edge is (src, dst) — the coarser
    view used for cross-tool comparison, where any port on a pair counts. ``port``
    (the default) keeps full (src, dst, port) resolution."""
    if granularity == "pair":
        return [(e[0], e[1], None) for e in edges]
    return list(edges)


def _add_source_args(p):
    src = p.add_mutually_exclusive_group()
    src.add_argument("--context", help="kube-context to read (live, read-only)")
    src.add_argument("--manifests", help="directory or file of YAML manifests to analyse offline")
    src.add_argument("--snapshot", help="a JSON inventory snapshot ({kind: [objects]})")
    p.add_argument("--namespace", help="restrict to one namespace")
    p.add_argument("--json", metavar="FILE", help="also write machine-readable JSON here")


# ------------------------------------------------------------------ derive
def cmd_derive(args):
    inv = _load_inventory(args)
    needed = derive_needed(inv)
    by_prov = {}
    for e in needed:
        by_prov[e.provenance.value] = by_prov.get(e.provenance.value, 0) + 1
    print(f"config-derived NEEDED graph: {len(needed)} edges "
          f"from {len(inv.workloads)} workloads, {len(inv.services)} services")
    for k, v in sorted(by_prov.items()):
        print(f"  {k:14} {v}")
    for e in sorted(needed, key=lambda x: (x.src, x.dst))[:args.limit]:
        print(f"    {e.src:38} -> {e.dst:28} :{_p(e.port):<6} [{e.provenance.value}] {e.evidence}")
    if args.json:
        json.dump({"needed": [_ed(e) for e in needed]}, open(args.json, "w"), indent=2)
        print(f"wrote {args.json}")
    return 0


# ------------------------------------------------------------------ readiness
def cmd_readiness(args):
    inv = _load_inventory(args)
    needed = derive_needed(inv)
    admitted, protected = derive_admitted(inv)
    res = reconcile(needed, admitted, total_workloads=len(inv.workloads), protected=protected)
    v = verdict(res, scope=args.namespace or "cluster")

    print("=" * 74)
    print(f"ENFORCEMENT READINESS — {v.scope}")
    print("=" * 74)
    c = res.counts
    print(f"  correct (admitted & needed) : {c['correct']}")
    print(f"  unused  (admitted, unneeded): {c['unused']}   over-privilege — safe to remove")
    print(f"  missing (protected & unadmitted): {c['missing']}   WOULD BREAK ON ENFORCE")
    print(f"  unprotected (default-allow deps): {c['unprotected']}   flow today; write policy to segment")
    print(f"  out-of-scope (egress/DNS/api)   : {c['out_of_scope']}   need egress policy / cluster-infra")
    print(f"  workloads protected            : {c['protected_workloads']}/{c['total_workloads']}")
    print("-" * 74)
    print(f"  readiness score : {v.readiness_score:.2f}   (fraction of needs admitted)")
    print(f"  GATE            : {v.gate.upper()}")
    print(f"  {v.rationale}")
    if v.would_break:
        print("\n  WOULD BREAK ON ENFORCE (fix these first):")
        for e in sorted(v.would_break, key=lambda x: (x.src, x.dst))[:args.limit]:
            print(f"    {e.src:36} -> {e.dst:26} :{_p(e.port):<6} [{e.provenance.value}] {e.evidence}")
    if args.show_unused and v.over_privilege:
        print("\n  OVER-PRIVILEGE (safe to remove):")
        for e in sorted(v.over_privilege, key=lambda x: (x.src, x.dst))[:args.limit]:
            print(f"    {e.src:36} -> {e.dst:26} :{_p(e.port)}")
    if args.json:
        json.dump(v.to_dict(), open(args.json, "w"), indent=2)
        print(f"\nwrote {args.json}")
    return 2 if v.gate == "shadow" else 0             # non-zero exit if unsafe to enforce


# ------------------------------------------------------------------ score
def cmd_score(args):
    g = args.granularity
    admitted = _project(_edges(args.admitted), g)
    L = _project(_edges(args.legit), g)
    A = _project(_edges(args.attacks), g)
    result = score(admitted, L, A)
    result["granularity"] = "(src,dst,port)" if g == "port" else "(src,dst)"
    print(json.dumps(result, indent=2))
    if args.observed:
        dec = decompose_false_deny(admitted, L, _project(_edges(args.observed), g))
        print("\ndecomposition:")
        print(json.dumps({k: dec[k] for k in ("false_deny", "coverage_component", "tool_penalty")},
                         indent=2))
    if args.json:
        json.dump(result, open(args.json, "w"), indent=2)
    return 0


# ------------------------------------------------------------------ fuse
def cmd_fuse(args):
    """Coverage by source: config-derived vs observed vs their union (thesis C5)."""
    g = args.granularity
    L = _project(_edges(args.legit), g)
    A = _project(_edges(args.attacks), g)
    observed = _project(_edges(args.observed), g)
    if args.declared:
        declared = _project(_edges(args.declared), g)
        src = f"declared file {args.declared}"
    else:
        needed = derive_needed(_load_inventory(args))
        declared = _project([(e.src, e.dst, e.port) for e in needed], g)
        src = "config-derived (npready derive)"

    res = fuse(declared, observed, L, A)
    cov = res["coverage"]
    print("=" * 66)
    print(f"COVERAGE BY SOURCE  (granularity {'(src,dst,port)' if g == 'port' else '(src,dst)'})")
    print("=" * 66)
    print(f"  legit edges L = {len(set(L))}   attack edges A = {len(set(A))}")
    print(f"  declared from : {src}")
    print("-" * 66)
    print(f"  config alone  : {cov['config_only']:.1%} covered   "
          f"(over-priv {res['config_only']['over_privilege']:.1%})")
    print(f"  observed      : {cov['observed']:.1%} covered   "
          f"(over-priv {res['observed']['over_privilege']:.1%})")
    print(f"  FUSED (union) : {cov['fused']:.1%} covered   "
          f"(over-priv {res['fused']['over_privilege']:.1%})")
    print("-" * 66)
    print(f"  fusion gain over observed : {res['fused_coverage_gain_over_observed']:+.1%} coverage")
    inv = res["declared_intersect_attacks"]
    verdict_txt = ("SAFE — config declares no attack edge; fusion adds no over-privilege"
                   if inv["safe"]
                   else f"COLLISION — {inv['count']} declared edge(s) coincide with an attack: "
                        f"{', '.join(inv['edges'])}")
    print(f"  security      : {verdict_txt}")
    if args.json:
        json.dump(res, open(args.json, "w"), indent=2)
        print(f"\nwrote {args.json}")
    return 0


# ------------------------------------------------------------------ attacks
def _find_chart() -> str:
    """Locate the attack Helm chart. It ships in the source repository (at
    ``attacks/``), so it's available for a git checkout / editable install but NOT
    inside a plain ``pip install`` wheel — see docs/ROADMAP.md. Return a real path if
    found, else "" so the caller prints an accurate instruction."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "..", "..", "attacks"),   # editable install / repo
                 os.path.join(os.getcwd(), "attacks")):        # run from repo root
        chart = os.path.normpath(cand)
        if os.path.exists(os.path.join(chart, "Chart.yaml")):
            return chart
    return ""


def cmd_attacks(args):
    from .attacks import OWASP_K8S, ROSTER
    print("ATT&CK-mapped network-reachability attack roster")
    print(f"addresses OWASP K8s: {OWASP_K8S['2025']} (2022: {OWASP_K8S['2022'].split(' ',1)[0]})")
    chart = _find_chart()
    if chart:
        print(f"deploy with:  helm install npready-attacks {chart} "
              f"-n npready-attacks --create-namespace\n")
    else:
        print("the attack chart ships in the source repository (not the pip package);\n"
              "  clone https://github.com/shivaswaroop40/netpol-readiness and:\n"
              "  helm install npready-attacks ./attacks -n npready-attacks --create-namespace\n")
    print(f"{'family':22} {'edge class':11} {'technique':13} {'mitigation':11} target")
    print("-" * 88)
    for f in ROSTER:
        print(f"{f['id']:22} {f['edge_class']:11} {f['technique']:13} "
              f"{f['mitigation']!s:11} {f['target']}")
    if args.json:
        json.dump(ROSTER, open(args.json, "w"), indent=2)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="npready", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"npready {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("derive", help="config-derived NEEDED dependency graph")
    _add_source_args(d)
    d.add_argument("--limit", type=int, default=40)
    d.set_defaults(func=cmd_derive)

    r = sub.add_parser("readiness", help="four-quadrant readiness + audit/shadow/enforce")
    _add_source_args(r)
    r.add_argument("--limit", type=int, default=40)
    r.add_argument("--show-unused", action="store_true")
    r.set_defaults(func=cmd_readiness)

    s = sub.add_parser("score", help="evaluate a generated policy against ground truth")
    s.add_argument("--admitted", required=True, help="JSON list of admitted [src,dst,port] edges")
    s.add_argument("--legit", required=True, help="JSON list of legitimate edges L")
    s.add_argument("--attacks", required=True, help="JSON list of attack edges A")
    s.add_argument("--observed", help="JSON list of observed edges O (enables decomposition)")
    s.add_argument("--granularity", choices=["port", "pair"], default="port",
                   help="score on (src,dst,port) [default] or the coarser (src,dst) pair")
    s.add_argument("--json", metavar="FILE")
    s.set_defaults(func=cmd_score)

    fz = sub.add_parser("fuse", help="coverage by source: config vs observation vs union")
    _add_source_args(fz)   # config source (--manifests/--snapshot/--context) for the declared set
    fz.add_argument("--declared", help="JSON list of declared [src,dst,port] edges "
                                       "(instead of deriving from a config source)")
    fz.add_argument("--observed", required=True, help="JSON list of observed edges O")
    fz.add_argument("--legit", required=True, help="JSON list of legitimate edges L (ground truth)")
    fz.add_argument("--attacks", required=True, help="JSON list of attack edges A")
    fz.add_argument("--granularity", choices=["port", "pair"], default="port",
                    help="score on (src,dst,port) [default] or the coarser (src,dst) pair")
    fz.set_defaults(func=cmd_fuse)

    a = sub.add_parser("attacks", help="print the ATT&CK-mapped attack roster")
    a.add_argument("--json", metavar="FILE")
    a.set_defaults(func=cmd_attacks)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _ed(e) -> dict:
    return {"src": e.src, "dst": e.dst, "port": e.port,
            "class": e.edge_class.value, "provenance": e.provenance.value,
            "evidence": e.evidence}


if __name__ == "__main__":
    sys.exit(main())
