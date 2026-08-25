#!/usr/bin/env python3
"""Wide-n stress test: run npready's config-derivation against many real apps and
find where it succeeds, produces nothing, or breaks.

This deliberately answers "where does the tool (and the thesis) break?" — it points
the derivation at a diverse corpus of real Kubernetes apps (fetched by fetch.sh) and
reports, per app: what each source (S1..S6) found, whether it crashed, and — the
thesis-critical number — how many apps config-derivation is actually USEFUL for.

Offline: no cluster needed. Everything runs from the fetched manifests.
"""
import json
import os
import sys
import traceback
from collections import Counter

from npready import Inventory, derive_admitted, derive_needed, reconcile, verdict
from npready.model import Provenance

APPS_DIR = sys.argv[1] if len(sys.argv) > 1 else "/tmp/widen-apps"

# (file, human label, what it's meant to stress)
CORPUS = [
    ("online-boutique.yaml", "Online Boutique", "env-addr microservices (gRPC)"),
    ("bookinfo.yaml", "Bookinfo", "hardcoded service names"),
    ("sock-shop.yaml", "Sock Shop", "hardcoded service names"),
    ("podinfo.yaml", "Podinfo", "single stateless service"),
    ("redis.yaml", "Redis (replication)", "StatefulSet + headless peers"),
    ("postgres-ha.yaml", "PostgreSQL-HA", "StatefulSet cluster"),
    ("rabbitmq.yaml", "RabbitMQ", "StatefulSet cluster"),
    ("kafka.yaml", "Kafka", "StatefulSet cluster"),
    ("mongodb.yaml", "MongoDB (replicaset)", "StatefulSet replicaset"),
    ("wordpress.yaml", "WordPress", "env-based DB endpoint"),
    ("wordpress-ingress.yaml", "WordPress+Ingress", "Ingress route (S3)"),
    ("ghost.yaml", "Ghost+Ingress", "Ingress route (S3)"),
    ("kube-prometheus.yaml", "kube-prometheus-stack", "large mixed stack (134 objs)"),
]

SOURCES = [Provenance.S1_ENV_ENDPOINT, Provenance.S3_INGRESS, Provenance.S4_DNS,
           Provenance.S5_APISERVER, Provenance.S6_PEER]


def analyse(path):
    inv = Inventory.from_manifests(path)
    needed = derive_needed(inv)
    admitted, protected = derive_admitted(inv)
    res = reconcile(needed, admitted, total_workloads=len(inv.workloads), protected=protected)
    v = verdict(res)
    by_src = Counter(e.provenance.value for e in needed)
    # "useful" = derivation found at least one real dependency edge (S1/S3/S6),
    # i.e. something beyond the universal S4 DNS + S5 apiserver boilerplate.
    real = sum(by_src.get(s.value, 0) for s in
               (Provenance.S1_ENV_ENDPOINT, Provenance.S3_INGRESS, Provenance.S6_PEER))
    return {
        "workloads": len(inv.workloads),
        "services": len(inv.services),
        "netpols": len(inv.networkpolicies),
        "needed": len(needed),
        "by_source": {s.value: by_src.get(s.value, 0) for s in SOURCES},
        "real_dependency_edges": real,
        "would_break": len(res.missing),
        "over_priv": len(res.unused),
        "out_of_scope": len(res.out_of_scope),
        "gate": v.gate,
    }


def main():
    rows = []
    for fname, label, stress in CORPUS:
        path = os.path.join(APPS_DIR, fname)
        if not os.path.exists(path):
            rows.append({"app": label, "stress": stress, "error": "not fetched"})
            continue
        try:
            r = analyse(path)
            r.update(app=label, stress=stress, error=None)
        except Exception as e:
            r = {"app": label, "stress": stress,
                 "error": f"{type(e).__name__}: {e}",
                 "trace": traceback.format_exc().splitlines()[-3:]}
        rows.append(r)

    json.dump(rows, open(os.path.join(os.path.dirname(__file__), "results.json"), "w"), indent=2)

    # ---- report ----
    print("=" * 92)
    print("WIDE-N STRESS TEST — npready config-derivation on real apps")
    print("=" * 92)
    hdr = f"{'app':22} {'wl':>3} {'svc':>3} {'np':>3} | {'S1':>3} {'S3':>3} {'S4':>3} {'S5':>3} {'S6':>3} | {'real':>4} {'break':>5} {'gate':8}"
    print(hdr)
    print("-" * len(hdr))
    crashed, useless, useful = [], [], []
    for r in rows:
        if r.get("error"):
            print(f"{r['app']:22} ERROR: {r['error']}")
            crashed.append(r)
            continue
        b = r["by_source"]
        print(f"{r['app']:22} {r['workloads']:>3} {r['services']:>3} {r['netpols']:>3} | "
              f"{b['s1_env']:>3} {b['s3_ingress']:>3} {b['s4_dns']:>3} {b['s5_apiserver']:>3} {b['s6_peer']:>3} | "
              f"{r['real_dependency_edges']:>4} {r['would_break']:>5} {r['gate']:8}")
        (useful if r["real_dependency_edges"] > 0 else useless).append(r)

    n = len([r for r in rows if not r.get("error")])
    print("\n" + "=" * 92)
    print("WHERE IT BREAKS")
    print("=" * 92)
    print(f"apps analysed: {n}/{len(rows)}   crashed: {len(crashed)}")
    print(f"config-derivation found REAL dependency edges (S1/S3/S6) for {len(useful)}/{n} apps")
    print(f"  -> USELESS (only DNS/apiserver boilerplate) for {len(useless)}/{n}: "
          + ", ".join(r["app"] for r in useless))
    if crashed:
        print("  -> CRASHED: " + ", ".join(f"{r['app']} ({r['error']})" for r in crashed))
    # source hit-rate
    print("\nsource hit-rate (apps where the source found >0 edges):")
    for s in SOURCES:
        hits = sum(1 for r in rows if not r.get("error") and r["by_source"][s.value] > 0)
        print(f"  {s.value:14} {hits}/{n}")
    print("\nwrote results.json")


if __name__ == "__main__":
    main()
