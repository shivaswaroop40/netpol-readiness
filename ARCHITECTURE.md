# Architecture

`npready` is one small library with a thin CLI. Every stage reads and writes the
same `Edge` vocabulary (`model.py`), so a generated policy, a NetworkPolicy, a
config-derived dependency, and an attack are all directly comparable.

```
                       ┌─────────────── inventory.py ───────────────┐
   kubectl get (RO) ──▶│  Inventory: workloads, services, netpols,   │
   manifests / JSON ──▶│  ingresses, rolebindings (normalised)       │
                       └───────┬───────────────────────┬─────────────┘
                               │                       │
                   graph.py    ▼                       ▼   policy.py
         ┌──────────────────────────────┐   ┌──────────────────────────────┐
         │ derive_needed  -> NEEDED edges│   │ derive_admitted -> ADMITTED   │
         │  S1 env  S3 ingress  S4 dns   │   │ edges (expand every           │
         │  S5 rbac  S6 headless peers   │   │ networking.k8s.io/v1 policy)  │
         └───────────────┬──────────────┘   └───────────────┬──────────────┘
                         │                                  │
                         └──────────────┬───────────────────┘
                                        ▼   reconcile.py
                        ┌───────────────────────────────────┐
                        │ reconcile(): four quadrants        │
                        │   correct | unused | missing       │
                        │ verdict(): audit / shadow / enforce │
                        └───────────────┬────────────────────┘
                                        ▼
                                   CLI / JSON

   score.py (independent evaluation): score(admitted, L, A) -> block_rate,
   over_privilege, false_deny; decompose_false_deny(admitted, L, observed) ->
   coverage vs tool_penalty.

   attacks.py + ../attacks (Helm): the ATT&CK-mapped probe roster deployed to a
   disposable namespace to empirically confirm what the policies block.
```

## Design decisions

- **Identity, not IP.** Edges are `namespace/name`, not pod IPs, so the model
  survives pod churn — the reason identity-based policy exists. Synthetic peers
  (`world`, `kube-apiserver`, `kube-dns`, `node`) use bare tokens.

- **Port granularity is load-bearing.** Reconciliation and scoring compare on
  `(src, dst, port)`. Dropping the port is how port-blind tools hide over-privilege
  (an SSRF to `:80` collapses onto legitimate egress to `:443`), so `npready` keeps
  it and makes wildcard admits explicit (`port=None`).

- **Provenance on every edge.** A derived edge is only actionable if you can see why
  it was derived. Every `Edge` carries a `Provenance` and the literal `evidence`.

- **Offline-capable.** All read paths work from manifests or a JSON snapshot, so the
  analysis runs in CI with no cluster and no credentials. The live path issues only
  `kubectl get`.

- **Dependency-light.** The core is stdlib + PyYAML. No cluster client library, no
  heavyweight graph engine — it must run in a restricted pod.

## Module map

| module | responsibility |
|---|---|
| `model.py` | `Edge`, `EdgeClass`, `Provenance`, `Quadrant`, `ReconcileResult` |
| `inventory.py` | load + normalise cluster inputs (3 sources); label-selector eval |
| `graph.py` | `derive_needed` — the six config-derivation sources |
| `policy.py` | `derive_admitted` — expand NetworkPolicy objects to edges |
| `reconcile.py` | quadrants + `verdict` (audit/shadow/enforce gate) |
| `score.py` | generator evaluation metrics + false-deny decomposition |
| `attacks.py` | the ATT&CK-mapped roster metadata (Helm chart deploys it) |
| `cli.py` | `derive` / `readiness` / `score` / `attacks` |
