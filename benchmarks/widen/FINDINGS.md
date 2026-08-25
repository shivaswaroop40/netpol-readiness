# Wide-n stress test — where the tool (and the thesis) break

Run `npready`'s config-derivation against a diverse corpus of **13 real Kubernetes apps**, offline (no cluster), to find where it succeeds, produces nothing, or breaks.

```bash
bash benchmarks/widen/fetch.sh          # fetch 11 apps (raw manifests + helm template)
python3 benchmarks/widen/run.py         # analyse; writes results.json
```

## The corpus (chosen to stress each derivation source)
env-based microservices (Online Boutique), hardcoded-endpoint apps (Sock Shop,
Bookinfo), a single stateless service (Podinfo), StatefulSet clusters (Redis,
PostgreSQL-HA, RabbitMQ, Kafka, MongoDB), an env-DB app (WordPress), and a large
mixed stack (kube-prometheus-stack, 134 objects).

## Result

| app | wl | S1 | S3 | S6 | real deps | gate |
|---|--:|--:|--:|--:|--:|---|
| Online Boutique | 12 | 16 | 0 | 0 | 16 | audit |
| Bookinfo | 6 | 0 | 0 | 0 | 0 | audit |
| Sock Shop | 14 | 0 | 0 | 0 | 0 | audit |
| Podinfo | 1 | 0 | 0 | 0 | 0 | audit |
| Redis (replication) | 2 | 0 | 0 | 2 | 2 | enforce |
| PostgreSQL-HA | 2 | 1 | 0 | 0 | 1 | enforce |
| RabbitMQ | 1 | 0 | 0 | 0 | 0 | enforce |
| Kafka | 1 | 0 | 0 | 0 | 0 | enforce |
| MongoDB (replicaset) | 2 | 2 | 0 | 0 | 2 | enforce |
| WordPress | 2 | 1 | 0 | 0 | 1 | enforce |
| kube-prometheus-stack | 4 | 0 | 0 | 0 | 0 | audit |

Source hit-rate (apps where the source found > 0 edges): **S1 6/13, S3 2/13, S6 8/13**,
S4 (DNS) 11/11, S5 (apiserver) 2/11.

## Where the TOOL breaks — found and fixed here
The first run reported **Online Boutique as SHADOW with 16 "would break on enforce"**,
despite it shipping **zero NetworkPolicies**. That was a cry-wolf bug: with no policy,
every destination is default-allow, so *nothing* actually breaks. Fixed — an unadmitted
declared dependency is only `missing` (would-break) when its **destination is actually
policy-protected**; otherwise it is `unprotected` (an AUDIT concern: the edge flows
today, write policy to segment it). Online Boutique is now correctly **AUDIT** with 0
would-break. No crashes across all 11 apps (robustness is sound).

## Where the THESIS breaks — the honest limitation, quantified
**Config-derivation found real dependency edges for 9 of 13 apps (69%).** It is
genuinely useful for **env-based ("twelve-factor") apps** (Online Boutique, MongoDB,
WordPress, PostgreSQL-HA) and returns only DNS/apiserver boilerplate for:

- **Hardcoded-endpoint apps** (Sock Shop, Bookinfo — the *standard* microservice
  benchmarks): they embed service names in code, so `S1` env-endpoint derivation finds
  nothing. This is the central limit of the fusion story: config-derivation only helps
  when the app *declares* its endpoints in config.
- **Single-StatefulSet clusters** (RabbitMQ, Kafka): `S6` needs a headless Service
  backing *multiple distinct* workload identities. One StatefulSet collapses to one
  identity, so peer edges are (correctly) not emitted — but that means the common
  clustering case yields nothing. **Fix on the roadmap: resolve peers via EndpointSlice
  / per-pod identity.**
- `S3` (Ingress) fired on **0/11** — this corpus uses LoadBalancer/NodePort/Istio, not
  `Ingress` objects. `S3` needs a corpus with real Ingress to be exercised.

## What this means
- **For the tool:** robust (no crashes), and the readiness verdict is now honest
  (AUDIT vs SHADOW distinguishes "no policy yet" from "policy would break"). The
  StatefulSet charts that ship their own NetworkPolicies correctly resolve to ENFORCE.
- **For the thesis:** the "fuse config with observation" contribution is bounded — it
  materially helps roughly half of diverse real apps today, and needs more derivation
  sources (static analysis of hardcoded endpoints, EndpointSlice peer resolution) to
  cover the rest. State this as the external-validity limit; it is a stronger, more
  credible claim than pretending config-derivation is universal.

## Update — after fixing S6 (StatefulSet peering) and adding Ingress apps
Two follow-up fixes, both found by re-running this benchmark:

- **S6 now models single-StatefulSet peering** as a self-edge `X -> X` on the cluster
  ports (etcd/kafka/rabbitmq peer with their own replicas), instead of dropping it.
  Hit-rate rose from **1/11 to 8/13**; useful-app rate from **45% to 69%**.
- **Policy parsing now credits self-edges from allow-all ingress.** The bitnami charts
  ship permissive `ingress: [{}]` policies that DO admit peering; the tool briefly
  reported them as would-break until it counted the allow-all self-admit. All the
  StatefulSet charts now correctly resolve to ENFORCE (they won't break — though an
  allow-all policy is separately over-permissive, which the `unused` bucket captures).
- **S3 (Ingress)** now exercised via WordPress+Ingress and Ghost+Ingress (2/13).

Remaining honest limits (unchanged conclusion, just quantified better): still useless
for hardcoded-endpoint apps (Sock Shop, Bookinfo) and apps with no derivable deps
(Podinfo, kube-prometheus). The fusion story helps ~two-thirds of diverse real apps
today; closing the rest needs static endpoint analysis for hardcoded service names.
