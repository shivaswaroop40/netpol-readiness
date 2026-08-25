# Wide-n stress test — where the tool (and the thesis) break

Run `npready`'s config-derivation against **13 diverse real Kubernetes apps**,
offline (no cluster), to find where it succeeds, produces nothing, or breaks.

```bash
bash benchmarks/widen/fetch.sh     # fetch the corpus (raw manifests + helm template)
python3 benchmarks/widen/run.py    # analyse; writes results.json
```

The corpus is chosen to stress each derivation source: env-based microservices
(Online Boutique), hardcoded-endpoint apps (Sock Shop, Bookinfo), a single stateless
service (Podinfo), StatefulSet clusters (Redis, PostgreSQL-HA, RabbitMQ, Kafka,
MongoDB), env-DB + Ingress apps (WordPress, Ghost), and a large mixed stack
(kube-prometheus-stack, 134 objects).

## Result

| app | wl | S1 | S3 | S6 | real deps | gate |
|---|--:|--:|--:|--:|--:|---|
| Online Boutique | 12 | 16 | 0 | 0 | 16 | audit |
| Bookinfo | 6 | 0 | 0 | 0 | 0 | audit |
| Sock Shop | 14 | 0 | 0 | 0 | 0 | audit |
| Podinfo | 1 | 0 | 0 | 0 | 0 | audit |
| Redis (replication) | 2 | 0 | 0 | 4 | 4 | enforce |
| PostgreSQL-HA | 2 | 1 | 0 | 1 | 2 | enforce |
| RabbitMQ | 1 | 0 | 0 | 4 | 4 | enforce |
| Kafka | 1 | 0 | 0 | 3 | 3 | enforce |
| MongoDB (replicaset) | 2 | 2 | 0 | 2 | 4 | enforce |
| WordPress | 2 | 1 | 0 | 1 | 2 | enforce |
| WordPress+Ingress | 2 | 1 | 1 | 1 | 3 | enforce |
| Ghost+Ingress | 2 | 1 | 1 | 1 | 3 | enforce |
| kube-prometheus-stack | 4 | 0 | 0 | 0 | 0 | audit |

Source hit-rate (apps where the source found > 0 edges): **S1 6/13,
S3 2/13, S6 8/13**, S4 (DNS) 13/13,
S5 (apiserver) 2/13. No crashes across all 13 apps.

## Where the TOOL broke — found and fixed by this benchmark
1. **Cry-wolf would-break.** Online Boutique (0 NetworkPolicies) was first reported
   SHADOW with 16 "would break on enforce" — wrong, because with no policy everything
   is default-allow and nothing breaks. Fixed: an unadmitted dependency is `missing`
   (would-break) only when its **destination is policy-protected**; otherwise it is
   `unprotected` (an AUDIT concern). Online Boutique is now correctly AUDIT / 0 break.
2. **Single-StatefulSet peering was invisible.** `S6` dropped the intra-cluster
   self-edge, so RabbitMQ/Kafka/etc. yielded nothing. Fixed: emit `X -> X` on the
   cluster ports (how a StatefulSet's replicas peer). S6 hit-rate 1/11 -> 8/13.
3. **Allow-all peering wasn't credited.** The StatefulSet charts ship permissive
   `ingress: [{}]` policies that DO admit peering; the tool briefly called them
   would-break until it counted the allow-all self-admit. They now resolve to ENFORCE
   (won't break — though allow-all is separately over-permissive, which `unused` flags).

## Where the THESIS breaks — the honest limit, quantified
**Config-derivation found real dependency edges for 9/13 apps (69%).**
It works for apps that *declare* their endpoints (env vars, Ingress, headless peers)
and returns only DNS/apiserver boilerplate for 4/13: Bookinfo, Sock Shop, Podinfo, kube-prometheus-stack.

The two structural gaps that remain:
- **Hardcoded-endpoint apps** (Sock Shop, Bookinfo — the standard microservice
  benchmarks) embed service names in code, so `S1` finds nothing. This is the central
  bound of the fusion story: it only helps when dependencies are declared in config.
- **Apps with no derivable deps** (Podinfo; kube-prometheus's scrape targets live in
  ServiceMonitors, not env/ingress).

**Conclusion for the thesis:** the "fuse config with observation" contribution
materially helps ~two-thirds of diverse real apps today. Closing the rest needs static
endpoint analysis for hardcoded service names (roadmap). Stating this bound is a
stronger, more credible claim than pretending config-derivation is universal.
