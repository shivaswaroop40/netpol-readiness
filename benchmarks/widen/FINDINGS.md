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
(kube-prometheus-stack, 139 objects).

The corpus is pinned (raw-manifest commit SHAs and Helm chart `--version`s in
`fetch.sh`); the numbers below were captured from that pinned corpus on 2026-08-31.

## Result

| app | wl | S1 | S3 | S6 | real deps | gate |
|---|--:|--:|--:|--:|--:|---|
| Online Boutique | 12 | 16 | 0 | 0 | 16 | audit |
| Bookinfo | 6 | 0 | 0 | 0 | 0 | audit |
| Sock Shop | 14 | 1 | 0 | 0 | 1 | audit |
| Podinfo | 1 | 0 | 0 | 0 | 0 | audit |
| Redis (replication) | 2 | 1 | 0 | 3 | 4 | enforce |
| PostgreSQL-HA | 2 | 0 | 0 | 1 | 1 | enforce |
| RabbitMQ | 1 | 0 | 0 | 4 | 4 | enforce |
| Kafka | 1 | 0 | 0 | 3 | 3 | enforce |
| MongoDB (replicaset) | 2 | 0 | 0 | 2 | 2 | audit |
| WordPress | 2 | 1 | 0 | 0 | 1 | enforce |
| WordPress+Ingress | 2 | 1 | 1 | 0 | 2 | enforce |
| Ghost+Ingress | 2 | 1 | 1 | 1 | 3 | enforce |
| kube-prometheus-stack | 4 | 0 | 0 | 0 | 0 | audit |

Source hit-rate (apps where the source found > 0 edges): **S1 6/13, S3 2/13, S6 6/13**, S4 (DNS) 13/13, S5 (apiserver) 2/13. No crashes across all 13 apps.

Edges are reported on the **pod-side (targetPort) port**, which is what a
NetworkPolicy governs. Where a Service remaps the port this is visible in the
appendix — e.g. Online Boutique's `frontend` and `emailservice` derive on `:8080`
(their `targetPort`), not the Service ports `:80`/`:5000` the caller dials.

## Where the TOOL broke — found and fixed by this benchmark
1. **Cry-wolf would-break.** Online Boutique (0 NetworkPolicies) was first reported
   SHADOW with 16 "would break on enforce" — wrong, because with no policy everything
   is default-allow and nothing breaks. Fixed: an unadmitted dependency is `missing`
   (would-break) only when its **destination is policy-protected**; otherwise it is
   `unprotected` (an AUDIT concern). Online Boutique is now correctly AUDIT / 0 break.
2. **Single-StatefulSet peering was invisible.** `S6` dropped the intra-cluster
   self-edge, so RabbitMQ/Kafka/etc. yielded nothing. Fixed: emit `X -> X` on the
   cluster ports (how a StatefulSet's replicas peer). S6 hit-rate 1/11 -> 6/13.
3. **Allow-all peering wasn't credited.** The StatefulSet charts ship permissive
   `ingress: [{}]` policies that DO admit peering; the tool briefly called them
   would-break until it counted the allow-all self-admit. They now resolve to ENFORCE
   (won't break — though allow-all is separately over-permissive, which `unused` flags).

## Where the THESIS breaks — the honest limit, quantified
**Config-derivation found real dependency edges for 10/13 apps (77%).**
It works for apps that *declare* their endpoints (env vars, Ingress, headless peers)
and returns only DNS/apiserver boilerplate for **3/13: Bookinfo, Podinfo,
kube-prometheus-stack**.

The one structural gap that remains:
- **Code-only dependencies.** Bookinfo embeds its peer service names entirely in
  application code, Podinfo declares no dependency at all, and kube-prometheus's
  scrape targets live in ServiceMonitor CRs, not env/Ingress/headless peering. `S1`
  therefore finds nothing for these three. This is the central bound of the fusion
  story: config-derivation only helps when a dependency is *declared in
  configuration* — which is exactly why observation remains necessary.

(Sock Shop used to fall in this bucket. After S1 was rebuilt to resolve by value —
see the next section — its `mongo=user-db:27017` dependency now derives, moving it
out of the boilerplate-only set and taking the useful count from 9/13 to 10/13.)

**Conclusion for the thesis:** the "fuse config with observation" contribution
materially helps roughly three-quarters of diverse real apps today. Closing the rest
needs static endpoint analysis for hardcoded service names (roadmap). Stating this
bound is a stronger, more credible claim than pretending config-derivation is
universal.

## Update — generalising derivation (verify, don't guess)
The first S1 fired only on env var **names** matching `_HOST|_URL|_ADDR|…`. That is a
hardcoded convention, and it silently missed real dependencies: Sock Shop declares
`mongo=user-db:27017`, a genuine edge that the pattern rejected purely because of the
variable's name.

S1 was rebuilt around the invariant that actually holds:

> a dependency exists when a configuration value **resolves to a Service that exists
> in this cluster**.

Every configuration surface is now scanned (env values, referenced ConfigMaps, and the
container command line), each token resolved against the live Service catalog by exact
match. The naming convention survives only as a **confidence signal** (1.0 when the
name corroborates, 0.75 when the value alone resolves). Nothing app-specific is
hardcoded, and it self-configures per cluster.

Result: Sock Shop now derives its one manifest-declared dependency, useful apps rose to
**10/13**, and a false-positive audit across the whole corpus found **0** bogus edges
(`MYSQL_DATABASE=socksdb`, `SESSION_REDIS=true`, `JAVA_OPTS=-Xms64m …` all correctly
resolve to nothing). The same change fixed a misclassification: pod-qualified headless
names (`db-0.db-headless`) resolve **in-cluster** instead of being reported as egress.

**The floor is now honest.** The 3 remaining apps are not a tooling gap: Bookinfo and
Podinfo declare *no* dependency anywhere in their manifests (Bookinfo's are entirely in
application code), and kube-prometheus declares its targets in ServiceMonitor CRs. That
is the genuine boundary between *config-derivable* and *code-only* dependencies — and
it is precisely why observation remains necessary. Config-derivation cannot be pushed
past it by better heuristics; only by static analysis of application code.

## Appendix — every S1 edge, so the false-positive claim is checkable

The zero-false-positive claim above covers these **21** configuration-value edges.
Each is shown with the literal configuration that produced it, and each port is the
resolved pod-side port. Regenerate with `python3 benchmarks/widen/run.py
benchmarks/widen/_corpus` — they are stored in `results.json` under `s1_edges`.

**Online Boutique**

```
default/cartservice -> default/redis-cart:6379  [env:REDIS_ADDR=redis-cart:6379]
default/checkoutservice -> default/cartservice:7070  [env:CART_SERVICE_ADDR=cartservice:7070]
default/checkoutservice -> default/currencyservice:7000  [env:CURRENCY_SERVICE_ADDR=currencyservice:7000]
default/checkoutservice -> default/emailservice:8080  [env:EMAIL_SERVICE_ADDR=emailservice:5000]
default/checkoutservice -> default/paymentservice:50051  [env:PAYMENT_SERVICE_ADDR=paymentservice:50051]
default/checkoutservice -> default/productcatalogservice:3550  [env:PRODUCT_CATALOG_SERVICE_ADDR=productcatalogservice:3550]
default/checkoutservice -> default/shippingservice:50051  [env:SHIPPING_SERVICE_ADDR=shippingservice:50051]
default/frontend -> default/adservice:9555  [env:AD_SERVICE_ADDR=adservice:9555]
default/frontend -> default/cartservice:7070  [env:CART_SERVICE_ADDR=cartservice:7070]
default/frontend -> default/checkoutservice:5050  [env:CHECKOUT_SERVICE_ADDR=checkoutservice:5050]
default/frontend -> default/currencyservice:7000  [env:CURRENCY_SERVICE_ADDR=currencyservice:7000]
default/frontend -> default/productcatalogservice:3550  [env:PRODUCT_CATALOG_SERVICE_ADDR=productcatalogservice:3550]
default/frontend -> default/recommendationservice:8080  [env:RECOMMENDATION_SERVICE_ADDR=recommendationservice:8080]
default/frontend -> default/shippingservice:50051  [env:SHIPPING_SERVICE_ADDR=shippingservice:50051]
default/loadgenerator -> default/frontend:8080  [env:FRONTEND_ADDR=frontend:80]
default/recommendationservice -> default/productcatalogservice:3550  [env:PRODUCT_CATALOG_SERVICE_ADDR=productcatalogservice:3550]
```

**Sock Shop**

```
sock-shop/user -> sock-shop/user-db:27017  [env:mongo=user-db:27017]
```

**Redis (replication)**

```
default/r-redis-replicas -> default/r-redis-master:6379  [env:REDIS_MASTER_HOST=r-redis-master-0.r-redis-headless.default.svc.cluster.local:6379]
```

**WordPress**

```
default/wp-wordpress -> default/wp-mariadb:3306  [env:MARIADB_HOST=wp-mariadb:3306]
```

**WordPress+Ingress**

```
default/wp-wordpress -> default/wp-mariadb:3306  [env:MARIADB_HOST=wp-mariadb:3306]
```

**Ghost+Ingress**

```
default/gh-ghost -> default/gh-mysql:3306  [env:GHOST_DATABASE_HOST=gh-mysql:3306]
```
