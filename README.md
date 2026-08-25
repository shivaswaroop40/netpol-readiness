# npready — Kubernetes NetworkPolicy enforcement-readiness

**Is this generated network policy safe to turn on?**

Existing tools tell you a policy is *loose* (over-privilege scanners) or that a CNI
*enforces the spec correctly* (cyclonus, the upstream conformance suite). Neither
tells you the thing that decides deployment: **if you enforce this policy, does it
stop attackers without breaking the application?**

`npready` answers that with two capabilities that, to our knowledge, no existing
tool combines:

1. **Config-derived readiness analysis** (`npready readiness`) — derives the
   dependency edges your workloads *declare* they need (from env vars, Ingress,
   RBAC, DNS, headless peers), compares them to what your NetworkPolicies *admit*,
   and surfaces the **`missing` quadrant: declared dependencies no policy admits —
   the edges that break production the moment you enforce.** Over-privilege scanners
   and observational audit modes cannot see these, because a missing edge may never
   appear in a benign observation window.

2. **An ATT&CK-mapped, declaratively-deployable attack roster** (`./attacks` Helm
   chart) — deploy a set of fail-closed probes into a namespace, turn your policies
   on, and see which unauthorized edges are actually blocked. The probes model a
   *compromised workload* and are organised by the network edge a policy must deny,
   not by a vulnerability class a policy cannot touch.

Plus an **evaluation framework** (`npready score`) that scores any policy generator
on the two axes that matter — over-privilege (attacks admitted) and false-deny
(legitimate traffic broken) — with a decomposition that says whether the fix is
"observe more" or "change tool".

> This tool is the software artifact of a master's thesis on network-policy
> enforcement-readiness. See [`docs/POSITIONING.md`](docs/POSITIONING.md) for an
> honest comparison to prior art and what is and isn't novel.

---

## Install

From a checkout (the supported path for now):

```bash
pip install -e .
```

Runtime dependency: PyYAML. The analysis core is otherwise stdlib-only, so it runs
inside a restricted CI pod. `kubectl` is used (read-only) only for the live path. A
PyPI release is planned (see `docs/ROADMAP.md`).

## Use

### 1. Is my namespace safe to enforce?

```bash
# read a live cluster (read-only kubectl get), or analyse manifests offline:
npready readiness --context my-cluster --namespace shop
npready readiness --manifests ./deploy/
```

```
ENFORCEMENT READINESS — shop
  correct (admitted & needed) : 12
  unused  (admitted, unneeded): 4    over-privilege — safe to remove
  missing (needed, unadmitted): 2    WOULD BREAK ON ENFORCE
  out-of-scope (egress/DNS/api): 6   need egress policy / cluster-infra
  workloads protected         : 9/11
  readiness score : 0.86
  GATE            : SHADOW
  2 declared dependency edge(s) are not admitted by any policy; enforcing now
  would deny legitimate traffic. Add them, then re-check.

  WOULD BREAK ON ENFORCE (fix these first):
    shop/orders-api -> shop/orders-cache :6379  [s1_env]  REDIS_ADDR=orders-cache:6379
    ingress-controller -> shop/storefront :80   [s3_ingress] ingress/shop-ingress
```

(DNS and apiserver dependencies are reported under *out-of-scope* — they need an
egress policy or are cluster-infra, so they are not counted as would-break-on-enforce
for an ingress policy.)

`readiness` exits non-zero when the gate is `shadow`, so you can wire it into CI to
block a merge that would break on enforce.

### 2. What does my config say I need?

```bash
npready derive --manifests ./deploy/ --json needed.json
```

### 3. Validate that my policies actually block attacks

```bash
# the attack chart ships in this repo (at attacks/); clone/checkout to use it.
# edit attacks/values.yaml to point families at your real targets, then:
helm install npready-attacks ./attacks -n npready-attacks --create-namespace
kubectl -n npready-attacks logs -l app.kubernetes.io/name=npready-attacks | grep RESULT
# RESULT 03-lateral-movement postgres.shop.svc:5432 BLOCKED  <- policy working
```

> The chart is distributed with the source repository (not yet inside the pip
> package — see `docs/ROADMAP.md`). `npready attacks` prints the correct chart path
> for your checkout.

### 4. Score a generated policy on the safe-to-enforce axis

```bash
npready score --admitted policy_edges.json --legit L.json --attacks A.json --observed O.json
```

```json
{ "block_rate": 1.0, "over_privilege": 0.0, "false_deny": 0.26 }
```

## How the readiness analysis works

`needed` edges come from six independent, auditable sources — every edge records the
literal config that justified it:

| source | signal | example |
|---|---|---|
| S1 | workload env endpoints | `REDIS_ADDR=cache:6379` → app → cache:6379 |
| S3 | Ingress / Gateway routes | ingress backend → service → workload |
| S4 | cluster DNS invariant | every pod → kube-dns:53 (the classic silent break) |
| S5 | RBAC bindings | bound ServiceAccount → kube-apiserver:443 |
| S6 | headless Service peers | StatefulSet replicas ↔ each other |

`admitted` edges come from expanding every `networking.k8s.io/v1` NetworkPolicy.
Reconciliation is set arithmetic at `(src, dst, port)` granularity — admitting
`a→b:443` does **not** silently satisfy a need for `a→b:5432`.

## Status

This is a v0.1 research artifact. Honest status:

| capability | status |
|---|---|
| config derivation (S1, S3, S4, S5, S6) | implemented, tested, run on a live cluster |
| policy parsing + four-quadrant reconciliation | implemented, tested |
| readiness gate (audit/shadow/enforce) | implemented, tested |
| scoring + decomposition | implemented, tested |
| attack roster Helm chart (fail-closed probes) | implemented, lint+render tested |
| S2 full Service-catalog resolution, Gateway API, ExternalName egress classes | partial |
| in-cluster results collector / report for the attack chart | roadmap |

See [`CHANGELOG.md`](CHANGELOG.md) and [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Prior art & what's novel

Read [`docs/POSITIONING.md`](docs/POSITIONING.md) before citing this as novel. In
short: `cyclonus`/`netassert`/the upstream e2e suite test connectivity against the
**spec** on a **synthetic fixture**; Cilium `--policy-audit-mode` / Calico
`StagedNetworkPolicy` are **observational** (they cannot see attack traffic that
never happened); over-privilege scanners see `unused` but not `missing`. `npready`'s
contribution is the config-derived `missing`-edge (would-break-on-enforce) analysis
and the ATT&CK-mapped declarative attack roster. We do **not** claim to be the first
to do reachability truth tables (cyclonus does) or declarative connectivity tests
(netassert does).

## License

Apache-2.0. See [`LICENSE`](LICENSE). This project ships benign network *probes*,
not exploits; see [`THREAT_MODEL.md`](THREAT_MODEL.md) and use only on clusters you
are authorised to test.
