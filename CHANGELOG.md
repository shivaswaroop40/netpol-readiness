# Changelog

## [0.3.0] - 2026-09-21

### Added
- `npready fuse`: coverage-by-source analysis. Reports what the declared set, the
  observed set, and their union each recover of the legitimate edge set, plus the
  fusion gain over observation alone, at pair or port granularity.
- `fuse()` in `score.py` implementing the union computation used above.
- `release.yml`: tag-triggered PyPI publish via Trusted Publishing (OIDC).
- `MANIFEST.in`; `tests/test_fuse.py`.

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [Unreleased]

### Added
- **`npready fuse` — coverage by source.** Scores the config-derived edges, an
  observed edge set, and their union against the same observation-independent ground
  truth, reporting per-source coverage and over-privilege. Brings the thesis's fusion
  result (C5) into the shipped tool: neither source is safe to rely on alone, the
  union equals the better source, and it is safe by construction — `declared ∩ A = ∅`
  at port granularity is checked and reported, not assumed.
- **`--granularity {port,pair}`** on `score` and `fuse`. `port` (default) compares at
  `(src,dst,port)`; `pair` drops the port to `(src,dst)`, the coarser cross-tool view
  that surfaces the identity-pair aggregation collision (e.g. `agent→world` :443 vs
  SSRF :80) which full port granularity keeps distinct.

### Docs
- ROADMAP corrected: the union **equals** the better source (it does not beat it); the
  value of fusion is that which source wins is not knowable in advance. Added S7
  (guarded mounted-config-graph parsing) as the measured DSB boundary.

## [0.2.1] — 2026-09-04

Correct Kubernetes port semantics end-to-end, broaden endpoint parsing, and finish
release hardening (packaging, CI, the attack chart, and a reproducible benchmark).

### Fixed (Kubernetes port semantics)
- **Edges are keyed on the pod-side (`targetPort`) port**, which is what a
  NetworkPolicy governs. Previously every edge derived through a Service used the
  Service's client-facing `port`; when a Service remapped the port (e.g.
  `port: 8080, targetPort: 9090`) a correct policy written for the real pod port was
  mis-reported as both `missing` (would break) and `unused` (safe to remove) at once.
- **Named ports in policy rules resolve to the target pod's `containerPort`**, and a
  named `targetPort` resolves through the backing containers.
- **`endPort` ranges are honoured** — a rule admitting `8000–9000` now satisfies a
  need on any port in that range instead of only `8000`.

### Added
- **JDBC URLs are parsed** — `jdbc:postgresql://host:5432/db` resolves to the host and
  port instead of treating the literal `jdbc` as the hostname.
- **`--namespace` now filters `--manifests`/`--snapshot` input**, instead of being
  silently ignored while the report header still claimed the namespace scope.
- `py.typed` marker so downstream type-checkers see the package's annotations.

### Packaging / CI / chart
- PEP 639 license metadata (`license = "Apache-2.0"` + `license-files`), per-version
  classifiers, `Issues`/`Changelog` URLs, and a `MANIFEST.in` so the sdist ships
  `conftest.py` + fixtures (pytest-from-sdist previously failed to collect).
- CI: `permissions: contents: read`, all actions pinned to commit SHAs, schema
  regression tests for the chart, and a `release.yml` using PyPI Trusted Publishing.
- Attack chart hardened: probe image digest-pinned, `values.schema.json` constrains
  `probe.image` (digest required), `serviceAccountName` and `namespace.name`; a
  resources envelope added; the `NOTES.txt` namespace-delete gated on
  `namespace.create`.
- Wide-n benchmark made reproducible: corpus pinned by commit SHA and chart version,
  temp paths moved off world-writable `/tmp`.

## [0.2.0] — thesis revision

Generalise config-derivation and fix would-break over-reporting.

### Changed
- **Derivation resolves by value against the Service catalog**, not by variable name.
  Every config surface (env, referenced ConfigMaps, container argv) is tokenised and
  each candidate resolved against the live Services; the old `_HOST|_URL|_ADDR|…` name
  pattern survives only as a confidence signal, so real dependencies like
  `mongo=user-db:27017` are no longer missed because of how the variable was named.
- Endpoint parsing strips URL schemes (`http://svc:8080` → `svc:8080`) and lets the
  scheme supply a default port (`https://host` → `:443`) when the value carries none.

### Fixed
- **Would-break over-reporting.** An unadmitted dependency is `missing` (would break on
  enforce) only when its destination is policy-protected; deps to a default-allow
  destination are `unprotected` (an audit concern), and DNS/apiserver/egress needs are
  `out_of_scope`. This stopped the gate being forced to SHADOW on unpoliced clusters.
- **`namespaceSelector` is evaluated** against namespace labels (previously treated as
  "all namespaces", the one false-*safe* bug); reconciliation honours the port
  wildcard; `policyTypes` omitted counts as ingress-affecting (k8s default).
- **S6 models StatefulSet peering** (self-edge on the cluster port) and credits
  allow-all self-admits, instead of emitting a phantom self-loop no policy could match.
- `kubectl get -o yaml` `List` envelopes are unwrapped when loading manifests.

### Added
- Wide-n benchmark (`benchmarks/widen/`) across 13 real apps, recording every S1 edge
  so the zero-false-positive claim is auditable.

## [0.1.0] — initial release

First public research-artifact release, accompanying the master's thesis on
NetworkPolicy enforcement-readiness.

### Added
- `npready readiness` — config-derived reconciliation into
  correct / unused / **missing** / unprotected / out-of-scope, and an
  audit/shadow/enforce gate.
- Config-derivation sources: S1 config endpoints (env, ConfigMap, argv), S3 Ingress,
  S4 DNS invariant, S5 RBAC→apiserver, S6 headless-Service peers — each edge carries
  provenance and the literal config that justified it.
- `npready derive` — emit the NEEDED dependency graph (text or JSON).
- `npready score` — over-privilege / block-rate / false-deny scoring of any
  generated policy, plus the coverage-vs-tool-penalty decomposition.
- `npready attacks` — the ATT&CK-mapped roster (OWASP K8s K07/K05).
- `./attacks` Helm chart — fail-closed, non-root, disposable-namespace probes for
  eight edge-class-organised attack families.

### Security (from the pre-release audit)
- **Closed a shell-injection path in the attack Helm chart.** Probe targets
  (`host`/`port`/`url`) were interpolated into a `/bin/sh -c` script; a crafted
  `values.yaml` could achieve RCE in the probe pod. Targets now reach the probe as
  env vars (literal strings, never shell-parsed; script is static and quotes every
  input), and a `values.schema.json` rejects malformed host/port/url at render time.
- **Stopped leaking inline credentials.** An env value like
  `DATABASE_URL=postgres://user:pass@host/db` was written verbatim into `evidence`
  and `--json`; evidence now records only the parsed `name=host:port`.

## Known limitations
- S2 full Service-catalog resolution, Gateway API routes, and ExternalName egress
  classification are partial. Sock-Shop-style hard-coded service names (no env
  endpoints) are not derived by S1. See `docs/ROADMAP.md`.
