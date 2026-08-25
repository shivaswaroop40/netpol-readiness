# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.1.0] — unreleased

First public research-artifact release, accompanying the master's thesis on
NetworkPolicy enforcement-readiness.

### Added
- `npready readiness` — config-derived four-quadrant reconciliation
  (correct / unused / **missing** / denied) and an audit/shadow/enforce gate.
- Config-derivation sources: S1 env endpoints, S3 Ingress, S4 DNS invariant,
  S5 RBAC→apiserver, S6 headless-Service peers — each edge carries provenance.
- `npready derive` — emit the NEEDED dependency graph (text or JSON).
- `npready score` — over-privilege / block-rate / false-deny scoring of any
  generated policy, plus the coverage-vs-tool-penalty decomposition.
- `npready attacks` — the ATT&CK-mapped roster (OWASP K8s K07/K05).
- `./attacks` Helm chart — fail-closed, non-root, disposable-namespace probes for
  eight edge-class-organised attack families.
- Test suite (30 tests) with a synthetic fixture whose quadrants are known and
  asserted, plus regression tests for the k8s-semantics fixes below; offline
  manifest/snapshot analysis paths.

### Security (from the pre-release audit)
- **Closed a shell-injection path in the attack Helm chart.** Probe targets
  (`host`/`port`/`url`) were interpolated into a `/bin/sh -c` script; a crafted
  `values.yaml` could achieve RCE in the probe pod. Targets now reach the probe as
  env vars (literal strings, never shell-parsed; script is static and quotes every
  input), and a `values.schema.json` rejects malformed host/port/url at render time.
- **Stopped leaking inline credentials.** An env value like
  `DATABASE_URL=postgres://user:pass@host/db` was written verbatim into `evidence`
  and `--json`; evidence now records only the parsed `name=host:port`.

### Fixed (correctness, from the pre-release code review)
- **`namespaceSelector` is now evaluated** against namespace labels. It was treated as
  "all namespaces", which over-admitted edges and could report a policy as safe to
  enforce when it was not (the one false-*safe* bug). Requires loading Namespace
  labels, now part of `Inventory`.
- **Reconciliation honours the port wildcard**: a policy rule with no `ports` (admits
  all ports) now satisfies a specific need like `a→b:5432`, matching k8s semantics and
  `score.py`'s existing wildcard handling.
- **DNS / apiserver / egress needs are reported `out_of_scope`**, not `missing`, so the
  readiness gate is no longer forced to SHADOW on every run by edges an ingress policy
  structurally cannot express.
- **S6 no longer emits a phantom self-loop** for a lone StatefulSet behind a headless
  Service (an edge no policy could ever satisfy).
- **`policyTypes` omitted now correctly counts as ingress-affecting** for the
  `protected` bookkeeping (k8s default), instead of under-counting protection.
- Endpoint parsing strips URL schemes correctly (`http://svc:8080` → `svc:8080`); the
  naïve regex in the original prototype matched the scheme as the hostname.

### Known limitations
- S2 full Service-catalog resolution, Gateway API routes, and ExternalName egress
  classification are partial. Sock-Shop-style hard-coded service names (no env
  endpoints) are not derived by S1. See `docs/ROADMAP.md`.
