# Roadmap

Honest view of what is built, what is partial, and what a credible OSS v1.0 needs.
Ordered by value-to-effort.

## Built (v0.2)
- Config derivation S1/S3/S4/S5/S6 with provenance; ports resolved to pod `targetPort`.
- Four-quadrant reconciliation + audit/shadow/enforce gate.
- Scoring + false-deny decomposition.
- **Fusion + coverage-by-source** (`npready fuse`): config vs observation vs their
  union against an observation-independent ground truth, with the `declared ∩ A = ∅`
  safety invariant checked (port granularity) and a `--granularity pair` view.
- Attack roster Helm chart (fail-closed probes).
- Tests + offline analysis + CI.

## Toward v1.0

### Generalise ground truth (the hard, important one) — ~3–4 weeks
The whole point is to remove hand-authored per-app edge sets. S1 covers twelve-factor
apps; apps that hard-code service names (e.g. Sock Shop) need fallbacks:
- S2 full Service-catalog resolution (any workload that mounts/references a Service).
- Static analysis of common client libraries / config maps for endpoints.
- **S7 — mounted config graphs (guarded).** Some apps declare their dependency graph
  in a mounted file (e.g. DeathStarBench social-network ships an all-to-all service
  map as JSON). Parsing it naively *over-declares* — it lists every service to every
  service — so this needs a whitelist-aware parser that keeps only edges corroborated
  by another surface, not a blind ingest. Measured boundary, not a guess (thesis C7).

The fusion primitive itself is now built (`npready fuse`); what remains is producing
the observed edge set automatically (an observer adapter, below) so fusion runs
end-to-end without a hand-supplied `--observed` file. The measured result is that the
union **equals the better source** and never beats it — its value is that which source
wins is not knowable in advance, so relying on either alone is unsafe.

### Package completeness — ~2 weeks
- **Ship the attack Helm chart inside the pip package.** Today the chart lives at
  `attacks/` in the source repo, so it's available to a git checkout / editable
  install but not to a plain `pip install` wheel. Relocate it under `src/npready/`
  and resolve it via `importlib.resources`, with an `npready attacks --emit DIR` to
  extract it, so PyPI users can deploy the probes too.
- In-cluster **results collector** for the attack chart: a small Job that scrapes all
  `RESULT ... OPEN|BLOCKED` lines and emits a single structured report + JUnit XML.
- Gateway API (`HTTPRoute`) and `ExternalName` egress edge classes.
- `EndpointSlice`-based peer resolution for headless services.

### Adapter interface — ~1 week
Formalise a plugin entry-point so a generator's output can be scored without editing
the tool: `npready score --adapter otterize --input map.json`.

### CI / conformance — ~1–2 weeks
- `kind`-based end-to-end job: deploy the mini-cluster, apply a policy, run the attack
  chart, assert the expected OPEN/BLOCKED matrix (a *readiness* conformance test,
  distinct from cyclonus's *spec* conformance).
- Publish to PyPI + a Helm repo.

### Docs / governance — ~1 week
- Security advisory process, `SECURITY.md`, signed releases.
- Worked examples for Sock Shop, Online Boutique, and a real platform.

## Explicit non-goals
- CNI-conformance testing (cyclonus owns this).
- L7 policy (NetworkPolicy is L3/L4; out of scope by construction).
- Exploit tooling (the roster stays probes-only; see THREAT_MODEL).
