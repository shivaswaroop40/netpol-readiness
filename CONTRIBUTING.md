# Contributing

Thanks for looking. This is a research artifact aiming to become a maintainable
tool, so contributions that harden or generalise the core are especially welcome.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                     # all tests must pass
ruff check src tests       # lint must be clean
```

## Ground rules

- **Every behaviour change ships with a test.** The `tests/fixtures/mini_cluster.yaml`
  fixture is designed so each derivation source and each quadrant has a known,
  asserted outcome. Extend it rather than adding ad-hoc fixtures where possible.
- **Provenance is not optional.** A new derivation source must set a `Provenance` and
  a human-readable `evidence` string on every edge it emits.
- **Do not overclaim.** If you add a capability, update `docs/POSITIONING.md` and the
  Status table in the README honestly. Novelty claims are checked against prior art.
- **Attack families are probes, not exploits.** Any new family in the Helm chart must
  stay within the [THREAT_MODEL](THREAT_MODEL.md): connect + report, fail-closed,
  non-root, disposable namespace. Map it to a real MITRE technique and record the
  taxonomy caveat, as the existing families do.

## Adding a config-derivation source

1. Add a `Provenance.SN_*` value in `model.py`.
2. Add an `sN_*(inv, ...)` function in `graph.py` returning `list[Edge]`.
3. Wire it into `derive_needed`.
4. Add a workload/resource to the fixture and a `test_graph.py::test_sN_*` asserting
   the exact edge it should produce.

## Commit style

Small, focused commits. Explain *why* in the body, not just *what*.
