## What this changes

Brief description, and *why*.

## Checklist

- [ ] Tests added/updated and `pytest` passes
- [ ] `ruff check src tests` is clean
- [ ] If a behaviour changed, docs updated (README status table / relevant `docs/`)
- [ ] New derivation source sets a `Provenance` and `evidence` on every edge
- [ ] New attack family stays a probe (connect + report), maps to a MITRE technique,
      and keeps the fail-closed / non-root / disposable-namespace guarantees
- [ ] No overclaim: `docs/POSITIONING.md` and the README Status table stay honest
