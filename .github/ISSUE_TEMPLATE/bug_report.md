---
name: Bug report
about: A correctness problem in the analysis, CLI, or attack chart
title: "[bug] "
labels: bug
---

**What happened**
A clear description of the wrong behaviour.

**What you expected**
What the correct output should have been.

**Reproduce**
- Command run (e.g. `npready readiness --manifests ...`)
- Input: a minimal manifest / snapshot that triggers it, if possible
- `npready --version` and Python version

**Security impact?**
Does this cause a wrong "safe to enforce" verdict, or an admitted-vs-needed
misclassification? If so, note it — those are highest priority.
