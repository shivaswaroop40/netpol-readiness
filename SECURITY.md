# Security Policy

`npready` ships a network-reachability **attack roster** (the `attacks/` Helm chart).
It is a defensive validation tool — the probes connect and report, they do not
exploit — but because it deploys workloads into a cluster and is used in security
testing, we take its safety seriously. Please read [`THREAT_MODEL.md`](THREAT_MODEL.md)
for exactly what the probes do and the safeguards around them.

## Supported versions

This is a pre-1.0 research artifact. Security fixes are applied to the latest
released `0.x` line only.

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1 | ❌ |

## Reporting a vulnerability

Please report security issues **privately**, not as a public GitHub issue.

- Preferred: open a private **GitHub Security Advisory** on this repository
  (Security → Advisories → "Report a vulnerability").
- Include: affected file/version, a description, and a reproduction if possible.

We aim to acknowledge within a few days. Because this is an academic project, please
allow reasonable time for a fix before any public disclosure.

## In scope

- Any way the analysis code (`src/npready/`) could mutate a cluster, leak
  credentials, or execute untrusted input (it is designed to be read-only and to
  never shell out except for `kubectl get`).
- Any way the attack Helm chart could exceed its stated behaviour — e.g. a crafted
  `values.yaml` achieving code execution beyond a benign probe, escaping the
  disposable namespace, or persisting access. (A prior audit closed a shell-injection
  path here; see `CHANGELOG.md`.)

## Out of scope

- The attacks the roster is *designed* to perform against a cluster **you are
  authorised to test**. Reachability results are the intended output.
- Findings that require already-privileged access the tool does not grant.
