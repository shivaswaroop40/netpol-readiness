# Threat model & responsible use

`npready` ships an attack roster. This document states precisely what it does, what
it deliberately does not do, and the safeguards that make it safe to run.

## What the probes are

Each family in the `./attacks` Helm chart is a **benign probe**: it opens a TCP
connection (`nc -z`) or an HTTP request (`wget`) to a target and reports **OPEN** or
**BLOCKED**. That is the whole behaviour.

## What the probes deliberately are NOT

- **Not exploits.** No RCE, no payload delivery, no credential use, no data read.
  A probe that reaches kubelet:10250 reports "OPEN"; it does not execute anything.
- **Not persistent.** `restartPolicy: Never`, `backoffLimit: 0`, and
  `ttlSecondsAfterFinished` auto-delete finished Jobs. No workload is left running.
- **Not privileged.** Every probe pod runs `runAsNonRoot`, drops **all** Linux
  capabilities, uses a read-only root filesystem, and sets
  `automountServiceAccountToken: false` — it holds no Kubernetes credentials.
- **Not broad.** Everything is confined to a single, clearly-labelled, disposable
  namespace (`npready-attacks` by default), never your application namespace.
- **Not exfiltrating.** The egress families target the cloud metadata IP or a
  configured stand-in host and report reachability; they transmit no cluster data.

## Safeguards (defence in depth)

| safeguard | mechanism |
|---|---|
| blast-radius containment | dedicated disposable namespace, labelled `npready.dev/disposable=true` |
| no privilege | non-root, `drop: [ALL]`, read-only rootfs, no SA token |
| fail-closed | `backoffLimit: 0`, `activeDeadlineSeconds`, short per-connect timeout |
| auto-cleanup | `ttlSecondsAfterFinished`, `helm uninstall` |
| explicit targets | every non-recon family is `enabled: false` by default and must be pointed at a real target you own |
| **no code injection from values** | target host/port/url reach the probe as **env vars** (Kubernetes delivers them as literal strings; the probe script interpolates *no* chart values and quotes every input), and `values.schema.json` rejects any `host`/`port`/`url` that is not a well-formed hostname/IP/integer/URL at render time. A crafted `values.yaml` cannot inject shell commands into the probe. |

### On trusting `values.yaml`

The probe script is static: it executes fixed shell text and reads the targets from
env vars, which are never shell-parsed. Combined with the JSON schema, a hostile or
mistyped target value fails at `helm template`/`install` time rather than becoming
code. This is what makes the "connect and report, never exploit" property hold even
when the target list comes from an untrusted source (a ticket, another team, a
generated manifest).

## Authorised-use expectation

Run `npready` only against clusters you own or are explicitly authorised to test.
The attack roster is a **defensive validation tool** — its purpose is to prove your
NetworkPolicies block what they should. Using reachability results to plan an actual
intrusion against a system you do not control is outside the intended use and may be
illegal.

## Reporting a security issue

If you find a way this tool could be misused beyond its stated probe behaviour, or a
vulnerability in the analysis code, please open a private security advisory on the
repository rather than a public issue.
