# Positioning & prior art

This document exists so that no claim in this project overstates its novelty. It is
based on a systematic review of the attack-simulation and network-policy-testing
ecosystems (verified against the GitHub API and primary sources, 2026-08).

## The one-sentence honest claim

> No existing artifact packages **network-reachability attacks declaratively for
> deployment into a cluster to validate NetworkPolicy enforcement**, and no existing
> tool surfaces the **config-derived `missing`-edge (would-break-on-enforce)**
> analysis. `npready` contributes exactly these two, and an evaluation framework
> that scores generator output on the safe-to-enforce axis.

## Two claims we explicitly do NOT make

1. **"Nobody does reachability truth tables."** [`cyclonus`](https://github.com/mattfenwick/cyclonus)
   does, thoroughly, and so does the upstream Kubernetes e2e suite (KEP-1611). We
   differentiate on **oracle** (threat model vs. spec-conformance), **fixture** (real
   workloads vs. a synthetic 9-pod grid), and **probe vocabulary** (attack behaviours
   vs. bare L4 connects).

2. **"Nobody tests netpols declaratively."** [`netassert v2`](https://github.com/controlplaneio/netassert)
   (ControlPlane, actively maintained) does. We differentiate on **attack semantics
   beyond L4**, an **ATT&CK-mapped scenario library**, and **in-cluster deployable
   delivery** (netassert is an external CLI injecting ephemeral containers).

## Landscape

### Attack-simulation tools — target the control plane / host, not the network
| tool | network reachability? | form |
|---|---|---|
| Stratus Red Team | no (0/8 k8s techniques) | external CLI |
| Atomic Red Team (Containers) | barely (1 of ~14: T1105 egress) | PowerShell executor |
| KubeHound | no (static attack graph; models no NetworkPolicy) | analysis, executes nothing |
| Peirates / CDK | yes, but interactive operator-driven | binary in a compromised pod |
| kube-hunter | best coverage — but **deprecated** (Nov 2023), no successor | in-cluster Job |

They exercise RBAC, secrets, tokens, the API server, and host escape — classes a
NetworkPolicy cannot affect — and are CLI/operator-driven, not declarative.

### Network-policy testing tools — test the spec, not a threat model
| tool | what it checks | oracle | fixture |
|---|---|---|---|
| cyclonus | CNI implements the spec | its own policy engine | synthetic 9 pods |
| netassert v2 | asserted connectivity holds | hand-written expectations | your workloads (ephemeral containers) |
| illuminatio | tests derived from existing policies | the policies themselves | your workloads (**archived** 2025) |
| NP-Guard | static semantic analysis | policy semantics | none (static) |

None frames tests as adversary behaviour, maps to ATT&CK, or ships a scenario
library.

### Vendor "validate before enforce" — observational, can't see un-happened traffic
Cilium `--policy-audit-mode` and Calico `StagedNetworkPolicy` show what *would* drop
based on **real traffic**. They are the closest thing to enforcement-readiness in
production — and their blind spot is exactly ours to fill: **they cannot tell you
about an edge that never fired in the observation window.** `npready`'s config
derivation catches precisely those declared-but-unobserved edges.

### Closest academic work
- **Inside Job** (Bufalino et al., *Proc. ACM Networking* 2025, arXiv:2506.21134) —
  reachability analysis over 287 apps, anchored on the Microsoft Threat Matrix
  "cluster-internal networking" technique. Does **reachability analysis, not attack
  simulation**; releases **no tool**.
- **Budigiri et al.** (IEEE EuCNC 2021) — attacker model + qualitative security
  analysis of NetworkPolicy; states it is "not a silver bullet". No taxonomy mapping,
  no artifact.
- Policy **generators** (Kunerva, KubeTeus, KubeGuard, AutoSeg) evaluate on flow
  coverage / rule count / latency — **none executes an attack**.

**Verified gap:** no prior work joins an attack taxonomy to empirically-measured
NetworkPolicy prevention by executing attacks against enforced policies. That is the
niche this artifact and its thesis occupy.

## Taxonomy honesty (why the roster is organised by edge class)

A NetworkPolicy is an L3/L4 allow-list. Of the OWASP Kubernetes Top Ten, exactly one
item is the network-segmentation control (**K07 in the 2022 list, renumbered K05 in
2025**), plus one partial (cluster-to-cloud lateral movement, egress only). The
web-application OWASP Top 10 is **not** the right taxonomy — a policy cannot stop
injection or broken access control, which ride authorized connections (the single
thread is SSRF → metadata egress).

In MITRE ATT&CK for Containers (v19), the Lateral Movement tactic contains one
technique with **no** network mitigation, and T1210 is absent — so "segmentation
stops lateral movement" maps to **Discovery (T1046/T1613) + re-exploitation**, not
the LM column. NetworkPolicy's two mitigations are **M1030** (Network Segmentation)
and **M1035** (Limit Access to Resource Over Network); its strongest real value is
**egress** (metadata theft T1552.005, exfil T1048), a class the Containers matrix
barely models. Every family in [`../src/npready/attacks.py`](../src/npready/attacks.py)
records its technique, matrix, mitigation, and the taxonomy caveat.

## Do-not-cite list (verified nonexistent / fabricated)
- `github.com/UK-IPOP/network-policy-validator` — 404, fabricated by a search result.
- `github.com/bust-a-kube-org/bust-a-kube` — does not exist; only VM images at
  bustakube.com, no source repo, no license.
