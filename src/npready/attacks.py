"""The attack roster: the taxonomy the Helm chart deploys.

Design principle — a NetworkPolicy is an L3/L4 allow-list. It can only stop an
attack that requires an *unauthorized network edge*. So the roster is organised by
EDGE CLASS (the reach a policy must deny), and each family is mapped to MITRE
ATT&CK **honestly**, including where the taxonomy does not fit.

Three findings from the taxonomy analysis are baked into these mappings, because a
reviewer will check them:

  1. The ATT&CK **Containers** matrix (v19, 2026) has 10 tactics and NO Command-and-
     Control, Exfiltration, or Reconnaissance. Egress attacks therefore map to the
     **Enterprise** matrix (T1048, T1552.005), not Containers — noted per family.

  2. The Containers **Lateral Movement** tactic contains a single technique
     (T1550.001) that carries NO network mitigation, and T1210 is not in the matrix.
     So "segmentation stops lateral movement" maps to **Discovery (T1046/T1613) +
     re-exploitation of the next hop**, not to the LM column. Family 03 records this.

  3. NetworkPolicy's two ATT&CK mitigations are **M1030 Network Segmentation** and
     **M1035 Limit Access to Resource Over Network** (plus M1037 for egress). We tag
     the mitigation, which is the rigorous claim, alongside the best-fit technique.

Families a NetworkPolicy CANNOT affect (RBAC, secrets-at-rest, supply chain, host
escape) are deliberately excluded; 08 is included only to document the hostNetwork
blind spot the Kubernetes docs call "undefined and implementation-specific".

Each family is realised as a Kubernetes Job (../attacks/templates) run from a probe
pod carrying a legitimate workload's identity (compromised-workload model). It
asserts whether the target edge is reachable and only reports — it never persists
access, and everything lives in a disposable, labelled namespace.
"""
from __future__ import annotations

# id           : stable family slug (matches Helm template + thesis harness)
# edge_class   : the reach a NetworkPolicy must deny (model.EdgeClass)
# technique    : best-fit MITRE technique id
# matrix       : which ATT&CK matrix the technique lives in
# mitigation   : the ATT&CK mitigation a NetworkPolicy provides (M-code) or None
# target       : concrete destination the probe attempts
# netpol_stops : the policy shape a readiness check must contain to block it
# note         : honest caveat about taxonomy fit / netpol limits
ROSTER = [
    {
        "id": "01-kubelet-rce",
        "edge_class": "in_cluster",
        "technique": "T1609",
        "technique_name": "Container Administration Command (kubelet)",
        "matrix": "containers",
        "mitigation": "M1035",
        "target": "node kubelet :10250",
        "netpol_stops": "deny pod -> node :10250 (note: kubelet is on hostNetwork; blocking is CNI-dependent)",
        "note": "Reaching :10250 also enables T1610 Deploy Container. hostNetwork target = partial coverage.",
    },
    {
        "id": "02-messagebus-abuse",
        "edge_class": "in_cluster",
        "technique": "T1046",
        "technique_name": "Network Service Discovery -> unauth service abuse",
        "matrix": "containers",
        "mitigation": "M1030",
        "target": "NATS :4222 (no credentials)",
        "netpol_stops": "restrict :4222 ingress to the pub/sub components",
        "note": "No dedicated Containers technique for message-bus abuse; the netpol-relevant step is the reach.",
    },
    {
        "id": "03-lateral-movement",
        "edge_class": "in_cluster",
        "technique": "T1046+T1552",
        "technique_name": "Discovery + cross-tier credential/data access",
        "matrix": "containers/enterprise",
        "mitigation": "M1030",
        "target": "postgres :5432 / vault :8200 cross-tier",
        "netpol_stops": "deny cross-tier pod -> datastore :5432, pod -> vault :8200",
        "note": "IMPORTANT: ATT&CK Containers LM tactic (T1550.001) has no network mitigation and T1210 "
                "is absent. Segmentation of lateral movement maps to Discovery + next-hop access, not the LM column.",
    },
    {
        "id": "04-metadata-egress",
        "edge_class": "egress",
        "technique": "T1552.005",
        "technique_name": "Unsecured Credentials: Cloud Instance Metadata API",
        "matrix": "enterprise",
        "mitigation": "M1035",
        "target": "169.254.169.254 :80",
        "netpol_stops": "egress deny to 169.254.169.254/32",
        "note": "Enterprise (IaaS platform), not in the Containers matrix. "
                "Primary fix is IAM; egress is the netpol lever.",
    },
    {
        "id": "05-unauthorized-api",
        "edge_class": "in_cluster",
        "technique": "T1552.007",
        "technique_name": "Unsecured Credentials: Container API",
        "matrix": "containers",
        "mitigation": "M1030+M1035",
        "target": "internal cluster-api :8000",
        "netpol_stops": "restrict :8000 ingress to ingress-controller + declared peers",
        "note": "Strong fit: MITRE lists both M1030 and M1035 for reachability to the API.",
    },
    {
        "id": "06-internal-recon",
        "edge_class": "in_cluster",
        "technique": "T1046",
        "technique_name": "Network Service Discovery",
        "matrix": "containers",
        "mitigation": "M1030",
        "target": "service/port sweep across namespaces",
        "netpol_stops": "default-deny ingress collapses the reachable surface a sweep can find",
        "note": "The canonical microsegmentation win — the clearest technique->control mapping.",
    },
    # --- coverage gaps found by the reproducibility work; the strongest additions ---
    {
        "id": "07-egress-exfil",
        "edge_class": "egress",
        "technique": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "matrix": "enterprise",
        "mitigation": "M1030",
        "target": "outbound to an attacker-controlled host :443",
        "netpol_stops": "default-deny egress (almost never written — the real, under-tested gap)",
        "note": "Containers matrix omits the Exfiltration tactic; this is the Enterprise technique. "
                "Kubesonde: none of 200 apps restricted outbound to the Internet.",
    },
    {
        "id": "08-hostnetwork-bypass",
        "edge_class": "excluded",
        "technique": "T1611",
        "technique_name": "Escape to Host (context)",
        "matrix": "containers",
        "mitigation": None,
        "target": "hostNetwork pod reaching node-local services",
        "netpol_stops": "NOT expressible by NetworkPolicy",
        "note": "Included to document the blind spot: k8s docs call hostNetwork policy behaviour "
                "'undefined and implementation-specific'. A negative control for the harness.",
    },
]

# Families the thesis harness already executes (the reproduced result set).
IMPLEMENTED = {"01-kubelet-rce", "02-messagebus-abuse", "03-lateral-movement",
               "04-metadata-egress", "05-unauthorized-api", "06-internal-recon"}

# OWASP Kubernetes Top Ten item this whole roster addresses. The list was
# renumbered in 2025 — cite the version explicitly.
OWASP_K8S = {"2022": "K07 Missing Network Segmentation Controls",
             "2025": "K05 Missing Network Segmentation Controls"}


def roster_by_class() -> dict:
    out: dict = {}
    for f in ROSTER:
        out.setdefault(f["edge_class"], []).append(f)
    return out
