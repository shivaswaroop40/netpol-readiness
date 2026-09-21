#!/usr/bin/env bash
# Fetch a diverse set of real app manifests for the wide-n stress test.
#
# Reproducibility: raw manifests are pinned to a commit SHA and Helm charts to an
# explicit --version, so re-running reproduces the corpus that produced the
# committed results.json (captured 2026-08-31) rather than tracking upstream HEAD.
# Bump the pins deliberately, then regenerate results.json + FINDINGS.md together.
set -uo pipefail

# Corpus dir: default to a repo-local, git-ignored scratch dir (overridable), never
# a fixed world-writable /tmp path a co-tenant could pre-create or symlink.
D="${1:-${WIDEN_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_corpus}}"
# An empty docker config keeps `helm template` from reading ambient registry creds.
export DOCKER_CONFIG="${DOCKER_CONFIG:-$(mktemp -d)}"
mkdir -p "$D"; cd "$D" || exit 1
ok(){ [ -s "$1" ] && grep -q 'kind:' "$1" && echo "  OK $1 ($(grep -c 'kind:' "$1") objects)" || echo "  FAIL $1"; }

# pinned upstream commit SHAs (raw manifests), resolved 2026-08-31
BOUTIQUE=72ba613a05f7fcee51cf1d0badff401b6ae7074d   # GoogleCloudPlatform/microservices-demo (Online Boutique)
BOOKINFO=3df24f85ae039073b970b81c18c94543f29ce9cb   # istio/istio (Bookinfo)
SOCKSHOP=9dff06fae4981921caec6a62393a6ebfce4b3e3f   # microservices-demo (Sock Shop)
GUESTBOOK=d6b8cd27eacb51e651a1aa6f7c190a28713eff6e   # kubernetes/examples
PODINFO=28ade761521df82ceff420c978736b7719465ec3    # stefanprodan/podinfo

echo "== raw-manifest demo apps =="
curl -fsSL -m30 "https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/${BOUTIQUE}/release/kubernetes-manifests.yaml" -o online-boutique.yaml 2>/dev/null; ok online-boutique.yaml
curl -fsSL -m30 "https://raw.githubusercontent.com/istio/istio/${BOOKINFO}/samples/bookinfo/platform/kube/bookinfo.yaml" -o bookinfo.yaml 2>/dev/null; ok bookinfo.yaml
curl -fsSL -m30 "https://raw.githubusercontent.com/microservices-demo/microservices-demo/${SOCKSHOP}/deploy/kubernetes/complete-demo.yaml" -o sock-shop.yaml 2>/dev/null; ok sock-shop.yaml
curl -fsSL -m30 "https://raw.githubusercontent.com/kubernetes/examples/${GUESTBOOK}/guestbook/all-in-one/guestbook-all-in-one.yaml" -o guestbook.yaml 2>/dev/null; ok guestbook.yaml
curl -fsSL -m30 "https://raw.githubusercontent.com/stefanprodan/podinfo/${PODINFO}/kustomize/deployment.yaml" -o podinfo.yaml 2>/dev/null; ok podinfo.yaml

echo "== helm-templated charts (StatefulSet clusters + env-DB apps) =="
# chart versions pinned for reproducibility (bitnami OCI + prometheus-community)
helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null 2>&1
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1
helm repo update >/dev/null 2>&1
helm template r bitnami/redis --version 20.1.0 --set architecture=replication > redis.yaml 2>/dev/null; ok redis.yaml
helm template pg bitnami/postgresql-ha --version 14.2.0 > postgres-ha.yaml 2>/dev/null; ok postgres-ha.yaml
helm template rmq bitnami/rabbitmq --version 14.7.0 --set replicaCount=3 > rabbitmq.yaml 2>/dev/null; ok rabbitmq.yaml
helm template kf bitnami/kafka --version 30.0.0 > kafka.yaml 2>/dev/null; ok kafka.yaml
helm template mg bitnami/mongodb --version 15.6.0 --set architecture=replicaset > mongodb.yaml 2>/dev/null; ok mongodb.yaml
helm template wp bitnami/wordpress --version 23.1.0 > wordpress.yaml 2>/dev/null; ok wordpress.yaml
helm template wp bitnami/wordpress --version 23.1.0 --set ingress.enabled=true --set ingress.hostname=wp.local > wordpress-ingress.yaml 2>/dev/null; ok wordpress-ingress.yaml
helm template gh bitnami/ghost --version 22.0.0 --set ingress.enabled=true --set ingress.hostname=blog.local > ghost.yaml 2>/dev/null; ok ghost.yaml
helm template kp prometheus-community/kube-prometheus-stack --version 62.3.0 > kube-prometheus.yaml 2>/dev/null; ok kube-prometheus.yaml

echo "== fetched apps =="
ls -1 ./*.yaml | while read -r f; do echo "  $f"; done
echo "count: $(ls -1 ./*.yaml | wc -l | tr -d ' ')"
echo "corpus dir: $D"
