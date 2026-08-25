#!/usr/bin/env bash
# Fetch a diverse set of real app manifests for the wide-n stress test.
set -u
export DOCKER_CONFIG=/tmp/empty_docker_cfg
D=/tmp/widen-apps
mkdir -p "$D"; cd "$D"
ok(){ [ -s "$1" ] && grep -q 'kind:' "$1" && echo "  OK $1 ($(grep -c 'kind:' "$1") objects)" || echo "  FAIL $1"; }

echo "== raw-manifest demo apps =="
curl -fsSL -m30 "https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/main/release/kubernetes-manifests.yaml" -o online-boutique.yaml 2>/dev/null; ok online-boutique.yaml
curl -fsSL -m30 "https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/platform/kube/bookinfo.yaml" -o bookinfo.yaml 2>/dev/null; ok bookinfo.yaml
curl -fsSL -m30 "https://raw.githubusercontent.com/microservices-demo/microservices-demo/master/deploy/kubernetes/complete-demo.yaml" -o sock-shop.yaml 2>/dev/null; ok sock-shop.yaml
curl -fsSL -m30 "https://raw.githubusercontent.com/kubernetes/examples/master/guestbook/all-in-one/guestbook-all-in-one.yaml" -o guestbook.yaml 2>/dev/null; ok guestbook.yaml
curl -fsSL -m30 "https://raw.githubusercontent.com/stefanprodan/podinfo/master/kustomize/deployment.yaml" -o podinfo.yaml 2>/dev/null; ok podinfo.yaml

echo "== helm-templated charts (StatefulSet clusters + env-DB apps) =="
helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null 2>&1
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1
helm repo update >/dev/null 2>&1
helm template r bitnami/redis --set architecture=replication > redis.yaml 2>/dev/null; ok redis.yaml
helm template pg bitnami/postgresql-ha > postgres-ha.yaml 2>/dev/null; ok postgres-ha.yaml
helm template rmq bitnami/rabbitmq --set replicaCount=3 > rabbitmq.yaml 2>/dev/null; ok rabbitmq.yaml
helm template kf bitnami/kafka > kafka.yaml 2>/dev/null; ok kafka.yaml
helm template mg bitnami/mongodb --set architecture=replicaset > mongodb.yaml 2>/dev/null; ok mongodb.yaml
helm template wp bitnami/wordpress > wordpress.yaml 2>/dev/null; ok wordpress.yaml
helm template wp bitnami/wordpress --set ingress.enabled=true --set ingress.hostname=wp.local > wordpress-ingress.yaml 2>/dev/null; ok wordpress-ingress.yaml
helm template gh bitnami/ghost --set ingress.enabled=true --set ingress.hostname=blog.local > ghost.yaml 2>/dev/null; ok ghost.yaml
helm template kp prometheus-community/kube-prometheus-stack > kube-prometheus.yaml 2>/dev/null; ok kube-prometheus.yaml

echo "== fetched apps =="
ls -1 *.yaml | while read f; do echo "  $f"; done
echo "count: $(ls -1 *.yaml | wc -l | tr -d ' ')"
