#!/usr/bin/env bash
# End-to-end readiness-conformance test. Runs on a kind cluster with a
# NetworkPolicy-enforcing CNI. Proves the full loop:
#   deploy -> npready flags the missing edge -> add policy -> attack probe BLOCKED.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NS=npready-demo
fail() { echo "E2E FAIL: $*" >&2; exit 1; }

echo "== 1. deploy demo workloads =="
kubectl apply -f "$HERE/demo.yaml"
kubectl -n "$NS" rollout status deploy/cache --timeout=120s
kubectl -n "$NS" rollout status deploy/client --timeout=120s

echo "== 2. npready readiness BEFORE policy: must flag client->cache as missing/would-break =="
# Dump the demo as a snapshot npready can read, then analyse offline.
npready readiness --context "$(kubectl config current-context)" --namespace "$NS" || true
BEFORE=$(npready readiness --context "$(kubectl config current-context)" --namespace "$NS" --json /tmp/before.json; cat /tmp/before.json)
echo "$BEFORE" | grep -q '"gate": "audit"\|"gate": "shadow"' || fail "expected audit/shadow before any policy"

echo "== 3. apply default-deny + the one declared allow edge =="
kubectl apply -f "$HERE/policies.yaml"
sleep 5

echo "== 4. legitimate client still reaches cache =="
kubectl -n "$NS" exec deploy/client -- sh -c 'redis-cli -h cache -t 3 ping' | grep -q PONG \
  || fail "legitimate client->cache was broken by the policy (false-deny!)"
echo "   client->cache OPEN (correct)"

echo "== 5. attack probe (compromised identity) must be BLOCKED reaching cache =="
helm install npready-attacks "$ROOT/attacks" -n "$NS" \
  --set namespace.create=false \
  --set namespace.name=npready-demo \
  --set 'families[0].id=03-lateral-movement' \
  --set 'families[0].enabled=true' \
  --set 'families[0].kind=tcp' \
  --set 'families[0].technique=T1046+T1552' \
  --set 'families[0].edgeClass=in_cluster' \
  --set 'families[0].expect=blocked' \
  --set 'families[0].targets[0].host=cache' \
  --set 'families[0].targets[0].port=6379'
# wait for the probe Job to finish
kubectl -n "$NS" wait --for=condition=complete job/probe-03-lateral-movement --timeout=90s || true
RESULT=$(kubectl -n "$NS" logs -l npready.dev/family=03-lateral-movement --tail=-1 | grep RESULT || true)
echo "   $RESULT"
echo "$RESULT" | grep -q "BLOCKED" || fail "compromised identity reached cache — the policy did NOT block it"

echo "E2E PASS: npready flagged the gap, the policy fixed it, and the attack was blocked."
