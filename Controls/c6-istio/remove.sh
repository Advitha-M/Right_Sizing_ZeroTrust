#!/usr/bin/env bash
# =============================================================================
# C3 remove — tear down Istio enforcement
#  - delete PeerAuthentication + AuthorizationPolicies
#  - remove injection label and restart workloads so sidecars are removed
#    (returns service traffic to plaintext / no-L7-authz baseline)
# =============================================================================
set -uo pipefail
TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)

echo "[c6-istio] deleting AuthorizationPolicies + PeerAuthentication"
kubectl delete authorizationpolicy -A -l zt-control=c6-istio --ignore-not-found 2>/dev/null || true
kubectl delete peerauthentication  -A -l zt-control=c6-istio --ignore-not-found 2>/dev/null || true

echo "[c6-istio] removing injection labels + restarting workloads (sidecars out)"
for T in "${TENANTS[@]}"; do
  kubectl label namespace "$T" istio-injection- >/dev/null 2>&1 || true
  kubectl rollout restart deployment -n "$T" >/dev/null 2>&1 || true
done
for T in "${TENANTS[@]}"; do
  { kubectl rollout status deployment -n "$T" --timeout=60s >/dev/null 2>&1 \
    || echo "[c6-istio]   (warn) $T workloads slow to roll — continuing"; } &
done
wait

echo "[c6-istio] REMOVED"
