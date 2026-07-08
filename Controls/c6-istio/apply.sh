#!/usr/bin/env bash
# c6-istio/apply.sh — Istio STRICT mTLS + AuthorizationPolicies (Rev6)
# Extended timeouts to prevent rc=124 under KIND + istiod readiness gate.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)

echo "[c6-istio][$(date +%H:%M:%S)] START — labelling tenant namespaces for sidecar injection"
for T in "${TENANTS[@]}"; do
  kubectl label namespace "$T" istio-injection=enabled --overwrite 2>/dev/null || true
done
echo "[c6-istio][$(date +%H:%M:%S)] DONE — namespace labelling"

echo "[c6-istio][$(date +%H:%M:%S)] START — rollout restart tenant workloads (4 namespaces)"
for T in "${TENANTS[@]}"; do
  echo "[c6-istio][$(date +%H:%M:%S)]   restarting $T"
  kubectl rollout restart deployment -n "$T" 2>/dev/null || true
done
echo "[c6-istio][$(date +%H:%M:%S)] DONE — rollout restarts issued"

echo "[c6-istio][$(date +%H:%M:%S)] START — waiting for istiod ready (120s)"
kubectl rollout status deployment/istiod -n istio-system --timeout=120s 2>/dev/null \
  || echo "[c6-istio][$(date +%H:%M:%S)] (warn) istiod readiness not confirmed — proceeding"
echo "[c6-istio][$(date +%H:%M:%S)] DONE — istiod readiness gate"

echo "[c6-istio][$(date +%H:%M:%S)] START — rollout status per namespace (90s each, 300s global deadline)"
DEADLINE=$(( $(date +%s) + 300 ))
for T in "${TENANTS[@]}"; do
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then
    echo "[c6-istio][$(date +%H:%M:%S)] global deadline hit — skipping remaining namespace checks"
    break
  fi
  echo "[c6-istio][$(date +%H:%M:%S)]   waiting $T"
  timeout 90 kubectl rollout status deployment -n "$T" 2>/dev/null \
    || echo "[c6-istio][$(date +%H:%M:%S)] (warn) $T rollout status timed out/incomplete — continuing"
  echo "[c6-istio][$(date +%H:%M:%S)]   done $T"
done
echo "[c6-istio][$(date +%H:%M:%S)] DONE — all namespace rollout status checks"

echo "[c6-istio][$(date +%H:%M:%S)] START — verifying tenant pods Running post-restart"
for T in "${TENANTS[@]}"; do
  running=$(kubectl get pods -n "$T" --field-selector=status.phase=Running \
    --no-headers 2>/dev/null | wc -l)
  echo "[c6-istio][$(date +%H:%M:%S)]   $T: $running Running pods"
done
echo "[c6-istio][$(date +%H:%M:%S)] DONE — pod count verification"

echo "[c6-istio][$(date +%H:%M:%S)] START — applying STRICT mTLS + AuthorizationPolicies (90s timeout)"
timeout 90 kubectl apply -f "${HERE}/authz.yaml" \
  || { echo "[c6-istio][$(date +%H:%M:%S)] ERROR: authz.yaml apply failed"; exit 1; }
echo "[c6-istio][$(date +%H:%M:%S)] DONE — authz.yaml applied"

echo "[c6-istio][$(date +%H:%M:%S)] START — policy propagation sleep 15s"
sleep 15
echo "[c6-istio][$(date +%H:%M:%S)] DONE — policy propagation"
echo "[c6-istio][$(date +%H:%M:%S)] COMPLETE"
