#!/usr/bin/env bash
# =============================================================================
# metrics/collect.sh — telemetry snapshot collector
#
# Captures the telemetry that the (deferred) ML detective layer will later
# consume, and that the paper uses for the detection-latency / overhead metrics.
# Pulls from the four live sources and drops timestamped artifacts under
# metrics/ and logs/. Safe to call between configs or ad hoc.
#
#   usage: bash metrics/collect.sh [label]
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="${1:-snapshot}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${REPO_ROOT}/metrics/${LABEL}-${TS}"
mkdir -p "$OUT" "${REPO_ROOT}/logs"

echo "[metrics] collecting telemetry snapshot -> $OUT"

# 1. Kubernetes audit log (from control-plane node)
docker exec zt-lab-control-plane sh -c 'cat /var/log/kubernetes/audit.log 2>/dev/null' \
  > "${OUT}/audit.log" 2>/dev/null || echo "[metrics] (warn) audit log unavailable"

# 2. Falco alerts (runtime syscalls)
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=2000 \
  > "${OUT}/falco.log" 2>/dev/null || echo "[metrics] (warn) Falco logs unavailable"

# 3. Hubble flows (network L3-L7) — last 1000 flows if hubble CLI/relay present
kubectl exec -n kube-system ds/cilium -- hubble observe --last 1000 \
  > "${OUT}/hubble-flows.txt" 2>/dev/null || echo "[metrics] (warn) Hubble flows unavailable"

# 4. Prometheus targets/metrics liveness snapshot
kubectl get --raw '/api/v1/namespaces/monitoring/services/monitoring-kube-prometheus-prometheus:9090/proxy/api/v1/query?query=up' \
  > "${OUT}/prometheus-up.json" 2>/dev/null || echo "[metrics] (warn) Prometheus query unavailable"

echo "[metrics] snapshot complete: $(ls -1 "$OUT" | wc -l) artifacts in $OUT"
