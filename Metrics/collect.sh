#!/usr/bin/env bash
# =============================================================================
# metrics/collect.sh — telemetry snapshot collector
#
# Captures the telemetry that the (deferred) ML detective layer will later
# consume, and that the paper uses for the detection-latency / overhead metrics.
# Pulls from the four live sources and drops timestamped artifacts under
# metrics/ and logs/. Safe to call between configs or ad hoc.
#
# CLUSTER_NAME (env, default "zt-lab") — matches every other script that
# targets a specific KIND cluster's control-plane container (Controls/
# c1-l1/apply.sh+remove.sh, Infra/KIND/recover.sh, driver.py's
# detect_applied_layers()). Previously hardcoded to "zt-lab-control-plane"
# here specifically, unlike everywhere else — would fail outright ("No such
# container") or silently collect from the wrong cluster when run against
# any parallel worker's non-default CLUSTER_NAME (e.g. zt-lab-canon-2,
# zt-lab-shap-1). KUBECONFIG is also respected implicitly via kubectl's own
# env lookup, same as every other script here — no explicit --kubeconfig
# flag needed, just make sure it's exported before calling this.
#
#   usage: CLUSTER_NAME=zt-lab-canon-2 KUBECONFIG=... bash metrics/collect.sh [label]
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-zt-lab}"
CP_CONTAINER="${CLUSTER_NAME}-control-plane"
# Default label includes CLUSTER_NAME so two workers calling this
# concurrently on the same VM (with different CLUSTER_NAME/KUBECONFIG, per
# azure/run_canonical.sh's / run_shapley.sh's worker model) never collide on
# the same output directory even if neither passes an explicit label.
LABEL="${1:-snapshot-${CLUSTER_NAME}}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${REPO_ROOT}/metrics/${LABEL}-${TS}"
mkdir -p "$OUT" "${REPO_ROOT}/logs"

echo "[metrics] cluster=${CLUSTER_NAME} collecting telemetry snapshot -> $OUT"

# 1. Kubernetes audit log (from control-plane node)
docker exec "$CP_CONTAINER" sh -c 'cat /var/log/kubernetes/audit.log 2>/dev/null' \
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
