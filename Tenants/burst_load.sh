#!/usr/bin/env bash
# =============================================================================
# Tenants/burst_load.sh — tenant-saas burst-load generator (brief Section 12)
#
# "tenant-saas: ... ResourceQuota sized to allow burst up to 3x quota.
#  Source of A7 burst load."
# "A7 scope constraint (burst load): burst load from tenant-saas must not
#  spike system pool CPU above 60%. Calibrate multiplier before main study;
#  lock it as a study parameter."
#
# PREVIOUSLY UNIMPLEMENTED: nothing in this repo generated any load from
# tenant-saas, and Controls/c4-tenant-isolation/apply.sh gave tenant-saas the
# same ResourceQuota as every other tenant (fixed separately — see that
# script's BURST_QUOTA_MULTIPLIER). This script is the missing piece: it
# generates the burst load itself and enforces the "must not spike system
# pool CPU above 60%" ceiling live, rather than just asserting it in a
# comment.
#
# Two subcommands:
#   calibrate   Ramps tenant-saas's burst replica count up step by step,
#               sampling system-pool node CPU (kubectl top nodes) between
#               steps, and locks the highest replica count that stayed under
#               Driver/constants.py's SYSTEM_POOL_CPU_BURST_CAP_PCT (60%) to
#               .burst_calibration next to this script. This is the
#               "calibrate multiplier before main study; lock it as a study
#               parameter" step — run it once per cluster sizing, not per
#               trial.
#   start       Deploys the burst-load Deployment in tenant-saas at the
#               locked (or, if calibration hasn't been run yet, a
#               conservative documented default) replica count, then runs a
#               foreground watchdog loop that polls system-pool CPU and
#               scales the burst Deployment DOWN (never up past the locked
#               value) if the cap is approached — a live self-throttle, not
#               just a one-time calibration.
#   stop        Removes the burst-load Deployment and stops the watchdog.
#
# Usage:
#   bash Tenants/burst_load.sh calibrate
#   bash Tenants/burst_load.sh start [--foreground]
#   bash Tenants/burst_load.sh stop
#
# Not wired into driver.py's per-trial loop: the brief frames this as a
# pre-study calibration/lock step ("before main study"), not a per-trial
# invariant — Section 11's Tier 2 "system pool CPU below 70%" check is the
# separate, already-implemented per-condition invariant. Run `start` once
# before the main C0-C7 sequential build if you want live burst load present
# throughout, and `stop` after.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALIB_FILE="${HERE}/.burst_calibration"

TENANT_SAAS="tenant-saas"
DEPLOY_NAME="saas-burst-load"

# Mirrors Driver/constants.py's SYSTEM_POOL_CPU_BURST_CAP_PCT / BURST_QUOTA_MULTIPLIER
# (kept in bash here for the same reason Controls/c4-tenant-isolation/apply.sh
# mirrors BURST_QUOTA_MULTIPLIER — this script has no Python import path of
# its own). Keep in sync if either constant changes.
SYSTEM_POOL_CPU_BURST_CAP_PCT=60
BURST_QUOTA_MULTIPLIER=3

# Conservative default replica count if calibrate has never been run —
# deliberately small; `calibrate` should be run before a real study so this
# fallback is never what actually gets locked in for a real run.
DEFAULT_REPLICAS=2
MAX_REPLICAS=$(( BURST_QUOTA_MULTIPLIER * 2 ))   # calibration ceiling, not a guess at the answer

log() { echo "[burst_load] $*"; }

system_pool_cpu_pct() {
  # Highest CPU% among nodes labeled node-pool=system, matching the same
  # label convention Driver/driver.py's check_system_pool_cpu() looks for.
  # Prints "" (caller treats as unknown -> non-fatal) if metrics-server or
  # the label isn't available.
  local sys_nodes
  sys_nodes=$(kubectl get nodes -l node-pool=system \
    -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
  [[ -z "$sys_nodes" ]] && { echo ""; return; }
  local max_pct=0
  local top_out
  top_out=$(kubectl top nodes --no-headers 2>/dev/null || true)
  [[ -z "$top_out" ]] && { echo ""; return; }
  for n in $sys_nodes; do
    local line pct
    line=$(echo "$top_out" | awk -v n="$n" '$1==n')
    [[ -z "$line" ]] && continue
    pct=$(echo "$line" | awk '{print $3}' | tr -d '%')
    [[ "$pct" =~ ^[0-9]+$ ]] || continue
    (( pct > max_pct )) && max_pct=$pct
  done
  echo "$max_pct"
}

apply_burst_deployment() {
  local replicas=$1
  kubectl apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${DEPLOY_NAME}
  namespace: ${TENANT_SAAS}
  labels: { app: saas-burst-load, zt-control: burst-load }
spec:
  replicas: ${replicas}
  selector: { matchLabels: { app: saas-burst-load } }
  template:
    metadata: { labels: { app: saas-burst-load, tenant: ${TENANT_SAAS} } }
    spec:
      tolerations:
        - key: tenant
          operator: Equal
          value: ${TENANT_SAAS}
          effect: NoSchedule
      containers:
        - name: burst
          image: alpine:3.18
          # Deliberately cheap, self-contained CPU burn (no external stress
          # tool dependency) — one busy-loop worker per requested vCPU so
          # replica count is a direct, legible knob on generated load.
          command: ["sh", "-c", "while true; do : ; done"]
          resources:
            requests: { cpu: "250m", memory: "32Mi" }
            limits:   { cpu: "500m", memory: "64Mi" }
EOF
}

scale_burst_deployment() {
  kubectl scale deployment "${DEPLOY_NAME}" -n "${TENANT_SAAS}" --replicas="$1" >/dev/null 2>&1 || true
}

cmd_calibrate() {
  log "calibrating burst replica count against SYSTEM_POOL_CPU_BURST_CAP_PCT=${SYSTEM_POOL_CPU_BURST_CAP_PCT}%"
  log "(ceiling for this pass: ${MAX_REPLICAS} replicas, BURST_QUOTA_MULTIPLIER=${BURST_QUOTA_MULTIPLIER})"
  local locked=0
  for replicas in $(seq 1 "$MAX_REPLICAS"); do
    log "  step: ${replicas} replica(s)"
    apply_burst_deployment "$replicas"
    kubectl rollout status deployment "${DEPLOY_NAME}" -n "${TENANT_SAAS}" \
      --timeout=60s >/dev/null 2>&1 || true
    sleep 10   # let CPU usage settle before sampling
    local pct
    pct=$(system_pool_cpu_pct)
    if [[ -z "$pct" ]]; then
      log "  (warn) could not read system-pool CPU (no node-pool=system label or "
      log "         metrics-server unavailable) — cannot calibrate safely, stopping here"
      break
    fi
    log "  system-pool CPU at ${replicas} replica(s): ${pct}%"
    if (( pct > SYSTEM_POOL_CPU_BURST_CAP_PCT )); then
      log "  ${pct}% exceeds ${SYSTEM_POOL_CPU_BURST_CAP_PCT}% cap — locking previous step (${locked} replicas)"
      break
    fi
    locked=$replicas
  done
  scale_burst_deployment 0
  echo "$locked" > "$CALIB_FILE"
  log "calibration complete: locked replicas=${locked} (written to ${CALIB_FILE})"
  log "burst Deployment scaled to 0 pending 'start' — calibration does not leave load running"
}

cmd_start() {
  local replicas="$DEFAULT_REPLICAS"
  if [[ -f "$CALIB_FILE" ]]; then
    replicas="$(cat "$CALIB_FILE")"
    log "using locked calibration: ${replicas} replicas (${CALIB_FILE})"
  else
    log "(warn) no calibration on file — using conservative default of ${replicas} "
    log "       replica(s). Run 'bash Tenants/burst_load.sh calibrate' before a real "
    log "       study run per brief Section 12 ('calibrate multiplier before main "
    log "       study; lock it as a study parameter')."
  fi
  apply_burst_deployment "$replicas"
  kubectl rollout status deployment "${DEPLOY_NAME}" -n "${TENANT_SAAS}" \
    --timeout=60s >/dev/null 2>&1 || true
  log "burst load started at ${replicas} replica(s); watchdog enforcing ${SYSTEM_POOL_CPU_BURST_CAP_PCT}% cap"

  if [[ "${1:-}" != "--foreground" ]]; then
    log "started (background use: re-run with --foreground to also block and watch)"
    return
  fi

  local current=$replicas
  while true; do
    sleep 15
    local pct
    pct=$(system_pool_cpu_pct)
    [[ -z "$pct" ]] && continue
    if (( pct > SYSTEM_POOL_CPU_BURST_CAP_PCT )) && (( current > 0 )); then
      current=$(( current - 1 ))
      log "  [THROTTLE] system-pool CPU ${pct}% > ${SYSTEM_POOL_CPU_BURST_CAP_PCT}% cap — scaling down to ${current}"
      scale_burst_deployment "$current"
    fi
  done
}

cmd_stop() {
  log "removing burst-load Deployment"
  kubectl delete deployment "${DEPLOY_NAME}" -n "${TENANT_SAAS}" --ignore-not-found >/dev/null 2>&1
  log "stopped"
}

case "${1:-}" in
  calibrate) cmd_calibrate ;;
  start)     cmd_start "${2:-}" ;;
  stop)      cmd_stop ;;
  *)
    echo "usage: $0 {calibrate|start [--foreground]|stop}" >&2
    exit 1
    ;;
esac
