#!/usr/bin/env bash
# =============================================================================
# azure/run_shapley.sh — runs on rszt-shapley (Azure account B), as the
# rszt-shapley.service systemd unit (Restart=on-failure, forever).
#
# PARALLELIZED: launches NUM_WORKERS workers on this one VM. Each worker
# gets its OWN:
#   - CLUSTER_NAME + KUBECONFIG  (own KIND cluster)
#   - K3S_INSTANCE (-> own K3S_SERVICE systemd unit, own data-dir/port/
#     config-dir, own ZT_K3S_KUBECONFIG — see Infra/k3s/bootstrap.sh and
#     Controls/c-l2-audit/apply.sh's K3S_SERVICE parameterization)
#   - ZT_RESULTS_DB (own SQLite file)
#   - a disjoint slice of each mode's Monte-Carlo draw list, via
#     --shard-index/--shard-count (driver.py's shard(), samples[i::n] —
#     every worker computes the same full draw list from the same seed
#     and just keeps its own slice, so draws are covered exactly once
#     with zero coordination between workers)
# All workers share the same persisted RUN_ID.
#
# NOTE on Infra/k3s/bootstrap.sh's multi-instance mechanism (INSTALL_K3S_NAME
# + --data-dir + --https-listen-port + --config): this has NOT been
# validated against a live install in the environment this was written in
# (no network egress to get.k3s.io there). Recommend a smoke test with
# NUM_WORKERS=2 before trusting a multi-day unattended run across more.
#
# Only self-deallocates once every worker's all three modes have completed.
# Any failure exits non-zero without deallocating, so systemd retries in
# place; per-worker per-mode sentinel files mean a retry skips whatever
# that worker already finished.
#
# One-time setup (see azure/install_service.sh):
#   sudo NUM_WORKERS=3 azure/install_service.sh rszt-shapley
# =============================================================================
set -uo pipefail
cd /opt/rszt

NUM_WORKERS="${NUM_WORKERS:-3}"

mkdir -p /opt/rszt/logs /opt/rszt/results /opt/rszt/kubeconfigs
RUN_ID_FILE=/opt/rszt/results/.shapley_run_id

if [[ -f "$RUN_ID_FILE" ]]; then
  RUN_ID="$(cat "$RUN_ID_FILE")"
  echo "[run_shapley] resuming existing RUN_ID=$RUN_ID (from $RUN_ID_FILE)"
else
  RUN_ID="${RUN_ID:-shapley_$(date +%Y%m%d_%H%M%S)}"
  echo "$RUN_ID" > "$RUN_ID_FILE"
  echo "[run_shapley] starting new RUN_ID=$RUN_ID (persisted to $RUN_ID_FILE)"
fi

worker() {
  local i="$1"                       # 0-based worker index
  local k3s_instance=$((i + 1))      # bootstrap.sh's K3S_INSTANCE, 1-based
  local cluster="zt-lab-shap-${i}"
  local kubeconfig="/opt/rszt/kubeconfigs/shap-${i}.yaml"
  local db="/opt/rszt/results/shap-${i}/results.db"
  local logdir="/opt/rszt/logs/shap-${i}"
  mkdir -p "$(dirname "$db")" "$logdir"

  export CLUSTER_NAME="$cluster"
  export KUBECONFIG="$kubeconfig"
  export ZT_RESULTS_DB="$db"
  export K3S_INSTANCE="$k3s_instance"
  export K3S_SERVICE="k3s-${k3s_instance}"
  export K3S_CONFIG_DIR="/etc/rancher/${K3S_SERVICE}"
  export ZT_K3S_KUBECONFIG="/opt/rszt/Infra/k3s/k3s-${k3s_instance}.yaml"

  {
    echo "[worker $i] cluster=$cluster k3s_instance=$k3s_instance db=$db"
    echo "[worker $i] bootstrapping KIND cluster (idempotent)"
    Infra/KIND/setup.sh all

    echo "[worker $i] bootstrapping k3s instance ${K3S_SERVICE} (idempotent)"
    Infra/k3s/bootstrap.sh
  } 2>&1 | tee -a "$logdir/setup.log"
  local setup_rc=${PIPESTATUS[0]}
  if [[ "$setup_rc" -ne 0 ]]; then
    echo "[worker $i] cluster setup failed rc=$setup_rc" | tee -a "$logdir/setup.log"
    return "$setup_rc"
  fi

  run_mode() {
    local mode="$1"
    local sentinel="/opt/rszt/results/shap-${i}/.${mode//-/_}_done"
    if [[ -f "$sentinel" ]]; then
      echo "[worker $i] mode=$mode already completed — skipping"
      return 0
    fi
    echo "[worker $i] === mode: $mode (shard $i/$NUM_WORKERS) ==="
    python3 Driver/driver.py --mode "$mode" --run-id "$RUN_ID" \
      --shard-index "$i" --shard-count "$NUM_WORKERS" \
      2>&1 | tee -a "$logdir/${mode//-/_}.log"
    local rc=${PIPESTATUS[0]}
    echo "[worker $i] mode=$mode rc=$rc"
    [[ "$rc" -eq 0 ]] && date > "$sentinel"
    return "$rc"
  }

  local worker_rc=0
  run_mode mc-pairs   || worker_rc=$?
  run_mode dl-robust  || worker_rc=$?
  run_mode l2-l3a-sep || worker_rc=$?
  return "$worker_rc"
}

PIDS=()
for i in $(seq 0 $((NUM_WORKERS - 1))); do
  worker "$i" &
  PIDS+=($!)
done

FINAL_RC=0
for pid in "${PIDS[@]}"; do
  wait "$pid" || FINAL_RC=$?
done

echo "[run_shapley] all workers exited, overall rc=$FINAL_RC"

if [[ "$FINAL_RC" -ne 0 ]]; then
  echo "[run_shapley] at least one worker/mode failed — NOT deallocating, leaving VM up" \
       "for systemd to retry (RUN_ID=$RUN_ID, completed worker/mode pairs skipped via sentinels)"
  exit "$FINAL_RC"
fi

echo "[run_shapley] COMPLETE — merging ${NUM_WORKERS} per-worker DBs into results/results.db"
rm -f /opt/rszt/results/results.db
WORKER_DBS=(/opt/rszt/results/shap-*/results.db)
python3 azure/merge_results.py "${WORKER_DBS[@]}" --out /opt/rszt/results/results.db

echo "[run_shapley] authenticating with VM managed identity to self-deallocate"
az login --identity >/dev/null
RG=$(curl -sH Metadata:true \
  "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text")
VM=$(curl -sH Metadata:true \
  "http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01&format=text")
echo "[run_shapley] deallocating $VM in $RG"
az vm deallocate -g "$RG" -n "$VM" --no-wait

exit 0
