#!/usr/bin/env bash
# =============================================================================
# azure/run_canonical.sh — runs on rszt-canonical (Azure account A), as the
# rszt-canonical.service systemd unit (Restart=on-failure, forever).
#
# PARALLELIZED: launches NUM_WORKERS independent KIND clusters on this one
# VM (docker supports many KIND clusters on one host fine; the constraint
# is CPU/RAM, tune NUM_WORKERS to the VM size). Each worker gets its own:
#   - CLUSTER_NAME (own KIND cluster, own control-plane container — see
#     Infra/preflight.sh's parametrized _pf_ensure_kind_cluster())
#   - KUBECONFIG (own file, so kubectl/docker-exec-derived commands never
#     cross-talk between workers)
#   - ZT_RESULTS_DB (own SQLite file — concurrent writers to ONE file on
#     one VM has the same problem as concurrent writers across VMs)
#   - a disjoint slice of --configs (C0..C7 round-robin across workers, so
#     the two resumability fixes — real-cluster-state layer detection and
#     per-(run_id,config,attack) trial resume — still apply per worker
#     exactly as before; workers never touch each other's configs so
#     there's no shared mutable state to race on)
# All workers share the same persisted RUN_ID (see run_shapley.sh's header
# for why that matters across restarts).
#
# Only self-deallocates once EVERY worker exits 0. Any worker failing exits
# this whole script non-zero without deallocating, so systemd retries in
# place — already-completed workers just fast-forward through their
# finished configs again (cheap: set_config() is idempotent, trial-resume
# skips already-recorded trials).
#
# One-time setup (see azure/install_service.sh):
#   sudo NUM_WORKERS=4 azure/install_service.sh rszt-canonical
# (NUM_WORKERS can also be set permanently via the systemd unit's
# Environment= line instead of passing it ad hoc.)
# =============================================================================
set -uo pipefail
cd /opt/rszt

NUM_WORKERS="${NUM_WORKERS:-4}"
CONFIGS=(C0 C1 C2 C3 C4 C5 C6 C7)

mkdir -p /opt/rszt/logs /opt/rszt/results /opt/rszt/kubeconfigs
RUN_ID_FILE=/opt/rszt/results/.canonical_run_id

if [[ -f "$RUN_ID_FILE" ]]; then
  RUN_ID="$(cat "$RUN_ID_FILE")"
  echo "[run_canonical] resuming existing RUN_ID=$RUN_ID (from $RUN_ID_FILE)"
else
  RUN_ID="${RUN_ID:-canonical_$(date +%Y%m%d_%H%M%S)}"
  echo "$RUN_ID" > "$RUN_ID_FILE"
  echo "[run_canonical] starting new RUN_ID=$RUN_ID (persisted to $RUN_ID_FILE)"
fi

worker() {
  local i="$1"
  local cluster="zt-lab-canon-${i}"
  local kubeconfig="/opt/rszt/kubeconfigs/canon-${i}.yaml"
  local db="/opt/rszt/results/canon-${i}/results.db"
  local log="/opt/rszt/logs/canonical_worker${i}_$(date +%Y%m%d_%H%M%S).log"
  mkdir -p "$(dirname "$db")"

  # This worker's slice of C0..C7 — round-robin, e.g. NUM_WORKERS=4 gives
  # worker0={C0,C4}, worker1={C1,C5}, worker2={C2,C6}, worker3={C3,C7}.
  local my_configs=()
  local idx=0
  for c in "${CONFIGS[@]}"; do
    if (( idx % NUM_WORKERS == i )); then my_configs+=("$c"); fi
    idx=$((idx + 1))
  done
  if [[ ${#my_configs[@]} -eq 0 ]]; then
    echo "[worker $i] NUM_WORKERS=$NUM_WORKERS > ${#CONFIGS[@]} configs — nothing assigned, idle" \
      | tee -a "$log"
    return 0
  fi

  {
    echo "[worker $i] cluster=$cluster configs=${my_configs[*]} db=$db"
    export CLUSTER_NAME="$cluster"
    export KUBECONFIG="$kubeconfig"
    export ZT_RESULTS_DB="$db"

    echo "[worker $i] bootstrapping KIND cluster $cluster (idempotent)"
    Infra/KIND/setup.sh all

    echo "[worker $i] starting driver.py --mode sequential --configs ${my_configs[*]}"
    python3 Driver/driver.py --mode sequential --run-id "$RUN_ID" --configs "${my_configs[@]}"
  } 2>&1 | tee -a "$log"
  return "${PIPESTATUS[0]}"
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

echo "[run_canonical] all workers exited, overall rc=$FINAL_RC"

if [[ "$FINAL_RC" -ne 0 ]]; then
  echo "[run_canonical] at least one worker failed — NOT deallocating, leaving VM up" \
       "for systemd to retry (RUN_ID=$RUN_ID, completed configs resume cheaply)"
  exit "$FINAL_RC"
fi

echo "[run_canonical] COMPLETE — merging ${NUM_WORKERS} per-worker DBs into results/results.db"
rm -f /opt/rszt/results/results.db   # idempotency: merge_results.py refuses to overwrite
WORKER_DBS=(/opt/rszt/results/canon-*/results.db)
python3 azure/merge_results.py "${WORKER_DBS[@]}" --out /opt/rszt/results/results.db

echo "[run_canonical] authenticating with VM managed identity to self-deallocate"
az login --identity >/dev/null
RG=$(curl -sH Metadata:true \
  "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text")
VM=$(curl -sH Metadata:true \
  "http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01&format=text")
echo "[run_canonical] deallocating $VM in $RG"
az vm deallocate -g "$RG" -n "$VM" --no-wait

exit 0
