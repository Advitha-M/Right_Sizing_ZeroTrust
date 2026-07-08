#!/usr/bin/env bash
# =============================================================================
# harness/run_attacks.sh — manual single-condition driver.py invocation
# Brief: Rev6 (corrected)
#
# This is a thin convenience wrapper around Driver/driver.py for
# manual/interactive use, e.g. smoke-testing one condition without kicking
# off the full C0-C7 x N=50 sequential build.
#
# It intentionally does NOT reimplement technique sampling, per-class
# attacker-namespace routing, invariant checks, cluster reset, or
# detection-latency measurement. The previous version of this script did
# reimplement all of that in bash, and it had drifted badly from the brief:
# stuck on a stale 6-condition build, hardcoded one global attacker/victim
# pair for every attack class, never sampled a technique (ran each attack
# script exactly once "native", bypassing the one-technique-per-trial
# requirement), never measured detection latency (dl_sec was always NULL),
# and wrote a thinner DB schema than driver.py's — despite a comment
# claiming it was schema-compatible.
#
# Driver/driver.py is the single authoritative implementation of all of
# that logic (draw_technique(), ATTACKER_NS_MAP routing, measure_dl(), the
# v3 schema with technique_token/t_start/t_alert/target_tenant/pivot_path).
# This script just translates a simple STACK_ID=... N_TRIALS=... call into
# the equivalent `driver.py --configs ... --trials ...` invocation, so a
# manual run and a full run write to the exact same DB with the exact same
# schema by construction — not by two implementations trying to stay in
# sync by hand, which is how the old version drifted in the first place.
#
#   usage: STACK_ID=C0 N_TRIALS=1  bash harness/run_attacks.sh
#          STACK_ID=C7 N_TRIALS=50 bash harness/run_attacks.sh
#          STACK_ID=C3 RUN_ID=my_smoke_test bash harness/run_attacks.sh
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
# shellcheck disable=SC1091
source "${LAB_DIR}/harness/config.env" 2>/dev/null || true

STACK_ID="${STACK_ID:-C0}"
N_TRIALS="${N_TRIALS:-10}"
RUN_ID="${RUN_ID:-manual_$(date +%Y%m%d_%H%M%S)_${STACK_ID}}"
DRIVER="${DRIVER:-${LAB_DIR}/Driver/driver.py}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# ---- validate STACK_ID against the corrected 8-condition build -------------
VALID_CONFIGS="C0 C1 C2 C3 C4 C5 C6 C7"
if [[ ! " $VALID_CONFIGS " == *" $STACK_ID "* ]]; then
  echo "ERROR: STACK_ID='$STACK_ID' is not a valid condition." >&2
  echo "       Must be one of: $VALID_CONFIGS" >&2
  exit 1
fi

if [[ ! -f "$DRIVER" ]]; then
  echo "ERROR: driver.py not found at $DRIVER" >&2
  echo "       Set DRIVER=/path/to/driver.py to override." >&2
  exit 1
fi

log "Delegating to driver.py: config=$STACK_ID trials=$N_TRIALS run_id=$RUN_ID"
log "(namespace routing, technique sampling, invariant checks, and DL"
log " measurement are all handled inside driver.py — see its own log output"
log " below for per-trial detail)"

python3 "$DRIVER" \
  --configs "$STACK_ID" \
  --trials "$N_TRIALS" \
  --run-id "$RUN_ID"
STATUS=$?

if [[ $STATUS -eq 0 ]]; then
  log "Run complete: config=$STACK_ID run_id=$RUN_ID"
else
  log "driver.py exited with status $STATUS — see output above"
fi
exit $STATUS
