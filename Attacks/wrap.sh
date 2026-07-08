#!/usr/bin/env bash
# =============================================================================
# attacks/wrappers/wrap.sh — semantic wrapper around a single attack
#
# WHY THIS EXISTS (the "wrapper architecture" from the original plan):
#   The raw attacks/attackN.sh scripts mix three concerns: (a) attack mechanics,
#   (b) outcome reporting, (c) cleanup. A wrapper gives every attack a UNIFORM
#   semantic contract so the driver/harness never has to know attack internals:
#
#       wrap.sh <attackN> [native|stratus]
#
#   It:
#     1. pins the environment (tenant roles, seed, result file) identically
#        across all configs — this is the "semantic pinning" that makes a
#        SUCCESS->BLOCKED transition attributable to the control just enabled;
#     2. dispatches to either the native shell attack or (optionally) a Stratus
#        Red Team detonation via stratus_adapter.sh;
#     3. captures raw output and hands it to the oracle for classification;
#     4. emits a single canonical line on stdout: STATUS|detail
#        (and chain-depth for A7), exactly what driver/oracle.py expects.
#
# Usage:
#   ATTACKER_NS=tenant-lowpriv VICTIM_NS=tenant-finserv PARTNER_NS=tenant-partner \
#     bash attacks/wrappers/wrap.sh attack1
#   USE_STRATUS=1 bash attacks/wrappers/wrap.sh attack5 stratus
# =============================================================================
set -uo pipefail

ATTACK="${1:?usage: wrap.sh <attackN> [native|stratus]}"
MODE="${2:-native}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ATTACK_SCRIPT="${REPO_ROOT}/attacks/${ATTACK}.sh"
ORACLE="${REPO_ROOT}/attacks/oracles/oracle.sh"
ADAPTER="${REPO_ROOT}/attacks/wrappers/stratus_adapter.sh"

# ---- semantic pinning: identical environment across every configuration ------
export ATTACKER_NS="${ATTACKER_NS:-tenant-lowpriv}"
export VICTIM_NS="${VICTIM_NS:-tenant-finserv}"
export PARTNER_NS="${PARTNER_NS:-tenant-partner}"
export ALLOWED_PARTNER_NS="${ALLOWED_PARTNER_NS:-tenant-saas}"
export SEED="${SEED:-42}"
export RESULT_FILE="${RESULT_FILE:-/tmp/${ATTACK}_$$.txt}"
ATTACK_TIMEOUT="${ATTACK_TIMEOUT:-90}"

# ---- dispatch ----------------------------------------------------------------
RAW=""
case "$MODE" in
  stratus)
    if [[ "${USE_STRATUS:-0}" == "1" ]] && command -v stratus >/dev/null 2>&1; then
      RAW="$(timeout "$ATTACK_TIMEOUT" bash "$ADAPTER" "$ATTACK" 2>&1)"
    else
      # Stratus requested but unavailable -> fall back to native, note it.
      RAW="$(timeout "$ATTACK_TIMEOUT" bash "$ATTACK_SCRIPT" 2>&1)"
      RAW="${RAW}"$'\n'"NOTE|stratus-unavailable-fell-back-to-native"
    fi
    ;;
  native|*)
    RAW="$(timeout "$ATTACK_TIMEOUT" bash "$ATTACK_SCRIPT" 2>&1)"
    ;;
esac

# ---- classify via the externalized oracle ------------------------------------
# The oracle prints the single canonical STATUS|detail line to stdout.
printf '%s\n' "$RAW" | bash "$ORACLE" "$ATTACK"
