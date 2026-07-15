#!/usr/bin/env bash
# =============================================================================
# azure/watchdog.sh — safety net for a HUNG (not crashed) process: if the
# service's most recent log file hasn't been written to in STALE_MINUTES,
# assume it's stuck (e.g. a subprocess call somehow got past its own
# timeout) and restart the unit. systemd's Restart=on-failure only fires
# on a non-zero exit — it does nothing for a process that's just silently
# stopped making progress, which is the gap this covers.
#
# Safe to fire aggressively: restarting mid-run is a normal, resumable
# event now (real-cluster-state layer detection + per-trial resume in
# driver.py), so a false-positive restart costs a little wall time, not
# correctness.
#
# Installed via install_watchdog.sh as a cron entry, not a long-running
# process itself.
# =============================================================================
set -uo pipefail

UNIT="${1:?usage: watchdog.sh <rszt-canonical|rszt-shapley>}"
STALE_MINUTES="${STALE_MINUTES:-180}"   # 3h — generous vs. driver.py's own
                                         # per-call timeouts (max ~480s)
LOG_DIR=/opt/rszt/logs

if ! systemctl is-active --quiet "${UNIT}.service"; then
  # Not running at all — Restart=on-failure / StartLimitIntervalSec=0
  # should already be handling this; nothing extra for the watchdog to do.
  exit 0
fi

LATEST_LOG=$(find "$LOG_DIR" -name '*.log' -printf '%T@ %p\n' 2>/dev/null \
  | sort -rn | head -1 | cut -d' ' -f2-)

if [[ -z "$LATEST_LOG" ]]; then
  echo "[watchdog] no log files found yet under $LOG_DIR — nothing to check"
  exit 0
fi

AGE_MIN=$(( ( $(date +%s) - $(stat -c %Y "$LATEST_LOG") ) / 60 ))
if [[ "$AGE_MIN" -ge "$STALE_MINUTES" ]]; then
  echo "[watchdog] $LATEST_LOG is ${AGE_MIN}min stale (>= ${STALE_MINUTES}min) — " \
       "restarting ${UNIT}.service"
  systemctl restart "${UNIT}.service"
else
  echo "[watchdog] $LATEST_LOG is ${AGE_MIN}min old — fine"
fi
