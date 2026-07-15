#!/usr/bin/env bash
# =============================================================================
# azure/install_service.sh — one-time setup on each VM. After this runs,
# the study starts, survives Azure host-maintenance reboots (systemd
# WantedBy=multi-user.target), and auto-restarts on any crash — no further
# SSH access needed for the life of the run.
#
# Usage (on rszt-canonical):  sudo azure/install_service.sh rszt-canonical
# Usage (on rszt-shapley):    sudo azure/install_service.sh rszt-shapley
# =============================================================================
set -euo pipefail

UNIT="${1:?usage: install_service.sh <rszt-canonical|rszt-shapley>}"
case "$UNIT" in
  rszt-canonical|rszt-shapley) ;;
  *) echo "unknown unit '$UNIT' — expected rszt-canonical or rszt-shapley" >&2; exit 1 ;;
esac

cp "/opt/rszt/azure/${UNIT}.service" "/etc/systemd/system/${UNIT}.service"
systemctl daemon-reload
systemctl enable --now "${UNIT}.service"

echo
echo "${UNIT}.service installed, enabled (starts on boot), and started."
echo "Check status any time with:"
echo "    systemctl status ${UNIT}.service"
echo "    journalctl -u ${UNIT}.service -f"
echo
echo "Also install the watchdog cron job (catches a HUNG-but-not-crashed"
echo "process — driver.py's own timeouts make this unlikely but not"
echo "impossible over a multi-day run):"
echo "    sudo azure/install_watchdog.sh ${UNIT}"
