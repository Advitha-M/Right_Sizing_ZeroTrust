#!/usr/bin/env bash
# azure/install_watchdog.sh — installs azure/watchdog.sh as a root cron job,
# checked every 30 minutes. Usage: sudo azure/install_watchdog.sh <unit>
set -euo pipefail
UNIT="${1:?usage: install_watchdog.sh <rszt-canonical|rszt-shapley>}"
chmod +x /opt/rszt/azure/watchdog.sh

CRON_LINE="*/30 * * * * root /opt/rszt/azure/watchdog.sh ${UNIT} >> /opt/rszt/logs/watchdog.log 2>&1"
CRON_FILE="/etc/cron.d/rszt-watchdog"

echo "$CRON_LINE" > "$CRON_FILE"
chmod 644 "$CRON_FILE"
echo "watchdog installed: checks every 30min, restarts ${UNIT}.service if its" \
     "log has been stale for 3h+. Edit STALE_MINUTES in watchdog.sh to tune."
