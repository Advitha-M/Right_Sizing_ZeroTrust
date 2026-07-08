#!/usr/bin/env bash
# =============================================================================
# attacks/oracles/oracle.sh — externalized outcome classifier (shell side)
#
# Reads raw attack stdout on STDIN, prints ONE canonical line:  STATUS|detail
# STATUS in {SUCCESS, BLOCKED, PARTIAL, SKIP, ERROR, TIMEOUT}.
#
# This is the shell twin of driver/oracle.py::classify — kept deliberately in
# lock-step so the wrapper path and the driver path classify identically.
# The native attacks/attackN.sh already print STATUS|detail themselves; this
# oracle's job is to (a) pick the authoritative last status line, (b) preserve
# chain-depth for A7, (c) fail closed to ERROR on unparseable output.
#
# Usage:  printf '%s' "$RAW" | bash oracle.sh attack7
# =============================================================================
set -uo pipefail
ATTACK="${1:-unknown}"
VALID="SUCCESS BLOCKED PARTIAL SKIP ERROR TIMEOUT"

RAW="$(cat)"

if [[ -z "${RAW// }" ]]; then
  echo "ERROR|no-output"
  exit 0
fi

# find the last line whose first |-field is a valid status
LINE=""
while IFS= read -r ln; do
  status="${ln%%|*}"
  for v in $VALID; do
    if [[ "$status" == "$v" ]]; then LINE="$ln"; fi
  done
done <<< "$RAW"

if [[ -z "$LINE" ]]; then
  # fallback: scan for a bare keyword anywhere
  for v in $VALID; do
    if grep -q "$v" <<< "$RAW"; then
      echo "${v}|inferred-from-output"
      exit 0
    fi
  done
  echo "ERROR|unparseable-output"
  exit 0
fi

STATUS="${LINE%%|*}"
DETAIL="${LINE#*|}"

# Preserve A7 chain-depth marker if present (SUCCESS|chain-depth=3|...).
if grep -q "chain-depth=" <<< "$LINE"; then
  DEPTH="$(grep -o 'chain-depth=[0-9]\+' <<< "$LINE" | head -1)"
  echo "${STATUS}|${DEPTH}|${DETAIL#*|}"
else
  echo "${STATUS}|${DETAIL}"
fi
