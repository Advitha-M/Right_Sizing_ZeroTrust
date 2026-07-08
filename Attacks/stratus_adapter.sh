#!/usr/bin/env bash
# =============================================================================
# attacks/wrappers/stratus_adapter.sh — optional Stratus Red Team integration
#
# WHY THIS IS A SEPARATE, GATED ADAPTER (the honest Stratus story):
#   The seven attack classes in this study are objective-based K8s in-cluster
#   probes (cross-tenant HTTP reach, ServiceAccount-token API calls, admission
#   denials, secret reads, multi-step lateral chains). Stratus Red Team's
#   catalog is overwhelmingly *cloud control-plane* TTPs (AWS/GCP/Azure) plus a
#   small set of generic Kubernetes techniques; none of them emit this study's
#   objective oracle (STATUS|detail), and most require cloud credentials this
#   air-gapped kind cluster does not have.
#
#   Therefore Stratus is NOT the primary attack driver — that would couple the
#   experiment to detonations that cannot express A1..A7. Instead it is offered
#   as an OPTIONAL technique source behind USE_STRATUS=1, mapped onto the few
#   classes where a Stratus K8s technique is semantically equivalent. Where no
#   equivalent exists, the adapter returns SKIP so the wrapper falls back to the
#   native implementation. This keeps Stratus *present and wired* (as planned)
#   without letting it silently degrade the objective-based measurement.
#
# Mapping (Stratus k8s.* technique  ->  our objective class), best-effort:
#   attack2 (priv-esc)         -> k8s.privilege-escalation.privileged-pod
#   attack3 (identity/cred)    -> k8s.credential-access.steal-serviceaccount-token
#   attack4 (resource/secret)  -> k8s.credential-access.dump-secrets
#   others                     -> SKIP (no faithful Stratus equivalent)
#
# Usage:  USE_STRATUS=1 bash stratus_adapter.sh attack2
# =============================================================================
set -uo pipefail
ATTACK="${1:?usage: stratus_adapter.sh <attackN>}"
ATTACKER_NS="${ATTACKER_NS:-tenant-lowpriv}"

if ! command -v stratus >/dev/null 2>&1; then
  echo "SKIP|stratus-not-installed"
  exit 0
fi

case "$ATTACK" in
  attack2) TECH="k8s.privilege-escalation.privileged-pod" ;;
  attack3) TECH="k8s.credential-access.steal-serviceaccount-token" ;;
  attack4) TECH="k8s.credential-access.dump-secrets" ;;
  *)       echo "SKIP|no-stratus-equivalent-for-${ATTACK}"; exit 0 ;;
esac

# Verify the technique exists in this Stratus build before detonating.
if ! stratus list 2>/dev/null | grep -q "$TECH"; then
  echo "SKIP|stratus-technique-absent:${TECH}"
  exit 0
fi

echo "[stratus] detonating ${TECH} (ns=${ATTACKER_NS})"
WARMUP_OUT="$(stratus warmup "$TECH" 2>&1 || true)"
DET_OUT="$(stratus detonate "$TECH" 2>&1 || true)"
# always attempt cleanup so trials stay independent
stratus cleanup "$TECH" >/dev/null 2>&1 || true

# Surface raw output; the oracle decides SUCCESS/BLOCKED from detonation result.
printf '%s\n%s\n' "$WARMUP_OUT" "$DET_OUT"
if echo "$DET_OUT" | grep -qiE "successfully detonated|attack technique.*detonated"; then
  echo "SUCCESS|stratus:${TECH}"
elif echo "$DET_OUT" | grep -qiE "forbidden|denied|admission|error"; then
  echo "BLOCKED|stratus:${TECH}"
else
  echo "ERROR|stratus-indeterminate:${TECH}"
fi
