#!/usr/bin/env bash
# =============================================================================
# ATTACK A6 — Supply Chain Compromise
# Doc class : A6  |  Script: attack6.sh
# Spec      : Rev5 Section 13
# Objective : run untrusted / unauthorized code introduced via the delivery
#             pipeline (dependency confusion / Cosign tamper / malicious
#             init-container)
#
# Techniques (spec-aligned — technique_sample_space.docx, |T|=1, Low tier):
#   T1 — Pipeline Injection   Dependency confusion / Cosign tamper /
#                             malicious init-container via delivery pipeline
#
# REVISION 6 NOTE: two extra techniques from the prior implementation
# (t1-disallowed-registry, t2-unpinned-image) have been REMOVED —
# technique_sample_space.docx fixes |T_A6|=1. The former t3-init-privileged
# case is retained and renamed to the spec token t1-pipeline-injection — a
# tampered privileged initContainer is a direct, concrete instance of
# "malicious init-container via delivery pipeline."
#
# Primary defender: L3b (OPA/Kyverno admission denies privileged
#                    initContainers)
#
# Output: SUCCESS|<technique>|<detail>
#         BLOCKED|<technique>|<detail>
#         SKIP|<reason>
# =============================================================================
set -euo pipefail

ATTACKER_NS="${ATTACKER_NS:-tenant-lowpriv}"
SEED="${SEED:-$$}"

succeed() { echo "SUCCESS|$1|$2" | tee "$RESULT_FILE" 2>/dev/null; cleanup; exit 0; }
blocked() { echo "BLOCKED|$1|$2" | tee "$RESULT_FILE" 2>/dev/null; cleanup; exit 1; }
skip()    { echo "SKIP|$1"       | tee "$RESULT_FILE" 2>/dev/null; cleanup; exit 2; }
RESULT_FILE="${RESULT_FILE:-/tmp/a6_result.txt}"

POD_NAME=""
cleanup() {
  [[ -n "$POD_NAME" ]] && \
    kubectl delete pod "$POD_NAME" -n "$ATTACKER_NS" \
      --ignore-not-found --grace-period=0 2>/dev/null || true
}

wait_running() {
  local name=$1 ns=$2
  for i in $(seq 1 20); do
    PHASE=$(kubectl get pod "$name" -n "$ns" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Missing")
    echo "  [$i] $name phase=$PHASE"
    [[ "$PHASE" == "Running" ]] && return 0
    [[ "$PHASE" == "Failed"  ]] && return 1
    sleep 1
  done
  return 1
}

TECHNIQUES=(t1-pipeline-injection)
N_TECH=${#TECHNIQUES[@]}
: "${TECHNIQUE_IDX:?TECHNIQUE_IDX env var required}"
[[ "$TECHNIQUE_IDX" -lt 0 || "$TECHNIQUE_IDX" -ge "$N_TECH" ]] && {
  echo "SKIP|TECHNIQUE_IDX-out-of-range-$TECHNIQUE_IDX"; exit 2; }
TECHNIQUE="${TECHNIQUES[$TECHNIQUE_IDX]}"
echo "[A6] SEED=$SEED TECHNIQUE_IDX=$TECHNIQUE_IDX technique=$TECHNIQUE"

case "$TECHNIQUE" in

  t1-pipeline-injection)
    # Simulates a delivery-pipeline compromise landing a malicious
    # initContainer in a pod spec (dependency confusion / tampered image /
    # unauthorized init-container — all converge on the same admission-time
    # signal: a privileged initContainer that shouldn't be there).
    # Success = pod admitted and initContainer ran privileged.
    # Blocked by L3b: OPA/Kyverno admission denies privileged containers.
    POD_NAME="a6-pipeline-inject-$$"
    echo "[A6-t1] deploying pod with malicious privileged initContainer (simulated pipeline injection)"
    APPLY_OUT=0
    cat <<EOF | kubectl apply -f - 2>&1 | grep -E 'created|denied|error|Error' || APPLY_OUT=$?
apiVersion: v1
kind: Pod
metadata:
  name: $POD_NAME
  namespace: $ATTACKER_NS
  labels:
    attack-artifact: "true"
spec:
  initContainers:
  - name: pipeline-inject
    image: alpine:3.18
    command: ["sh", "-c", "echo 'injected via pipeline' && id"]
    securityContext:
      privileged: true
  containers:
  - name: main
    image: alpine:3.18
    command: ["sleep", "60"]
  restartPolicy: Never
  tolerations:
  - operator: Exists
EOF
    if [[ $APPLY_OUT -ne 0 ]]; then
      blocked "t1-pipeline-injection" "admission-denied-privileged-initcontainer"
    elif wait_running "$POD_NAME" "$ATTACKER_NS"; then
      succeed "t1-pipeline-injection" "pod-running privileged-init=true"
    else
      blocked "t1-pipeline-injection" "pod-not-running"
    fi
    ;;

  *)
    skip "unknown-technique-$TECHNIQUE"
    ;;
esac
