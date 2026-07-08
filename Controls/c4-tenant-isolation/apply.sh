#!/usr/bin/env bash
# =============================================================================
# controls/c4-tenant-isolation/apply.sh
# Layer: L4 — Tenant Isolation (C4 in augmentation sequence)
# Applies: hard NoSchedule taints per worker node (one taint per tenant),
#          ResourceQuota and LimitRange per tenant namespace.
# Label:   zt-control=c4-tenant-isolation on all created objects
#          so cleanup/reset_controls.sh can find them by label.
# Idempotent: safe to run multiple times.
# =============================================================================
set -euo pipefail

LABEL="zt-control=c4-tenant-isolation"
TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)

# ---------------------------------------------------------------------------
# 0. Confirm all expected tenant nodes exist before touching anything
# ---------------------------------------------------------------------------
echo "[c4] Discovering tenant-labelled nodes..."

declare -A NODE_FOR_TENANT

while IFS=' ' read -r node tenant; do
  [[ -z "$node" || -z "$tenant" ]] && continue
  NODE_FOR_TENANT["$tenant"]="$node"
  echo "[c4]   tenant=$tenant → node=$node"
done < <(kubectl get nodes -l tenant \
  -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.labels.tenant}{"\n"}{end}')

for t in "${TENANTS[@]}"; do
  if [[ -z "${NODE_FOR_TENANT[$t]:-}" ]]; then
    echo "[c4] ERROR: No node found with label tenant=$t" >&2
    echo "[c4]   Run: kubectl get nodes --show-labels | grep tenant" >&2
    exit 1
  fi
done

echo "[c4] All 4 tenant nodes confirmed. Proceeding."

# ---------------------------------------------------------------------------
# 1. Apply hard NoSchedule taints to each worker node
#    Effect: pods without a matching toleration cannot schedule there,
#    regardless of nodeSelector — this is the hard isolation guarantee.
#    Idempotent: kubectl taint is a no-op if the taint already exists.
# ---------------------------------------------------------------------------
echo "[c4] Applying NoSchedule taints..."

for t in "${TENANTS[@]}"; do
  node="${NODE_FOR_TENANT[$t]}"
  # The --overwrite flag makes this idempotent (no error if taint exists)
  kubectl taint node "$node" "tenant=${t}:NoSchedule" --overwrite
  echo "[c4]   Tainted $node with tenant=${t}:NoSchedule"
done

# ---------------------------------------------------------------------------
# 1b. Patch tenant deployments with matching toleration so rollout-restart
#     succeeds while NoSchedule taints are active. Running pods are not
#     evicted by NoSchedule, but any new pod (e.g. from c6-istio rollout
#     restart) must carry a matching toleration to schedule on the tainted
#     tenant node. Idempotent: 'add' replaces value if path already exists.
# ---------------------------------------------------------------------------
echo "[c4] Patching deployment tolerations for tenant scheduling..."
for t in "${TENANTS[@]}"; do
  for d in $(kubectl get deployment -n "$t" -o name 2>/dev/null); do
    kubectl patch "$d" -n "$t" --type='json' \
      -p='[{"op":"add","path":"/spec/template/spec/tolerations","value":[{"key":"tenant","operator":"Equal","value":"'"$t"'","effect":"NoSchedule"}]}]' \
      2>/dev/null || true
  done
  echo "[c4]   tolerations patched in $t"
done

# ---------------------------------------------------------------------------
# 2. Apply ResourceQuota per tenant namespace
#    Bounds: chosen to be tight enough to prevent noisy-neighbour resource
#    exhaustion while not interfering with normal Bookinfo operation.
#    Labels: zt-control=c4-tenant-isolation for cleanup targeting.
# ---------------------------------------------------------------------------
echo "[c4] Applying ResourceQuota per tenant namespace..."

for t in "${TENANTS[@]}"; do
  kubectl apply -f - <<EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: c4-quota
  namespace: ${t}
  labels:
    zt-control: c4-tenant-isolation
spec:
  hard:
    # Compute
    requests.cpu: "2"
    limits.cpu: "4"
    requests.memory: "1Gi"
    limits.memory: "2Gi"
    # Workloads — prevent unbounded pod spawning
    pods: "20"
    # Services
    services: "10"
    services.loadbalancers: "0"
    services.nodeports: "0"
    # Secrets / ConfigMaps — bound to reduce secret enumeration surface
    secrets: "20"
    configmaps: "20"
    # Persistent storage
    persistentvolumeclaims: "5"
EOF
  echo "[c4]   ResourceQuota c4-quota applied in namespace=$t"
done

# ---------------------------------------------------------------------------
# 3. Apply LimitRange per tenant namespace
#    Enforces per-container defaults so pods that don't specify resources
#    still get bounded. Without this, a pod with no resource spec is
#    unbounded even with a ResourceQuota on the namespace.
# ---------------------------------------------------------------------------
echo "[c4] Applying LimitRange per tenant namespace..."

for t in "${TENANTS[@]}"; do
  kubectl apply -f - <<EOF
apiVersion: v1
kind: LimitRange
metadata:
  name: c4-limits
  namespace: ${t}
  labels:
    zt-control: c4-tenant-isolation
spec:
  limits:
  - type: Container
    default:
      cpu: "500m"
      memory: "256Mi"
    defaultRequest:
      cpu: "100m"
      memory: "64Mi"
    max:
      cpu: "2"
      memory: "1Gi"
    min:
      cpu: "10m"
      memory: "16Mi"
  - type: Pod
    max:
      cpu: "3"
      memory: "1536Mi"
EOF
  echo "[c4]   LimitRange c4-limits applied in namespace=$t"
done

# ---------------------------------------------------------------------------
# 4. Verify
# ---------------------------------------------------------------------------
echo ""
echo "[c4] === Verification ==="
echo "[c4] Node taints:"
for t in "${TENANTS[@]}"; do
  node="${NODE_FOR_TENANT[$t]}"
  taint=$(kubectl get node "$node" -o jsonpath='{.spec.taints}' 2>/dev/null || echo "none")
  echo "[c4]   $node: $taint"
done

echo "[c4] ResourceQuotas:"
kubectl get resourcequota -A -l "$LABEL" \
  --no-headers -o custom-columns="NS:.metadata.namespace,NAME:.metadata.name"

echo "[c4] LimitRanges:"
kubectl get limitrange -A -l "$LABEL" \
  --no-headers -o custom-columns="NS:.metadata.namespace,NAME:.metadata.name"

echo ""
echo "[c4] L4 tenant isolation APPLIED. C4 condition active."
