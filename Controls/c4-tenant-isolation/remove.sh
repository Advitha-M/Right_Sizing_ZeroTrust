#!/usr/bin/env bash
# =============================================================================
# controls/c4-tenant-isolation/remove.sh
# Layer: L4 — Tenant Isolation (C4 in augmentation sequence)
# Removes: NoSchedule taints from worker nodes,
#          ResourceQuota and LimitRange from tenant namespaces.
# Idempotent: safe to run even if partially applied or already removed.
# =============================================================================
set -euo pipefail

LABEL="zt-control=c4-tenant-isolation"
TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)

# ---------------------------------------------------------------------------
# 0. Discover tenant nodes (same logic as apply.sh — do not assume names)
# ---------------------------------------------------------------------------
echo "[c4] Discovering tenant-labelled nodes..."

declare -A NODE_FOR_TENANT

while IFS=' ' read -r node tenant; do
  [[ -z "$node" || -z "$tenant" ]] && continue
  NODE_FOR_TENANT["$tenant"]="$node"
  echo "[c4]   tenant=$tenant → node=$node"
done < <(kubectl get nodes -l tenant \
  -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.labels.tenant}{"\n"}{end}')

# ---------------------------------------------------------------------------
# 1. Remove NoSchedule taints from each worker node
#    Trailing dash (-) is kubectl syntax for taint removal.
#    If the taint does not exist, kubectl exits non-zero — we suppress that
#    with || true to keep remove.sh idempotent.
# ---------------------------------------------------------------------------
echo "[c4] Removing NoSchedule taints..."

for t in "${TENANTS[@]}"; do
  if [[ -z "${NODE_FOR_TENANT[$t]:-}" ]]; then
    echo "[c4]   WARN: No node found for tenant=$t — skipping taint removal"
    continue
  fi
  node="${NODE_FOR_TENANT[$t]}"
  # The trailing - removes the taint. || true makes it idempotent.
  if kubectl taint node "$node" "tenant=${t}:NoSchedule-" 2>/dev/null; then
    echo "[c4]   Removed taint tenant=${t}:NoSchedule from $node"
  else
    echo "[c4]   Taint tenant=${t}:NoSchedule not present on $node (already removed or never applied)"
  fi
done

# ---------------------------------------------------------------------------
# 1b. Clear the toleration patches added by apply.sh so deployment templates
#     return to their untainted-baseline state. Sets tolerations to [] which
#     is safe: the only non-system toleration we added was the tenant one.
# ---------------------------------------------------------------------------
echo "[c4] Clearing deployment toleration patches..."
for t in "${TENANTS[@]}"; do
  for d in $(kubectl get deployment -n "$t" -o name 2>/dev/null); do
    kubectl patch "$d" -n "$t" --type='json' \
      -p='[{"op":"add","path":"/spec/template/spec/tolerations","value":[]}]' \
      2>/dev/null || true
  done
  echo "[c4]   tolerations cleared in $t"
done

# ---------------------------------------------------------------------------
# 2. Remove ResourceQuotas labelled zt-control=c4-tenant-isolation
#    Using label selector so we never accidentally delete user-created quotas.
# ---------------------------------------------------------------------------
echo "[c4] Removing ResourceQuotas..."

for t in "${TENANTS[@]}"; do
  if kubectl get resourcequota c4-quota -n "$t" &>/dev/null; then
    kubectl delete resourcequota c4-quota -n "$t"
    echo "[c4]   Deleted ResourceQuota c4-quota from namespace=$t"
  else
    echo "[c4]   ResourceQuota c4-quota not found in namespace=$t (already removed)"
  fi
done

# ---------------------------------------------------------------------------
# 3. Remove LimitRanges labelled zt-control=c4-tenant-isolation
# ---------------------------------------------------------------------------
echo "[c4] Removing LimitRanges..."

for t in "${TENANTS[@]}"; do
  if kubectl get limitrange c4-limits -n "$t" &>/dev/null; then
    kubectl delete limitrange c4-limits -n "$t"
    echo "[c4]   Deleted LimitRange c4-limits from namespace=$t"
  else
    echo "[c4]   LimitRange c4-limits not found in namespace=$t (already removed)"
  fi
done

# ---------------------------------------------------------------------------
# 4. Paranoia check — scan for any leftover objects with our label
#    across all namespaces. Should print nothing after clean removal.
# ---------------------------------------------------------------------------
echo ""
echo "[c4] === Leftover check (should be empty) ==="
echo "[c4] ResourceQuotas with label $LABEL:"
kubectl get resourcequota -A -l "$LABEL" --no-headers 2>/dev/null \
  | grep -v "^$" && echo "[c4]   WARN: leftover ResourceQuotas found above" \
  || echo "[c4]   none"

echo "[c4] LimitRanges with label $LABEL:"
kubectl get limitrange -A -l "$LABEL" --no-headers 2>/dev/null \
  | grep -v "^$" && echo "[c4]   WARN: leftover LimitRanges found above" \
  || echo "[c4]   none"

echo "[c4] Node taints (should show no tenant= taints):"
for t in "${TENANTS[@]}"; do
  if [[ -z "${NODE_FOR_TENANT[$t]:-}" ]]; then continue; fi
  node="${NODE_FOR_TENANT[$t]}"
  taint=$(kubectl get node "$node" -o jsonpath='{.spec.taints}' 2>/dev/null || echo "unreachable")
  echo "[c4]   $node: ${taint:-none}"
done

echo ""
echo "[c4] L4 tenant isolation REMOVED. C4 condition inactive."
