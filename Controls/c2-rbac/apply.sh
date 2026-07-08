#!/usr/bin/env bash
# =============================================================================
# C2 apply — RBAC (L3a) least-privilege
#  - REMOVE the permissive C0 binding (tenant-lowpriv default SA = cluster-admin)
#  - grant each tenant default SA ONLY namespaced read on its own resources
# Idempotent: safe to run repeatedly.
# Defends: A1-t3 (cross-ns API IDOR), A2-t2/t3 (escalation via API),
#          A3-t1 (cross-ns secret enum), A4-t1/t2/t3 (unauthorized resource/secret/exec)
# =============================================================================
set -uo pipefail
TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)

echo "[c2-rbac] removing permissive baseline bindings"
# C0 setup may have created either of these names — remove both
kubectl delete clusterrolebinding tenant-lowpriv-permissive   --ignore-not-found 2>/dev/null || true
kubectl delete clusterrolebinding tenant-lowpriv-cluster-admin --ignore-not-found 2>/dev/null || true
# Remove tenant-partner-nodes-read baseline grant (restored by remove.sh / restore_baseline.sh)
kubectl delete clusterrolebinding tenant-partner-nodes-read --ignore-not-found 2>/dev/null || true
kubectl delete clusterrole        tenant-partner-nodes-read --ignore-not-found 2>/dev/null || true

echo "[c2-rbac] applying per-tenant least-privilege Roles"
for T in "${TENANTS[@]}"; do
  kubectl apply -f - >/dev/null <<YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: tenant-self-read
  namespace: ${T}
  labels: { zt-control: c2-rbac }
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "endpoints", "configmaps"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tenant-self-read-bind
  namespace: ${T}
  labels: { zt-control: c2-rbac }
subjects:
  - kind: ServiceAccount
    name: default
    namespace: ${T}
roleRef:
  kind: Role
  name: tenant-self-read
  apiGroup: rbac.authorization.k8s.io
YAML
done

echo "[c2-rbac] APPLIED — tenant-lowpriv default SA is now namespaced-read-only on tenant-lowpriv"
