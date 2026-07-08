#!/usr/bin/env bash
# =============================================================================
# C2 remove — tear down RBAC least-privilege, restore permissive baseline
# Restores the C0/C1 invariant: tenant-lowpriv default SA = cluster-admin (wide open).
# Idempotent.
# =============================================================================
set -uo pipefail
TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)

echo "[c2-rbac] removing per-tenant Roles/RoleBindings"
for T in "${TENANTS[@]}"; do
  kubectl delete rolebinding tenant-self-read-bind -n "$T" --ignore-not-found 2>/dev/null || true
  kubectl delete role        tenant-self-read      -n "$T" --ignore-not-found 2>/dev/null || true
done

echo "[c2-rbac] restoring permissive baseline (tenant-lowpriv default SA = cluster-admin)"
kubectl create clusterrolebinding tenant-lowpriv-permissive \
  --clusterrole=cluster-admin --serviceaccount=tenant-lowpriv:default \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1 || true

echo "[c2-rbac] restoring tenant-partner-nodes-read baseline grant"
kubectl apply -f - >/dev/null 2>&1 <<'YAML' || true
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tenant-partner-nodes-read
  labels: { zt-lab/baseline: "true" }
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tenant-partner-nodes-read
  labels: { zt-lab/baseline: "true" }
subjects:
  - kind: ServiceAccount
    name: default
    namespace: tenant-partner
roleRef:
  kind: ClusterRole
  name: tenant-partner-nodes-read
  apiGroup: rbac.authorization.k8s.io
YAML

echo "[c2-rbac] REMOVED — back to C0 permissive baseline"
