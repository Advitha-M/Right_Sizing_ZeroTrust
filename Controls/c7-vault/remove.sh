#!/usr/bin/env bash
# =============================================================================
# C7 remove — tear down Vault dynamic-secret enforcement
#  - disable kubernetes auth + the policy/role
#  - (the static-secret baseline is recreated on demand by the A6 attack itself,
#     so removing the layer simply restores the wide-open static-secret world)
# =============================================================================
set -uo pipefail
VAULT_NS="vault"
VPOD="$(kubectl get pod -n "$VAULT_NS" -l app.kubernetes.io/name=vault \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"

vexec() { kubectl exec -n "$VAULT_NS" "$VPOD" -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root $*" 2>/dev/null; }

if [[ -n "$VPOD" ]]; then
  echo "[c7-vault] disabling kubernetes auth + removing role/policy"
  vexec "vault delete auth/kubernetes/role/tenant-finserv" || true
  vexec "vault policy delete tenant-finserv-read" || true
  vexec "vault auth disable kubernetes" || true
fi

echo "[c7-vault] clearing dynamic secret-mode marker on tenant-finserv"
kubectl annotate namespace tenant-finserv zt-lab/secret-mode- >/dev/null 2>&1 || true

echo "[c7-vault] restoring static finserv-static-credentials k8s Secret"
kubectl create secret generic finserv-static-credentials \
  --from-literal=api-key="FINSERV_STATIC_API_KEY" \
  --from-literal=db-password="db-pass-secret" \
  -n tenant-finserv --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null || true

echo "[c7-vault] REMOVED — back to static-secret baseline"
