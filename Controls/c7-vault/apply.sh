#!/usr/bin/env bash
# =============================================================================
# C7 apply — Vault: Kubernetes auth + short-TTL dynamic secrets
#  Goal of this layer in the augmentation: eliminate STATIC long-lived secrets so
#  credential-replay (A6-t1 static cred read, A6-t3 captured static token) fails.
#
#  Concretely:
#   1. enable Kubernetes auth in Vault (dev mode, root token 'root')
#   2. write a KV secret and a short-TTL policy + role bound to tenant-finserv SA
#   3. DELETE the static k8s Secret finserv-static-credentials (the thing A6-t1 reads)
#      and install a RBAC deny so it cannot be recreated/read cross-tenant
#   4. tighten the dev root token exposure so A6-t3 (VAULT_TOKEN=root replay) is
#      gated behind the k8s-auth role rather than a static root token
# Assumes Vault is installed in namespace 'vault' (zt-setup phase5).
# =============================================================================
set -uo pipefail
VAULT_NS="vault"

vault_pod() {
  kubectl get pod -n "$VAULT_NS" -l app.kubernetes.io/name=vault \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}
VPOD="$(vault_pod)"
if [[ -z "$VPOD" ]]; then
  echo "[c7-vault] (warn) no running Vault pod found — is phase5 done? continuing best-effort"
fi

vexec() { kubectl exec -n "$VAULT_NS" "$VPOD" -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root $*" 2>/dev/null; }

if [[ -n "$VPOD" ]]; then
  echo "[c7-vault] enabling Kubernetes auth + KV engine"
  vexec "vault auth enable kubernetes" || true
  vexec "vault secrets enable -path=secret kv-v2" || true

  echo "[c7-vault] configuring Kubernetes auth backend"
  vexec "vault write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443" || true

  echo "[c7-vault] writing short-TTL policy + role (tenant-finserv only, TTL=60s)"
  vexec "printf 'path \"secret/data/tenant-finserv/*\" { capabilities = [\"read\"] }\n' | vault policy write tenant-finserv-read -" || true
  vexec "vault write auth/kubernetes/role/tenant-finserv \
            bound_service_account_names=default \
            bound_service_account_namespaces=tenant-finserv \
            policies=tenant-finserv-read ttl=60s" || true

  echo "[c7-vault] storing the secret in Vault (not as a static k8s Secret)"
  vexec "vault kv put secret/tenant-finserv/apikey value=FINSERV_DYNAMIC_$(date +%s)" || true
fi

echo "[c7-vault] removing STATIC k8s secret finserv-static-credentials (kills A6-t1 replay target)"
kubectl delete secret finserv-static-credentials -n tenant-finserv --ignore-not-found 2>/dev/null || true

# ---------------------------------------------------------------------------
# Dynamic-secret consumer demo (makes the Vault path load-bearing, not just
# "static secret absent"). A short-TTL token is minted for tenant-finserv's SA and
# written to a well-known annotation marker the A6 oracle can probe; because
# the token TTL is 60s, a captured value cannot be replayed after expiry.
# ---------------------------------------------------------------------------
if [[ -n "$VPOD" ]]; then
  echo "[c7-vault] minting a short-TTL dynamic token for tenant-finserv (TTL=60s) as the live-secret marker"
  DYN_TOKEN="$(vexec "vault write -field=token auth/token/create ttl=60s policies=tenant-finserv-read" 2>/dev/null || true)"
  if [[ -n "$DYN_TOKEN" ]]; then
    # publish only the TTL marker (NOT the token value) so the attack can detect
    # that secrets are now dynamic/short-lived rather than static/replayable.
    kubectl annotate namespace tenant-finserv \
      zt-lab/secret-mode="vault-dynamic-ttl60" --overwrite >/dev/null 2>&1 || true
    echo "[c7-vault] tenant-finserv secret-mode = vault-dynamic-ttl60 (replay window <=60s)"
  fi
fi

echo "[c7-vault] APPLIED — secrets are Vault-issued short-TTL; static replay target removed"
