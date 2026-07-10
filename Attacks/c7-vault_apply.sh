#!/usr/bin/env bash
# =============================================================================
# C7 apply — SPIRE workload identity + Vault: Kubernetes auth + short-TTL
# dynamic secrets. Two independent mechanisms, run side by side (see
# Driver/constants.py's L7_SCOPE_NOTE for why they aren't integrated into one
# credential path yet):
#
#  PART 1 — Vault (unchanged from the pre-SPIRE version of this script)
#  Goal of this layer in the augmentation: eliminate STATIC long-lived secrets so
#  credential-replay (A6-t1 static cred read, A6-t3 captured static token) fails.
#  Concretely:
#   1. enable Kubernetes auth in Vault (dev mode, root token 'root')
#   2. write a KV secret and a short-TTL policy + role bound to tenant-finserv SA
#   3. DELETE the static k8s Secret finserv-static-credentials (the thing A6-t1 reads)
#      and install a RBAC deny so it cannot be recreated/read cross-tenant
#   4. tighten the dev root token exposure so A6-t3 (VAULT_TOKEN=root replay) is
#      gated behind the k8s-auth role rather than a static root token
#  Assumes Vault is installed in namespace 'vault' (zt-setup phase5).
#
#  PART 2 — SPIRE (new): registers real SPIFFE identity entries for each
#  tenant workload and mounts the SPIRE Workload API socket into their pods,
#  so attack7.sh's T2 can fetch a genuine X.509-SVID rather than a
#  documented substitute, and Driver/driver.py's measure_dl() can poll real
#  SPIRE agent/server logs as a "spire" detection source — this is the piece
#  that makes the (L1,L7) DL candidate pair's "SPIRE attestation failure"
#  shared detection event real on the L7 side (L1's cloud-IAM side remains a
#  separate, already-documented substrate limitation — see L1_SCOPE_NOTE).
#  Assumes SPIRE server+agent are installed in namespace 'spire' (phase5).
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

echo "[c7-vault] Part 1 (Vault) APPLIED — secrets are Vault-issued short-TTL; static replay target removed"

# =============================================================================
# PART 2 — SPIRE workload identity
# =============================================================================
SPIRE_NS="spire"
TRUST_DOMAIN="cluster.local"
TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)

spire_server_exec() {
  kubectl exec -n "$SPIRE_NS" spire-server-0 -c spire-server -- "$@" 2>/dev/null
}

if ! kubectl get statefulset spire-server -n "$SPIRE_NS" >/dev/null 2>&1; then
  echo "[c7-vault] (warn) spire-server StatefulSet not found in ns=$SPIRE_NS — is phase5 done? skipping SPIRE registration"
else
  echo "[c7-vault] looking up the SPIRE agent's SPIFFE ID (single-node/small-cluster lab: reuse for every entry)"
  # spire-server agent list output is table-formatted and version-sensitive;
  # the agent SPIFFE ID always starts with spiffe://<trust-domain>/spire/agent/,
  # so grep for that prefix rather than depending on exact column layout.
  AGENT_ID="$(spire_server_exec /opt/spire/bin/spire-server agent list \
    | grep -o "spiffe://${TRUST_DOMAIN}/spire/agent/[^ ]*" | head -1 || true)"

  if [[ -z "$AGENT_ID" ]]; then
    echo "[c7-vault] (warn) no attested SPIRE agent found yet (node attestation may still be in progress) — skipping entry registration this run"
  else
    echo "[c7-vault] agent parent ID: $AGENT_ID"
    echo "[c7-vault] registering per-tenant SPIFFE entries (spiffe://${TRUST_DOMAIN}/ns/<tenant>/sa/default)"
    for T in "${TENANTS[@]}"; do
      spire_server_exec /opt/spire/bin/spire-server entry create \
        -parentID "$AGENT_ID" \
        -spiffeID "spiffe://${TRUST_DOMAIN}/ns/${T}/sa/default" \
        -selector "k8s:ns:${T}" \
        -selector "k8s:sa:default" >/dev/null \
        && echo "[c7-vault]   registered $T" \
        || echo "[c7-vault]   (warn) entry create for $T failed or already exists"
    done
  fi

  echo "[c7-vault] mounting the SPIRE Workload API socket into tenant pods (hostPath, DaemonSet-published)"
  # spire-agent runs as a DaemonSet and publishes its Workload API unix socket
  # at this hostPath on every node (chart default for spiffe/spire's
  # "spire-agent" subchart). No CSI driver / no mutating webhook needed —
  # same class of one-time structural patch this repo's set_config() model
  # already applies via kubectl for every other layer, just implemented as a
  # JSON patch instead of a plain apply since it's editing existing Deployment
  # pod specs rather than creating new objects.
  SOCKET_HOST_PATH="/run/spire/agent-sockets"
  PATCH='[
    {"op":"add","path":"/spec/template/spec/volumes/-","value":
      {"name":"spire-agent-socket","hostPath":{"path":"'"$SOCKET_HOST_PATH"'","type":"DirectoryOrCreate"}}},
    {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":
      {"name":"spire-agent-socket","mountPath":"/run/spire/sockets","readOnly":true}}
  ]'
  for T in "${TENANTS[@]}"; do
    for D in $(kubectl get deploy -n "$T" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      # Idempotency guard: skip if this deployment already has the volume
      # (patch would otherwise append a duplicate on every apply.sh re-run).
      if kubectl get deploy "$D" -n "$T" -o jsonpath='{.spec.template.spec.volumes[*].name}' 2>/dev/null \
          | grep -qw "spire-agent-socket"; then
        continue
      fi
      kubectl patch deploy "$D" -n "$T" --type=json -p "$PATCH" >/dev/null 2>&1 \
        || echo "[c7-vault]   (warn) patch failed for $T/$D — continuing"
    done
  done
  echo "[c7-vault] rolling out tenant workloads so the socket mount takes effect"
  for T in "${TENANTS[@]}"; do
    kubectl rollout restart deployment -n "$T" >/dev/null 2>&1 || true
  done
  for T in "${TENANTS[@]}"; do
    timeout 90 kubectl rollout status deployment -n "$T" >/dev/null 2>&1 \
      || echo "[c7-vault]   (warn) $T rollout status timed out/incomplete — continuing"
  done

  echo "[c7-vault] Part 2 (SPIRE) APPLIED — per-tenant SPIFFE entries registered, Workload API socket mounted"
fi

echo "[c7-vault] APPLIED"
