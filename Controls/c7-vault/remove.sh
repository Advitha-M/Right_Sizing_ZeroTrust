#!/usr/bin/env bash
# =============================================================================
# C7 remove — tear down SPIRE workload identity + Vault dynamic-secret
# enforcement (reverses Controls/c7-vault/apply.sh's Part 1 and Part 2).
#  PART 1 (Vault): disable kubernetes auth + the policy/role. The
#  static-secret baseline is recreated on demand by the A6 attack itself,
#  so removing the layer simply restores the wide-open static-secret world.
#  PART 2 (SPIRE): delete the per-tenant SPIFFE entries and un-mount the
#  Workload API socket from tenant pods, restoring the no-SPIFFE-identity
#  baseline. SPIRE server+agent themselves stay installed (phase5's "present,
#  not enforcing" tools are never uninstalled by a Controls/ script, same
#  convention as Istio/Gatekeeper/Vault).
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

echo "[c7-vault] Part 1 (Vault) REMOVED — back to static-secret baseline"

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
  echo "[c7-vault] (info) spire-server not present — nothing to remove for Part 2"
else
  echo "[c7-vault] deleting per-tenant SPIFFE entries"
  for T in "${TENANTS[@]}"; do
    ENTRY_ID="$(spire_server_exec /opt/spire/bin/spire-server entry show \
        -spiffeID "spiffe://${TRUST_DOMAIN}/ns/${T}/sa/default" \
        | grep -o 'Entry ID *: *[^[:space:]]*' | head -1 | awk '{print $NF}' || true)"
    if [[ -n "$ENTRY_ID" ]]; then
      spire_server_exec /opt/spire/bin/spire-server entry delete -entryID "$ENTRY_ID" >/dev/null \
        && echo "[c7-vault]   deleted entry for $T" \
        || echo "[c7-vault]   (warn) delete failed for $T"
    fi
  done

  echo "[c7-vault] un-mounting the SPIRE Workload API socket from tenant pods"
  for T in "${TENANTS[@]}"; do
    for D in $(kubectl get deploy -n "$T" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      HAS_MOUNT="$(kubectl get deploy "$D" -n "$T" \
        -o jsonpath='{.spec.template.spec.volumes[*].name}' 2>/dev/null | grep -qw "spire-agent-socket" && echo yes || echo no)"
      if [[ "$HAS_MOUNT" == "yes" ]]; then
        # Remove by name (JSON patch "remove" needs the current index — look
        # it up rather than assuming position 0, since other layers may have
        # appended their own volumes/mounts after ours).
        VOL_IDX="$(kubectl get deploy "$D" -n "$T" -o json \
          | python3 -c "import json,sys; d=json.load(sys.stdin); vols=d['spec']['template']['spec']['volumes']; print(next((i for i,v in enumerate(vols) if v['name']=='spire-agent-socket'), ''))" 2>/dev/null || true)"
        MNT_IDX="$(kubectl get deploy "$D" -n "$T" -o json \
          | python3 -c "import json,sys; d=json.load(sys.stdin); mounts=d['spec']['template']['spec']['containers'][0].get('volumeMounts',[]); print(next((i for i,v in enumerate(mounts) if v['name']=='spire-agent-socket'), ''))" 2>/dev/null || true)"
        if [[ -n "$VOL_IDX" && -n "$MNT_IDX" ]]; then
          kubectl patch deploy "$D" -n "$T" --type=json -p '[
            {"op":"remove","path":"/spec/template/spec/containers/0/volumeMounts/'"$MNT_IDX"'"},
            {"op":"remove","path":"/spec/template/spec/volumes/'"$VOL_IDX"'"}
          ]' >/dev/null 2>&1 || echo "[c7-vault]   (warn) un-patch failed for $T/$D — continuing"
        fi
      fi
    done
  done
  echo "[c7-vault] rolling out tenant workloads so the socket un-mount takes effect"
  for T in "${TENANTS[@]}"; do
    kubectl rollout restart deployment -n "$T" >/dev/null 2>&1 || true
  done
  for T in "${TENANTS[@]}"; do
    timeout 90 kubectl rollout status deployment -n "$T" >/dev/null 2>&1 \
      || echo "[c7-vault]   (warn) $T rollout status timed out/incomplete — continuing"
  done

  echo "[c7-vault] Part 2 (SPIRE) REMOVED — entries deleted, socket un-mounted (SPIRE itself stays installed)"
fi

echo "[c7-vault] REMOVED"
