#!/usr/bin/env bash
# =============================================================================
# C1 remove — L1 (Cloud & Infrastructure)
#  Reverts all four parts of the composite control (see apply.sh for
#  details), in reverse-apply order (matches set_config()'s convention):
#  Part 4 (VPC-segmentation) -> Part 3 (Dex/OIDC) -> Part 2 (digest-pin)
#  -> Part 1 (etcd encryption).
#
#  KNOWN LAB LIMITATION: removing --encryption-provider-config stops NEW
#  writes from being encrypted, but data already written while encryption
#  was active REMAINS encrypted at rest in etcd until explicitly rewritten
#  (kubectl get <resource> -o json | kubectl replace -f - decrypts+rewrites
#  each object). This script does NOT force that rewrite — for trial
#  isolation purposes the apiserver's encryption-provider-config flag being
#  absent/present is the toggle signal that matters, not literal byte-level
#  etcd state. Document this explicitly if a trial depends on "no data was
#  ever encrypted" rather than "encryption is not currently configured."
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP_CONTAINER="${CLUSTER_NAME:-zt-lab}-control-plane"
APISERVER_MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"

# ── Part 4: VPC-segmentation proxy ───────────────────────────────────────────

echo "[c1-l1] [1/4] removing VPC-segmentation proxy (CiliumClusterwideNetworkPolicy)"
kubectl delete ciliumclusterwidenetworkpolicy -l zt-control=c1-l1 --ignore-not-found >/dev/null 2>&1 || true
echo "  removed (or was not present)"

# ── Part 3: cloud-IAM proxy (Dex OIDC federation) ────────────────────────────

echo "[c1-l1] [2/4] removing cloud-IAM proxy (apiserver --oidc-* flags)"
if docker exec "$CP_CONTAINER" grep -q "oidc-issuer-url" "$APISERVER_MANIFEST" 2>/dev/null; then
  docker exec "$CP_CONTAINER" sed -i \
    -e "/--oidc-issuer-url=/d" \
    -e "/--oidc-client-id=/d" \
    -e "/--oidc-username-claim=/d" \
    -e "/--oidc-username-prefix=/d" \
    "$APISERVER_MANIFEST"
  echo "  waiting for kubelet to restart apiserver..."
  for i in $(seq 1 30); do
    kubectl get --raw='/healthz' >/dev/null 2>&1 && break
    sleep 2
  done
  echo "  apiserver back up (or timed out — check manually if remove seems incomplete)"
  echo "  NOTE: A2-t2-oidc-token-replay will SKIP again below this condition"
  echo "  (constants.TECHNIQUE_MIN_CONDITION), same as before Part 3 existed."
else
  echo "  --oidc-issuer-url not present — nothing to remove"
fi

# ── Part 2 removed next: drop the Constraint before touching apiserver ──────
# (ordering matches set_config()'s reverse-order removal convention)

echo "[c1-l1] [3/4] removing image-pull verification (digest-pin constraint)"
kubectl delete -f "${HERE}/digest-pin-constraint.yaml" --ignore-not-found >/dev/null 2>&1 || true
kubectl delete -f "${HERE}/digest-pin-template.yaml" --ignore-not-found >/dev/null 2>&1 || true
echo "  removed. NOTE: shared Gatekeeper controller left running if L3b's"
echo "  constraints are still active — this script only removes L1's own"
echo "  ConstraintTemplate/Constraint, never the shared engine."

# ── Part 1: etcd encryption at rest ─────────────────────────────────────────

echo "[c1-l1] [4/4] removing etcd encryption at rest"
if docker exec "$CP_CONTAINER" grep -q "encryption-provider-config" "$APISERVER_MANIFEST" 2>/dev/null; then
  docker exec "$CP_CONTAINER" sed -i \
    "/--encryption-provider-config=/d" \
    "$APISERVER_MANIFEST"
  echo "  waiting for kubelet to restart apiserver..."
  for i in $(seq 1 30); do
    kubectl get --raw='/healthz' >/dev/null 2>&1 && break
    sleep 2
  done
  echo "  apiserver back up (or timed out — check manually if remove seems incomplete)"
else
  echo "  --encryption-provider-config not present — nothing to remove"
fi

echo "[c1-l1] REMOVED — L1 controls inactive (see limitation note above re: existing encrypted data)"
