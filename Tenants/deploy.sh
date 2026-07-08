#!/usr/bin/env bash
# =============================================================================
# tenants/deploy.sh — deploy the 4 node-pinned Bookinfo tenants + C0 baseline
#
# Extracted from zt-setup.sh phase2 as a standalone, reusable component so the
# tenant topology is a first-class artifact (referenced by README + Makefile).
# Idempotent.
#
# C0 BASELINE, RE-DERIVED FROM BRIEF §1 (C0={L2} only):
# Kubernetes RBAC is default-deny with no native "off" switch — absent any
# bindings, a ServiceAccount simply has no permissions. So "L3a not yet
# applied" isn't a state you can toggle off; it has to be constructed as an
# explicit, maximally-permissive starting point, which C2 (Controls/c2-rbac)
# then locks down. This script creates exactly the two baseline grants that
# Controls/c2-rbac/apply.sh removes and Controls/c2-rbac/remove.sh restores,
# using identical resource names so the two scripts round-trip cleanly:
#   1. tenant-lowpriv-permissive   — tenant-lowpriv:default = cluster-admin.
#      tenant-lowpriv is the attacker foothold for A1/A2/A5; at C0 it starts
#      wide open, and L3a (C2) is what narrows it down to the
#      tenant-self-read Role described in Controls/c2-rbac/rbac.yaml.
#   2. tenant-partner-nodes-read   — tenant-partner:default = ClusterRole
#      {nodes: get,list}. Represents the "legitimate but overpermissioned"
#      vendor/partner profile from Brief §13 — a misconfigured-operator
#      baseline that Attacks/attack3.sh (t1-scoped-binding-escalation)
#      specifically targets. This grant existing at C0 is a documented
#      precondition for A3, not an artifact of "no RBAC" — it stays even
#      independent of the L3a toggle being about tenant-lowpriv.
# tenant-finserv and tenant-saas get no baseline ClusterRole/ClusterRoleBinding
# — nothing in Brief §13 calls for one, and inventing one would be exactly
# the kind of unstated assumption this cleanup is trying to remove.
#
# REVISION 6 CHANGE: every image deployed here is now DIGEST-PINNED at apply
# time, not tag-referenced. This is required for L1 (image-pull verification
# — controls/c1-l1) to be a meaningful, independently-toggleable control: if
# tenant infrastructure itself used mutable tags, L1's digest-pin Constraint
# would deny legitimate tenant pods from C1 onward, corrupting every attack
# class's trials, not just testing L1. Digests are resolved dynamically via
# `docker pull` + `docker inspect` at deploy time (NOT hardcoded — hardcoded
# digests go stale the moment an upstream image is rebuilt under the same
# tag). A6's own attack payload (attacks/attack6.sh) is the ONE deliberate
# exception in the whole taxonomy and stays tag-referenced — that is what
# L1's digest-pin check is meant to catch.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOKINFO="${HERE}/bookinfo.yaml"
RESOLVED_BOOKINFO="/tmp/bookinfo-resolved.yaml"
TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)

# ── Digest resolution ────────────────────────────────────────────────────────
# Pulls the image locally and reads back the registry digest actually
# fetched. Falls back to the original tag reference (with a loud warning)
# if the pull fails — e.g. offline dev iteration — rather than hard-failing
# the whole deploy. In that fallback case L1's digest-pin check will
# correctly (if inconveniently) deny that pod, which is a signal to fix
# connectivity before trusting any L1-inclusive run.

resolve_digest() {
  local image_ref="$1"
  if ! docker pull "$image_ref" >/dev/null 2>&1; then
    echo "  (warn) could not pull $image_ref — leaving tag-referenced (L1 will deny this pod)" >&2
    echo "$image_ref"
    return
  fi
  local digest
  digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$image_ref" 2>/dev/null || true)
  if [[ -z "$digest" ]]; then
    echo "  (warn) no RepoDigest found for $image_ref — leaving tag-referenced" >&2
    echo "$image_ref"
  else
    echo "$digest"
  fi
}

echo "[tenants] resolving Bookinfo image digests"
cp "$BOOKINFO" "$RESOLVED_BOOKINFO"
for IMAGE_TAG in $(grep -oP '(?<=image: )\S+' "$BOOKINFO" | sort -u); do
  RESOLVED="$(resolve_digest "$IMAGE_TAG")"
  echo "  $IMAGE_TAG -> $RESOLVED"
  # escape / and & for sed replacement safety
  ESC_TAG=$(printf '%s\n' "$IMAGE_TAG" | sed 's/[&/\]/\\&/g')
  ESC_RESOLVED=$(printf '%s\n' "$RESOLVED" | sed 's/[&/\]/\\&/g')
  sed -i "s/${ESC_TAG}/${ESC_RESOLVED}/g" "$RESOLVED_BOOKINFO"
done

echo "[tenants] deploying Bookinfo into each tenant, node-pinned (digest-pinned images)"
for T in "${TENANTS[@]}"; do
  echo "  tenant: $T"
  kubectl create namespace "$T" 2>/dev/null || true
  kubectl label namespace "$T" tenant="$T" --overwrite >/dev/null
  kubectl apply -n "$T" -f "$RESOLVED_BOOKINFO" >/dev/null
  for d in $(kubectl get deploy -n "$T" -o name 2>/dev/null); do
    kubectl patch -n "$T" "$d" --type merge \
      -p "{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"tenant\":\"$T\"}}}}}" >/dev/null
  done
  # netshoot client pod for tests + attacks — digest-pinned (was nicolaka/netshoot:latest)
  CLIENT_IMAGE="$(resolve_digest nicolaka/netshoot:latest)"
  kubectl apply -n "$T" -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: client, namespace: $T }
spec:
  replicas: 1
  selector: { matchLabels: { app: client } }
  template:
    metadata: { labels: { app: client, tenant: $T } }
    spec:
      nodeSelector: { tenant: $T }
      containers:
        - { name: netshoot, image: "$CLIENT_IMAGE", command: [ "sleep", "infinity" ] }
YAML
done

echo "[tenants] establishing C0 baseline (L3a/RBAC not yet applied — see header)"
echo "  tenant-lowpriv: default SA = cluster-admin (removed by Controls/c2-rbac/apply.sh)"
kubectl create clusterrolebinding tenant-lowpriv-permissive \
  --clusterrole=cluster-admin --serviceaccount=tenant-lowpriv:default \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo "  tenant-partner: default SA = nodes read-only (overpermissioned-operator baseline; A3 precondition)"
kubectl apply -f - >/dev/null <<'YAML'
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

echo "[tenants] waiting for productpage in each tenant"
for T in "${TENANTS[@]}"; do
  kubectl rollout status -n "$T" deploy/productpage-v1 --timeout=180s \
    || echo "  (warn) $T productpage slow — verify later"
done

echo "[tenants] deploying Fortio benign load generator (digest-pinned)"
kubectl create namespace load --dry-run=client -o yaml | kubectl apply -f - >/dev/null
FORTIO_IMAGE="$(resolve_digest fortio/fortio:latest)"
kubectl -n load apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: fortio, namespace: load }
spec:
  replicas: 1
  selector: { matchLabels: { app: fortio } }
  template:
    metadata: { labels: { app: fortio } }
    spec:
      containers:
        - { name: fortio, image: "$FORTIO_IMAGE", command: [ "sleep", "infinity" ] }
YAML
kubectl -n load rollout status deploy/fortio --timeout=120s || true
echo "[tenants] done."
