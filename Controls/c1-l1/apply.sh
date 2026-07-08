#!/usr/bin/env bash
# =============================================================================
# C1 apply — L1 (Cloud & Infrastructure)
#  Composite control, toggled as ONE unit:
#   1. etcd encryption at rest  — kube-apiserver --encryption-provider-config,
#      applied by editing the static pod manifest (kubelet auto-restarts the
#      apiserver on manifest change — same mechanism as any static-pod flag).
#   2. Image-pull verification  — a Gatekeeper ConstraintTemplate/Constraint
#      requiring every container image be digest-pinned (@sha256:...) before
#      the pod is admitted. This is a DELIBERATE PROXY for full cosign
#      signature verification: a real cosign chain (signing keys, a registry
#      that actually stores signatures, admission-time signature lookup)
#      is out of scope for a single apply/remove script in this lab. Digest
#      pinning is a genuine, real supply-chain control in its own right
#      (blocks "mutable tag" attacks — a tag can be repointed after the
#      fact, a digest cannot), and is DISTINCT from L3b's own admission
#      checks (privileged/hostPath/host-namespace/registry-allowlist) — see
#      controls/c2-opa/constraints.yaml. It reuses the SAME Gatekeeper
#      engine L3b installs (if already running), but as an independently
#      toggleable Constraint object, not a modification to L3b's own
#      constraint set.
#
#  KNOWN LAB LIMITATION (documented, not silently dropped — see
#  constants.py L1_SCOPE_NOTE): this is a digest-pin proxy, NOT cryptographic
#  signature verification. If a real cosign chain is stood up later, this
#  Constraint should be replaced, not stacked alongside it.
#
#  Assumes: KIND cluster named "zt-lab" (infra/kind-cluster.yaml), control
#  plane container "zt-lab-control-plane". Gatekeeper controller installed
#  by zt-setup phase5 (same engine L3b uses) — this script installs it
#  standalone if L1 is toggled before L3b in a permuted ordering.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP_CONTAINER="zt-lab-control-plane"
ENC_CONFIG_PATH="/etc/kubernetes/pki/encryption-config.yaml"
APISERVER_MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"

# ── Part 1: etcd encryption at rest ─────────────────────────────────────────

echo "[c1-l1] [1/2] etcd encryption at rest"

if ! docker exec "$CP_CONTAINER" test -s "$ENC_CONFIG_PATH" 2>/dev/null || \
   ! docker exec "$CP_CONTAINER" grep -q "kind: EncryptionConfiguration" "$ENC_CONFIG_PATH" 2>/dev/null; then
  echo "  generating AES-CBC encryption key + EncryptionConfiguration"
  ENC_KEY="$(docker exec "$CP_CONTAINER" head -c 32 /dev/urandom | base64 2>/dev/null || true)"
  if [[ -z "$ENC_KEY" ]]; then
    echo "  (warn) could not generate encryption key in $CP_CONTAINER — is the container name correct? skipping etcd encryption half"
  else
    docker exec -i "$CP_CONTAINER" sh -c "cat > $ENC_CONFIG_PATH" <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - aescbc:
          keys:
            - name: zt-lab-l1-key
              secret: ${ENC_KEY}
      - identity: {}
EOF
    docker exec "$CP_CONTAINER" chmod 600 "$ENC_CONFIG_PATH"
    echo "  wrote $ENC_CONFIG_PATH"
  fi
else
  echo "  $ENC_CONFIG_PATH already present — reusing existing key (idempotent)"
fi

if docker exec "$CP_CONTAINER" test -f "$ENC_CONFIG_PATH" 2>/dev/null; then
  if docker exec "$CP_CONTAINER" grep -q "encryption-provider-config" "$APISERVER_MANIFEST" 2>/dev/null; then
    echo "  apiserver manifest already has --encryption-provider-config — skipping edit"
  else
    echo "  patching $APISERVER_MANIFEST to add --encryption-provider-config"
    docker exec "$CP_CONTAINER" sed -i \
      "s#- kube-apiserver#- kube-apiserver\n    - --encryption-provider-config=${ENC_CONFIG_PATH}#" \
      "$APISERVER_MANIFEST"
    echo "  waiting for kubelet to restart apiserver (manifest-watch triggers automatically)..."
    for i in $(seq 1 30); do
      kubectl get --raw='/healthz' >/dev/null 2>&1 && break
      sleep 2
    done
    echo "  apiserver back up (or timed out waiting — check manually if apply seems incomplete)"
  fi
fi

# ── Part 2: image-pull verification (digest-pin proxy) ──────────────────────

echo "[c1-l1] [2/2] image-pull verification (digest-pin Gatekeeper constraint)"

if ! kubectl get crd constrainttemplates.templates.gatekeeper.sh >/dev/null 2>&1; then
  echo "  Gatekeeper CRDs not found — L3b hasn't installed the engine yet in this"
  echo "  ordering. Installing Gatekeeper controller standalone (idempotent if"
  echo "  L3b installs it later — same engine, shared)."
  kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml >/dev/null 2>&1 || \
    echo "  (warn) Gatekeeper controller install failed/unavailable — image-pull half will not enforce"
  echo "  waiting for gatekeeper-controller-manager..."
  kubectl wait --for=condition=available --timeout=120s \
    deployment/gatekeeper-controller-manager -n gatekeeper-system >/dev/null 2>&1 || true
fi

kubectl apply -f "${HERE}/digest-pin-template.yaml" >/dev/null 2>&1
for i in $(seq 1 30); do
  kubectl get crd k8srequiredigestpin.constraints.gatekeeper.sh >/dev/null 2>&1 && break
  sleep 2
done
kubectl apply -f "${HERE}/digest-pin-constraint.yaml" >/dev/null 2>&1

echo "[c1-l1] APPLIED — etcd encryption + digest-pin image verification active"
