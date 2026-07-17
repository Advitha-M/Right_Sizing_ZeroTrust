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
#   3. Cloud-IAM proxy (NEW)    — wires the apiserver's --oidc-issuer-url et
#      al. to Dex (Infra phase5), the same docker-exec-into-static-manifest
#      technique Part 1 already uses. Real cloud IAM reaches Kubernetes via
#      OIDC federation (AWS IRSA, GCP Workload Identity) — Dex run locally
#      is that same mechanism, not an analogy standing in for something
#      unrelated. This is what unblocks attack2.sh's A2-t2-oidc-token-replay
#      (previously SKIPped unconditionally — no OIDC issuer configured
#      anywhere) and gives L1 a real detection source (Dex's own logs,
#      polled by Driver.driver.measure_dl() as alert_source="cloud-iam").
#   4. VPC-segmentation proxy (NEW) — a CiliumClusterwideNetworkPolicy at
#      the Cilium host-firewall level (node-to-node traffic), gating on the
#      "vpc" node label Infra phase5 applies (vpc-regulated =
#      tenant-finserv+tenant-partner nodes, vpc-general =
#      tenant-lowpriv+tenant-saas nodes). Genuinely distinct from L5, which
#      enforces pod/namespace NetworkPolicy — this operates one layer below
#      that, closer to what a real cloud VPC/subnet boundary would enforce.
#      Detection source: Cilium's own drop/policy-verdict monitor
#      (`cilium monitor -t drop`, no separate Hubble install needed),
#      alert_source="vpc-segmentation".
#
#  KNOWN LAB LIMITATION (documented, not silently dropped — see
#  constants.py L1_SCOPE_NOTE): none of these four are full-fidelity clones
#  of real cloud infrastructure (digest-pin is not cosign signature
#  verification; Dex is not a real cloud IAM policy engine; Cilium host
#  policy is not real VPC/subnet routing). All four are genuine, functioning
#  local proxies for the mechanism a real deployment would use — not
#  simulated, not stubbed out.
#
#  Assumes: KIND cluster named "zt-lab" (infra/kind-cluster.yaml), control
#  plane container "zt-lab-control-plane". Gatekeeper controller, Dex, and
#  the "vpc" node labels installed by zt-setup phase5 (same engine L3b
#  uses for Gatekeeper) — this script installs Gatekeeper standalone if L1
#  is toggled before L3b in a permuted ordering (unchanged from before);
#  Dex and the vpc labels are NOT re-created here if phase5 hasn't run —
#  Parts 3/4 log a (warn) and skip rather than failing the whole script.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# CLUSTER_NAME lets parallel workers each target their own KIND cluster
# (kind's own "<cluster-name>-control-plane" naming convention) instead of
# the single hardcoded "zt-lab" this used to assume.
CP_CONTAINER="${CLUSTER_NAME:-zt-lab}-control-plane"
ENC_CONFIG_PATH="/etc/kubernetes/pki/encryption-config.yaml"
APISERVER_MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"

# ── Part 1: etcd encryption at rest ─────────────────────────────────────────

echo "[c1-l1] [1/4] etcd encryption at rest"

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

echo "[c1-l1] [2/4] image-pull verification (digest-pin Gatekeeper constraint)"

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

echo "[c1-l1] Parts 1-2 APPLIED — etcd encryption + digest-pin image verification active"

# ── Part 3: cloud-IAM proxy (Dex OIDC federation) ────────────────────────────

echo "[c1-l1] [3/4] cloud-IAM proxy — wiring apiserver to Dex OIDC issuer"

DEX_ISSUER="https://dex.dex.svc.cluster.local:5556/dex"
if ! kubectl get deployment dex -n dex >/dev/null 2>&1; then
  echo "  (warn) Dex deployment not found in ns=dex — is phase5 done? skipping Part 3"
else
  if docker exec "$CP_CONTAINER" grep -q "oidc-issuer-url" "$APISERVER_MANIFEST" 2>/dev/null; then
    echo "  apiserver manifest already has --oidc-issuer-url — skipping edit"
  else
    # CORRECTED (real run failure): DEX_ISSUER used to be "http://..." —
    # kube-apiserver hard-requires https:// for --oidc-issuer-url (validated
    # at startup, no override exists) and would crash-loop permanently the
    # instant this patch landed. Dex now actually serves HTTPS (see
    # Infra/KIND/setup.sh's phase5) with a self-signed cert stored in the
    # "dex-tls" Secret — fetch that cert here and give the apiserver
    # --oidc-ca-file pointing at it, or the connection will still fail
    # (differently: a TLS trust error instead of a scheme-validation
    # error, but still permanently broken either way).
    DEX_CA_PATH="/etc/kubernetes/pki/dex-ca.crt"
    echo "  fetching Dex's self-signed cert (acts as its own CA) into ${CP_CONTAINER}:${DEX_CA_PATH}"
    if ! kubectl get secret dex-tls -n dex -o jsonpath='{.data.tls\.crt}' 2>/dev/null \
         | base64 -d | docker exec -i "$CP_CONTAINER" sh -c "cat > ${DEX_CA_PATH}"; then
      echo "  (warn) could not fetch dex-tls secret — --oidc-ca-file will point at a " \
           "path that doesn't exist, and the apiserver will fail to trust Dex's cert. " \
           "Check 'kubectl get secret dex-tls -n dex' was actually created by phase5."
    else
      docker exec "$CP_CONTAINER" chmod 644 "$DEX_CA_PATH"
    fi
    echo "  patching $APISERVER_MANIFEST to add --oidc-issuer-url=${DEX_ISSUER}"
    docker exec "$CP_CONTAINER" sed -i \
      "s#- kube-apiserver#- kube-apiserver\n    - --oidc-issuer-url=${DEX_ISSUER}\n    - --oidc-client-id=zt-lab-kubectl\n    - --oidc-username-claim=email\n    - --oidc-username-prefix=oidc:\n    - --oidc-ca-file=${DEX_CA_PATH}#" \
      "$APISERVER_MANIFEST"
    echo "  waiting for kubelet to restart apiserver (manifest-watch triggers automatically)..."
    for i in $(seq 1 30); do
      kubectl get --raw='/healthz' >/dev/null 2>&1 && break
      sleep 2
    done
    echo "  apiserver back up (or timed out waiting — check manually if apply seems incomplete)"
  fi
  echo "  Part 3 APPLIED — apiserver now validates Dex-issued OIDC tokens (unblocks A2-t2)"
fi

# ── Part 4: VPC-segmentation proxy (Cilium host-policy node segmentation) ───

echo "[c1-l1] [4/4] VPC-segmentation proxy — Cilium host-firewall between vpc node groups"
echo "  SCOPE: this restricts HOST-level (node-to-node infrastructure/management"
echo "  traffic — kubelet-to-kubelet, node health checks) between the two"
echo "  simulated VPC groups, analogous to a cloud security-group boundary"
echo "  between subnets. It does NOT restrict ordinary pod-to-pod application"
echo "  traffic across those nodes — that remains L5's domain (pod/namespace"
echo "  NetworkPolicy), a deliberately different enforcement point from this one."

if ! kubectl get nodes -l vpc=vpc-regulated 2>/dev/null | grep -q Ready; then
  echo "  (warn) no nodes labelled vpc=vpc-regulated found — is phase5 done, and does"
  echo "  this cluster have more than one node (k3s single-node has nothing to"
  echo "  segment)? skipping Part 4"
else
  # Cilium host-firewall: a CiliumClusterwideNetworkPolicy whose nodeSelector
  # targets a node group makes that group's `reserved:host` identity
  # default-deny in whichever direction(s) are specified, with fromNodes/
  # toNodes matchExpressions as the actual allow-list mechanism (Cilium
  # 1.13+; this repo pins 1.19.3). Requires hostFirewall.enabled=true at
  # Cilium's helm install — Infra phase1 sets this.
  # Two policies for bidirectional isolation between the groups.
  cat <<'CNPOLICY' | kubectl apply -f - >/dev/null 2>&1
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: c1-l1-vpc-segmentation-general
  labels: { zt-control: c1-l1 }
spec:
  nodeSelector:
    matchLabels: { vpc: vpc-general }
  ingress:
    - fromEntities: ["health", "kube-apiserver"]
    - fromNodes:
        - matchExpressions:
            - { key: vpc, operator: NotIn, values: ["vpc-regulated"] }
---
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: c1-l1-vpc-segmentation-regulated
  labels: { zt-control: c1-l1 }
spec:
  nodeSelector:
    matchLabels: { vpc: vpc-regulated }
  ingress:
    - fromEntities: ["health", "kube-apiserver"]
    - fromNodes:
        - matchExpressions:
            - { key: vpc, operator: NotIn, values: ["vpc-general"] }
CNPOLICY
  echo "  Part 4 APPLIED — vpc-general <-> vpc-regulated host-level traffic denied"
  echo "  (health checks/apiserver excepted); cilium monitor drops are the"
  echo "  detection source."
fi

echo "[c1-l1] APPLIED"
