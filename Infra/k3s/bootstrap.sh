#!/usr/bin/env bash
# =============================================================================
# Infra/k3s/bootstrap.sh — stand up the single-node k3s cluster used ONLY by
# Driver/driver.py's --mode l2-l3a-sep (Driver/samplers_l2l3a_k3s.py).
#
#  Why a second cluster at all: L2 (audit logging) is baked into the KIND
#  cluster's static apiserver manifest at bootstrap and is never toggled
#  there (Driver/constants.BASE_LAYER). Measuring L2's true solo DL
#  contribution against L3a requires L2 to actually vary, which requires
#  cheap, repeated apiserver restarts — feasible on k3s (single systemd
#  binary, `systemctl restart k3s` takes seconds), not on the multi-node
#  KIND cluster. See Controls/c-l2-audit/apply.sh's header for the full
#  rationale. This is a SEPARATE cluster from the main KIND one; the two
#  must never be pointed at by the same kubeconfig/run.
#
#  What this script provisions (mirrors Infra/files(1)/setup.sh's phases
#  1-3+5, retargeted at k3s):
#    - k3s server (single node, Traefik/ServiceLB disabled — not needed)
#    - the four v6 tenant namespaces + C0 permissive RBAC baseline +
#      finserv-static-credentials secret (same content as KIND Phase 2)
#    - Falco (namespace 'falco') — Driver.driver.measure_dl() polls this
#      on WHICHEVER cluster KUBECONFIG points at, so it must exist here
#      too for DL measurement to work during l2-l3a-sep runs
#    - OPA Gatekeeper + Istio + Vault (installed, not enforcing) — needed
#      because l2_l3a_separation_sampler's "others" pool (L1,L3b,L4,L5,L6,L7)
#      can land inside a draw's precursor/active set, and set_config_k3s()
#      will call those layers' existing Controls/*/apply.sh scripts
#      against THIS cluster
#
#  KNOWN LIMITATION — read before running draws that include L1: this repo's
#  Controls/c1-l1/apply.sh does `docker exec zt-lab-control-plane ...` for
#  its etcd-encryption half, which is a KIND-specific control-plane
#  container name. That branch will silently fail (script has `set -uo
#  pipefail`, not `-e`, and swallows docker exec errors) against a
#  host-installed k3s node — the digest-pin (Gatekeeper) half of L1 still
#  works, but etcd encryption will not actually be toggled here. Same
#  caution applies to any other control that assumes KIND's docker-based
#  layout rather than a plain kubectl-addressable cluster. Verify each
#  Controls/*/apply.sh manually against this cluster before trusting L1/L6/L7
#  results from an l2-l3a-sep run; this script does not attempt to fix that
#  compatibility gap.
#
#  Usage:
#     sudo -v                     # cache your password ONCE
#     Infra/k3s/bootstrap.sh       # idempotent, safe to re-run
#
#  Env overrides: K3S_CONFIG_DIR (default /etc/rancher/k3s), matches
#  Controls/c-l2-audit/apply.sh's default.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
K3S_CONFIG_DIR="${K3S_CONFIG_DIR:-/etc/rancher/k3s}"

# ADDED (validation pass): dependency preflight — checks kubectl/helm/
# python3+scipy+numpy, installs whichever is missing, and restarts this
# script once so freshly-installed tools are picked up cleanly. docker/kind
# checks are skipped for this path (k3s runs directly on the host, no KIND/
# docker involved) — see Infra/preflight.sh's header.
source "${HERE}/../preflight.sh" k3s "$0" "$@"

TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)

banner(){ echo; echo "=============================================="; echo "$1"; echo "=============================================="; }
step(){ echo "-> $1"; }

banner "Infra/k3s/bootstrap.sh — (L2,L3a) separation sampler cluster"

step "Installing k3s (single node; Traefik + ServiceLB disabled — not used here)"
if ! command -v k3s >/dev/null 2>&1; then
  curl -sfL https://get.k3s.io | \
    INSTALL_K3S_EXEC="server --disable traefik --disable servicelb" sh -
else
  echo "   k3s already installed — skipping install (idempotent)"
fi

step "Waiting for k3s apiserver"
sudo mkdir -p "${K3S_CONFIG_DIR}"
for i in $(seq 1 30); do
  sudo test -f /etc/rancher/k3s/k3s.yaml && break
  sleep 2
done

step "Copying kubeconfig to ${HERE}/k3s.yaml (Driver/config.py's K3S_KUBECONFIG)"
sudo cp /etc/rancher/k3s/k3s.yaml "${HERE}/k3s.yaml"
sudo chmod 644 "${HERE}/k3s.yaml"
# Single-node install — server URL (127.0.0.1) is already correct, no rewrite needed.
export KUBECONFIG="${HERE}/k3s.yaml"
for i in $(seq 1 30); do
  kubectl get --raw='/healthz' >/dev/null 2>&1 && break
  sleep 2
done

step "Creating tenant namespaces (v6 naming, same as Infra/files(1)/setup.sh Phase 2)"
kubectl delete ns "${TENANTS[@]}" --ignore-not-found --wait=true 2>/dev/null || true
for t in "${TENANTS[@]}"; do
  kubectl create ns "$t" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
done

step "Applying permissive C0 RBAC baseline (removed by Controls/c2-rbac/apply.sh at C2)"
kubectl create clusterrolebinding tenant-lowpriv-permissive \
  --clusterrole=cluster-admin --serviceaccount=tenant-lowpriv:default \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create clusterrole tenant-partner-nodes-read \
  --verb=get,list,watch --resource=nodes \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create clusterrolebinding tenant-partner-nodes-read \
  --clusterrole=tenant-partner-nodes-read --serviceaccount=tenant-partner:default \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

step "Provisioning finserv-static-credentials (removed by Controls/c7-vault/apply.sh at C7)"
kubectl create secret generic finserv-static-credentials \
  --namespace tenant-finserv \
  --from-literal=api_key="mock-static-key-$(date +%s)" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

step "Deploying tenant workloads (Tenants/bookinfo.yaml, per namespace)"
for t in "${TENANTS[@]}"; do
  kubectl apply -n "$t" -f "${REPO_ROOT}/Tenants/bookinfo.yaml" >/dev/null 2>&1 || \
    echo "   (warn) workload deploy into $t had an issue — verify later"
done

step "Installing Falco (namespace 'falco' — Driver.driver.measure_dl() depends on this)"
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1
helm repo update >/dev/null
helm upgrade --install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=modern_ebpf --set tty=true \
  --set falcosidekick.enabled=false \
  --wait --timeout 5m || echo "   (warn) Falco install issue — verify later"

step "Installing OPA Gatekeeper (present, not enforcing — needed if L1/L3b land in a draw)"
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts >/dev/null 2>&1
helm repo update >/dev/null
helm upgrade --install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system --create-namespace \
  --wait --timeout 5m || echo "   (warn) gatekeeper issue — verify later"

step "Installing Istio minimal profile (present, not enforcing — needed if L6 lands in a draw)"
if ! command -v istioctl >/dev/null 2>&1; then
  (cd /tmp && curl -fsSL https://istio.io/downloadIstio | sh -)
  IST=$(ls -d /tmp/istio-* 2>/dev/null | head -1)
  [ -n "$IST" ] && sudo install -m 0755 "$IST/bin/istioctl" /usr/local/bin/istioctl
fi
istioctl install --set profile=minimal -y || echo "   (warn) istio install issue — verify later"

step "Installing Vault dev mode (present, not enforcing — needed if L7 lands in a draw)"
helm repo add hashicorp https://helm.releases.hashicorp.com >/dev/null 2>&1
helm repo update >/dev/null
helm upgrade --install vault hashicorp/vault \
  --namespace vault --create-namespace \
  --set "server.dev.enabled=true" --set "server.dev.devRootToken=root" \
  --wait --timeout 5m || echo "   (warn) vault issue — verify later"

step "Installing SPIRE server + agent (present, not enforcing — needed if L7 lands in a draw)"
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ >/dev/null 2>&1
helm repo update >/dev/null
helm upgrade --install spire spiffe/spire \
  --namespace spire --create-namespace \
  --set global.spire.trustDomain=cluster.local \
  --set global.spire.clusterName=zt-lab-k3s \
  --wait --timeout 5m || echo "   (warn) SPIRE install issue — verify later"

step "Installing Dex (present, not enforcing — needed if L1 lands in a draw)"
kubectl create namespace dex --dry-run=client -o yaml | kubectl apply -f - >/dev/null
cat <<'DEXCFG' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: dex-config
  namespace: dex
data:
  config.yaml: |
    issuer: http://dex.dex.svc.cluster.local:5556/dex
    storage: { type: memory }
    web: { http: 0.0.0.0:5556 }
    oauth2: { responseTypes: ["code", "token", "id_token"], skipApprovalScreen: true }
    expiry: { idTokens: "30s" }
    staticClients:
      - id: zt-lab-kubectl
        secret: zt-lab-kubectl-secret
        name: zt-lab-kubectl
        redirectURIs: ["http://localhost/callback"]
        public: false
    enablePasswordDB: true
    staticPasswords:
      - email: "attacker@zt-lab.local"
        # Same verified hash as Infra/files(1)/setup.sh's phase5 (password: attacker-pw)
        hash: "$2b$10$5SXv5Hj.yJYlXYxEYDo9GuEOIhxCCUBQ23cel2lbv2PZ7hIDVb1/G"
        username: "attacker"
        userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
DEXCFG
cat <<'DEXDEPLOY' | kubectl apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: { name: dex, namespace: dex }
spec:
  replicas: 1
  selector: { matchLabels: { app: dex } }
  template:
    metadata: { labels: { app: dex } }
    spec:
      containers:
        - name: dex
          image: dexidp/dex:v2.41.1
          args: ["dex", "serve", "/etc/dex/cfg/config.yaml"]
          ports: [{ containerPort: 5556 }]
          volumeMounts: [{ name: config, mountPath: /etc/dex/cfg }]
      volumes:
        - { name: config, configMap: { name: dex-config } }
---
apiVersion: v1
kind: Service
metadata: { name: dex, namespace: dex }
spec:
  selector: { app: dex }
  ports: [{ port: 5556, targetPort: 5556 }]
DEXDEPLOY
kubectl -n dex rollout status deployment/dex --timeout=90s \
  || echo "   (warn) dex not Ready — check 'kubectl -n dex get pods'"
# NOTE: no vpc=vpc-regulated/vpc-general node labelling here, unlike
# Infra/files(1)/setup.sh's phase5 — this is a single-node k3s cluster, so
# node-level VPC-segmentation (Controls/c1-l1 Part 4) has nothing to
# segment. If L1 lands in an l2-l3a-sep draw, its Part 4 step will find no
# matching nodes and log a (warn), not fail — Part 3 (Dex/OIDC) is
# unaffected and still applies normally on a single node.

banner "bootstrap.sh done"
echo "KUBECONFIG for this cluster: ${HERE}/k3s.yaml (= Driver/config.py's K3S_KUBECONFIG)"
echo "L2 (audit logging) is OFF by default — Controls/c-l2-audit/apply.sh turns it on;"
echo "Driver/driver.py --mode l2-l3a-sep toggles it automatically per draw."
echo "Next: python3 Driver/driver.py --mode l2-l3a-sep --dry-run   (sanity check)"
echo "Then: python3 Driver/driver.py --mode l2-l3a-sep --trials 50"
