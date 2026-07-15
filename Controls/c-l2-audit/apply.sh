#!/usr/bin/env bash
# =============================================================================
# c-l2-audit apply — L2 (Cluster access control / audit logging), k3s ONLY
#
#  Everywhere else in this repo, L2 = BASE_LAYER (Driver/constants.py):
#  fixed, always active, baked into the KIND control plane's static pod
#  manifest at bootstrap, never toggled by a Controls/ apply.sh/remove.sh
#  pair. This script is the SOLE exception, scoped to the k3s (L2,L3a)
#  separation sampler (Driver/samplers_l2l3a_k3s.py), which needs to
#  measure L2's true solo DL contribution independent of L3a — which
#  requires L2 to actually vary across draws, not just L3a.
#
#  This is only feasible on k3s: k3s is a single systemd-managed binary,
#  so editing its kube-apiserver args and restarting is a few-second
#  operation, safe to repeat ~15-30 times per sampler run. Doing the
#  equivalent on the multi-node KIND cluster (kubeadm-style static pod
#  manifest edits) would be slower and riskier to repeat that many times,
#  which is why L2 stayed fixed for the rest of the study.
#
#  Mechanism: writes audit-policy.yaml to the k3s host, adds
#  --audit-policy-file / --audit-log-path to k3s's kube-apiserver-arg list
#  in /etc/rancher/k3s/config.yaml, and restarts the k3s service.
#  Idempotent: safe to run repeatedly.
#
#  Assumes: k3s installed on this host (systemd service "k3s"), passwordless
#  sudo already cached (see Infra/k3s/bootstrap.sh's "sudo -v" convention),
#  and K3S_CONFIG_DIR overridable via env for non-default installs.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

K3S_CONFIG_DIR="${K3S_CONFIG_DIR:-/etc/rancher/k3s}"
K3S_CONFIG_YAML="${K3S_CONFIG_DIR}/config.yaml"
AUDIT_POLICY_DST="${K3S_CONFIG_DIR}/c-l2-audit-policy.yaml"
AUDIT_LOG_PATH="${AUDIT_LOG_PATH:-/var/log/k3s-audit.log}"
# K3S_SERVICE lets parallel workers each restart their OWN native k3s
# instance (see Infra/k3s/bootstrap.sh's K3S_INSTANCE) instead of every
# worker fighting over the single hardcoded "k3s" systemd service. Pass the
# same K3S_SERVICE/K3S_CONFIG_DIR values bootstrap.sh printed for this
# worker's instance.
K3S_SERVICE="${K3S_SERVICE:-k3s}"

echo "[c-l2-audit] [1/3] installing audit policy to ${AUDIT_POLICY_DST}"
sudo mkdir -p "${K3S_CONFIG_DIR}"
sudo cp "${HERE}/audit-policy.yaml" "${AUDIT_POLICY_DST}"

echo "[c-l2-audit] [2/3] enabling audit flags in ${K3S_CONFIG_YAML}"
sudo touch "${K3S_CONFIG_YAML}"
if sudo grep -q "audit-policy-file" "${K3S_CONFIG_YAML}" 2>/dev/null; then
  echo "  audit flags already present — reusing (idempotent)"
else
  sudo tee -a "${K3S_CONFIG_YAML}" >/dev/null <<EOF
kube-apiserver-arg:
  - "audit-policy-file=${AUDIT_POLICY_DST}"
  - "audit-log-path=${AUDIT_LOG_PATH}"
EOF
  echo "  appended kube-apiserver-arg block"
fi

echo "[c-l2-audit] [3/3] restarting ${K3S_SERVICE} and waiting for apiserver"
sudo systemctl restart "${K3S_SERVICE}"
for i in $(seq 1 30); do
  kubectl get --raw='/healthz' >/dev/null 2>&1 && break
  sleep 2
done
if ! kubectl get --raw='/healthz' >/dev/null 2>&1; then
  echo "  (warn) apiserver did not report healthy within timeout — check "
  echo "  'systemctl status k3s' / 'journalctl -u k3s' manually"
fi

echo "[c-l2-audit] APPLIED — L2 audit logging active on this k3s node"
