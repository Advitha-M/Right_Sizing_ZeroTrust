#!/usr/bin/env bash
# =============================================================================
# Infra/k3s/teardown.sh — tear down the k3s cluster created by bootstrap.sh.
# Not called automatically by Driver/driver.py --mode l2-l3a-sep (same
# convention as every other mode leaving the KIND cluster running post-run,
# so results can be inspected before the cluster is discarded).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

K3S_INSTANCE="${K3S_INSTANCE:-1}"
K3S_SERVICE="k3s-${K3S_INSTANCE}"

echo "-> Uninstalling ${K3S_SERVICE}"
if command -v "/usr/local/bin/${K3S_SERVICE}-uninstall.sh" >/dev/null 2>&1; then
  sudo "/usr/local/bin/${K3S_SERVICE}-uninstall.sh"
elif [ -x "/usr/local/bin/${K3S_SERVICE}-uninstall.sh" ]; then
  sudo "/usr/local/bin/${K3S_SERVICE}-uninstall.sh"
else
  echo "   ${K3S_SERVICE}-uninstall.sh not found — instance may not be installed (idempotent no-op)"
fi

echo "-> Removing local kubeconfig copy"
rm -f "${HERE}/k3s-${K3S_INSTANCE}.yaml"

echo "teardown.sh done (instance ${K3S_SERVICE})."
