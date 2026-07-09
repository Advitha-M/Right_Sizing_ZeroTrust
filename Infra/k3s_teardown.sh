#!/usr/bin/env bash
# =============================================================================
# Infra/k3s/teardown.sh — tear down the k3s cluster created by bootstrap.sh.
# Not called automatically by Driver/driver.py --mode l2-l3a-sep (same
# convention as every other mode leaving the KIND cluster running post-run,
# so results can be inspected before the cluster is discarded).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "-> Uninstalling k3s"
if command -v /usr/local/bin/k3s-uninstall.sh >/dev/null 2>&1; then
  sudo /usr/local/bin/k3s-uninstall.sh
elif [ -x /usr/local/bin/k3s-uninstall.sh ]; then
  sudo /usr/local/bin/k3s-uninstall.sh
else
  echo "   k3s-uninstall.sh not found — k3s may not be installed (idempotent no-op)"
fi

echo "-> Removing local kubeconfig copy"
rm -f "${HERE}/k3s.yaml"

echo "teardown.sh done."
