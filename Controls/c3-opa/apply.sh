#!/usr/bin/env bash
# =============================================================================
# C3 apply — OPA Gatekeeper ConstraintTemplates + Constraints
#  1. apply the 3 ConstraintTemplates (creates the Constraint CRDs)
#  2. wait for the new CRDs to register
#  3. apply the Constraints (deny privileged/hostPath, host namespaces, registries)
# Assumes gatekeeper controller is installed (zt-setup phase5).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[c3-opa] applying ConstraintTemplates"
kubectl apply -f "${HERE}/templates/" >/dev/null

echo "[c3-opa] waiting for Constraint CRDs to register"
for crd in k8sdenyprivileged k8sdenyhostnamespaces k8sallowedregistries; do
  for i in $(seq 1 30); do
    kubectl get crd "${crd}.constraints.gatekeeper.sh" >/dev/null 2>&1 && break
    sleep 2
  done
done
# gatekeeper needs a moment to start serving the new constraint kinds
sleep 5

echo "[c3-opa] applying Constraints"
kubectl apply -f "${HERE}/constraints.yaml" >/dev/null

echo "[c3-opa] APPLIED — privileged/hostPath/host-ns denied; only allowed registries admitted"
