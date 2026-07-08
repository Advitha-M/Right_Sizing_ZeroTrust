#!/usr/bin/env bash
# C3 remove — delete Constraints then ConstraintTemplates (admission wide-open)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[c3-opa] deleting Constraints"
kubectl delete -f "${HERE}/constraints.yaml" --ignore-not-found 2>/dev/null || true
echo "[c3-opa] deleting ConstraintTemplates"
kubectl delete -f "${HERE}/templates/" --ignore-not-found 2>/dev/null || true
echo "[c3-opa] REMOVED"
