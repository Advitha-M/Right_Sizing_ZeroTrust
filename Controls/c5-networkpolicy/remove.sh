#!/usr/bin/env bash
# C5 remove — delete all C2 NetworkPolicies (back to wide-open L3/L4)
set -uo pipefail
echo "[c5-networkpolicy] removing all zt-control=c5-networkpolicy NetworkPolicies"
for NS in tenant-lowpriv tenant-finserv tenant-partner tenant-saas; do
  kubectl delete networkpolicy -n "$NS" -l zt-control=c5-networkpolicy --ignore-not-found 2>/dev/null || true
done
echo "[c5-networkpolicy] REMOVED"
