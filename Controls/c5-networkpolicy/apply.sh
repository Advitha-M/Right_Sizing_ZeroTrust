#!/usr/bin/env bash
# C5 apply — Cilium NetworkPolicy: default-deny + scoped allows
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[c5-networkpolicy] applying default-deny + intra-tenant + partner allows"
kubectl apply -f "${HERE}/networkpolicy.yaml" >/dev/null
echo "[c5-networkpolicy] APPLIED — tenant-finserv/tenant-partner network-isolated from tenant-lowpriv; tenant-saas allowed"
