#!/usr/bin/env bash
# =============================================================================
# c-l2-audit remove — reverts apply.sh's changes, k3s ONLY.
#
#  Mirrors apply.sh's three steps in reverse:
#    1. strip the audit-policy-file / audit-log-path kube-apiserver-arg
#       entries (and the now-empty kube-apiserver-arg: key itself) out of
#       ${K3S_CONFIG_DIR}/config.yaml
#    2. delete the copied audit-policy file at ${K3S_CONFIG_DIR}
#    3. restart k3s and wait for the apiserver to report healthy again
#  Idempotent: safe to run repeatedly, and a no-op if apply.sh was never run
#  (or was already removed) — same convention as this repo's other
#  Controls/*/remove.sh scripts (c1-l1, c7-vault).
#
#  NOTE: this script assumes c-l2-audit is the ONLY thing that has ever
#  written a kube-apiserver-arg: block to this k3s node's config.yaml (true
#  for this repo's own automation — apply.sh's idempotency check confirms
#  it's the sole owner of that key here). If this config.yaml is ever
#  hand-edited to add other kube-apiserver-arg entries alongside these two,
#  this script's blanket removal of the key line would need to become
#  additive-only (strip just the two known list items, keep the key line
#  if anything else remains under it) rather than removing the key
#  outright — not needed for this repo's current usage, called out here so
#  a future editor doesn't assume it silently.
#
#  Assumes: k3s installed on this host (systemd service "k3s"), passwordless
#  sudo already cached (see Infra/k3s/bootstrap.sh's "sudo -v" convention),
#  and K3S_CONFIG_DIR overridable via env for non-default installs — same
#  defaults as apply.sh, so remove.sh finds what apply.sh created without
#  needing separate configuration.
# =============================================================================
set -uo pipefail

K3S_CONFIG_DIR="${K3S_CONFIG_DIR:-/etc/rancher/k3s}"
K3S_CONFIG_YAML="${K3S_CONFIG_DIR}/config.yaml"
AUDIT_POLICY_DST="${K3S_CONFIG_DIR}/c-l2-audit-policy.yaml"
K3S_SERVICE="${K3S_SERVICE:-k3s}"

echo "[c-l2-audit] [1/3] removing audit flags from ${K3S_CONFIG_YAML}"
if sudo test -f "${K3S_CONFIG_YAML}" && sudo grep -q "audit-policy-file=" "${K3S_CONFIG_YAML}" 2>/dev/null; then
  # Strip the two list items apply.sh added, then drop the kube-apiserver-arg:
  # key line too if nothing else is left under it (see NOTE above on why a
  # blanket removal is safe for this repo's current usage). Done via a
  # temp file + sudo tee rather than sudo sed -i, since sed -i needs write
  # access to the directory as well as the file under sudo on some hosts.
  TMP_CONFIG="$(mktemp)"
  sudo awk '
    /^kube-apiserver-arg:[[:space:]]*$/ { pending_key = $0; next }
    /audit-policy-file=/ { skip_key = 1; next }
    /audit-log-path=/    { skip_key = 1; next }
    {
      if (pending_key != "") {
        if (!skip_key) print pending_key
        pending_key = ""
      }
      print
    }
    END {
      if (pending_key != "" && !skip_key) print pending_key
    }
  ' "${K3S_CONFIG_YAML}" > "${TMP_CONFIG}"
  sudo cp "${TMP_CONFIG}" "${K3S_CONFIG_YAML}"
  rm -f "${TMP_CONFIG}"
  echo "  removed audit-policy-file / audit-log-path kube-apiserver-arg entries"
else
  echo "  audit flags not present — nothing to remove (idempotent no-op)"
fi

echo "[c-l2-audit] [2/3] removing copied audit policy ${AUDIT_POLICY_DST}"
sudo rm -f "${AUDIT_POLICY_DST}"
echo "  removed (or was not present)"

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

echo "[c-l2-audit] REMOVED — L2 audit logging reverted on this k3s node"
