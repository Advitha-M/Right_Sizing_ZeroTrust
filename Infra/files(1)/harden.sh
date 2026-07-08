#!/usr/bin/env bash
# =============================================================================
# infra/harden.sh — ONE-TIME host hardening (run BEFORE creating the cluster
# via `kind create cluster --config infra/kind-cluster.yaml`)
#
# Prevents the post-reboot Cilium/kube-proxy deadlock documented in
# infra/debug_reboot_cilium.txt. Root cause: the host default
# fs.inotify.max_user_instances=128 is shared across all 5 root-owned kind
# containers (zt-lab-control-plane + 4 tenant workers); after a reboot
# kube-proxy randomly fails with EMFILE on the nodes that lose the inotify
# race, cascading into Cilium deleteQueue overflow.
#
# Fix: raise inotify limits persistently so they are set before kind starts.
# Idempotent. Falls back to a privileged docker container if sudo is absent
# (matching how the limits were applied during the live recovery session).
#
# Unchanged by the v6 tenant-naming correction — this script operates purely
# on host kernel parameters and the (fixed) "zt-lab" cluster name, neither of
# which reference tenant namespaces.
# =============================================================================
set -uo pipefail

SYSCTL_FILE="/etc/sysctl.d/99-kind-kubernetes.conf"
read -r -d '' SETTINGS <<'EOF'
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 1048576
fs.inotify.max_queued_events = 32768
EOF

echo "[harden] target sysctl settings:"
echo "$SETTINGS" | sed 's/^/    /'

if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  echo "[harden] writing $SYSCTL_FILE (persistent across reboots)"
  echo "$SETTINGS" | sudo tee "$SYSCTL_FILE" >/dev/null
  sudo sysctl --system >/dev/null 2>&1 || true
  echo "[harden] applied via sysctl --system"
elif command -v sudo >/dev/null 2>&1; then
  echo "[harden] writing $SYSCTL_FILE (will prompt for sudo)"
  echo "$SETTINGS" | sudo tee "$SYSCTL_FILE" >/dev/null
  sudo sysctl --system >/dev/null 2>&1 || true
  echo "[harden] applied via sysctl --system"
else
  echo "[harden] sudo unavailable — applying live via privileged docker (non-persistent)"
  docker run --rm --privileged --pid=host alpine sh -c "
    echo 8192    > /proc/sys/fs/inotify/max_user_instances
    echo 1048576 > /proc/sys/fs/inotify/max_user_watches
    echo 32768   > /proc/sys/fs/inotify/max_queued_events
  " || echo "[harden] (warn) privileged docker fallback failed — set limits manually"
  echo "[harden] NOTE: write $SYSCTL_FILE manually for the fix to survive reboots."
fi

echo "[harden] current values:"
for k in max_user_instances max_user_watches max_queued_events; do
  printf '    fs.inotify.%s = %s\n' "$k" "$(cat /proc/sys/fs/inotify/$k 2>/dev/null || echo '?')"
done
echo "[harden] done. Next: kind create cluster --config infra/kind-cluster.yaml"
