#!/usr/bin/env bash
# =============================================================================
# infra/recover.sh — automated post-reboot recovery for the kind cluster
#
# Automates the repair sequence from infra/debug_reboot_cilium.txt for when the
# host was rebooted WITHOUT infra/harden.sh having raised inotify limits, and
# nodes come back with Cilium/kube-proxy Unknown/CrashLoopBackOff and an
# overflowed Cilium deleteQueue.
#
# Steps (idempotent, safe to re-run):
#   1. raise inotify limits live (privileged docker)
#   2. clear overflowed Cilium deleteQueue on every node
#   3. force-delete Unknown/CrashLoopBackOff/Error Cilium & kube-proxy pods
#      so DaemonSets recreate them
#   4. wait for Cilium to go Ready on all nodes (eBPF restores ClusterIP routing)
#
# We deliberately do NOT re-add the temporary manual DNAT / static pod-CIDR
# routes from the live session: those were only needed because sudo was absent
# mid-incident; once inotify is fixed and the deleteQueue cleared, Cilium's own
# eBPF restores routing automatically (see "Fix 6" in the debug log).
#
# FIX vs prior version: step 3's awk filter had `/CrashLoopBackOff||Error/` —
# the doubled pipe creates an empty middle alternative (CrashLoopBackOff | "" |
# Error), and an empty regex alternative matches every line. That collapsed
# the whole condition to just `/cilium|kube-proxy/`, so it force-deleted ALL
# Cilium/kube-proxy pods on every run, including healthy Running ones, not
# just broken ones. Corrected to a single pipe below.
#
# Unaffected by the v6 tenant-naming correction — recovery only touches
# kube-system (Cilium/kube-proxy), not tenant namespaces.
# =============================================================================
set -uo pipefail
CLUSTER="${CLUSTER_NAME:-zt-lab}"

nodes() { docker ps --format '{{.Names}}' | grep "^${CLUSTER}-" || true; }

echo "[recover] === step 1: raise inotify limits live ==="
docker run --rm --privileged --pid=host alpine sh -c "
  echo 8192    > /proc/sys/fs/inotify/max_user_instances
  echo 1048576 > /proc/sys/fs/inotify/max_user_watches
  echo 32768   > /proc/sys/fs/inotify/max_queued_events
" 2>/dev/null && echo "  inotify limits raised" || echo "  (warn) could not raise inotify limits"

echo "[recover] === step 2: clear Cilium deleteQueue on every node ==="
for n in $(nodes); do
  CNT=$(docker exec "$n" sh -c 'ls /var/run/cilium/deleteQueue/*.delete 2>/dev/null | wc -l' 2>/dev/null || echo 0)
  docker exec "$n" sh -c 'rm -f /var/run/cilium/deleteQueue/*.delete' 2>/dev/null || true
  echo "  $n: cleared ${CNT} stale delete entries"
done

echo "[recover] === step 3: force-delete Unknown/CrashLoopBackOff/Error Cilium / kube-proxy pods ==="
kubectl get pods -n kube-system -o wide 2>/dev/null \
  | awk '/cilium|kube-proxy/ && (/Unknown/ || /CrashLoopBackOff/ || /Error/){print $1}' \
  | while read -r p; do
      [[ -n "$p" ]] && kubectl delete pod "$p" -n kube-system --force --grace-period=0 2>/dev/null || true
      echo "  force-deleted $p"
    done

echo "[recover] === step 4: wait for Cilium DaemonSet to become Ready ==="
kubectl -n kube-system rollout status daemonset/cilium --timeout=240s 2>/dev/null \
  && echo "  Cilium Ready on all nodes" \
  || echo "  (warn) Cilium not fully Ready yet — re-run recover or check 'kubectl get pods -A'"

echo "[recover] === node status ==="
kubectl get nodes 2>/dev/null || true
echo "[recover] done. If pods are still Unknown, wait 60s and re-run: ./infra/recover.sh"
