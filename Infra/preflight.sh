#!/usr/bin/env bash
# =============================================================================
# Infra/preflight.sh — dependency preflight check, self-heal, and restart
#
# ADDED (validation pass): previously nothing in this repo checked for
# docker, kind, kubectl, helm, python3, or scipy/numpy before using them —
# every one of the 264 kubectl / 41 helm / etc. call sites just assumed the
# tool worked, and the KIND cluster itself was never created by any script
# at all (kind create cluster was never invoked anywhere). k3s and istioctl
# were the only two dependencies that were ever actually checked+installed.
# This script brings every dependency up to that same standard: check ->
# install if absent -> restart the calling script cleanly so the freshly
# installed tool is picked up in a new process rather than assumed to be on
# PATH within the same shell.
#
# USAGE (sourced, not executed, as the very first line of a caller):
#   source "${REPO_ROOT}/Infra/preflight.sh" kind "$0" "$@"     # KIND path
#   source "${HERE}/../preflight.sh"          k3s  "$0" "$@"     # k3s path
#
# $1 = substrate ("kind" or "k3s") — gates docker + KIND-cluster-creation
#      checks, which only apply to the KIND path; kubectl/helm/python are
#      checked either way since both substrates use them.
# $2 = the calling script's own path ($0), so this can re-exec it
# $@ (rest) = the calling script's original arguments, replayed on restart
#
# WHAT THIS CANNOT FIX (hard-fails immediately, does not loop/restart):
#   - no internet access — nothing here can install connectivity
#   - insufficient CPU/RAM/disk — nothing here can add hardware; this is a
#     WARN not a hard-fail, since the study may still run, just riskily
#   - a dependency still missing after one restart already happened —
#     treated as an installation failure, not something to retry forever
#
# RESTART SEMANTICS: at most ONE restart per invocation, tracked via
# ZT_PREFLIGHT_RESTARTS (inherited across exec). If docker was freshly
# installed, the restart runs via `sg docker -c ...` so the new group
# membership is actually active in the restarted process — a plain re-exec
# in the same login session would NOT pick up a fresh `usermod -aG docker`
# without this, since group membership is normally only re-read at login.
# =============================================================================

_PF_SUBSTRATE="${1:?preflight.sh: substrate (kind|k3s) required}"; shift
_PF_CALLER="${1:?preflight.sh: caller script path ($0) required}"; shift
_PF_CALLER_ARGS=("$@")

_pf_log()  { echo "[preflight] $*"; }
_pf_warn() { echo "[preflight] (warn) $*" >&2; }
_pf_fail() { echo "[preflight] FAIL: $*" >&2; exit 1; }

_PF_NEEDS_RESTART=false
_PF_DOCKER_FRESH=false

_pf_arch_suffix() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) _pf_fail "unsupported architecture: $(uname -m) — install dependencies manually" ;;
  esac
}

# Infra/ directory — computed once, reused by _pf_ensure_kind_cluster (kind-
# cluster.yaml lives at ${_PF_INFRA_DIR}/files(1)/) and _pf_check_python
# (requirements.txt lives at ${_PF_INFRA_DIR}/../).
_PF_INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Wraps privileged commands: uses sudo if present, runs directly if already
# root, fails clearly otherwise — rather than crashing on "sudo: command not
# found" (containers/some minimal hosts have no sudo binary at all, but may
# already be running as root).
_pf_sudo() {
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  elif [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    _pf_fail "need root to run: $* — no sudo binary found and not running as " \
             "root. Install manually as root/with sudo and re-run."
  fi
}

# ---------------------------------------------------------------------------
# Checks that CANNOT be fixed by installing anything — fail/warn immediately,
# never contribute to the restart loop.
# ---------------------------------------------------------------------------
_pf_check_internet() {
  _pf_log "checking internet access..."
  if curl -fsS --max-time 5 https://github.com -o /dev/null 2>/dev/null \
     || curl -fsS --max-time 5 https://pypi.org -o /dev/null 2>/dev/null; then
    _pf_log "  OK: internet reachable"
  else
    _pf_fail "no internet access (tried github.com, pypi.org) — every remaining " \
             "check needs to download something the first time it's missing; " \
             "nothing in this script can install connectivity. Fix networking " \
             "and re-run."
  fi
}

_pf_check_resources() {
  _pf_log "checking CPU/memory/disk sizing (5-node KIND + Cilium + Istio + " \
          "Gatekeeper + Vault + SPIRE + Falco is a heavy stack)..."
  local cores mem_mb disk_gb
  cores=$(nproc 2>/dev/null || echo 0)
  mem_mb=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
  disk_gb=$(df -Pm . 2>/dev/null | awk 'NR==2{print int($4/1024)}')

  local min_cores=4 min_mem_mb=8000 min_disk_gb=20
  [[ "$cores" -lt "$min_cores" ]] && \
    _pf_warn "only ${cores} CPU core(s) detected (recommended >= ${min_cores}) — " \
             "the study may run, but expect slow/flaky trials, especially under " \
             "the Shapley MC sampler's concurrent-looking condition churn."
  [[ -n "$mem_mb" && "$mem_mb" -lt "$min_mem_mb" ]] && \
    _pf_warn "only ${mem_mb}MB memory detected (recommended >= ${min_mem_mb}MB) — " \
             "Cilium+Istio+Gatekeeper+Vault+SPIRE+Falco running together can OOM " \
             "a node at this size; watch for evicted pods."
  [[ -n "$disk_gb" && "$disk_gb" -lt "$min_disk_gb" ]] && \
    _pf_warn "only ${disk_gb}GB free disk detected (recommended >= ${min_disk_gb}GB) " \
             "— container images for 8+ control-plane components plus results.db " \
             "growth over a full run can add up."
  _pf_log "  resource check complete (warnings above, if any, are non-fatal — " \
          "nothing here can add hardware, so this cannot restart/fix itself)"
}

# ---------------------------------------------------------------------------
# Checks that CAN be fixed by installing something — each sets
# _PF_NEEDS_RESTART=true if it had to install anything.
# ---------------------------------------------------------------------------
_pf_check_docker() {
  [[ "$_PF_SUBSTRATE" != "kind" ]] && return 0   # k3s path doesn't need docker
  _pf_log "checking docker..."
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    _pf_log "  OK: docker present and responding"
    return 0
  fi

  if command -v docker >/dev/null 2>&1; then
    local err
    err="$(docker info 2>&1 >/dev/null || true)"

    if echo "$err" | grep -qi "permission denied"; then
      # This user just isn't in the docker group (yet, or the group was
      # granted in a previous run but this session predates it). Fixable
      # without any manual log-out/login: (re-)add to the group and restart
      # this script through `sg docker` so the new membership is active in
      # the very next process, not just after a fresh login.
      _pf_log "  'docker info' failed with permission denied — adding " \
              "\$USER to the docker group and restarting through it " \
              "(no manual log-out/login needed)"
      _pf_sudo usermod -aG docker "$USER" || \
        _pf_fail "tried to fix docker permissions with 'usermod -aG docker " \
                 "$USER' but it failed — this needs root and neither sudo " \
                 "nor running-as-root was available"
      _PF_DOCKER_FRESH=true   # reuses the sg-docker restart path below
      _PF_NEEDS_RESTART=true
      return 0
    fi

    _pf_warn "docker binary present but 'docker info' failed (daemon appears " \
             "to be down) — trying to start it..."
    _pf_sudo systemctl start docker 2>/dev/null || true
    sleep 2
    if docker info >/dev/null 2>&1; then
      _pf_log "  OK: docker daemon started"
      return 0
    fi

    _pf_warn "daemon still not responding after a start attempt — trying a " \
             "reinstall (get.docker.com is idempotent/safe to re-run) before " \
             "giving up..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh && \
      sh /tmp/get-docker.sh && \
      _pf_sudo systemctl enable --now docker 2>/dev/null
    sleep 2
    if docker info >/dev/null 2>&1; then
      _pf_log "  OK: docker working after reinstall"
      return 0
    fi

    _pf_fail "docker is installed but its daemon won't come up even after a " \
             "start attempt and a reinstall attempt — this looks like a real " \
             "host problem (out of disk, kernel/cgroup mismatch, conflicting " \
             "runtime, etc.) rather than something safe to keep guessing at " \
             "automatically. Check 'sudo journalctl -u docker' for the actual " \
             "daemon error and re-run."
  fi

  _pf_log "  docker not found — installing via get.docker.com..."
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh || \
    _pf_fail "could not download the docker install script from get.docker.com"
  sh /tmp/get-docker.sh || _pf_fail "docker install script failed — see output above"
  _pf_sudo usermod -aG docker "$USER" || \
    _pf_fail "docker installed but 'usermod -aG docker $USER' failed"
  _pf_sudo systemctl enable --now docker 2>/dev/null || true
  command -v docker >/dev/null 2>&1 || \
    _pf_fail "docker install script ran but 'docker' still isn't on PATH"
  _PF_DOCKER_FRESH=true
  _PF_NEEDS_RESTART=true
  _pf_log "  docker installed — will restart to pick up the new docker group membership"
}

_pf_check_kind() {
  [[ "$_PF_SUBSTRATE" != "kind" ]] && return 0   # k3s path doesn't need kind
  _pf_log "checking kind..."
  if command -v kind >/dev/null 2>&1; then
    _pf_log "  OK: kind present ($(kind version 2>/dev/null | head -1))"
    return 0
  fi
  _pf_log "  kind not found — installing pinned v0.23.0..."
  local suffix; suffix=$(_pf_arch_suffix)
  curl -fsSLo /tmp/kind "https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-${suffix}" || \
    _pf_fail "could not download kind from kind.sigs.k8s.io"
  chmod +x /tmp/kind || _pf_fail "downloaded kind binary but chmod +x failed"
  _pf_sudo install -m 0755 /tmp/kind /usr/local/bin/kind || \
    _pf_fail "downloaded kind binary but installing it to /usr/local/bin failed"
  command -v kind >/dev/null 2>&1 || \
    _pf_fail "kind installed to /usr/local/bin but still isn't on PATH — check " \
             "that /usr/local/bin is in \$PATH"
  _PF_NEEDS_RESTART=true
  _pf_log "  kind installed"
}

# All 5 nodes (1 control-plane + 4 workers, brief Section 11's "5-node KIND
# cluster") report Ready — used both after creation and to decide whether a
# pre-existing cluster is actually usable or silently broken.
#
# CLUSTER_NAME (env, default "zt-lab") — Infra/KIND/recover.sh already
# established this convention; reused here (and by
# _pf_create_kind_cluster_with_retry / _pf_ensure_kind_cluster below) so
# parallel workers on one VM can each stand up their own independently-named
# KIND cluster instead of every process fighting over one hardcoded "zt-lab".
_pf_kind_cluster_ready() {
  local name="${CLUSTER_NAME:-zt-lab}"
  local kubeconfig_flag=(--context "kind-${name}")
  local ready_count
  ready_count=$(kubectl "${kubeconfig_flag[@]}" get nodes --no-headers 2>/dev/null \
    | awk '$2=="Ready"' | wc -l)
  [[ "${ready_count:-0}" -ge 5 ]]
}

# Wraps `kind create cluster` with one self-healing retry: if creation fails
# (e.g. a stale docker network/container left over from a previous aborted
# run), delete whatever partial state exists and retry once before giving
# up — rather than failing and expecting a human to run `kind delete
# cluster` by hand before re-running.
_pf_create_kind_cluster_with_retry() {
  local cfg="$1"
  local name="${CLUSTER_NAME:-zt-lab}"
  # CORRECTED (real cluster-boot failure, traced to kind-cluster.yaml's
  # extraMounts.hostPath): kind resolves a relative extraMounts hostPath
  # against the CURRENT WORKING DIRECTORY at the moment `kind create
  # cluster` runs — NOT relative to the config file's own location. This
  # function previously just inherited whatever CWD the caller happened to
  # leave it in (worked only because Infra/KIND/setup.sh happens to cd to
  # the repo root before sourcing this). Pin it explicitly instead of
  # trusting that — a future caller invoking this from a different CWD
  # (e.g. `cd Infra/KIND && kind create cluster --config kind-cluster.yaml`,
  # a very natural thing to try by hand) would otherwise silently resolve
  # relative hostPaths in kind-cluster.yaml against the wrong directory,
  # and docker creates an empty directory for a nonexistent bind-mount
  # source rather than erroring — so this fails silently, not loudly.
  local repo_root
  repo_root="$(cd "${_PF_INFRA_DIR}/.." && pwd)"
  (
    cd "$repo_root" || _pf_fail "could not cd to repo root (${repo_root}) before " \
                                 "kind create cluster — extraMounts hostPaths in " \
                                 "kind-cluster.yaml are resolved relative to CWD, " \
                                 "so this has to succeed first."
    # --name overrides whatever `name:` kind-cluster.yaml itself has, so the
    # yaml doesn't need per-worker templating — one flag is enough.
    kind create cluster --name "$name" --config "$cfg" --wait 3m
  ) && return 0

  _pf_warn "kind create cluster failed on the first attempt — cleaning up any " \
           "partial state and retrying once (no manual 'kind delete cluster' " \
           "needed)"
  kind delete cluster --name "$name" 2>/dev/null || true
  docker rm -f "${name}-control-plane" "${name}-worker" "${name}-worker2" \
    "${name}-worker3" "${name}-worker4" >/dev/null 2>&1 || true
  (
    cd "$repo_root" || _pf_fail "could not cd to repo root (${repo_root}) for retry"
    kind create cluster --name "$name" --config "$cfg" --wait 3m
  ) || _pf_fail "kind create cluster failed twice in a row (see output above) — " \
                 "this usually means docker itself is unhealthy or out of " \
                 "resources, not something a retry can paper over."
}

_pf_ensure_kind_cluster() {
  [[ "$_PF_SUBSTRATE" != "kind" ]] && return 0
  # Runs after kind is confirmed present (either already there, or about to
  # be after a restart — skip on this pass if kind itself was just installed,
  # since we're restarting anyway and this check will run again post-restart
  # with a real `kind` binary on PATH).
  command -v kind >/dev/null 2>&1 || return 0

  local name="${CLUSTER_NAME:-zt-lab}"

  # Locate kind-cluster.yaml by search rather than a hardcoded folder name —
  # previously hardcoded to Infra/files(1)/, which would silently break (and
  # require a manual code edit) the moment that folder is renamed. `find`
  # makes this survive a rename with zero code changes, which matters here
  # specifically because "no manual intervention at any stage" has to include
  # "no manual intervention after routine repo housekeeping" too.
  local cfg
  cfg="$(find "$_PF_INFRA_DIR" -maxdepth 2 -name "kind-cluster.yaml" -print -quit 2>/dev/null)"
  [[ -n "$cfg" && -f "$cfg" ]] || \
    _pf_fail "could not find kind-cluster.yaml anywhere under ${_PF_INFRA_DIR} " \
             "(searched 2 levels deep) — it may have been moved or deleted."

  _pf_log "checking for the '${name}' KIND cluster..."
  if kind get clusters 2>/dev/null | grep -qx "$name"; then
    if _pf_kind_cluster_ready; then
      _pf_log "  OK: ${name} cluster already exists and all nodes are Ready"
      return 0
    fi
    _pf_warn "${name} cluster exists but isn't fully Ready — deleting and " \
             "recreating rather than leaving a broken cluster for someone to " \
             "diagnose by hand"
    kind delete cluster --name "$name" 2>/dev/null || true
  fi

  _pf_log "  creating ${name} cluster (kind create cluster --name ${name} --config ${cfg})..."
  _pf_create_kind_cluster_with_retry "$cfg"
  _pf_kind_cluster_ready || \
    _pf_fail "${name} cluster was created but nodes never reached Ready — " \
             "check 'kubectl get nodes' / 'docker ps' for what's stuck."
  _pf_log "  ${name} cluster created and all nodes Ready"
}

_pf_check_kubectl() {
  _pf_log "checking kubectl..."
  if command -v kubectl >/dev/null 2>&1; then
    _pf_log "  OK: kubectl present ($(kubectl version --client --short 2>/dev/null || echo present))"
    return 0
  fi
  _pf_log "  kubectl not found — installing latest stable..."
  local suffix version
  suffix=$(_pf_arch_suffix)
  version=$(curl -fsSL https://dl.k8s.io/release/stable.txt) || \
    _pf_fail "could not resolve the latest stable kubectl version from dl.k8s.io"
  curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/${version}/bin/linux/${suffix}/kubectl" || \
    _pf_fail "could not download kubectl ${version} from dl.k8s.io"
  chmod +x /tmp/kubectl || _pf_fail "downloaded kubectl binary but chmod +x failed"
  _pf_sudo install -m 0755 /tmp/kubectl /usr/local/bin/kubectl || \
    _pf_fail "downloaded kubectl binary but installing it to /usr/local/bin failed"
  command -v kubectl >/dev/null 2>&1 || \
    _pf_fail "kubectl installed to /usr/local/bin but still isn't on PATH — check " \
             "that /usr/local/bin is in \$PATH"
  _PF_NEEDS_RESTART=true
  _pf_log "  kubectl ${version} installed"
}

_pf_check_helm() {
  _pf_log "checking helm..."
  if command -v helm >/dev/null 2>&1; then
    _pf_log "  OK: helm present ($(helm version --short 2>/dev/null))"
    return 0
  fi
  _pf_log "  helm not found — installing via get-helm-3..."
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 -o /tmp/get-helm-3 || \
    _pf_fail "could not download the get-helm-3 install script"
  chmod +x /tmp/get-helm-3 || _pf_fail "downloaded get-helm-3 but chmod +x failed"
  /tmp/get-helm-3 || _pf_fail "get-helm-3 install script failed — see output above"
  command -v helm >/dev/null 2>&1 || \
    _pf_fail "get-helm-3 ran but 'helm' still isn't on PATH"
  _PF_NEEDS_RESTART=true
  _pf_log "  helm installed"
}

_pf_check_python() {
  _pf_log "checking python3..."
  if command -v python3 >/dev/null 2>&1; then
    _pf_log "  OK: python3 present ($(python3 --version 2>&1))"
  else
    _pf_log "  python3 not found — installing (apt-based systems only; other " \
            "distros: install manually and re-run)..."
    if command -v apt-get >/dev/null 2>&1; then
      _pf_sudo apt-get update -y && _pf_sudo apt-get install -y python3 python3-pip || \
        _pf_fail "apt-get install python3 python3-pip failed — see output above"
    else
      _pf_fail "python3 is missing and this host isn't apt-based — install " \
               "python3 + pip manually, then re-run."
    fi
    command -v python3 >/dev/null 2>&1 || \
      _pf_fail "apt-get install reported success but python3 still isn't on PATH"
    _PF_NEEDS_RESTART=true
    _pf_log "  python3 installed"
  fi

  _pf_log "checking scipy + numpy (Driver/deliverable_a.py's only non-stdlib deps " \
          "— see requirements.txt)..."
  if python3 -c "import scipy, numpy" >/dev/null 2>&1; then
    _pf_log "  OK: scipy + numpy importable"
    return 0
  fi
  _pf_log "  missing — installing..."
  local req_file="${_PF_INFRA_DIR}/../requirements.txt"
  local pip_target=(-r "$req_file")
  [[ -f "$req_file" ]] || pip_target=(scipy numpy)   # fallback if requirements.txt is ever removed
  if ! python3 -m pip install --quiet "${pip_target[@]}" 2>/tmp/pf_pip_err.log; then
    # PEP 668 "externally-managed-environment" systems (modern Debian/Ubuntu)
    # refuse a bare pip install; fall back to the explicit override.
    if grep -qi "externally-managed-environment" /tmp/pf_pip_err.log 2>/dev/null; then
      _pf_log "  bare pip install blocked (externally-managed-environment) — " \
              "retrying with --break-system-packages"
      python3 -m pip install --quiet --break-system-packages "${pip_target[@]}" || \
        _pf_fail "pip install failed even with --break-system-packages " \
                 "— install manually (consider a venv) and re-run."
    else
      _pf_fail "pip install scipy numpy failed: $(cat /tmp/pf_pip_err.log)"
    fi
  fi
  _PF_NEEDS_RESTART=true
  _pf_log "  scipy + numpy installed"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
_pf_log "=== preflight: substrate=${_PF_SUBSTRATE} restart_count=${ZT_PREFLIGHT_RESTARTS:-0} ==="

_pf_check_internet
_pf_check_resources     # warn-only, never sets _PF_NEEDS_RESTART

# ---------------------------------------------------------------------------
# FIX (multi-worker race): run_canonical.sh/run_shapley.sh launch 2-4
# `worker()` processes in parallel on ONE VM, and each one sources this file
# via `Infra/KIND/setup.sh all` before it has any KIND cluster of its own.
# On a freshly provisioned VM every worker hits "docker/kind/kubectl/helm/
# python3 not found" at the same instant and would previously run
# concurrent `apt-get install`, concurrent `curl get.docker.com | sh`, and
# concurrent installs to the same /usr/local/bin/{kind,kubectl,helm} paths
# with zero coordination — a near-guaranteed dpkg-lock/partial-binary race
# on exactly the first, unattended boot of a multi-day run.
#
# Fixed with a flock-guarded critical section around ONLY the shared
# host-level installs. What's NOT in this section: _pf_ensure_kind_cluster
# (each worker creates its own uniquely-named KIND cluster — safe/desired
# to run concurrently) and everything setup.sh does afterward (Cilium/
# Falco/Prometheus/Istio/Gatekeeper/Vault/SPIRE — all installed via `helm`
# against each worker's OWN $KUBECONFIG-selected cluster, no shared state).
# Only the "is this binary on PATH system-wide yet" checks need to be
# serialized; per-cluster work stays fully parallel.
#
# Lock file lives in /tmp by default (always writable, survives for the
# life of the VM's uptime, which is all we need — it does not need to
# survive a reboot). Override via ZT_PREFLIGHT_LOCK if /tmp is unusable
# for some reason. A 900s (15min) wait cap avoids a genuinely wedged
# worker (e.g. one that died mid-`apt-get` while holding the lock) hanging
# every other worker forever; on timeout this hard-fails with a message
# pointing at what to check, rather than looping silently.
# ---------------------------------------------------------------------------
_PF_LOCK_FILE="${ZT_PREFLIGHT_LOCK:-/tmp/.zt_preflight_install.lock}"
_pf_log "acquiring shared install lock (${_PF_LOCK_FILE}) — serializes the" \
        "docker/kind/kubectl/helm/python installs below across any other" \
        "worker on this same VM doing the same checks concurrently"
exec {_PF_LOCK_FD}>"${_PF_LOCK_FILE}" || \
  _pf_fail "could not open ${_PF_LOCK_FILE} for the shared install lock"
if ! flock -w 900 "${_PF_LOCK_FD}"; then
  _pf_fail "timed out after 900s waiting for the shared install lock" \
           "(${_PF_LOCK_FILE}) — another worker's dependency install may be" \
           "stuck. Check that worker's log under /opt/rszt/logs, and/or" \
           "'ps aux | grep -E \"apt-get|get-docker|get-helm\"' on this VM." \
           "If the holder is confirmed dead (not just slow), remove" \
           "${_PF_LOCK_FILE} and re-run."
fi
_pf_log "  lock acquired"

_pf_check_docker
_pf_check_kind
_pf_check_kubectl
_pf_check_helm
_pf_check_python

flock -u "${_PF_LOCK_FD}"
exec {_PF_LOCK_FD}>&-
_pf_log "shared install lock released"

if $_PF_NEEDS_RESTART; then
  if [[ "${ZT_PREFLIGHT_RESTARTS:-0}" -ge 1 ]]; then
    _pf_fail "still need to install something after already restarting once " \
             "— treating this as an installation failure rather than looping " \
             "forever. Check the output above for which install step failed " \
             "silently, fix it manually, and re-run ${_PF_CALLER}."
  fi
  _pf_log "one or more dependencies were just installed — restarting " \
          "${_PF_CALLER} once so they're picked up cleanly"
  export ZT_PREFLIGHT_RESTARTS=1
  # CORRECTED (real run failure): this used to `exec "$_PF_CALLER" ...`
  # directly, which requires the caller script's own +x bit to be set —
  # but the original invocation this whole run started from was
  # `bash Infra/KIND/setup.sh all`, which never needed that bit at all
  # (bash was handed the path explicitly). A fresh clone/scp'd copy without
  # +x set failed here with "Permission denied" right after installs
  # completed, discarding a restart that had otherwise gone perfectly.
  # Re-invoke through bash explicitly instead, matching the original
  # invocation, so this never depends on file permissions.
  local _pf_interpreter="${BASH:-bash}"
  if $_PF_DOCKER_FRESH && command -v sg >/dev/null 2>&1; then
    # `exec "$0"` alone would NOT pick up the fresh docker group membership
    # in this same login session — re-exec through `sg docker` so it does.
    _pf_cmd="$(printf '%q ' "$_pf_interpreter" "$_PF_CALLER" "${_PF_CALLER_ARGS[@]}")"
    exec sg docker -c "$_pf_cmd"
  else
    exec "$_pf_interpreter" "$_PF_CALLER" "${_PF_CALLER_ARGS[@]}"
  fi
fi

# Only reached once kind is confirmed present without needing a fresh
# install this pass (see _pf_ensure_kind_cluster's own guard).
_pf_ensure_kind_cluster

_pf_log "=== preflight passed — all dependencies present ==="
