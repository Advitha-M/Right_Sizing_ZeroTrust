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
    _pf_warn "docker binary present but 'docker info' failed (daemon down or " \
             "permission denied) — trying to start the daemon..."
    _pf_sudo systemctl start docker 2>/dev/null || true
    sleep 2
    if docker info >/dev/null 2>&1; then
      _pf_log "  OK: docker daemon started"
      return 0
    fi
    _pf_fail "docker is installed but not usable (daemon won't start, or this " \
             "user isn't in the docker group and passwordless sudo isn't " \
             "available) — fix manually (e.g. 'sudo usermod -aG docker \$USER' " \
             "then log out/in) and re-run."
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

_pf_ensure_kind_cluster() {
  [[ "$_PF_SUBSTRATE" != "kind" ]] && return 0
  # Runs after kind is confirmed present (either already there, or about to
  # be after a restart — skip on this pass if kind itself was just installed,
  # since we're restarting anyway and this check will run again post-restart
  # with a real `kind` binary on PATH).
  command -v kind >/dev/null 2>&1 || return 0
  _pf_log "checking for the 'zt-lab' KIND cluster..."
  if kind get clusters 2>/dev/null | grep -qx "zt-lab"; then
    _pf_log "  OK: zt-lab cluster already exists"
    return 0
  fi
  _pf_log "  zt-lab cluster not found — creating it now " \
          "(kind create cluster --config Infra/files(1)/kind-cluster.yaml). " \
          "This previously had to be done manually; no script ever ran it."
  local cfg="${_PF_INFRA_DIR}/files(1)/kind-cluster.yaml"
  [[ -f "$cfg" ]] || _pf_fail "expected KIND config at ${cfg} but it's not there — " \
                              "if you've renamed Infra/files(1), update this path " \
                              "in Infra/preflight.sh's _pf_ensure_kind_cluster()."
  kind create cluster --config "$cfg" || \
    _pf_fail "kind create cluster failed — see output above"
  _pf_log "  zt-lab cluster created"
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

_pf_check_docker
_pf_check_kind
_pf_check_kubectl
_pf_check_helm
_pf_check_python

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
  if $_PF_DOCKER_FRESH && command -v sg >/dev/null 2>&1; then
    # `exec "$0"` alone would NOT pick up the fresh docker group membership
    # in this same login session — re-exec through `sg docker` so it does.
    _pf_cmd="$(printf '%q ' "$_PF_CALLER" "${_PF_CALLER_ARGS[@]}")"
    exec sg docker -c "$_pf_cmd"
  else
    exec "$_PF_CALLER" "${_PF_CALLER_ARGS[@]}"
  fi
fi

# Only reached once kind is confirmed present without needing a fresh
# install this pass (see _pf_ensure_kind_cluster's own guard).
_pf_ensure_kind_cluster

_pf_log "=== preflight passed — all dependencies present ==="
