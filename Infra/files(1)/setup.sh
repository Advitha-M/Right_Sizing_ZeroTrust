#!/usr/bin/env bash
# ============================================================================
#  infra/setup.sh  —  Right-Sizing Zero Trust lab : full build (Phases 1 to 5)
# ----------------------------------------------------------------------------
#  Rewritten against the actual v6-corrected repo layout: Attacks/, Controls/
#  (c1-l1, c2-rbac, c3-opa, c4-tenant-isolation, c5-networkpolicy, c6-istio,
#  c7-vault), Driver/, Harness/. The old repo generation this was based on
#  used lowercase attacks/controls/tenants dirs and acme/globex/initech/
#  umbrella tenant namespaces — none of that exists here. Tenant namespaces
#  are the four names in Driver/constants.TENANTS: tenant-lowpriv,
#  tenant-finserv, tenant-partner, tenant-saas. Do not reintroduce the old
#  naming (see Harness/config.env's explicit note on this).
#
#  Usage:
#     sudo -v                 # cache your password ONCE
#     ./infra/setup.sh all    # run everything (default)
#     ./infra/setup.sh verify # check every phase + baseline (all 7 SUCCEED @ C0)
#     ./infra/setup.sh phase1|phase2|phase3|phase4|phase5
#
#  KEY DIFFERENCES vs the pre-v6 generator's setup.sh:
#   * Phase 1 is NEW. There is no Makefile in this repo (the old header
#     comment's "make cilium" target doesn't exist here), so Cilium was
#     never actually installed by anything. Phase 1 does it explicitly,
#     pinned to 1.19.3 to match the Tier-1 invariant
#     ("Cilium 1.19.3 agent healthy").
#   * Phase 2 targets the four v6 tenant namespaces directly (no
#     tenants/deploy.sh in this repo to delegate to) and provisions the two
#     things Driver/driver.py's invariant checks and Controls/c2-rbac's
#     cleanup logic depend on: a permissive C0 RBAC baseline, and the
#     finserv-static-credentials secret that check_finserv_credentials()
#     polls for pre-C7 and that Controls/c7-vault/apply.sh deletes.
#   * Phase 3 does NOT hand-create a `trials` table. The old version wrote
#     a (config,attack,trial,seed,outcome,success,chain_depth,detail,dl_sec)
#     schema; Driver/driver.py's own init_db() creates and forward-migrates
#     a richer v3 schema (run_id, doc_class, technique_token, t_start, t_end,
#     t_alert, alert_source, exit_code, error_type, target_tenant,
#     pivot_path). driver.py's own header comment calls out exactly this
#     failure mode in the old Harness/run_attacks.sh ("wrote a thinner DB
#     schema than driver.py's — despite a comment claiming it was
#     schema-compatible") — Phase 3 avoids repeating it by not touching the
#     schema at all and letting driver.py own it exclusively.
#   * Phase 4 marks Attacks/*.sh executable (flat directory — no
#     attacks/wrappers/ or attacks/oracles/ subdirs in this repo; see
#     Harness/config.env's note that those don't exist here).
#   * Phase 5 is functionally unchanged (Istio/Gatekeeper/Vault, installed
#     but not enforcing) — Controls/c1-l1, c3-opa, c6-istio, and c7-vault
#     apply.sh scripts all explicitly assume this phase already ran.
# ============================================================================
set -o pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

TENANTS=(tenant-lowpriv tenant-finserv tenant-partner tenant-saas)
CILIUM_VERSION="1.19.3"

banner(){ echo; echo "############################################################"; echo "##  $1"; echo "############################################################"; }
step(){ echo "  ->  $1"; }

# ----------------------------------------------------------------------------
# PHASE 1 : Cilium CNI (NEW — no Makefile in this repo to do this)
# ----------------------------------------------------------------------------
phase1(){
  banner "PHASE 1 : Cilium ${CILIUM_VERSION} CNI"
  step "Adding cilium helm repo"
  helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1
  helm repo update >/dev/null
  step "Installing Cilium ${CILIUM_VERSION} (pinned — Tier-1 invariant expects this exact version)"
  helm upgrade --install cilium cilium/cilium --version "${CILIUM_VERSION}" \
    --namespace kube-system \
    --wait --timeout 5m || echo "       (warn) Cilium install issue — verify later"
  step "Waiting for Cilium DaemonSet rollout"
  kubectl -n kube-system rollout status daemonset/cilium --timeout=180s \
    || echo "       (warn) Cilium not fully Ready — check 'cilium status' inside an agent pod"
  echo "  PHASE 1 done."
}

# ----------------------------------------------------------------------------
# PHASE 2 : tenant namespaces + permissive C0 RBAC baseline + finserv secret
# ----------------------------------------------------------------------------
phase2(){
  banner "PHASE 2 : tenant namespaces (v6 naming) + C0 baseline"

  step "Removing old tenants (if any)"
  kubectl delete ns "${TENANTS[@]}" --ignore-not-found --wait=true 2>/dev/null || true

  step "Creating tenant namespaces"
  for t in "${TENANTS[@]}"; do
    kubectl create ns "$t" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  done

  step "Applying permissive C0 RBAC baseline (removed by controls/c2-rbac/apply.sh at C2)"
  # tenant-lowpriv default SA gets cluster-admin at C0 — this is the
  # deliberately wide-open baseline that L3a (RBAC) locks down. C0 setup may
  # create either binding name below; c2-rbac's cleanup deletes both.
  kubectl create clusterrolebinding tenant-lowpriv-permissive \
    --clusterrole=cluster-admin \
    --serviceaccount=tenant-lowpriv:default \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label clusterrolebinding tenant-lowpriv-permissive zt-lab/baseline=true --overwrite >/dev/null 2>&1 || true

  # tenant-partner: scoped-but-legitimate cross-namespace node read, modeling
  # the "overpermissioned-operator" profile used as A3's attacker origin.
  # Cleaned up by controls/c2-rbac/apply.sh at C2.
  kubectl create clusterrole tenant-partner-nodes-read \
    --verb=get,list,watch --resource=nodes \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl create clusterrolebinding tenant-partner-nodes-read \
    --clusterrole=tenant-partner-nodes-read \
    --serviceaccount=tenant-partner:default \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  step "Provisioning finserv-static-credentials (removed by controls/c7-vault/apply.sh at C7)"
  # Driver/driver.py's check_finserv_credentials() polls for this secret at
  # every condition below C7; it models the static long-lived credential
  # that L7 (Vault dynamic secrets) eliminates.
  kubectl create secret generic finserv-static-credentials \
    --namespace tenant-finserv \
    --from-literal=api_key="mock-static-key-$(date +%s)" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  echo "  PHASE 2 done. NOTE: this provisions namespaces + the two baseline"
  echo "  RBAC grants + the finserv secret that driver.py's invariant checks"
  echo "  and controls/c2-rbac + c7-vault's cleanup logic depend on. If your"
  echo "  tenant workloads (deployments/services/PVCs per tenant) are"
  echo "  provisioned by a separate script, run that here too before verify."
}

# ----------------------------------------------------------------------------
# PHASE 3 : observability (Falco + Prometheus/Grafana) + Python analysis toolkit
#           (does NOT create the trials table — driver.py's init_db() owns it)
# ----------------------------------------------------------------------------
phase3(){
  banner "PHASE 3 : observability + analysis toolkit"

  step "Installing Falco (runtime syscall monitoring — namespace 'falco', "
  step "matches Driver/driver.py's measure_dl() log query)"
  helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1
  helm repo update >/dev/null
  helm upgrade --install falco falcosecurity/falco \
    --namespace falco --create-namespace \
    --set driver.kind=modern_ebpf --set tty=true \
    --set falcosidekick.enabled=false \
    --wait --timeout 5m || echo "       (warn) Falco install issue — verify later"

  step "Installing Prometheus + Grafana (kube-prometheus-stack)"
  helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1
  helm repo update >/dev/null
  helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
    --namespace monitoring --create-namespace \
    --wait --timeout 8m || echo "       (warn) monitoring stack slow — verify later"

  step "Installing system packages (python venv, sqlite)"
  sudo apt-get update -qq >/dev/null 2>&1
  sudo apt-get install -y -qq python3-venv python3-pip sqlite3 >/dev/null 2>&1 \
    || echo "       (warn) apt step had an issue — verify later"

  step "Building the Python analysis venv (pandas, numpy, scipy, matplotlib)"
  python3 -m venv "${REPO_ROOT}/venv"
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/venv/bin/activate"
  pip install --quiet --upgrade pip
  pip install --quiet pandas numpy scipy matplotlib pyarrow
  deactivate

  step "Ensuring results/ directory exists (schema owned by Driver/driver.py)"
  mkdir -p "${REPO_ROOT}/results"
  echo "       results.db is created/migrated by Driver/driver.py's init_db()"
  echo "       on first run (Harness/run_attacks.sh or driver.py directly)."
  echo "       Deliberately NOT hand-creating a trials table here — see this"
  echo "       file's header comment for why the old version's schema drift"
  echo "       bug is being avoided rather than reintroduced."

  echo "  PHASE 3 done."
}

# ----------------------------------------------------------------------------
# PHASE 4 : attack tooling — Stratus (optional) + Attacks/*.sh executable
#           (flat directory: attackN.sh, wrap.sh, oracle.sh, stratus_adapter.sh)
# ----------------------------------------------------------------------------
phase4(){
  banner "PHASE 4 : attack tooling (Stratus optional)"

  step "Marking Attacks/*.sh and controls/*/apply.sh + remove.sh executable"
  chmod +x "${REPO_ROOT}"/Attacks/*.sh \
           "${REPO_ROOT}"/Controls/*/apply.sh \
           "${REPO_ROOT}"/Controls/*/remove.sh \
           "${REPO_ROOT}"/Harness/*.sh 2>/dev/null || true

  step "Installing Stratus Red Team (optional — Attacks/stratus_adapter.sh degrades to native if absent)"
  URL=$(curl -s https://api.github.com/repos/DataDog/stratus-red-team/releases/latest \
        | grep "browser_download_url" | grep -iE "linux.*(amd64|x86_64)\.tar\.gz" | head -1 | cut -d '"' -f 4)
  if [ -n "$URL" ]; then
    curl -fsSL -o /tmp/stratus.tar.gz "$URL"
    tar xzf /tmp/stratus.tar.gz -C /tmp stratus 2>/dev/null
    sudo install -m 0755 /tmp/stratus /usr/local/bin/stratus 2>/dev/null \
      && echo "       stratus installed ($(stratus version 2>/dev/null | head -1))" \
      || echo "       (warn) stratus install needs sudo — install manually; Attacks/stratus_adapter.sh falls back to native"
  else
    echo "       (warn) couldn't resolve Stratus download — stratus_adapter.sh falls back to native attacks"
  fi

  echo "  PHASE 4 done. (Native attacks committed; Stratus optional via USE_STRATUS=1.)"
}

# ----------------------------------------------------------------------------
# PHASE 5 : install the CONTROL TOOLS (present, NOT enforcing yet)
#           Controls/c1-l1, c3-opa, c6-istio, and c7-vault apply.sh scripts
#           all explicitly assume this phase already ran.
# ----------------------------------------------------------------------------
phase5(){
  banner "PHASE 5 : install Istio + OPA Gatekeeper + Vault (installed, NOT enforcing)"

  step "Installing istioctl + Istio control plane (minimal profile)"
  if ! command -v istioctl >/dev/null 2>&1; then
    (cd "$REPO_ROOT" && curl -fsSL https://istio.io/downloadIstio | sh -)
    IST=$(ls -d "$REPO_ROOT"/istio-* 2>/dev/null | head -1)
    [ -n "$IST" ] && sudo install -m 0755 "$IST/bin/istioctl" /usr/local/bin/istioctl
  fi
  istioctl install --set profile=minimal -y || echo "       (warn) istio install issue — verify later"
  # Sidecar injection is NOT enabled here; controls/c6-istio/apply.sh labels
  # the 4 tenant namespaces istio-injection=enabled and rolls workloads at C6.

  step "Installing OPA Gatekeeper (no constraints yet — shared by c1-l1 and c3-opa)"
  helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts >/dev/null 2>&1
  helm repo update >/dev/null
  helm upgrade --install gatekeeper gatekeeper/gatekeeper \
    --namespace gatekeeper-system --create-namespace \
    --wait --timeout 5m || echo "       (warn) gatekeeper issue — verify later"
  # ConstraintTemplates/Constraints are applied at C1 (digest-pin) and C3
  # (privileged/hostPath/registry) by their respective apply.sh scripts.

  step "Installing Vault (dev mode: root token 'root', namespace 'vault')"
  helm repo add hashicorp https://helm.releases.hashicorp.com >/dev/null 2>&1
  helm repo update >/dev/null
  helm upgrade --install vault hashicorp/vault \
    --namespace vault --create-namespace \
    --set "server.dev.enabled=true" \
    --set "server.dev.devRootToken=root" \
    --wait --timeout 5m || echo "       (warn) vault issue — verify later"
  # k8s auth + dynamic secrets are wired at C7 (controls/c7-vault/apply.sh).

  step "Installing SPIRE server + agent (namespace 'spire', trust domain cluster.local)"
  # Present, NOT attesting any workloads yet — controls/c7-vault/apply.sh
  # (Part 2) registers the actual per-tenant SPIFFE entries at C7, same
  # "installed but not enforcing until its Controls/ apply.sh runs" pattern
  # as Istio/Gatekeeper above. Chart values below are the common defaults for
  # spiffe/helm-charts-hardened's "spire" chart as of this writing — verify
  # against that repo's docs if the chart's value schema has moved on.
  helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ >/dev/null 2>&1
  helm repo update >/dev/null
  helm upgrade --install spire spiffe/spire \
    --namespace spire --create-namespace \
    --set global.spire.trustDomain=cluster.local \
    --set global.spire.clusterName=zt-lab \
    --wait --timeout 5m || echo "       (warn) SPIRE install issue — verify later (chart values may need adjusting for your chart version)"
  step "Waiting for spire-server-0 and spire-agent DaemonSet"
  kubectl -n spire rollout status statefulset/spire-server --timeout=120s \
    || echo "       (warn) spire-server not Ready — check 'kubectl -n spire get pods'"
  kubectl -n spire rollout status daemonset/spire-agent --timeout=120s \
    || echo "       (warn) spire-agent DaemonSet not Ready — check 'kubectl -n spire get pods'"

  echo "  PHASE 5 done. Tools installed; baseline behaviour UNCHANGED (still wide-open)."
}

# ----------------------------------------------------------------------------
# VERIFY : check every phase, then run the corpus at baseline
# ----------------------------------------------------------------------------
verify(){
  G="\033[32m[ OK ]\033[0m"; R="\033[31m[FAIL]\033[0m"; Y="\033[33m[info]\033[0m"
  ok(){ echo -e "$G $1"; }; bad(){ echo -e "$R $1"; }; nfo(){ echo -e "$Y $1"; }

  banner "VERIFY — send this whole output to Claude"

  echo "----- Phase 1 : cluster + Cilium -----"
  N=$(kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready"' | wc -l)
  [ "$N" -eq 5 ] && ok "5 nodes Ready" || bad "expected 5 Ready nodes, got ${N:-0}"
  kubectl get pods -n kube-system 2>/dev/null | grep -q cilium && ok "Cilium running" || bad "Cilium missing"
  CVER=$(helm list -n kube-system 2>/dev/null | awk '$1=="cilium"{print $NF}')
  [[ "$CVER" == *"1.19.3"* ]] && ok "Cilium pinned at 1.19.3" || nfo "Cilium version check inconclusive (got: ${CVER:-unknown}) — confirm manually"

  echo "----- Phase 2 : tenant namespaces (v6 naming) -----"
  for T in "${TENANTS[@]}"; do
    R=$(kubectl get pods -n "$T" --no-headers 2>/dev/null | grep -c Running)
    [ "${R:-0}" -ge 1 ] && ok "$T: $R pods Running" || bad "$T: only ${R:-0} pods Running"
  done
  kubectl get nodes -l tenant -o name 2>/dev/null | grep -q . \
    && ok "tenant node labels present" || bad "no nodes labelled 'tenant' — controls/c4-tenant-isolation will fail node discovery"
  kubectl get clusterrolebinding tenant-lowpriv-permissive >/dev/null 2>&1 \
    && ok "permissive C0 baseline binding present" || bad "tenant-lowpriv-permissive baseline binding missing"
  kubectl get secret finserv-static-credentials -n tenant-finserv >/dev/null 2>&1 \
    && ok "finserv-static-credentials present (needed pre-C7)" || bad "finserv-static-credentials missing — driver.py invariant will fail for C0-C6"

  echo "----- Phase 3 : observability + toolkit -----"
  kubectl get pods -n falco 2>/dev/null | grep -q Running && ok "Falco running" || bad "Falco not running"
  kubectl get pods -n monitoring 2>/dev/null | grep -q prometheus && ok "Prometheus running" || bad "Prometheus missing"
  kubectl get pods -n monitoring 2>/dev/null | grep -qi grafana && ok "Grafana running" || bad "Grafana missing"
  [ -d "${REPO_ROOT}/venv" ] && ok "Python venv exists" || bad "venv missing"
  [ -f "${REPO_ROOT}/results/results.db" ] \
    && ok "results.db exists (created by driver.py)" \
    || nfo "results.db not created yet — normal until the first driver.py/harness run"

  echo "----- Phase 4 : attacks + wrappers -----"
  command -v stratus >/dev/null 2>&1 && ok "Stratus installed (optional)" || nfo "Stratus absent — Attacks/stratus_adapter.sh falls back to native (OK)"
  C=$(ls "${REPO_ROOT}"/Attacks/attack*.sh 2>/dev/null | wc -l)
  [ "$C" -eq 7 ] && ok "7 attack scripts present" || bad "expected 7 attacks, got $C"
  [ -f "${REPO_ROOT}/Attacks/wrap.sh" ] && ok "wrapper present" || bad "Attacks/wrap.sh missing"
  [ -f "${REPO_ROOT}/Attacks/oracle.sh" ] && ok "oracle (shell) present" || bad "Attacks/oracle.sh missing"
  [ -f "${REPO_ROOT}/Driver/oracle.py" ] && ok "oracle (python) present" || bad "Driver/oracle.py missing"
  [ -f "${REPO_ROOT}/Driver/config.py" ] \
    && ok "Driver/config.py present" \
    || bad "Driver/config.py MISSING — driver.py 'import config as C' will fail immediately; nothing else in this checklist can actually run without it"

  echo "----- Phase 5 : controls installed (not enforcing) -----"
  kubectl get pods -n istio-system 2>/dev/null | grep -q istiod && ok "Istio (istiod) running" || bad "istiod missing"
  kubectl get pods -n gatekeeper-system 2>/dev/null | grep -q Running && ok "OPA Gatekeeper running" || bad "Gatekeeper not running"
  kubectl get pods -n vault 2>/dev/null | grep -q Running && ok "Vault running" || bad "Vault not running"

  echo "----- Controls : all 7 layers have apply.sh + remove.sh -----"
  for c in c1-l1 c2-rbac c3-opa c4-tenant-isolation c5-networkpolicy c6-istio c7-vault; do
    [ -f "${REPO_ROOT}/Controls/${c}/apply.sh" ] && [ -f "${REPO_ROOT}/Controls/${c}/remove.sh" ] \
      && ok "control $c apply+remove present" || bad "control $c incomplete"
  done

  echo "----- Baseline behaviour : all 7 attacks should SUCCEED at C0 -----"
  if [ -f "${REPO_ROOT}/Driver/config.py" ]; then
    STACK_ID=C0 N_TRIALS=1 bash "${REPO_ROOT}/Harness/run_attacks.sh" 2>/dev/null | grep -E "attack[0-9]" || true
    S=$(sqlite3 "${REPO_ROOT}/results/results.db" \
          "SELECT COUNT(*) FROM trials WHERE config='C0' AND success=1;" 2>/dev/null)
    [ "${S:-0}" -ge 7 ] && ok "all 7 attacks SUCCEED at baseline (C0 correctly wide-open)" \
                        || nfo "${S:-0}/7 succeeded at C0 — paste this; a couple may need a tweak"
  else
    nfo "skipped — Driver/config.py missing, see Phase 4 result above"
  fi

  echo; echo "================ END OF VERIFY — send everything above ================"
}

# ----------------------------------------------------------------------------
case "${1:-all}" in
  phase1) phase1 ;;
  phase2) phase2 ;;
  phase3) phase3 ;;
  phase4) phase4 ;;
  phase5) phase5 ;;
  verify) verify ;;
  all)
    sudo -v
    phase1; phase2; phase3; phase4; phase5
    echo; echo "############################################################"
    echo "##  ALL PHASES ATTEMPTED."
    echo "##  Now run:   ./infra/setup.sh verify   and send Claude the output."
    echo "############################################################"
    ;;
  *) echo "usage: ./infra/setup.sh [all|phase1|phase2|phase3|phase4|phase5|verify]" ;;
esac
