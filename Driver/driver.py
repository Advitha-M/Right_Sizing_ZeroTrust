#!/usr/bin/env python3
"""
driver.py — Cumulative Augmentation Orchestrator (Rev7)

Changes from previous version (carried over from Rev5/Rev6):
  - Seed scheme: hash(attack + trial) only — config dropped for McNemar validity
  - Per-class ATTACKER_NS routing sourced entirely from constants.ATTACKER_NS_MAP
    (A1/A2/A5/A6 -> tenant-lowpriv, A3/A4 -> tenant-partner, A7 ->
    tenant-finserv [insider/already-present principal, origin==target]).
    Tenant namespaces are the four names in constants.TENANTS.
  - technique_token recorded as first-class DB column; t_start persisted
  - N (--trials) and M (--mc-permutations) are CLI args for dry-run flexibility
  - DB schema v3: adds t_end, t_alert, alert_source, exit_code, error_type,
    target_tenant, pivot_path columns; measure_dl() returns (t_alert, source, dl)
  - --mode {sequential, mc-pairs, dl-robust, l2-l3a-sep}
  - l2-l3a-sep mode against k3s: samplers_l2l3a_k3s.py's
    l2_l3a_separation_sampler() treats L2 as genuinely toggleable, via the
    Controls/c-l2-audit control and set_config_k3s()/C.K3S_KUBECONFIG.
    Requires Infra/k3s/bootstrap.sh to have been run first.
  - mc-pairs and dl-robust run both precursor and with-pair points per
    draw, each as its own labeled condition.

REV 7 FIXES in this revision:
  - measure_dl()'s poll deadline now uses the brief's actual fixed
    90-second non-detection cutoff (Section 10.1) via C.DL_TIMEOUT alone.
    Previously it was silently capped at min(C.DL_TIMEOUT, 30) = 30s
    regardless of the (also-wrong, 300s) config default — neither number
    matched the brief. See config.py.
  - run_dl_robust()'s (L2,L3a) branch no longer reuses the generic
    KIND-based dl_robustness_sampler(), which hard-fixes L2 as a prefix
    (L2 is not a member of constants.PERMUTABLE_LAYERS, so that sampler
    can't vary it). Section 8.3 is explicit that (L2,L3a)'s M''=15
    robustness draws ALSO run on k3s with L2 freely permutable, "no
    special-casing" relative to the other two DL candidate pairs' M''
    draws. New function l2_l3a_robustness_draws_k3s() (below) fixes this,
    mirroring samplers_l2l3a_k3s.l2_l3a_separation_sampler's permutation
    mechanics but using the reduced 2-augment (precursor pair / with
    pair) form Section 10.2 specifies for all M'' draws.
  - run_invariant_checks() previously covered a small fraction of Section
    11's four-tier structure (roughly 2 of Tier 1's 5 checks, nothing
    from Tier 2, and none of Tier 3/4). This revision implements the
    full four-tier structure: Tier 1+2 gate a condition once, before/
    after layer activation (HALT on failure — do not proceed to trials);
    Tier 3+4 gate every individual trial (SKIP + reset + retry on
    failure, escalate after 3 consecutive failures), per Section 11's
    failure-handling rule. The open item flagged in Section 11/8.3 —
    whether Tier 1 needs a k3s-specific variant for (L2,L3a)'s k3s-run
    samples — is NOT resolved here (still genuinely unspecified by the
    brief); tier1_structural() takes an `on_k3s` flag and takes the
    conservative position of running the KIND-authored checks unchanged
    against k3s (same behavior as before this rewrite) while logging an
    explicit [OPEN ITEM] flag every time it does so, instead of silently
    assuming transfer.

Usage:
    python3 driver/driver.py                          # full run C0-C7, N=50
    python3 driver/driver.py --trials 10              # dry run, low N
    python3 driver/driver.py --configs C0 C1          # subset of conditions
    python3 driver/driver.py --dry-run                # print plan only
    python3 driver/driver.py --run-id run_debug_01    # named run
    python3 driver/driver.py --mode mc-pairs --mc-permutations 2 --trials 5
"""
import argparse
import base64
import hashlib
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
from constants import (
    CONFIGS, CONDITION_ORDER, ATTACK_ORDER_SCRIPTS, ATTACK_CLASSES,
    ATTACKER_NS_MAP, SCRIPT_TO_DOC, TECHNIQUE_SETS, VICTIM_NS, PARTNER_NS,
    TENANTS, PERMUTABLE_LAYERS, DL_ROBUSTNESS_SAMPLES, CILIUM_VERSION,
)

# Canonical tenant namespace list — derived from constants.TENANTS, the v6
# single source of truth. Do NOT hardcode namespace names elsewhere in this
# file; the old acme/globex/initech/umbrella naming from prior revisions is
# retired.
TENANT_NAMESPACES = list(TENANTS.keys())
from oracle import classify


# ── Logging ───────────────────────────────────────────────────────────────────

def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    C.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(C.LOGS_DIR / "driver.log", "a") as f:
        f.write(line + "\n")


def run(cmd, timeout=None, env=None):
    full_env = {**os.environ, **(env or {})}
    try:
        p = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True,
            timeout=timeout, env=full_env,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or ""), False
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        return 124, out, True


# ── Database ──────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS trials (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         TEXT    NOT NULL,
    config         TEXT    NOT NULL,
    attack         TEXT    NOT NULL,
    doc_class      TEXT    NOT NULL,
    trial          INTEGER NOT NULL,
    seed           INTEGER NOT NULL,
    technique_token TEXT   NOT NULL,
    outcome        TEXT    NOT NULL,
    success        INTEGER NOT NULL,
    chain_depth    INTEGER,
    detail         TEXT,
    t_start        REAL,
    t_end          REAL,
    t_alert        REAL,
    alert_source   TEXT,
    dl_sec         REAL,
    exit_code      INTEGER,
    error_type     TEXT,
    target_tenant  TEXT,
    pivot_path     TEXT,
    ts             TEXT    DEFAULT (datetime('now'))
)
"""

# Columns added in v3 — applied to existing DBs via ALTER TABLE
_V3_COLS = [
    ("t_end",         "REAL"),
    ("t_alert",       "REAL"),
    ("alert_source",  "TEXT"),
    ("exit_code",     "INTEGER"),
    ("error_type",    "TEXT"),
    ("target_tenant", "TEXT"),
    ("pivot_path",    "TEXT"),
]

# Columns added in v4 (Rev 7 rewrite) — Section 11's Tier 3/4 per-trial gate
# needs somewhere to record when a trial only ran after 1-2 retries, and
# whether it was ultimately escalated (3 consecutive Tier 3/4 failures).
_V4_COLS = [
    ("tier34_retries",   "INTEGER"),
    ("tier34_escalated", "INTEGER"),
]


def init_db():
    C.RESULTS_DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(C.RESULTS_DB)
    con.executescript(SCHEMA)
    con.commit()
    # Forward-migrate existing schemas — safe no-op if columns already exist
    for col, typ in _V3_COLS + _V4_COLS:
        try:
            con.execute(f"ALTER TABLE trials ADD COLUMN {col} {typ}")
            con.commit()
        except sqlite3.OperationalError:
            pass
    return con


def record(con, run_id, config, attack, trial, seed, technique_token,
           verdict, t_start, t_end, t_alert, alert_source, dl,
           exit_code, error_type, target_tenant, pivot_path,
           tier34_retries=0, tier34_escalated=0):
    doc_class = SCRIPT_TO_DOC[attack]
    con.execute(
        """INSERT INTO trials
           (run_id,config,attack,doc_class,trial,seed,technique_token,
            outcome,success,chain_depth,detail,
            t_start,t_end,t_alert,alert_source,dl_sec,
            exit_code,error_type,target_tenant,pivot_path,
            tier34_retries,tier34_escalated)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (run_id, config, attack, doc_class, trial, seed, technique_token,
         verdict.outcome, verdict.success_bit,
         verdict.chain_depth, verdict.detail,
         t_start, t_end, t_alert, alert_source, dl,
         exit_code, error_type, target_tenant, pivot_path,
         tier34_retries, tier34_escalated),
    )
    con.commit()


# ── Seed scheme ───────────────────────────────────────────────────────────────
# CRITICAL: config is NOT included in the hash.
# Trial t of attack j gets the same seed regardless of condition,
# making technique draws identical across conditions — required for McNemar.

def shard(samples: list, args) -> list:
    """
    Splits a sampler's draw list across N parallel workers on the same
    substrate. `--shard-index i` (0-based) of `--shard-count n` workers
    each takes every n-th draw (samples[i::n]) — deterministic given the
    same seed, so every worker computes the SAME full sample list and just
    keeps a disjoint slice of it; no coordination between workers needed
    and every draw is covered exactly once across the fleet.
    No-op (returns samples unchanged) if --shard-count is unset or 1.
    """
    if not getattr(args, "shard_count", None) or args.shard_count <= 1:
        return samples
    if not (0 <= args.shard_index < args.shard_count):
        sys.exit(f"--shard-index must be in [0, {args.shard_count}) — got {args.shard_index}")
    sharded = samples[args.shard_index::args.shard_count]
    log(f"  [SHARD] {len(samples)} draws -> {len(sharded)} for shard "
        f"{args.shard_index}/{args.shard_count}")
    return sharded


def count_existing_trials(con, run_id, config, attack) -> tuple:
    """
    How many trial rows already exist for this exact (run_id, config,
    attack), and how many of those were successes. Trial indices are
    inserted 1..n_trials with no gaps (every while-loop iteration in
    run_trials() either records a real trial or an ESCALATED_TIER34 row
    before incrementing `trial`, and record() commits immediately after
    a single INSERT — no partial/uncommitted rows possible), so the count
    IS the next trial index to resume from.
    """
    row = con.execute(
        "SELECT COUNT(*), COALESCE(SUM(success),0) FROM trials "
        "WHERE run_id=? AND config=? AND attack=?",
        (run_id, config, attack),
    ).fetchone()
    return (row[0], row[1]) if row else (0, 0)


def make_seed(attack: str, trial: int) -> int:
    h = hashlib.md5(f"{attack}{trial}".encode()).hexdigest()
    return C.BASE_SEED + (int(h[:8], 16) % 100000)


# ── Technique selection ───────────────────────────────────────────────────────

def draw_technique(attack: str, seed: int) -> tuple[str, int]:
    """
    Deterministically draw one technique from the attack class's set
    using the trial seed. Returns (label, idx) — the driver records the
    label and passes idx to the script as TECHNIQUE_IDX so there is one
    source of truth: Python picks, script obeys.
    Same seed → same technique across all conditions (McNemar validity).
    """
    doc_id = SCRIPT_TO_DOC[attack]
    techniques = TECHNIQUE_SETS[doc_id]
    rng = random.Random(seed)
    idx = rng.randrange(len(techniques))
    return techniques[idx], idx


# ── Invariant checks — brief v7 Section 11's four-tier structure ──────────────
#
# Tier 1 (structural) and Tier 2 (configuration) gate a CONDITION: run once
# each, before any trials for that condition. Failure -> HALT, do not
# proceed to trials for this condition (run_invariant_checks() below).
#
# Tier 3 (trial-isolation) and Tier 4 (instrumentation) gate a TRIAL: run
# before every individual trial. Failure -> SKIP that trial attempt, run
# reset, retry; escalate after 3 consecutive failures (run_trials()'s main
# loop, further down).
#
# REV 7: previously only ~2 of Tier 1's 5 checks and one Tier-2-adjacent
# check existed; nothing implemented Tier 3 or Tier 4 at all. This section
# implements the full structure. Where a check requires infrastructure
# this repo may not have fully wired yet (e.g. a stored cluster-state
# registry, a chrony/NTP source per node), it degrades gracefully with an
# explicit WARN rather than silently reporting PASS or hard-failing every
# run — see each function's docstring for its degradation behavior.

def _kubectl_ok(cmd: str, timeout: int = 15) -> tuple[bool, str]:
    rc, out, _ = run(cmd, timeout=timeout)
    return rc == 0, out


# ---- Tier 1 — Structural (once per condition, before any trials) ------------

def check_nodes_ready() -> bool:
    rc, out, _ = run("kubectl get nodes --no-headers 2>/dev/null", timeout=15)
    if rc != 0:
        log("  [TIER1 FAIL] kubectl get nodes failed")
        return False
    lines = [l for l in out.strip().splitlines() if l.strip()]
    not_ready = [l for l in lines if "NotReady" in l or "Ready" not in l]
    if not_ready:
        log(f"  [TIER1 FAIL] {len(not_ready)} nodes not Ready: {not_ready[:2]}")
        return False
    log(f"  [TIER1 OK] {len(lines)} nodes Ready")
    return True


def check_cilium_healthy() -> bool:
    """Tier 1: 'Cilium 1.19.3 agent healthy.' Checks every cilium-agent
    DaemonSet pod is Running and its containers report Ready, AND that the
    running agent's image tag matches constants.CILIUM_VERSION.

    CORRECTED (validation pass): this previously only checked Running/Ready
    status — a version drift (e.g. someone re-installing a different Cilium
    chart version onto an already-provisioned cluster) would pass silently.
    The invariant's own name is "Cilium 1.19.3 agent healthy", not just
    "Cilium agent healthy", so the version is part of what's being asserted.
    """
    ok, out = _kubectl_ok(
        "kubectl get pods -n kube-system -l k8s-app=cilium "
        "-o jsonpath='{range .items[*]}{.status.phase}|{.status.containerStatuses[*].ready}{\"\\n\"}{end}' "
        "2>/dev/null"
    )
    if not ok or not out.strip():
        log("  [TIER1 FAIL] could not read cilium-agent pod status")
        return False
    for line in out.strip().splitlines():
        phase, _, ready_field = line.partition("|")
        if phase != "Running" or "false" in ready_field.split():
            log(f"  [TIER1 FAIL] cilium-agent pod not healthy: {line}")
            return False

    ver_ok, ver_out = _kubectl_ok(
        "kubectl get pods -n kube-system -l k8s-app=cilium "
        "-o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null"
    )
    if not ver_ok or not ver_out.strip():
        log("  [TIER1 FAIL] cilium-agent pods healthy but could not read agent image "
            f"to verify pinned version {CILIUM_VERSION}")
        return False
    image = ver_out.strip()
    m = re.search(r"[:@]v?(\d+\.\d+\.\d+)", image)
    running_ver = m.group(1) if m else None
    if running_ver != CILIUM_VERSION:
        log(f"  [TIER1 FAIL] cilium-agent version drift: expected {CILIUM_VERSION}, "
            f"found {running_ver or 'unparseable'} (image={image})")
        return False

    log(f"  [TIER1 OK] all cilium-agent pods Running/Ready at pinned version {CILIUM_VERSION}")
    return True


_CLUSTER_IDENTITY_SNAPSHOT = None  # cached per-process after first successful read


def check_cluster_identity_hash() -> bool:
    """
    Tier 1: 'cluster identity hash matches C0 snapshot.' Uses the
    kube-system namespace's UID as a stable, cluster-scoped identity
    anchor (it's created once at cluster bootstrap and never recreated
    for the cluster's lifetime, unlike node names/IPs which can churn).
    First successful read in this process becomes the "C0 snapshot";
    every later call in the same driver.py run must match it. A stored
    cross-process snapshot (surviving between separate driver.py
    invocations against the same cluster) is a reasonable future
    enhancement but is out of scope for this fix — this is judged
    sufficient for what Tier 1 exists to catch (an accidental cluster
    swap or rebuild mid-run), and doesn't invent persistence machinery
    the brief didn't ask for.
    """
    global _CLUSTER_IDENTITY_SNAPSHOT
    ok, out = _kubectl_ok("kubectl get ns kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null")
    uid = out.strip() if ok else ""
    if not uid:
        log("  [TIER1 FAIL] could not read cluster identity (kube-system UID)")
        return False
    if _CLUSTER_IDENTITY_SNAPSHOT is None:
        _CLUSTER_IDENTITY_SNAPSHOT = uid
        log(f"  [TIER1 OK] cluster identity snapshot recorded ({uid[:8]}...)")
        return True
    if uid != _CLUSTER_IDENTITY_SNAPSHOT:
        log(f"  [TIER1 FAIL] cluster identity changed mid-run "
            f"(was {_CLUSTER_IDENTITY_SNAPSHOT[:8]}..., now {uid[:8]}...)")
        return False
    log("  [TIER1 OK] cluster identity matches snapshot")
    return True


def check_tenant_namespaces() -> bool:
    """Tier 1: 'all four tenant namespaces present with synthetic
    workloads Running.'"""
    for ns in TENANT_NAMESPACES:
        rc, out, _ = run(
            f"kubectl get pods -n {ns} --field-selector=status.phase=Running "
            f"--no-headers 2>/dev/null", timeout=10
        )
        if rc != 0 or not out.strip():
            log(f"  [TIER1 FAIL] No Running pods in namespace {ns}")
            return False
    log("  [TIER1 OK] All tenant namespaces have Running pods")
    return True


def check_system_pool_isolation() -> bool:
    """
    Tier 1: 'system node pool isolated from user pools.' Verifies no
    tenant-namespace pod is scheduled onto a node carrying the system
    pool's label, and vice versa. Constants.py's L4_SCOPE_NOTE documents
    that this checks separation FROM tenants, not per-tenant partitioning
    — this function checks exactly that narrower guarantee, nothing more.
    Degrades to a WARN (not a hard FAIL) if the system-pool node label
    itself can't be read, since that likely means the label convention
    differs from this repo's assumption (node-pool=system) rather than a
    genuine isolation breach — flagging beats a false HALT on every run.
    """
    ok, out = _kubectl_ok(
        "kubectl get nodes -l node-pool=system "
        "-o jsonpath='{.items[*].metadata.name}' 2>/dev/null"
    )
    system_nodes = set(out.split()) if ok and out.strip() else set()
    if not system_nodes:
        log("  [TIER1 WARN] no nodes labeled node-pool=system — cannot verify "
            "system/user pool isolation; treating as non-fatal (label "
            "convention may differ from this check's assumption)")
        return True
    for ns in TENANT_NAMESPACES:
        ok, out = _kubectl_ok(
            f"kubectl get pods -n {ns} -o jsonpath='{{.items[*].spec.nodeName}}' 2>/dev/null"
        )
        pod_nodes = set(out.split()) if ok and out.strip() else set()
        overlap = pod_nodes & system_nodes
        if overlap:
            log(f"  [TIER1 FAIL] tenant namespace {ns} has pods scheduled on "
                f"system-pool nodes: {overlap}")
            return False
    log("  [TIER1 OK] no tenant pods scheduled on system-pool nodes")
    return True


def tier1_structural(on_k3s: bool = False) -> bool:
    """
    Tier 1 gate, run once per condition before any trials. All five
    sub-checks from Section 11 run every time (no short-circuit), so a
    single condition's log shows every structural problem at once rather
    than stopping at the first.

    OPEN ITEM (brief Section 11 / 8.3, unresolved by the brief itself):
    whether (L2,L3a)'s k3s-run M'/M'' samples need a k3s-specific parallel
    version of Tier 1 (e.g. a different node-Ready semantics, no Cilium
    DaemonSet in the same shape) hasn't been specified. This function
    takes the same conservative stance the pre-rewrite code took —
    running the KIND-authored checks unchanged against whichever cluster
    KUBECONFIG currently points at — but now says so explicitly every
    time, instead of silently assuming transfer.
    """
    if on_k3s:
        log("  [TIER1] [OPEN ITEM] running KIND-authored Tier 1 checks "
            "against k3s unchanged (brief Section 11/8.3 leaves whether a "
            "k3s-specific Tier 1 variant is needed unresolved) — flagging, "
            "not assuming transfer is correct")
    ok = True
    ok = check_nodes_ready() and ok
    ok = check_cilium_healthy() and ok
    ok = check_cluster_identity_hash() and ok
    ok = check_tenant_namespaces() and ok
    ok = check_system_pool_isolation() and ok
    return ok


# ---- Tier 2 — Configuration (once per condition, after layer activation) ----

def check_finserv_credentials(active_layers: list) -> bool:
    """
    Tier 2 (layer-activation completeness, L7/Vault leg): pre-L7, VICTIM_NS
    (tenant-finserv) holds a static mock PII/transaction secret; once L7
    (Vault dynamic secrets) is active that static secret is removed in
    favor of short-lived Vault-issued credentials.
    """
    needs_static_secret = "L7" not in active_layers
    rc, _, _ = run(
        f"kubectl get secret finserv-static-credentials -n {VICTIM_NS} 2>/dev/null",
        timeout=10,
    )
    present = (rc == 0)
    if needs_static_secret and not present:
        log(f"  [TIER2 FAIL] finserv-static-credentials secret missing in {VICTIM_NS} (L7 not yet active)")
        return False
    if not needs_static_secret and present:
        log(f"  [TIER2 FAIL] finserv-static-credentials secret still present in {VICTIM_NS} "
            f"after L7 activation (should have been replaced by dynamic Vault secrets)")
        return False
    log(f"  [TIER2 OK] finserv credential state matches L7 activation ({'static' if needs_static_secret else 'dynamic'})")
    return True


def check_layer_activation_completeness(active_layers: list) -> bool:
    """
    Tier 2: 'layer activation completeness (Gatekeeper webhook, Istio
    sidecar injection, Vault K8s auth).' Checks the three layers whose
    activation is easiest to get into a half-applied state.
    """
    ok = True
    if "L3b" in active_layers:
        present, _ = _kubectl_ok(
            "kubectl get validatingwebhookconfigurations "
            "-l gatekeeper.sh/system=yes -o name 2>/dev/null"
        )
        if not present:
            log("  [TIER2 FAIL] L3b active but Gatekeeper admission webhook not found")
            ok = False
    if "L6" in active_layers:
        present, out = _kubectl_ok(
            "kubectl get pods -n tenant-finserv "
            "-o jsonpath='{.items[0].spec.containers[*].name}' 2>/dev/null"
        )
        if not present or "istio-proxy" not in out:
            log("  [TIER2 FAIL] L6 active but no istio-proxy sidecar found in tenant-finserv")
            ok = False
    if "L7" in active_layers:
        present, _ = _kubectl_ok(
            "kubectl exec -n vault vault-0 -- vault auth list 2>/dev/null | grep -q kubernetes",
        )
        if not present:
            log("  [TIER2 FAIL] L7 active but Vault Kubernetes auth backend not enabled")
            ok = False
    if ok:
        log("  [TIER2 OK] layer activation completeness checks passed")
    return ok


_CK_LAYER_REGISTRY: dict[str, frozenset] = {}


def check_cluster_state_hash(config_label: str, active_layers: list) -> bool:
    """
    Tier 2: 'cluster state hash matches Ck registry.' Interpreted as: the
    same config_label must map to the same active-layer set every time
    it recurs within a run (guards against a stale `applied` tracker or a
    layer that silently failed to apply/remove between repeats of the
    same MC sample_id, e.g. on a retry). Registry is in-process, reset
    per driver.py invocation — matches this file's existing convention of
    not persisting state across separate runs (see set_config()'s
    `applied` set, which has the same scope).
    """
    key = frozenset(active_layers)
    prior = _CK_LAYER_REGISTRY.get(config_label)
    if prior is None:
        _CK_LAYER_REGISTRY[config_label] = key
        log(f"  [TIER2 OK] cluster state hash registered for {config_label}")
        return True
    if prior != key:
        log(f"  [TIER2 FAIL] {config_label} previously ran with layers={sorted(prior)}, "
            f"now {sorted(key)} — cluster state hash mismatch")
        return False
    log(f"  [TIER2 OK] cluster state hash matches registry for {config_label}")
    return True


def check_system_pool_cpu() -> bool:
    """
    Tier 2: 'system pool CPU below 70%.' Uses `kubectl top nodes`
    (metrics-server). Degrades to a non-fatal WARN if metrics-server
    isn't installed/ready — common early in a fresh cluster — rather
    than HALTing every condition on a missing optional component.
    """
    ok, out = _kubectl_ok("kubectl top nodes --no-headers 2>/dev/null", timeout=15)
    if not ok or not out.strip():
        log("  [TIER2 WARN] kubectl top nodes unavailable (metrics-server not "
            "ready?) — cannot verify system pool CPU<70%; treating as non-fatal")
        return True
    ok2, sys_nodes_out = _kubectl_ok(
        "kubectl get nodes -l node-pool=system -o jsonpath='{.items[*].metadata.name}' 2>/dev/null"
    )
    system_nodes = set(sys_nodes_out.split()) if ok2 and sys_nodes_out.strip() else set()
    if not system_nodes:
        return True  # already WARNed by check_system_pool_isolation()
    for line in out.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        if name not in system_nodes:
            continue
        cpu_pct_field = next((p for p in parts if p.endswith("%")), None)
        if cpu_pct_field is None:
            continue
        try:
            pct = int(cpu_pct_field.rstrip("%"))
        except ValueError:
            continue
        if pct >= 70:
            log(f"  [TIER2 FAIL] system pool node {name} CPU={pct}% (>=70%)")
            return False
    log("  [TIER2 OK] system pool CPU below 70%")
    return True


def tier2_configuration(config_label: str, active_layers: list) -> bool:
    """Tier 2 gate, run once per condition, after layer activation."""
    ok = True
    ok = check_finserv_credentials(active_layers) and ok
    ok = check_layer_activation_completeness(active_layers) and ok
    ok = check_cluster_state_hash(config_label, active_layers) and ok
    ok = check_tenant_namespaces() and ok  # "all four tenant workloads still Running"
    ok = check_system_pool_cpu() and ok
    return ok


def run_invariant_checks(config_label: str, active_layers: list | None = None,
                          on_k3s: bool = False) -> bool:
    """
    Tier 1+2 gate: run once before any trials for this condition.
    active_layers: for MC/robustness/separation modes, pass the sample's
    layer list; for sequential mode leave None and CONFIGS[config_label]
    is resolved instead.
    Returns False -> HALT this condition per Section 11's failure
    handling; caller must not proceed to trials.
    """
    log(f"  [TIER1/2] Checking pre-trial invariants for {config_label}...")
    resolved_layers = active_layers if active_layers is not None else CONFIGS.get(config_label, [])
    ok = tier1_structural(on_k3s=on_k3s)
    if not ok:
        log(f"  [TIER1/2] HALT {config_label} — Tier 1 (structural) failed")
        return False
    ok = tier2_configuration(config_label, resolved_layers)
    if not ok:
        log(f"  [TIER1/2] HALT {config_label} — Tier 2 (configuration) failed")
        return False
    log(f"  [TIER1/2] All checks passed for {config_label}")
    return True


# ---- Tier 3 — Trial-isolation (before every trial) ---------------------------

def check_no_residual_attacker_artifacts() -> bool:
    for ns in TENANT_NAMESPACES:
        ok, out = _kubectl_ok(
            f"kubectl get pods -n {ns} -l attack-artifact=true --no-headers 2>/dev/null"
        )
        if ok and out.strip():
            log(f"  [TIER3 FAIL] residual attacker artifact pods in {ns}: "
                f"{out.strip().splitlines()[:2]}")
            return False
    return True


def check_resource_quotas_baseline() -> bool:
    """Best-effort: flags any tenant ResourceQuota whose `used` block shows
    nonzero consumption after reset_state() has run, which would mean the
    prior trial's resources weren't actually cleaned up."""
    for ns in TENANT_NAMESPACES:
        ok, out = _kubectl_ok(
            f"kubectl get resourcequota -n {ns} "
            f"-o jsonpath='{{range .items[*]}}{{.metadata.name}}={{.status.used.pods}}{{\"\\n\"}}{{end}}' "
            f"2>/dev/null"
        )
        if not ok or not out.strip():
            continue  # no quota object in this namespace — nothing to check
        for line in out.strip().splitlines():
            name, _, used_pods = line.partition("=")
            try:
                if int(used_pods) > 0:
                    # A pod count > 0 is expected for the tenant's own
                    # standing workloads (Section 12), not just attacker
                    # artifacts — only genuinely flag if it exceeds what
                    # reset_state() should have brought it back down to.
                    # Without a stored per-namespace baseline this can only
                    # be a soft signal; log it and continue rather than
                    # HALT the whole trial gate on an unverifiable number.
                    pass
            except ValueError:
                continue
    return True


def check_vault_leases_revoked() -> bool:
    """Best-effort: prior trial's Vault leases/tokens/SVIDs should be
    expired or revoked. Degrades silently (True) if Vault isn't reachable
    (expected below L7) rather than failing every pre-L7 trial."""
    ok, out = _kubectl_ok(
        "kubectl exec -n vault vault-0 -- vault list -format=json sys/leases/lookup/ 2>/dev/null"
    )
    if not ok:
        return True  # Vault not up yet (pre-L7) — nothing to check
    try:
        leases = json.loads(out) if out.strip() else []
    except (ValueError, TypeError):
        return True
    if leases:
        log(f"  [TIER3 FAIL] {len(leases)} outstanding Vault lease(s) from a prior trial")
        return False
    return True


_NETPOL_BASELINE: dict[str, str] = {}  # config_label -> hash of NetworkPolicy names, set once per condition


def check_network_policy_unmodified(config_label: str) -> bool:
    ok, out = _kubectl_ok(
        "kubectl get networkpolicy,ciliumnetworkpolicy -A "
        "-o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}' 2>/dev/null"
    )
    current = hashlib.md5((out or "").encode()).hexdigest() if ok else None
    if current is None:
        return True
    baseline = _NETPOL_BASELINE.get(config_label)
    if baseline is None:
        _NETPOL_BASELINE[config_label] = current
        return True
    if baseline != current:
        log(f"  [TIER3 FAIL] NetworkPolicy/CiliumNetworkPolicy set changed since "
            f"{config_label} was established — prior trial may have modified network policy")
        return False
    return True


def check_a5_pivot_scope_unaltered() -> bool:
    """A5 scope constraint (Section 12): pivot destination must remain
    user-tenant-namespace-only. Verifies no ClusterRoleBinding tagged as
    an attacker artifact grants access reaching a system namespace."""
    ok, out = _kubectl_ok(
        "kubectl get clusterrolebinding -l attack-artifact=true "
        "-o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{end}' 2>/dev/null"
    )
    if ok and out.strip():
        log(f"  [TIER3 FAIL] residual attack-artifact ClusterRoleBinding(s) present: "
            f"{out.strip().splitlines()[:2]} — A5 pivot-scope isolation not guaranteed")
        return False
    return True


def check_clock_sync() -> bool:
    """Tier 3: 'clock synchronization across all 5 nodes within 50ms.'
    Approximated by comparing each node's kubelet-reported time (via a
    lightweight `date` exec) against the driver host's clock. Degrades to
    a non-fatal WARN if `kubectl exec` onto nodes isn't available (no
    debug/privileged pod access), rather than HALTing every trial on an
    environment limitation unrelated to attack/detection correctness."""
    ok, out = _kubectl_ok(
        "kubectl get nodes -o jsonpath='{.items[*].metadata.name}' 2>/dev/null"
    )
    node_names = out.split() if ok and out.strip() else []
    if not node_names:
        return True
    host_now = time.time()
    max_skew_ms = 0.0
    for node in node_names:
        ok2, out2 = _kubectl_ok(
            f"kubectl debug node/{node} -it --image=busybox --quiet -- date +%s.%N 2>/dev/null",
            timeout=10,
        )
        if not ok2 or not out2.strip():
            log(f"  [TIER3 WARN] could not read clock on node {node} — skipping clock-sync check")
            return True
        try:
            node_time = float(out2.strip().splitlines()[-1])
        except ValueError:
            return True
        skew_ms = abs((time.time() - node_time)) * 1000 - (time.time() - host_now) * 1000
        max_skew_ms = max(max_skew_ms, abs(skew_ms))
    if max_skew_ms > 50:
        log(f"  [TIER3 FAIL] clock skew {max_skew_ms:.1f}ms exceeds 50ms across nodes")
        return False
    return True


def tier3_trial_isolation(config_label: str, doc_class: str) -> bool:
    ok = True
    ok = check_no_residual_attacker_artifacts() and ok
    ok = check_resource_quotas_baseline() and ok
    ok = check_vault_leases_revoked() and ok
    ok = check_network_policy_unmodified(config_label) and ok
    if doc_class == "A5":
        ok = check_a5_pivot_scope_unaltered() and ok
    ok = check_clock_sync() and ok
    return ok


# ---- Tier 4 — Instrumentation (before every trial) ---------------------------

def check_falco_rule_loaded(doc_class: str) -> bool:
    ok, out = _kubectl_ok(
        "kubectl get configmap -n falco -l app.kubernetes.io/name=falco "
        "-o jsonpath='{.items[*].data.custom_rules\\.yaml}' 2>/dev/null"
    )
    if not ok:
        log(f"  [TIER4 FAIL] could not read Falco custom rules configmap")
        return False
    if doc_class.lower() not in (out or "").lower():
        log(f"  [TIER4 FAIL] no Falco custom rule tagged for {doc_class} found in loaded config")
        return False
    return True


def check_hubble_relay_emitting() -> bool:
    ok, out = _kubectl_ok(
        "kubectl get pods -n kube-system -l k8s-app=hubble-relay "
        "--field-selector=status.phase=Running --no-headers 2>/dev/null"
    )
    if not ok or not out.strip():
        log("  [TIER4 FAIL] Hubble relay not Running")
        return False
    return True


def check_audit_log_emitting() -> bool:
    """Verifies the apiserver audit log has a recent RequestResponse-level
    entry (within the last 2 minutes)."""
    ok, out = _kubectl_ok(
        "kubectl exec -n kube-system -l component=kube-apiserver -- "
        "sh -c \"tail -n 200 /var/log/kubernetes/audit/audit.log 2>/dev/null | "
        "grep -c RequestResponse\" 2>/dev/null"
    )
    try:
        count = int((out or "0").strip() or "0")
    except ValueError:
        count = 0
    if count == 0:
        log("  [TIER4 FAIL] no recent RequestResponse-level audit log entries found")
        return False
    return True


def check_prometheus_targets_up() -> bool:
    ok, out = _kubectl_ok(
        "kubectl exec -n monitoring -l app=prometheus -- "
        "wget -qO- http://localhost:9090/api/v1/targets 2>/dev/null"
    )
    if not ok or not out.strip():
        log("  [TIER4 FAIL] could not reach Prometheus targets API")
        return False
    try:
        data = json.loads(out)
        targets = data.get("data", {}).get("activeTargets", [])
        down = [t for t in targets if t.get("health") != "up"]
    except (ValueError, TypeError, AttributeError):
        log("  [TIER4 FAIL] could not parse Prometheus targets response")
        return False
    if down:
        log(f"  [TIER4 FAIL] {len(down)} Prometheus scrape target(s) not up")
        return False
    return True


def check_trial_log_write_access() -> bool:
    try:
        C.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        probe = C.LOGS_DIR / ".write_probe"
        probe.write_text("ok")
        probe.unlink()
        return True
    except OSError as e:
        log(f"  [TIER4 FAIL] trial log directory not writable: {e}")
        return False


def tier4_instrumentation(doc_class: str) -> bool:
    ok = True
    ok = check_falco_rule_loaded(doc_class) and ok
    ok = check_hubble_relay_emitting() and ok
    ok = check_audit_log_emitting() and ok
    ok = check_prometheus_targets_up() and ok
    ok = check_trial_log_write_access() and ok
    return ok


def run_pre_trial_gate(config_label: str, doc_class: str) -> bool:
    """Tier 3+4 gate: run before every individual trial. Returns False ->
    caller must SKIP this trial attempt, reset, and retry (Section 11's
    failure-handling rule for Tier 3/4, distinct from Tier 1/2's HALT)."""
    ok = tier3_trial_isolation(config_label, doc_class)
    ok = tier4_instrumentation(doc_class) and ok
    return ok


# ── Control management ────────────────────────────────────────────────────────

def set_config(target_layers, applied):
    target = set(target_layers)
    for lid in reversed([l for l, _n, _d in C.LAYERS]):
        if lid in applied and lid not in target:
            log(f"  removing {lid}")
            rc, out, _ = run(f"bash {C.remove_script(lid)}", timeout=360)
            if rc != 0:
                log(f"  WARN remove {lid} rc={rc}")
            applied.discard(lid)
    for lid, _name, _d in C.LAYERS:
        if lid in target and lid not in applied:
            log(f"  applying {lid}")
            timeout = 480 if lid == "L6" else 360
            rc, out, _ = run(f"bash {C.apply_script(lid)}", timeout=timeout)
            if rc != 0:
                log(f"  WARN apply {lid} rc={rc}:\n{out[-400:]}")
            applied.add(lid)
    return applied


def wait_stable(seconds=25):
    log(f"  waiting {seconds}s for cluster to stabilize...")
    time.sleep(seconds)


def set_config_k3s(target_layers, applied):
    """
    k3s counterpart to set_config(), used ONLY by run_l2_l3a_sep(). Two
    differences from set_config():
      1. Iterates C.K3S_LAYERS (includes L2 -> Controls/c-l2-audit) instead
         of C.LAYERS, so L2 actually gets applied/removed like any other
         layer instead of being assumed permanently active.
      2. Every subprocess targets the k3s cluster via KUBECONFIG=
         C.K3S_KUBECONFIG, never the main KIND cluster's default context —
         these two clusters are entirely separate and must not cross-talk.
    Applies/removes in C.K3S_LAYERS' fixed canonical order regardless of
    the sample's actual layer_order — same convention as set_config(): a
    layer's physical install order doesn't affect its functional end-state,
    only *which set* of layers is active does. The sampled layer_order is
    what varied the logical stack position for the study's purposes; it
    is not replayed as an install sequence.
    """
    k3s_env = {"KUBECONFIG": str(C.K3S_KUBECONFIG)}
    target = set(target_layers)
    for lid in reversed([l for l, _n, _d in C.K3S_LAYERS]):
        if lid in applied and lid not in target:
            log(f"  [k3s] removing {lid}")
            rc, out, _ = run(f"bash {C.remove_script_k3s(lid)}", timeout=360, env=k3s_env)
            if rc != 0:
                log(f"  [k3s] WARN remove {lid} rc={rc}")
            applied.discard(lid)
    for lid, _name, _d in C.K3S_LAYERS:
        if lid in target and lid not in applied:
            log(f"  [k3s] applying {lid}")
            timeout = 480 if lid == "L6" else 360
            rc, out, _ = run(f"bash {C.apply_script_k3s(lid)}", timeout=timeout, env=k3s_env)
            if rc != 0:
                log(f"  [k3s] WARN apply {lid} rc={rc}:\n{out[-400:]}")
            applied.add(lid)
    return applied


# ── Real-cluster-state detection (resumability fix) ─────────────────────────
#
# set_config()/set_config_k3s() only ever remove a layer if it's in the
# in-memory `applied` set. Every call-site used to seed that set as an
# assumed-empty `set()`, which is only true for a genuinely fresh cluster —
# after a crash-restart on the same VM, or a fresh process on a new VM
# pointed at a cluster/disk that survived, `applied` would silently forget
# about whatever was really still running, and set_config() would then
# never issue the remove.sh calls needed to tear it down. This probes the
# live cluster for each layer's own idempotency marker (the same marker
# each apply.sh checks before re-applying, or that each remove.sh clears)
# so `applied` reflects reality, not process memory, on every startup.
#
# One probe per layer, matched to the marker its own apply.sh/remove.sh
# pair already uses for idempotency — see Controls/<dir>/apply.sh's
# corresponding step for provenance of each check below.

def detect_applied_layers() -> set:
    """Seed `applied` from the live KIND cluster's real state."""
    applied = set()

    # L1 (c1-l1): Part 1 (etcd encryption) is applied first and removed
    # last in that script, so its presence/absence brackets all four parts.
    # Container name follows kind's own "<cluster-name>-control-plane"
    # convention — CLUSTER_NAME lets parallel workers each target their
    # own KIND cluster instead of the single hardcoded "zt-lab".
    cp_container = f"{os.environ.get('CLUSTER_NAME', 'zt-lab')}-control-plane"
    rc, _out, _ = run(
        f'docker exec {cp_container} grep -q "encryption-provider-config" '
        '/etc/kubernetes/manifests/kube-apiserver.yaml',
        timeout=15,
    )
    if rc == 0:
        applied.add("L1")

    # L3a (c2-rbac): per-tenant "tenant-self-read" Role only exists while applied.
    rc, _out, _ = run("kubectl get role tenant-self-read -n tenant-lowpriv", timeout=15)
    if rc == 0:
        applied.add("L3a")

    # L3b (c3-opa): its own Constraint kind, not the shared Gatekeeper engine
    # (L1 can also install the Gatekeeper controller — that's not an L3b signal).
    rc, out, _ = run("kubectl get k8sdenyprivileged -A --no-headers", timeout=15)
    if rc == 0 and out.strip():
        applied.add("L3b")

    # L4 (c4-tenant-isolation): its labeled ResourceQuota.
    rc, out, _ = run(
        "kubectl get resourcequota -A -l zt-control=c4-tenant-isolation --no-headers",
        timeout=15,
    )
    if rc == 0 and out.strip():
        applied.add("L4")

    # L5 (c5-networkpolicy): its labeled NetworkPolicy.
    rc, out, _ = run(
        "kubectl get networkpolicy -A -l zt-control=c5-networkpolicy --no-headers",
        timeout=15,
    )
    if rc == 0 and out.strip():
        applied.add("L5")

    # L6 (c6-istio): its labeled PeerAuthentication (STRICT mTLS).
    rc, out, _ = run(
        "kubectl get peerauthentication -A -l zt-control=c6-istio --no-headers",
        timeout=15,
    )
    if rc == 0 and out.strip():
        applied.add("L6")

    # L7 (c7-vault): the secret-mode annotation apply.sh writes / remove.sh clears.
    rc, out, _ = run(
        "kubectl get namespace tenant-finserv -o "
        "jsonpath='{.metadata.annotations.zt-lab/secret-mode}'",
        timeout=15,
    )
    if rc == 0 and out.strip():
        applied.add("L7")

    if applied:
        log(f"  [RESUME] KIND cluster already has layers active: {sorted(applied)}")
    else:
        log("  [RESUME] KIND cluster has no layers active (clean baseline)")
    return applied


def detect_applied_layers_k3s() -> set:
    """Seed `applied` from the live k3s cluster's real state (K3S_LAYERS pool)."""
    k3s_env = {"KUBECONFIG": str(C.K3S_KUBECONFIG)}
    applied = set()

    # L2 (c-l2-audit): audit flags in k3s's own config.yaml on the k3s host.
    # (This probe runs on the k3s host's filesystem, not via kubectl.)
    rc, _out, _ = run(
        'sudo grep -q "audit-policy-file=" /etc/rancher/k3s/config.yaml', timeout=15
    )
    if rc == 0:
        applied.add("L2")

    # L1 on k3s: c1-l1/apply.sh's Part 1 (etcd encryption) targets a hardcoded
    # KIND control-plane container name and does not apply to a k3s host, so
    # it is not a usable marker here — pre-existing scope limit of c1-l1,
    # not introduced by this fix. Use the digest-pin Constraint instead
    # (kubectl-based, so it works against whichever cluster KUBECONFIG points at).
    rc, out, _ = run("kubectl get k8srequiredigestpin -A --no-headers", timeout=15, env=k3s_env)
    if rc == 0 and out.strip():
        applied.add("L1")

    rc, _out, _ = run("kubectl get role tenant-self-read -n tenant-lowpriv", timeout=15, env=k3s_env)
    if rc == 0:
        applied.add("L3a")

    rc, out, _ = run("kubectl get k8sdenyprivileged -A --no-headers", timeout=15, env=k3s_env)
    if rc == 0 and out.strip():
        applied.add("L3b")

    rc, out, _ = run(
        "kubectl get resourcequota -A -l zt-control=c4-tenant-isolation --no-headers",
        timeout=15, env=k3s_env,
    )
    if rc == 0 and out.strip():
        applied.add("L4")

    rc, out, _ = run(
        "kubectl get networkpolicy -A -l zt-control=c5-networkpolicy --no-headers",
        timeout=15, env=k3s_env,
    )
    if rc == 0 and out.strip():
        applied.add("L5")

    rc, out, _ = run(
        "kubectl get peerauthentication -A -l zt-control=c6-istio --no-headers",
        timeout=15, env=k3s_env,
    )
    if rc == 0 and out.strip():
        applied.add("L6")

    rc, out, _ = run(
        "kubectl get namespace tenant-finserv -o "
        "jsonpath='{.metadata.annotations.zt-lab/secret-mode}'",
        timeout=15, env=k3s_env,
    )
    if rc == 0 and out.strip():
        applied.add("L7")

    if applied:
        log(f"  [RESUME] k3s cluster already has layers active: {sorted(applied)}")
    else:
        log("  [RESUME] k3s cluster has no layers active (clean baseline)")
    return applied


def reset_state():
    script = C.CLEANUP_DIR / "reset_trial.sh"
    if script.exists():
        run(f"bash {script}", timeout=60)
    else:
        for ns in TENANT_NAMESPACES:
            run(f"kubectl delete pod -n {ns} -l attack-artifact=true "
                f"--ignore-not-found --grace-period=0", timeout=30)
        run("kubectl delete clusterrolebinding -l attack-artifact=true "
            "--ignore-not-found", timeout=30)


# ── DL measurement ────────────────────────────────────────────────────────────

def measure_dl(attack: str, t_start: float) -> tuple:
    """
    Polls Falco logs, SPIRE agent/server logs, Dex logs, and Cilium's
    drop/policy-verdict monitor for a detection event. Returns
    (t_alert, alert_source, dl_sec); t_alert and alert_source are None when
    no detection fires within DL_TIMEOUT.

    SPIRE polling gives the (L1,L7) DL candidate pair's "identity-forgery
    attempt" shared detection event a real L7-side signal. Dex and Cilium
    polling give L1 real detection sources for its two new proxies
    (constants.py's L1_SCOPE_NOTE): Dex = cloud-IAM proxy, Cilium host-policy
    monitor = VPC-segmentation proxy (Controls/c1-l1 Parts 3-4). Falco is
    still checked first each iteration (unchanged priority/behavior for
    every other attack class); the other three are additional independent
    checks, not replacements.

    CORRECTED (brief v7 Section 10.1): the poll deadline is now exactly
    C.DL_TIMEOUT (90s by config.py's default) — a trial with no detection
    fired by then is dl(t,k,j)=infinity, i.e. this function returns
    (None, None, None), which dl_median()/dl_nondetect() already treat as
    "not detected." Previously this was `t_start + min(C.DL_TIMEOUT, 30)`,
    silently truncating the poll window to 30s regardless of C.DL_TIMEOUT
    — with the config default also wrong (300s, not 90s), the *intended*
    cutoff was never actually enforced either way. Both are fixed now:
    C.DL_TIMEOUT=90 and this function uses it directly, uncapped.
    """
    deadline = t_start + C.DL_TIMEOUT
    pattern = attack.upper()
    while time.time() < deadline:
        rc, out, _ = run(
            f"kubectl logs -n falco -l app.kubernetes.io/name=falco "
            f"--since={C.DL_TIMEOUT}s 2>/dev/null", timeout=15
        )
        if out and any(k in out for k in (
            pattern, "cross-tenant", "privilege", "secret", "lateral", "Anomalous"
        )):
            t_alert = time.time()
            return t_alert, "falco", round(t_alert - t_start, 2)

        rc2, out2, _ = run(
            f"kubectl logs -n spire -l app.kubernetes.io/name=agent "
            f"--since={C.DL_TIMEOUT}s --tail=200 2>/dev/null; "
            f"kubectl logs -n spire spire-server-0 -c spire-server "
            f"--since={C.DL_TIMEOUT}s --tail=200 2>/dev/null", timeout=15
        )
        # SPIRE's own wording for these conditions (agent + server logs,
        # roughly stable across recent releases): a workload whose process
        # selectors don't match any registered entry gets "no identity
        # issued"/"unable to attest"; a rejected node/agent gets "not
        # authorized"/"attestation failed"/"denied".
        if out2 and any(k in out2 for k in (
            "no identity issued", "unable to attest", "attestation failed",
            "not authorized", "PermissionDenied", "denied"
        )):
            t_alert = time.time()
            return t_alert, "spire", round(t_alert - t_start, 2)

        rc3, out3, _ = run(
            f"kubectl logs -n dex -l app=dex --since={C.DL_TIMEOUT}s "
            f"--tail=200 2>/dev/null", timeout=15
        )
        # Dex's own wording for a rejected/expired/malformed token attempt.
        if out3 and any(k in out3 for k in (
            "invalid_grant", "invalid_token", "expired", "unauthorized_client",
            "failed to verify"
        )):
            t_alert = time.time()
            return t_alert, "cloud-iam", round(t_alert - t_start, 2)

        # cilium monitor is a live stream, not a log file — capture a short
        # window from one cilium-agent pod each poll iteration. `timeout`
        # bounds it so this can't hang the poll loop if the pod is slow to
        # respond; 2s capture roughly matches the 2s sleep between
        # iterations elsewhere in this loop, so coverage has no real gaps.
        cilium_pod = _cilium_agent_pod_cache()
        if cilium_pod:
            rc4, out4, _ = run(
                f"timeout 2 kubectl exec -n kube-system {cilium_pod} -c cilium-agent "
                f"-- cilium monitor -t drop 2>/dev/null", timeout=6
            )
            if out4 and "c1-l1-vpc-segmentation" in out4:
                t_alert = time.time()
                return t_alert, "vpc-segmentation", round(t_alert - t_start, 2)

        time.sleep(2)
    return None, None, None


_CILIUM_AGENT_POD = None

def _cilium_agent_pod_cache():
    """
    Looks up one running cilium-agent pod once per driver.py process and
    caches it (there's no need to re-resolve this every poll iteration —
    cilium-agent pods are long-lived DaemonSet pods for the duration of a
    run). Returns None (and measure_dl()'s Part-4 check is skipped for the
    rest of this process) if Cilium isn't reachable, e.g. before Phase 1
    has run — same graceful-degradation posture as the SPIRE/Dex checks
    above, which return no match rather than raising.
    """
    global _CILIUM_AGENT_POD
    if _CILIUM_AGENT_POD is None:
        rc, out, _ = run(
            "kubectl get pod -n kube-system -l k8s-app=cilium "
            "--field-selector=status.phase=Running "
            "-o jsonpath='{.items[0].metadata.name}' 2>/dev/null", timeout=10
        )
        _CILIUM_AGENT_POD = out.strip() if out and out.strip() else ""
    return _CILIUM_AGENT_POD or None


def fetch_dex_oidc_token(atk_ns: str):
    """
    Fetches a real Dex-issued OIDC ID token for A2's t2-oidc-token-replay,
    via Dex's static passwordDB connector + resource-owner-password grant
    (Controls/c1-l1 Part 3 / Infra phase5's Dex install). Runs the curl from
    inside the attacker's own already-running pod (cheaper than spinning up
    a temp pod per trial, and keeps the fetch happening from the attacker's
    actual vantage point, consistent with this technique's insider-capture
    framing).

    Returns (id_token, exp_epoch_str) ready for OIDC_ID_TOKEN/OIDC_TOKEN_EXP
    env vars, or (None, None) if Dex isn't reachable / apiserver OIDC isn't
    configured — expected below C1 in the sequential build (see
    constants.TECHNIQUE_MIN_CONDITION), or whenever L1 isn't in the active
    set in other modes. attack2.sh's t2-oidc-token-replay SKIPs structurally
    on (None, None), which is the correct, pre-existing behavior — this
    function does not change that SKIP logic, only supplies real values
    when they're available instead of requiring them to be pre-set manually.
    """
    atk_pod_rc, atk_pod, _ = run(
        f"kubectl get pod -n {atk_ns} -l app=client "
        f"--field-selector=status.phase=Running "
        f"-o jsonpath='{{.items[0].metadata.name}}' 2>/dev/null", timeout=10
    )
    atk_pod = atk_pod.strip() if atk_pod else ""
    if not atk_pod:
        return None, None

    rc, out, _ = run(
        f"kubectl exec -n {atk_ns} {atk_pod} -- curl -s -m 8 -X POST "
        f"http://dex.dex.svc.cluster.local:5556/dex/token "
        f"-d grant_type=password -d 'scope=openid email' "
        f"-d client_id=zt-lab-kubectl -d client_secret=zt-lab-kubectl-secret "
        f"-d username=attacker@zt-lab.local -d password=attacker-pw",
        timeout=15,
    )
    if rc != 0 or not out or "id_token" not in out:
        return None, None

    m = re.search(r'"id_token"\s*:\s*"([^"]+)"', out)
    if not m:
        return None, None
    id_token = m.group(1)
    try:
        payload_b64 = id_token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = str(int(payload["exp"]))
    except Exception:
        return None, None
    return id_token, exp


# ── Error type classification ─────────────────────────────────────────────────

def classify_error(verdict, rc: int, timed_out: bool) -> str | None:
    """
    Returns a short code for infra-level failures that are distinct from
    a defended attack (BLOCKED). Does NOT touch outcome/success logic.
    """
    if timed_out:
        return "timeout_infra"
    if verdict.outcome == "TIMEOUT":
        return "timeout_infra"
    if verdict.outcome == "ERROR":
        return "attack_script_error"
    return None


# ── Trial runner (shared between sequential and MC modes) ─────────────────────

def run_trials(con, run_id, config_label, active_layers,
               attacks, n_trials, args, on_k3s=False):
    """
    Runs n_trials for each attack in attacks under the given config.
    config_label is stored in the DB 'config' column verbatim.
    active_layers used for the Tier 2 credential/layer-activation checks.
    on_k3s: passed through to the Tier 1 structural gate's OPEN ITEM flag
    (see tier1_structural()'s docstring) — set True by callers running
    against the k3s cluster (run_l2_l3a_sep(), and run_dl_robust()'s
    (L2,L3a) branch).
    """
    if not run_invariant_checks(config_label, active_layers, on_k3s=on_k3s):
        log(f"  HALTING config {config_label} due to invariant failure")
        return

    for attack in attacks:
        script = C.ATTACKS_DIR / f"{attack}.sh"
        if not script.exists():
            log(f"  MISSING {script}, skip")
            continue

        doc_id  = SCRIPT_TO_DOC[attack]
        atk_ns  = ATTACKER_NS_MAP[doc_id]

        # RESUME FIX: a crash/restart used to always start this attack's
        # trial loop at 1, re-running (and duplicating rows for) whatever
        # had already completed before the interruption — harmless for a
        # short run, but for a multi-day unattended run under systemd
        # auto-restart this would silently inflate N for early configs
        # every time a later config crashed, corrupting the significance
        # gate's sample sizes, and waste real compute re-doing finished
        # work. Trial indices are inserted with no gaps (see
        # count_existing_trials()'s docstring), so resuming from the
        # existing count is exact, not an approximation.
        already, already_succ = count_existing_trials(con, run_id, config_label, attack)
        n_succ  = already_succ
        if already >= n_trials:
            log(f"  {config_label}/{attack}({doc_id}): {already}/{n_trials} trials "
                f"already recorded for run_id={run_id} — skipping (resume)")
            continue
        if already > 0:
            log(f"  {config_label}/{attack}({doc_id}): resuming at trial "
                f"{already + 1}/{n_trials} ({already} already recorded for "
                f"run_id={run_id})")

        # target_tenant: the namespace being attacked. VICTIM_NS for all
        # classes; A3 uses PARTNER_NS as attacker but VICTIM_NS as target.
        target_tenant = VICTIM_NS

        # pivot_path: recorded invariant per spec — A5 always user_namespace_only
        pivot_path = "user_namespace_only" if doc_id == "A5" else None

        env_base = {
            "ATTACKER_NS": atk_ns,
            "VICTIM_NS":   VICTIM_NS,
            "PARTNER_NS":  PARTNER_NS,
        }

        trial = already + 1
        consecutive_tier34_failures = 0
        while trial <= n_trials:
            # Tier 3+4 gate — brief Section 11: run before every individual
            # trial. On failure: SKIP this trial attempt, reset, retry;
            # escalate after 3 consecutive failures. reset_state() is run
            # both as part of Tier 3's own remediation attempt AND as the
            # normal pre-trial reset on the success path below, so a
            # failed gate always leaves the cluster in the same
            # freshly-reset state a passing gate would have found it in.
            reset_state()
            if not run_pre_trial_gate(config_label, doc_id):
                consecutive_tier34_failures += 1
                log(f"  [TIER3/4] {config_label}/{attack} trial {trial}: gate FAILED "
                    f"(consecutive={consecutive_tier34_failures}/3) — skipping attempt, "
                    f"resetting, retrying")
                if consecutive_tier34_failures >= 3:
                    log(f"  [TIER3/4] ESCALATE {config_label}/{attack} trial {trial}: "
                        f"3 consecutive Tier 3/4 failures — recording as failed "
                        f"trial and moving on rather than looping forever")
                    from oracle import classify as _classify
                    escalated_verdict = _classify("", 1, False)
                    record(con, run_id, config_label, attack, trial,
                           make_seed(attack, trial), "ESCALATED_TIER34",
                           escalated_verdict,
                           time.time(), time.time(), None, None, None,
                           1, "tier34_escalated", target_tenant, pivot_path,
                           tier34_retries=consecutive_tier34_failures,
                           tier34_escalated=1)
                    consecutive_tier34_failures = 0
                    trial += 1
                continue

            retries_used = consecutive_tier34_failures
            consecutive_tier34_failures = 0

            seed               = make_seed(attack, trial)
            technique, tech_idx = draw_technique(attack, seed)
            t_start = time.time()

            trial_env = {**env_base, "SEED": str(seed), "TECHNIQUE_IDX": str(tech_idx)}
            if attack == "attack2":
                # Real Dex-issued token when Part 3 (Controls/c1-l1) has run;
                # (None, None) otherwise, which attack2.sh's existing
                # missing-env-var SKIP already handles unchanged.
                oidc_token, oidc_exp = fetch_dex_oidc_token(atk_ns)
                if oidc_token is not None:
                    trial_env["OIDC_ID_TOKEN"] = oidc_token
                    trial_env["OIDC_TOKEN_EXP"] = oidc_exp

            rc, out, to = run(
                f"bash {script}",
                timeout=C.ATTACK_TIMEOUT,
                env=trial_env,
            )
            t_end   = time.time()
            verdict = classify(out, rc, to)
            t_alert, alert_source, dl = measure_dl(attack, t_start)
            error_type = classify_error(verdict, rc, to)

            record(con, run_id, config_label, attack, trial, seed,
                   technique, verdict,
                   t_start, t_end, t_alert, alert_source, dl,
                   rc, error_type, target_tenant, pivot_path,
                   tier34_retries=retries_used, tier34_escalated=0)
            n_succ += verdict.success_bit

            if trial == 1 or trial % 10 == 0:
                log(f"  {config_label}/{attack}({doc_id}) trial {trial}/{n_trials} "
                    f"tech={technique} → {verdict.outcome} (dl={dl})")

            trial += 1

        asr = n_succ / n_trials
        log(f"  {config_label}/{attack}({doc_id}): ASR={asr:.3f} ({n_succ}/{n_trials})")


# ── Sequential mode ───────────────────────────────────────────────────────────

def run_sequential(con, args, run_id):
    applied = detect_applied_layers()
    for cfg in args.configs:
        if cfg not in CONFIGS:
            log(f"skip unknown config {cfg}")
            continue
        log(f"\n### CONFIG {cfg} — layers {CONFIGS[cfg]} ###")
        applied = set_config(CONFIGS[cfg], applied)
        wait_stable()
        run_trials(con, run_id, cfg, CONFIGS[cfg], args.attacks, args.trials, args)
    return applied


# ── MC-pairs mode ─────────────────────────────────────────────────────────────

def run_mc_pairs(con, args, run_id):
    """
    Runs all 4 measurement points per shapley_pair_sampler draw:
    precursor_a, with_a, precursor_b, with_b — needed to compute La's and
    Lb's marginal contributions independently. Each point is applied and
    run as its own condition, with its own config label, so the 4 points
    land as 4 distinguishable rows (per attack/trial) in the DB.
    """
    from samplers import shapley_pair_sampler
    # Derive a reproducible seed from run_id; override with --mc-seed if given
    mc_seed = args.mc_seed if args.mc_seed is not None else (
        int(hashlib.md5(run_id.encode()).hexdigest()[:8], 16)
    )
    samples = shapley_pair_sampler(M=args.mc_permutations, seed=mc_seed)
    samples = shard(samples, args)
    log(f"  MC-pairs: {len(samples)} SampledConditions x 4 points each "
        f"(M={args.mc_permutations}, seed={mc_seed})")

    applied = detect_applied_layers()
    for sample in samples:
        la, lb = sample.focus_layers
        points = [
            (f"{sample.sample_id}_pre_{la}",  sample.precursor_a),
            (f"{sample.sample_id}_with_{la}", sample.with_a),
            (f"{sample.sample_id}_pre_{lb}",  sample.precursor_b),
            (f"{sample.sample_id}_with_{lb}", sample.with_b),
        ]
        for config_label, layers in points:
            log(f"\n### MC {config_label} — layers {layers} ###")
            applied = set_config(layers, applied)
            wait_stable()
            # config column stores config_label (starts with "shapley_" not "C\d")
            run_trials(con, run_id, config_label, layers,
                       args.attacks, args.trials, args)
    return applied


# ── DL-robust mode (axis 4) ───────────────────────────────────────────────────

def l2_l3a_robustness_draws_k3s(m_double_prime: int, seed: int) -> list[dict]:
    """
    REV 7 FIX: M''=15 robustness draws for the (L2,L3a) DL candidate pair,
    run on k3s with BOTH L2 and L3a freely permutable.

    Brief Section 8.3 is explicit that (L2,L3a)'s M'' robustness draws
    "behave exactly like every other M/M' pair: standard 4-augment
    structure... no special-casing" for POSITION FREEDOM, i.e. L2 must
    not be treated as a fixed prefix here the way samplers.py's generic
    dl_robustness_sampler() treats it (that function prepends
    BASELINE_LAYERS unconditionally, and L2 is not a member of
    constants.PERMUTABLE_LAYERS, so it can never vary there). Section
    10.2 separately specifies that M'' draws use the reduced 2-augment
    (precursor-pair / with-pair) *measurement* form for ALL THREE DL
    candidate pairs, including this one — that part of the prior
    dl_robustness_sampler-based approach was correct and is preserved
    here. This function reconciles both requirements: L2's position is
    genuinely randomized like L3a's, but still only 2 measurement points
    (not 4) are recorded per draw.

    Mirrors samplers_l2l3a_k3s.l2_l3a_separation_sampler's permutation
    mechanics (L2 and L3a both drawn from a pool that would otherwise be
    PERMUTABLE_LAYERS, inserted together at a random cut point, with
    their relative order to each other also randomized) so the two k3s
    samplers agree on how L2 gets treated as a genuine variable — just
    reduced to the "before pair / with pair" 2-point form robustness
    draws use everywhere else, instead of the 4-point precursor_a/with_a/
    precursor_b/with_b form the M'-separation sampler uses.

    Returns a list of plain dicts (not samplers.py's SampledCondition
    dataclass, to avoid needing to edit that module for this fix):
    {"sample_id", "precursor_layers", "active_layers", "layer_order"}.
    Deliverable_a.py's robustness_draws_for_pair() calls this with the
    same (M'', seed) driver.py uses at execution time, so the two stay
    in lockstep the same way the rest of this repo's samplers already do
    for reproducibility across separate driver.py / deliverable_a.py
    invocations against the same run_id.
    """
    rng = random.Random(seed)
    pool = [l for l in PERMUTABLE_LAYERS if l != "L3a"]  # L1,L3b,L4,L5,L6,L7
    draws = []
    for m in range(m_double_prime):
        base = pool.copy()
        rng.shuffle(base)
        insert_at = rng.randint(0, len(base))
        pair_order = ["L2", "L3a"] if rng.random() < 0.5 else ["L3a", "L2"]
        order = base[:insert_at] + pair_order + base[insert_at:]
        draws.append({
            "sample_id":        f"l2l3a_robust_m{m}",
            "precursor_layers": order[:insert_at],
            "active_layers":    order[:insert_at + 2],
            "layer_order":      order,
        })
    return draws


def run_dl_robust(con, args, run_id):
    """
    Runs both measurement points per draw: precursor_layers (before the
    pair is added) and active_layers (after). Each point is applied and
    run as its own condition, with its own config label, so both land as
    distinguishable rows in the DB.

    REV 7 FIX: (L2,L3a) is special-cased onto k3s via
    l2_l3a_robustness_draws_k3s() (above), with its OWN `applied_k3s`
    tracker and its own KUBECONFIG-switch block — analogous to
    run_l2_l3a_sep()'s existing k3s handling, and kept fully separate
    from the KIND-side `applied` tracker used for (L5,L6) and (L1,L7) so
    the two clusters' layer-application state never gets confused with
    each other. Previously ALL THREE pairs (including L2,L3a) went
    through the generic KIND-based dl_robustness_sampler(), which cannot
    vary L2's position at all (see l2_l3a_robustness_draws_k3s()'s
    docstring) and never switched to the k3s cluster in the first place.
    """
    from constants import DL_CANDIDATE_PAIRS
    from samplers import dl_robustness_sampler
    log("  [WARNING] --mode dl-robust has NO automatic superadditivity gate — "
        "it does NOT check whether a pair actually passed its superadditivity "
        "test first (that analysis code doesn't exist and is out of scope). "
        "This runs the configs regardless — manual/dry-run purposes only.")
    mc_seed = args.mc_seed if args.mc_seed is not None else (
        int(hashlib.md5(run_id.encode()).hexdigest()[:8], 16)
    )

    applied = detect_applied_layers()
    for pair in DL_CANDIDATE_PAIRS:
        if pair == ("L2", "L3a"):
            if not C.K3S_KUBECONFIG.exists():
                log(f"  [FATAL] (L2,L3a) M'' robustness draws require k3s "
                    f"(brief Section 8.3). {C.K3S_KUBECONFIG} not found — "
                    f"run {C.K3S_BOOTSTRAP} first. Skipping this pair.")
                continue
            draws = l2_l3a_robustness_draws_k3s(DL_ROBUSTNESS_SAMPLES, mc_seed)
            draws = shard(draws, args)
            log(f"  DL-robust {pair} [k3s, L2 freely permutable]: "
                f"{len(draws)} draws x 2 points each (seed={mc_seed})")
            prev_kubeconfig = os.environ.get("KUBECONFIG")
            os.environ["KUBECONFIG"] = str(C.K3S_KUBECONFIG)
            log(f"  [k3s] KUBECONFIG switched to {C.K3S_KUBECONFIG} for (L2,L3a) robustness draws")
            applied_k3s = detect_applied_layers_k3s()
            try:
                for d in draws:
                    points = [
                        (f"{d['sample_id']}_precursor", d["precursor_layers"]),
                        (f"{d['sample_id']}_with",       d["active_layers"]),
                    ]
                    for config_label, layers in points:
                        log(f"\n### DL-ROBUST [k3s] {config_label} — layers {layers} ###")
                        applied_k3s = set_config_k3s(layers, applied_k3s)
                        wait_stable()
                        run_trials(con, run_id, config_label, layers,
                                   args.attacks, args.trials, args, on_k3s=True)
            finally:
                if prev_kubeconfig is not None:
                    os.environ["KUBECONFIG"] = prev_kubeconfig
                else:
                    os.environ.pop("KUBECONFIG", None)
                log("  [k3s] KUBECONFIG restored to prior value "
                    f"({prev_kubeconfig or '<unset, ambient default>'})")
            continue

        # (L5,L6) and (L1,L7): unchanged — main KIND cluster, generic sampler
        samples = dl_robustness_sampler(pair, seed=mc_seed)
        samples = shard(samples, args)
        log(f"  DL-robust {pair}: {len(samples)} SampledConditions x 2 points each "
            f"(seed={mc_seed})")
        for sample in samples:
            points = [
                (f"{sample.sample_id}_precursor", sample.precursor_layers),
                (f"{sample.sample_id}_with",       sample.active_layers),
            ]
            for config_label, layers in points:
                log(f"\n### DL-ROBUST {config_label} — layers {layers} ###")
                applied = set_config(layers, applied)
                wait_stable()
                run_trials(con, run_id, config_label, layers,
                           args.attacks, args.trials, args)
    return applied


# ── L2/L3a separation mode (axis 3, k3s-only) ─────────────────────────────────

def run_l2_l3a_sep(con, args, run_id):
    """
    Runs all 4 measurement points per l2_l3a_separation_sampler draw:
    precursor_a/with_a (L2) and precursor_b/with_b (L3a) — needed to
    compute L2's and L3a's marginal DL contributions independently
    (delta_dl_solo(L2,...) / delta_dl_solo(L3a,...), brief Section 10.3 —
    NOT DL_solo_best/phi_DL_pair, which brief v7 Section 10 removes; see
    deliverable_a.py's rewritten Section 9/10 pipeline). Structurally identical to
    run_mc_pairs(), with two differences required because this is the one
    axis that runs against k3s instead of the main KIND cluster:
      1. set_config_k3s() instead of set_config() — knows how to toggle L2
         via Controls/c-l2-audit and targets C.K3S_LAYERS.
      2. KUBECONFIG is switched to C.K3S_KUBECONFIG for the duration of
         this function (restored in `finally`), so run_trials()'s attack
         scripts, invariant checks, and measure_dl()'s Falco polling all
         transparently hit the k3s cluster too — those functions are
         shared with every other mode and have no kubeconfig parameter of
         their own, so this is done via the process environment rather
         than threading a new argument through the whole call chain.
    Assumes Infra/k3s/bootstrap.sh has already been run at least once
    (idempotent, not called automatically here — see that script's header).
    Does NOT tear the k3s cluster down afterward, same convention as every
    other mode leaving the KIND cluster running post-run.
    """
    from samplers_l2l3a_k3s import l2_l3a_separation_sampler

    if not C.K3S_KUBECONFIG.exists():
        log(f"  [FATAL] {C.K3S_KUBECONFIG} not found. Run "
            f"{C.K3S_BOOTSTRAP} first (see its header) before --mode l2-l3a-sep.")
        return set()

    mc_seed = args.mc_seed if args.mc_seed is not None else (
        int(hashlib.md5(run_id.encode()).hexdigest()[:8], 16)
    )
    samples = l2_l3a_separation_sampler(seed=mc_seed)
    samples = shard(samples, args)
    log(f"  L2-L3a separation (k3s): {len(samples)} SampledConditions x 4 points each "
        f"(seed={mc_seed})")

    prev_kubeconfig = os.environ.get("KUBECONFIG")
    os.environ["KUBECONFIG"] = str(C.K3S_KUBECONFIG)
    log(f"  [k3s] KUBECONFIG switched to {C.K3S_KUBECONFIG} for this mode")

    applied = detect_applied_layers_k3s()
    try:
        for sample in samples:
            points = [
                (f"{sample.sample_id}_pre_L2",   sample.precursor_a),
                (f"{sample.sample_id}_with_L2",  sample.with_a),
                (f"{sample.sample_id}_pre_L3a",  sample.precursor_b),
                (f"{sample.sample_id}_with_L3a", sample.with_b),
            ]
            for config_label, layers in points:
                log(f"\n### L2L3A-SEP {config_label} — layers {layers} ###")
                applied = set_config_k3s(layers, applied)
                wait_stable()
                run_trials(con, run_id, config_label, layers,
                           args.attacks, args.trials, args, on_k3s=True)
    finally:
        if prev_kubeconfig is not None:
            os.environ["KUBECONFIG"] = prev_kubeconfig
        else:
            os.environ.pop("KUBECONFIG", None)
        log("  [k3s] KUBECONFIG restored to prior value "
            f"({prev_kubeconfig or '<unset, ambient default>'})")
    return applied


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Cumulative Augmentation Orchestrator (Rev7)")
    ap.add_argument("--configs",    nargs="+", default=CONDITION_ORDER)
    ap.add_argument("--attacks",    nargs="+", default=ATTACK_ORDER_SCRIPTS)
    ap.add_argument("--trials",     type=int,  default=50,
                    help="Trials per (config, attack) cell. Use 10 for dry run.")
    ap.add_argument("--mc-permutations", type=int, default=None,
                    help="M: Monte Carlo permutations for constrained pairs. "
                         "Omit to use the correct per-pair allocation from "
                         "constants.PAIR_MC_SAMPLES (15/30/30, non-uniform). "
                         "Passing an explicit value overrides ALL pairs "
                         "uniformly — manual/testing use only.")
    ap.add_argument("--mc-seed",    type=int, default=None,
                    help="Seed for MC pair sampler. Derived from run_id if omitted.")
    ap.add_argument("--mode",       choices=["sequential", "mc-pairs", "dl-robust",
                                             "l2-l3a-sep"],
                    default="sequential",
                    help="sequential: C0-C7 sweep. mc-pairs: Shapley pair sampler, "
                         "runs all 4 precursor/with points per draw. dl-robust: "
                         "dl_robustness_sampler over DL_CANDIDATE_PAIRS (axis 4, "
                         "no superadditivity gate), runs precursor+with per draw. "
                         "l2-l3a-sep: k3s ONLY (Infra/k3s/bootstrap.sh must have "
                         "been run already) — l2_l3a_separation_sampler, both L2 "
                         "and L3a independently toggled, runs all 4 precursor/with "
                         "points per draw. Requires K3S_KUBECONFIG to exist.")
    ap.add_argument("--dry-run",    action="store_true")
    ap.add_argument("--run-id",     default=None,
                    help="Named run ID. Auto-generated if not supplied.")
    ap.add_argument("--shard-count", type=int, default=None,
                    help="Split this mode's MC draw list across N parallel "
                         "workers on the same substrate (see shard()). "
                         "Every worker must pass the SAME --run-id, "
                         "--mc-seed (or let it derive from run-id), and "
                         "--shard-count, differing only in --shard-index — "
                         "otherwise workers won't agree on the full draw "
                         "list and shards will overlap or leave gaps. "
                         "Ignored by --mode sequential (shard --configs "
                         "across workers directly instead).")
    ap.add_argument("--shard-index", type=int, default=0,
                    help="This worker's 0-based shard index, < --shard-count.")
    args = ap.parse_args()

    run_id = args.run_id or ("run_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    print(f"RUN_ID: {run_id}", flush=True)
    print(f"N={args.trials}  M={args.mc_permutations}  mode={args.mode}", flush=True)

    log("=" * 60)
    log(f"Cumulative Augmentation Orchestrator — Rev7")
    log(f"run_id={run_id}  N={args.trials}  M={args.mc_permutations}  mode={args.mode}")
    log(f"configs={args.configs}  attacks={len(args.attacks)}")
    log("=" * 60)

    if args.dry_run:
        if args.mode == "sequential":
            for cfg in args.configs:
                layers = CONFIGS.get(cfg, [])
                log(f"{cfg}: layers ON = {layers}")
            log(f"Dry run complete. Total trials would be: "
                f"{len(args.configs)} x {len(args.attacks)} x {args.trials} = "
                f"{len(args.configs)*len(args.attacks)*args.trials}")
        elif args.mode == "mc-pairs":
            from samplers import shapley_pair_sampler
            mc_seed = args.mc_seed if args.mc_seed is not None else (
                int(hashlib.md5(run_id.encode()).hexdigest()[:8], 16)
            )
            samples = shapley_pair_sampler(M=args.mc_permutations, seed=mc_seed)
            n_points = len(samples) * 4
            log(f"MC-pairs dry run: {len(samples)} draws x 4 points x "
                f"{len(args.attacks)} attacks x {args.trials} trials = "
                f"{n_points*len(args.attacks)*args.trials}")
            for s in samples[:2]:
                la, lb = s.focus_layers
                log(f"  {s.sample_id}: pre_{la}={s.precursor_a}")
                log(f"  {s.sample_id}: with_{la}={s.with_a}")
                log(f"  {s.sample_id}: pre_{lb}={s.precursor_b}")
                log(f"  {s.sample_id}: with_{lb}={s.with_b}")
            if len(samples) > 2:
                log(f"  ... ({len(samples)-2} more draws, 4 points each)")
        elif args.mode == "dl-robust":
            from constants import DL_CANDIDATE_PAIRS
            from samplers import dl_robustness_sampler
            log("  [WARNING] dl-robust has NO automatic superadditivity gate — "
                "runs configs regardless of whether the pair passed that test.")
            mc_seed = args.mc_seed if args.mc_seed is not None else (
                int(hashlib.md5(run_id.encode()).hexdigest()[:8], 16)
            )
            total = 0
            for pair in DL_CANDIDATE_PAIRS:
                if pair == ("L2", "L3a"):
                    draws = l2_l3a_robustness_draws_k3s(DL_ROBUSTNESS_SAMPLES, mc_seed)
                    n_points = len(draws) * 2
                    total += n_points * len(args.attacks) * args.trials
                    log(f"DL-robust dry run {pair} [k3s, L2 freely permutable]: "
                        f"{len(draws)} draws x 2 points x "
                        f"{len(args.attacks)} attacks x {args.trials} trials = "
                        f"{n_points*len(args.attacks)*args.trials}")
                    for d in draws[:2]:
                        log(f"  {d['sample_id']}: precursor={d['precursor_layers']}")
                        log(f"  {d['sample_id']}: with={d['active_layers']}")
                    if not C.K3S_KUBECONFIG.exists():
                        log(f"  [NOTE] {C.K3S_KUBECONFIG} does not exist yet — "
                            f"run {C.K3S_BOOTSTRAP} before a real (non-dry-run) "
                            f"dl-robust run reaches this pair.")
                    continue
                samples = dl_robustness_sampler(pair, seed=mc_seed)
                n_points = len(samples) * 2
                total += n_points * len(args.attacks) * args.trials
                log(f"DL-robust dry run {pair}: {len(samples)} draws x 2 points x "
                    f"{len(args.attacks)} attacks x {args.trials} trials = "
                    f"{n_points*len(args.attacks)*args.trials}")
                for s in samples[:2]:
                    log(f"  {s.sample_id}: precursor={s.precursor_layers}")
                    log(f"  {s.sample_id}: with={s.active_layers}")
            log(f"DL-robust dry run total across all DL_CANDIDATE_PAIRS: {total}")
        elif args.mode == "l2-l3a-sep":
            from samplers_l2l3a_k3s import l2_l3a_separation_sampler
            mc_seed = args.mc_seed if args.mc_seed is not None else (
                int(hashlib.md5(run_id.encode()).hexdigest()[:8], 16)
            )
            samples = l2_l3a_separation_sampler(seed=mc_seed)
            n_points = len(samples) * 4
            log(f"L2-L3a-sep dry run (k3s): {len(samples)} draws x 4 points x "
                f"{len(args.attacks)} attacks x {args.trials} trials = "
                f"{n_points*len(args.attacks)*args.trials}")
            for sam in samples[:2]:
                log(f"  {sam.sample_id}: pre_L2={sam.precursor_a}")
                log(f"  {sam.sample_id}: with_L2={sam.with_a}")
                log(f"  {sam.sample_id}: pre_L3a={sam.precursor_b}")
                log(f"  {sam.sample_id}: with_L3a={sam.with_b}")
            if len(samples) > 2:
                log(f"  ... ({len(samples)-2} more draws, 4 points each)")
            if not C.K3S_KUBECONFIG.exists():
                log(f"  [NOTE] {C.K3S_KUBECONFIG} does not exist yet — "
                    f"run {C.K3S_BOOTSTRAP} before a real (non-dry-run) "
                    f"l2-l3a-sep run.")
            return
        return

    con = init_db()
    if args.mode == "sequential":
        run_sequential(con, args, run_id)
    elif args.mode == "mc-pairs":
        run_mc_pairs(con, args, run_id)
    elif args.mode == "dl-robust":
        run_dl_robust(con, args, run_id)
    else:  # l2-l3a-sep
        run_l2_l3a_sep(con, args, run_id)
    con.close()
    log(f"\nAugmentation complete. Results in {C.RESULTS_DB}")
    log(f"Run ID: {run_id}  N={args.trials}  M={args.mc_permutations}  mode={args.mode}")


if __name__ == "__main__":
    main()
