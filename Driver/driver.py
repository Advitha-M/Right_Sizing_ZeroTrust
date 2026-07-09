#!/usr/bin/env python3
"""
driver.py — Cumulative Augmentation Orchestrator (Rev5)

Changes from previous version:
  - Seed scheme: hash(attack + trial) only — config dropped for McNemar validity
  - Per-class ATTACKER_NS routing sourced entirely from constants.ATTACKER_NS_MAP
    (v6-corrected: A1/A2/A5/A6 -> tenant-lowpriv, A3/A4 -> tenant-partner,
    A7 -> tenant-finserv [insider/already-present principal, origin==target,
    corrected from tenant-lowpriv this revision]). Tenant namespaces are the
    four names in constants.TENANTS (tenant-lowpriv, tenant-finserv,
    tenant-partner, tenant-saas) — NOT the old acme/globex/initech/umbrella
    naming from earlier revisions.
  - technique_token recorded as first-class DB column
  - t_start persisted in DB
  - N (--trials) and M (--mc-permutations) are CLI args for dry-run flexibility
  - Pre-condition invariant checks (structural gate before first trial per config)
  - DB schema v3: adds t_end, t_alert, alert_source, exit_code, error_type,
    target_tenant, pivot_path columns; measure_dl() returns (t_alert, source, dl)
  - --mode {sequential, mc-pairs}: mc-pairs wires shapley_pair_sampler
  - joint-config mode REMOVED (joint_config_constructor dropped from
    samplers.py; author-confirmed, not needed for this study)
  - l2-l3a-sep mode IMPLEMENTED against k3s: samplers_l2l3a_k3s.py's
    l2_l3a_separation_sampler() treats L2 as genuinely toggleable (unlike
    everywhere else in this repo, where L2 = BASE_LAYER, fixed), via the
    new Controls/c-l2-audit control and set_config_k3s()/C.K3S_KUBECONFIG.
    Requires Infra/k3s/bootstrap.sh to have been run first.
  - mc-pairs and dl-robust now run BOTH precursor and with-pair points
    per draw (mc-pairs: 4 points — precursor/with x La/Lb; dl-robust:
    2 points — precursor/with for the joint pair), each as its own
    labeled condition, matching samplers.py's precursor/with model

Usage:
    python3 driver/driver.py                          # full run C0-C7, N=50
    python3 driver/driver.py --trials 10              # dry run, low N
    python3 driver/driver.py --configs C0 C1          # subset of conditions
    python3 driver/driver.py --dry-run                # print plan only
    python3 driver/driver.py --run-id run_debug_01    # named run
    python3 driver/driver.py --mode mc-pairs --mc-permutations 2 --trials 5
"""
import argparse
import hashlib
import os
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
    TENANTS,
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


def init_db():
    C.RESULTS_DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(C.RESULTS_DB)
    con.executescript(SCHEMA)
    con.commit()
    # Forward-migrate existing schemas — safe no-op if columns already exist
    for col, typ in _V3_COLS:
        try:
            con.execute(f"ALTER TABLE trials ADD COLUMN {col} {typ}")
            con.commit()
        except sqlite3.OperationalError:
            pass
    return con


def record(con, run_id, config, attack, trial, seed, technique_token,
           verdict, t_start, t_end, t_alert, alert_source, dl,
           exit_code, error_type, target_tenant, pivot_path):
    doc_class = SCRIPT_TO_DOC[attack]
    con.execute(
        """INSERT INTO trials
           (run_id,config,attack,doc_class,trial,seed,technique_token,
            outcome,success,chain_depth,detail,
            t_start,t_end,t_alert,alert_source,dl_sec,
            exit_code,error_type,target_tenant,pivot_path)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (run_id, config, attack, doc_class, trial, seed, technique_token,
         verdict.outcome, verdict.success_bit,
         verdict.chain_depth, verdict.detail,
         t_start, t_end, t_alert, alert_source, dl,
         exit_code, error_type, target_tenant, pivot_path),
    )
    con.commit()


# ── Seed scheme ───────────────────────────────────────────────────────────────
# CRITICAL: config is NOT included in the hash.
# Trial t of attack j gets the same seed regardless of condition,
# making technique draws identical across conditions — required for McNemar.

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
    import random
    doc_id = SCRIPT_TO_DOC[attack]
    techniques = TECHNIQUE_SETS[doc_id]
    rng = random.Random(seed)
    idx = rng.randrange(len(techniques))
    return techniques[idx], idx


# ── Invariant checks ──────────────────────────────────────────────────────────

def check_nodes_ready() -> bool:
    rc, out, _ = run("kubectl get nodes --no-headers 2>/dev/null", timeout=15)
    if rc != 0:
        log("  [INVARIANT FAIL] kubectl get nodes failed")
        return False
    lines = [l for l in out.strip().splitlines() if l.strip()]
    not_ready = [l for l in lines if "NotReady" in l or "Ready" not in l]
    if not_ready:
        log(f"  [INVARIANT FAIL] {len(not_ready)} nodes not Ready: {not_ready[:2]}")
        return False
    log(f"  [INVARIANT OK] {len(lines)} nodes Ready")
    return True


def check_tenant_namespaces() -> bool:
    for ns in TENANT_NAMESPACES:
        rc, out, _ = run(
            f"kubectl get pods -n {ns} --field-selector=status.phase=Running "
            f"--no-headers 2>/dev/null", timeout=10
        )
        if rc != 0 or not out.strip():
            log(f"  [INVARIANT FAIL] No Running pods in namespace {ns}")
            return False
    log("  [INVARIANT OK] All tenant namespaces have Running pods")
    return True


def check_finserv_credentials() -> bool:
    """
    Pre-L7 static credential check. VICTIM_NS (tenant-finserv) holds a static
    mock PII/transaction secret until L7 (Vault dynamic secrets) is active,
    at which point the static secret is removed in favor of short-lived
    Vault-issued credentials. Renamed from the Rev5 check_globex_credentials()
    — 'globex' no longer exists as a namespace in the v6 tenant model.
    """
    rc, _, _ = run(
        f"kubectl get secret finserv-static-credentials -n {VICTIM_NS} 2>/dev/null",
        timeout=10,
    )
    if rc != 0:
        log(f"  [INVARIANT FAIL] finserv-static-credentials secret missing in {VICTIM_NS}")
        return False
    log("  [INVARIANT OK] finserv-static-credentials present")
    return True


def run_invariant_checks(config: str, active_layers: list | None = None) -> bool:
    """
    Tier 1+2 gate: run before any trials for this condition.
    active_layers: for MC mode, pass the sample's layer list; for sequential
    mode leave None and config label is used to decide credential check.
    Returns False → HALT this condition, do not run trials.
    """
    log(f"  [INVARIANTS] Checking pre-trial invariants for {config}...")
    ok = True
    ok = check_nodes_ready() and ok
    ok = check_tenant_namespaces() and ok
    # Credentials check: skip only when L7 (Vault) is active, which removes
    # the static secret. In sequential mode infer from config label; in MC
    # mode use active_layers directly.
    if active_layers is not None:
        needs_cred_check = "L7" not in active_layers
    else:
        # CORRECTED (v6): L7/Vault now activates at C7, not C6, under the
        # 8-condition primary build (L2 base + 7 single-layer steps).
        needs_cred_check = config in ("C0", "C1", "C2", "C3", "C4", "C5", "C6")
    if needs_cred_check:
        ok = check_finserv_credentials() and ok
    if not ok:
        log(f"  [INVARIANTS] FAILED for {config} — skipping all trials in this condition")
    else:
        log(f"  [INVARIANTS] All checks passed for {config}")
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
    Polls Falco logs, and now also SPIRE agent/server logs, for a detection
    event. Returns (t_alert, alert_source, dl_sec); t_alert and alert_source
    are None when no detection fires within DL_TIMEOUT.

    SPIRE polling added so the (L1,L7) DL candidate pair's "identity-forgery
    attempt" shared detection event (constants.DL_CANDIDATE_PAIRS) has a real
    L7-side signal: attempted attestation with mismatched/unregistered
    selectors, or a rejected SVID, both produce a log line matching the
    patterns below on the spire-agent DaemonSet or spire-server StatefulSet.
    Falco is still checked first each iteration (unchanged priority/behavior
    for every other attack class); SPIRE is an additional independent check,
    not a replacement.
    """
    deadline = t_start + min(C.DL_TIMEOUT, 30)
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

        time.sleep(2)
    return None, None, None


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
               attacks, n_trials, args):
    """
    Runs n_trials for each attack in attacks under the given config.
    config_label is stored in the DB 'config' column verbatim.
    active_layers used only for the credentials invariant check.
    """
    if not run_invariant_checks(config_label, active_layers):
        log(f"  HALTING config {config_label} due to invariant failure")
        return

    for attack in attacks:
        script = C.ATTACKS_DIR / f"{attack}.sh"
        if not script.exists():
            log(f"  MISSING {script}, skip")
            continue

        doc_id  = SCRIPT_TO_DOC[attack]
        atk_ns  = ATTACKER_NS_MAP[doc_id]
        n_succ  = 0

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

        for trial in range(1, n_trials + 1):
            seed               = make_seed(attack, trial)
            technique, tech_idx = draw_technique(attack, seed)
            reset_state()
            t_start = time.time()

            rc, out, to = run(
                f"bash {script}",
                timeout=C.ATTACK_TIMEOUT,
                env={**env_base, "SEED": str(seed), "TECHNIQUE_IDX": str(tech_idx)},
            )
            t_end   = time.time()
            verdict = classify(out, rc, to)
            t_alert, alert_source, dl = measure_dl(attack, t_start)
            error_type = classify_error(verdict, rc, to)

            record(con, run_id, config_label, attack, trial, seed,
                   technique, verdict,
                   t_start, t_end, t_alert, alert_source, dl,
                   rc, error_type, target_tenant, pivot_path)
            n_succ += verdict.success_bit

            if trial == 1 or trial % 10 == 0:
                log(f"  {config_label}/{attack}({doc_id}) trial {trial}/{n_trials} "
                    f"tech={technique} → {verdict.outcome} (dl={dl})")

        asr = n_succ / n_trials
        log(f"  {config_label}/{attack}({doc_id}): ASR={asr:.3f} ({n_succ}/{n_trials})")


# ── Sequential mode ───────────────────────────────────────────────────────────

def run_sequential(con, args, run_id):
    applied = set()
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
    log(f"  MC-pairs: {len(samples)} SampledConditions x 4 points each "
        f"(M={args.mc_permutations}, seed={mc_seed})")

    applied = set()
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

def run_dl_robust(con, args, run_id):
    """
    Runs both measurement points per dl_robustness_sampler draw:
    precursor_layers (before the pair is added) and active_layers (after).
    Each point is applied and run as its own condition, with its own
    config label, so both land as distinguishable rows in the DB.
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

    applied = set()
    for pair in DL_CANDIDATE_PAIRS:
        samples = dl_robustness_sampler(pair, seed=mc_seed)
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
    (DL_solo_best, brief Section 10.2). Structurally identical to
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
    log(f"  L2-L3a separation (k3s): {len(samples)} SampledConditions x 4 points each "
        f"(seed={mc_seed})")

    prev_kubeconfig = os.environ.get("KUBECONFIG")
    os.environ["KUBECONFIG"] = str(C.K3S_KUBECONFIG)
    log(f"  [k3s] KUBECONFIG switched to {C.K3S_KUBECONFIG} for this mode")

    applied = set()
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
                           args.attacks, args.trials, args)
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
    ap = argparse.ArgumentParser(description="Cumulative Augmentation Orchestrator (Rev5)")
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
    args = ap.parse_args()

    run_id = args.run_id or ("run_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    print(f"RUN_ID: {run_id}", flush=True)
    print(f"N={args.trials}  M={args.mc_permutations}  mode={args.mode}", flush=True)

    log("=" * 60)
    log(f"Cumulative Augmentation Orchestrator — Rev5")
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
