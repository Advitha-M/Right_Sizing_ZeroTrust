"""
Driver/config.py — paths and per-layer control wiring for driver.py.

BONUS FILE — this was missing from the uploaded repo. driver.py does
`import config as C` and references C.LOGS_DIR, C.RESULTS_DB, C.LAYERS,
C.apply_script()/C.remove_script(), C.ATTACKS_DIR, C.CLEANUP_DIR,
C.DL_TIMEOUT, C.ATTACK_TIMEOUT, C.BASE_SEED — without this module driver.py
fails on import before anything else in the pipeline can run. Written to
match the actual repo layout (Attacks/, Controls/c1-l1..c7-vault, Driver/,
harness/).

CORRECTED (brief v7 Section 10.1): DL_TIMEOUT was 300s, disagreeing with
the brief's fixed, uniform 90-second non-detection cutoff
("dl(t,k,j) = infinity if no alert fires within 90 seconds of trial
start... a fixed 90-second wall-clock cutoff, uniform across all 7 attack
classes -- not class-specific and not tied to each trial's own execution
time"). harness/Harness/config.env still defaults to DL_TIMEOUT=300 and
was NOT part of this rewrite's requested scope (config.py, driver.py,
deliverable_a.py only) -- update it to 90 too before relying on it for a
real run; a bare `python3 Driver/driver.py` invocation is unaffected
since it reads this module's default, not that file's.

Values NOT hardcoded elsewhere in constants.py live here on purpose —
constants.py is explicit that it holds shared *vocabulary* (conditions,
tenants, techniques), not filesystem layout.
"""
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

ATTACKS_DIR  = REPO_ROOT / "Attacks"
CONTROLS_DIR = REPO_ROOT / "Controls"
LOGS_DIR     = REPO_ROOT / "logs"
RESULTS_DB   = Path(os.environ.get("ZT_RESULTS_DB",
                                    str(REPO_ROOT / "results" / "results.db")))

# CLEANUP_DIR / reset_trial.sh does not exist in this repo — driver.py's
# reset_state() already falls back to inline kubectl cleanup commands when
# this path is absent, so this is left pointing at a directory that may not
# exist rather than invented to hide that gap.
CLEANUP_DIR = REPO_ROOT / "cleanup"

# ── Per-layer control wiring ──────────────────────────────────────────────
# (layer_id, human label, control directory name) — order matches the
# canonical build order L1->L7 from constants.CANONICAL_ORDER (minus the
# base layer L2, which is never applied/removed via a script on the main
# KIND cluster — see infra/audit/audit-policy.yaml). set_config() in
# driver.py applies in this order and removes in reverse, so ordering here
# IS the apply/remove order, not just documentation.
# EXCEPTION: K3S_LAYERS below (LAYERS + an L2 entry) is used by the k3s-only
# (L2,L3a) separation sampler, where L2 IS live-toggled — see
# Controls/c-l2-audit/apply.sh.
LAYERS = [
    ("L1",  "Cloud & infra (etcd encryption + digest-pin)", "c1-l1"),
    ("L3a", "RBAC",                                          "c2-rbac"),
    ("L3b", "OPA Gatekeeper admission",                       "c3-opa"),
    ("L4",  "Tenant isolation",                               "c4-tenant-isolation"),
    ("L5",  "NetworkPolicy",                                  "c5-networkpolicy"),
    ("L6",  "Istio mTLS",                                     "c6-istio"),
    ("L7",  "Vault dynamic secrets",                          "c7-vault"),
]

_DIR_FOR_LAYER = {lid: d for lid, _name, d in LAYERS}


def apply_script(layer_id: str) -> Path:
    return CONTROLS_DIR / _DIR_FOR_LAYER[layer_id] / "apply.sh"


def remove_script(layer_id: str) -> Path:
    return CONTROLS_DIR / _DIR_FOR_LAYER[layer_id] / "remove.sh"


# ── k3s (L2,L3a) separation sampler wiring ────────────────────────────────
# Scoped entirely to Driver.driver.run_l2_l3a_sep() / samplers_l2l3a_k3s.py.
# Everywhere else in this file/driver.py, LAYERS and set_config() target the
# main KIND cluster's default kubeconfig context and never touch L2. See
# Controls/c-l2-audit/apply.sh's header for why L2 can only be genuinely
# toggled on k3s.
K3S_DIR        = REPO_ROOT / "Infra" / "k3s"
K3S_BOOTSTRAP  = K3S_DIR / "bootstrap.sh"
K3S_TEARDOWN   = K3S_DIR / "teardown.sh"
# Populated by bootstrap.sh (copies the instance's k3s.yaml here). Override
# via ZT_K3S_KUBECONFIG so parallel workers on one VM each point at their
# own native k3s instance (see bootstrap.sh's K3S_INSTANCE) instead of all
# sharing this one hardcoded path.
K3S_KUBECONFIG = Path(os.environ.get("ZT_K3S_KUBECONFIG", str(K3S_DIR / "k3s.yaml")))

# L2 + the existing 7 LAYERS, in canonical build order — used ONLY by
# set_config_k3s(). The main set_config() keeps using LAYERS (no L2 entry)
# unchanged for every other mode.
K3S_LAYERS = [("L2", "Cluster access control (audit logging)", "c-l2-audit")] + LAYERS

_K3S_DIR_FOR_LAYER = {lid: d for lid, _name, d in K3S_LAYERS}


def apply_script_k3s(layer_id: str) -> Path:
    return CONTROLS_DIR / _K3S_DIR_FOR_LAYER[layer_id] / "apply.sh"


def remove_script_k3s(layer_id: str) -> Path:
    return CONTROLS_DIR / _K3S_DIR_FOR_LAYER[layer_id] / "remove.sh"


# ── Timing / seed defaults ────────────────────────────────────────────────
# Mirrors harness/config.env's ":${VAR:=...}" defaults so a bare
# `python3 Driver/driver.py` run and a harness/run_attacks.sh run agree
# unless the caller overrides via environment.

BASE_SEED      = int(os.environ.get("BASE_SEED", 42))
# Brief v7 Section 10.1: "dl(t,k,j) = infinity if no alert fires within 90
# seconds of trial start... fixed... uniform across all 7 attack classes."
# CORRECTED from 300 -- 300 both disagreed with the brief's fixed value
# and (via driver.measure_dl()'s deadline calc) was being silently
# overridden down to an undocumented 30s anyway. Now the single source of
# truth for the poll deadline; see measure_dl()'s docstring in driver.py.
DL_TIMEOUT     = int(os.environ.get("DL_TIMEOUT", 90))
ATTACK_TIMEOUT = int(os.environ.get("ATTACK_TIMEOUT", 90))
