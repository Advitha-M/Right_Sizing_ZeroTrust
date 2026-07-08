"""
Driver/config.py — paths and per-layer control wiring for driver.py.

BONUS FILE — this was missing from the uploaded repo. driver.py does
`import config as C` and references C.LOGS_DIR, C.RESULTS_DB, C.LAYERS,
C.apply_script()/C.remove_script(), C.ATTACKS_DIR, C.CLEANUP_DIR,
C.DL_TIMEOUT, C.ATTACK_TIMEOUT, C.BASE_SEED — without this module driver.py
fails on import before anything else in the pipeline can run. Written to
match the actual repo layout (Attacks/, Controls/c1-l1..c7-vault, Driver/,
harness/) and harness/config.env's defaults (N_TRIALS=50, BASE_SEED=42,
DL_TIMEOUT=300, ATTACK_TIMEOUT=90).

Values NOT hardcoded elsewhere in constants.py live here on purpose —
constants.py is explicit that it holds shared *vocabulary* (conditions,
tenants, techniques), not filesystem layout.
"""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

ATTACKS_DIR  = REPO_ROOT / "Attacks"
CONTROLS_DIR = REPO_ROOT / "Controls"
LOGS_DIR     = REPO_ROOT / "logs"
RESULTS_DB   = REPO_ROOT / "results" / "results.db"

# CLEANUP_DIR / reset_trial.sh does not exist in this repo — driver.py's
# reset_state() already falls back to inline kubectl cleanup commands when
# this path is absent, so this is left pointing at a directory that may not
# exist rather than invented to hide that gap.
CLEANUP_DIR = REPO_ROOT / "cleanup"

# ── Per-layer control wiring ──────────────────────────────────────────────
# (layer_id, human label, control directory name) — order matches the
# canonical build order L1->L7 from constants.CANONICAL_ORDER (minus the
# base layer L2, which is never applied/removed via a script — see
# infra/audit/audit-policy.yaml). set_config() in driver.py applies in this
# order and removes in reverse, so ordering here IS the apply/remove order,
# not just documentation.
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


# ── Timing / seed defaults ────────────────────────────────────────────────
# Mirrors harness/config.env's ":${VAR:=...}" defaults so a bare
# `python3 Driver/driver.py` run and a harness/run_attacks.sh run agree
# unless the caller overrides via environment.
import os

BASE_SEED      = int(os.environ.get("BASE_SEED", 42))
DL_TIMEOUT     = int(os.environ.get("DL_TIMEOUT", 300))
ATTACK_TIMEOUT = int(os.environ.get("ATTACK_TIMEOUT", 90))
