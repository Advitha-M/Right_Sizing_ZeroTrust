#!/usr/bin/env python3
"""
analysis_common.py -- shared plumbing for deliverable_a.py and deliverable_b.py

Lives in Driver/, alongside constants.py, samplers.py, oracle.py, driver.py.
Nothing in this file is specific to Deliverable A or B; it's the DB access,
significance-gate math, and technique/config bookkeeping both of them need,
factored out so the two deliverables don't duplicate it.

See deliverable_a.py's module docstring for the config-label resolution
strategy (regenerating sampler output from a run_id-derived seed rather than
parsing the label string) and the (L2,L3a) data-gap note.
"""

import hashlib
import math
import sqlite3

import numpy as np
from scipy import stats

from constants import (
    BASE_LAYER, PERMUTABLE_LAYERS, BASELINE_LAYERS,
    CONFIGS, CONDITION_ORDER, ATTACK_ORDER_DOCS,
    TECHNIQUE_SETS, TECHNIQUE_MIN_CONDITION,
    CONSTRAINED_PAIRS_ASR, DL_CANDIDATE_PAIRS,
    ALPHA, COHENS_H_MIN,
)

ATTACK_CLASSES = ATTACK_ORDER_DOCS  # ["A1".."A7"]

# Section 14 DL validity filter, as indices into TECHNIQUE_SETS[class] so the
# actual token strings always come from constants.py (avoids the label drift
# seen between constants.py and Attacks/attack2.sh's TECHNIQUES=()).
#   idx 0 = T1, idx 1 = T2, idx 2 = T3
DL_VALIDITY_IDX = {
    ("L5", "L6"): {"A1": [2], "A5": [1], "A7": [0]},               # A1:T3, A5:T2, A7:T1
    ("L1", "L7"): {"A2": [1], "A7": [1]},                           # A2:T2, A7:T2
    ("L2", "L3a"): {"A1": [0], "A2": [0], "A5": [0], "A3": [0]},   # all T1
}
for _pair in DL_CANDIDATE_PAIRS:
    DL_VALIDITY_IDX.setdefault(_pair, {})
    DL_VALIDITY_IDX[_pair].setdefault("A4", [0])  # single-technique classes: T1 always
    DL_VALIDITY_IDX[_pair].setdefault("A6", [0])


def dl_valid_techniques(pair, attack_class):
    idxs = DL_VALIDITY_IDX.get(pair, {}).get(attack_class, [])
    techs = TECHNIQUE_SETS.get(attack_class, [])
    return [techs[i] for i in idxs if i < len(techs)]


def pair_key(a, b):
    return f"{a}_{b}"


def mc_seed_for(run_id):
    """Exactly driver.py's run_mc_pairs/run_dl_robust seed derivation."""
    return int(hashlib.md5(run_id.encode()).hexdigest()[:8], 16)


# ==============================================================================
# Database access
# ==============================================================================

def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def list_run_ids(conn):
    return [r["run_id"] for r in conn.execute("SELECT DISTINCT run_id FROM trials")]


def resolve_run_id(conn, run_id_arg):
    if run_id_arg is not None:
        return run_id_arg
    ids = list_run_ids(conn)
    if len(ids) == 1:
        return ids[0]
    if not ids:
        raise SystemExit("No rows in trials table.")
    raise SystemExit(f"Multiple run_ids present ({ids}); pass --run-id to select one.")


def load_rows(conn, config, doc_class, technique=None, run_id=None):
    """Rows for one (config, doc_class[, technique]), ordered by trial number
    (the pairing key: make_seed(attack, trial) is config-independent, so
    trial #N always draws the same technique across every condition/sample)."""
    q = "SELECT * FROM trials WHERE config=? AND doc_class=?"
    params = [config, doc_class]
    if technique is not None:
        q += " AND technique_token=?"
        params.append(technique)
    if run_id is not None:
        q += " AND run_id=?"
        params.append(run_id)
    q += " ORDER BY trial"
    return conn.execute(q, params).fetchall()


def is_detected(row):
    return row["dl_sec"] is not None or row["t_alert"] is not None


def latency(row):
    if row["dl_sec"] is not None:
        return row["dl_sec"]
    if row["t_alert"] is not None and row["t_start"] is not None:
        return row["t_alert"] - row["t_start"]
    return None


TECHNIQUE_MIN_LAYER = {
    key: (CONFIGS[cond][-1] if CONFIGS[cond] else BASE_LAYER)
    for key, cond in TECHNIQUE_MIN_CONDITION.items()
}  # e.g. ("A7","t2-vault-sa-token-exfil") -> "L7"


def _excluded_by_min_condition(row, config):
    key = (row["doc_class"], row["technique_token"])
    if key not in TECHNIQUE_MIN_CONDITION:
        return False
    min_cond = TECHNIQUE_MIN_CONDITION[key]
    if config not in CONDITION_ORDER:
        return None  # caller resolves via active-layers check instead
    return CONDITION_ORDER.index(config) < CONDITION_ORDER.index(min_cond)


def filter_rows(rows, config, active_layers=None):
    """Apply the TECHNIQUE_MIN_CONDITION exclusion (constants.py: a (class,
    technique) cell whose BLOCKED/SKIP outcome below a given condition is
    structurally expected, e.g. the Vault role doesn't exist yet -- not a
    layer-enforcement signal -- must be excluded from McNemar/Cohen's h)."""
    out = []
    for r in rows:
        key = (r["doc_class"], r["technique_token"])
        if key in TECHNIQUE_MIN_LAYER:
            required_layer = TECHNIQUE_MIN_LAYER[key]
            if config in CONDITION_ORDER:
                if _excluded_by_min_condition(r, config):
                    continue
            elif active_layers is not None and required_layer not in active_layers:
                continue
        out.append(r)
    return out


def paired_by_trial(rows_a, rows_b):
    """Align two row sets by the 'trial' column (the true pairing key)."""
    by_a = {r["trial"]: r for r in rows_a}
    by_b = {r["trial"]: r for r in rows_b}
    common = sorted(set(by_a) & set(by_b))
    return [by_a[t] for t in common], [by_b[t] for t in common]


# ==============================================================================
# Section 5 -- primary metrics
# ==============================================================================

def asr(rows):
    if not rows:
        return None
    return sum(r["success"] for r in rows) / len(rows)


def dl_median(rows, technique=None):
    filtered = [r for r in rows if is_detected(r)]
    if technique is not None:
        filtered = [r for r in filtered if r["technique_token"] == technique]
    vals = [v for v in (latency(r) for r in filtered) if v is not None]
    return float(np.median(vals)) if vals else None


def dl_nondetect(rows):
    if not rows:
        return None
    return sum(1 for r in rows if not is_detected(r)) / len(rows)


def mixture_asr(conn, config, attack_class, run_id=None, active_layers=None):
    """Section 7 mixture; Requirement #20a: zero-trial techniques count as 0,
    not omitted from the mixture denominator."""
    techs = TECHNIQUE_SETS[attack_class]
    weight = 1.0 / len(techs)
    total = 0.0
    breakdown = {}
    for t in techs:
        rows = load_rows(conn, config, attack_class, technique=t, run_id=run_id)
        rows = filter_rows(rows, config, active_layers)
        a = asr(rows) if rows else 0.0
        breakdown[t] = {"asr": a, "n": len(rows)}
        total += weight * a
    return total, breakdown


# ==============================================================================
# Section 6 -- significance gate
# ==============================================================================

def cohens_h(p1, p2):
    return 2 * math.asin(math.sqrt(p1)) - 2 * math.asin(math.sqrt(p2))


def mcnemar_exact_p(x, y):
    x, y = np.asarray(x), np.asarray(y)
    b = int(np.sum((x == 1) & (y == 0)))
    c = int(np.sum((x == 0) & (y == 1)))
    n = b + c
    if n == 0:
        return 1.0
    return stats.binomtest(min(b, c), n, 0.5, alternative="two-sided").pvalue


def rank_biserial_matched(x, y):
    x, y = np.asarray(x), np.asarray(y)
    n_plus, n_minus = int(np.sum(x > y)), int(np.sum(x < y))
    denom = n_plus + n_minus
    return (n_plus - n_minus) / denom if denom else 0.0


def wilcoxon_p(x, y):
    x, y = np.asarray(x), np.asarray(y)
    if np.all(x == y):
        return 1.0
    try:
        _, p = stats.wilcoxon(x, y, zero_method="wilcox")
    except ValueError:
        p = 1.0
    return p


def gated_delta_asr(rows_prev, rows_curr):
    """DeltaASR = ASR(prev) - ASR(curr), gated: McNemar p<0.05/7 AND
    |Cohen's h|>=0.20 (Section 6), else forced to zero. Paired by trial#."""
    p_prev, p_curr = asr(rows_prev), asr(rows_curr)
    if p_prev is None or p_curr is None:
        return {"delta": None, "significant": False, "p": None, "effect_h": None,
                "asr_prev": p_prev, "asr_curr": p_curr, "n": 0}
    pa, pb = paired_by_trial(rows_prev, rows_curr)
    if not pa:
        return {"delta": None, "significant": False, "p": None, "effect_h": None,
                "asr_prev": p_prev, "asr_curr": p_curr, "n": 0}
    x = [r["success"] for r in pa]
    y = [r["success"] for r in pb]
    p = mcnemar_exact_p(x, y)
    h = cohens_h(p_prev, p_curr)
    raw_delta = p_prev - p_curr
    significant = (p < ALPHA) and (abs(h) >= COHENS_H_MIN)
    return {"delta": raw_delta if significant else 0.0, "raw_delta": raw_delta,
            "significant": significant, "p": p, "effect_h": h,
            "asr_prev": p_prev, "asr_curr": p_curr, "n": len(pa)}


def gated_delta_dl(rows_prev, rows_curr, technique=None):
    """DeltaDL, gated: Wilcoxon p<0.05/7 AND |rank-biserial r|>=0.20."""
    dl_prev = dl_median(rows_prev, technique)
    dl_curr = dl_median(rows_curr, technique)
    if dl_prev is None or dl_curr is None:
        return {"delta": None, "significant": False, "p": None, "effect_r": None,
                "dl_prev": dl_prev, "dl_curr": dl_curr, "n": 0}
    pa, pb = paired_by_trial(
        [r for r in rows_prev if is_detected(r) and (technique is None or r["technique_token"] == technique)],
        [r for r in rows_curr if is_detected(r) and (technique is None or r["technique_token"] == technique)],
    )
    if not pa:
        return {"delta": None, "significant": False, "p": None, "effect_r": None,
                "dl_prev": dl_prev, "dl_curr": dl_curr, "n": 0}
    x = [latency(r) for r in pa]
    y = [latency(r) for r in pb]
    p = wilcoxon_p(x, y)
    r_eff = rank_biserial_matched(x, y)
    raw_delta = dl_prev - dl_curr
    significant = (p < ALPHA) and (abs(r_eff) >= COHENS_H_MIN)
    return {"delta": raw_delta if significant else 0.0, "raw_delta": raw_delta,
            "significant": significant, "p": p, "effect_r": r_eff,
            "dl_prev": dl_prev, "dl_curr": dl_curr, "n": len(pa)}
