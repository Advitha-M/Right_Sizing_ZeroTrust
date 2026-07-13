#!/usr/bin/env python3
"""
deliverable_a.py -- Deliverable A: the augmentation study measurement pipeline

Lives in Driver/, alongside constants.py, samplers.py, oracle.py, driver.py,
analysis_common.py. Reads the "trials" table driver.py writes to results.db
and produces absolute marginal security contribution estimates per layer, on
both an ASR and detection-latency axis:

  Section 5    Primary metrics:         ASR(k,j), DL_median(k,j,T), DL_nondetect(k,j)
  Section 6    Marginal deltas + gate:  McNemar+Cohen's h (ASR), Wilcoxon+rank-biserial r
                                         (DL), Bonferroni/7, |effect|>=0.20
  Section 7    Technique mixture:       uniform mixture over each class's technique set
  Section 8    Shapley correction:      (L3a,L3b), (L5,L6), (L1,L7)
  Sections 9/10 DL pipeline:            delta_dl_solo(La/Lb,j,T), delta_dl_joint(La,Lb,j,T),
                                         one-sample Wilcoxon superadditivity test (MAX
                                         comparator, delta space)

Does NOT touch risk tolerance or stack selection -- that's deliverable_b.py,
which consumes this script's --out JSON as its primary input. Per the brief:
"Build A completely before starting B."

-------------------------------------------------------------------------
REV 7 REWRITE OF SECTIONS 9/10
-------------------------------------------------------------------------
The previous version of this pipeline computed DL_solo_best (MIN of two
solo DL_medians) and phi_dl_pair, and gated superadditivity on
`dl_joint < solo_best` via a two-sample paired Wilcoxon test between raw
joint-condition trials and precursor ("without") trials. Brief v7 Section
10 is explicit: "REMOVED IN REV 7: DL_solo_best, dl_joint_T, and
phi_DL_pair are removed from the study entirely... REPLACED BY:
delta_dl_solo(La,j,T) / delta_dl_solo(Lb,j,T) and
delta_dl_joint(La,Lb,j,T)." It also corrects the comparator from MIN to
MAX and the test from a two-sample paired comparison to a one-sample
Wilcoxon of diff(m) = delta_dl_joint(m) - MAX(delta_dl_solo(La),
delta_dl_solo(Lb)) against zero, over the M''=15 robustness draws
themselves (Section 10.6). Section 10.4 additionally requires each
before/with scalar pair (one pair per M/M'/M'' draw) to be categorized
before it can feed a delta mean: both sides finite ("delta", the only
category that feeds a mean), before=inf/with=finite ("enabled",
qualitative only), before=finite/with=inf ("disabled", a RED FLAG,
qualitative only), or both=inf ("both_nondetect", contributes nothing).
This file's Section 9/10 functions (delta_dl_solo, delta_dl_joint,
superadditivity_test, run_dl_pipeline) were rewritten from scratch against
that spec; see each function's docstring below for how the categorization
and the one-sample test are implemented.

-------------------------------------------------------------------------
(L2,L3a) DATA SOURCE
-------------------------------------------------------------------------
L2 is the fixed base layer everywhere else in this codebase, so
shapley_pair_sampler (Section 8's ASR-constrained pairs) never varies it.
For M/M' data (the per-layer solo precursor/with points delta_dl_solo
needs), that's why the dedicated k3s-only sampler in
samplers_l2l3a_k3s.py (l2_l3a_separation_sampler, driven by driver.py's
run_l2_l3a_sep() / --mode l2-l3a-sep) exists at all: it treats L2 as
genuinely toggleable via Controls/c-l2-audit and records the same
precursor/with pair for L2 that shapley_pair_sampler records for every
other focus layer. This module regenerates that sampler's output the same
way it regenerates shapley_pair_sampler's (see CONFIG-LABEL RESOLUTION
below) and reads its "_pre_L2"/"_with_L2"/"_pre_L3a"/"_with_L3a" rows from
results.db.

REV 7 FIX: for the M''=15 robustness draws feeding delta_dl_joint (the
Section 10.6 test's other input), this file now ALSO sources (L2,L3a)
from a dedicated k3s sampler -- driver.l2_l3a_robustness_draws_k3s() --
instead of the ordinary KIND-based dl_robustness_sampler(). The previous
version of this file reused dl_robustness_sampler() for (L2,L3a) on the
theory that "L2 being fixed-active there too means its precursor/with cut
already isolates L3a's marginal effect" -- but brief Section 8.3 is
explicit that (L2,L3a)'s M'' draws must ALSO run on k3s with L2 freely
permutable, "no special-casing" relative to the other two pairs' M''
draws; L2 being silently fixed-active was exactly the bug, not a
harmless simplification. See driver.l2_l3a_robustness_draws_k3s()'s
docstring for the sampler itself and robustness_draws_for_pair() below
for the dispatch.

If --mode l2-l3a-sep or --mode dl-robust (for the (L2,L3a) pair
specifically) was never run for a given run_id, the k3s-sourced queries
above simply come back empty and every function below reports the result
as unavailable (insufficient data) rather than fabricating a number --
the same convention used everywhere else in this file when a query comes
back empty.

-------------------------------------------------------------------------
CONFIG-LABEL RESOLUTION
-------------------------------------------------------------------------
The DB's `config` column is a bare string: "C0".."C7" for the primary
build, or a sampler sample_id + point suffix (e.g.
"shapley_L5L6_m3_with_L5", "dl_robust_L1L7_m9_precursor",
"l2l3a_robust_m4_with") for the correction/robustness samples. Which
layers were actually active behind a given label is a deterministic
function of the sampler + the seed driver.py derived from that run's
run_id (int(hashlib.md5(run_id.encode()).hexdigest()[:8], 16), see
driver.py's run_mc_pairs / run_dl_robust / run_l2_l3a_sep). This script
regenerates the exact same sampler output for the run being analyzed
rather than parsing the label string -- that's the only way to know,
e.g., whether Lb happened to land inside La's "with_a" cut for a given
draw (the sampler does not guarantee purity; see samplers.py's own
self-check, which only asserts La is absent from its own precursor, not
that Lb is absent from La's "with" cut).

Usage:
    python3 deliverable_a.py --db results.db [--run-id run_20260101_120000]
                              [--mc-permutations N] --out deliverable_a_report.json
"""

import argparse
import json

import numpy as np
from scipy import stats

from constants import (
    BASE_LAYER, PERMUTABLE_LAYERS, BASELINE_LAYERS, CONFIGS, CONDITION_ORDER,
    CONSTRAINED_PAIRS_ASR, DL_CANDIDATE_PAIRS, DL_ROBUSTNESS_SAMPLES,
    L2_L3A_SEPARATION_SAMPLES, TECHNIQUE_SETS,
)
from samplers import shapley_pair_sampler, dl_robustness_sampler
from samplers_l2l3a_k3s import l2_l3a_separation_sampler
from analysis_common import (
    ATTACK_CLASSES, connect, resolve_run_id, load_rows, filter_rows,
    mixture_asr, dl_median, dl_nondetect, gated_delta_asr, gated_delta_dl,
    dl_valid_techniques, pair_key, mc_seed_for, BONFERRONI_ALPHA, COHENS_H_MIN,
)


# ==============================================================================
# Section 5/6 -- primary metrics and marginal deltas over the sequential build
# ==============================================================================

def build_primary_report(conn, run_id):
    report = {}
    for cond in CONDITION_ORDER:
        layers = BASELINE_LAYERS + CONFIGS[cond]
        report[cond] = {"layers": layers, "classes": {}}
        for j in ATTACK_CLASSES:
            rows = filter_rows(load_rows(conn, cond, j, run_id=run_id), cond)
            mixed, breakdown = mixture_asr(conn, cond, j, run_id)
            report[cond]["classes"][j] = {
                "n": len(rows), "asr": mixed, "asr_breakdown_by_technique": breakdown,
                "dl_nondetect": dl_nondetect(rows),
                "dl_median_by_technique": {t: dl_median(rows, t) for t in TECHNIQUE_SETS[j]},
            }
    return report


def technique_breakdown_asr_delta(conn, cond_prev, cond_curr, attack_class, run_id):
    """Requirement #20b + Section 7 reporting requirement: per-technique
    gated ASR deltas, each independently gated, then uniformly mixed."""
    techs = TECHNIQUE_SETS[attack_class]
    weight = 1.0 / len(techs)
    mixed, per_t = 0.0, {}
    for t in techs:
        rp = filter_rows(load_rows(conn, cond_prev, attack_class, t, run_id), cond_prev)
        rc = filter_rows(load_rows(conn, cond_curr, attack_class, t, run_id), cond_curr)
        g = gated_delta_asr(rp, rc)
        d = g["delta"] if g["delta"] is not None else 0.0
        per_t[t] = g
        mixed += weight * d
    return mixed, per_t


def build_marginal_report(conn, run_id):
    report = {}
    for idx in range(1, len(CONDITION_ORDER)):
        cond_prev, cond_curr = CONDITION_ORDER[idx - 1], CONDITION_ORDER[idx]
        added = [l for l in CONFIGS[cond_curr] if l not in CONFIGS[cond_prev]]
        layer_added = added[0] if added else None
        report[cond_curr] = {"layer_added": layer_added, "classes": {}}
        for j in ATTACK_CLASSES:
            rows_prev = filter_rows(load_rows(conn, cond_prev, j, run_id=run_id), cond_prev)
            rows_curr = filter_rows(load_rows(conn, cond_curr, j, run_id=run_id), cond_curr)
            mixed_delta, per_t = technique_breakdown_asr_delta(conn, cond_prev, cond_curr, j, run_id)
            report[cond_curr]["classes"][j] = {
                "delta_asr": gated_delta_asr(rows_prev, rows_curr),
                "delta_dl": gated_delta_dl(rows_prev, rows_curr),
                "delta_asr_mixture_gated": mixed_delta,
                "delta_asr_by_technique": per_t if len(TECHNIQUE_SETS[j]) > 1 else None,
            }
    return report


# ==============================================================================
# Section 8 -- Shapley correction for the ASR-constrained pairs
# ==============================================================================

def shapley_draws(run_id, mc_permutations=None):
    """Regenerate the exact shapley_pair_sampler output for this run_id --
    the only reliable source for which layers were active behind a config
    label (see module docstring)."""
    return shapley_pair_sampler(M=mc_permutations, pairs=CONSTRAINED_PAIRS_ASR,
                                 seed=mc_seed_for(run_id))


def l2_l3a_draws(run_id):
    """Regenerate the exact l2_l3a_separation_sampler (samplers_l2l3a_k3s.py)
    output for this run_id -- the k3s-only counterpart to shapley_draws(),
    for (L2,L3a), the one DL candidate pair that isn't in
    CONSTRAINED_PAIRS_ASR and so never appears in shapley_draws()'s output.
    Uses the same mc_seed_for(run_id) seed driver.py's run_l2_l3a_sep()
    derives its Monte Carlo seed from, so the regenerated draws line up
    with the "_pre_L2"/"_with_L2"/"_pre_L3a"/"_with_L3a" rows that run
    actually wrote to results.db."""
    return l2_l3a_separation_sampler(M_prime=L2_L3A_SEPARATION_SAMPLES,
                                      seed=mc_seed_for(run_id))


# NOTE: draws_for_pair() lives with the rest of the Section 9/10 DL pipeline
# further down (it's only used there) — see that definition for docs.


def shapley_phi_asr(conn, la, lb, attack_class, draws, run_id):
    pair_draws = [d for d in draws if d.focus_layers == (la, lb)]
    results = {}
    for layer, precursor_attr, with_attr in ((la, "precursor_a", "with_a"),
                                              (lb, "precursor_b", "with_b")):
        deltas = []
        for d in pair_draws:
            precursor_cfg = f"{d.sample_id}_pre_{layer}"
            with_cfg = f"{d.sample_id}_with_{layer}"
            precursor_active = set(getattr(d, precursor_attr))
            with_active = set(getattr(d, with_attr))
            rows_prev = filter_rows(
                load_rows(conn, precursor_cfg, attack_class, run_id=run_id),
                precursor_cfg, precursor_active)
            rows_curr = filter_rows(
                load_rows(conn, with_cfg, attack_class, run_id=run_id),
                with_cfg, with_active)
            g = gated_delta_asr(rows_prev, rows_curr)
            if g["delta"] is not None:
                deltas.append(g["delta"])
        phi = float(np.mean(deltas)) if deltas else None
        results[layer] = {"phi": phi, "n_draws": len(pair_draws), "n_available": len(deltas)}
    return results


def build_phi_table(conn, run_id, mc_permutations=None):
    constrained_layers = {l for pair in CONSTRAINED_PAIRS_ASR for l in pair}
    unconstrained = [l for l in PERMUTABLE_LAYERS if l not in constrained_layers]
    phi = {l: {} for l in PERMUTABLE_LAYERS}
    draws = shapley_draws(run_id, mc_permutations)

    for j in ATTACK_CLASSES:
        for idx, cond in enumerate(CONDITION_ORDER):
            if idx == 0:
                continue
            added = [l for l in CONFIGS[cond] if l not in CONFIGS[CONDITION_ORDER[idx - 1]]]
            if len(added) != 1 or added[0] not in unconstrained:
                continue
            prev_cond = CONDITION_ORDER[idx - 1]
            rows_prev = filter_rows(load_rows(conn, prev_cond, j, run_id=run_id), prev_cond)
            rows_curr = filter_rows(load_rows(conn, cond, j, run_id=run_id), cond)
            phi[added[0]][j] = gated_delta_asr(rows_prev, rows_curr)["delta"]

        for (la, lb) in CONSTRAINED_PAIRS_ASR:
            res = shapley_phi_asr(conn, la, lb, j, draws, run_id)
            phi[la][j] = res[la]["phi"]
            phi[lb][j] = res[lb]["phi"]

    return phi


# ==============================================================================
# Sections 9/10 -- detection latency pipeline (Rev 7: delta space, MAX
# comparator, one-sample Wilcoxon; see module docstring's REV 7 REWRITE note)
# ==============================================================================

def categorize_before_with(before_val, with_val):
    """
    Brief Section 10.4: categorize a single draw's (before, with)
    DL_median scalar pair before it's allowed to feed any delta mean.
    `before_val`/`with_val` are None when DL_median() found no detected
    trials at that point (the Section 10.1 90-second cutoff's dl=infinity
    case; dl_median() already excludes non-detected trials, so "None"
    here plays the role of infinity).

    Returns (category, value):
      ("delta", before_val - with_val)  both finite -> feeds the mean
      ("enabled", None)   before=inf, with=finite -> qualitative only
      ("disabled", None)  before=finite, with=inf -> RED FLAG, qualitative only
      ("both_nondetect", None)  neither side detected -> contributes nothing
    """
    if before_val is None and with_val is None:
        return ("both_nondetect", None)
    if before_val is None:
        return ("enabled", None)
    if with_val is None:
        return ("disabled", None)
    return ("delta", before_val - with_val)


def _empty_categorization_bucket():
    return {"deltas": [], "n_enabled": 0, "n_disabled_RED_FLAG": 0, "n_both_nondetect": 0}


def _apply_categorization(bucket, before_val, with_val):
    kind, val = categorize_before_with(before_val, with_val)
    if kind == "delta":
        bucket["deltas"].append(val)
    elif kind == "enabled":
        bucket["n_enabled"] += 1
    elif kind == "disabled":
        bucket["n_disabled_RED_FLAG"] += 1
    else:
        bucket["n_both_nondetect"] += 1


def _bucket_summary(bucket, n_draws_total):
    return {
        "value": float(np.mean(bucket["deltas"])) if bucket["deltas"] else None,
        "per_draw_deltas": list(bucket["deltas"]),
        "n_draws_total": n_draws_total,
        "n_delta": len(bucket["deltas"]),
        "n_enabled": bucket["n_enabled"],
        "n_disabled_RED_FLAG": bucket["n_disabled_RED_FLAG"],
        "n_both_nondetect": bucket["n_both_nondetect"],
    }


def draws_for_pair(la, lb, shapley_draw_list, run_id):
    """Return the sampler draws that cover this DL candidate pair's M/M'
    (solo precursor/with) measurement points. (L5,L6) and (L1,L7) are also
    ASR-constrained pairs, so their per-layer precursor/with draws already
    exist in shapley_draw_list (regenerated once per run_id by
    shapley_draws()). (L2,L3a) is DL-only -- L2 is fixed-active everywhere
    shapley_pair_sampler runs, so it never appears there -- and its draws
    instead come from l2_l3a_draws()."""
    if pair_key(la, lb) == pair_key("L2", "L3a"):
        return l2_l3a_draws(run_id)
    return shapley_draw_list


def robustness_draws_for_pair(la, lb, run_id):
    """
    Return the M''=15 robustness draws (2-augment precursor/with-pair
    form, Section 10.2) that feed delta_dl_joint for this DL candidate
    pair. REV 7 FIX: (L2,L3a) is dispatched to
    driver.l2_l3a_robustness_draws_k3s() (L2 freely permutable, run on
    k3s -- Section 8.3), not the generic KIND-based dl_robustness_sampler
    every other pair uses. Imports driver lazily to avoid a module-level
    dependency cycle (driver.py doesn't import this module, but keeping
    the import local here mirrors this file's existing lazy-import style
    for samplers_l2l3a_k3s-adjacent code paths).
    """
    if pair_key(la, lb) == pair_key("L2", "L3a"):
        from driver import l2_l3a_robustness_draws_k3s
        return l2_l3a_robustness_draws_k3s(DL_ROBUSTNESS_SAMPLES, mc_seed_for(run_id))
    return dl_robustness_sampler((la, lb), M_double_prime=DL_ROBUSTNESS_SAMPLES,
                                  seed=mc_seed_for(run_id))


def _m2_draw_fields(d):
    """Adapts the two possible M'' draw shapes to (sample_id,
    precursor_layers, active_layers): samplers.dl_robustness_sampler()
    returns SampledCondition dataclass instances; driver's
    l2_l3a_robustness_draws_k3s() returns plain dicts (see that
    function's docstring for why -- avoids needing to edit samplers.py)."""
    if isinstance(d, dict):
        return d["sample_id"], set(d["precursor_layers"]), set(d["active_layers"])
    return d.sample_id, set(d.precursor_layers), set(d.active_layers)


def delta_dl_solo(conn, la, lb, attack_class, technique, draws, run_id):
    """
    Brief Section 10.3: for each of La, Lb, delta_dl_solo(layer,j,T) is
    the mean over M/M' draws where that layer precedes the other within
    the draw, of [DL_median(before layer) - DL_median(with layer)], each
    draw's scalar pair categorized per Section 10.4 (only "delta"
    draws -- both sides finite -- feed the mean; "enabled"/
    "disabled"/"both_nondetect" are tracked but never blended in).
    Precedence conditioning means each draw feeds exactly one of the two
    layers' deltas, never both -- mirrors dl_solo_best's old
    "purity-filtered" framing but via precedence rather than an
    other-layer-absent check, since the M/M' sampler's own with_a/with_b
    cuts are already precedence-consistent by construction.

    Returns {la: summary, lb: summary}, each summary from
    _bucket_summary() (value, per-draw deltas, and the categorization
    counts required by Section 10.4's red-flag tracking).
    """
    pair_draws = [d for d in draws if d.focus_layers == (la, lb)]
    out = {}
    for focus, other, pre_attr, with_attr in (
        (la, lb, "precursor_a", "with_a"),
        (lb, la, "precursor_b", "with_b"),
    ):
        bucket = _empty_categorization_bucket()
        n_considered = 0
        for d in pair_draws:
            if d.layer_order.index(focus) >= d.layer_order.index(other):
                continue  # only draws where `focus` precedes `other` count toward focus's delta
            n_considered += 1
            pre_cfg  = f"{d.sample_id}_pre_{focus}"
            with_cfg = f"{d.sample_id}_with_{focus}"
            pre_active  = set(getattr(d, pre_attr))
            with_active = set(getattr(d, with_attr))
            before_val = dl_median(filter_rows(
                load_rows(conn, pre_cfg, attack_class, technique=technique, run_id=run_id),
                pre_cfg, pre_active))
            with_val = dl_median(filter_rows(
                load_rows(conn, with_cfg, attack_class, technique=technique, run_id=run_id),
                with_cfg, with_active))
            _apply_categorization(bucket, before_val, with_val)
        out[focus] = _bucket_summary(bucket, n_considered)
    return out


def delta_dl_joint(conn, la, lb, attack_class, technique, m2_draws, run_id):
    """
    Brief Section 10.3: delta_dl_joint(La,Lb,j,T) is the mean over
    "passing" (Section 10.4 "delta" category -- both sides finite) M''=15
    robustness draws of [DL_median(before pair) - DL_median(with pair)].
    Also returns the per-draw list of finite deltas, needed by
    superadditivity_test()'s one-sample Wilcoxon (Section 10.6), and the
    same enablement/disablement bookkeeping delta_dl_solo tracks.
    """
    bucket = _empty_categorization_bucket()
    for d in m2_draws:
        sample_id, precursor_layers, active_layers = _m2_draw_fields(d)
        pre_cfg  = f"{sample_id}_precursor"
        with_cfg = f"{sample_id}_with"
        before_val = dl_median(filter_rows(
            load_rows(conn, pre_cfg, attack_class, technique=technique, run_id=run_id),
            pre_cfg, precursor_layers))
        with_val = dl_median(filter_rows(
            load_rows(conn, with_cfg, attack_class, technique=technique, run_id=run_id),
            with_cfg, active_layers))
        _apply_categorization(bucket, before_val, with_val)
    return _bucket_summary(bucket, len(m2_draws))


def _rank_biserial_one_sample(diffs):
    """Rank-biserial effect size r from the signed ranks of a one-sample
    Wilcoxon test's differences: r = (W+ - W-) / (W+ + W-), computed from
    ranks of |diff| with zero-diffs excluded (matches scipy.stats.wilcoxon's
    default zero_method='wilcox' handling, so p and r are consistent with
    each other)."""
    diffs = np.asarray(diffs, dtype=float)
    nonzero = diffs[diffs != 0]
    if nonzero.size == 0:
        return 0.0
    ranks = stats.rankdata(np.abs(nonzero))
    w_plus = ranks[nonzero > 0].sum()
    w_minus = ranks[nonzero < 0].sum()
    denom = w_plus + w_minus
    return float((w_plus - w_minus) / denom) if denom else 0.0


def superadditivity_test(conn, la, lb, attack_class, shapley_draw_list, run_id):
    """
    Brief Section 10.6 (Rev 7 correction from prior revisions' MIN
    comparator + two-sample paired test): one-sample Wilcoxon signed-rank
    test of diff(m) = delta_dl_joint(m) - MAX(delta_dl_solo(La),
    delta_dl_solo(Lb)) against zero, over the M''=15 robustness draws
    themselves (i.e. n = number of draws whose before/with pair was
    "delta"-categorized, not number of trials). H1: median(diff) > 0
    (the pair's joint improvement exceeds the better solo layer's
    improvement -- superadditive). GATE: reject H0 (confirmed=True) only
    if p < Bonferroni/7 AND the rank-biserial effect r >= 0.20 -- both
    required, matching Section 6's gating convention elsewhere in this
    file (Bonferroni/7 + |effect|>=0.20), applied here to a one-sample
    rather than two-sample statistic.
    """
    solo_draws = draws_for_pair(la, lb, shapley_draw_list, run_id)
    m2_draws = robustness_draws_for_pair(la, lb, run_id)
    valid_techs = dl_valid_techniques((la, lb), attack_class)
    out = {}
    for t in valid_techs:
        solo = delta_dl_solo(conn, la, lb, attack_class, t, solo_draws, run_id)
        joint = delta_dl_joint(conn, la, lb, attack_class, t, m2_draws, run_id)
        solo_a, solo_b = solo[la]["value"], solo[lb]["value"]
        if solo_a is None or solo_b is None or not joint["per_draw_deltas"]:
            out[t] = {
                "confirmed": False, "reason": "insufficient_data",
                "delta_dl_solo": solo, "delta_dl_joint": joint,
            }
            continue
        max_solo = max(solo_a, solo_b)
        diffs = np.array(joint["per_draw_deltas"]) - max_solo
        if np.all(diffs == 0):
            p, r_eff = 1.0, 0.0
        else:
            try:
                _, p = stats.wilcoxon(diffs, alternative="greater", zero_method="wilcox")
            except ValueError:
                # all-zero or too few non-zero diffs after zero_method='wilcox'
                # drops ties -- scipy raises rather than returning a p-value
                p = 1.0
            r_eff = _rank_biserial_one_sample(diffs)
        confirmed = (p < BONFERRONI_ALPHA) and (r_eff >= COHENS_H_MIN)
        out[t] = {
            "confirmed": bool(confirmed),
            "delta_dl_solo": solo,
            "max_solo": max_solo,
            "delta_dl_joint": joint,
            "p": float(p),
            "effect_r": r_eff,
            "n_diff_draws": int(len(diffs)),
        }
    return out


def run_dl_pipeline(conn, run_id, mc_permutations=None):
    """
    Runs superadditivity_test() over every DL candidate pair x attack
    class x valid technique, collecting confirmed dropper pairs (the one
    output allowed to cross into deliverable_b.py, per the module
    docstring) and any Section 10.4 "disabled" (detection-regression) red
    flags encountered along the way, from BOTH the solo and joint legs.
    """
    shapley_draw_list = shapley_draws(run_id, mc_permutations)
    report, confirmed_dropper_pairs, red_flags = {}, [], []
    for (la, lb) in DL_CANDIDATE_PAIRS:
        pk = pair_key(la, lb)
        report[pk] = {}
        for j in ATTACK_CLASSES:
            techs = dl_valid_techniques((la, lb), j)
            if not techs:
                continue
            supertest = superadditivity_test(conn, la, lb, j, shapley_draw_list, run_id)
            report[pk][j] = supertest
            for t, verdict in supertest.items():
                if verdict.get("confirmed"):
                    confirmed_dropper_pairs.append((la, lb, j, t))
                solo = verdict.get("delta_dl_solo")
                if solo:
                    for layer_key in (la, lb):
                        d = solo.get(layer_key, {})
                        if d.get("n_disabled_RED_FLAG"):
                            red_flags.append({
                                "pair": pk, "class": j, "technique": t,
                                "kind": f"solo_{layer_key}_detection_disabled",
                                "count": d["n_disabled_RED_FLAG"],
                            })
                joint = verdict.get("delta_dl_joint")
                if joint and joint.get("n_disabled_RED_FLAG"):
                    red_flags.append({
                        "pair": pk, "class": j, "technique": t,
                        "kind": "joint_detection_disabled",
                        "count": joint["n_disabled_RED_FLAG"],
                    })
    return report, confirmed_dropper_pairs, red_flags


# ==============================================================================
# Report assembly / CLI
# ==============================================================================

def run_deliverable_a(conn, run_id, mc_permutations=None):
    primary = build_primary_report(conn, run_id)
    marginal = build_marginal_report(conn, run_id)
    phi_table = build_phi_table(conn, run_id, mc_permutations)
    dl_pipeline, confirmed_dropper_pairs, red_flags = run_dl_pipeline(conn, run_id, mc_permutations)

    return {
        "run_id": run_id,
        "primary_metrics": primary,
        "marginal_deltas": marginal,
        "phi_table_asr": phi_table,
        "asr_c0": {j: primary["C0"]["classes"][j]["asr"] for j in ATTACK_CLASSES},
        "dl_pipeline": dl_pipeline,
        "confirmed_dropper_pairs": [
            {"pair": pair_key(la, lb), "class": j, "technique": t}
            for (la, lb, j, t) in confirmed_dropper_pairs
        ],
        "detection_disabled_red_flags": red_flags,
        "known_gaps": [
            "(L2,L3a)'s M/M' data (delta_dl_solo inputs) is sourced from "
            "samplers_l2l3a_k3s.l2_l3a_separation_sampler's k3s-only "
            "'_pre_L2'/'_with_L2'/'_pre_L3a'/'_with_L3a' rows (driver.py "
            "--mode l2-l3a-sep); its M'' data (delta_dl_joint inputs) is "
            "sourced from driver.l2_l3a_robustness_draws_k3s()'s "
            "'l2l3a_robust_m*_precursor'/'_with' rows (driver.py --mode "
            "dl-robust, which dispatches this pair to that k3s sampler -- "
            "see driver.py's REV 7 FIXES note). If either mode was never "
            "run for this run_id, the k3s-sourced queries come back empty "
            "and this pair reports as unavailable (insufficient data) "
            "rather than an estimate derived from unrelated data.",
        ],
    }


def main():
    ap = argparse.ArgumentParser(description="Deliverable A -- augmentation study measurement pipeline")
    ap.add_argument("--db", required=True)
    ap.add_argument("--run-id", default=None, help="Analyze one run_id. Auto-detected if the DB has exactly one.")
    ap.add_argument("--mc-permutations", type=int, default=None,
                     help="Only if driver.py was invoked with an explicit --mc-permutations override; "
                          "omit to use the correct per-pair allocation (15/30/30).")
    ap.add_argument("--out", required=True, help="Path to write the Deliverable A JSON report "
                                                   "(deliverable_b.py consumes this).")
    args = ap.parse_args()

    conn = connect(args.db)
    run_id = resolve_run_id(conn, args.run_id)
    report = run_deliverable_a(conn, run_id, args.mc_permutations)

    print(f"=== Deliverable A -- run_id: {run_id} ===")
    print("=== ASR by condition (mixture over technique set, Section 7) ===")
    for cond in CONDITION_ORDER:
        vals = [f"{j}={report['primary_metrics'][cond]['classes'][j]['asr']:.3f}" for j in ATTACK_CLASSES]
        print(f"  {cond} (layers={report['primary_metrics'][cond]['layers']}): " + "  ".join(vals))

    print("\n=== Gated marginal DeltaASR per layer introduction (Section 6) ===")
    for cond, entry in report["marginal_deltas"].items():
        vals = []
        for j in ATTACK_CLASSES:
            d = entry["classes"][j]["delta_asr"]["delta"]
            vals.append(f"{j}={d:.3f}" if d is not None else f"{j}=NA")
        print(f"  {entry['layer_added']} ({cond}): " + "  ".join(vals))

    print("\n=== Shapley-corrected phi(Lk,j) (Section 8) ===")
    constrained_layers = {l for pair in CONSTRAINED_PAIRS_ASR for l in pair}
    for layer in sorted(constrained_layers):
        vals = [f"{j}={report['phi_table_asr'][layer].get(j):.3f}"
                if report['phi_table_asr'][layer].get(j) is not None else f"{j}=NA"
                for j in ATTACK_CLASSES]
        print(f"  {layer}: " + "  ".join(vals))

    print(f"\n=== Confirmed DL dropper pairs (Section 10.6): {len(report['confirmed_dropper_pairs'])} ===")
    for c in report["confirmed_dropper_pairs"]:
        print(f"  {c['pair']} / {c['class']} / {c['technique']}")

    red_flags = report.get("detection_disabled_red_flags", [])
    print(f"\n=== Detection-disabled RED FLAGS (Section 10.4): {len(red_flags)} ===")
    for rf in red_flags:
        print(f"  {rf['pair']} / {rf['class']} / {rf['technique']} — {rf['kind']} x{rf['count']}")

    print("\n=== Known gaps ===")
    for g in report["known_gaps"]:
        print(f"  - {g}")

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nDeliverable A report written to {args.out}")
    print("Pass this file to deliverable_b.py --report to build the minimal stack.")


if __name__ == "__main__":
    main()
