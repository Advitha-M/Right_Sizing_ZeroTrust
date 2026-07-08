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
  Sections 9/10 DL pipeline:            DL_solo_best (validation only), superadditivity
                                         test, phi_DL_pair (pair-level, never decomposed)

Does NOT touch risk tolerance or stack selection -- that's deliverable_b.py,
which consumes this script's --out JSON as its primary input. Per the brief:
"Build A completely before starting B."

-------------------------------------------------------------------------
WHAT THIS FILLS IN
-------------------------------------------------------------------------
driver.py's run_dl_robust() prints, verbatim:
    "[WARNING] --mode dl-robust has NO automatic superadditivity gate ...
     that analysis code doesn't exist and is out of scope."
That analysis -- the Section 10.3 superadditivity test and the pair-level
phi_DL_pair Shapley averaging -- is implemented here.

-------------------------------------------------------------------------
KNOWN GAP THIS SCRIPT DOES NOT PAPER OVER
-------------------------------------------------------------------------
samplers.py is explicit that l2_l3a_separation_sampler does not exist yet
("deferred to a k3s-based implementation") and driver.py's --mode
l2-l3a-sep is disabled. (L2,L3a) -- the one DL-only candidate pair --
currently has no dedicated solo-DL data in results.db. Every function below
that touches (L2,L3a) DL work detects this (zero rows) and reports it as
unavailable rather than fabricating a number.

-------------------------------------------------------------------------
CONFIG-LABEL RESOLUTION
-------------------------------------------------------------------------
The DB's `config` column is a bare string: "C0".."C7" for the primary
build, or a shapley_pair_sampler / dl_robustness_sampler sample_id + point
suffix (e.g. "shapley_L5L6_m3_with_L5", "dl_robust_L1L7_m9_precursor") for
the correction/robustness samples. Which layers were actually active behind
a given label is a deterministic function of the sampler + the seed
driver.py derived from that run's run_id
(int(hashlib.md5(run_id.encode()).hexdigest()[:8], 16), see driver.py's
run_mc_pairs / run_dl_robust). This script regenerates the exact same
sampler output for the run being analyzed rather than parsing the label
string -- that's the only way to know, e.g., whether Lb happened to land
inside La's "with_a" cut for a given draw (the sampler does not guarantee
purity; see samplers.py's own self-check, which only asserts La is absent
from its own precursor, not that Lb is absent from La's "with" cut).

Usage:
    python3 deliverable_a.py --db results.db [--run-id run_20260101_120000]
                              [--mc-permutations N] --out deliverable_a_report.json
"""

import argparse
import json

import numpy as np

from constants import (
    BASE_LAYER, PERMUTABLE_LAYERS, BASELINE_LAYERS, CONFIGS, CONDITION_ORDER,
    CONSTRAINED_PAIRS_ASR, DL_CANDIDATE_PAIRS, DL_ROBUSTNESS_SAMPLES,
    TECHNIQUE_SETS,
)
from samplers import shapley_pair_sampler, dl_robustness_sampler
from analysis_common import (
    ATTACK_CLASSES, connect, resolve_run_id, load_rows, filter_rows,
    mixture_asr, dl_median, dl_nondetect, gated_delta_asr, gated_delta_dl,
    dl_valid_techniques, pair_key, mc_seed_for,
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
# Sections 9/10 -- detection latency pipeline
# ==============================================================================

def dl_solo_best(conn, la, lb, attack_class, technique, draws, run_id):
    """DL_solo_best = MIN(solo_A, solo_B) -- VALIDATION ONLY, never a formula
    input to phi_DL_pair (Section 10.2). Purity-filtered: a draw's 'with_a'
    point only counts toward solo_A if Lb is genuinely absent from it."""
    pk = pair_key(la, lb)
    if pk == pair_key("L2", "L3a"):
        return None, {"note": "sampler not implemented for (L2,L3a) -- "
                               "samplers.py: l2_l3a_separation_sampler is deferred "
                               "to a k3s-based implementation; no solo-DL data exists "
                               "for this pair in the current pipeline."}
    pair_draws = [d for d in draws if d.focus_layers == (la, lb)]
    solo_vals = {"A": [], "B": []}
    for role, focus, other, with_attr in (("A", la, lb, "with_a"), ("B", lb, la, "with_b")):
        for d in pair_draws:
            with_active = set(getattr(d, with_attr))
            if other in with_active:
                continue  # impure draw -- other layer already present, skip
            cfg = f"{d.sample_id}_with_{focus}"
            rows = load_rows(conn, cfg, attack_class, technique=technique, run_id=run_id)
            m = dl_median(rows)
            if m is not None:
                solo_vals[role].append(m)
    solo_a = float(np.mean(solo_vals["A"])) if solo_vals["A"] else None
    solo_b = float(np.mean(solo_vals["B"])) if solo_vals["B"] else None
    detail = {"solo_a": solo_a, "solo_b": solo_b,
              "n_pure_draws_a": len(solo_vals["A"]), "n_pure_draws_b": len(solo_vals["B"])}
    vals = [v for v in (solo_a, solo_b) if v is not None]
    return (min(vals) if vals else None), detail


def robustness_draws(pair, run_id):
    return dl_robustness_sampler(pair, M_double_prime=DL_ROBUSTNESS_SAMPLES, seed=mc_seed_for(run_id))


def superadditivity_test(conn, la, lb, attack_class, shapley_draw_list, run_id):
    """
    Section 10.3, generalized to reuse the M''=15 dl_robustness_sampler output
    as the joint-config measurement (driver.py's run_dl_robust() has no
    separate full-C7 joint run -- its 'with' point at each draw IS the only
    joint (La present AND Lb present) data this pipeline produces). H1:
    dl_joint < solo_best, Wilcoxon-gated (Bonferroni/7, |r|>=0.20).
    """
    pk = pair_key(la, lb)
    if pk == pair_key("L2", "L3a"):
        return {"note": "unavailable -- (L2,L3a) separation sampler not implemented "
                         "(see samplers.py); no superadditivity test possible with "
                         "current data."}
    from analysis_common import wilcoxon_p, rank_biserial_matched, is_detected, latency, paired_by_trial, BONFERRONI_ALPHA, COHENS_H_MIN  # noqa: E501
    valid_techs = dl_valid_techniques(pk, attack_class)
    out = {}
    r_draws = robustness_draws((la, lb), run_id)
    for t in valid_techs:
        solo_best, solo_detail = dl_solo_best(conn, la, lb, attack_class, t, shapley_draw_list, run_id)
        joint_rows, without_rows = [], []
        for d in r_draws:
            joint_rows += list(load_rows(conn, f"{d.sample_id}_with", attack_class, technique=t, run_id=run_id))
            without_rows += list(load_rows(conn, f"{d.sample_id}_precursor", attack_class, technique=t, run_id=run_id))
        dl_joint = dl_median(joint_rows)
        if solo_best is None or dl_joint is None:
            out[t] = {"confirmed": False, "reason": "insufficient_data", "solo_detail": solo_detail}
            continue
        det_joint = [r for r in joint_rows if is_detected(r)]
        det_without = [r for r in without_rows if is_detected(r)]
        pa, pb = paired_by_trial(det_without, det_joint)
        if not pa:
            out[t] = {"confirmed": False, "reason": "no_paired_detected_trials"}
            continue
        x = [latency(r) for r in pa]
        y = [latency(r) for r in pb]
        p = wilcoxon_p(x, y)
        r_eff = rank_biserial_matched(x, y)
        confirmed = (dl_joint < solo_best) and (p < BONFERRONI_ALPHA) and (abs(r_eff) >= COHENS_H_MIN)
        out[t] = {"confirmed": bool(confirmed), "solo_best": solo_best, "dl_joint": dl_joint,
                   "p": p, "effect_r": r_eff, "n_pairs": len(pa)}
    return out


def phi_dl_pair(conn, la, lb, attack_class, technique, run_id):
    """Section 10: pair-level phi_DL_pair from the M''=15 robustness draws,
    self-contained -- not derived from DL_solo_best, never decomposed
    per-layer (Section 15 item 13)."""
    pk = pair_key(la, lb)
    if pk == pair_key("L2", "L3a"):
        return {"phi_dl_pair": None, "note": "unavailable -- separation sampler not implemented"}
    r_draws = robustness_draws((la, lb), run_id)
    deltas = []
    for d in r_draws:
        with_rows = load_rows(conn, f"{d.sample_id}_with", attack_class, technique=technique, run_id=run_id)
        without_rows = load_rows(conn, f"{d.sample_id}_precursor", attack_class, technique=technique, run_id=run_id)
        dl_with, dl_without = dl_median(with_rows), dl_median(without_rows)
        if dl_with is not None and dl_without is not None:
            deltas.append(dl_without - dl_with)
    if not deltas:
        return {"phi_dl_pair": None, "n_draws": len(r_draws), "n_available": 0}
    return {"phi_dl_pair": float(np.mean(deltas)), "n_draws": len(r_draws), "n_available": len(deltas)}


def run_dl_pipeline(conn, run_id, mc_permutations=None):
    shapley_draw_list = shapley_draws(run_id, mc_permutations)
    report, confirmed_dropper_pairs = {}, []
    for (la, lb) in DL_CANDIDATE_PAIRS:
        pk = pair_key(la, lb)
        report[pk] = {}
        for j in ATTACK_CLASSES:
            techs = dl_valid_techniques(pk, j)
            if not techs:
                continue
            supertest = superadditivity_test(conn, la, lb, j, shapley_draw_list, run_id)
            entry = {"superadditivity": supertest, "phi_dl_pair": {}}
            if isinstance(supertest, dict) and "note" in supertest:
                report[pk][j] = entry
                continue
            for t, verdict in supertest.items():
                if verdict.get("confirmed"):
                    confirmed_dropper_pairs.append((la, lb, j, t))
                    entry["phi_dl_pair"][t] = phi_dl_pair(conn, la, lb, j, t, run_id)
            report[pk][j] = entry
    return report, confirmed_dropper_pairs


# ==============================================================================
# Report assembly / CLI
# ==============================================================================

def run_deliverable_a(conn, run_id, mc_permutations=None):
    primary = build_primary_report(conn, run_id)
    marginal = build_marginal_report(conn, run_id)
    phi_table = build_phi_table(conn, run_id, mc_permutations)
    dl_pipeline, confirmed_dropper_pairs = run_dl_pipeline(conn, run_id, mc_permutations)

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
        "known_gaps": [
            "(L2,L3a) has no DL solo-contribution or superadditivity data: "
            "samplers.py's l2_l3a_separation_sampler is deferred to a "
            "k3s-based implementation and driver.py's --mode l2-l3a-sep is "
            "disabled. phi_DL_pair and DL_solo_best for this pair report as "
            "unavailable rather than being estimated from unrelated data.",
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

    print(f"\n=== Confirmed DL dropper pairs (Section 10.3): {len(report['confirmed_dropper_pairs'])} ===")
    for c in report["confirmed_dropper_pairs"]:
        print(f"  {c['pair']} / {c['class']} / {c['technique']}")

    print("\n=== Known gaps ===")
    for g in report["known_gaps"]:
        print(f"  - {g}")

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nDeliverable A report written to {args.out}")
    print("Pass this file to deliverable_b.py --report to build the minimal stack.")


if __name__ == "__main__":
    main()
