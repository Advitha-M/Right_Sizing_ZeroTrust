#!/usr/bin/env python3
"""
deliverable_b.py -- Deliverable B: the minimal-stack decision tool

Lives in Driver/, alongside constants.py, samplers.py, driver.py,
analysis_common.py, deliverable_a.py. Consumes deliverable_a.py's JSON
report (phi_table_asr, asr_c0, confirmed_dropper_pairs) plus a directly
supplied risk tolerance, and recommends the cheapest layer combination
satisfying that tolerance:

  Section 11.1  Risk tolerance:      theta(c,j) in [0.05,1.0] per class, direct
                                      user input, no default; theta_DL(c,j) in
                                      seconds, unspecified = +infinity
  Section 11.2  ResidualASR:         ASR(C0,j) * PRODUCT (1 - phi(Lk,j)/ASR(C0,j))
  Section 11.3  Precedence:          (L3a,L3b), (L2,L3a), (L2,L6) -- recommendation
                                      engine only, never applied to Shapley sampling
  Section 11.4  Two-stage build:     Stage 1 ASR-only smallest valid subset; Stage 2
                                      (only if theta_DL given) resolves DL-violating
                                      classes via CONFIRMED_DROPPER_PAIRS, preferring
                                      a partial-match single-layer add over the full
                                      pair cost

Per the brief: "Build A completely before starting B." This script assumes
deliverable_a.py has already been run and does not recompute phi(Lk,j) or
run any significance tests itself -- it only reads deliverable_a.py's output
and (for the Stage 2 DL check) looks up the already-measured DL_median at
the resulting stack directly from the results DB.

Usage:
    python3 deliverable_b.py --db results.db --report deliverable_a_report.json \\
        --theta '{"A1":0.1,"A2":0.15,"A3":0.15,"A4":0.2,"A5":0.1,"A6":0.2,"A7":0.15}' \\
        [--theta-dl '{"A1":30}'] [--out minimal_stack.json]
"""

import argparse
import json
from itertools import combinations

from constants import BASE_LAYER, PERMUTABLE_LAYERS, BASELINE_LAYERS, CONFIGS, CONDITION_ORDER, is_valid_subset
from analysis_common import ATTACK_CLASSES, connect, resolve_run_id, load_rows, filter_rows, dl_median


def load_deliverable_a_report(path):
    with open(path) as f:
        return json.load(f)


# ==============================================================================
# Section 11.2 -- ResidualASR
# ==============================================================================

def residual_asr(subset, phi_table, asr_c0, attack_class):
    """ResidualASR(S,j) = ASR(C0,j) * PRODUCT_{Lk in S} (1 - phi(Lk,j)/ASR(C0,j)).
    ASR(C0,j) is measured at C0={L2}, the corrected base -- not an empty stack."""
    base = asr_c0.get(attack_class)
    if not base:
        return 0.0
    product = 1.0
    for layer in subset:
        phi = (phi_table.get(layer) or {}).get(attack_class) or 0.0
        product *= (1 - phi / base)
    return base * product


# ==============================================================================
# Section 11.4 -- two-stage minimal stack construction
# ==============================================================================

def find_minimal_stack_stage1(theta, phi_table, asr_c0):
    """Stage 1 (ASR-only, always runs): smallest precedence-valid subset S of
    the optional layers such that ResidualASR(S,j) <= theta(c,j) for every
    class j with a supplied tolerance. Classes absent from theta are
    unconstrained (Section 11.1: 'unspecified means no constraint')."""
    constrained = {j: t for j, t in theta.items() if t is not None}
    for size in range(0, len(PERMUTABLE_LAYERS) + 1):
        for subset in combinations(PERMUTABLE_LAYERS, size):
            if not is_valid_subset(list(subset)):
                continue
            if all(residual_asr(subset, phi_table, asr_c0, j) <= t for j, t in constrained.items()):
                return list(subset)
    return list(PERMUTABLE_LAYERS)  # full stack always satisfies everything by construction


def dl_at_condition(conn, subset, attack_class, run_id):
    """DL_median(S*,j): looked up directly from the primary sequential build
    if S* union {L2} matches one of the C0..C7 active layer sets exactly
    (which it always will, since Stage 1 only ever adds PERMUTABLE_LAYERS in
    combination -- but a subset built by an unusual precedence/tie-break
    path could in principle not correspond to any measured condition, in
    which case this returns None and the caller must treat theta_DL as
    unverifiable for that class rather than guessing)."""
    target = frozenset(subset) | {BASE_LAYER}
    for cond in CONDITION_ORDER:
        if frozenset(BASELINE_LAYERS + CONFIGS[cond]) == target:
            rows = load_rows(conn, cond, attack_class, run_id=run_id)
            return dl_median(filter_rows(rows, cond))
    return None


def minimal_stack(conn, theta, theta_dl, phi_table, asr_c0, confirmed_dropper_pairs, run_id):
    s_star = find_minimal_stack_stage1(theta, phi_table, asr_c0)

    if not any(v is not None for v in theta_dl.values()):
        return {"stack": s_star, "stage": 1, "violating_classes": []}

    violating = []
    for j, t_dl in theta_dl.items():
        if t_dl is None:
            continue
        dl_curr = dl_at_condition(conn, s_star, j, run_id)
        if dl_curr is not None and dl_curr > t_dl:
            violating.append(j)
    if not violating:
        return {"stack": s_star, "stage": 1, "violating_classes": []}

    s2 = list(s_star)
    resolutions = {}
    for j in violating:
        candidates = [c for c in confirmed_dropper_pairs if c["class"] == j]
        if not candidates:
            resolutions[j] = {"resolution": "no_confirmed_dropper_pair"}
            continue
        pairs = [tuple(c["pair"].split("_", 1)) for c in candidates]
        # partial match: exactly one member of the pair already in s2
        partial = None
        for (la, lb), c in zip(pairs, candidates):
            if (la in s2) != (lb in s2):
                partial = (la, lb, c["technique"])
                break
        if partial:
            la, lb, t = partial
            missing = lb if la in s2 else la
            if missing not in s2:
                s2.append(missing)
            resolutions[j] = {"resolution": "partial_match_added", "layer_added": missing, "technique": t}
        else:
            la, lb = pairs[0]
            t = candidates[0]["technique"]
            for layer in (la, lb):
                if layer not in s2:
                    s2.append(layer)
            resolutions[j] = {"resolution": "full_pair_cost", "layers_added": [la, lb], "technique": t}

    return {"stack": s2, "stage": 2, "violating_classes": violating, "resolutions": resolutions}


def main():
    ap = argparse.ArgumentParser(description="Deliverable B -- minimal-stack decision tool")
    ap.add_argument("--db", required=True, help="results.db -- needed only for the Stage-2 "
                                                  "theta_DL check against measured DL_median.")
    ap.add_argument("--report", required=True, help="Path to deliverable_a.py's --out JSON report.")
    ap.add_argument("--run-id", default=None, help="Defaults to the run_id recorded in --report.")
    ap.add_argument("--theta", required=True,
                     help='JSON risk tolerance per class, e.g. \'{"A1":0.1,"A2":0.15}\' (Sec 11.1). '
                          'Classes omitted are unconstrained.')
    ap.add_argument("--theta-dl", default=None,
                     help='JSON DL tolerance (seconds) per class, e.g. \'{"A1":30}\' (Sec 11.1). '
                          'Omitted = +infinity (Stage 2 skipped entirely if none given).')
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    a_report = load_deliverable_a_report(args.report)
    run_id = args.run_id or a_report["run_id"]

    theta_in = json.loads(args.theta)
    theta_dl_in = json.loads(args.theta_dl) if args.theta_dl else {}
    theta = {j: theta_in.get(j) for j in ATTACK_CLASSES}
    theta_dl = {j: theta_dl_in.get(j) for j in ATTACK_CLASSES}
    for j, t in theta.items():
        if t is not None and not (0.05 <= t <= 1.0):
            raise SystemExit(f"theta[{j}]={t} outside the spec's [0.05, 1.0] range (Section 11.1)")

    conn = connect(args.db)
    result = minimal_stack(
        conn, theta, theta_dl,
        a_report["phi_table_asr"], a_report["asr_c0"],
        a_report["confirmed_dropper_pairs"], run_id,
    )

    print(f"=== Deliverable B -- minimal stack (run_id: {run_id}) ===")
    print(f"theta:    {theta}")
    print(f"theta_dl: {theta_dl}")
    print(f"\nStage {result['stage']} result: {sorted(result['stack'])}")
    print(f"(full active layer set including base: {sorted(set(result['stack']) | {BASE_LAYER})})")
    if result["violating_classes"]:
        print(f"\nDL-violating classes after Stage 1: {result['violating_classes']}")
        for j, res in result["resolutions"].items():
            print(f"  {j}: {res}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"run_id": run_id, "theta": theta, "theta_dl": theta_dl, **result}, f, indent=2, default=str)
        print(f"\nWritten to {args.out}")


if __name__ == "__main__":
    main()
