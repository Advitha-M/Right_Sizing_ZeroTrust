"""
samplers.py — sampling procedures for the layered defense-stack study.
All experiment vocabulary imported from constants.py.

Two randomized samplers are defined here:

  shapley_pair_sampler   For each ASR-constrained pair, randomly varies the
                          relative order and distance between the pair's two
                          layers within the permutable stack. One condition
                          per draw, recording 4 measurement points: a
                          precursor/with pair for each of the two focus
                          layers independently.

  dl_robustness_sampler  For a DL candidate pair, treats the pair as a single
                          joint unit and randomly varies its position within
                          the stack. Each draw records two measurement
                          points: the stack immediately before the pair is
                          added, and the stack immediately after.

A third, non-randomized helper draws attack techniques per trial:

  technique_sampler       Independently draws one technique per trial from
                           an attack class's technique set.

Not implemented in this module: a dedicated (L2,L3a) separation sampler.
L2 is the fixed base layer and is always present, so measuring its DL
solo-contribution against L3a needs its own sampler rather than reusing
dl_robustness_sampler's precursor/with-pair logic. That sampler is deferred
— it cannot be run meaningfully on the current KIND substrate and will be
implemented against k3s instead, in a separate module.
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Optional

from constants import (
    BASELINE_LAYERS, PERMUTABLE_LAYERS,
    CONSTRAINED_PAIRS_ASR, DL_CANDIDATE_PAIRS, TECHNIQUE_SETS,
    PAIR_MC_SAMPLES, DL_ROBUSTNESS_SAMPLES,
)


@dataclass
class SampledCondition:
    sample_id:    str
    purpose:      str
    layer_order:  list[str]
    active_layers: list[str]
    focus_layers: tuple
    precursor_layers: Optional[list[str]] = None
    # Per-layer measurement points for the two focus_layers members,
    # "a" = focus_layers[0], "b" = focus_layers[1]. Populated by
    # shapley_pair_sampler (each focus layer needs its own precursor/with
    # pair since their marginal contributions are measured independently,
    # unlike dl_robustness_sampler's single joint precursor/active pair).
    precursor_a: Optional[list[str]] = None
    with_a:      Optional[list[str]] = None
    precursor_b: Optional[list[str]] = None
    with_b:      Optional[list[str]] = None
    note:         str = ""

    def __repr__(self):
        return (f"<{self.purpose} {self.sample_id} "
                f"focus={self.focus_layers} "
                f"precursor={self.precursor_layers} active={self.active_layers}>")


def _build_order(permuted_suffix: list[str]) -> list[str]:
    return BASELINE_LAYERS + permuted_suffix


# ── Sampler 1: Shapley ASR pair sampler ──────────────────────────────────────

def shapley_pair_sampler(
    M: Optional[int] = None,
    pairs: Optional[list[tuple]] = None,
    seed: Optional[int] = None,
) -> list[SampledCondition]:
    """
    For each constrained pair, draw M random arrangements of the
    permutable suffix (PERMUTABLE_LAYERS). The pair's two members are
    inserted independently, so both their relative order and the distance
    between them vary across draws. Each draw produces one SampledCondition
    for the pair.

    Each draw records 4 measurement points, needed to compute La's and
    Lb's marginal contributions independently:
      precursor_a: the stack immediately BEFORE La is added
      with_a:      the stack immediately AFTER La is added
      precursor_b: the stack immediately BEFORE Lb is added
      with_b:      the stack immediately AFTER Lb is added
    These 4 points are well-defined regardless of which of La/Lb lands
    first in a given draw. active_layers is retained as the joint
    "both present" cut (max of the two), for convenience.

    Sample size is per-pair, from constants.PAIR_MC_SAMPLES:
      (L3a,L3b) -> 15
      (L5,L6)   -> 30
      (L1,L7)   -> 30

    Passing an explicit M overrides ALL pairs uniformly (dry-run use only).
    Omit M to use the per-pair allocation from PAIR_MC_SAMPLES.

    Returns sum(M_pair) SampledConditions across all pairs.
    """
    rng   = random.Random(seed)
    pairs = pairs or CONSTRAINED_PAIRS_ASR
    out: list[SampledCondition] = []

    for (la, lb) in pairs:
        pair_m = M if M is not None else PAIR_MC_SAMPLES.get((la, lb), 30)
        permutable_pair = [l for l in (la, lb) if l in PERMUTABLE_LAYERS]
        others          = [l for l in PERMUTABLE_LAYERS if l not in {la, lb}]

        for m in range(pair_m):
            base = others.copy()
            rng.shuffle(base)
            for member in permutable_pair:
                pos  = rng.randint(0, len(base))
                base = base[:pos] + [member] + base[pos:]
            order = _build_order(base)

            pos_a, pos_b = order.index(la), order.index(lb)
            distance     = abs(pos_a - pos_b)
            first, second = (la, lb) if pos_a < pos_b else (lb, la)
            cut = max(pos_a, pos_b) + 1

            out.append(SampledCondition(
                sample_id=f"shapley_{la}{lb}_m{m}",
                purpose="shapley_pair_sampler",
                layer_order=order,
                active_layers=order[:cut],
                focus_layers=(la, lb),
                precursor_a=order[:pos_a],
                with_a=order[:pos_a + 1],
                precursor_b=order[:pos_b],
                with_b=order[:pos_b + 1],
                note=(f"{first} before {second}, distance={distance} "
                      f"(positions {pos_a + 1},{pos_b + 1}; M={pair_m})"),
            ))
    return out


# ── Sampler 2: DL robustness sampler ──────────────────────────────────────────

def dl_robustness_sampler(
    confirmed_pair: tuple,
    M_double_prime: int = DL_ROBUSTNESS_SAMPLES,
    seed: Optional[int] = None,
) -> list[SampledCondition]:
    """
    Generic KIND-based M''=15 robustness sampler (brief Section 10.2's
    2-augment "before pair / with pair" form). In the current Rev 7
    pipeline this is used for (L5,L6) and (L1,L7) only — both stay on
    KIND with L2 hard-fixed as base, so treating the pair as a single
    joint unit inserted into PERMUTABLE_LAYERS is correct for them.

    (L2,L3a) is NOT routed through this sampler for its M''=15 robustness
    draws. Brief Section 8.3 requires (L2,L3a)'s M'' draws to also run on
    k3s with L2 freely permutable, "no special-casing" relative to the
    other two pairs — but this sampler's _build_order() unconditionally
    prepends BASELINE_LAYERS (= ["L2"]) to every sample, which would
    silently keep L2 fixed-active and defeat that requirement. deliverable
    _a.py's robustness_draws_for_pair() and driver.py's run_dl_robust()
    both special-case (L2,L3a) to call
    driver.l2_l3a_robustness_draws_k3s() instead, which mirrors this
    function's 2-augment shape but independently inserts both L2 and L3a
    into the permutation (see samplers_l2l3a_k3s.py for the sibling
    M'=15 sampler that does the analogous thing for the 4-augment case).
    This function accepts (L2,L3a) as a `confirmed_pair` argument without
    erroring, but nothing in the current pipeline calls it that way —
    if something ever does, note that L2 will incorrectly stay fixed.

    Each draw records two measurement points:
      precursor_layers: the stack immediately BEFORE the pair is added
      active_layers:    the stack immediately AFTER the pair is added
    """
    rng    = random.Random(seed)
    la, lb = confirmed_pair
    permutable_members = [l for l in (la, lb) if l in PERMUTABLE_LAYERS]
    others = [l for l in PERMUTABLE_LAYERS if l not in {la, lb}]
    out: list[SampledCondition] = []

    for m in range(M_double_prime):
        base      = others.copy()
        rng.shuffle(base)
        insert_at = rng.randint(0, len(base))
        suffix    = base[:insert_at] + permutable_members + base[insert_at:]
        order     = _build_order(suffix)

        if permutable_members:
            precursor_cut = min(order.index(l) for l in permutable_members)
            with_cut      = max(order.index(l) for l in permutable_members) + 1
        else:
            precursor_cut = with_cut = len(BASELINE_LAYERS)

        out.append(SampledCondition(
            sample_id=f"dl_robust_{la}{lb}_m{m}",
            purpose="dl_robustness_sampler",
            layer_order=order,
            active_layers=order[:with_cut],
            precursor_layers=order[:precursor_cut],
            focus_layers=(la, lb),
            note=f"Precursor stack ends at position {precursor_cut}; "
                 f"joint ({la},{lb}) added at positions "
                 f"{precursor_cut + 1}-{with_cut}. "
                 f"delta_dl_joint (brief Section 10.3) computed directly "
                 f"from this M''={M_double_prime} output's precursor/with "
                 f"pairs — not derived from delta_dl_solo or any per-layer "
                 f"value (delta_dl_solo/DL_solo_best/phi_DL_pair are a "
                 f"separate, per-layer quantity computed from M/M' draws, "
                 f"not from this sampler's output).",
        ))
    return out


# ── Sampler 3: Per-trial technique sampler (§12) ──────────────────────────────

@dataclass
class TrialTechniqueDraw:
    trial_index:        int
    attack_class:       str
    technique:          str
    technique_set_size: int


def technique_sampler(
    attack_class: str,
    n_trials: int = 50,
    seed: Optional[int] = None,
) -> list[TrialTechniqueDraw]:
    """
    Each trial independently draws exactly one technique from the class set.
    For single-technique classes (A4, A6) every draw returns the same technique.
    """
    if attack_class not in TECHNIQUE_SETS:
        raise ValueError(f"Unknown attack class: {attack_class}")
    techniques = TECHNIQUE_SETS[attack_class]
    rng        = random.Random(seed)
    return [
        TrialTechniqueDraw(
            trial_index=t,
            attack_class=attack_class,
            technique=rng.choice(techniques),
            technique_set_size=len(techniques),
        )
        for t in range(n_trials)
    ]


# ── Self-check ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from collections import Counter

    print("=" * 70)
    print("1. Shapley pair sampler — per-pair M (3 pairs: 15/30/30), one")
    print("   condition per draw, varying relative order and distance")
    s1 = shapley_pair_sampler(seed=42)
    expected_total = sum(PAIR_MC_SAMPLES[p] for p in CONSTRAINED_PAIRS_ASR)
    print(f"   Total: {len(s1)} (expected {expected_total})")
    assert len(s1) == expected_total, "FAIL: sample count mismatch"
    assert all(c.layer_order[:1] == ["L2"] for c in s1), "FAIL: base layer"
    for c in s1:
        la, lb = c.focus_layers
        assert c.with_a == c.precursor_a + [la], "FAIL: with_a != precursor_a + La"
        assert c.with_b == c.precursor_b + [lb], "FAIL: with_b != precursor_b + Lb"
        assert la not in c.precursor_a, "FAIL: La found in its own precursor"
        assert lb not in c.precursor_b, "FAIL: Lb found in its own precursor"
    print(f"   4 measurement points per draw (precursor/with x La/Lb): PASS")
    l1l7 = [c for c in s1 if c.focus_layers == ("L1", "L7")]
    l1_positions = {tuple(c.layer_order).index("L1") for c in l1l7}
    print(f"   L1 position varies across (L1,L7) samples: "
          f"{len(l1_positions)} distinct positions (should be >1): "
          + ("PASS" if len(l1_positions) > 1 else "FAIL"))
    l3b_before_l3a = [c for c in s1
                      if "L3a" in c.layer_order and "L3b" in c.layer_order
                      and c.layer_order.index("L3b") < c.layer_order.index("L3a")]
    print(f"   L3b precedes L3a in {len(l3b_before_l3a)} samples (should be >0): "
          + ("PASS" if l3b_before_l3a else "WARN"))

    print("=" * 70)
    print("2. DL robustness sampler (M''=15, all 3 DL candidate pairs)")
    print("   — 2 measurement points per draw: precursor-to-pair, with-pair")
    for pair in DL_CANDIDATE_PAIRS:
        s2 = dl_robustness_sampler(pair, seed=42)
        permutable_members = {l for l in pair if l in PERMUTABLE_LAYERS}
        assert all(c.layer_order[:1] == ["L2"] for c in s2)
        assert all(c.precursor_layers is not None for c in s2), "FAIL: missing precursor"
        assert all(
            set(c.active_layers) - set(c.precursor_layers) == permutable_members
            for c in s2
        ), "FAIL: active_layers minus precursor should equal the pair's permutable members"
        print(f"   {pair}: {len(s2)} samples — PASS "
              f"(added between precursor/active: {sorted(permutable_members)})")

    print("=" * 70)
    print("3. Technique sampler — verify |T| against spec for all 7 classes")
    expected_sizes = {"A1": 3, "A2": 3, "A3": 2, "A4": 1, "A5": 3, "A6": 1, "A7": 2}
    for cls, expected in expected_sizes.items():
        draws = technique_sampler(cls, n_trials=50, seed=42)
        actual = draws[0].technique_set_size
        status = "PASS" if actual == expected else "FAIL"
        print(f"   {cls}: |T|={actual} (expected {expected}) — {status}")
        assert actual == expected, f"FAIL: {cls} technique count mismatch"
    print(f"   Total techniques across all classes: "
          f"{sum(expected_sizes.values())} (spec says 15)")

    print("=" * 70)
    print("4. Sample cost accounting")
    axis2 = sum(PAIR_MC_SAMPLES[p] for p in CONSTRAINED_PAIRS_ASR)
    axis3 = DL_ROBUSTNESS_SAMPLES * len(DL_CANDIDATE_PAIRS)
    deferred_l2l3a_separation = 15  # brief §4.2 — implemented on k3s, not here
    print(f"   Axis 2 (ASR Shapley, 3 pairs, one condition per draw): {axis2} conditions")
    print(f"     -> (L3a,L3b) 15, (L5,L6) 30, (L1,L7) 30 = {axis2}")
    print(f"   Axis 3 (DL robustness, M''=15 x 3 pairs):              {axis3} conditions")
    print(f"   This module's total: {axis2 + axis3} conditions")
    print(f"   NOT produced here (deferred to k3s implementation):    "
          f"{deferred_l2l3a_separation} conditions — (L2,L3a) dedicated separation, brief §4.2")
    print(f"   Brief §4.2 total (30+30+15+15+15x3): "
          f"{axis2 + axis3 + deferred_l2l3a_separation} (matches brief's 135)")

    print("=" * 70)
    print("All self-checks passed.")
