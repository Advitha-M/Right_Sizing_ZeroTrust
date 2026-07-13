"""
samplers_l2l3a_k3s.py — dedicated (L2,L3a) separation sampler, k3s ONLY.

Scope: brief Section 8.1's M'=15 dedicated separation sample for the one DL
candidate pair that dl_robustness_sampler (samplers.py) cannot measure
correctly: (L2, L3a).

Why this lives in its own module instead of samplers.py:

  Everywhere else in this codebase, L2 = constants.BASE_LAYER — fixed,
  always active, baked into the KIND control plane's static pod manifest
  at cluster bootstrap, never toggled by a Controls/ apply.sh/remove.sh
  pair. samplers._build_order() encodes this directly: it unconditionally
  prepends BASELINE_LAYERS (= ["L2"]) to every sample it builds, for all
  three samplers in that module. dl_robustness_sampler() in samplers.py is
  only ever invoked for (L5,L6) and (L1,L7) in this pipeline for exactly
  this reason (see that function's own docstring) — for (L2,L3a), L2 would
  never move there, so only L3a's position would vary, and its joint
  precursor/active model only records ONE measurement pair for the whole
  unit anyway. Neither limitation is acceptable for (L2,L3a): it cannot
  produce the independent per-layer solo points delta_dl_solo(L2,...) /
  delta_dl_solo(L3a,...) need (brief Section 10.3's definition for a
  DL-only pair requires L2's solo config to be genuinely measured, not
  assumed fixed).

  This sampler instead mirrors shapley_pair_sampler's mechanics exactly:
  both L2 and L3a are independently inserted into a shuffled permutation of
  the remaining permutable layers, so their relative order AND the distance
  between them both vary across draws, exactly like (L5,L6) and (L1,L7) do
  within shapley_pair_sampler. It does NOT call samplers._build_order() —
  L2 is a member of the permutation here, not a fixed prefix.

  Making L2 genuinely vary requires it to be live-toggleable, which in turn
  requires Controls/c-l2-audit/{apply,remove}.sh and a substrate where
  restarting the apiserver to flip that flag is cheap enough to do ~15
  times in a run. k3s (single systemd-managed binary, `systemctl restart
  k3s` takes seconds) is that substrate; the multi-node KIND cluster this
  repo's other 32 samplers.py conditions run against is not — see
  Controls/c-l2-audit/apply.sh's header for the full rationale. Driven by
  Driver/driver.py's run_l2_l3a_sep() against a separate k3s kubeconfig
  (Driver/config.py's K3S_KUBECONFIG), never against the main KIND cluster.

Imported by: Driver/driver.py (run_l2_l3a_sep(), k3s-only code path).
"""
from __future__ import annotations
import random
from typing import Optional

from constants import PERMUTABLE_LAYERS
from samplers import SampledCondition

# This sampler's own separation-sample size — same constant the rest of the
# codebase already uses for this pair (constants.L2_L3A_SEPARATION_SAMPLES),
# imported here rather than redefined so the two stay in sync.
from constants import L2_L3A_SEPARATION_SAMPLES


def l2_l3a_separation_sampler(
    M_prime: int = L2_L3A_SEPARATION_SAMPLES,
    seed: Optional[int] = None,
) -> list[SampledCondition]:
    """
    Draw M_prime random arrangements of {L2, L3a} plus the six other
    permutable layers (L1, L3b, L4, L5, L6, L7). L2 and L3a are each
    independently inserted into a shuffled permutation of the other six,
    so both their relative order and the distance between them vary
    across draws — identical mechanics to shapley_pair_sampler's per-pair
    loop, applied to a pair that isn't in constants.CONSTRAINED_PAIRS_ASR
    (L2 isn't normally a permutable layer at all; this sampler is the one
    place it's treated as one).

    Each draw records the same 4 measurement points shapley_pair_sampler
    produces, needed to compute L2's and L3a's marginal DL contributions
    independently as delta_dl_solo(L2,...) / delta_dl_solo(L3a,...)
    (brief Section 10.3; DL_solo_best is the retracted Rev5/v6 quantity
    this replaces, per Section 10's removal note — not something this
    sampler computes or feeds):
      precursor_a: the stack immediately BEFORE L2 is added
      with_a:      the stack immediately AFTER L2 is added
      precursor_b: the stack immediately BEFORE L3a is added
      with_b:      the stack immediately AFTER L3a is added
    active_layers is the joint "both present" cut, for convenience —
    identical semantics to shapley_pair_sampler's active_layers.

    Unlike every other sampler in this codebase, the returned layer_order
    does NOT start with L2 fixed at position 0 — L2's position varies
    draw-to-draw like any other permutable layer. Driver.set_config_k3s()
    is responsible for actually toggling L2 via Controls/c-l2-audit, which
    Driver.set_config() (used by every other mode) does not know how to do.
    """
    rng = random.Random(seed)
    others = [l for l in PERMUTABLE_LAYERS if l != "L3a"]   # L1,L3b,L4,L5,L6,L7
    out: list[SampledCondition] = []

    for m in range(M_prime):
        base = others.copy()
        rng.shuffle(base)
        for member in ("L2", "L3a"):
            pos = rng.randint(0, len(base))
            base = base[:pos] + [member] + base[pos:]
        order = base   # full 8-layer order — no fixed L2 prefix, unlike samplers.py

        pos_l2, pos_l3a = order.index("L2"), order.index("L3a")
        distance = abs(pos_l2 - pos_l3a)
        first, second = ("L2", "L3a") if pos_l2 < pos_l3a else ("L3a", "L2")
        cut = max(pos_l2, pos_l3a) + 1

        out.append(SampledCondition(
            sample_id=f"l2l3a_sep_m{m}",
            purpose="l2_l3a_separation_sampler",
            layer_order=order,
            active_layers=order[:cut],
            focus_layers=("L2", "L3a"),
            precursor_a=order[:pos_l2],
            with_a=order[:pos_l2 + 1],
            precursor_b=order[:pos_l3a],
            with_b=order[:pos_l3a + 1],
            note=(f"{first} before {second}, distance={distance} "
                  f"(positions {pos_l2 + 1},{pos_l3a + 1}; "
                  f"k3s-only, M'={M_prime})"),
        ))
    return out


# ── Self-check ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("(L2,L3a) separation sampler — k3s-only, M'=15, both members")
    print("independently inserted (relative order AND distance both vary)")
    s = l2_l3a_separation_sampler(seed=42)
    print(f"Total: {len(s)} (expected {L2_L3A_SEPARATION_SAMPLES})")
    assert len(s) == L2_L3A_SEPARATION_SAMPLES, "FAIL: sample count mismatch"

    for c in s:
        assert c.with_a == c.precursor_a + ["L2"], "FAIL: with_a != precursor_a + L2"
        assert c.with_b == c.precursor_b + ["L3a"], "FAIL: with_b != precursor_b + L3a"
        assert "L2" not in c.precursor_a, "FAIL: L2 found in its own precursor"
        assert "L3a" not in c.precursor_b, "FAIL: L3a found in its own precursor"
    print("4 measurement points per draw (precursor/with x L2/L3a): PASS")

    l2_positions = {tuple(c.layer_order).index("L2") for c in s}
    print(f"L2 position varies across draws: {len(l2_positions)} distinct "
          f"positions (should be >1): " + ("PASS" if len(l2_positions) > 1 else "FAIL"))
    assert len(l2_positions) > 1, "FAIL: L2 position never varies"

    l2_before_l3a = sum(1 for c in s if c.layer_order.index("L2") < c.layer_order.index("L3a"))
    l3a_before_l2 = len(s) - l2_before_l3a
    print(f"L2-before-L3a: {l2_before_l3a}  L3a-before-L2: {l3a_before_l2} "
          f"(both >0 expected across M'={L2_L3A_SEPARATION_SAMPLES}): "
          + ("PASS" if l2_before_l3a > 0 and l3a_before_l2 > 0 else "WARN (small M', can happen by chance)"))

    distances = {abs(c.layer_order.index("L2") - c.layer_order.index("L3a")) for c in s}
    print(f"Distance between L2 and L3a varies: {len(distances)} distinct "
          f"values (should be >1): " + ("PASS" if len(distances) > 1 else "FAIL"))
    assert len(distances) > 1, "FAIL: distance never varies"

    print("=" * 70)
    print("All self-checks passed.")
