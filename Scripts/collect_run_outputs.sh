#!/usr/bin/env bash
# =============================================================================
# Scripts/collect_run_outputs.sh
# Usage: bash Scripts/collect_run_outputs.sh <RUN_ID> [--with-deliverable-b]
#
# CORRECTED (validation pass): this script previously called
# figures/analyze.py, figures/plot.py, figures/compositional.py, and
# figures/plot_compositional.py, and sourced ./venv/bin/activate — none of
# which exist anywhere in this repo (confirmed: figures/ is not a valid path,
# there is no venv/ checked in). It also never touched Driver/deliverable_a.py
# at all, so it could not have produced the actual Deliverable A output.
# It now runs the real pipeline: Driver/deliverable_a.py against
# results/results.db, per Driver/config.py's RESULTS_DB path.
#
# Deliverable B is out of scope / deferred (per prior instruction) — its
# invocation below is opt-in via --with-deliverable-b and is otherwise
# skipped, not run by default.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

RUN_ID="${1:?usage: collect_run_outputs.sh <run_id> [--with-deliverable-b]}"
WITH_B=false
[[ "${2:-}" == "--with-deliverable-b" ]] && WITH_B=true

DB="results/results.db"
OUTDIR="output/${RUN_ID}"
mkdir -p "$OUTDIR"

if [[ ! -f "$DB" ]]; then
  echo "[collect_run_outputs] ERROR: $DB not found — run Driver/driver.py first" >&2
  exit 1
fi

# Optional venv: only activate if the caller actually has one, don't assume it
if [[ -f "venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source venv/bin/activate
fi

echo "=== Deliverable A: run_deliverable_a pipeline (Driver/deliverable_a.py) ==="
python3 Driver/deliverable_a.py \
  --db "$DB" \
  --run-id "$RUN_ID" \
  --out "$OUTDIR/deliverable_a_report.json"

if $WITH_B; then
  echo "=== Deliverable B (opt-in, --with-deliverable-b passed) ==="
  python3 Driver/deliverable_b.py \
    --db "$DB" \
    --report "$OUTDIR/deliverable_a_report.json" \
    --out "$OUTDIR/deliverable_b_report.json" || \
    echo "[collect_run_outputs] (warn) deliverable_b.py failed or is not ready for this run"
else
  echo "=== Deliverable B skipped (deferred; pass --with-deliverable-b to include it) ==="
fi

rm -f output/latest
ln -s "$RUN_ID" output/latest

echo "=== Files in $OUTDIR ==="
ls -la "$OUTDIR"
echo "=== output/latest points to: $(readlink output/latest) ==="
