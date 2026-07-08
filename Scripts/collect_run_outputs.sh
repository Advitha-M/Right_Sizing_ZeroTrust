#!/usr/bin/env bash
# Usage: bash scripts/collect_run_outputs.sh <RUN_ID>
set -euo pipefail
RUN_ID="${1:?usage: collect_run_outputs.sh <run_id>}"
OUTDIR="output/${RUN_ID}"
mkdir -p "$OUTDIR"

source ./venv/bin/activate

echo "=== Empirical analysis ==="
python3 figures/analyze.py --run-id "$RUN_ID" --out "$OUTDIR/summary.csv" || true

echo "=== Empirical figures ==="
python3 figures/plot.py --csv "$OUTDIR/summary.csv" --outdir "$OUTDIR" || true

echo "=== Compositional model ==="
python3 figures/compositional.py --db results/results.db --out "$OUTDIR" || true

echo "=== Compositional figures ==="
python3 figures/plot_compositional.py --outdir "$OUTDIR" || true

rm -f output/latest
ln -s "$RUN_ID" output/latest

echo "=== Files in $OUTDIR ==="
ls -la "$OUTDIR"
echo "=== output/latest points to: $(readlink output/latest) ==="
