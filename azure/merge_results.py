#!/usr/bin/env python3
"""
azure/merge_results.py — merge rszt-canonical's and rszt-shapley's
results.db into one file for Deliverable A's analysis pipeline.

Needed because rszt-canonical and rszt-shapley run CONCURRENTLY in two
separate Azure accounts, each writing to its own disk (SQLite explicitly
warns against multi-writer access over a network mount, so this repo
never shares one live results.db between machines regardless of
scheduling). `run_id` already disambiguates rows, so this is a straight
UNION via ATTACH, not a schema reconciliation. Run this from wherever
you're doing analysis (your laptop, a third VM) — not from either
account's VM itself.

Usage:
    python3 merge_results.py canonical_results.db shapley_results.db \
        --out merged_results.db

Pull the two source files down first, one scp per account (each account
has its own admin SSH key/public IP — see provision_canonical.sh's and
provision_shapley.sh's output):
    scp ztadmin@<canonical-ip>:/opt/rszt/results/results.db canonical_results.db
    scp ztadmin@<shapley-ip>:/opt/rszt/results/results.db   shapley_results.db

If direct SSH access to both accounts isn't convenient from one place
(e.g. corporate network restrictions differ per account), have each
run_*.sh's tail upload to an Azure Storage container in its own account
instead (`az storage blob upload`) and pull both blobs down with
`az storage blob download` under each account's respective `az login` —
same end result, just avoids needing simultaneous SSH reachability.
"""
import argparse
import shutil
import sqlite3
import sys
from pathlib import Path


def merge(sources: list[Path], out_path: Path) -> None:
    if out_path.exists():
        sys.exit(f"refusing to overwrite existing {out_path} — remove it first")

    shutil.copy(sources[0], out_path)
    con = sqlite3.connect(out_path)

    for i, src in enumerate(sources[1:], start=1):
        alias = f"src{i}"
        con.execute(f"ATTACH DATABASE ? AS {alias}", (str(src),))
        # id is AUTOINCREMENT-local to each source db; let the merged db
        # assign its own ids. run_id is what actually disambiguates rows,
        # so duplicate ids across sources are expected and harmless.
        cols = [r[1] for r in con.execute("PRAGMA table_info(trials)").fetchall()
                if r[1] != "id"]
        col_list = ", ".join(cols)
        con.execute(f"INSERT INTO trials ({col_list}) "
                    f"SELECT {col_list} FROM {alias}.trials")
        con.commit()
        n = con.execute(f"SELECT COUNT(*) FROM {alias}.trials").fetchone()[0]
        print(f"  merged {n} rows from {src}")
        con.execute(f"DETACH DATABASE {alias}")

    total = con.execute("SELECT COUNT(*) FROM trials").fetchone()[0]
    run_ids = [r[0] for r in con.execute("SELECT DISTINCT run_id FROM trials").fetchall()]
    print(f"merged db has {total} total trial rows across run_ids: {run_ids}")
    con.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("sources", nargs="+", type=Path,
                     help="results.db files to merge, first one is the base copy")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    merge(args.sources, args.out)
