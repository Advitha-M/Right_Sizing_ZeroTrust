# driver.py patch — make set_config() halt on apply/remove failure

Currently `set_config()` and `set_config_k3s()` only log a `WARN` when an
`apply.sh`/`remove.sh` returns non-zero, then unconditionally mark the layer
as `applied` anyway. `run_trials()` already HALTs a condition when
`run_invariant_checks()` fails (that's what caught the smoke3 C1 failure) —
but it only finds out ~25s later, indirectly, via generic-looking Tier 1
failures ("kubectl get nodes failed" etc.) that don't say *why*. This patch
makes a bad apply/remove fail fast, with a specific reason, at the point it
actually happened.

Apply these as three `str_replace`-style edits to `Driver/driver.py`.

---

## Edit 1 — `set_config()` (around line 880)

**OLD:**
```python
def set_config(target_layers, applied):
    target = set(target_layers)
    for lid in reversed([l for l, _n, _d in C.LAYERS]):
        if lid in applied and lid not in target:
            log(f"  removing {lid}")
            rc, out, _ = run(f"bash {C.remove_script(lid)}", timeout=360)
            if rc != 0:
                log(f"  WARN remove {lid} rc={rc}")
            applied.discard(lid)
    for lid, _name, _d in C.LAYERS:
        if lid in target and lid not in applied:
            log(f"  applying {lid}")
            timeout = 480 if lid == "L6" else 360
            rc, out, _ = run(f"bash {C.apply_script(lid)}", timeout=timeout)
            if rc != 0:
                log(f"  WARN apply {lid} rc={rc}:\n{out[-400:]}")
            applied.add(lid)
    return applied
```

**NEW:**
```python
def set_config(target_layers, applied):
    """Returns (applied, ok). ok=False means an apply/remove script failed
    (non-zero rc) — the caller must NOT proceed to run_trials() for this
    condition; the cluster may be in a broken or inconsistent state, and
    the specific failure has already been logged here with its script
    output, rather than being discovered indirectly via generic Tier 1
    failures a step later."""
    ok = True
    target = set(target_layers)
    for lid in reversed([l for l, _n, _d in C.LAYERS]):
        if lid in applied and lid not in target:
            log(f"  removing {lid}")
            rc, out, _ = run(f"bash {C.remove_script(lid)}", timeout=360)
            if rc != 0:
                log(f"  FAIL remove {lid} rc={rc}:\n{out[-400:]}")
                ok = False
            applied.discard(lid)
    for lid, _name, _d in C.LAYERS:
        if lid in target and lid not in applied:
            log(f"  applying {lid}")
            timeout = 480 if lid == "L6" else 360
            rc, out, _ = run(f"bash {C.apply_script(lid)}", timeout=timeout)
            if rc != 0:
                log(f"  FAIL apply {lid} rc={rc}:\n{out[-400:]}")
                ok = False
            else:
                applied.add(lid)
    return applied, ok
```

Note the small but important extra change: `applied.add(lid)` moved inside
the `else` — a layer whose apply.sh failed should NOT be recorded as
active, since (with the hardened apply.sh) a failure means it rolled itself
back. Previously it was added regardless of rc, which would have made
`detect_applied_layers()`/resume logic on the next run believe L1 was
active when it wasn't.

---

## Edit 2 — `set_config_k3s()` (around line 905) — same treatment

**OLD:**
```python
    for lid in reversed([l for l, _n, _d in C.K3S_LAYERS]):
        if lid in applied and lid not in target:
            log(f"  [k3s] removing {lid}")
            rc, out, _ = run(f"bash {C.remove_script_k3s(lid)}", timeout=360, env=k3s_env)
            if rc != 0:
                log(f"  [k3s] WARN remove {lid} rc={rc}")
            applied.discard(lid)
    for lid, _name, _d in C.K3S_LAYERS:
        if lid in target and lid not in applied:
            log(f"  [k3s] applying {lid}")
            timeout = 480 if lid == "L6" else 360
            rc, out, _ = run(f"bash {C.apply_script_k3s(lid)}", timeout=timeout, env=k3s_env)
            if rc != 0:
                log(f"  [k3s] WARN apply {lid} rc={rc}:\n{out[-400:]}")
            applied.add(lid)
    return applied
```

**NEW:**
```python
    ok = True
    for lid in reversed([l for l, _n, _d in C.K3S_LAYERS]):
        if lid in applied and lid not in target:
            log(f"  [k3s] removing {lid}")
            rc, out, _ = run(f"bash {C.remove_script_k3s(lid)}", timeout=360, env=k3s_env)
            if rc != 0:
                log(f"  [k3s] FAIL remove {lid} rc={rc}:\n{out[-400:]}")
                ok = False
            applied.discard(lid)
    for lid, _name, _d in C.K3S_LAYERS:
        if lid in target and lid not in applied:
            log(f"  [k3s] applying {lid}")
            timeout = 480 if lid == "L6" else 360
            rc, out, _ = run(f"bash {C.apply_script_k3s(lid)}", timeout=timeout, env=k3s_env)
            if rc != 0:
                log(f"  [k3s] FAIL apply {lid} rc={rc}:\n{out[-400:]}")
                ok = False
            else:
                applied.add(lid)
    return applied, ok
```

(also add `ok = True` right after the `target = set(target_layers)` line at
the top of `set_config_k3s()`, same as Edit 1.)

---

## Edit 3 — the four call sites

All four follow the same shape. In each, unpack the tuple and skip
`run_trials()` (or `continue`, for the loop bodies) when `ok` is False.

### 3a. `run_sequential()` (~line 1434)

**OLD:**
```python
        applied = set_config(CONFIGS[cfg], applied)
        wait_stable()
        run_trials(con, run_id, cfg, CONFIGS[cfg], args.attacks, args.trials, args)
```

**NEW:**
```python
        applied, ok = set_config(CONFIGS[cfg], applied)
        if not ok:
            log(f"  HALTING config {cfg} — apply/remove failed before any invariant check ran")
            continue
        wait_stable()
        run_trials(con, run_id, cfg, CONFIGS[cfg], args.attacks, args.trials, args)
```

### 3b. `run_mc_pairs()` (~line 1471)

**OLD:**
```python
            applied = set_config(layers, applied)
            wait_stable()
            run_trials(con, run_id, config_label, layers,
                       args.attacks, args.trials, args)
```

**NEW:**
```python
            applied, ok = set_config(layers, applied)
            if not ok:
                log(f"  HALTING {config_label} — apply/remove failed before any invariant check ran")
                continue
            wait_stable()
            run_trials(con, run_id, config_label, layers,
                       args.attacks, args.trials, args)
```

### 3c. `run_dl_robust()` (~line 1614) — identical shape to 3b

**OLD:**
```python
                applied = set_config(layers, applied)
                wait_stable()
                run_trials(con, run_id, config_label, layers,
                           args.attacks, args.trials, args)
```

**NEW:**
```python
                applied, ok = set_config(layers, applied)
                if not ok:
                    log(f"  HALTING {config_label} — apply/remove failed before any invariant check ran")
                    continue
                wait_stable()
                run_trials(con, run_id, config_label, layers,
                           args.attacks, args.trials, args)
```

### 3d. `run_l2_l3a_sep()` — uses `set_config_k3s()`

Search for its `applied = set_config_k3s(...)` call (same file, in the
k3s-separation section) and apply the identical `applied, ok = ...` /
`if not ok: ... continue` treatment.

---

## Why `continue` and not `raise`/`sys.exit`

Matches the existing failure-handling convention in this file exactly:
`run_trials()` already does `log(...HALTING...); return` on a Tier 1/2
failure and lets the outer loop move on to the next config/sample rather
than aborting the whole run. This patch just moves that same HALT-and-move-on
behavior one step earlier, for the specific case where the cause is already
known (the apply/remove script itself failed) rather than waiting to
re-discover it generically through Tier 1.
