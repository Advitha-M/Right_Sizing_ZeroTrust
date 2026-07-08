"""
oracle.py — outcome classification for attack results.

Each attack script prints a single line:  STATUS|detail
   SUCCESS|<which technique>     attack objective achieved
   BLOCKED|<reason>             all techniques blocked by the active controls
   PARTIAL|<reason>             partial progress (e.g. lateral chain depth 1)
   SKIP|<reason>               preconditions not met (e.g. no attacker pod)

The oracle normalizes this into a structured verdict the driver records.
"""
from dataclasses import dataclass
from typing import Optional
import re

VALID = {"SUCCESS", "BLOCKED", "PARTIAL", "SKIP", "ERROR", "TIMEOUT"}


@dataclass
class Verdict:
    outcome: str            # one of VALID
    detail: str             # human-readable detail / which technique
    chain_depth: Optional[int] = None   # pivot depth, when an attack script
                                         # reports one (e.g. A5 lateral
                                         # movement). Recorded as metadata
                                         # only — see success_bit below.
    raw: str = ""

    @property
    def success_bit(self) -> int:
        """Binary success indicator for ASR computation.

        Per the brief's conservative scoring rule (Section 4):
        outcome(t,k,j) = true only if the attack script itself
        programmatically verifies its full stated objective was achieved.
        That is a binary self-report from the script's own SUCCESS/BLOCKED/
        PARTIAL/SKIP line — success_bit is 1 iff outcome == "SUCCESS",
        full stop. chain_depth is recorded metadata (e.g. for reporting
        A5 pivot depth) and does NOT feed into this determination; there
        is no chain_depth threshold anywhere in this function, and PARTIAL
        is never counted as success.
        """
        return 1 if self.outcome == "SUCCESS" else 0


def classify(raw_output: str, returncode: int = 0, timed_out: bool = False) -> Verdict:
    """Turn raw attack stdout + exit status into a Verdict."""
    if timed_out:
        return Verdict("TIMEOUT", "attack exceeded timeout", raw=raw_output)

    if not raw_output or not raw_output.strip():
        return Verdict("ERROR", "no output from attack", raw=raw_output)

    # take the last non-empty line that looks like STATUS|detail
    line = ""
    for ln in reversed(raw_output.strip().splitlines()):
        ln = ln.strip()
        if "|" in ln and ln.split("|", 1)[0] in VALID:
            line = ln
            break
    if not line:
        # fallback: scan for a bare keyword
        for kw in VALID:
            if kw in raw_output:
                return Verdict(kw, "inferred from output", raw=raw_output)
        return Verdict("ERROR", "unparseable output", raw=raw_output)

    parts = line.split("|")
    status = parts[0].strip()
    detail = parts[-1].strip() if len(parts) > 1 else ""

    # extract chain depth if present (A5 lateral movement pivot depth:
    # SUCCESS|chain-depth=3|...). Metadata only — see success_bit.
    depth = None
    m = re.search(r"chain-depth=(\d+)", line)
    if m:
        depth = int(m.group(1))

    return Verdict(status, detail, chain_depth=depth, raw=raw_output)
