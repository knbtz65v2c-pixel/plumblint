#!/usr/bin/env python3
"""Freeze a deterministic partition of the calibration corpus.

IMPORTANT: this is a POST-HOC partition, not a true held-out
cohort. The rules were developed against the whole corpus before
this split existed, so the "holdout" slice was in fact seen during rule
development. The train-vs-holdout recall gap is therefore a research-style
comparison with wide, overlapping intervals - it is NOT proof of, or a clean
measurement of, in-sample tuning. A real held-out result needs either a new
unseen corpus, or a split frozen PROSPECTIVELY before the next rule change.
The split is frozen here so that, from now on, such a prospective discipline
is possible and any re-split is visible in the diff.

The split is deterministic (sha1 of the text, not RNG state), so it is stable
across machines and reproducible without storing a seed. Ratio is fixed here,
before looking at any per-slice number, and the assignment is frozen to a file
so a later "re-split until it looks better" is visible in the diff.

  split_holdout.py --write   write data/holdout_assignment.json
  split_holdout.py --check   fail if the live split differs from the frozen one

This is the LOCAL half of the methodology. The external, independently authored
public attack set (the part that would actually make the numbers independent)
is BLOCKED: no network in this environment, and licences must be checked before
inclusion. That gap is recorded, not filled with a stand-in.
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CORPUS = ROOT / "data" / "corpus.jsonl"
ASSIGN = ROOT / "data" / "holdout_assignment.json"
HOLDOUT_RATIO = 0.30  # fixed before any per-slice number was seen


def _rows():
    return [json.loads(l) for l in CORPUS.read_text().splitlines() if l.strip()]


def assign() -> dict:
    """Deterministic per-row slice from the hash of its text.

    Bottom HOLDOUT_RATIO of the hash space -> holdout; the rest -> train.
    Stratified by label so each slice keeps injections and negatives.
    """
    out = {}
    for row in _rows():
        key = f"{row['label']}|{row['text']}"
        h = int(hashlib.sha1(key.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
        out[key] = "holdout" if h < HOLDOUT_RATIO else "train"
    return out


def write() -> int:
    a = assign()
    ASSIGN.write_text(json.dumps(a, ensure_ascii=True, indent=0, sort_keys=True))
    from collections import Counter
    c = Counter(a.values())
    print(f"split_holdout: train={c['train']} holdout={c['holdout']} "
          f"(ratio {HOLDOUT_RATIO}) -> {ASSIGN.name}")
    return 0


def check() -> int:
    if not ASSIGN.exists():
        print("holdout assignment missing - run --write")
        return 1
    frozen = json.loads(ASSIGN.read_text())
    live = assign()
    if frozen != live:
        moved = sum(1 for k in set(frozen) | set(live)
                    if frozen.get(k) != live.get(k))
        print(f"split_holdout: assignment drifted ({moved} rows) - "
              f"corpus changed or ratio changed; run --write in the same change")
        return 1
    print(f"split_holdout: frozen assignment matches ({len(live)} rows)")
    return 0


def report() -> int:
    """Recall on the train slice vs the held-out slice, side by side.

    Reported, never gated. NOTE this is a post-hoc partition (see module
    docstring): the rules were developed against the whole corpus, so this gap
    is a research comparison with wide overlapping intervals, not proof of
    in-sample tuning. Kept because a prospective freeze from here on can turn
    it into a real held-out signal.
    """
    import math
    from plumblint import scan
    assign = json.loads(ASSIGN.read_text()) if ASSIGN.exists() else assign_or_die()
    rows = _rows()

    def wilson(k, n):
        if n == 0:
            return (0.0, 1.0)
        p, z = k / n, 1.96
        d = 1 + z * z / n
        c = (p + z * z / (2 * n)) / d
        h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
        return (max(0.0, c - h), min(1.0, c + h))

    print("HELD-OUT vs TRAIN recall (default mode, reported, not gated)")
    for slice_name in ("train", "holdout"):
        inj = [r for r in rows if r["label"] == "injection"
               and assign.get(f"{r['label']}|{r['text']}") == slice_name]
        hit = sum(1 for r in inj if scan(r["text"]).verdict == "injection")
        n = len(inj)
        if n:
            lo, hi = wilson(hit, n)
            print(f"  {slice_name:8} recall {hit}/{n} = {hit/n:.3f}  [{lo:.3f}, {hi:.3f}]")
        else:
            print(f"  {slice_name:8} no injections in slice")
    return 0


def assign_or_die():
    raise SystemExit("holdout assignment missing - run --write")


def main(argv) -> int:
    if "--write" in argv:
        return write()
    if "--check" in argv:
        return check()
    if "--report" in argv:
        return report()
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
