#!/usr/bin/env python3
"""Generate the calibration numbers in README.md from a live corpus run.

report-from-ledger discipline applied to the sales document: the headline
calibration table is produced by running the corpus through the shipped
detector, not typed by hand. A guard (--check) fails if the block in README
drifts from a fresh run, so a number in the README cannot silently disagree
with what the code actually does.

  readme_stats.py --write   regenerate the AUTO block in README.md
  readme_stats.py --check   fail (exit 1) if the block is stale

Only the operating-point table lives in the block; the surrounding prose is
hand-written. Numbers outside the block that duplicate these would be a place
for drift, so the prose refers to the block rather than repeating figures.
"""

import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
sys.path.insert(0, str(ROOT))

BEGIN = "<!-- AUTO:calibration -->"
END = "<!-- /AUTO:calibration -->"


def _wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def _measure():
    from plumblint import scan
    from collections import Counter
    rows = [json.loads(l) for l in
            (ROOT / "data" / "corpus.jsonl").read_text().splitlines() if l.strip()]
    n = Counter(r["label"] for r in rows)
    inj = [r for r in rows if r["label"] == "injection"]
    hit = sum(1 for r in inj if scan(r["text"]).verdict == "injection")
    hit_s = sum(1 for r in inj if scan(r["text"]).verdict in ("injection", "suspicious"))

    # A false alarm is a negative the mode would BLOCK. Default mode blocks
    # only `injection`, so a negative that scores `suspicious` is not a false
    # alarm there; strict mode blocks `suspicious` too. Counting them the same
    # was wrong (it made default's hard-negative rate read 7/30 instead of the
    # correct 0/30).
    def fp(label, mode):
        rr = [r for r in rows if r["label"] == label]
        blocked = (("injection",) if mode == "default"
                   else ("injection", "suspicious"))
        return sum(1 for r in rr if scan(r["text"]).verdict in blocked), len(rr)
    return {
        "inj_n": len(inj), "hit": hit, "hit_s": hit_s,
        "easy_fp_d": fp("easy_negative", "default")[0],
        "hard_fp_d": fp("hard_negative", "default")[0],
        "easy_fp_s": fp("easy_negative", "strict")[0],
        "hard_fp_s": fp("hard_negative", "strict")[0],
        "easy_n": fp("easy_negative", "default")[1],
        "hard_n": fp("hard_negative", "default")[1],
    }


def _pct(k, n):
    lo, hi = _wilson(k, n)
    return f"{k}/{n} = **{k/n:.3f}** [{lo:.3f}, {hi:.3f}]"


def generate_block() -> str:
    m = _measure()
    return "\n".join([
        BEGIN,
        "Generated from a live corpus run by `tools/readme_stats.py`; the CI"
        " guard fails if this drifts from the code. Recall is reported, not"
        " gated (CONTRACT.md v2); the gate is on false alarms.",
        "",
        "| operating point | recall | false alarms, ordinary | false alarms, security-talk |",
        "|---|---|---|---|",
        f"| `injection` only (default) | {_pct(m['hit'], m['inj_n'])} "
        f"| {_pct(m['easy_fp_d'], m['easy_n'])} | {_pct(m['hard_fp_d'], m['hard_n'])} |",
        f"| `+suspicious` (strict, in-sample*) | {_pct(m['hit_s'], m['inj_n'])} "
        f"| {_pct(m['easy_fp_s'], m['easy_n'])} | {_pct(m['hard_fp_s'], m['hard_n'])} |",
        "",
        "*strict recall is in-sample (the `suspicious`-blocks decision was made"
        " after seeing this corpus); it never gates. Known-bypass coverage is a"
        " separate table - run `calibrate.py --bypass`.",
        END,
    ])


def write() -> int:
    block = generate_block()
    text = README.read_text()
    if BEGIN not in text or END not in text:
        print("README.md: AUTO:calibration markers missing - add them first")
        return 1
    head = text[: text.index(BEGIN)]
    tail = text[text.index(END) + len(END):]
    README.write_text(head + block + tail)
    print("readme_stats: calibration block written")
    return 0


def check() -> int:
    if not README.exists():
        print("README.md missing")
        return 1
    text = README.read_text()
    if BEGIN not in text or END not in text:
        print("README.md: AUTO:calibration markers missing")
        return 1
    current = text[text.index(BEGIN): text.index(END) + len(END)]
    if current != generate_block():
        print("README.md: calibration block is stale - run tools/readme_stats.py --write")
        return 1
    print("readme_stats: calibration block matches live run")
    return 0


def main(argv) -> int:
    if "--write" in argv:
        return write()
    if "--check" in argv:
        return check()
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
