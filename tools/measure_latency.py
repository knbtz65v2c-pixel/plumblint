#!/usr/bin/env python3
"""Measure scan() latency on a fixed workload; emit a number for CI.

README must not carry a hand-typed "worst case 10 ms": the figure would be
unreproducible and machine-dependent. Latency belongs to a
measurement, printed by CI on the runner it ran on, not asserted in prose.

Prints median and p95 microseconds over the corpus plus a few adversarial
inputs, and (with --json) a machine-readable line. Growth being linear is the
property that matters; the absolute number is reported with its machine.
"""

import json
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from plumblint import scan
from plumblint.detector import MAX_INPUT_CHARS


def _workload():
    rows = [json.loads(l) for l in
            (ROOT / "data" / "corpus.jsonl").read_text().splitlines() if l.strip()]
    texts = [r["text"] for r in rows]
    # a few near-limit adversarial shapes (bounded by the scan window)
    texts.append("a " * (MAX_INPUT_CHARS // 2))
    texts.append("QUJD" * (MAX_INPUT_CHARS // 8))  # base64-ish blob
    texts.append("i g n o r e " * 200)
    return texts


def measure(reps: int = 3):
    texts = _workload()
    samples = []
    for _ in range(reps):
        for t in texts:
            t0 = time.perf_counter()
            scan(t)
            samples.append((time.perf_counter() - t0) * 1e6)  # microseconds
    samples.sort()
    return {
        "n_calls": len(samples),
        "median_us": round(statistics.median(samples), 1),
        "p95_us": round(samples[int(len(samples) * 0.95)], 1),
        "max_us": round(samples[-1], 1),
        "python": platform.python_version(),
        "machine": platform.machine(),
    }


def main(argv) -> int:
    m = measure()
    if "--json" in argv:
        print(json.dumps(m))
    else:
        print(f"scan() latency over {m['n_calls']} calls "
              f"(python {m['python']}, {m['machine']}):")
        print(f"  median {m['median_us']} us | p95 {m['p95_us']} us | "
              f"max {m['max_us']} us")
        print("  (absolute numbers are machine-dependent; linear growth is the "
              "property, not a fixed millisecond claim)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
