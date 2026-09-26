#!/usr/bin/env python3
"""One local gate that mirrors the CI build, runnable without network.

CI (.github/workflows/ci.yml) runs the same steps across a Python matrix. This
script runs them once here, so the workflow is validated before it is pushed
and can be re-run locally. It contains NO model calls and NO network: every
step is plain code over the shipped tree.

Split into two groups, deliberately:

  GATE steps decide the build (exit 1 on any failure): the test suite and the
  five guards (constants+freeze, weakness map, readme stats, holdout split,
  deidentification), plus the CLI exit-code and HTTP-smoke sanity.

  REPORT steps always run and print, but never fail the build: the calibration
  run and the latency measurement. Calibration legitimately exits non-zero
  (default recall is below the guard bar; hard-negative false alarms sit in the
  grey zone) - those are documented, reported states, not build breakers. This
  mirrors CONTRACT.md v2: recall is reported, not gated; the badge means "the
  contracts and guards hold", and the numbers are in the log for the reader.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def _run(name, args, gating):
    print(f"\n=== {name} ===")
    r = subprocess.run([PY, "-B", *args], cwd=str(ROOT))
    ok = r.returncode == 0
    tag = "PASS" if ok else ("FAIL" if gating else "reported (non-gating)")
    print(f"--- {name}: exit {r.returncode} -> {tag}")
    return ok if gating else True


GATE = [
    ("unit tests", ["-m", "unittest", "discover", "-s", "tests"]),
    ("constants+freeze", ["tools/check_constants.py"]),
    ("bypass corpus vs live detector", ["tools/build_bypass_corpus.py", "--verify"]),
    ("weakness map", ["tools/weakness_map.py", "--check"]),
    ("readme stats", ["tools/readme_stats.py", "--check"]),
    ("holdout split", ["tools/split_holdout.py", "--check"]),
    ("deidentification", ["tools/check_deident.py"]),
]

REPORT = [
    ("calibration (reported)", ["calibrate.py"]),
    ("bypass coverage (reported)", ["calibrate.py", "--bypass"]),
    ("latency (reported)", ["tools/measure_latency.py"]),
    ("holdout partition recall (reported)", ["tools/split_holdout.py", "--report"]),
]


def main() -> int:
    failures = []
    for name, args in GATE:
        if not _run(name, args, gating=True):
            failures.append(name)
    for name, args in REPORT:
        _run(name, args, gating=False)
    print("\n" + "=" * 60)
    if failures:
        print(f"CI GATE: FAIL ({', '.join(failures)})")
        return 1
    print("CI GATE: all gating checks PASS")
    print("(calibration and latency are reported above, not gated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
