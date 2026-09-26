#!/usr/bin/env python3
"""Gate: every tunable constant equals its declared value in CONTRACT.md.

This check compares values, fails loudly, and runs in CI on every push. A
changed number cannot merge with a green build unless CONTRACT.md is edited in
the same change, which is exactly the visibility promised.

Exit 0: all declared constants match the code. Exit 1: any mismatch,
each printed with both values. Exit 2: the declaration table is missing
or unparseable.
"""

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ROW = re.compile(r"^\|\s*`([A-Za-z_.\[\]\"']+)`\s*\|\s*([0-9.]+)\s*\|")


def declared_constants(contract_text: str) -> dict:
    rows = {}
    in_table = False
    for line in contract_text.splitlines():
        if line.strip().startswith("| constant"):
            in_table = True
            continue
        if in_table:
            m = ROW.match(line.strip())
            if m:
                rows[m.group(1)] = float(m.group(2))
            elif line.strip() and not line.strip().startswith("|--"):
                in_table = False
    return rows


def actual_constants() -> dict:
    from plumblint import detector as d
    from plumblint import signals as sg
    import calibrate as cal
    values = {
        "THRESHOLD_SUSPICIOUS": d.THRESHOLD_SUSPICIOUS,
        "THRESHOLD_INJECTION": d.THRESHOLD_INJECTION,
        "OBFUSCATION_BOOST": d.OBFUSCATION_BOOST,
        "MAX_SINGLE_WEIGHT": d.MAX_SINGLE_WEIGHT,
        "MITIGATOR_QUOTED": sg.MITIGATOR_QUOTED,
        "MITIGATOR_INTERROGATIVE": sg.MITIGATOR_INTERROGATIVE,
        "MITIGATOR_META": sg.MITIGATOR_META,
        "MITIGATOR_NEGATED": sg.MITIGATOR_NEGATED,
        "RECALL_PASS": cal.RECALL_PASS,
        "RECALL_FAIL": cal.RECALL_FAIL,
        "EASY_FP_PASS": cal.EASY_FP_PASS,
        "EASY_FP_FAIL": cal.EASY_FP_FAIL,
        "HARD_FP_PASS": cal.HARD_FP_PASS,
        "HARD_FP_FAIL": cal.HARD_FP_FAIL,
    }
    for name, _, weight in sg._SIGNAL_SETS:
        values[f'weight["{name}"]'] = weight
    return values


FREEZE_ROW = re.compile(r"`data/corpus\.jsonl`\s*\|\s*\d+\s*\|\s*`([0-9a-f]{64})`")


def frozen_corpus_hash(contract_text: str):
    m = FREEZE_ROW.search(contract_text)
    return m.group(1) if m else None


def main() -> int:
    contract = (ROOT / "CONTRACT.md").read_text()
    declared = declared_constants(contract)
    if not declared:
        print("check_constants: declaration table not found in CONTRACT.md")
        return 2
    actual = actual_constants()
    problems = []
    for name, value in declared.items():
        if name not in actual:
            problems.append(f"declared but absent in code: {name}")
        elif abs(actual[name] - value) > 1e-12:
            problems.append(f"{name}: code={actual[name]} contract={value}")
    for name in actual:
        if name not in declared:
            problems.append(f"in code but not declared: {name}")

    # Corpus freeze: the file must match the hash frozen in CONTRACT.md.
    frozen = frozen_corpus_hash(contract)
    if frozen is None:
        problems.append("corpus freeze row missing from CONTRACT.md")
    else:
        actual_hash = hashlib.sha256(
            (ROOT / "data" / "corpus.jsonl").read_bytes()).hexdigest()
        if actual_hash != frozen:
            problems.append(
                f"corpus.jsonl sha256 {actual_hash} != frozen {frozen} "
                f"(update the freeze row in the same change)")

    if problems:
        print("check_constants: MISMATCH")
        for p in problems:
            print("  -", p)
        return 1
    print(f"check_constants: OK ({len(declared)} constants match, corpus frozen)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
