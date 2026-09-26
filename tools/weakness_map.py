#!/usr/bin/env python3
"""Generate WEAKNESS_MAP.md from the bypass corpus, and check it.

report-from-ledger discipline: the numbers and the case table live inside an
AUTO block generated from data/bypass_corpus.jsonl. Prose around the block is
hand-written; anything with a number is generated. A guard checks the block is
byte-identical to a fresh generation, so the map cannot drift from the corpus.

  weakness_map.py --write   regenerate the AUTO block in WEAKNESS_MAP.md
  weakness_map.py --check   fail (exit 1) if the block differs from generation

The map is the "open card of weaknesses" the baseline publishes: every row is
a documented, reproducible way the detector fails, with a status decided by a
live run.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAP = ROOT / "WEAKNESS_MAP.md"
CORPUS = ROOT / "data" / "bypass_corpus.jsonl"

BEGIN = "<!-- AUTO:weakness-table -->"
END = "<!-- /AUTO:weakness-table -->"


def _rows() -> list:
    if not CORPUS.exists():
        raise SystemExit("bypass corpus missing - run tools/build_bypass_corpus.py")
    return [json.loads(l) for l in CORPUS.read_text().splitlines() if l.strip()]


def _cell(text: str) -> str:
    # a pipe would split the markdown cell
    return text.replace("|", "\\|")


def generate_block() -> str:
    rows = _rows()
    bypasses = [r for r in rows if r["risk_class"] != "control"]
    caught = sum(1 for r in bypasses if r["status"] == "MITIGATED")
    n = len(bypasses)
    lines = [
        BEGIN,
        f"**Known-bypass coverage: {caught} of {n} caught.** Each row is a "
        "reproducible input on which the detector fails to return the "
        "`injection` verdict. Status is decided by a live "
        "`scan()` in tools/build_bypass_corpus.py, not asserted here.",
        "",
        "| status | case | verdict | note |",
        "|---|---|---|---|",
    ]
    for r in bypasses:
        lines.append(
            f"| {r['status']} | `{r['case_id']}` "
            f"| {r['verdict']} ({r['score']}) | {_cell(r['note'])} |"
        )
    lines.append(END)
    return "\n".join(lines)


def _skeleton() -> str:
    return f"""# Weakness map

This detector is a **baseline**, not an impenetrable guard. Its known ways of
failing are listed here as reproducible cases rather than left for a buyer to
discover. The table below is generated from `data/bypass_corpus.jsonl` by
`tools/weakness_map.py`; do not edit it by hand - edit the corpus builder and
regenerate. A CI guard (`--check`) fails if the table drifts from the corpus.

Each case is one input derived from a single canonical payload put through a
transform documented in `plumblint/normalize.py`.

{BEGIN}
{END}

## Not in this table, stated plainly

- **Paraphrase.** An injection reworded in ordinary English, with no
  characteristic phrase, is missed. This is the same gap the default-mode
  recall (0.534) already reports; it is a property of a lexical detector, not
  a separate defect.
- **Non-English text.** All rules are English; other languages pass.
- **Semantic / multi-turn attacks.** Persuasion and gradual context poisoning
  across turns carry no lexical marker and are out of scope for a single-turn
  rule engine.

These are named because a baseline that hid them would not be honest; closing
them would mean a different class of tool (this one adds no model and makes no
network call, by design).
"""


def write() -> int:
    block = generate_block()
    if MAP.exists():
        text = MAP.read_text()
        if BEGIN in text and END in text:
            head = text[: text.index(BEGIN)]
            tail = text[text.index(END) + len(END):]
            MAP.write_text(head + block + tail)
        else:
            raise SystemExit("markers missing in WEAKNESS_MAP.md")
    else:
        skel = _skeleton()
        MAP.write_text(skel.replace(f"{BEGIN}\n{END}", block))
    print(f"weakness_map: written ({block.count(chr(10))+1} lines in block)")
    return 0


def check() -> int:
    if not MAP.exists():
        print("WEAKNESS_MAP.md missing - run --write")
        return 1
    text = MAP.read_text()
    if BEGIN not in text or END not in text:
        print("WEAKNESS_MAP.md: AUTO markers missing")
        return 1
    current = text[text.index(BEGIN): text.index(END) + len(END)]
    expected = generate_block()
    if current != expected:
        print("WEAKNESS_MAP.md: AUTO block is stale - run tools/weakness_map.py --write")
        return 1
    print("weakness_map: AUTO block matches corpus")
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
