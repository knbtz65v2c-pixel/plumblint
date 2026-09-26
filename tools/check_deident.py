#!/usr/bin/env python3
"""Gate: no owner-identifying strings and no non-ASCII in shipped files.

A published baseline must not carry the author's machine paths, real name, or
stray non-ASCII (which earlier crept in from a working session). This runs in
CI on every push so a leak cannot merge.

Exit 0: clean. Exit 1: any hit, each printed with file:line.

Scope is the shipped tree only.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Owner-identifying patterns. The home path and the real name must never ship.
FORBIDDEN = [
    re.compile(r"/Users/[a-z]"),
    re.compile(r"\bFuad\b"),
    re.compile(r"\bPoladov\b"),
    re.compile(r"MacBook-Pro", re.IGNORECASE),
]

# Legitimate, deliberate occurrences (owner attribution, and the guard's own
# pattern definitions). Each is a (file, substring) pair, so the rest of those
# files is still scanned.
ALLOW = {
    ("tests/test_plumblint.py", '/Users/'),   # asserts CLI does NOT leak it
    ("LICENSE", "Poladov"),                       # owner's chosen attribution
    ("LICENSE", "Fuad"),                          # owner's chosen attribution
    ("pyproject.toml", "Poladov"),                # package author
    ("pyproject.toml", "Fuad"),                   # package author
    ("tools/check_deident.py", "Fuad"),           # pattern definition site
    ("tools/check_deident.py", "Poladov"),
    ("tools/check_deident.py", "MacBook-Pro"),
    ("tools/check_deident.py", "/Users/"),
}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "build", "dist"}
SKIP_SUFFIX = {".pyc"}


def _files():
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix in SKIP_SUFFIX:
            continue
        yield p


def main() -> int:
    problems = []
    for p in _files():
        rel = p.relative_to(ROOT).as_posix()
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat in FORBIDDEN:
                if pat.search(line):
                    if any(rel == f and tok in line for f, tok in ALLOW):
                        continue
                    problems.append(f"{rel}:{i}  identifying: {line.strip()[:70]}")
            non_ascii = [c for c in line if ord(c) > 127]
            if non_ascii:
                sample = "".join(f"U+{ord(c):04X}" for c in non_ascii[:4])
                problems.append(f"{rel}:{i}  non-ASCII [{sample}]: {line.strip()[:50]}")
    if problems:
        print(f"check_deident: {len(problems)} issue(s)")
        for p in problems[:40]:
            print("  -", p)
        return 1
    print("check_deident: clean (no identifying strings, ASCII only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
