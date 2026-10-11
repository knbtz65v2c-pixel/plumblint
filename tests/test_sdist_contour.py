"""The source distribution carries a gate that runs from it.

Two properties, each tied to a failure observed when tools/ci_checks.py was run
inside an unpacked sdist:

1. Every file the gate reads from the source tree is shipped. The workflow
   test reads .github/workflows/ci.yml; MANIFEST.in did not include it, so the
   suite errored in the sdist (FileNotFoundError - an error, not an assertion).
2. The de-identification guard accepts the packaging metadata setuptools
   writes from pyproject.toml. The declared author lands in PKG-INFO and in
   plumblint.egg-info/PKG-INFO; the guard flagged that line in the sdist,
   although the same author is allowed in pyproject.toml itself. Only that
   exact line is accepted: anything else in those files is still scanned.

The author name is read from pyproject.toml, so this file carries no
identifying literal of its own.
"""

import fnmatch
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Files the gate reads from the source tree (tools/ci_checks.py, the tools it
# runs, calibrate.py and the suite). Literal: a new input belongs here AND in
# MANIFEST.in. pyproject.toml and the package modules are always shipped by
# the build backend and are not listed.
GATE_INPUTS = [
    ".github/workflows/ci.yml",
    "CONTRACT.md",
    "LICENSE",
    "README.md",
    "WEAKNESS_MAP.md",
    "calibrate.py",
    "data/bypass_corpus.jsonl",
    "data/corpus.jsonl",
    "data/holdout_assignment.json",
    "tests/test_plumblint.py",
    "tests/test_sdist_contour.py",
    "tools/build_bypass_corpus.py",
    "tools/check_constants.py",
    "tools/check_deident.py",
    "tools/ci_checks.py",
    "tools/measure_latency.py",
    "tools/readme_stats.py",
    "tools/split_holdout.py",
    "tools/weakness_map.py",
]


def manifest_ships(path, lines):
    """Whether MANIFEST.in `lines` ship the relative `path`.

    Evaluates the directives this project uses, in order, later lines winning
    as in setuptools: include, exclude, recursive-include, recursive-exclude,
    global-include, global-exclude, graft, prune. Any other directive raises,
    so an unfamiliar rule cannot be silently read as "not shipped".
    """
    name = path.rsplit("/", 1)[-1]
    shipped = False
    for raw in lines:
        parts = raw.split()
        if not parts or parts[0].startswith("#"):
            continue
        cmd, args = parts[0], parts[1:]
        if cmd in ("include", "exclude"):
            hit = any(fnmatch.fnmatchcase(path, p) for p in args)
        elif cmd in ("recursive-include", "recursive-exclude"):
            top, pats = args[0].rstrip("/"), args[1:]
            hit = path.startswith(top + "/") and any(fnmatch.fnmatchcase(name, p) for p in pats)
        elif cmd in ("global-include", "global-exclude"):
            hit = any(fnmatch.fnmatchcase(name, p) for p in args)
        elif cmd in ("graft", "prune"):
            hit = path.startswith(args[0].rstrip("/") + "/")
        else:
            raise ValueError(f"unknown MANIFEST.in directive {cmd!r}")
        if hit:
            shipped = cmd in ("include", "recursive-include", "global-include", "graft")
    return shipped


class TestSdistShipsTheGateInputs(unittest.TestCase):

    def test_the_evaluator_on_known_rules(self):
        """The evaluator itself, against literal expectations."""
        rules = ["include LICENSE", "recursive-include tests *.py",
                 "recursive-include .github/workflows *.yml",
                 "global-exclude *.py[cod]", "# a comment"]
        table = {
            "LICENSE": True,
            "tests/test_x.py": True,
            "tests/test_x.pyc": False,
            ".github/workflows/ci.yml": True,
            ".github/dependabot.yml": False,
            "notes.txt": False,
            "data/corpus.jsonl": False,
        }
        for path, want in table.items():
            with self.subTest(path=path):
                self.assertIs(manifest_ships(path, rules), want)
        with self.assertRaises(ValueError):
            manifest_ships("LICENSE", ["recursive-graft x"])

    def test_manifest_ships_every_gate_input(self):
        lines = (ROOT / "MANIFEST.in").read_text().splitlines()
        missing = [p for p in GATE_INPUTS if not manifest_ships(p, lines)]
        self.assertEqual(missing, [], "gate inputs left out of the sdist")


class TestDeidentAcceptsGeneratedMetadata(unittest.TestCase):
    """The real guard script, run on a small tree laid out like an sdist."""

    @classmethod
    def setUpClass(cls):
        meta = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        cls.author = meta["authors"][0]["name"]
        cls.author_line = f"Author: {cls.author}"

    def _guard(self, files):
        tmp = Path(tempfile.mkdtemp(prefix="plumblint-deident-"))
        try:
            (tmp / "tools").mkdir()
            shutil.copy(ROOT / "tools/check_deident.py", tmp / "tools/check_deident.py")
            for rel, text in files.items():
                p = tmp / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            r = subprocess.run([sys.executable, "-B", "tools/check_deident.py"],
                               cwd=str(tmp), capture_output=True, text=True)
            return r.returncode, r.stdout
        finally:
            shutil.rmtree(tmp)

    def _pkg_info(self, *extra):
        return "\n".join(["Metadata-Version: 2.4", "Name: plumblint",
                          "Version: 0.0.0", self.author_line, *extra]) + "\n"

    def test_generated_author_line_is_accepted(self):
        rc, out = self._guard({"PKG-INFO": self._pkg_info(),
                               "plumblint.egg-info/PKG-INFO": self._pkg_info()})
        self.assertEqual(rc, 0, out)
        self.assertIn("clean", out)

    def test_the_same_line_elsewhere_is_still_flagged(self):
        rc, out = self._guard({"notes.md": self.author_line + "\n"})
        self.assertEqual(rc, 1, out)
        self.assertIn("notes.md:1", out)

    def test_other_lines_of_the_metadata_are_still_scanned(self):
        home = "/Users/" + "someone/project"
        cases = {
            "another field naming the author": f"Maintainer: {self.author}",
            "a home path": f"Home-page: file://{home}",
        }
        for label, line in cases.items():
            with self.subTest(label):
                rc, out = self._guard({"PKG-INFO": self._pkg_info(line)})
                self.assertEqual(rc, 1, out)
                self.assertIn("PKG-INFO:5", out)


if __name__ == "__main__":
    unittest.main()
