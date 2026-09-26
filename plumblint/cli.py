"""CLI: plumblint [text | -f file | -] [--json] [--strict]

Exit codes are a contract (CI branches on them), so failure modes must not
collide with verdicts:

    0  clean
    1  suspicious
    2  injection (and suspicious under --strict)
    3  input error: no input, empty input, unreadable file, input longer
       than the scan window (a silent prefix-only verdict would read as
       "clean" to the caller - refusing is the honest answer)
    64 usage error

Code 3 keeps input failures distinct from verdicts. A missing file or empty
stdin must never look like a clean or suspicious scan, and tracebacks must not
leak installation paths.
"""

import argparse
import json
import sys

from .detector import scan
from . import __version__

_COLOR = {"clean": "\033[32m", "suspicious": "\033[33m", "injection": "\033[31m"}
_RESET = "\033[0m"
EXIT_CLEAN, EXIT_SUSPICIOUS, EXIT_INJECTION, EXIT_ERROR, EXIT_USAGE = 0, 1, 2, 3, 64


def _render(v, use_color: bool) -> str:
    tag = v.verdict.upper()
    if use_color:
        tag = f"{_COLOR[v.verdict]}{tag}{_RESET}"
    lines = [f"{tag}  score={v.score:.3f}"]
    if v.obfuscation_detected:
        lines.append("  ! obfuscation: signal visible only after normalisation")
    if v.truncated:
        lines.append("  ! input truncated at limit")
    for s in v.signals:
        mit = f"  mitigated: {', '.join(s.mitigated_by)}" if s.mitigated_by else ""
        lines.append(f"  [{s.name}] weight={s.weight:.3f}{mit}")
        lines.append(f"      evidence: {s.evidence!r}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="plumblint",
        description="Prompt injection detector. Zero dependencies, no network calls.",
    )
    ap.add_argument("text", nargs="?", help="text to scan; '-' reads stdin")
    ap.add_argument("-f", "--file", help="read the text from a file")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--strict", action="store_true",
                    help="treat suspicious as injection (exit code 2)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"plumblint {__version__}")
    args = ap.parse_args(argv)

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            # One line, no traceback: a traceback prints absolute paths of
            # the installation, and the interpreter's exit 1 collides with
            # EXIT_SUSPICIOUS.
            print(f"error: cannot read input file: {exc.strerror or exc}",
                  file=sys.stderr)
            return EXIT_ERROR
    elif args.text == "-" or (args.text is None and not sys.stdin.isatty()):
        text = sys.stdin.read()
    elif args.text is not None:
        text = args.text
    else:
        ap.print_help()
        return EXIT_USAGE

    if not text.strip():
        print("error: empty input - nothing was scanned", file=sys.stderr)
        return EXIT_ERROR

    from .detector import MAX_INPUT_CHARS
    if len(text) > MAX_INPUT_CHARS:
        print(f"error: input is {len(text)} chars, scan window is "
              f"{MAX_INPUT_CHARS}; a verdict would cover only a prefix. "
              f"Split the input and scan the parts.", file=sys.stderr)
        return EXIT_ERROR

    v = scan(text)

    if args.json:
        print(json.dumps(v.to_dict(), ensure_ascii=False, indent=2))
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        print(_render(v, use_color))

    if v.verdict == "injection":
        return EXIT_INJECTION
    if v.verdict == "suspicious":
        return EXIT_INJECTION if args.strict else EXIT_SUSPICIOUS
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
