"""Detector assembly: variants -> signals -> score -> three-way verdict.

The thresholds are fixed HERE, in code, BEFORE the first run against the
calibration corpus. Changing them after seeing the results would be fitting
the instrument to the answer. If the thresholds turn out to be poor, that
is the measurement's result, not grounds for a second attempt.
"""

from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .normalize import variants
from .signals import _QUOTED_RE, Signal, find_signals

# --- THRESHOLDS -----------------------------------------------------------
# Declared by value in CONTRACT.md and enforced twice: tools/check_constants.py
# fails the build on any drift between these numbers and the declaration, and
# TestConstantsPinned asserts them inside the suite.
THRESHOLD_SUSPICIOUS = 0.30
THRESHOLD_INJECTION = 0.55

# Multiplier for a signal visible ONLY after obfuscation is stripped.
# Rationale: ordinary text is not written with zero-width characters and
# not spaced out letter by letter. A hidden instruction is nearly always
# deliberate.
OBFUSCATION_BOOST = 1.45
MAX_SINGLE_WEIGHT = 0.95

# --- WORK BOUNDS ------------------------------------------------------------
# WINDOW_OVERLAP_CHARS and MAX_SCAN_WINDOWS are declared by value in
# CONTRACT.md and checked by tools/check_constants.py; all of them, and the
# derived constants below, are pinned in TestConstantsPinned.
#
# One scan WINDOW is MAX_INPUT_CHARS characters: the fragment size the
# thresholds were calibrated on. An input longer than one window is not
# verdicted on its prefix (the payload hidden past the window was never seen,
# and the verdict read "clean"): it is cut into overlapping windows, each
# window is judged like a stand-alone fragment, and the input takes the worst
# window's verdict. Work stays bounded three ways:
#   * every window is at most MAX_WINDOW_TEXT_CHARS characters (a window is
#     MAX_INPUT_CHARS of input plus the few characters of seam context
#     described below);
#   * consecutive windows overlap by WINDOW_OVERLAP_CHARS, so a payload up to
#     WINDOW_OVERLAP_CHARS + 1 characters long that straddles a seam still
#     lies whole inside one window;
#   * at most MAX_SCAN_WINDOWS windows are scanned, i.e. MAX_SCAN_CHARS
#     characters. Nothing past that is inspected, and the result says so
#     (`truncated`). A payload placed beyond MAX_SCAN_CHARS is NOT detected:
#     any finite bound has this edge, it is documented, not hidden.
MAX_INPUT_CHARS = 8192
WINDOW_OVERLAP_CHARS = 512
MAX_SCAN_WINDOWS = 16

_WINDOW_STRIDE = MAX_INPUT_CHARS - WINDOW_OVERLAP_CHARS
MAX_SCAN_CHARS = MAX_INPUT_CHARS + (MAX_SCAN_WINDOWS - 1) * _WINDOW_STRIDE

# A window that does not start at the beginning of the input gets this
# prefix. Reason: `^` in a signal pattern means "start of the text"
# (`^\s*(?:system|assistant)\s*:`); a window cut mid-document is not the
# start of anything, and without the mark a chat log with a role label at
# exactly a seam would raise structure_spoof that the same log does not
# raise as one piece. "|" is not whitespace, not a letter or digit (no
# leetspeak / homoglyph / base64 / spaced-letter rule touches it), and is
# stable under NFKC.
_CONTINUATION_MARK = "|"

# --- SEAM CONTEXT: quotes are a property of the DOCUMENT, not of a window ----
# The quoted-mitigator pairs quote characters by position
# (signals._QUOTED_RE: the first `"` opens, the next closes). A window cut in
# the middle of a quoted span starts (or ends) with a delimiter whose partner
# is on the other side of the seam; read in isolation the window pairs that
# stray delimiter with the NEXT one, the pairing flips, the payload that sits
# inside its own quotes reads as un-quoted, the x0.35 quoted mitigator is
# lost, and a benign document that merely QUOTES a payload verbatim scores
# "injection" (measured in tests/test_bypass_truncation.py, class
# TestQuotedPayloadNoSeamFalseAlarm). Every quoted payload in a long document
# is cut by some seam at some offset, so this is a class, not a case.
#
# The fix keeps the window the calibrated unit and gives it the quote context
# it has in the document. The pairing is computed ONCE over a bounded global
# view (the scanned region plus one window of look-ahead, so that a span cut by
# the scan bound still closes), and each window whose start or end falls
# strictly inside a global quoted span is completed with synthetic delimiters:
#   * a start inside a span gets the span's opening delimiter, then
#     _EDGE_FILLER (quotes need >= 4 characters inside to pair at all);
#   * an end inside a span gets the span's closing delimiter;
#   * a start inside a 3-character fence delimiter is moved left to the
#     delimiter's first character (at most 2 characters), so the delimiter is
#     whole.
# The synthetic characters contain no letters or digits, so no signal rule and
# no normalisation step can match them or be changed by them. The two ends of
# the INPUT are not repaired: a quote that really is unclosed there is left as
# it is, exactly as a stand-alone fragment would be.
_PAIRING_VIEW_CHARS = MAX_SCAN_CHARS + MAX_INPUT_CHARS
_FENCE = "```"
_EDGE_FILLER = "...."
_CLOSERS = {'"': '"', "'": "'", "`": "`", "\u00ab": "\u00bb"}

# The longest window text handed to variants(): the input slice (up to
# len(_FENCE) - 1 characters longer than MAX_INPUT_CHARS when the start is
# moved to a whole fence delimiter), the continuation mark, the opening
# delimiter with its filler, and the closing delimiter.
MAX_WINDOW_TEXT_CHARS = (MAX_INPUT_CHARS + len(_FENCE) - 1
                         + len(_CONTINUATION_MARK)
                         + len(_FENCE) + len(_EDGE_FILLER)
                         + len(_FENCE))


@dataclass
class Verdict:
    """The result of scanning one fragment."""
    verdict: str                      # clean | suspicious | injection
    score: float
    signals: List[Signal] = field(default_factory=list)
    obfuscation_detected: bool = False
    # True iff part of the input was NOT inspected: it is longer than
    # MAX_SCAN_CHARS. An input of up to MAX_SCAN_CHARS characters is
    # inspected in full, however many windows that takes.
    truncated: bool = False

    def to_dict(self) -> Dict:
        return {
            "verdict": self.verdict,
            "score": round(self.score, 4),
            "obfuscation_detected": self.obfuscation_detected,
            "truncated": self.truncated,
            "signals": [
                {
                    "name": s.name,
                    "weight": s.weight,
                    "evidence": s.evidence,
                    "mitigated_by": s.mitigated_by,
                }
                for s in self.signals
            ],
        }


def _combine(weights: List[float]) -> float:
    """Probabilistic combination: 1 - prod(1 - w).

    Not a plain sum: two signals of 0.6 must not add up to 1.2.
    Not a maximum: two independent markers must outweigh one.
    """
    acc = 1.0
    for w in weights:
        acc *= (1.0 - min(max(w, 0.0), MAX_SINGLE_WEIGHT))
    return 1.0 - acc


def _scan_window(text: str, continued: bool = False,
                 opening: str = "", closing: str = "") -> Verdict:
    """Verdicts ONE window (at most MAX_WINDOW_TEXT_CHARS characters).

    `continued` marks a window that does not start at the beginning of the
    input (see _CONTINUATION_MARK). It is False for a fragment scanned whole.
    `opening` / `closing` are the synthetic seam-context delimiters (see SEAM
    CONTEXT); both are empty for a fragment scanned whole.
    """
    if not text.strip():
        return Verdict(verdict="clean", score=0.0)

    text = opening + text + closing
    if continued:
        text = _CONTINUATION_MARK + text

    all_variants = variants(text)
    has_alternate_variants = len(all_variants) > 1

    # Two independent facts are tracked separately on purpose:
    #   best[name]      - the strongest hit of that signal class anywhere;
    #   seen_in_plain   - whether that class appeared in the untouched input.
    # An earlier version derived the second from the first, which silently
    # assumed a signal's weight can never be higher in a normalised variant
    # than in the original. That assumption was never proved, so the flag
    # could invert and apply an obfuscation boost where nothing was hidden.
    best: Dict[str, Signal] = {}
    seen_in_plain: Set[str] = set()

    for idx, variant in enumerate(all_variants):
        for sig in find_signals(variant):
            if idx == 0:
                seen_in_plain.add(sig.name)
            prev = best.get(sig.name)
            if prev is None or sig.weight > prev.weight:
                best[sig.name] = sig

    obfuscation_detected = has_alternate_variants and any(
        name not in seen_in_plain for name in best
    )

    final_signals: List[Signal] = []
    for name, sig in best.items():
        weight = sig.weight
        if name not in seen_in_plain:
            weight = min(weight * OBFUSCATION_BOOST, MAX_SINGLE_WEIGHT)
            sig = Signal(
                name=sig.name,
                weight=round(weight, 4),
                evidence=sig.evidence,
                raw_weight=sig.raw_weight,
                mitigated_by=sig.mitigated_by + ["obfuscation_boost"],
            )
        final_signals.append(sig)

    final_signals.sort(key=lambda s: s.weight, reverse=True)
    score = _combine([s.weight for s in final_signals])

    if score >= THRESHOLD_INJECTION:
        label = "injection"
    elif score >= THRESHOLD_SUSPICIOUS:
        label = "suspicious"
    else:
        label = "clean"

    return Verdict(
        verdict=label,
        score=score,
        signals=final_signals,
        obfuscation_detected=obfuscation_detected,
    )


def _window_plan(length: int) -> List[Tuple[int, int]]:
    """(start, end) of every window of an input longer than one window.

    The window that reaches the end of the input is right-aligned
    (start = length - MAX_INPUT_CHARS) instead of being a short remainder: a
    short tail fragment has little surrounding context, and context is what
    the mitigators read. Measured on long legitimate stress documents
    (concatenated clean corpus rows): every non-clean verdict came from a
    short trailing fragment (tests/test_bypass_truncation.py::
    TestNoFalseAlarmFlood). Right-alignment only moves the start EARLIER, so
    the overlap with the previous window is still >= WINDOW_OVERLAP_CHARS.
    """
    plan = []
    for k in range(MAX_SCAN_WINDOWS):
        start = min(k * _WINDOW_STRIDE, length - MAX_INPUT_CHARS)
        plan.append((start, start + MAX_INPUT_CHARS))
        if start + MAX_INPUT_CHARS >= length:
            break
    return plan


def _spans_across_edges(text: str, edges: List[int],
                        view_end: int) -> Dict[int, Tuple[int, int]]:
    """{edge: (start, end)} of the global quoted span each edge falls
    STRICTLY inside (start < edge < end). Edges not inside any span are absent.

    One pass of the very regex the quoted-mitigator uses (so the two cannot
    disagree about what a quotation is), over text[:view_end] only. Spans are
    consumed as the regex yields them and none is kept except the at most
    two per window that an edge falls inside: memory is one copy of the view
    (at most _PAIRING_VIEW_CHARS characters), however many spans there are.
    """
    edges = sorted(edges)
    found: Dict[int, Tuple[int, int]] = {}
    if not edges:
        return found
    view = text[:view_end]
    # `\u00ab[^\u00bb]+\u00bb` re-scans to the end of the view from EVERY
    # opener that has no closer after it, which is quadratic in the view (131k
    # openers: 5 s; the same input cut into windows: 0.4 s). An opener after
    # the last closer can never start a span and, as text, is inert to every
    # other alternative, so it is blanked: same positions, same spans.
    tail = view.rfind("\u00bb") + 1
    if "\u00ab" in view[tail:]:
        view = view[:tail] + view[tail:].replace("\u00ab", " ")
    last = edges[-1]
    for m in _QUOTED_RE.finditer(view):
        start, end = m.span()
        if start >= last:
            break
        i = bisect_right(edges, start)
        while i < len(edges) and edges[i] < end:
            found[edges[i]] = (start, end)
            i += 1
    return found


def _delimiters(text: str, span_start: int) -> Optional[Tuple[str, str]]:
    """(opening, closing) delimiter of the quoted span starting there."""
    if text.startswith(_FENCE, span_start):
        return _FENCE, _FENCE
    closer = _CLOSERS.get(text[span_start])
    return (text[span_start], closer) if closer else None


def _seam_context(text: str, start: int, end: int,
                  across: Dict[int, Tuple[int, int]]) -> Tuple[int, str, str]:
    """(start, opening, closing) that give window [start, end) its quote
    context. See SEAM CONTEXT."""
    opening = closing = ""
    if start in across:
        s, e = across[start]
        delims = _delimiters(text, s)
        if delims is not None:
            fence = len(delims[0]) > 1
            if fence and start < s + len(_FENCE):
                start = s                        # inside the opening fence
            else:
                if fence and start > e - len(_FENCE):
                    start = e - len(_FENCE)      # inside the closing fence
                opening = delims[0] + _EDGE_FILLER
    if end in across:
        delims = _delimiters(text, across[end][0])
        if delims is not None:
            closing = delims[1]
    return start, opening, closing


def _window_layout(text: str) -> List[Tuple[int, int, str, str]]:
    """(start, end, opening, closing) of every window of an input longer than
    one window: the slice text[start:end] with the seam context around it."""
    length = len(text)
    plan = _window_plan(length)
    # an edge is a place where a window was cut out of the document;
    # the two ends of the input itself are not cuts
    edges = {a for a, _ in plan if a > 0}
    edges |= {b for _, b in plan if b < length}
    across = _spans_across_edges(text, list(edges),
                                 min(length, _PAIRING_VIEW_CHARS))
    layout = []
    for start, end in plan:
        start, opening, closing = _seam_context(text, start, end, across)
        layout.append((start, end, opening, closing))
    return layout


def scan(text: str) -> Verdict:
    """Scans untrusted text.

    Up to MAX_INPUT_CHARS characters this is one fragment, judged whole.
    Longer input is judged window by window (see WORK BOUNDS) and takes the
    highest-scoring window's verdict, signals and score - a window is the
    calibrated unit, so signals are not pooled across windows - but each
    window reads the quote context it has in the document (SEAM CONTEXT).
    `truncated` is True only when the input exceeds MAX_SCAN_CHARS.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")

    length = len(text)
    if length <= MAX_INPUT_CHARS:
        result = _scan_window(text)
    else:
        result = None
        for start, end, opening, closing in _window_layout(text):
            window = _scan_window(text[start:end], continued=start > 0,
                                  opening=opening, closing=closing)
            if result is None or window.score > result.score:
                result = window
    result.truncated = length > MAX_SCAN_CHARS
    return result


def is_injection(text: str, strict: bool = False) -> bool:
    """Boolean shortcut for quick integration.

    strict=True treats "suspicious" as an injection. The default is False:
    the three-way verdict exists precisely so that "not sure" is not
    silently rounded to one side. The caller makes that choice.
    """
    v = scan(text)
    if strict:
        return v.verdict in ("injection", "suspicious")
    return v.verdict == "injection"
