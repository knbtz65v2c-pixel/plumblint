"""Text normalisation applied before rule matching.

One job: strip cheap obfuscation that breaks a signature without changing
what the model reads. A model parses "i g n o r e   p r e v i o u s" as
"ignore previous"; a naive regex does not.

Normalisation must NOT merge distinct words into one - that manufactures
false positives. Each technique is therefore applied separately, and the
detector inspects EVERY variant rather than one maximally-folded string.
"""

import base64
import binascii
import re
import unicodedata
from typing import List, Tuple

# Zero-width and bidirectional control characters used to split signatures.
_INVISIBLE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u061c"
    "\u202a-\u202e\u2066-\u2069]"
)

# Homoglyphs: Cyrillic and Greek characters that look like Latin ones.
_HOMOGLYPH_MAP = {
    # Cyrillic look-alikes
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u04bb": "h", "\u0501": "d", "\u051b": "q", "\u051d": "w", "\u0475": "v",
    "\u0457": "i", "\u04cf": "l", "\u0261": "g",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S", "\u04ba": "H",
    # Greek
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03c1": "p", "\u03c5": "u",
    "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03b7": "n", "\u03c4": "t",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u039f": "O", "\u03a1": "P",
    "\u03a4": "T", "\u03a7": "X", "\u0399": "I", "\u039a": "K", "\u039d": "N",
    "\u0396": "Z", "\u0397": "H", "\u039c": "M",
    # Other Latin variants
    "\u0251": "a", "\u0269": "i", "\u1d0f": "o", "\u0138": "k",
}

# Leetspeak. 1->l and 5->s are deliberately excluded here: they produce
# too many false positives on ordinary text containing numbers.
_LEET_MAP = {"0": "o", "3": "e", "4": "a", "@": "a", "$": "s", "!": "i"}

# Extended table: digits 1 and 5 are ambiguous (1 -> i or l, 5 -> s), so
# they generate a SEPARATE variant instead of joining the main path.
# The aggressive variant covers forms such as "1gn0r3".
_LEET_MAP_AGGRESSIVE = dict(_LEET_MAP)
_LEET_MAP_AGGRESSIVE.update({"1": "i", "5": "s", "7": "t", "8": "b", "9": "g", "+": "t"})

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# Compiled once at import because these run on every scanned fragment.
_SPACED_LETTERS = re.compile(r"\b(?:[A-Za-z][ \t\-.]{1,4}){3,}[A-Za-z]\b")
_SEP_SPLIT = re.compile(r"([ \t\-.]{1,4})")
_WS_RUN = re.compile(r"\s+")
_ALPHA_RUN = re.compile(r"[A-Za-z]{3,}")


def strip_invisible(text: str) -> str:
    """Removes zero-width characters and bidirectional control marks."""
    return _INVISIBLE.sub("", text)


def fold_homoglyphs(text: str) -> str:
    """Folds Cyrillic and Greek look-alikes down to Latin."""
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def fold_leet(text: str) -> str:
    """Expands unambiguous leetspeak."""
    return "".join(_LEET_MAP.get(ch, ch) for ch in text)


def fold_leet_aggressive(text: str) -> str:
    """Expands leetspeak including the ambiguous digits.

    A separate function rather than an extension of the main one: mapping
    1->i and 5->s corrupts ordinary text containing numbers. It produces an
    independent variant checked alongside the others, never replacing them.
    """
    return "".join(_LEET_MAP_AGGRESSIVE.get(ch, ch) for ch in text)


def collapse_spacing(text: str) -> str:
    """Rejoins "i g n o r e   a l l" -> "ignore all".

    The subtle part: the separator inside a split word and the separator
    BETWEEN words are the same space character, differing only in length.
    A single separator is treated as intra-word and removed; two or more
    are treated as a word boundary and collapsed to one space.

    Without that distinction "i g n o r e   a l l   p r e v i o u s" folds
    into "ignoreallprevious" and stops matching any rule that expects \\s+
    between words. This miss was caught by calibration before release; see
    tests/test_plumblint.py::test_word_boundaries_survive_letter_spacing.

    Only fires on runs of 4+ single letters, otherwise initials and short
    ordinary sequences would be damaged.
    """
    def _join(m: "re.Match") -> str:
        chunk = m.group(0)
        parts = _SEP_SPLIT.split(chunk)
        out = []
        for i, part in enumerate(parts):
            if i % 2 == 0:
                out.append(part)
            else:
                # 2+ separator chars => word boundary, otherwise join
                out.append(" " if len(part) >= 2 else "")
        return "".join(out)

    return _SPACED_LETTERS.sub(_join, text)


def normalize_whitespace(text: str) -> str:
    """Collapses any whitespace run into a single space."""
    return _WS_RUN.sub(" ", text).strip()


def decode_base64_blobs(text: str) -> List[Tuple[str, str]]:
    """Finds base64-looking chunks, returns (original, decoded) pairs.

    Only returns blobs that decode into meaningful printable text; random
    hashes and identifiers are discarded, otherwise the result is noise.
    """
    found = []
    for m in _B64_CANDIDATE.finditer(text):
        blob = m.group(0)
        if len(blob) % 4:
            continue
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t")
        if not decoded or printable / len(decoded) < 0.9:
            continue
        if not _ALPHA_RUN.search(decoded):
            continue
        found.append((blob, decoded))
    return found


def variants(text: str) -> List[str]:
    """Returns every text variant the rules must be run against.

    A list, not one maximally-folded string: aggressive normalisation can
    both reveal something hidden and manufacture a match that was never
    there. The detector must see both states.

    variant[0] is the ORIGINAL text (only whitespace/case folded), so the
    detector's notion of "seen in the plain input" is the real input. NFKC is
    just another de-obfuscation step, added as its own variant. An earlier
    version made NFKC the plain variant, so a full-width payload (which NFKC
    folds straight to ASCII) was treated as un-obfuscated and got no boost,
    while the zero-width equivalent did. The downstream folds run on the NFKC form so
    hidden payloads are still revealed.
    """
    original = text
    out = [original]
    base = unicodedata.normalize("NFKC", text)
    if base != original:
        out.append(base)

    stripped = strip_invisible(base)
    if stripped != base:
        out.append(stripped)

    folded = fold_homoglyphs(stripped)
    if folded != stripped:
        out.append(folded)

    collapsed = collapse_spacing(folded)
    if collapsed != folded:
        out.append(collapsed)

    leet = fold_leet(collapsed)
    if leet != collapsed:
        out.append(leet)

    leet_hard = fold_leet_aggressive(collapsed)
    if leet_hard != collapsed and leet_hard != leet:
        out.append(leet_hard)

    for _, decoded in decode_base64_blobs(base):
        out.append(decoded)

    return [normalize_whitespace(v).lower() for v in out]
