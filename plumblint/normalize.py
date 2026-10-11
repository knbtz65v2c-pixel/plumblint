"""Text normalisation applied before rule matching.

One job: strip cheap obfuscation that breaks a signature without changing
what the model reads. A model parses "i g n o r e   p r e v i o u s" as
"ignore previous"; a naive regex does not.

Normalisation must NOT merge distinct words into one - that manufactures
false positives. Each technique is therefore applied separately, and the
detector inspects EVERY variant rather than one maximally-folded string.
"""

import binascii
import re
import unicodedata
from typing import Iterator, List, Optional, Tuple

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

# --- BASE64 DECODER LIMITS ------------------------------------------------
# Declared by value in CONTRACT.md, checked by tools/check_constants.py and
# pinned by TestConstantsPinned. Both are DoS bounds, not tuning knobs for
# recall: neither value is derived from data (conventions, stated as such).
#
# B64_MAX_DEPTH: how many times decoded output is fed back through the
#   decoder. 1 reproduces the old "decode once" behaviour. Each layer shrinks
#   the text by 3/4, so depth is bounded by length anyway; the cap is the
#   explicit guarantee. A payload wrapped in MORE layers than this is not
#   decoded - a finite cap always leaves that residual, by design.
# B64_MAX_DECODED_BYTES: total bytes base64 decoding may produce in ONE
#   variants() call, across all layers, candidates and rejected attempts.
#   Charged BEFORE each decode from the input length, so it bounds the work
#   done, not just what was kept. scan() already truncates input, so this
#   only bites on direct variants() calls and on crafted long chains.
B64_MAX_DEPTH = 8
B64_MAX_DECODED_BYTES = 65536

_B64_MIN_CHARS = 16      # shortest blob worth decoding (was a bare 16 in the regex)
_B64_HEAD_CHARS = 16     # chars decoded to pre-screen a chain start (12 bytes)
_B64_HEAD_BYTES = 12
_B64_TRIM_MIN_CHARS = 16  # shortest text prefix accepted after trimming a junk tail

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % _B64_MIN_CHARS)
# Base64-alphabet runs of ANY length separated only by whitespace: pieces of a
# blob broken across lines can be one character long. Padding, if present,
# ends the run; any other character (punctuation, a quote) ends it too.
_B64_CHAIN = re.compile(r"[A-Za-z0-9+/]+(?:\s+[A-Za-z0-9+/]+)+={0,2}|[A-Za-z0-9+/]+={0,2}")

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


class _Budget:
    """Bytes of base64 output still allowed for one variants() call."""
    __slots__ = ("left",)

    def __init__(self, total: int) -> None:
        self.left = total

    def take(self, n: int) -> bool:
        if n > self.left:
            return False
        self.left -= n
        return True


def _decode_cost(core_len: int) -> int:
    """Upper bound on the bytes a base64 decode yields for core_len characters."""
    return 3 * ((core_len + 3) // 4)


def _looks_like_text(decoded: str) -> bool:
    """The sanity filter: mostly printable, and at least one real word-ish run.

    Unchanged from the original decoder. It is what keeps hashes, identifiers
    and random binary from entering the variants as "text".
    """
    if not decoded:
        return False
    printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t")
    if printable / len(decoded) < 0.9:
        return False
    return _ALPHA_RUN.search(decoded) is not None


def _b64_bytes(chars: str, budget: _Budget, lenient_length: bool) -> Optional[bytes]:
    """Decode a run of base64-alphabet characters, padding it if it is short.

    Padding is optional in the wild (an encoder may strip it), so it is
    restored here instead of rejecting on len % 4. A length of 4k+1 cannot be
    valid base64; it is refused unless lenient_length, which drops the odd
    trailing character (used for joined runs that may end in stray prose).
    """
    core = chars.rstrip("=")
    if len(core) % 4 == 1:
        if not lenient_length:
            return None
        core = core[:-1]
    if not core or not budget.take(_decode_cost(len(core))):
        return None
    try:
        # the alphabet was enforced by the regex that found these characters
        return binascii.a2b_base64(core + "=" * (-len(core) % 4))
    except (binascii.Error, ValueError):
        return None


def _accept_strict(raw: bytes) -> Optional[str]:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if _looks_like_text(decoded) else None


def _accept_trimmed(raw: bytes) -> Optional[str]:
    """Like strict, but tolerates garbage AFTER a valid text prefix.

    A joined run whose last token is prose ("...cHJvbXB0 thanks") decodes to
    the payload followed by a few junk bytes. Only used as a fallback (no
    strict decode was found), so it is held to a higher bar than the strict
    path: the surviving prefix must be a full-size block of text that is
    overwhelmingly plain ASCII, which random binary that happens to start
    with a few valid UTF-8 bytes essentially never is.
    """
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        decoded = raw[:exc.start].decode("utf-8")
        if len(decoded) < _B64_TRIM_MIN_CHARS or not _looks_like_text(decoded):
            return None
        plain = sum(1 for c in decoded if c.isascii() and (c.isprintable() or c in "\r\n\t"))
        return decoded if plain / len(decoded) >= 0.9 else None
    return None      # fully valid input is handled by _accept_strict


def _plausible_head(head_chars: str, budget: _Budget) -> bool:
    """Cheap pre-screen: do the first 12 decoded bytes look like text?

    Runs once per candidate start of a joined run so that the full decode is
    attempted only where it can succeed. A multi-byte UTF-8 character cut by
    the 12-byte boundary is tolerated; any byte sequence that can never be
    UTF-8 is not.
    """
    if not budget.take(_B64_HEAD_BYTES):
        return False
    try:
        raw = binascii.a2b_base64(head_chars)
    except (binascii.Error, ValueError):
        return False
    if raw.isascii():
        head = raw.decode("ascii")
    else:
        try:
            head = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            if exc.reason != "unexpected end of data":
                return False
            head = raw[:exc.start].decode("utf-8")
    if not head:
        return False
    # '\r' counts as text here: a CRLF-broken inner layer can open with two
    # of them inside 12 bytes. This is only a pre-screen; the strict filter
    # (_looks_like_text) still decides.
    printable = sum(1 for c in head if c.isprintable() or c in "\r\n\t")
    return printable / len(head) >= 0.9


def _b64_chains(text: str) -> Iterator[List[str]]:
    """Runs of >=2 base64-alphabet tokens separated ONLY by whitespace.

    A blob broken by newlines, tabs or spaces is several tokens in a row. A
    token that carries padding ends a run (padding is terminal), and any
    other character - punctuation, a quote, a bracket - ends it too, which
    is what separates a payload from the prose around it. Runs too short to
    hold a blob are dropped here: they are most of what ordinary text has.
    """
    for run in [r for r in _B64_CHAIN.findall(text) if len(r) > _B64_MIN_CHARS]:
        tokens = run.split()
        if len(tokens) > 1 and len("".join(tokens).rstrip("=")) >= _B64_MIN_CHARS:
            yield tokens


def _decode_chain(chain: List[str], budget: _Budget) -> List[Tuple[str, str]]:
    """Decode a whitespace-broken blob, wherever inside the run it starts.

    The run may begin with ordinary words ("decode this SGVs bG8g..."), and
    a word is as valid a base64 alphabet as any, so the start is not known.
    Every token boundary is tried, leftmost first; a start is worth a full
    decode only if its first 12 bytes look like text.

    Returns up to TWO strict decodes. Words before the payload can, rarely,
    line up on a 4-character boundary and decode to a few junk bytes that are
    still valid UTF-8; that window then succeeds first and its text carries a
    junk prefix. Junk in front is harmless to the rules, but when the text is
    itself an inner base64 layer it shifts that layer's alignment. The next
    success is the clean one (the true start), so both are returned and the
    junk one dies at the next layer on its own.

    Only when no start succeeds strictly are tails trimmed, so a payload
    followed by stray words still decodes but noise cannot pre-empt it.
    """
    joined = "".join(chain)
    core_len = len(joined.rstrip("="))
    offsets = [0]
    for tok in chain:
        offsets.append(offsets[-1] + len(tok))
    wins: List[Tuple[str, str]] = []
    fallbacks: List[Tuple[str, bytes]] = []
    for k in range(len(chain) - 1):           # a run of >=2 tokens only
        if core_len - offsets[k] < _B64_MIN_CHARS or budget.left < _B64_HEAD_BYTES:
            break                              # later starts only get shorter
        suffix = joined[offsets[k]:]
        if not _plausible_head(suffix[:_B64_HEAD_CHARS], budget):
            continue
        raw = _b64_bytes(suffix, budget, lenient_length=True)
        if raw is None:
            continue
        decoded = _accept_strict(raw)
        if decoded is not None:
            wins.append((suffix, decoded))
            if len(wins) == 2:
                break
        else:
            fallbacks.append((suffix, raw))
    if wins:
        return wins
    for suffix, raw in fallbacks:
        decoded = _accept_trimmed(raw)
        if decoded is not None:
            return [(suffix, decoded)]
    return []


def decode_base64_blobs(text: str, _budget: Optional[_Budget] = None,
                        _tolerant: bool = False) -> List[Tuple[str, str]]:
    """One decode layer: returns (encoded, decoded) pairs found in text.

    Two shapes are decoded. A contiguous blob of 16+ characters, with or
    without its padding; and a blob broken by whitespace at any offset, which
    is rejoined (see _decode_chain). Only blobs that decode into meaningful
    printable text are returned; random hashes and identifiers are discarded,
    otherwise the result is noise. Decoding of the OUTPUT is decode_base64_
    layers' job, not this function's.

    _tolerant is for text that is itself the output of an earlier decode
    (layer 2 and deeper). A joined run that ended in stray words leaves a few
    junk characters on the decoded text; a single contiguous blob there may
    therefore carry a junk tail or an odd length. Raw input is never held to
    this looser rule.
    """
    budget = _budget if _budget is not None else _Budget(B64_MAX_DECODED_BYTES)
    found = []
    for m in _B64_CANDIDATE.finditer(text):
        if budget.left < _B64_HEAD_BYTES:
            return found
        blob = m.group(0)
        raw = _b64_bytes(blob, budget, lenient_length=_tolerant)
        if raw is None:
            continue
        decoded = _accept_strict(raw)
        if decoded is None and _tolerant:
            decoded = _accept_trimmed(raw)
        if decoded is not None:
            found.append((blob, decoded))
    for chain in _b64_chains(text):
        if budget.left < _B64_HEAD_BYTES:
            break
        found.extend(_decode_chain(chain, budget))
    return found


def decode_base64_layers(text: str) -> List[str]:
    """Every string reachable by decoding, and by decoding the decoded.

    Decoded output goes back through the same decoder up to B64_MAX_DEPTH
    layers, all layers sharing one B64_MAX_DECODED_BYTES budget.
    """
    budget = _Budget(B64_MAX_DECODED_BYTES)
    out: List[str] = []
    seen = set()

    def walk(layer_text: str, layer: int) -> None:
        if layer > B64_MAX_DEPTH:
            return
        for _, decoded in decode_base64_blobs(layer_text, budget, layer > 1):
            if decoded in seen:
                continue
            seen.add(decoded)
            out.append(decoded)
            walk(decoded, layer + 1)

    walk(text, 1)
    return out


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

    out.extend(decode_base64_layers(base))

    return [normalize_whitespace(v).lower() for v in out]
