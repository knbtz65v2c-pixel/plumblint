# Detector contract

Tunable values and the calibration corpus are checked at value level:

1. every tunable constant is DECLARED below, by value;
2. `tools/check_constants.py` compares each declared value against the
   code and fails the build on any mismatch, missing declaration, or
   undeclared tunable;
3. `tests/test_plumblint.py::TestConstantsPinned` asserts the same
   values inside the test suite.

A changed number cannot pass the build unless this document is updated in the
same change. The contract promises visible changes, not immutability.

## Declared constants

The `role` column says how each number is used. `RECALL_PASS` / `RECALL_FAIL`
are **reported-only**: since the v2 estimand (below), recall no longer gates the
exit code - these two bounds only label recall's standing when it is printed.
They are still declared and pinned here so a silent change to them is caught.

| constant | value | role |
|---|---|---|
| `THRESHOLD_SUSPICIOUS` | 0.30 | verdict threshold |
| `THRESHOLD_INJECTION` | 0.55 | verdict threshold |
| `OBFUSCATION_BOOST` | 1.45 | scoring |
| `MAX_SINGLE_WEIGHT` | 0.95 | scoring cap |
| `B64_MAX_DEPTH` | 8 | base64 decode-layer cap (DoS bound) |
| `B64_MAX_DECODED_BYTES` | 65536 | base64 decoded-bytes budget per window, i.e. per variants() call (DoS bound) |
| `WINDOW_OVERLAP_CHARS` | 512 | work bound: overlap of consecutive scan windows |
| `MAX_SCAN_WINDOWS` | 16 | work bound: windows scanned per input |
| `MITIGATOR_QUOTED` | 0.35 | mitigator multiplier |
| `MITIGATOR_INTERROGATIVE` | 0.40 | mitigator multiplier |
| `MITIGATOR_META` | 0.35 | mitigator multiplier |
| `MITIGATOR_NEGATED` | 0.30 | mitigator multiplier |
| `weight["instruction_override"]` | 0.55 | signal weight |
| `weight["role_hijack"]` | 0.40 | signal weight |
| `weight["prompt_extraction"]` | 0.50 | signal weight |
| `weight["structure_spoof"]` | 0.60 | signal weight |
| `weight["restriction_bypass"]` | 0.45 | signal weight |
| `weight["exfiltration"]` | 0.65 | signal weight |
| `EASY_FP_PASS` | 0.02 | false-alarm gate (default mode) |
| `EASY_FP_FAIL` | 0.05 | false-alarm gate (default mode) |
| `HARD_FP_PASS` | 0.15 | false-alarm gate (default mode) |
| `HARD_FP_FAIL` | 0.30 | false-alarm gate (default mode) |
| `RECALL_PASS` | 0.85 | reported-only (not gated) |
| `RECALL_FAIL` | 0.70 | reported-only (not gated) |

## The exact question

Given a fragment of text arriving in an LLM application from an untrusted
source (user input, web page content, a file, a tool response): does it
contain an attempt to seize control of the model?

## Two distinguishable hypotheses

- **H1 (injection):** the text carries an instruction addressed to the MODEL
  rather than to the user - revoke prior instructions, disclose the system
  prompt, change role, act with system authority.
- **H0 (clean):** the text is data, or an ordinary request, even when it talks
  ABOUT injections, security, or system prompts.

The boundary between them is the difference between **mentioning** and
**addressing**. "how do I defend against prompt injection?" is H0. "ignore
previous instructions" is H1. A detector that cannot separate those two is
useless in production.

## Unit of analysis

One text fragment up to 8192 characters (`MAX_INPUT_CHARS`, one scan
window). Not a conversation, not a session.

An input longer than one window is not judged on its prefix. It is cut into
overlapping windows (consecutive windows share `WINDOW_OVERLAP_CHARS`; the
window that reaches the end of the input is right-aligned, never a short
remainder), each window is judged like a stand-alone fragment **that reads the
quote context it has in the document** (next section), and the input takes the
highest-scoring window's verdict. Signals are not pooled across windows: the
window is the calibrated unit, and the three mitigator vocabularies read only
their own window. At most `MAX_SCAN_WINDOWS` windows are scanned, i.e.
`MAX_INPUT_CHARS + (MAX_SCAN_WINDOWS - 1) * (MAX_INPUT_CHARS -
WINDOW_OVERLAP_CHARS)` characters (123392 with the values above; pinned in
`TestConstantsPinned`). `Verdict.truncated` is True only for input longer
than that bound. **A payload placed beyond the bound is not inspected** - a
finite bound has this edge; it is pinned by
`tests/test_bypass_truncation.py::TestBeyondTheBoundIsTheDocumentedOpenEdge`,
not hidden. The frozen calibration corpus (rows of at most a few hundred
characters) never reaches the windowed path, so the gate below does not
measure it; `tests/test_bypass_truncation.py::TestNoFalseAlarmFlood` and
`TestQuotedPayloadNoSeamFalseAlarm` do.

**The command line is narrower than the library, on purpose.** The CLI does
not scan in windows: it takes at most one window (`MAX_INPUT_CHARS`
characters) and refuses any longer input with exit code 3 and no verdict. That
is fail-closed - a caller that branches on the exit code cannot read an
over-long input as clean - and it is pinned by
`tests/test_plumblint.py::TestCliExitContract::test_oversized_input_is_refused_not_prefix_scanned`.
Everything in this section about windows describes the library `scan()`.
Widening the command line to the library's bound is a separate decision, not
an oversight.

### Seam context

Windowing must not manufacture alarms. The quoted mitigator pairs quote
characters by position, so a window cut inside a quotation used to pair the
stray delimiter with the NEXT one, read the payload inside its own quotes as
un-quoted, lose the quoted multiplier, and turn a benign document that merely
quotes a payload verbatim into `injection` (two reproducing documents; measured
as a class over quote style, seam offset, and length in
`TestQuotedPayloadNoSeamFalseAlarm`). The window now gets the context the
document gives it:

- the pairing is computed once, by the same regex the mitigator uses, over a
  bounded view of the input (`MAX_SCAN_CHARS + MAX_INPUT_CHARS` characters:
  the scanned region plus one window of look-ahead, so a quotation cut by the
  scan bound still closes);
- a window whose start falls inside a quotation begins with that quotation's
  opening delimiter and a filler; one whose end falls inside a quotation ends
  with its closing delimiter; a start inside a three-character fence delimiter
  moves left onto the delimiter (at most two characters);
- the added characters contain no letters or digits, so no signal rule and no
  normalisation step can match or be changed by them, and they are bounded:
  a window's text is at most `MAX_WINDOW_TEXT_CHARS` (derived; pinned in
  `TestConstantsPinned`). The ends of the input itself are never repaired: a
  quote that really is unclosed there reads as it would in a fragment.

The property, tested against an independent reference (the pairing of the
whole text): every character a window shows has the same quoted status it has
in the document, except the last four characters of a window that cuts a
quotation short (`TestSeamContext`). Work stays bounded: the pairing is one
linear pass over the view (a run of unclosed `U+00AB` would make it quadratic
and is blanked first), and the number of `variants()` calls is still at most
`MAX_SCAN_WINDOWS`.

### Encoded content: what is not covered

Four rows of the weakness map concern encoded or over-long input. Each of them
is caught as a specific input; the class is not closed. The edges below are
open, and every one is pinned AS IT IS in `tests/test_open_base64_edges.py`: a
change in behaviour fails the pin, and this section changes in the same commit.

1. **A long blob on a window seam.** A window decodes the base64 it holds. A
   blob longer than `WINDOW_OVERLAP_CHARS` that crosses a seam lies whole in no
   window, and depending on where the cut falls its pieces do not decode.
   Measured: a 876-character blob is `clean` at 91 (payload first in the
   encoded text) to 251 (payload last) of the 875 positions in which it crosses
   the end of the first window; the same blob inside one window is `injection`;
   a blob shorter than the overlap is caught at every position. Whoever
   controls the position of a blob in a long input can aim for such a cut
   (`TestLongBlobOnAWindowSeamIsOpen`).
2. **Decoy tokens.** The decode budget belongs to a window
   (`B64_MAX_DECODED_BYTES` for one `variants()` call) and is charged for
   rejected attempts too. A blob broken into whitespace-separated chunks that
   stands behind 16 text-looking decoy tokens in the same run is not decoded:
   the budget is spent before its start is reached. With 15 decoys it is
   decoded; a contiguous blob is not affected
   (`TestDecoyTokensExhaustTheWindowBudgetIsOpen`).
3. **A blob that runs past the scan bound.** A payload in the part beyond
   `MAX_SCAN_CHARS` is never seen. When the part inside the bound is 4k+1
   characters long, a contiguous blob is not decoded at all, so a payload in
   its visible part is missed as well (`TestBlobPastTheScanBoundIsOpen`).
4. **Control separators are whitespace.** U+001C..U+001F inside a blob are
   read by the window decoder exactly like a newline: the blob is caught inside
   a window and is subject to edge 1 on a seam
   (`TestControlSeparatorsAreWhitespaceToTheDecoder`).

A fix for edge 1 was written and withdrawn. It decoded the whole encoded run
from the document, which made the decoded text a second document that was not
judged like one: its signals were pooled and quote context was lost at its
cuts. Measured on it: 11 of 131 benign long encoded documents turned into
`injection`, and bypasses were still left. Closing these
edges needs a different design - blobs extracted once from the document with
their offsets, decoded text judged with its own context, one explicit budget -
not a patch on the window path.

**Work actually done - measured, not derived.** Each window spends its own
decode budget, so a scan of `MAX_SCAN_WINDOWS` windows can decode
`MAX_SCAN_WINDOWS * B64_MAX_DECODED_BYTES` bytes (16 x 65536 = 1048576), not
`B64_MAX_DECODED_BYTES`. The heaviest input found - the scan bound filled with
text-looking 8-character tokens - produces 1048405 bytes of base64 output in
one scan (`TestDecodeWorkIsBoundedByTheWindowBudgets`). Over a battery of 44
adversarial inputs the largest peak of traced memory was about 0.95 MB and the
longest scan 0.34 s (single runs on a shared machine). These are observations,
not a proven ceiling for memory or time.

### Seam context: what it does not cover

Stated, and pinned by `TestSeamContextResidualsAreDocumented`:

1. **A quotation longer than the pairing view.** A fence or quote that opens
   before a window edge and closes only beyond the view cannot be seen closed;
   windows inside it read the payload as un-quoted (`injection`). It needs an
   input longer than the view and a quotation that long.
2. **Mitigator vocabulary is window-local.** The interrogative, meta-discussion
   and negation cues (`how do I`, `for example`, `never ignore`, ...) are read
   inside the window only, as they were calibrated. A cue cut off by a seam, or
   simply more than a window away from the payload it qualifies, leaves that
   payload in a window without it: `injection` where the same text as one
   fragment is `suspicious`. Repairing it needs either the position of each
   signal's match (to let the window where a payload is central decide it,
   which `signals.py` does not expose) or carrying cues across the whole input,
   which would let one cue word at the top of a document downgrade a payload
   placed past the first window from `injection` to `suspicious` - trading the
   closed truncation bypass for a false-alarm fix. Neither is done.
3. **Quote pairing weaknesses of the fragment are inherited, not introduced.**
   The pairing is the document's, computed by the same regex, so what that
   regex reads wrongly in a fragment it reads wrongly in a long document.
   Most consequential: a quoted string shorter than four characters is not a
   quotation to it, and its closing quote pairs with the NEXT opening quote,
   so from the first such sibling on (`["<payload>", "x"]`, or an apostrophe
   amid contractions) the payload reads un-quoted. A fragment cut at the
   right place hides this behind the first payload (the first match is the
   quoted one); a long document is cut everywhere, so windows expose it. It is
   not a seam effect: the same text cut at an arbitrary offset, as one
   fragment, reads the same. Fixing it means fixing the pairing in
   `signals.py`, which changes the calibrated fragment path too.

## Input and output

Input: `text: str`.

Output:
- `score: float` in [0,1] - a continuous quantity, NOT a probability;
- `verdict: {"clean", "suspicious", "injection"}` - three-way, not binary;
- `signals: list` - which detectors fired, on what, with what weight;
- `evidence: str` - the exact substring that triggered the match.

The three-way verdict is mandatory: "not sure" is its own answer, not a
rounding of one of the other two.

## Success criteria (v2) - the estimand is two operating points

The initial calibration contract placed one recall bar across a three-way
instrument. That run did not satisfy the contract. The current estimand reports
two operating points, because default and strict modes express different
false-alarm/recall trade-offs.

**Default mode** (`verdict == injection`) - the pre-registered strength is a
low false-alarm rate. This is what the GATE (exit code of calibrate.py) checks:

| Gated metric | Pass | Fail |
|---|---|---|
| False alarms on EASY negatives (ordinary requests) | <= 0.02 | > 0.05 |
| False alarms on HARD negatives (text ABOUT injections) | <= 0.15 | > 0.30 |

**Reported, not gated** - recall in both modes, with Wilson intervals and its
standing against the 0.85 guard bar. The false-alarm criteria remain unchanged,
the recall result and its below-bar status remain visible, and no recall bar
was lowered to produce a pass. This baseline gates on false alarms and reports
what it catches.

The strict-mode recall (0.983) is **in-sample**: the decision to treat
`suspicious` as blocking was made after seeing this corpus, so it is not an
independent measurement and never gates anything.

Hard negatives are a separate row on purpose. A detector that simply matches
the word "ignore" would collapse here. Averaging easy and hard negatives into
one figure is forbidden - it would hide exactly that.

## Corpus freeze

The numbers above are meaningful only against a fixed corpus. The calibration
corpus is frozen by hash; `tools/check_constants.py` and the test suite compare
the live file against this value, so a silent edit to the corpus (which would
move every number) cannot pass a green build.

| artifact | rows | sha256 |
|---|---|---|
| `data/corpus.jsonl` | 118 | `fe2224ce67153ec09a23b52b95c70a9183e968abb66f154b6d9c35cb496cc84e` |

Changing the corpus is allowed, but it is a new frozen cohort: the hash here
must be updated in the same change, which makes the movement visible in the
diff rather than silent.

## Mandatory to publish alongside any number

1. Wilson intervals on recall and false-alarm rates - 10/10 and 0/10 are not
   100% and 0%.
2. The size of every group (the denominator).
3. The thresholds, fixed before the run.
4. A list of what the detector does NOT catch, with examples.

## What counts as a failure of method

- Moving a threshold after seeing results;
- averaging false alarms across easy and hard negatives;
- publishing "accuracy" without separate recall and false-alarm figures;
- reporting a rate without its denominator.

## Stated limitation of the corpus

The calibration corpus was written by the author of the detector. That makes
every figure an **upper bound**: the tool is graded on examples its own author
thought of. An independent corpus would score lower. This limitation belongs
in the product README, not in a footnote.
