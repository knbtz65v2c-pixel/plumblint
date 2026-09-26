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

One text fragment up to 8192 characters. Not a conversation, not a session.

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
