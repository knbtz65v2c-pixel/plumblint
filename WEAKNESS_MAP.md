# Weakness map

This detector is a **baseline**, not an impenetrable guard. Its known ways of
failing are listed here as reproducible cases rather than left for a buyer to
discover. The table below is generated from `data/bypass_corpus.jsonl` by
`tools/weakness_map.py`; do not edit it by hand - edit the corpus builder and
regenerate. A CI guard (`--check`) fails if the table drifts from the corpus.

Each case is one input derived from a single canonical payload put through a
transform documented in `plumblint/normalize.py`.

<!-- AUTO:weakness-table -->
**Known-bypass coverage: 1 of 6 caught.** Each row is a reproducible input on which the detector fails to return the `injection` verdict. Status is decided by a live `scan()` in tools/build_bypass_corpus.py, not asserted here.

| status | case | verdict | note |
|---|---|---|---|
| OPEN | `mitigator-suffix` | clean (0.1416) | mitigators are whole-text booleans and multiply; payload bytes unchanged (the minimal suffix in this fixture is 4 words) |
| OPEN | `mitigator-negation` | clean (0.2903) | the negation mitigator fires on the whole text, not near the match |
| OPEN | `truncation-tail` | clean (0.0) | library scan() verdicts the prefix; the CLI now refuses such input with exit 3 rather than emitting a prefix-only verdict |
| OPEN | `b64-unpadded` | clean (0.0) | the len%4 filter in decode_base64_blobs skips it; the padded form of the same payload IS decoded and caught |
| MITIGATED | `b64-wrapped` | injection (0.725) | measured MITIGATED here: the break fell on a 4-char boundary, so the second half still decodes to a matchable fragment. A break off the boundary leaves two undecodable halves and bypasses - the corpus records the measured status, not the worst case |
| OPEN | `b64-double` | clean (0.0) | decoding is applied once, not to its own output |
<!-- /AUTO:weakness-table -->

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
