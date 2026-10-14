# Weakness map

This detector is a **baseline**, not an impenetrable guard. Its known ways of
failing are listed here as reproducible cases rather than left for a buyer to
discover. The table below is generated from `data/bypass_corpus.jsonl` by
`tools/weakness_map.py`; do not edit it by hand - edit the corpus builder and
regenerate. A CI guard (`--check`) fails if the table drifts from the corpus.

Each case is one input derived from a single canonical payload put through a
transform documented in `plumblint/normalize.py`.

<!-- AUTO:weakness-table -->
**Known-bypass coverage: 4 of 6 caught.** Each row is a reproducible input on which the detector failed to return the `injection` verdict. OPEN rows still fail; MITIGATED rows are now caught. MITIGATED is about that one input: it does not say the class the input belongs to is closed (see the list under the table). Status is decided by a live `scan()` in tools/build_bypass_corpus.py, not asserted here.

| status | case | verdict | note |
|---|---|---|---|
| OPEN | `mitigator-suffix` | clean (0.1416) | mitigators are whole-text booleans and multiply; payload bytes unchanged (the minimal suffix in this fixture is 4 words) |
| OPEN | `mitigator-negation` | clean (0.2903) | the negation mitigator fires on the whole text, not near the match |
| MITIGATED | `truncation-tail` | injection (0.775) | this input is caught: the library scan() reads the input in overlapping windows up to MAX_SCAN_CHARS and returns the highest-scoring window's verdict. Not closed as a class: a payload beyond MAX_SCAN_CHARS is not inspected (the verdict is flagged truncated). The CLI refuses input longer than one window with exit 3 |
| MITIGATED | `b64-unpadded` | injection (0.9443) | this input is caught: the padding is restored before decoding |
| MITIGATED | `b64-wrapped` | injection (0.9443) | this input is caught: whitespace-separated base64 tokens are rejoined before decoding. Not closed as a class: a broken blob behind 16 decoy tokens, and a blob longer than the window overlap on a window seam, are still missed (see the list under the table) |
| MITIGATED | `b64-double` | injection (0.9443) | this input is caught: decoded output is decoded again, up to B64_MAX_DEPTH layers. Not closed as a class: a payload nested deeper than the cap is not decoded |
<!-- /AUTO:weakness-table -->

## Not in this table, stated plainly

- **Paraphrase.** An injection reworded in ordinary English, with no
  characteristic phrase, is missed. This is the same gap the default-mode
  recall (0.534) already reports; it is a property of a lexical detector, not
  a separate defect.
- **Non-English text.** All rules are English; other languages pass.
- **Beyond the scan bound.** The library reads an input in overlapping windows
  up to `MAX_SCAN_CHARS`; a payload placed after that is not inspected, and
  the verdict is flagged `truncated`. An encoded blob that starts inside the
  bound and runs past it: a payload in its tail is not seen, and when the part
  inside the bound is 4k+1 characters long a contiguous blob is not decoded at
  all. The command line refuses any input longer than one window.
- **Encodings other than base64, and base64 past its bounds.** hex and rot13
  are not decoded. Base64 nested deeper than `B64_MAX_DEPTH` layers is not
  decoded. Base64 wrapped around another obfuscation (a leetspeak payload) or
  around a non-UTF-8 payload (UTF-16) is missed.
- **A long encoded blob on a window seam.** Consecutive windows share
  `WINDOW_OVERLAP_CHARS`. A base64 blob longer than that overlap which crosses
  a seam is held whole by no window, and depending on where the cut falls it
  is not decoded: a 876-character blob passes as `clean` at 91 to 251 of the
  875 positions in which it crosses the end of the first window, while the
  same blob inside one window is caught. Whoever controls the position of the
  blob in a long input can aim for such a cut.
- **Decoy tokens before a broken blob.** The decode budget of a window is
  charged for rejected attempts. A blob broken into whitespace-separated
  chunks behind 16 text-looking decoy tokens in the same run is not decoded;
  behind 15 it is. A contiguous blob is not affected.
- **Long documents.** A window is judged with the cues it contains. A
  quotation longer than the pairing view, or a mitigating cue more than a
  window away from the phrase it qualifies, leaves that window without it:
  `injection` where the same text as one fragment would be `suspicious`.
  CONTRACT.md, "Seam context: what it does not cover", states these cases.
- **Semantic / multi-turn attacks.** Persuasion and gradual context poisoning
  across turns carry no lexical marker and are out of scope for a single-turn
  rule engine.

The encoded-content edges are stated with their measurements in CONTRACT.md,
"Encoded content: what is not covered", and pinned as they are in
`tests/test_open_base64_edges.py`.

These are named because a baseline that hid them would not be honest; closing
them would mean a different class of tool (this one adds no model and makes no
network call, by design).
