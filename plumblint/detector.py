"""Detector assembly: variants -> signals -> score -> three-way verdict.

The thresholds are fixed HERE, in code, BEFORE the first run against the
calibration corpus. Changing them after seeing the results would be fitting
the instrument to the answer. If the thresholds turn out to be poor, that
is the measurement's result, not grounds for a second attempt.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set

from .normalize import variants
from .signals import Signal, find_signals

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

MAX_INPUT_CHARS = 8192


@dataclass
class Verdict:
    """The result of scanning one fragment."""
    verdict: str                      # clean | suspicious | injection
    score: float
    signals: List[Signal] = field(default_factory=list)
    obfuscation_detected: bool = False
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


def scan(text: str) -> Verdict:
    """Scans a fragment of untrusted text."""
    if not isinstance(text, str):
        raise TypeError("text must be str")

    truncated = len(text) > MAX_INPUT_CHARS
    if truncated:
        text = text[:MAX_INPUT_CHARS]

    if not text.strip():
        return Verdict(verdict="clean", score=0.0, truncated=truncated)

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
        truncated=truncated,
    )


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
