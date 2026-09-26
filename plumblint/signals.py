"""Detector signals.

Each signal answers exactly one question and must produce evidence: the
concrete substring that matched. A signal without evidence does not count.

The idea the whole file exists for: separate an INSTRUCTION aimed at the
model from a MENTION of the technique. "ignore previous instructions" and
"how do I stop users from sending 'ignore previous instructions'?" share
the same substring but are not the same thing. A detector that confuses
them emits so many false alarms that it gets switched off within a week.

The separation is done by mitigators: interrogative form, quotation, and
analytical vocabulary. They do not zero a signal out, only reduce its
weight - a quoted payload can still be a live one.
"""

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class Signal:
    """A single hit: what matched, where, and how much it weighs."""
    name: str
    weight: float
    evidence: str
    raw_weight: float
    mitigated_by: List[str] = field(default_factory=list)


# --- Patterns of instructions aimed at the model ---------------------------

_OVERRIDE = [
    r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|preceding|above|earlier|foregoing)\s+"
    r"(?:instruction|prompt|direction|rule|command|message|context)",
    r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)\s*"
    r"(?:instruction|prompt|rule|message|context)?",
    r"forget\s+(?:everything|all)\s+(?:you|that|above|before|previous)",
    r"forget\s+(?:your|the)\s+(?:previous\s+)?(?:instruction|rule|training|prompt)",
    r"(?:override|overrule|cancel|nullify|void)\s+(?:all\s+)?(?:previous\s+|prior\s+|the\s+)?"
    r"(?:instruction|rule|restriction|directive|system\s+prompt)",
    r"(?:from\s+now\s+on|starting\s+now|going\s+forward)[,\s]+(?:you|ignore|disregard|forget)",
    r"(?:new|updated|revised)\s+(?:instruction|rule|directive|task)s?\s*:",
    r"stop\s+(?:following|obeying|adhering\s+to)\s+(?:the\s+|your\s+)?(?:previous|prior|above|system)",
]

_ROLE_HIJACK = [
    r"you\s+are\s+(?:now|no\s+longer)\s+",
    r"(?:act|behave|respond|talk|write)\s+as\s+(?:if\s+you\s+(?:are|were)\s+|a\s+|an\s+|the\s+)",
    r"pretend\s+(?:to\s+be|you\s+are|that\s+you)",
    r"roleplay\s+as\b",
    r"you\s+must\s+now\s+(?:act|behave|respond|obey|comply)",
    r"\bDAN\s+mode\b",
    r"\bdo\s+anything\s+now\b",
    r"switch\s+to\s+(?:developer|debug|admin|god|unrestricted)\s+mode",
    r"enable\s+(?:developer|debug|admin|jailbreak|unrestricted)\s+mode",
    r"your\s+new\s+(?:role|persona|identity|character)\s+is",
]

_PROMPT_EXTRACTION = [
    r"(?:repeat|print|output|show|reveal|display|echo|reproduce|dump)\s+"
    r"(?:me\s+)?(?:your|the|all)\s+"
    r"(?:system\s+|initial\s+|original\s+|hidden\s+|secret\s+)?"
    r"(?:prompt|instruction|message|rule|directive|configuration)",
    r"what\s+(?:is|are|was|were)\s+your\s+"
    r"(?:system\s+|initial\s+|original\s+|exact\s+)"
    r"(?:prompt|instruction|message|rule)",
    r"(?:tell|show|give)\s+me\s+your\s+(?:system\s+)?(?:prompt|instruction)",
    r"everything\s+(?:above|before)\s+(?:this|the)\s+(?:line|message|point)",
    r"verbatim\s+(?:the\s+)?(?:text|content|instruction)s?\s+(?:above|before)",
    r"start\s+your\s+(?:reply|response|answer)\s+with\s+[\"'\u201c]",
]

_STRUCTURE_SPOOF = [
    r"<\|(?:im_start|im_end|system|endoftext|assistant|user)\|>",
    r"\[/?(?:INST|SYS|SYSTEM)\]",
    r"<<\s*SYS\s*>>",
    r"^\s*(?:system|assistant)\s*:",
    r"\n\s*(?:system|assistant)\s*:\s*(?:you|your|ignore|the\s+user)",
    r"###\s*(?:system|instruction|new\s+instruction)",
    r"\{\{\s*system\s*\}\}",
]

_RESTRICTION_BYPASS = [
    r"(?:without|ignoring|bypassing|circumventing)\s+(?:any\s+|all\s+|your\s+)?"
    r"(?:restriction|limitation|filter|guardrail|safety|censorship|ethical)",
    r"you\s+(?:have\s+)?no\s+(?:longer\s+)?(?:restriction|limitation|filter|rule|guideline)",
    r"there\s+are\s+no\s+(?:rules|restrictions|limits|guidelines)",
    r"(?:disable|turn\s+off|remove|bypass)\s+(?:your\s+|the\s+|all\s+)?"
    r"(?:safety|filter|guardrail|restriction|content\s+polic)",
    r"this\s+is\s+(?:a\s+)?(?:test|hypothetical|fiction)[,\s]+so\s+you\s+(?:can|may|should)\s+ignore",
]

_EXFILTRATION = [
    # Regression: the pattern once required "noun to url" adjacently and
    # broke on "conversation HISTORY to", "credentials YOU CAN ACCESS to".
    # Up to 4 words are now allowed between the object and the preposition.
    r"(?:send|post|transmit|upload|forward|leak|exfiltrate|deliver)\s+"
    r"(?:the\s+|all\s+|this\s+|your\s+|any\s+|every\s+)?"
    r"(?:\w+\s+){0,2}?"
    r"(?:data|content|conversation|history|prompt|credential|token|key|secret|"
    r"password|message|transcript|context|file)s?\b"
    r"(?:\s+\w+){0,4}?\s+to\s+"
    r"(?:https?://|this\s+(?:url|link|endpoint|address|server)|the\s+following\s+(?:url|link))",

    # Markdown image with interpolation - a classic exfiltration channel.
    r"!\[[^\]]*\]\(\s*https?://[^)]*(?:\{|\$|%s|\+)",

    r"(?:append|include|add|embed|attach)\s+(?:the\s+)?"
    r"(?:\w+\s+){0,2}?"
    r"(?:conversation|history|prompt|secret|credential|token|data)s?\b"
    r"(?:\s+\w+){0,3}?\s+(?:to|into|in)\s+(?:the\s+)?"
    r"(?:url|link|query|parameter|image|request)",

    # Separate form: "make a request to <url> with the data"
    r"(?:make|issue|perform)\s+(?:a\s+|an\s+)?(?:https?\s+)?"
    r"(?:request|call|fetch)\s+to\s+https?://",
]

_SIGNAL_SETS = [
    ("instruction_override", _OVERRIDE, 0.55),
    ("role_hijack", _ROLE_HIJACK, 0.40),
    ("prompt_extraction", _PROMPT_EXTRACTION, 0.50),
    ("structure_spoof", _STRUCTURE_SPOOF, 0.60),
    ("restriction_bypass", _RESTRICTION_BYPASS, 0.45),
    ("exfiltration", _EXFILTRATION, 0.65),
]

_COMPILED = [
    (name, [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in pats], w)
    for name, pats, w in _SIGNAL_SETS
]


# --- Mitigators: markers that this is talk ABOUT, not a command -------------

_INTERROGATIVE = re.compile(
    r"\b(?:how\s+(?:do|can|would|should)\s+(?:i|we|you|one)|"
    r"what\s+(?:is|are|does|do)\s+(?:a|an|the)?\s*(?:prompt|injection|attack|way)|"
    r"why\s+(?:do|does|is|are)|"
    r"can\s+(?:you\s+)?(?:explain|describe|tell\s+me\s+about)|"
    r"is\s+it\s+possible\s+to\s+(?:detect|prevent|block|stop))",
    re.IGNORECASE,
)

_META_DISCUSSION = re.compile(
    r"\b(?:for\s+example|such\s+as|e\.g\.|an?\s+example\s+of|"
    r"attackers?\s+(?:might|may|could|often|typically|will)|"
    r"researchers?|vulnerability|mitigation|defen[cs]e|countermeasure|"
    r"this\s+(?:article|paper|post|guide|section|tutorial)|"
    r"owasp|cwe-|cve-|test\s+case|unit\s+test|"
    r"(?:detect|prevent|block|filter|sanitiz)\w*\s+(?:such|these|those|this|it|them))",
    re.IGNORECASE,
)

# Mitigator multipliers. Values are pinned by
# tests/test_plumblint.py::TestConstantsPinned.
MITIGATOR_QUOTED = 0.35
MITIGATOR_INTERROGATIVE = 0.40
MITIGATOR_META = 0.35
MITIGATOR_NEGATED = 0.30

_NEGATED = re.compile(
    r"\b(?:should\s+not|shouldn't|must\s+not|mustn't|never|do\s+not|don't|"
    r"cannot|can't|refuse\s+to|will\s+not|won't)\s+"
    r"(?:\w+\s+){0,3}?(?:ignore|disregard|forget|reveal|comply|obey)",
    re.IGNORECASE,
)


_QUOTED_RE = re.compile(
    r"```.*?```|`[^`]+`|\"[^\"]{4,}\"|'[^']{4,}'|\u00ab[^\u00bb]+\u00bb",
    re.DOTALL)


def _quoted_spans(text: str) -> List[range]:
    """Spans inside quotes and code blocks - where things get quoted."""
    spans = []
    for m in _QUOTED_RE.finditer(text):
        spans.append(range(m.start(), m.end()))
    return spans


def _in_quotes(pos: int, spans: List[range]) -> bool:
    return any(pos in s for s in spans)


def find_signals(variant: str) -> List[Signal]:
    """Runs every rule against one text variant."""
    signals: List[Signal] = []
    spans = _quoted_spans(variant)

    has_question = bool(_INTERROGATIVE.search(variant))
    has_meta = bool(_META_DISCUSSION.search(variant))
    has_negation = bool(_NEGATED.search(variant))

    for name, patterns, base_weight in _COMPILED:
        for pat in patterns:
            m = pat.search(variant)
            if not m:
                continue

            weight = base_weight
            mitigators: List[str] = []

            if _in_quotes(m.start(), spans):
                weight *= MITIGATOR_QUOTED
                mitigators.append("quoted")
            if has_question:
                weight *= MITIGATOR_INTERROGATIVE
                mitigators.append("interrogative")
            if has_meta:
                weight *= MITIGATOR_META
                mitigators.append("meta_discussion")
            if has_negation:
                weight *= MITIGATOR_NEGATED
                mitigators.append("negated")

            signals.append(Signal(
                name=name,
                weight=round(weight, 4),
                evidence=m.group(0)[:160],
                raw_weight=base_weight,
                mitigated_by=mitigators,
            ))
            break  # one hit per signal class - never count it twice

    return signals
