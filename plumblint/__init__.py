"""Plumblint - a prompt injection detector with zero dependencies.

    from plumblint import scan
    v = scan(untrusted_text)
    if v.verdict == "injection":
        reject(v.signals)

Runs on the Python 3.11+ standard library alone. Pulls in nothing, makes no
network calls, and logs nothing outward.
"""

from .detector import (
    THRESHOLD_INJECTION,
    THRESHOLD_SUSPICIOUS,
    Verdict,
    is_injection,
    scan,
)
from .signals import Signal

__version__ = "0.1.1"
__all__ = [
    "scan", "is_injection", "Verdict", "Signal",
    "THRESHOLD_SUSPICIOUS", "THRESHOLD_INJECTION",
]
