"""Generic, OWASP-style detection signatures for Blue v0.

IMPORTANT: these signatures are GENERIC patterns for the three CWE classes. They
are deliberately written WITHOUT looking at red/payloads.json — Blue v0 is a
baseline classifier, not an answer key. Blue classifies from the proxy log fields
only (path, query, body); it never sees request ids, headers, or ground truth.

Inputs may be percent-encoded, including double-encoded (e.g. %2500 -> %00 -> NUL),
so each field is decoded until stable before matching, and the raw form is matched
too (so an encoding that would hide a pattern cannot evade a raw match).

classify() returns one taxonomy label. v0 is single-label, first-match by a fixed
category priority, so the result is deterministic.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

# Category priority for v0's single-label verdict. The three classes are
# syntactically distinct, so this order only matters if a request trips more
# than one family; we then report the first in this list.
PRIORITY = ["CWE-22", "CWE-89", "CWE-79"]

SIGNATURES: dict[str, list[re.Pattern]] = {
    # SQL injection: tautologies, UNION-based reads, stacked/time-based probes.
    "CWE-89": [re.compile(p, re.IGNORECASE) for p in [
        r"union\s+select",
        r"\b(or|and)\s+\d+\s*=\s*\d+",       # or 1=1
        r"'\s*(or|and)\s+",                   # ' or ...
        r"'\s*--",                            # quote then SQL comment
        r";\s*(drop|insert|update|delete)\s+",
        r"\b(sleep|benchmark|pg_sleep)\s*\(",
        r"'\s*(=|;|\)\))",                    # quote breaking out of a string/clause
    ]],
    # Path traversal: dot-segments, encoded separators, and NUL-byte suffix tricks.
    "CWE-22": [re.compile(p, re.IGNORECASE) for p in [
        r"\.\.[\\/]",                         # ../ or ..\
        r"\.\.%2f",                           # encoded ../ (also caught after decode)
        r"\x00",                              # decoded NUL byte
        r"%00",                               # single-encoded NUL
        r"%2500",                             # double-encoded NUL
        r"/etc/(passwd|shadow)",
        r"\.(bak|key|md|conf)\x00",           # NUL-byte suffix bypass on a filename
    ]],
    # Cross-site scripting: script/iframe injection and inline event handlers.
    "CWE-79": [re.compile(p, re.IGNORECASE) for p in [
        r"<\s*script",
        r"<\s*iframe",
        r"javascript:",
        r"\bon(error|load|mouseover|click)\s*=",
        r"<\s*img[^>]*\bsrc",
        r"alert\s*\(",
    ]],
}


def _decode_all(value: str, max_rounds: int = 3) -> str:
    """Percent-decode until stable (handles double-encoding like %2500)."""
    seen = value
    for _ in range(max_rounds):
        nxt = unquote(seen)
        if nxt == seen:
            break
        seen = nxt
    return seen


def haystack(path: str, query: str, body: str) -> str:
    """Build the string Blue matches against: raw and fully-decoded forms of each
    field, joined so a pattern hidden by encoding is still caught in the raw copy."""
    parts: list[str] = []
    for value in (path or "", query or "", body or ""):
        parts.append(value)
        decoded = _decode_all(value)
        if decoded != value:
            parts.append(decoded)
    return "\n".join(parts)


def matches(label: str, path: str, query: str, body: str) -> bool:
    text = haystack(path, query, body)
    return any(pat.search(text) for pat in SIGNATURES[label])


def classify(path: str, query: str, body: str) -> str:
    """Return a taxonomy label: the first matching category by PRIORITY, else benign."""
    text = haystack(path, query, body)
    for label in PRIORITY:
        if any(pat.search(text) for pat in SIGNATURES[label]):
            return label
    return "benign"
