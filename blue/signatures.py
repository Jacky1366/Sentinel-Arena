"""Generic, OWASP-style detection signatures for Blue v0.

IMPORTANT: these signatures are GENERIC patterns for the three CWE classes. They
are deliberately written WITHOUT looking at red/payloads.json — Blue v0 is a
baseline classifier, not an answer key. Blue classifies from the proxy log fields
only (path, query, body); it never sees request ids, headers, or ground truth.

Inputs may be percent-encoded, including double-encoded (e.g. %2500 -> %00 -> NUL).
Each field is expanded into its normalized FORMS by rules/normalize.py, the ONE
normalization shared with the rule engine and the Judge (raw form, every decoding
step, and '+'-decoding for query/body); a pattern matches if it matches any form.

classify() returns one taxonomy label. v0 is single-label, first-match by a fixed
category priority, so the result is deterministic.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rules import normalize  # noqa: E402

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


_decode_all = normalize.decode_all  # kept for existing callers/tests


def haystack(path: str, query: str, body: str) -> str:
    """The string Blue matches against: every normalized form of path, query and
    body (rules/normalize.py), joined with newlines. Unlike the rule engine, which
    matches each field separately, a signature can in principle match across this
    join (contract §6.7, expressiveness finding)."""
    parts: list[str] = []
    for field, value in (("path", path), ("query", query), ("body", body)):
        parts.extend(normalize.field_forms(field, value))
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
