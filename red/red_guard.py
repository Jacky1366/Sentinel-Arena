"""Rules of engagement for AI Red (Stage 5.6, D15). PURE.

The body runs these checks on Red's proposed request BEFORE anything is sent. Red
supplies only the method, the path (with any query string) and the body; the body
fixes the scheme, host and headers. A failed check means: nothing is sent, no Red
record is written, a `red_unsent.jsonl` line records the reason, and the slot is
consumed (the next turn tells Red its request was blocked and why).

Each reason is one machine-readable string:
  scope_violation    the path carries a scheme, authority (//), host or port
  method_not_allowed the method is not in the allowlist
  invalid_encoding   the path is not a valid, percent-encoded request target
  above_root         the normalized path climbs above the web root (limitation #1:
                     nginx would reject it before logging, so it must never be sent)
  invalid_label      the label is not one of the three CWE values (D5)
  path_too_large     the path exceeds MAX_PATH_CHARS
  body_too_large     the body exceeds MAX_BODY_CHARS

above_root mirrors nginx: it percent-decodes the path (every round, as
rules/normalize does), then resolves dot-segments; if the depth ever goes below the
root, the path is blocked. tools/verify_red_guard.py checks this against the real
nginx on the arena port.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from rules import normalize

ALLOWED_METHODS = ("GET", "POST")
ALLOWED_LABELS = ("CWE-89", "CWE-79", "CWE-22")
MAX_PATH_CHARS = 2048
MAX_BODY_CHARS = 4096

# A valid request-target: visible ASCII only, well-formed %XX, no spaces or controls.
_VALID_TARGET = re.compile(r"^(?:%[0-9A-Fa-f]{2}|[!-~])+$")
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    reason: str | None = None
    detail: str | None = None


def _above_root(path: str) -> bool:
    """True if the path's normalized form climbs above the web root. Decodes percent
    sequences first (nginx decodes before resolving dot-segments)."""
    only_path = path.split("?", 1)[0].split("#", 1)[0]
    decoded = normalize.decode_all(only_path)
    depth = 0
    for seg in decoded.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


def check(method: str, path: str, body: str, label: str) -> GuardResult:
    """Validate one proposed Red request. Order is fixed so the reason is stable."""
    if label not in ALLOWED_LABELS:
        return GuardResult(False, "invalid_label", f"label {label!r} not in {ALLOWED_LABELS}")
    if method not in ALLOWED_METHODS:
        return GuardResult(False, "method_not_allowed", f"method {method!r}")
    if len(path) > MAX_PATH_CHARS:
        return GuardResult(False, "path_too_large", f"{len(path)} > {MAX_PATH_CHARS}")
    if len(body) > MAX_BODY_CHARS:
        return GuardResult(False, "body_too_large", f"{len(body)} > {MAX_BODY_CHARS}")
    if not path.startswith("/") or path.startswith("//"):
        return GuardResult(False, "scope_violation", "path must begin with a single '/'")
    split = urlsplit(path)
    if split.scheme or split.netloc:
        return GuardResult(False, "scope_violation", "path carries a scheme or authority")
    if "\\" in path or _BAD_PERCENT.search(path) or not _VALID_TARGET.match(path):
        return GuardResult(False, "invalid_encoding", "not a valid percent-encoded target")
    if _above_root(path):
        return GuardResult(False, "above_root", "normalized path climbs above the web root")
    return GuardResult(True)
