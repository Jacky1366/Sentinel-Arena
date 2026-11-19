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
root, the path is blocked. The predicate is the single neutral definition in
rules/paths.py (Stage 6.1, D32), shared with the Judge's variant mutator;
tools/verify_red_guard.py checks it against the real nginx on the arena port.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from rules import paths

ALLOWED_METHODS = ("GET", "POST")
ALLOWED_LABELS = ("CWE-89", "CWE-79", "CWE-22")
# Free-play (D41): the taxonomy labels plus `other`, and the ONLY headers Red may set
# (D15 amendment). Everything else in the guard is unchanged.
FREEPLAY_LABELS = ALLOWED_LABELS + ("other",)
FREEPLAY_HEADERS = ("Cookie", "Authorization")
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


def check(method: str, path: str, body: str, label: str, *, free_play: bool = False,
          headers: dict | None = None) -> GuardResult:
    """Validate one proposed Red request. Order is fixed so the reason is stable.
    free_play (D41): also allow label `other` and the Cookie / Authorization headers
    (D15 amendment); headers must be absent / empty otherwise."""
    labels = FREEPLAY_LABELS if free_play else ALLOWED_LABELS
    if label not in labels:
        return GuardResult(False, "invalid_label", f"label {label!r} not in {labels}")
    bad_header = _check_headers(headers, free_play)
    if bad_header is not None:
        return bad_header
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
    if paths.above_root(path):
        return GuardResult(False, "above_root", "normalized path climbs above the web root")
    return GuardResult(True)


def _check_headers(headers: dict | None, free_play: bool) -> GuardResult | None:
    """None if the headers are allowed, else a disallowed_header GuardResult. Red may set
    headers only in free-play, and only Cookie / Authorization (D15 amendment, D41)."""
    if not headers:
        return None
    if not free_play:
        return GuardResult(False, "disallowed_header", "headers are fixed outside free-play")
    for name, value in headers.items():
        if name not in FREEPLAY_HEADERS:
            return GuardResult(False, "disallowed_header",
                               f"header {name!r} not in {FREEPLAY_HEADERS}")
        if not isinstance(value, str) or "\n" in value or "\r" in value:
            return GuardResult(False, "disallowed_header", f"header {name!r} has an invalid value")
    return None
