"""The ONE request normalization, used by scripted Blue's signatures and by the rule
engine (Blue's rules and the Judge's replay). PURE.

A field yields a list of FORMS; a pattern matches a field if it matches ANY form.

NORMALIZATION_VERSION "2" (Stage 5.3). Additive over "1" (Stage 3), which yielded
[raw, final unquote decoding (if different)]. Version 2 yields, de-duplicated, in
this order:

  1. the raw value
  2. every distinct `unquote` step (at most 3 rounds, stopping when stable); the
     last one is version 1's decoded form, the earlier ones are new
     (e.g. %2500 -> %00 -> NUL: the %00 step is now visible)
  3. query and body only: every distinct `unquote_plus` step (at most 3 rounds),
     so '+' becomes a space (e.g. UNION+SELECT -> UNION SELECT). Never for path,
     where '+' is literal.

`method` is never decoded. Decoding is content-type agnostic: a JSON body is
URL-decoded too (a literal %27 inside a JSON value also yields a form with ').
Inherited from Stage 3 and kept deliberately (contract §6.7 limitations).
"""

from __future__ import annotations

from urllib.parse import unquote, unquote_plus

NORMALIZATION_VERSION = "2"
MAX_ROUNDS = 3
FIELDS = ("method", "path", "query", "body")
PLUS_FIELDS = ("query", "body")


def _steps(value: str, decode) -> list[str]:
    """Every distinct decoding step of `value` (not including value itself)."""
    out, seen = [], value
    for _ in range(MAX_ROUNDS):
        nxt = decode(seen)
        if nxt == seen:
            break
        out.append(nxt)
        seen = nxt
    return out


def decode_all(value: str, max_rounds: int = MAX_ROUNDS) -> str:
    """Percent-decode until stable (version 1's single decoded form)."""
    seen = value
    for _ in range(max_rounds):
        nxt = unquote(seen)
        if nxt == seen:
            break
        seen = nxt
    return seen


def field_forms(field: str, value: str | None) -> list[str]:
    """All forms of one request field, raw first, de-duplicated, order stable."""
    value = value or ""
    if field == "method":
        return [value]
    forms = [value, *_steps(value, unquote)]
    if field in PLUS_FIELDS:
        forms += _steps(value, unquote_plus)
    out: list[str] = []
    for f in forms:
        if f not in out:
            out.append(f)
    return out


def request_forms(path: str, query: str, body: str, method: str = "") -> dict[str, list[str]]:
    return {"method": field_forms("method", method), "path": field_forms("path", path),
            "query": field_forms("query", query), "body": field_forms("body", body)}
