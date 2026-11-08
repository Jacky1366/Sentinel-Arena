"""Prompt building (stable prefix first, D11) and safe JSON parsing. PURE.

A prompt is: fixed system prompt -> append-only history -> newest turn last. The
system prompt may not contain volatile values (timestamps, match ids, request
ids), because any byte that changes between calls breaks provider-side prompt
caching from that byte on. History is append-only, so the request for round N+1
starts with the exact bytes of the request for round N.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

VOLATILE = {
    "uuid": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    "timestamp": re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"),
    "match_id": re.compile(r"\b\d{8}T\d{6}Z-[0-9a-f]{4}\b|\bm\d{3,}\b"),
}


class PromptBuilder:
    def __init__(self, system: str, forbidden: tuple[str, ...] = ()):
        for kind, pattern in VOLATILE.items():
            if pattern.search(system):
                raise ValueError(f"system prompt contains a volatile value ({kind}); "
                                 f"put per-call values in the newest turn instead")
        for s in forbidden:
            if s in system:
                raise ValueError(f"system prompt contains a forbidden string: {s!r}")
        self._system = system
        self._turns: list[tuple[str, str]] = []

    @property
    def system(self) -> str:
        return self._system

    def add(self, role: str, content: str) -> None:
        """Append one turn. Roles alternate, starting with the user."""
        if role not in ("user", "assistant"):
            raise ValueError(f"role must be user or assistant, not {role!r}")
        expected = "user" if len(self._turns) % 2 == 0 else "assistant"
        if role != expected:
            raise ValueError(f"turn {len(self._turns) + 1} must be {expected}, not {role}")
        self._turns.append((role, content))

    def messages(self) -> list[dict]:
        """A fresh list each call: callers can never edit the history in place."""
        return [{"role": r, "content": c} for r, c in self._turns]

    def render(self) -> bytes:
        """Prefix-stable byte form: system line, then one JSON line per turn."""
        lines = [json.dumps(self._system, ensure_ascii=False)]
        lines += [json.dumps({"role": r, "content": c}, ensure_ascii=False, sort_keys=True)
                  for r, c in self._turns]
        return ("\n".join(lines) + "\n").encode("utf-8")


@dataclass(frozen=True)
class ParsedJSON:
    ok: bool
    value: Any = None
    error: str | None = None


_FULL_FENCE = re.compile(r"\A```[A-Za-z0-9_-]*[ \t]*\n?(.*?)\n?[ \t]*```\Z", re.S)
_ANY_FENCE = re.compile(r"```[A-Za-z0-9_-]*[ \t]*\n(.*?)```", re.S)


def parse_json(text: str | None, expect_object: bool = True) -> ParsedJSON:
    """Strip markdown fences and parse. Never raises: returns a structured error.
    The error never echoes the text (it may be long, or contain anything)."""
    if text is None or not text.strip():
        return ParsedJSON(False, error="empty response")
    s = text.strip()
    blocks = _ANY_FENCE.findall(s)
    m = _FULL_FENCE.match(s)
    if len(blocks) > 1:
        return ParsedJSON(False, error=f"{len(blocks)} fenced blocks; expected one")
    if m and "```" not in m.group(1):
        s = m.group(1).strip()
    elif len(blocks) == 1:
        s = blocks[0].strip()
    try:
        value = json.loads(s)
    except json.JSONDecodeError as exc:
        return ParsedJSON(False, error=f"invalid JSON at line {exc.lineno} col {exc.colno}: "
                                       f"{exc.msg}")
    except RecursionError:
        return ParsedJSON(False, error="invalid JSON: nested too deeply")
    if expect_object and not isinstance(value, dict):
        return ParsedJSON(False, error=f"expected a JSON object, got {type(value).__name__}")
    return ParsedJSON(True, value=value)
