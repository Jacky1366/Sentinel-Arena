"""Path predicates shared by Red's guard and the Judge's variant mutator (Stage 6.1,
D32). PURE.

`above_root` is the ONE definition of nginx limitation #1 (contract §9): a path whose
normalized form climbs above the web root is rejected by nginx while it parses the
request line, so it is logged as stray (empty request_id and path) and is invisible to
Blue and the Judge. red/red_guard.py blocks such a path before it is sent;
judge/variants.py excludes such a variant from counting (it could never appear in a
real log). tools/verify_red_guard.py checks this function against the real nginx.

Lives in the neutral rules/ package so judge/ never imports red/. Any behaviour change
here is governed by judge.JUDGE_VERSION.
"""

from __future__ import annotations

from rules import normalize


def above_root(path: str) -> bool:
    """True if the path's normalized form climbs above the web root. Decodes percent
    sequences first (nginx decodes before resolving dot-segments); the query string and
    fragment are ignored."""
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
