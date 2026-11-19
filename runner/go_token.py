"""The designer's GO token, by construction (Stage 6.1b).

Every paid entry point (a tool run with `--real-calls` / `--real-call`) also requires the
environment variable ARENA_GO to equal the id of the gate being run, e.g.
`ARENA_GO=gate-6.1b-1`. Without it the tool exits 2 BEFORE constructing Ops, touching
Docker or building an AI client. The token is set per command by whoever runs the gate
after the designer's GO; it is never stored in `.env` and tests never set it
(tests/conftest.py removes every ARENA_* variable).
"""

from __future__ import annotations

import os
from collections.abc import Mapping

ENV = "ARENA_GO"


def check(gate_id: str, env: Mapping[str, str] | None = None) -> str | None:
    """None when ARENA_GO equals gate_id; otherwise the refusal message."""
    got = (os.environ if env is None else env).get(ENV)
    if got == gate_id:
        return None
    seen = "unset" if got is None else f"set to {got!r}"
    return (f"REFUSED: {ENV}={gate_id} is required for this paid run ({ENV} is {seen}); "
            f"set it only after the designer's GO for {gate_id}. Nothing was called.")
