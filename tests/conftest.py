"""Session-wide test guard: no test can ever reach a real, paid AI provider.

Every test runs with every ARENA_* environment variable removed, and with
llm_client's .env path pointed at a file that does not exist. llm_client reads
keys ONLY from those two places and refuses any call without a key
(`missing_key`), so even a test whose fake is incomplete (a call that falls
through to a real adapter) is refused before anything is sent. This does not
rely on the fakes being complete (docs/ops.md). A test that needs a key sets a
fake one itself (monkeypatch.setenv / an explicit env dict).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from agents import llm_client  # noqa: E402

NO_DOTENV = REPO / "tests" / ".no-such-dotenv-for-tests"


@pytest.fixture(autouse=True)
def _no_real_api_keys(monkeypatch):
    for name in list(os.environ):
        if name.startswith("ARENA_"):
            monkeypatch.delenv(name)
    monkeypatch.setattr(llm_client, "DOTENV_PATH", NO_DOTENV)
    yield
