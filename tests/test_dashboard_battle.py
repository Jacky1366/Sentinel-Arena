"""Dashboard Battle model (Stage 7 #13): runs dashboard/test/*.test.mjs (node:test, no npm
dependency) against (a) the live-server event stream of a fake match and (b) the committed
demo bundles. Done when: a fake live match and an existing bundle both play through all
three acts. Skipped if node is not installed."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from live_fakes import PRICES, lab, play  # noqa: F401 (fixture)
from llm_fakes import REPO
from liveserver import tailer as T

DASH = REPO / "dashboard"
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_battle_model_plays_live_and_replay(lab, tmp_path):
    live, runs, transcript = lab
    code, match_dir = play(lab)
    assert code == 0
    log = T.EventLog()
    T.Tailer(log, live, runs, transcript, prices=PRICES).poll()
    events = tmp_path / "events.jsonl"
    events.write_text("".join(json.dumps(e) + "\n" for e in log.since(None)))
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("ARENA_")},
           "ARENA_LIVE_EVENTS": str(events), "ARENA_LIVE_MATCH": str(match_dir),
           "ARENA_BUNDLES": str(DASH / "public" / "data")}
    r = subprocess.run([NODE, "--test", "test/"], cwd=DASH, env=env, capture_output=True,
                       text=True, timeout=120)
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-2000:]
    assert "# fail 0" in r.stdout and "# skipped 0" in r.stdout
