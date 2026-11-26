"""Dashboard Battle model (Stage 7 #13): runs dashboard/test/*.test.mjs (node:test, no npm
dependency) against (a) the live-server event stream of a fake match and (b) the committed
demo bundles. Done when: a fake live match and an existing bundle both play through all
three acts. Skipped if node is not installed."""

from __future__ import annotations

import json
import os
import re
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
           "ARENA_BUNDLES": str(DASH / "public" / "data"),
           "ARENA_COMPARE": str(DASH / "public" / "compare" / "freeplay.json")}
    r = subprocess.run([NODE, "--test", "test/"], cwd=DASH, env=env, capture_output=True,
                       text=True, timeout=120)
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-2000:]
    assert "# fail 0" in r.stdout and "# skipped 0" in r.stdout


# #29: Battle and Compare are for a non-technical audience at a glance (display only).
JARGON = re.compile(r"\b(landed|benign|frozen log|Judge facts?|proxy log|request_id|match id)\b", re.I)


def _visible_strings(src: str, jsx: bool = True) -> list[str]:
    """JSX text and string literals of a view, without comments and without code."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("//"))
    texts = re.findall(r">([^<>{}=&|;()]+)<", src) if jsx else []  # JSX text
    texts += re.findall(r"\"([^\"\n]*)\"|`([^`\n]*)`", src)        # literals (tuples)
    flat = []
    for t in texts:
        flat += [x for x in (t if isinstance(t, tuple) else (t,)) if x]
    flat = [re.sub(r"\$\{[^}]*\}", "", t) for t in flat]              # interpolated code
    return [t for t in flat if " " in t.strip()]                   # words, not class names


@pytest.mark.parametrize("view", ["battle/Battle.jsx", "compare/Compare.jsx", "battle/model.js",
                                  "compare/compareModel.js", "labels.js"])
def test_battle_and_compare_use_plain_words(view):
    src = (DASH / "src" / view).read_text(encoding="utf-8")
    shown = _visible_strings(src, jsx=view.endswith(".jsx"))
    bad = [t for t in shown if JARGON.search(t) and "className" not in t]
    assert bad == [], bad
    assert not re.search(r"\bD\d{2}\b", "\n".join(shown))


def test_inspect_is_an_audit_link_not_a_main_tab():
    app = (DASH / "src" / "App.jsx").read_text(encoding="utf-8")
    assert 'const TABS = ["battle", "compare", "report"];' in app
    assert ">\n          {tab === \"audit\" ? \"← back\" : \"Audit\"}" in app
