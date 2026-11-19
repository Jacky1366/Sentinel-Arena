"""Committed Stage 6.3 D42 open-Blue evidence (data/golden/replays/gate-6.3-C-open/): 6 open
Blue (v3-open) replays of the free-play + deepseek logs. Read-only integrity + the headline
analysis result. The 2c prompt-FP numbers are in the README (not persisted as verdict rows)."""

from __future__ import annotations

import json

import pytest

from llm_fakes import REPO
import run_match  # noqa: E402
from blue import claude_engine  # noqa: E402

GATE = REPO / "data" / "golden" / "replays" / "gate-6.3-C-open"
GOLDEN = REPO / "data" / "golden"
COMMIT = "724979c"
LIB_V5_SHA = "324a1eceace9499606284230f4997cb961da39af6ec67ab2a6d7c4e70a168bc7"
ARMS = [f"eval-6.3-gateB-{k}-match{i}" for k in ("freeplay", "deepseek") for i in (1, 2, 3)]


def rounds(d):
    return {r["round"]: r for r in (json.loads(l) for l in
                                    (d / "rounds.jsonl").read_text().splitlines())}


def test_six_open_replays_committed_with_the_open_prompt():
    got = sorted(p.name for p in GATE.iterdir() if p.name.startswith("eval-"))
    assert got == sorted(f"{a}-open" for a in ARMS)
    assert (GATE / "fp-on").is_dir() and (GATE / "fp-open").is_dir()  # the 2c FP check


@pytest.mark.parametrize("arm", ARMS)
def test_open_replay_files_match_hashes_and_config(arm):
    d = GATE / f"{arm}-open"
    m = json.loads((d / "replay.json").read_text())
    assert m["status"] == "completed" and m["git"]["commit"].startswith(COMMIT)
    p = m["blue_params"]
    assert p["prompt_version"] == "3-open"
    assert p["system_prompt_sha256"] == claude_engine.SYSTEM_PROMPT_V3_OPEN_SHA256
    assert p["rules"]["mode"] == "on" and p["library"]["sha256"] == LIB_V5_SHA
    assert m["source"]["path"] == (GOLDEN / arm).relative_to(REPO).as_posix()
    hashes = run_match.artifact_hashes(d)
    hashes.pop("replay.json")
    assert hashes == m["artifacts"]


def test_open_recovers_the_two_landed_other_class_free_play_misses():
    # freeplay-match2: original Blue missed two landed `other`-class attacks; open catches both.
    src = GOLDEN / "eval-6.3-gateB-freeplay-match2"
    o, n = rounds(src), rounds(GATE / "eval-6.3-gateB-freeplay-match2-open")
    gained = [r for r in sorted(n) if n[r].get("detected") is True
              and o.get(r, {}).get("detected") is not True]
    assert gained == [8, 10]
    for r in gained:
        assert n[r]["verdict"] == "other" and n[r].get("newly_solved")  # landed


@pytest.mark.parametrize("arm", [f"eval-6.3-gateB-deepseek-match{i}" for i in (1, 2, 3)])
def test_widening_does_not_hurt_the_taxonomy_arm(arm):
    o, n = rounds(GOLDEN / arm), rounds(GATE / f"{arm}-open")
    det = lambda rr: sum(1 for r in rr.values() if r.get("detected") is True)  # noqa: E731
    tc = lambda rr: sum(1 for r in rr.values() if r.get("type_correct") is True)  # noqa: E731
    assert det(n) == det(o) and tc(n) == tc(o)
    assert not any(r.get("verdict") == "other" for r in n.values())  # no CWE attack mislabelled
