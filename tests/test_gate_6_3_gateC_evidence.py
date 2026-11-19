"""The committed Stage 6.3 Gate C evidence (designer GO, 2026-11-18):
data/golden/replays/gate-6.3-C/, the three Gate B eval matches (TEST data, D35) each replayed
with Sonnet 5.5 + library v5 (thinking between_tools) and with Haiku 5.5 + the empty library
v0000. Read-only integrity checks: every file matches its replay.json hash, the copied inputs
match the committed source match, the library snapshot is the committed library file, and
the arm configuration and cost are the ones in the README."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO
import run_match  # noqa: E402

GATE = REPO / "data" / "golden" / "replays" / "gate-6.3-C"
LIB = REPO / "data" / "library"
COMMIT = "ea07305"
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "replay_manifest.schema.json")
                                         .read_text()))
SOURCES = {"eval-6.3-gateB-match1": "20261119T061057Z-6177",
           "eval-6.3-gateB-match2": "20261119T061403Z-789a",
           "eval-6.3-gateB-match3": "20261119T061702Z-18d1"}
# arm -> (model, thinking, library file)
ARMS = {"sonnet-v5": ("claude-sonnet-5-5", "between_tools", "rule_library_v0005.json"),
        "haiku-empty": ("claude-haiku-5-5", "disabled", "rule_library_v0000.json")}
COSTS = {"eval-6.3-gateB-match1-haiku-empty": (25, 0.001674),
         "eval-6.3-gateB-match1-sonnet-v5": (19, 0.022905),
         "eval-6.3-gateB-match2-haiku-empty": (25, 0.001657),
         "eval-6.3-gateB-match2-sonnet-v5": (20, 0.020302),
         "eval-6.3-gateB-match3-haiku-empty": (25, 0.001717),
         "eval-6.3-gateB-match3-sonnet-v5": (20, 0.021366)}


def test_exactly_the_six_replays_and_a_readme():
    assert sorted(p.name for p in GATE.iterdir()) == sorted([*COSTS, "README.md"])
    total = sum(json.loads((GATE / f / "replay.json").read_text())["cost"]["total_usd"]
                for f in COSTS)
    assert round(total, 6) == 0.069621


@pytest.mark.parametrize("folder", sorted(COSTS))
def test_files_match_their_hashes_sources_and_configuration(folder):
    d = GATE / folder
    m = json.loads((d / "replay.json").read_text())
    src_name = next(s for s in SOURCES if folder.startswith(s + "-"))
    arm = folder[len(src_name) + 1:]
    model, thinking, lib_file = ARMS[arm]
    assert SCHEMA.is_valid(m) and m["status"] == "completed"
    assert m["git"]["commit"].startswith(COMMIT) and m["git"]["dirty"] is False
    p = m["blue_params"]
    assert m["blue_engine"] == "claude" and p["model"] == model
    assert p["request"]["thinking"] == thinking and p["request"]["effort"] == "low"
    assert p["rules"]["mode"] == "on" and p["caching"] == {"mode": "on", "ttl": "5m"}
    assert p["prompt_version"] == "2"
    hashes = run_match.artifact_hashes(d)
    hashes.pop("replay.json")
    assert hashes == m["artifacts"]  # nothing changed since the replay finished
    src = REPO / "data" / "golden" / src_name
    assert m["source"]["match_id"] == SOURCES[src_name]
    assert m["source"]["path"] == src.relative_to(REPO).as_posix()
    assert m["source"]["match_json_sha256"] == run_match.sha256_file(src / "match.json")
    for f in m["source"]["copied"]:
        assert run_match.sha256_file(d / f) == m["source"]["artifacts"][f]["sha256"]
    assert run_match.sha256_file(d / "library.json") == \
        run_match.sha256_file(LIB / lib_file) == p["library"]["sha256"]
    calls, usd = COSTS[folder]
    assert m["cost"]["attempts"] == calls and abs(m["cost"]["total_usd"] - usd) < 1e-9
