"""The committed Stage 6.1b M5 replay evidence (designer GO for this integrity test,
2026-11-18): data/golden/replays/gate-6.1b-2/ (rules on, empty v0000 vs library v5) and
data/golden/replays/gate-6.1b-2b/ (rules off, no library), all on the three Stage 5.7 Gate 3
sources. Read-only integrity checks: every file matches its replay.json hash, the copied
inputs match the committed source match, the library snapshot is the committed library
file, and the configuration and cost are the ones reported in docs/progress.md."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO
import run_match  # noqa: E402

REPLAYS = REPO / "data" / "golden" / "replays"
LIB = REPO / "data" / "library"
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "replay_manifest.schema.json")
                                         .read_text()))
SOURCES = {"ai-vs-ai-gate3-match1": "20261114T072114Z-1a3a",
           "ai-vs-ai-gate3-match2": "20261114T072400Z-a58a",
           "ai-vs-ai-gate3-match3": "20261114T072621Z-a41b"}
# gate folder -> (commit, {arm: library file or None}, rules mode,
#                 {folder: (calls, usd)}, (total calls, total usd))
GATES = {
    "gate-6.1b-2": ("fe37b2f", {"empty": "rule_library_v0000.json",
                                "library": "rule_library_v0005.json"}, "on",
                    {"ai-vs-ai-gate3-match1-empty": (23, 0.001753),
                     "ai-vs-ai-gate3-match1-library": (17, 0.000963),
                     "ai-vs-ai-gate3-match2-empty": (23, 0.001476),
                     "ai-vs-ai-gate3-match2-library": (18, 0.001005),
                     "ai-vs-ai-gate3-match3-empty": (24, 0.001602),
                     "ai-vs-ai-gate3-match3-library": (17, 0.000965)}),
    "gate-6.1b-2b": ("d65e2cd", {}, "off",
                     {"ai-vs-ai-gate3-match1-off": (26, 0.001385),
                      "ai-vs-ai-gate3-match2-off": (26, 0.001232),
                      "ai-vs-ai-gate3-match3-off": (27, 0.001328)}),
}
CASES = [(g, f) for g, spec in GATES.items() for f in spec[3]]


def manifest(gate, folder):
    return json.loads((REPLAYS / gate / folder / "replay.json").read_text())


@pytest.mark.parametrize("gate", sorted(GATES))
def test_exactly_the_replays_and_a_readme(gate):
    assert sorted(p.name for p in (REPLAYS / gate).iterdir()) == \
        sorted([*GATES[gate][3], "README.md"])


@pytest.mark.parametrize("gate,folder", CASES)
def test_files_match_their_hashes_sources_and_configuration(gate, folder):
    commit, libs, mode, costs = GATES[gate]
    d, m = REPLAYS / gate / folder, manifest(gate, folder)
    src_name, arm = folder.rsplit("-", 1)
    assert SCHEMA.is_valid(m) and m["status"] == "completed"
    assert m["git"]["commit"].startswith(commit) and m["git"]["dirty"] is False
    p = m["blue_params"]
    assert m["blue_engine"] == "claude" and p["model"] == "claude-haiku-5-5"
    assert p["rules"]["mode"] == mode and p["caching"] == {"mode": "on", "ttl": "5m"}
    assert p["prompt_version"] == ("2" if mode == "on" else "1")
    hashes = run_match.artifact_hashes(d)
    hashes.pop("replay.json")
    assert hashes == m["artifacts"]  # nothing changed since the replay finished
    src = REPO / "data" / "golden" / src_name
    assert m["source"]["match_id"] == SOURCES[src_name]
    assert m["source"]["path"] == src.relative_to(REPO).as_posix()
    assert m["source"]["match_json_sha256"] == run_match.sha256_file(src / "match.json")
    for f in m["source"]["copied"]:
        assert run_match.sha256_file(d / f) == m["source"]["artifacts"][f]["sha256"]
    lib_file = libs.get(arm)
    if lib_file is None:
        assert p.get("library") is None and not (d / "library.json").exists()
    else:
        assert run_match.sha256_file(d / "library.json") == \
            run_match.sha256_file(LIB / lib_file) == p["library"]["sha256"]
    calls, usd = costs[folder]
    assert m["cost"]["attempts"] == calls and abs(m["cost"]["total_usd"] - usd) < 1e-9


@pytest.mark.parametrize("gate", sorted(GATES))
def test_gate_totals_are_the_reported_ones(gate):
    costs = GATES[gate][3]
    by_arm: dict[str, list] = {}
    for folder in costs:
        m = manifest(gate, folder)
        by_arm.setdefault(folder.rsplit("-", 1)[1], []).append(m["cost"])
    totals = {a: (sum(c["attempts"] for c in cs), round(sum(c["total_usd"] for c in cs), 6))
              for a, cs in by_arm.items()}
    expect = {"gate-6.1b-2": {"empty": (70, 0.004831), "library": (52, 0.002933)},
              "gate-6.1b-2b": {"off": (79, 0.003945)}}
    assert totals == expect[gate]
