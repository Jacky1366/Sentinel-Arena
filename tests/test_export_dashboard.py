"""Dashboard export (Stage 6.4, M8): tools/export_dashboard.py is a pure reader; every
value in a bundle is copied from an artifact; the running cost ends at the folder's own
total; the committed demo bundles regenerate byte for byte; and the built dashboard makes
no network request (offline demo)."""

from __future__ import annotations

import json
import re

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO
from stats import match_stats as ms  # noqa: E402
from tools import export_dashboard as ex  # noqa: E402

GOLDEN = REPO / "data" / "golden"
TRAIN = GOLDEN / "train-6.1b-gate1-match1"
SCRIPTED = GOLDEN / "scripted-baseline-benign-match"
DASH = REPO / "dashboard"
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "dashboard_bundle.schema.json")
                                         .read_text()))
DEMO = {"train-gate1-match1": TRAIN,
        "m5-library-gate3-match1": GOLDEN / "replays" / "gate-6.1b-2"
        / "ai-vs-ai-gate3-match1-library"}  # designer GO: the M5 library arm as demo data


def jl(p):
    return ms.read_rounds(p)


@pytest.mark.parametrize("folder", [TRAIN, SCRIPTED], ids=["train-ai", "scripted"])
def test_every_step_is_copied_from_the_artifacts(folder):
    b = ex.bundle(folder, "x")
    assert SCHEMA.is_valid(b)
    lines = [l for l in jl(folder / "proxy.jsonl") if l.get("request_id")]
    assert [s["request_id"] for s in b["steps"]] == [l["request_id"] for l in lines]
    rounds = {r["request_id"]: r for r in jl(folder / "rounds.jsonl")}
    benign = {r["request_id"]: r for r in jl(folder / "benign_results.jsonl")}
    verdicts = {v["request_id"]: v for v in jl(folder / "verdicts.jsonl")}
    for s, line in zip(b["steps"], lines):
        rid = s["request_id"]
        assert s["request"]["method"] == line["method"] and s["request"]["status"] == line["status"]
        if s["red"]["kind"] == "attack":
            r = rounds[rid]
            assert (s["red"]["round"], s["red"]["label"]) == (r["round"], r["label"])
            assert (s["judge"]["landed"], s["judge"]["detected"], s["judge"]["type_correct"]) == \
                (r["landed"], r["detected"], r["type_correct"])
        else:
            assert s["judge"]["false_positive"] == benign[rid]["false_positive"]
        v = verdicts[rid]
        assert s["blue"]["verdict"] == v["verdict"]
        assert s["blue"]["source"] == v.get("source")
        assert s["blue"]["rule_origin"] == v.get("rule_origin")
        assert s["log_seq"] == v["log_seq"]


def test_running_cost_is_monotone_and_ends_at_the_folder_total():
    b = ex.bundle(TRAIN, "x")
    m = json.loads((TRAIN / "match.json").read_text())
    usd = [s["cost_so_far"]["usd"] for s in b["steps"]]
    calls = [s["cost_so_far"]["calls"] for s in b["steps"]]
    assert usd == sorted(usd) and calls == sorted(calls)
    assert b["steps"][-1]["cost_so_far"] == b["total_cost"]
    assert b["total_cost"]["calls"] == m["cost"]["attempts"]
    assert abs(b["total_cost"]["usd"] - m["cost"]["total_usd"]) < 1e-9
    scripted = ex.bundle(SCRIPTED, "y")
    assert scripted["total_cost"]["calls"] == 0 and scripted["meta"]["library"] is None


def test_library_rules_and_origin_come_from_the_snapshot():
    b = ex.bundle(DEMO["m5-library-gate3-match1"], "z")
    lib = [r for r in b["rules"] if r["origin"] == "library"]
    assert len(lib) == b["meta"]["library"]["entries"] == 19
    assert all(r["rule_id"].startswith("lib-") for r in lib)
    fired = {i for s in b["steps"] if s["blue"] for i in s["blue"]["fired_rule_ids"]}
    assert fired <= {r["rule_id"] for r in b["rules"]}
    assert sum(s["blue"]["rule_origin"] == "library" for s in b["steps"]) == 9


def test_export_refuses_bad_names_and_the_source_folder(tmp_path):
    with pytest.raises(ValueError, match="bundle name"):
        ex.export(TRAIN, "Bad Name", tmp_path)
    with pytest.raises(ValueError, match="source folder"):
        ex.export(TRAIN, "ok", TRAIN / "dash")
    assert not (TRAIN / "dash").exists()
    (tmp_path / "x").mkdir()
    with pytest.raises(ValueError, match="not a frozen"):
        ex.bundle(tmp_path / "x", "x")


def test_committed_demo_bundles_regenerate_byte_for_byte(tmp_path):
    for name, folder in DEMO.items():
        ex.export(folder, name, tmp_path)
        assert (tmp_path / f"{name}.json").read_bytes() == \
            (DASH / "public" / "data" / f"{name}.json").read_bytes(), name
    assert (tmp_path / "bundles.js").read_bytes() == \
        (DASH / "public" / "data" / "bundles.js").read_bytes()
    assert sorted(p.name for p in (DASH / "public" / "data").iterdir()) == \
        sorted([*(f"{n}.json" for n in DEMO), "bundles.js"])


NETWORK = re.compile(r"\bfetch\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|"
                     r"navigator\.serviceWorker")


def test_the_built_dashboard_is_offline():
    html = (DASH / "dist" / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="([^"]*)"', html)
    assert refs == ["./data/bundles.js"]  # everything else is inlined
    assert not NETWORK.search(html)
    for p in (DASH / "src").rglob("*"):
        if p.is_file():
            text = p.read_text(encoding="utf-8")
            assert not NETWORK.search(text), p.name
            assert not re.search(r"https?://", text), p.name
    for name in [*(f"{n}.json" for n in DEMO), "bundles.js"]:
        assert (DASH / "dist" / "data" / name).read_bytes() == \
            (DASH / "public" / "data" / name).read_bytes(), f"rebuild the dashboard: {name}"


def test_dependencies_are_pinned():
    pkg = json.loads((DASH / "package.json").read_text())
    for deps in (pkg["dependencies"], pkg["devDependencies"]):
        assert all(re.fullmatch(r"\d+\.\d+\.\d+", v) for v in deps.values()), deps
    assert (DASH / "package-lock.json").is_file()
