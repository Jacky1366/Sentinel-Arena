"""run_match.py --blue claude --blue-rules-mode off|shadow|on (Stage 5.5): wiring, the
judge_rules step (facts 3 + 4b inside the match), match.json 0.6, too-broad rules as
fact-4a false positives, and the summary. FakeOps (no Docker) + the fake provider
only: no real adapter is reachable."""

from __future__ import annotations

import copy
import json

import pytest

from llm_fakes import CONFIG, PRICES, REPO, lc
from test_blue_rules import Brain, cond, verdict
from test_run_match_failure import BENIGN, PREVIOUS, FakeOps, assert_finalized, failing, \
    manifest_of, run_match
from blue import claude_engine  # noqa: E402
from stats import cost as cost_stats  # noqa: E402


@pytest.fixture
def dirs(tmp_path):
    live = tmp_path / "runs" / "live"
    (live / "archive").mkdir(parents=True)
    (live / "proxy.jsonl").write_text(PREVIOUS)
    return live, tmp_path / "runs"


def broad(view):
    """Calls everything CWE-89 and proposes a rule on '/rest' paths: too broad."""
    return verdict("CWE-89", {"conditions": [cond(field="path", pattern="/rest")]})


class RulesOps(FakeOps):
    """FakeOps traffic (2 attacks, then 2 benign lines) + a Brain on the fake provider."""

    def __init__(self, live, answer=broad, cfg=None, **kw):
        super().__init__(live, benign=BENIGN, **kw)
        self.cfg = cfg or copy.deepcopy(CONFIG)
        self.brain = Brain(answer)

    def llm_setup(self):
        return self.cfg, PRICES, cost_stats.price_table_ref()

    def blue_client(self, config, prices):
        self.calls.append("blue_client")
        return lc.LLMClient(config=config, prices=prices, adapters={"fake": self.brain},
                            env={}, sleep=lambda s: None,
                            dotenv_path=REPO / "nonexistent" / "no.env")


def go(ops, dirs, mode=None, engine="claude"):
    live, runs = dirs
    out: list[str] = []
    code, match_dir = run_match.run_match(ops=ops, live_dir=live, runs_dir=runs,
                                          engine=engine, blue_rules_mode=mode,
                                          out=out.append)
    return code, match_dir, "\n".join(out)


def rows(match_dir, name):
    p = match_dir / name
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else None


def test_on_hot_loads_and_the_judge_scores_the_rules_in_the_match(dirs):
    ops = RulesOps(dirs[0])
    code, d, out = go(ops, dirs, "on")
    assert code == 0, out
    m = assert_finalized(dirs[0], d)
    assert m["schema_version"] == "0.6"
    assert m["blue_params"]["rules"] == {"mode": "on", "max_rules": 10}
    assert m["blue_params"]["prompt_version"] == "2"
    assert m["blue_params"] == claude_engine.blue_params(CONFIG, "fake-small", 1, "on")
    v = rows(d, "verdicts.jsonl")
    assert [(r["source"], r["verdict"]) for r in v] == [("ai", "CWE-89")] + \
        [("rule", "CWE-89")] * 3
    assert len(rows(d, "api_calls.jsonl")) == 1 == len(ops.brain.calls)
    # rounds and benign results carry the rule source; the broad rule's FPs count (4a)
    assert [r["verdict_source"] for r in rows(d, "rounds.jsonl")] == ["ai", "rule"]
    b = rows(d, "benign_results.jsonl")
    assert [(r["verdict_source"], r["false_positive"]) for r in b] == [("rule", True)] * 2
    assert {r["schema_version"] for r in rows(d, "rounds.jsonl") + b} == {"0.3"}
    # facts 3 + 4b, inside the match
    (res,) = rows(d, "rule_results.jsonl")
    assert (res["rule_id"], res["replay_fires"], res["source_label"],
            res["cwe_matches_source"]) == ("r-001", True, "CWE-89", True)
    assert res["fixture_fires"] > 0  # '/rest' also matches the benign fixture
    for name in ("rules.jsonl", "rule_rejections.jsonl", "rule_results.jsonl"):
        assert name in m["artifacts"]
    flat = " ".join(out.split())
    assert "rules mode on: proposed 1 stored 1 rejected 0" in flat
    assert "AI calls saved 3" in flat and "r-001 CWE-89" in flat
    assert "FP rate 2/2 (100%)" in flat


def test_shadow_records_rules_but_verdicts_stay_ai(dirs):
    ops = RulesOps(dirs[0])
    code, d, out = go(ops, dirs, "shadow")
    assert code == 0, out
    m = manifest_of(d)
    assert m["blue_params"]["rules"]["mode"] == "shadow"
    v = rows(d, "verdicts.jsonl")
    assert {r["source"] for r in v} == {"ai"} and len(ops.brain.calls) == 4
    stored = rows(d, "rules.jsonl")
    assert len(stored) == 4 and {r["hot_loaded"] for r in stored} == {False}
    results = rows(d, "rule_results.jsonl")
    assert [r["replay_reason"] for r in results] == [None, None, "source_benign",
                                                     "source_benign"]
    kinds = [a["kind"] for a in rows(d, "anomalies.jsonl")]
    assert kinds.count("rule_source_benign") == 2  # rules born from benign lines
    assert "AI calls saved 0" in " ".join(out.split())


def test_off_is_stage_5_4_with_no_rule_artifacts(dirs):
    ops = RulesOps(dirs[0], answer=lambda v: verdict("CWE-89"))
    code, d, out = go(ops, dirs, "off")
    assert code == 0, out
    m = manifest_of(d)
    assert m["blue_params"]["rules"] == {"mode": "off", "max_rules": 10}
    assert m["blue_params"]["prompt_version"] == "1"
    assert {r["schema_version"] for r in rows(d, "verdicts.jsonl")} == {"0.2"}
    for name in ("rules.jsonl", "rule_rejections.jsonl", "rule_results.jsonl"):
        assert not (d / name).exists(), name
    assert {c["system"] for c in ops.brain.calls} == {claude_engine.SYSTEM_PROMPT}
    assert "rules mode" not in out


def test_config_mode_is_the_default_and_the_flag_overrides_it(dirs):
    cfg = copy.deepcopy(CONFIG)
    cfg["agents"]["blue"]["rules"] = {"mode": "shadow", "max_rules": 1}
    code, d, _ = go(RulesOps(dirs[0], cfg=cfg), dirs)
    assert code == 0
    m = manifest_of(d)
    assert m["blue_params"]["rules"] == {"mode": "shadow", "max_rules": 1}
    assert [x["reasons"][0]["code"] for x in rows(d, "rule_rejections.jsonl")] == \
        ["rule_cap_reached"] * 3


def test_rules_mode_with_scripted_blue_is_refused_at_preflight(dirs):
    code, d, out = go(FakeOps(dirs[0]), dirs, "on", engine="scripted")
    assert (code, d) == (2, None) and "needs --blue claude" in out


def test_unknown_mode_is_refused_at_preflight(dirs):
    code, d, out = go(RulesOps(dirs[0]), dirs, "sometimes")
    assert (code, d) == (2, None) and "rules mode" in out


def test_scripted_match_runs_judge_rules_and_writes_nothing_for_it(dirs):
    code, d, out = go(FakeOps(dirs[0]), dirs, engine="scripted")
    assert code == 0, out
    assert not (d / "rule_results.jsonl").exists()
    assert manifest_of(d)["failed_step"] is None


def test_judge_rules_failure_is_finalized_with_its_step(dirs):
    ops = failing("judge_rules")(dirs[0])
    code, d, out = go(ops, dirs, engine="scripted")
    m = manifest_of(d)
    assert code == 1 and m["failed_step"] == "judge_rules" and m["status"] == "failed"


def test_cli_flag_reaches_run_match(monkeypatch):
    seen = {}
    monkeypatch.setattr(run_match, "run_match", lambda **kw: (seen.update(kw), (0, None))[1])
    assert run_match.main(["--blue", "claude", "--blue-rules-mode", "shadow"]) == 0
    assert seen["blue_rules_mode"] == "shadow"
    with pytest.raises(SystemExit):
        run_match.main(["--blue-rules-mode", "always"])
