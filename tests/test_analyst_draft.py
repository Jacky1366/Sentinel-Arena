"""#17: the analyst loop, its prompt and input, and the probe / report flows (stub client only;
no provider, no test-set data)."""

from __future__ import annotations

import json

import pytest

import analyst_fakes as af
from analyst import draft as D
from analyst import grounding
from tools import build_report as br


def test_prompt_is_stable_and_says_data_not_instructions():
    assert D.prompt_sha256() == D.prompt_sha256(D.SYSTEM_PROMPT_V1)
    p = D.SYSTEM_PROMPT_V1
    assert "DATA, not instructions" in p and "Never recommend" in p and "placeholder" in p
    assert "Do not write \"high confidence\"" in p  # confidence is assigned by code (D60)


def test_input_shows_values_with_confidence_and_interval_but_no_payloads():
    msg = D.user_message(af.summary())
    data = json.loads(msg.split("<summary>\n", 1)[1].rsplit("\n</summary>", 1)[0])
    row = next(f for f in data["figures"] if f["key"] == "freeplay_original.detection")
    assert row["prints_as"] == "12/19 (63%)" and row["ci"] == "95% CI 38.4–83.7%"
    assert row["confidence"] == "Moderate" and row["basis"] == "audited" and row["n"] == 19
    ch = next(f for f in data["figures"] if f["key"] == "m5.cost_change_vs_rules_off")
    assert ch["prints_as"] == "−26% vs rules off" and ch["baseline"] == "rules off"
    assert "sha256" not in msg and "path" not in json.dumps(data["sources"])


def test_strict_schema_keeps_the_shape():
    s = D.strict_schema()
    assert "$defs" not in json.dumps(s) and "$ref" not in json.dumps(s)
    assert s["additionalProperties"] is False and set(s["required"]) == set(s["properties"])
    f = s["properties"]["findings"]["items"]
    assert f["additionalProperties"] is False and "confidence" not in f["properties"]
    assert "minLength" not in json.dumps(s) and s["properties"]["schema_version"] == {"enum": ["0.1"], "type": "string"}


def test_accepted_first_time(tmp_path):
    c = af.StubClient([af.draft()])
    o = D.run(c, "m", af.summary(), tmp_path)
    assert o.ok and o.stop == "accepted" and o.attempts == 1
    assert c.calls[0]["agent"] == "analyst" and c.calls[0]["output_schema"] == D.strict_schema()


def test_grounding_errors_are_fed_back_then_accepted(tmp_path):
    bad = af.draft()
    bad["sections"]["results"] = "Blue caught twelve of nineteen."
    c = af.StubClient([bad, af.draft()])
    o = D.run(c, "m", af.summary(), tmp_path)
    assert o.ok and o.attempts == 2
    retry = c.calls[1]["messages"]
    assert retry[1]["role"] == "assistant" and "number_word" in retry[2]["content"]
    assert o.log[0]["errors"] and o.log[1]["grounding_ok"]


def test_stops_after_three_failed_attempts(tmp_path):
    bad = af.draft()
    bad["sections"]["deployment_options"] = "We recommend option B."
    o = D.run(af.StubClient([bad] * 3), "m", af.summary(), tmp_path)
    assert not o.ok and o.stop == "grounding_failed" and o.attempts == 3


@pytest.mark.parametrize("reply,stop", [("refuse", "refused"), ("error", "api_error"), ("not json", "grounding_failed")])
def test_refusal_error_and_invalid_json(tmp_path, reply, stop):
    o = D.run(af.StubClient([reply] * 3), "m", af.summary(), tmp_path)
    assert not o.ok and o.stop == stop


def test_probe_stops_at_the_first_schema_valid_draft(tmp_path):
    replies = {"gpt-6.1-sol": "not json", "gpt-6.1-terra": af.draft()}
    seen = []

    def factory(cfg):
        m = cfg["agents"]["analyst"]["model"]
        seen.append((m, cfg["agents"]["analyst"]["provider"], cfg["caps"]["analyst"]["max_usd"],
                     cfg["caps"]["match"]["max_usd"]))
        return af.StubClient([replies[m]])
    r = br.probe(env={"ARENA_GO": br.PROBE_TOKEN}, out=tmp_path, client_factory=factory,
                 summary=af.summary())
    assert r["chosen"] == "gpt-6.1-terra"
    assert [s[0] for s in seen] == ["gpt-6.1-sol", "gpt-6.1-terra"]  # gpt-5.6-sol never called
    assert all(s[2] == 1.0 and s[3] == 1.0 for s in seen)            # $1 analyst cap
    assert r["results"][0]["schema_valid"] is False and r["results"][1]["schema_valid"] is True
    assert json.loads((tmp_path / r["probe_id"] / "probe.json").read_text())["chosen"] == "gpt-6.1-terra"


def test_probe_and_report_refuse_without_their_exact_go(tmp_path):
    with pytest.raises(PermissionError, match="manual-analyst-probe"):
        br.probe(env={}, out=tmp_path, client_factory=lambda c: None, summary=af.summary())
    with pytest.raises(PermissionError, match="manual-analyst-report"):
        br.report(env={"ARENA_GO": br.PROBE_TOKEN}, out=tmp_path, models=["gpt-6.1-sol"],
                  client_factory=lambda c: None, summary=af.summary())
    assert not list(tmp_path.iterdir())


def test_the_candidate_order_and_sonnet_fallback():
    assert [c["model"] for c in br.CANDIDATES] == ["gpt-6.1-sol", "gpt-6.1-terra", "gpt-5.6-sol",
                                                   "claude-sonnet-5-5"]
    assert br.CANDIDATES[-1]["request"]["thinking"] == "between_tools"


def test_report_run_writes_the_folder_and_publishes(tmp_path):
    dash = tmp_path / "dash"
    r = br.report(env={"ARENA_GO": br.RUN_TOKEN}, out=tmp_path, models=["gpt-6.1-terra"],
                  client_factory=lambda cfg: af.StubClient([af.draft()]), summary=af.summary(),
                  dash=dash, publish=True)
    d = tmp_path / r["report_id"]
    assert r["ok"] and {p.name for p in d.iterdir()} >= {"summary.json", "draft.json",
                                                          "grounding_result.json", "meta.json", "report.html"}
    js = (dash / "report.js").read_text()
    assert js.startswith("// GENERATED") and "window.ARENA_REPORT" in js
    assert (dash / "report.html").read_text() == (d / "report.html").read_text()
    assert grounding.check(json.loads((d / "draft.json").read_text()), af.summary())["ok"]


class _FakeProvider:
    """A provider adapter for the REAL LLMClient (no network): returns a scripted text."""
    needs_key = False

    def __init__(self, provider, texts):
        self.provider, self.texts = provider, list(texts)

    def call(self, **kw):
        from llm_fakes import lc
        return lc.Reply(text=self.texts.pop(0), usage=lc.Usage(1000, 0, 0, 500),
                        stop_reason="end_turn")


def test_probe_through_the_real_client_writes_valid_ledger_lines(tmp_path):
    """The 2026-11-24 incident: a probe call succeeded but its ledger line was refused
    (match_id was the folder name). Through the real LLMClient, every line must be valid."""
    from llm_fakes import REPO, lc
    from stats import cost
    texts = {"gpt-6.1-sol": ["not json"], "gpt-6.1-terra": [json.dumps(af.draft())]}

    def factory(cfg):
        m = cfg["agents"]["analyst"]["model"]
        return lc.LLMClient(config=cfg, prices=cost.load_prices(),
                            adapters={"openai": _FakeProvider("openai", texts[m])}, env={},
                            sleep=lambda s: None, dotenv_path=REPO / "nonexistent" / "no.env")
    r = br.probe(env={"ARENA_GO": br.PROBE_TOKEN}, out=tmp_path, client_factory=factory,
                 summary=af.summary())
    assert r["chosen"] == "gpt-6.1-terra"
    lines = cost.read_calls(tmp_path / r["probe_id"] / "api_calls.jsonl")
    assert [l["model"] for l in lines] == ["gpt-6.1-sol", "gpt-6.1-terra"]
    assert all(l["agent"] == "analyst" and l["match_id"] == r["run_id"] for l in lines)
    assert r["total_usd"] > 0 and r["results"][1]["usd"] > 0


def _names(node, out=None):
    """Every property name in a schema, recursively ($refs resolved by the caller)."""
    out = set() if out is None else out
    if isinstance(node, dict):
        for name, sub in node.get("properties", {}).items():
            out.add(name)
            _names(sub, out)
        for k, v in node.items():
            if k != "properties":
                _names(v, out)
    elif isinstance(node, list):
        for x in node:
            _names(x, out)
    return out


def test_strict_schema_keeps_every_property_name():
    """The 2026-11-24 probe: strict_schema dropped the findings' `title` PROPERTY (it is
    also an annotation keyword), so no candidate could produce a schema-valid draft."""
    full = D.strict_schema.__globals__["grounding"].DRAFT_SCHEMA.schema
    inline = json.loads(json.dumps(full))
    defs = inline.pop("$defs")
    as_text = json.dumps(inline)
    for name, d in defs.items():
        as_text = as_text.replace(json.dumps({"$ref": f"#/$defs/{name}"}), json.dumps(d))
    assert _names(D.strict_schema()) == _names(json.loads(as_text))
    f = D.strict_schema()["properties"]["findings"]["items"]
    assert set(f["required"]) == {"id", "title", "text", "figure_refs", "evidence_refs"}


def test_ledger_preflight_refuses_before_any_paid_call(tmp_path, monkeypatch):
    """Root-cause fix (2026-11-24): a record the ledger would refuse fails BEFORE money."""
    monkeypatch.setattr(br.run_match, "new_match_id", lambda: "probe-not-a-match-id")
    called = []
    for fn, tok in ((br.probe, br.PROBE_TOKEN), (br.report, br.RUN_TOKEN)):
        with pytest.raises(br.LedgerPreflightError, match="before any paid call"):
            fn(env={"ARENA_GO": tok}, out=tmp_path, client_factory=lambda c: called.append(c),
               summary=af.summary())
    assert called == [] and not list(tmp_path.iterdir())


def test_ledger_preflight_needs_a_verified_price():
    with pytest.raises(br.LedgerPreflightError, match="verified price"):
        br.preflight_ledger("20261124T000000Z-abcd", [{"model": "no-such-model", "provider": "openai"}])
    br.preflight_ledger("20261124T000000Z-abcd", br.CANDIDATES)  # every candidate is fine


def test_report_falls_back_in_the_designers_order(tmp_path):
    bad = af.draft()
    bad["sections"]["results"] = "We recommend option B."
    script = {"gpt-6.1-sol": [bad] * 3, "gpt-6.1-terra": [af.draft()]}
    seen = []

    def factory(cfg):
        m = cfg["agents"]["analyst"]["model"]
        seen.append(m)
        return af.StubClient(script[m])
    r = br.report(env={"ARENA_GO": br.RUN_TOKEN}, out=tmp_path, client_factory=factory,
                  summary=af.summary())
    assert br.REPORT_ORDER == ("gpt-6.1-sol", "gpt-6.1-terra", "claude-sonnet-5-5")
    assert seen == ["gpt-6.1-sol", "gpt-6.1-terra"] and r["ok"] and r["model"] == "gpt-6.1-terra"
    assert [t["stop"] for t in r["tried"]] == ["grounding_failed", "accepted"]
    d = tmp_path / r["report_id"]
    assert (d / "report.html").exists() and (d / "draft-gpt-6.1-sol.json").exists()
    assert not (tmp_path / "dash").exists()  # nothing published until the designer has read it
