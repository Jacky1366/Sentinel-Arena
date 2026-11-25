"""Committed analyst report (data/golden/analyst-report-7, #17): read-only integrity checks
(standing GO for committed integrity tests). No AI call, no source folder re-read."""

from __future__ import annotations

import json

from llm_fakes import REPO
from analyst import draft as D
from analyst import grounding, render
from stats import cost
from tools import build_summary

G = REPO / "data" / "golden" / "analyst-report-7"
DASH = REPO / "dashboard" / "public" / "report"
j = lambda n: json.loads((G / n).read_text(encoding="utf-8"))  # noqa: E731


def test_files_and_meta():
    for n in ("summary.json", "draft.json", "grounding_result.json", "meta.json", "api_calls.jsonl",
              "brief.html", "brief.pdf", "report.html", "report.pdf", "README.md"):
        assert (G / n).is_file(), n
    m = j("meta.json")
    assert (m["model"], m["provider"], m["prompt_version"], m["attempts"]) == ("gpt-6.1-sol", "openai", "3", 1)
    assert m["prompt_sha256"] == D.prompt_sha256(D.SYSTEM_PROMPTS["3"])
    assert m["go_token"] == "manual-analyst-report"
    assert all(r["ai_calls"] == 0 for r in m["rerenders"])
    calls = cost.read_calls(G / "api_calls.jsonl")
    assert len(calls) == 1 and calls[0]["agent"] == "analyst" and calls[0]["match_id"] == m["run_id"]
    assert cost.summarize(calls, cost.load_prices())["total_usd"] == m["cost_usd"]


def test_summary_valid_and_the_draft_still_grounds():
    s, d = j("summary.json"), j("draft.json")
    assert build_summary.validate(s) == []
    assert grounding.check(d, s) == j("grounding_result.json") and j("grounding_result.json")["ok"]
    assert d == j("draft-gpt-6.1-sol.json")


def test_both_views_rerender_byte_for_byte():
    s, d, g, m = j("summary.json"), j("draft.json"), j("grounding_result.json"), j("meta.json")
    assert m["template_sha256"] == render.template_sha256() == render.TEMPLATE_SHA256
    assert render.render(s, d, g, m) == (G / "report.html").read_text(encoding="utf-8")
    assert render.render(s, d, g, m, brief=True) == (G / "brief.html").read_text(encoding="utf-8")


def test_key_figures_and_no_script():
    brief = (G / "brief.html").read_text(encoding="utf-8")
    for fig in ("28/28 (100.0%)", "12/19 (63.2%)", "14/19 (73.7%)", "5/7 (71.4%)", "7/7 (100.0%)",
                "0/57 (0.0%)", "6/57 (10.5%)", "The decision required: choose option A, B or C."):
        assert fig in brief, fig
    for n in ("brief.html", "report.html"):
        h = (G / n).read_text(encoding="utf-8")
        assert "<script" not in h.lower() and "audience" not in h.lower()


def test_pdfs_and_the_dashboard_copies():
    for n in ("brief.pdf", "report.pdf"):
        assert (G / n).read_bytes()[:5] == b"%PDF-"
        assert (DASH / n).read_bytes() == (G / n).read_bytes(), n
    for n in ("brief.html", "report.html"):
        assert (DASH / n).read_text(encoding="utf-8") == (G / n).read_text(encoding="utf-8"), n
    js = (DASH / "report.js").read_text(encoding="utf-8")
    payload = json.loads(js.split("window.ARENA_REPORT = ", 1)[1].rsplit(";", 1)[0])
    assert payload["html"] == (G / "report.html").read_text(encoding="utf-8")
    assert payload["brief"] == (G / "brief.html").read_text(encoding="utf-8")
