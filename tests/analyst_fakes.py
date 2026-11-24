"""Synthetic analyst data for the #17 tests: a schema-valid 0.2 summary (no test-set data),
a draft that passes the grounding check, and a stub analyst client (no provider)."""

from __future__ import annotations

import copy
import json

from llm_fakes import lc

XSS = '<script>alert(document.cookie)</script>" onerror="x'


def rate(k, n, conf, basis="audited", blue="original", lo=0.3, hi=0.9, sid="gate_b#1"):
    return {"kind": "rate", "value": round(k / n, 4), "k": k, "n": n, "pct": round(100 * k / n, 1),
            "ci_low": lo, "ci_high": hi, "unit": "rounds", "basis": basis, "blue": blue,
            "confidence": conf, "source_ids": [sid], "definition": "Detection over audited attempts."}


def usd(v, n=3):
    return {"kind": "usd", "value": v, "n": n, "unit": "USD", "basis": "measured", "blue": "original",
            "confidence": "Moderate", "source_ids": ["m5_library#1"], "definition": "Total AI cost."}


def summary() -> dict:
    return {
        "schema_version": "0.2", "built_at": "2026-11-24T23:00:00Z",
        "git": {"commit": "f" * 40, "dirty": False}, "judge_version": "0.7.0",
        "confidence_rules": "D60", "manifest": None,
        "groups": [{"id": "freeplay_original", "label": "Free-play, original Blue", "kind": "freeplay",
                    "blue": "original", "basis": "audited", "folders": 3, "notes": []}],
        "sources": [{"id": "freeplay_original#1", "path": "data/x", "match_id": "20261119T180616Z-a388",
                     "replay_id": None, "purpose": "eval", "test_data": "test",
                     "artifacts": [{"file": "rounds.jsonl", "sha256": "a" * 64}]},
                    {"id": "gate_b#1", "path": "data/y", "match_id": None, "replay_id": None,
                     "purpose": "eval", "test_data": "test", "artifacts": []},
                    {"id": "m5_library#1", "path": "data/z", "match_id": None, "replay_id": None,
                     "purpose": None, "test_data": "test", "artifacts": []}],
        "figures": {
            "freeplay_original.detection": rate(12, 19, "Moderate", lo=0.3836, hi=0.8371,
                                                sid="freeplay_original#1"),
            "gate_b.detection": rate(28, 28, "High", lo=0.8766, hi=1.0),
            "m5_library.cost_usd": usd(0.002933), "m5_rules_off.cost_usd": usd(0.003945),
            "m5.cost_change_vs_rules_off": {
                "kind": "change", "mode": "relative", "value": -0.2565,
                "of": "m5_library.cost_usd", "vs": "m5_rules_off.cost_usd",
                "baseline": "rules off", "of_value": 0.002933, "vs_value": 0.003945, "n": 3,
                "unit": "relative change", "basis": "measured", "blue": "original",
                "confidence": "Moderate", "source_ids": ["m5_library#1"], "definition": "d"},
        },
        "descriptive": {"groups": {"freeplay_original": {
            "red_models": ["deepseek-v4-pro"], "blue_models": ["claude-haiku-5-5"],
            "dates": ["2026-11-19"],
            "rounds": [{"match_id": "m", "round": 1, "label": "other", "technique": XSS,
                        "attack_attempt": "yes", "detected": False,
                        "solved": []}]}}},
    }


def draft() -> dict:
    return {
        "schema_version": "0.1",
        "sections": {
            "executive_summary": "Original Blue detected {{gate_b.detection}} of taxonomy attacks; "
                                 "on free-play traffic it detected {{freeplay_original.detection}} "
                                 "({{freeplay_original.detection.ci}}), a tentative result.",
            "methodology": "Blue (claude-haiku-5-5) read only the proxy log.",
            "results": "The library changed cost by {{m5.cost_change_vs_rules_off}}.",
            "risk_register": "We describe three kinds of blindness.",
            "deployment_options": "Options A, B and C trade coverage against false alarms.",
            "decision_criteria": "The decision is human.",
            "limitations": "Open Blue verdicts vary run to run.",
        },
        "findings": [{"id": "F-01", "title": "Free-play reaches beyond the taxonomy",
                      "text": "Detection was {{freeplay_original.detection}}; " + XSS,
                      "figure_refs": ["freeplay_original.detection"],
                      "evidence_refs": ["freeplay_original#1"]},
                     {"id": "F-02", "title": "Taxonomy attacks are detected",
                      "text": "Detection was {{gate_b.detection}} with cost change "
                              "{{m5.cost_change_vs_rules_off}}.",
                      "figure_refs": ["gate_b.detection", "m5.cost_change_vs_rules_off"],
                      "evidence_refs": ["gate_b#1"]}],
        "options": [{"id": i, "summary": s, "strengths": ["x"], "weaknesses": ["y"]}
                    for i, s in (("A", "Original Blue"), ("B", "Open Blue"), ("C", "Layered"))],
        "criteria": [{"if_you_value": "few false alarms", "option": "A", "because": "it is precise"}],
    }


class StubClient:
    """Scripted analyst replies: str (text), "refuse" (body refusal) or "error"."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls: list[dict] = []

    def complete(self, agent, model, system, messages, **kw):
        self.calls.append({"agent": agent, "model": model, "system": system,
                           "messages": copy.deepcopy(messages), **kw})
        r = self.replies.pop(0)
        if r == "refuse":
            return lc.Result(ok=False, error="refused", error_type="refused", attempts=0,
                             refusal={"scope": "analyst", "reason": "max_usd"})
        if r == "error":
            return lc.Result(ok=False, error="boom", error_type="server_error", attempts=1)
        text = r if isinstance(r, str) else json.dumps(r)
        return lc.Result(ok=True, text=text, usage=lc.Usage(100, 0, 0, 50), attempts=1,
                         stop_reason="end_turn")
