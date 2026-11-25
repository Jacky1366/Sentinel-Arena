"""analyst/grounding.py (#16; D54, D55, D60). Done when: the grounding check rejects planted
bad drafts (unknown placeholder, bare number, wrong shape, ...) and accepts a valid one."""

from __future__ import annotations

import copy

import pytest

from llm_fakes import REPO  # noqa: F401 (repo on sys.path)
from analyst.grounding import check


def fig(conf="High", kind="rate"):
    base = {"kind": kind, "value": 0.5, "n": 28, "unit": "rounds", "basis": "audited",
            "blue": "original", "confidence": conf, "source_ids": ["gate_b#1"],
            "definition": "d"}
    if kind == "rate":
        base.update(k=14, pct=50.0, ci_low=0.3, ci_high=0.7)
    return base


SUMMARY = {
    "figures": {"gate_b.detection": fig("High"), "freeplay_original.detection": fig("Moderate"),
                "fp_check_open.fp": fig("Moderate"), "gate_b.cost_usd": fig("Moderate", "usd")},
    "sources": [{"id": "gate_b#1"}, {"id": "freeplay_original#1"}],
    "descriptive": {"groups": {"gate_b": {"red_models": ["gpt-6-luna"],
                                          "blue_models": ["claude-haiku-5-5"], "dates": []}}},
}

VALID = {
    "schema_version": "0.1",
    "sections": {
        "executive_summary": "Original Blue detected {{gate_b.detection.pct}} of checked "
                             "known-type attacks (CWE-89, CWE-79, CWE-22). On free-play "
                             "traffic it detected {{freeplay_original.detection}}; the open prompt's "
                             "false alarms were {{fp_check_open.fp}}. The decision required: "
                             "choose option A, B or C.",
        "methodology": "Blue (claude-haiku-5-5) read only the proxy log; Red was gpt-6-luna. "
                       "Library v5 was read-only. The demo shows Act 1 to Act 3.",
        "results": "Free-play detection was {{freeplay_original.detection}} "
                   "({{freeplay_original.detection.k}} of {{freeplay_original.detection.n}}).",
        "risk_register": "We describe three kinds of blindness: prompt scope, application "
                         "context and structural (§6).",
        "deployment_options": "Options A, B and C trade coverage against false alarms.",
        "decision_criteria": "Criteria are listed below; the decision is human.",
        "limitations": "Open Blue verdicts vary run to run; the audit came after its results.",
    },
    "findings": [
        {"id": "F-01", "title": "Taxonomy attacks are detected",
         "text": "Detection {{gate_b.detection}}, {{gate_b.detection.ci}}.",
         "figure_refs": ["gate_b.detection"], "evidence_refs": ["gate_b#1"]},
        {"id": "F-02", "title": "Free-play reaches outside the taxonomy",
         "text": "Detection fell to {{freeplay_original.detection.pct}}; the open prompt's "
                 "false-positive rate was {{fp_check_open.fp}}.",
         "figure_refs": ["freeplay_original.detection", "fp_check_open.fp"],
         "evidence_refs": ["freeplay_original#1"]},
    ],
    "options": [
        {"id": "A", "summary": "Original Blue", "strengths": ["detected {{gate_b.detection}}"], "weaknesses": ["blind outside the known types"]},
        {"id": "B", "summary": "Open Blue", "strengths": ["wider coverage"], "weaknesses": ["false alarms {{fp_check_open.fp}}"]},
        {"id": "C", "summary": "Layered", "strengths": ["keeps precise alerts"], "weaknesses": ["untested"]},
    ],
    "criteria": [{"if_you_value": "few false alarms", "option": "A",
                  "because": "its false-positive rate was {{gate_b.detection.k}} lines lower"}],
}


def codes(res):
    return sorted({e["code"] for e in res["errors"]})


def test_a_valid_draft_is_accepted_with_code_assigned_confidence():
    res = check(copy.deepcopy(VALID), SUMMARY)
    assert res["ok"], res["errors"]
    assert res["findings"] == [{"id": "F-01", "confidence": "High"},
                               {"id": "F-02", "confidence": "Moderate"}]  # the lowest cited
    assert res["stats"]["placeholders"] >= 9 and res["stats"]["findings"] == 2


def planted(path, value):
    d = copy.deepcopy(VALID)
    target = d
    for k in path[:-1]:
        target = target[k]
    target[path[-1]] = value
    return d


@pytest.mark.parametrize("path,value,code", [
    (("sections", "results"), "Detection was {{gate_b.nonexistent}}.", "placeholder"),
    (("sections", "results"), "Detection was {{gate_b.detection.median}}.", "placeholder"),
    (("sections", "results"), "Lower bound {{gate_b.detection.ci_low}}.", "placeholder"),  # Q4
    (("sections", "results"), "Cost {{gate_b.cost_usd.ci}}.", "placeholder"),  # rates only
    (("sections", "results"), "Detection was {gate_b.detection}.", "placeholder"),
    (("sections", "results"), "Detection was {{gate_b.detection}.", "placeholder"),
    (("sections", "results"), "Blue detected 12 of 19 attempts.", "bare_number"),
    (("sections", "results"), "As decided in D44, open Blue is analysis only.", "bare_number"),  # D60 b amendment
    (("sections", "results"), "The M5 replays cost less.", "bare_number"),
    (("sections", "results"), "Detection was 63.2%.", "bare_number"),
    (("sections", "results"), "Cost was $0.09 in total.", "bare_number"),
    (("sections", "results"), "Blue missed seven attacks.", "number_word"),
    (("sections", "results"), "Blue caught half of them.", "number_word"),
    (("sections", "results"), "False alarms rose twofold, about ten percent.", "number_word"),
    (("sections", "results"), "Nineteen attempts were audited.", "number_word"),
    (("sections", "results"), "Twenty-eight rounds.", "number_word"),
    (("sections", "deployment_options"), "We recommend option B.", "recommendation"),
    (("sections", "deployment_options"), "You should choose the layered option.", "recommendation"),
    (("sections", "deployment_options"), "Option C is the best option.", "recommendation"),
    (("sections", "limitations"), "We have high confidence in F-01.", "confidence_claim"),
])
def test_planted_bad_prose_is_rejected(path, value, code):
    res = check(planted(path, value), SUMMARY)
    assert not res["ok"] and code in codes(res), res["errors"]
    assert res["findings"] == []
    assert all(e["path"].startswith("$.") for e in res["errors"])


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("findings"),                                   # missing section
    lambda d: d["sections"].pop("limitations"),
    lambda d: d.update(recommendation="B"),                         # no such field (D54)
    lambda d: d["findings"][0].update(confidence="High"),           # code assigns it (D60)
    lambda d: d["findings"][0].update(id="F1"),                     # id shape
    lambda d: d.update(options=d["options"][:2]),                   # A, B, C required
    lambda d: d["criteria"][0].update(option="D"),
    lambda d: d["findings"][0].update(figure_refs=[]),
])
def test_wrong_shape_is_rejected(mutate):
    d = copy.deepcopy(VALID)
    mutate(d)
    res = check(d, SUMMARY)
    assert codes(res) == ["schema"]


def test_not_an_object_is_rejected():
    assert codes(check(["not", "a", "draft"], SUMMARY)) == ["schema"]


def test_reference_errors():
    d = copy.deepcopy(VALID)
    d["findings"][0]["figure_refs"] = ["gate_b.detection", "gate_b.unknown"]
    d["findings"][1]["figure_refs"] = ["freeplay_original.detection"]  # fp_check_open.fp used, unlisted
    d["findings"][1]["evidence_refs"] = ["nowhere#9"]
    d["findings"].append(copy.deepcopy(d["findings"][0]))               # duplicate id
    res = check(d, SUMMARY)
    details = " ".join(e["detail"] for e in res["errors"])
    assert codes(res) == ["evidence_ref", "figure_ref", "schema"]
    assert "gate_b.unknown" in details and "fp_check_open.fp" in details and "nowhere#9" in details


def test_allowlisted_tokens_pass_and_every_error_is_reported():
    ok = planted(("sections", "methodology"),
                 "CWE-89 and CWE-22, F-02, §6.14, v5 and v3-open, gpt-6-luna, "
                 "claude-haiku-5-5, Act 2, three kinds of blindness.")
    assert check(ok, SUMMARY)["ok"]
    bad = planted(("sections", "methodology"), "It ran 3 times; one of the two runs had 5 misses.")
    res = check(bad, SUMMARY)
    nums = [e for e in res["errors"] if e["code"] == "bare_number"]
    words = [e for e in res["errors"] if e["code"] == "number_word"]
    assert len(nums) == 2 and len(words) == 1  # all reported, not just the first; "one" allowed


def test_a_model_id_not_in_the_summary_is_a_bare_number():
    res = check(planted(("sections", "methodology"), "Blue was claude-opus-5-5."), SUMMARY)
    assert codes(res) == ["bare_number"]


# -- #17 review: structure, hedging, composition, jargon (fail closed) -------------------

def test_executive_summary_needs_three_figures_and_the_decision():
    few = planted(("sections", "executive_summary"),
                  "Detection was {{gate_b.detection}}. The decision required: choose option A, B or C.")
    assert "structure" in codes(check(few, SUMMARY))
    no_end = planted(("sections", "executive_summary"),
                     "Detection {{gate_b.detection}}, free-play {{freeplay_original.detection}}, "
                     "false alarms {{fp_check_open.fp}}.")
    res = check(no_end, SUMMARY)
    assert any(e["code"] == "structure" and "decision required" in e["detail"] for e in res["errors"])


def test_options_a_and_b_must_cite_figures_c_need_not():
    d = copy.deepcopy(VALID)
    d["options"][1]["weaknesses"] = ["false alarms, unstable"]  # B cites nothing now
    res = check(d, SUMMARY)
    assert any(e["code"] == "structure" and e["path"] == "$.options[1]" for e in res["errors"])
    assert not any(e["path"] == "$.options[2]" for e in res["errors"])


def test_tentative_only_with_a_low_figure():
    low = copy.deepcopy(SUMMARY)
    low["figures"]["raw.det"] = {**fig("Low"), "basis": "raw"}
    bad = planted(("sections", "results"), "Free-play detection {{freeplay_original.detection}} is tentative.")
    assert "hedging" in codes(check(bad, low))
    ok = planted(("sections", "results"), "The unchecked result {{raw.det}} is tentative.")
    assert check(ok, low)["ok"]


def test_a_finding_never_mixes_unchecked_and_checked_figures():
    s = copy.deepcopy(SUMMARY)
    s["figures"]["raw.det"] = {**fig("Low"), "basis": "raw"}
    d = copy.deepcopy(VALID)
    d["findings"][0]["text"] = "Checked {{gate_b.detection}}; unchecked {{raw.det}}."
    d["findings"][0]["figure_refs"] = ["gate_b.detection", "raw.det"]
    assert "composition" in codes(check(d, s))


@pytest.mark.parametrize("text", ["A gain of ten pp.", "Orphaned rounds were dropped.",
                                  "Instrumentation failures were excluded.",
                                  "Sealed benign requests.", "Landing was measured."])
def test_internal_jargon_is_rejected(text):
    assert "jargon" in codes(check(planted(("sections", "limitations"), text), SUMMARY))


# -- #17 review round 2 ------------------------------------------------------------------

def test_executive_summary_has_no_finding_ids():
    d = planted(("sections", "executive_summary"), VALID["sections"]["executive_summary"].replace(
        "(CWE-89, CWE-79, CWE-22).", "(CWE-89, CWE-79, CWE-22); see F-01."))
    res = check(d, SUMMARY)
    assert any(e["code"] == "structure" and "finding ids" in e["detail"] for e in res["errors"])


def test_executive_summary_cites_every_successful_attack_figure():
    s = copy.deepcopy(SUMMARY)
    s["figures"]["freeplay_original.landed_detection"] = fig("Moderate")
    s["figures"]["freeplay_open.landed_detection"] = fig("Moderate")
    res = check(copy.deepcopy(VALID), s)
    missing = sorted(e["detail"] for e in res["errors"] if e["code"] == "structure")
    assert len(missing) == 2 and all("landed_detection" in m for m in missing)
    d = copy.deepcopy(VALID)
    d["sections"]["executive_summary"] = d["sections"]["executive_summary"].replace(
        "The decision required", "Successful attacks flagged: {{freeplay_original.landed_detection}} "
        "vs {{freeplay_open.landed_detection}}. The decision required")
    assert check(d, s)["ok"]


@pytest.mark.parametrize("field,text", [
    ("if_you_value", "If you value few false alarms"),
    ("because", "option A fits, because it is precise"),
    ("because", "it fits, because it is precise"),
])
def test_criteria_are_bare_phrases(field, text):
    d = copy.deepcopy(VALID)
    d["criteria"][0][field] = text
    assert any(e["code"] == "structure" and e["path"] == f"$.criteria[0].{field}"
               for e in check(d, SUMMARY)["errors"])
