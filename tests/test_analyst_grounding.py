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
        "executive_summary": "Original Blue detected {{gate_b.detection.pct}} of audited "
                             "taxonomy attacks (CWE-89, CWE-79, CWE-22), see F-01.",
        "methodology": "Blue (claude-haiku-5-5) read only the proxy log; Red was gpt-6-luna. "
                       "Library v5 was read-only (D44). The demo shows Act 1 to Act 3.",
        "results": "Free-play detection was {{freeplay_original.detection}} "
                   "({{freeplay_original.detection.k}} of {{freeplay_original.detection.n}}).",
        "risk_register": "We describe three kinds of blindness: prompt scope, application "
                         "context and structural (§6).",
        "deployment_options": "Options A, B and C trade coverage against false alarms.",
        "decision_criteria": "Criteria are listed below; the decision is human (D54).",
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
        {"id": "A", "summary": "Original Blue", "strengths": ["precise"], "weaknesses": ["blind outside the taxonomy"]},
        {"id": "B", "summary": "Open Blue", "strengths": ["wider coverage"], "weaknesses": ["false alarms, unstable"]},
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
                 "CWE-89 and CWE-22, F-02, D41, §6.14, v5 and v3-open, gpt-6-luna, "
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
