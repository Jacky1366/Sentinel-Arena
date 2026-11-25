"""#17: relative figures name their baseline (designer, 2026-11-24) + Q4 number formats."""

from __future__ import annotations

import json

import pytest

from analyst_fakes import rate, usd
from analyst import fmt
from analyst.summary import comparison
from tools import build_summary

FIGS = {"m5_library.cost_usd": usd(0.002933), "m5_rules_off.cost_usd": usd(0.003945),
        "m5_empty.cost_usd": usd(0.004831),
        "a.detection": rate(14, 19, "Moderate", blue="open"), "b.detection": rate(12, 19, "Moderate"),
        "g.detection": rate(28, 28, "High"), "r.detection": rate(26, 26, "Low", basis="raw")}


def cmp(id_, of, vs, mode, baseline="the baseline"):
    return comparison({"id": id_, "of": of, "vs": vs, "mode": mode, "baseline": baseline}, FIGS)


def test_the_m5_trio_side_by_side():
    off = cmp("m5.cost_change_vs_rules_off", "m5_library.cost_usd", "m5_rules_off.cost_usd", "relative", "rules off")
    emp = cmp("m5.cost_change_vs_empty_library", "m5_library.cost_usd", "m5_empty.cost_usd", "relative", "empty library")
    e_off = cmp("m5.empty_library_cost_change_vs_rules_off", "m5_empty.cost_usd", "m5_rules_off.cost_usd", "relative", "rules off")
    assert fmt.change(off) == "−25.7% vs rules off"        # the headline
    assert fmt.change(emp) == "−39.3% vs empty library"
    assert fmt.change(e_off) == "+22.5% vs rules off"
    assert off["of_value"] == 0.002933 and off["vs_value"] == 0.003945
    assert off["confidence"] == "Moderate" and off["n"] == 3


def test_points_for_rates_and_the_lower_confidence():
    c = cmp("freeplay.open_detection_change_vs_original", "a.detection", "b.detection", "points", "original Blue")
    assert c["value"] == 10.5 and c["unit"] == "percentage points"
    assert fmt.change(c) == "+10.5 percentage points vs original Blue"
    assert cmp("x.det_change_vs_raw", "g.detection", "r.detection", "points")["confidence"] == "Low"
    assert cmp("x.det_change_vs_raw", "g.detection", "r.detection", "points")["basis"] == "raw"


@pytest.mark.parametrize("id_,of,vs,mode,msg", [
    ("m5.cost_change", "m5_library.cost_usd", "m5_rules_off.cost_usd", "relative", "baseline"),
    ("m5.cost_reduction", "m5_library.cost_usd", "m5_rules_off.cost_usd", "relative", "baseline"),
    ("m5.cost_change_vs_x", "m5_library.cost_usd", "nope", "relative", "unknown figure"),
    ("m5.cost_change_vs_x", "a.detection", "b.detection", "relative", "counts or costs"),
    ("m5.cost_change_vs_x", "m5_library.cost_usd", "b.detection", "points", "two rates"),
    ("m5.cost_change_vs_x", "m5_library.cost_usd", "m5_rules_off.cost_usd", "ratio", "mode"),
])
def test_refusals(id_, of, vs, mode, msg):
    with pytest.raises(ValueError, match=msg):
        cmp(id_, of, vs, mode)


def test_zero_baseline_is_refused():
    figs = {**FIGS, "z.cost_usd": usd(0.0)}
    with pytest.raises(ValueError, match="zero"):
        comparison({"id": "m5.cost_change_vs_z", "of": "m5_library.cost_usd", "vs": "z.cost_usd",
                    "mode": "relative", "baseline": "z"}, figs)


def test_q4_formats():
    f = rate(12, 19, "Moderate", lo=0.3836, hi=0.8371)
    assert fmt.figure(f) == "12/19 (63.2%)" and fmt.figure(f, "pct") == "12/19 (63.2%)"  # never bare
    assert fmt.figure(f, "ci") == "95% CI 38.4–83.7%"
    assert fmt.figure(rate(6, 57, "Moderate", lo=0.0396, hi=0.2152), "ci") == "95% CI 4.0–21.5%"
    assert fmt.figure(f, "k") == "12" and fmt.figure(f, "n") == "19"
    assert fmt.figure(usd(0.002933)) == "$0.0029" and fmt.figure(usd(0.002933), appendix=True) == "$0.002933"


def test_committed_manifest_comparisons_name_their_baseline():
    m = json.loads(build_summary.MANIFEST.read_text())
    ids = [c["id"] for c in m["comparisons"]]
    assert {"m5.cost_change_vs_rules_off", "m5.cost_change_vs_empty_library",
            "m5.empty_library_cost_change_vs_rules_off"} <= set(ids)
    assert all("_change_vs_" in i and c["baseline"] for i, c in zip(ids, m["comparisons"]))


def test_committed_labels_and_baselines_are_reader_facing():
    """Designer 2026-11-24: experiments are named by labels the analyst can quote; no internal
    ids, milestone / gate names or D-numbers, and they pass the grounding prose checks."""
    import re
    from analyst import grounding
    m = json.loads(build_summary.MANIFEST.read_text())
    models = {"gpt-6-luna", "deepseek-v4-pro", "claude-sonnet-5-5"}
    texts = [g["label"] for g in m["groups"]] + [c["baseline"] for c in m["comparisons"]]
    for t in texts:
        rest = grounding._strip_allowed(t, models)
        assert not re.search(r"\d", rest), t
        assert not grounding.NUMBER_WORDS.search(rest), t
        assert not re.search(r"\b(Gate|M\d|D\d)", t), t
