"""#17 rendering (D56, D57; designer Q4 and the #17 review): Jinja2 autoescape, code-filled
numbers (one decimal, count, interval, baseline), confidence by code, the brief and the full
report, labels in the body (ids only in the appendix), glossary, frozen template, XSS as text."""

from __future__ import annotations

import re

import pytest

import analyst_fakes as af
from analyst import grounding, render

META = {"report_id": "report-20261124T000000Z-abcd", "model": "gpt-6.1-sol", "provider": "openai",
        "date": "2026-11-24", "prompt_version": "2", "prompt_sha256": "c" * 64, "attempts": 1,
        "cost_usd": 0.123456, "go_token": "manual-analyst-report"}


def _render(brief=False, meta=META):
    s, d = af.summary(), af.draft()
    return render.render(s, d, grounding.check(d, s), meta, brief=brief)


@pytest.fixture
def html():
    return _render()


@pytest.fixture
def brief():
    return _render(brief=True)


def body(html):
    return html.split("Appendix A.")[0]


def test_the_template_is_frozen():
    assert render.template_sha256() == render.TEMPLATE_SHA256


@pytest.mark.parametrize("which", ["full", "brief"])
def test_xss_strings_render_as_text(which):
    h = _render(brief=which == "brief")
    assert "<script" not in h.lower()                             # nothing executable at all
    assert "default-src 'none'" in h                              # CSP: no script source
    if which == "full":
        assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in h
        assert 'onerror="x' not in h and "&#34; onerror=&#34;x" in h


def test_numbers_one_decimal_with_count_interval_and_baseline(html):
    assert "12/19 (63.2%)" in html and "95% CI 38.4–83.7%" in html
    assert "−25.6% vs rules off" in html or "−25.7% vs rules off" in html
    assert not re.search(r"(?<![/(\d.])\b63%", body(html))          # never a bare or rounded %
    assert " pp " not in body(html) and "percentage points" in html  # glossary spells it out
    assert "$0.123456" in html                                       # appendix precision


def test_labels_not_ids_in_the_body(html):
    b = body(html)
    for key in af.summary()["figures"]:
        assert key not in b, key                                    # ids only in the appendix
    assert "An experiment: detection of attacks" in b
    assert "m5.cost_change_vs_rules_off" in html.split("Appendix A.")[1]


def test_no_decision_numbers_before_the_appendix_and_no_typo(html):
    assert not re.search(r"\bD\d{2}\b", body(html))
    assert "report report-" not in html


def test_confidence_comes_from_code(html):
    assert 'class="fig c-moderate"' in html
    f01 = html.split("F-01")[1].split("</h3>")[0]
    assert "conf-moderate" in f01  # the lowest of the figures it cites (D60)


def test_every_d57_section_with_authorship_glossary_and_print(html):
    for n, title, who in [(0, "Document control", "code"), (1, "Executive summary", "AI"),
                          (2, "Scope", "code"), (3, "Methodology", "AI"), (4, "Results", "code"),
                          (5, "Key findings", "AI"), (6, "Risk register", "AI"),
                          (7, "Deployment options", "AI"), (8, "Decision criteria", "AI"),
                          (9, "Limitations", "AI"), (10, "Decision record", "human")]:
        assert re.search(rf"<h2[^>]*>{n}\. {title} <span class=\"by by-{who.lower()}\">written by {who}", html), (n, title)
    for a in ("Appendix A. Evidence manifest", "Appendix B. AI disclosure", "Appendix C. Glossary"):
        assert a in html
    assert "@media print" in html and ".appendix { break-before: page; }" in html
    assert html.count('class="appendix"') == 1                     # breaks only before the appendices
    assert "Added after the first draft (post hoc)" in html        # the composition rule


def test_decision_record_has_no_audience_vote(html, brief):
    for h in (html, brief):
        assert "Audience vote" not in h and "audience" not in h.lower()
        assert "presenter acts as decision-maker" in h


def test_the_brief(brief):
    assert "decision brief" in brief and "Decision required: choose option A, B or C." in brief
    for part in ("Executive summary", "Options", "Decision criteria", "Decision record"):
        assert f"<h2>{part}" in brief, part
    assert brief.count("written by AI") == 1        # one authorship line, not a badge per heading
    for absent in ("Key findings", "Risk register", "Appendix A", "Glossary"):
        assert absent not in brief, absent
    assert "12/19 (63.2%)" in brief                                # figures carried into the brief


def test_provider_aware_disclosure():
    assert "OpenAI analyst model commenting on it" in _render()
    assert "same family as the defender" in _render(meta={**META, "provider": "anthropic",
                                                           "model": "claude-sonnet-5-5"})


def test_refuses_a_draft_that_failed_grounding():
    with pytest.raises(ValueError, match="grounding"):
        render.render(af.summary(), af.draft(), {"ok": False}, META)
