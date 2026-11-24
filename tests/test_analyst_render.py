"""#17 rendering (D56, D57; designer Q4): Jinja2 autoescape, code-filled numbers, confidence by
code, every section with its authorship mark, frozen template, and the XSS test string."""

from __future__ import annotations

import re

import pytest

import analyst_fakes as af
from analyst import grounding, render

META = {"report_id": "report-x", "model": "gpt-6.1-terra", "provider": "openai",
        "date": "2026-11-24", "prompt_version": "1", "prompt_sha256": "c" * 64, "attempts": 1,
        "cost_usd": 0.123456, "go_token": "manual-analyst-report"}


@pytest.fixture
def html():
    s, d = af.summary(), af.draft()
    return render.render(s, d, grounding.check(d, s), META)


def test_the_template_is_frozen():
    assert render.template_sha256() == render.TEMPLATE_SHA256


def test_xss_strings_render_as_text(html):
    assert "<script>alert(document.cookie)</script>" not in html   # from AI prose
    assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in html
    assert 'onerror="x' not in html and "&#34; onerror=&#34;x" in html
    assert "<script" not in html.lower()                            # nothing executable at all
    assert "default-src 'none'" in html                             # CSP: no script source


def test_numbers_are_code_formatted_with_count_baseline_and_interval(html):
    assert "12/19 (63%)" in html and "95% CI 38.4–83.7%" in html
    assert "−26% vs rules off" in html
    body = html.split("Appendix A.")[0]
    assert not re.search(r"(?<![/(\d])\b63%", body.replace("12/19 (63%)", ""))  # never bare
    assert "$0.123456" in html                                        # appendix precision


def test_confidence_comes_from_code(html):
    assert 'class="fig c-moderate"' in html
    f01 = html.split("F-01")[1].split("</h3>")[0]
    assert "conf-moderate" in f01  # the lowest of the figures it cites (D60)


def test_every_d57_section_with_authorship(html):
    for n, title, who in [(0, "Document control", "code"), (1, "Executive summary", "AI"),
                          (2, "Scope", "code"), (3, "Methodology", "AI"), (4, "Results", "code"),
                          (5, "Key findings", "AI"), (6, "Risk register", "AI"),
                          (7, "Deployment options", "AI"), (8, "Decision criteria", "AI"),
                          (9, "Limitations", "AI"), (10, "Decision record", "human")]:
        m = re.search(rf"<h2[^>]*>{n}\. {title} <span class=\"by by-{who.lower()}\">written by {who}", html)
        assert m, (n, title, who)
    assert "Appendix A. Evidence manifest" in html and "Appendix B. AI disclosure" in html
    assert "@media print" in html and "size: A4" in html


def test_provider_aware_disclosure():
    s, d = af.summary(), af.draft()
    g = grounding.check(d, s)
    assert "OpenAI analyst model commenting on it" in render.render(s, d, g, META)
    assert "same family as Blue" in render.render(s, d, g, {**META, "provider": "anthropic",
                                                             "model": "claude-sonnet-5-5"})


def test_refuses_a_draft_that_failed_grounding():
    s, d = af.summary(), af.draft()
    with pytest.raises(ValueError, match="grounding"):
        render.render(s, d, {"ok": False}, META)
