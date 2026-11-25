"""Render the analyst report (#17; D56, D57). Jinja2 (pinned), autoescape ON, StrictUndefined.

AI prose is split into segments: plain text (autoescaped by the template) and figure
placeholders, which code formats (analyst/fmt.py, designer Q4) and marks with the figure's
D60 confidence. Nothing the AI wrote is ever inserted as markup. The template is frozen: its
sha256 is recorded in the report and checked by a test.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from analyst import fmt
from analyst.grounding import PLACEHOLDER, resolve

TEMPLATES = Path(__file__).resolve().parent / "templates"
TEMPLATE = "report.html.j2"
TEMPLATE_SHA256 = "efc49bed0b24e6afb092605f97c8b535f1ecd1a658621278bff347828aed77ca"  # frozen (D56): change only with a new REPORT_VERSION
REPORT_VERSION = "2"  # #17 review: brief + full, labels, glossary


def template_sha256() -> str:
    return hashlib.sha256((TEMPLATES / TEMPLATE).read_bytes()).hexdigest()


def segments(text: str, figures: dict) -> list[dict]:
    """[{"t": "text", "s": ...} | {"t": "fig", "s": formatted, "confidence": ..., "key": ...}]"""
    out, pos = [], 0
    for m in PLACEHOLDER.finditer(text):
        if m.start() > pos:
            out.append({"t": "text", "s": text[pos:m.start()]})
        ref = m.group(1)
        key = resolve(ref, figures)
        if key is None:  # never after a passed grounding check; shown, never hidden
            out.append({"t": "text", "s": m.group(0)})
        else:
            field = ref[len(key) + 1:] or None
            f = figures[key]
            out.append({"t": "fig", "s": fmt.figure(f, field), "key": key,
                        "label": f.get("label", key), "confidence": f["confidence"]})
        pos = m.end()
    if pos < len(text):
        out.append({"t": "text", "s": text[pos:]})
    return out


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True,
                      undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
    env.filters["usd_appendix"] = lambda v: fmt.usd(v, appendix=True)
    return env


def render(summary: dict, draft: dict, ground: dict, meta: dict, brief: bool = False) -> str:
    """meta: model, provider, date, prompt_sha256, prompt_version, attempts, cost_usd,
    go_token, report_id. Requires a passed grounding result. brief=True renders the decision
    brief (decision required, executive summary, options, criteria, decision record)."""
    if not ground.get("ok"):
        raise ValueError("refusing to render a draft that failed the grounding check")
    figs = summary["figures"]
    conf = {f["id"]: f["confidence"] for f in ground["findings"]}
    sec = {k: segments(v, figs) for k, v in draft["sections"].items()}
    group_label = {g["id"]: g["label"] for g in summary["groups"]}

    def evidence(refs):  # reader-facing: experiment labels; the source ids are in Appendix A
        out = []
        for r in refs:
            lab = group_label.get(r.split("#")[0], r)
            if lab not in out:
                out.append(lab)
        return out
    findings = [{"id": f["id"], "title": segments(f["title"], figs),
                 "text": segments(f["text"], figs), "confidence": conf.get(f["id"]),
                 "figure_labels": [figs[r].get("label", r) for r in f["figure_refs"] if r in figs],
                 "evidence_labels": evidence(f["evidence_refs"])}
                for f in draft["findings"]]
    options = [{"id": o["id"], "summary": segments(o["summary"], figs),
                "strengths": [segments(s, figs) for s in o["strengths"]],
                "weaknesses": [segments(s, figs) for s in o["weaknesses"]]}
               for o in draft["options"]]
    criteria = [{"value": segments(c["if_you_value"], figs), "option": c["option"],
                 "because": segments(c["because"], figs)} for c in draft["criteria"]]
    cited = sorted({r for f in draft["findings"] for r in f["figure_refs"]})
    results = [{"key": k, "f": figs[k], "text": fmt.figure(figs[k]),
                "ci": fmt.ci(figs[k]) if figs[k]["kind"] == "rate" else ""}
               for k in sorted(figs)]
    return _env().get_template(TEMPLATE).render(
        summary=summary, sections=sec, findings=findings, options=options,
        criteria=criteria, results=results, cited=cited, meta=meta, ground=ground,
        group_label=group_label, brief=brief,
        template_sha256=template_sha256(), report_version=REPORT_VERSION)
