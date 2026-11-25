"""The grounding check (#16; D54, D55, D60 b). PURE.

An analyst draft is accepted only if every check passes. All errors are returned (not just
the first), each with a machine-readable code and a JSON path, so a retry (#17) can be told
exactly what to fix. Fail closed: a false reject only costs a retry within the analyst cap.

  schema           the draft matches schemas/analyst_draft.schema.json (no confidence and no
                   recommendation field exist in it: code assigns confidence, D55)
  placeholder      every {{key}} / {{key.field}} resolves to a summary figure
                   (field: value, k, n, pct; ci for rates); stray braces are rejected.
                   (#17, designer Q4: a percentage always prints with its count, an
                   interval as "95% CI a-b%", a change with its baseline, so the bare
                   interval endpoints ci_low / ci_high are not placeholder fields.)
  bare_number      after placeholders and allowlisted tokens are removed, no digit remains
                   (D60 b amendment, 2026-11-24: decision numbers and internal milestone /
                   gate ids are NOT allowed; experiments are named by their summary labels)
  number_word      no spelled-out number or fraction word, outside a few fixed phrases
  figure_ref       every finding's figure_refs entry is a summary figure; every placeholder
                   used in a finding is listed in its figure_refs
  evidence_ref     every finding's evidence_refs entry is a summary source id
  recommendation   no recommending phrasing (D54: analysis, criteria, never a recommendation)
  confidence_claim no "high / moderate / low confidence" in prose (code assigns it, D60)
  structure        (#17 review) the executive summary cites at least 3 distinct figures and ends
                   with the decision required (choose A, B or C); options A and B each cite at
                   least one figure (option C is untested)
  hedging          (#17 review) "tentative(ly)" only in a text that cites a Low figure:
                   uncertainty is carried by the confidence labels and intervals
  composition      (#17 review, POST HOC, disclosed in the report) a finding never mixes
                   unaudited (raw) figures with audited / ground-truth ones, so an audited
                   result is not rated by its unaudited contrast
  jargon           (#17 review) internal terms readers do not know: "pp", "orphan(ed)",
                   "instrumentation failure", "sealed", "landing"

On success the result lists each finding's confidence: the lowest D60 confidence among the
figures it cites (analyst/confidence.finding_confidence).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

from analyst.confidence import finding_confidence
from analyst.summary import model_ids

REPO = Path(__file__).resolve().parent.parent
DRAFT_SCHEMA = Draft202012Validator(json.loads(
    (REPO / "schemas" / "analyst_draft.schema.json").read_text(encoding="utf-8")))
RESULT_SCHEMA = Draft202012Validator(json.loads(
    (REPO / "schemas" / "grounding_result.schema.json").read_text(encoding="utf-8")))

FIELDS = ("value", "k", "n", "pct", "ci")
RATE_ONLY = ("k", "pct", "ci")
PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}")
# Tokens that carry digits but are not quantities.
TOKEN_ALLOW = [
    re.compile(r"\bCWE-\d+\b"),                 # taxonomy ids
    re.compile(r"\bF-\d{2}\b"),                 # finding ids
    re.compile(r"§\d+(?:\.\d+)*"),              # section references
    re.compile(r"\bv\d+(?:\.\d+)*\b"),          # library / prompt versions
]
# Fixed phrases (D60 b): digits or number words that name a thing, not a quantity.
PHRASE_ALLOW = ["three kinds of blindness", "Act 1", "Act 2", "Act 3"]
NUMBER_WORDS = re.compile(
    r"\b(zero|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|"
    r"fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|"
    r"sixty|seventy|eighty|ninety|hundreds?|thousands?|millions?|dozens?|"
    r"half|halves|thirds?|quarters?|fifths?|sixths?|sevenths?|eighths?|ninths?|tenths?|"
    r"twice|thrice|double[ds]?|triple[ds]?|quadruple[ds]?|tenfold|twofold|threefold|"
    r"percent|percentage|per\s?cent)\b", re.IGNORECASE)
RECOMMEND = re.compile(
    r"\b(we|i)\s+(would\s+)?(recommend|suggest|advise|propose)\b|\brecommendation\b|"
    r"\brecommended\b|\byou\s+should\b|\bshould\s+(choose|adopt|deploy|pick|use|select|go\s+with)\b|"
    r"\b(the\s+)?best\s+(option|choice)\b|\bis\s+(clearly\s+)?preferable\b",
    re.IGNORECASE)
CONFIDENCE = re.compile(r"\b(high|moderate|medium|low)\s+confidence\b", re.IGNORECASE)
TENTATIVE = re.compile(r"\btentative(ly)?\b", re.IGNORECASE)
JARGON = re.compile(r"\bpp\b|\borphan(ed|s)?\b|\binstrument(ation)?\s+failures?\b|\bsealed\b|"
                    r"\blanding\b", re.IGNORECASE)
DECISION_END = re.compile(r"\b(choose|decide|decision)\b.*\bA\b.*\bB\b.*\bC\b", re.IGNORECASE)
MIN_SUMMARY_FIGURES = 3
FINDING_ID = re.compile(r"\bF-\d{2}\b")
CRIT_VALUE_PREFIX = re.compile(r"^\s*if\s+you\s+value\b", re.IGNORECASE)
CRIT_BECAUSE_PREFIX = re.compile(r"^\s*option\s+[ABC]\s+fits\b|\bfits,\s*because\b", re.IGNORECASE)


def _texts(draft: dict):
    """(json path, text) for every prose field the analyst wrote."""
    for k, v in draft.get("sections", {}).items():
        yield f"$.sections.{k}", v
    for i, f in enumerate(draft.get("findings", [])):
        yield f"$.findings[{i}].title", f["title"]
        yield f"$.findings[{i}].text", f["text"]
    for i, o in enumerate(draft.get("options", [])):
        yield f"$.options[{i}].summary", o["summary"]
        for j, s in enumerate(o["strengths"]):
            yield f"$.options[{i}].strengths[{j}]", s
        for j, s in enumerate(o["weaknesses"]):
            yield f"$.options[{i}].weaknesses[{j}]", s
    for i, c in enumerate(draft.get("criteria", [])):
        yield f"$.criteria[{i}].if_you_value", c["if_you_value"]
        yield f"$.criteria[{i}].because", c["because"]


def resolve(ref: str, figures: dict) -> str | None:
    """The figure key a placeholder refers to, or None. `key` or `key.<field>`."""
    if ref in figures:
        return ref
    base, _, field = ref.rpartition(".")
    if field not in FIELDS or base not in figures:
        return None
    if field in RATE_ONLY and figures[base]["kind"] != "rate":
        return None
    return base


def _strip_allowed(text: str, models: set[str]) -> str:
    for phrase in PHRASE_ALLOW:
        text = re.sub(re.escape(phrase), " ", text, flags=re.IGNORECASE)
    for m in sorted(models, key=len, reverse=True):
        text = text.replace(m, " ")
    for rx in TOKEN_ALLOW:
        text = rx.sub(" ", text)
    return text


def check(draft, summary: dict) -> dict:
    errors: list[dict] = []

    def err(code, path, detail):
        errors.append({"code": code, "path": path, "detail": detail})

    if not isinstance(draft, dict):
        err("schema", "$", "the draft is not a JSON object")
        return _result(errors, {}, [])
    for e in DRAFT_SCHEMA.iter_errors(draft):
        err("schema", "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}"
                                    for p in e.absolute_path), e.message)
    if errors:  # the other checks assume the shape
        return _result(errors, {}, [])
    ids = [f["id"] for f in draft["findings"]]
    for dup in sorted({x for x in ids if ids.count(x) > 1}):
        err("schema", "$.findings", f"duplicate finding id {dup}")

    figures = summary["figures"]
    sources = {s["id"] for s in summary["sources"]}
    models = model_ids(summary)
    used: dict[str, set[str]] = {}
    n_placeholders = 0
    for path, text in _texts(draft):
        refs = set()
        for m in PLACEHOLDER.finditer(text):
            n_placeholders += 1
            key = resolve(m.group(1), figures)
            if key is None:
                err("placeholder", path, f"unknown figure {{{{{m.group(1)}}}}}")
            else:
                refs.add(key)
        used[path] = refs
        rest = PLACEHOLDER.sub(" ", text)
        if "{" in rest or "}" in rest:
            err("placeholder", path, "stray or malformed brace (placeholders are {{key}})")
        rest = _strip_allowed(rest, models)
        for m in re.finditer(r"\S*\d\S*", rest):
            err("bare_number", path, f"bare number {m.group(0)!r}: cite a figure placeholder")
        for m in NUMBER_WORDS.finditer(rest):
            err("number_word", path, f"spelled-out quantity {m.group(0)!r}: cite a placeholder")
        for m in RECOMMEND.finditer(text):
            err("recommendation", path, f"recommending phrase {m.group(0)!r} (D54)")
        for m in CONFIDENCE.finditer(text):
            err("confidence_claim", path, f"{m.group(0)!r}: confidence is assigned by code (D60)")
        if TENTATIVE.search(text) and not any(figures[k]["confidence"] == "Low" for k in refs):
            err("hedging", path, "'tentative' without a Low figure in the same text: the "
                "confidence labels and intervals already carry the uncertainty")
        for m in JARGON.finditer(rest):
            err("jargon", path, f"internal term {m.group(0)!r}: use plain language (see the glossary)")

    # structure (#17 review)
    es = used.get("$.sections.executive_summary", set())
    if len(es) < MIN_SUMMARY_FIGURES:
        err("structure", "$.sections.executive_summary",
            f"cites {len(es)} figure(s); cite at least {MIN_SUMMARY_FIGURES} key figures")
    last = re.split(r"(?<=[.!?])\s+", draft["sections"]["executive_summary"].strip())[-1]
    if not DECISION_END.search(last):
        err("structure", "$.sections.executive_summary",
            "must end with the decision required: choose option A, B or C")
    if FINDING_ID.search(draft["sections"]["executive_summary"]):
        err("structure", "$.sections.executive_summary",
            "the executive summary stands alone: no finding ids")
    for key in sorted(k for k in figures if k.endswith(".landed_detection")):
        if key not in es:
            err("structure", "$.sections.executive_summary",
                f"cite the successful-attack figure {{{{{key}}}}} in the executive summary")
    for i, c in enumerate(draft["criteria"]):
        if CRIT_VALUE_PREFIX.search(c["if_you_value"]):
            err("structure", f"$.criteria[{i}].if_you_value",
                "a bare phrase: the table already says 'If you value'")
        if CRIT_BECAUSE_PREFIX.search(c["because"]):
            err("structure", f"$.criteria[{i}].because",
                "a bare reason: the table already says 'option X fits, because'")
    for i, o in enumerate(draft["options"]):
        if o["id"] in ("A", "B"):
            paths = [f"$.options[{i}].summary"] + \
                [f"$.options[{i}].strengths[{j}]" for j in range(len(o["strengths"]))] + \
                [f"$.options[{i}].weaknesses[{j}]" for j in range(len(o["weaknesses"]))]
            if not any(used.get(p_) for p_ in paths):
                err("structure", f"$.options[{i}]", f"option {o['id']} cites no figure")

    out_findings = []
    for i, f in enumerate(draft["findings"]):
        refs = set(f["figure_refs"])
        for r in sorted(refs - set(figures)):
            err("figure_ref", f"$.findings[{i}].figure_refs", f"unknown figure {r!r}")
        cited = used.get(f"$.findings[{i}].title", set()) | used.get(f"$.findings[{i}].text", set())
        for r in sorted(cited - refs):
            err("figure_ref", f"$.findings[{i}].figure_refs",
                f"placeholder {r!r} is used in the finding but not listed")
        for r in sorted(set(f["evidence_refs"]) - sources):
            err("evidence_ref", f"$.findings[{i}].evidence_refs", f"unknown source {r!r}")
        bases = {figures[r]["basis"] for r in f["figure_refs"] if r in figures}
        if "raw" in bases and bases & {"audited", "ground_truth"}:
            err("composition", f"$.findings[{i}].figure_refs",
                "mixes unaudited (raw) figures with audited ones: give unaudited results their "
                "own finding")
        known = [figures[r]["confidence"] for r in f["figure_refs"] if r in figures]
        out_findings.append({"id": f["id"],
                             "confidence": finding_confidence(known) if known else None})
    stats = {"placeholders": n_placeholders, "findings": len(draft["findings"]),
             "texts": len(used)}
    return _result(errors, stats, out_findings)


def _result(errors: list[dict], stats: dict, findings: list[dict]) -> dict:
    ok = not errors
    res = {"schema_version": "0.1", "ok": ok, "errors": errors,
           "stats": {"placeholders": 0, "findings": 0, "texts": 0, **stats},
           "findings": findings if ok else []}
    problems = [e.message for e in RESULT_SCHEMA.iter_errors(res)]
    if problems:  # a bug here, never data-dependent
        raise RuntimeError(f"grounding result is schema-invalid: {problems}")
    return res
