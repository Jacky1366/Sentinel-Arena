"""Free-play measurement (Stage 6.3, D41). PURE: reads a frozen free-play match folder
and the designer's binary audit; computes nothing new that the core Judge did not record.

Free-play reinterprets the standard facts (the core Judge is unchanged):
  - landing (fact 1): ANY newly-solved Juice Shop challenge counts (not only the mapped
    challenge). round_record already records `newly_solved`; the category comes from the
    captured `challenge_catalog.json`.
  - detection (fact 2): binary -- did Blue flag the line as an attack (`detected`). The
    denominator is the rounds the designer audited as attack attempts (recon / normal
    browsing = not an attempt, excluded). Type-correctness covers only taxonomy-labelled
    attempts; `other` is excluded.
Blue never emits `other`, so its vocabulary and the core artifacts are unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

CWES = ("CWE-89", "CWE-79", "CWE-22")


def _jl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def load_audit(path: Path) -> dict[int, str]:
    """{round: attack_attempt} from a free-play binary audit file (missing -> empty)."""
    return {r["round"]: r["attack_attempt"] for r in _jl(path)}


def rows(match_dir: Path, audit_path: Path | None = None) -> list[dict]:
    """One row per Red round, joining round_record + red_attacks + the catalog + the audit."""
    match_dir = Path(match_dir)
    rounds = {r["round"]: r for r in _jl(match_dir / "rounds.jsonl")}
    reds = {r["round"]: r for r in _jl(match_dir / "red_attacks.jsonl")}
    catalog = {}
    cat_file = match_dir / "challenge_catalog.json"
    if cat_file.is_file():
        catalog = json.loads(cat_file.read_text(encoding="utf-8"))
    audit = load_audit(audit_path) if audit_path else {}
    out = []
    for rnd in sorted(reds):
        rr = rounds.get(rnd, {})
        red = reds[rnd]
        solved = rr.get("newly_solved") or []
        out.append({
            "round": rnd,
            "label": red["label"],
            "technique": red.get("technique"),
            "headers_set": sorted((red.get("headers") or {}).keys()),
            "detected": rr.get("detected"),
            "verdict": rr.get("verdict"),
            "type_correct": rr.get("type_correct"),
            "landed_freeplay": bool(solved),
            "newly_solved": [{"challenge": c, "category": catalog.get(c, "")} for c in solved],
            "attack_attempt": audit.get(rnd, "unaudited"),
        })
    return out


def summary(match_dir: Path, audit_path: Path | None = None) -> dict:
    """Per-match free-play measures. Detection/type are over AUDITED attack attempts; if
    the audit is absent or incomplete they are null (and `pre_audit_*` give the raw view
    over all rounds, so the run can be reported before the designer audits it)."""
    rs = rows(match_dir, audit_path)
    attempts = [r for r in rs if r["attack_attempt"] == "yes"]
    audited = all(r["attack_attempt"] != "unaudited" for r in rs) and bool(rs)

    def rate(items, pred):
        items = list(items)
        return {"num": sum(1 for r in items if pred(r)), "den": len(items)} if items else None

    detection = rate(attempts, lambda r: r["detected"] is True) if audited else None
    taxo = [r for r in attempts if r["label"] in CWES]
    type_acc = rate(taxo, lambda r: r["type_correct"] is True) if audited else None
    solved = [s for r in rs for s in r["newly_solved"]]
    return {
        "match_id": Path(match_dir).name,
        "rounds": len(rs),
        "audited": audited,
        "attack_attempts": len(attempts) if audited else None,
        "detection": detection,              # binary, over audited attempts
        "type_correct": type_acc,            # taxonomy-labelled attempts only (`other` excluded)
        "pre_audit_detection": rate(rs, lambda r: r["detected"] is True),  # all rounds, raw
        "landed_rounds": sum(1 for r in rs if r["landed_freeplay"]),
        "solved_challenges": sorted({s["challenge"] for s in solved}),
        "solved_categories": sorted({s["category"] for s in solved if s["category"]}),
        "other_rounds": sum(1 for r in rs if r["label"] == "other"),
    }
