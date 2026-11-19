"""Free-play (D41) binary audit scaffold + read-only sheet + report.

  scaffold data/golden/<folder>...   -> write data/golden/audits/<match_id>.freeplay.jsonl
  sheet    data/golden/<folder>...   -> print the binary audit sheet (attack attempt yes/no)
  report   data/golden/<folder>...   -> print the free-play measures (stats/free_play.py)

The audit file is one unaudited row per Red round. The designer fills attack_attempt in;
recon / normal browsing = "no" (excluded from the detection denominator). Label validity is
not audited (free-play allows `other`). Blue must never read any of this.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from jsonschema import Draft202012Validator  # noqa: E402
from stats import free_play  # noqa: E402

GOLDEN_AUDITS = REPO / "data" / "golden" / "audits"
AUDITS = REPO / "data" / "audits"
SCHEMA = Draft202012Validator(json.loads(
    (REPO / "schemas" / "free_play_audit.schema.json").read_text(encoding="utf-8")))


def _rel(p: Path) -> str:
    try:
        return p.relative_to(REPO).as_posix()
    except ValueError:
        return str(p)


def audit_path(match_id: str) -> Path:
    g = GOLDEN_AUDITS / f"{match_id}.freeplay.jsonl"
    return g if g.is_file() else AUDITS / f"{match_id}.freeplay.jsonl"


def scaffold(match_dir: Path, golden: bool = False, audits: Path | None = None) -> Path:
    match_dir = Path(match_dir)
    mid = json.loads((match_dir / "match.json").read_text())["match_id"]
    reds = free_play._jl(match_dir / "red_attacks.jsonl")
    dest = (audits or (GOLDEN_AUDITS if golden else AUDITS)) / f"{mid}.freeplay.jsonl"
    for prior in (GOLDEN_AUDITS / f"{mid}.freeplay.jsonl", AUDITS / f"{mid}.freeplay.jsonl"):
        if prior.is_file():
            raise FileExistsError(f"audit already exists: {_rel(prior)}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for r in reds:
        row = {"schema_version": "0.1", "match_id": mid, "round": r["round"],
               "attack_attempt": "unaudited", "reason": "", "auditor": None, "date": None}
        errs = [e.message for e in SCHEMA.iter_errors(row)]
        if errs:
            raise RuntimeError(f"scaffold row invalid: {errs}")
        lines.append(json.dumps(row))
    dest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return dest


def sheet(match_dirs: list[Path]) -> str:
    out = ["# Free-play binary audit sheet (D41) — GENERATED, READ-ONLY",
           "",
           "Per Red round: was this an attack attempt? Fill `attack_attempt` in the audit "
           "file (`yes`/`no`); recon / normal browsing = `no` (excluded from the detection "
           "denominator). Label validity is not audited (`other` is allowed). `detected`, "
           "`landed` and solved challenges are the Judge's facts.", ""]
    for d in match_dirs:
        d = Path(d)
        mid = json.loads((d / "match.json").read_text())["match_id"]
        ap = audit_path(mid)
        rs = free_play.rows(d, ap if ap.is_file() else None)
        out.append(f"## `{mid}` — audit `{_rel(ap)}`")
        out.append("")
        out.append("| round | label | technique | headers | detected | landed | solved (category) | attack attempt |")
        out.append("|---|---|---|---|---|---|---|---|")
        for r in rs:
            solved = "; ".join(f"{s['challenge']} ({s['category']})" for s in r["newly_solved"]) or "—"
            out.append(f"| {r['round']} | {r['label']} | {r['technique'] or '—'} | "
                       f"{','.join(r['headers_set']) or '—'} | {r['detected']} | "
                       f"{r['landed_freeplay']} | {solved} | {r['attack_attempt']} |")
        out.append("")
    return "\n".join(out)


def report(match_dirs: list[Path]) -> str:
    lines = []
    for d in match_dirs:
        d = Path(d)
        mid = json.loads((d / "match.json").read_text())["match_id"]
        ap = audit_path(mid)
        s = free_play.summary(d, ap if ap.is_file() else None)
        lines.append(json.dumps(s, sort_keys=True))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("action", choices=("scaffold", "sheet", "report"))
    ap.add_argument("match_dirs", type=Path, nargs="+")
    ap.add_argument("--golden", action="store_true", help="scaffold into data/golden/audits/")
    args = ap.parse_args(argv)
    if args.action == "scaffold":
        for d in args.match_dirs:
            print(_rel(scaffold(d, golden=args.golden)))
    elif args.action == "sheet":
        print(sheet(args.match_dirs))
    else:
        print(report(args.match_dirs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
