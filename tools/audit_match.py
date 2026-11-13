"""Designer label audit (D16, contract 6.8): scaffold, validate, apply, sheet.

    .venv/bin/python tools/audit_match.py scaffold data/runs/<match_id> [--golden]
    .venv/bin/python tools/audit_match.py validate data/runs/<match_id>
    .venv/bin/python tools/audit_match.py apply    data/runs/<match_id> [--json]
    .venv/bin/python tools/audit_match.py sheet    data/runs/<a> data/runs/<b> ... --out F.md

The audit file is the SINGLE source of truth for label verdicts: one JSONL line per
Red round, written by the designer AFTER the match, OUTSIDE the immutable match folder:
  data/audits/<match_id>.jsonl         dev matches (git-ignored)
  data/golden/audits/<match_id>.jsonl  committed golden reference matches
An `invalid` label is EXCLUDED from the audited statistics, never corrected (relabeling
would be a human rewriting ground truth). The Judge's output is never changed.

Only AI-generated labels are audited (D16, Stage 5.5): a round whose Red source is
scripted (or a legacy 0.1 Red record without a source) carries a designer-written label
verified in Stage 2, so it is valid by construction and has no audit line. A match with
only scripted rounds needs no audit file: its audited numbers equal the raw ones.

A replay folder (tools/replay_blue.py, D17) is audited through its SOURCE match: the
match id comes from replay.json source.match_id, so the source's audit file applies.

  scaffold  one `unaudited` line per round in rounds.jsonl; refuses to overwrite.
  validate  schema per line, match_id, no duplicate rounds, exactly the match's rounds.
  apply     prints raw and audited numbers side by side, plus the audit-first list
            (rounds that solved a challenge outside challenge_map; advisory only).
            --json writes the same summary to stdout. Nothing is stored: derived
            data is recomputed, never written.
  sheet     a generated, READ-ONLY markdown view across matches; verdicts and reasons
            are read from the audit files (empty where unaudited).
Pure file work: no network, no AI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from stats import match_stats as ms  # noqa: E402

AUDITS = REPO / "data" / "audits"
GOLDEN_AUDITS = REPO / "data" / "golden" / "audits"
CHALLENGE_MAP = REPO / "config" / "challenge_map.json"
SCHEMA = Draft202012Validator(json.loads(
    (REPO / "schemas" / "match_audit.schema.json").read_text(encoding="utf-8")))


# Label criteria the designer audits against (D16). Dated; a refinement is recorded
# openly with what prompted it, never applied silently. Rendered in the sheet header.
LABEL_CRITERIA = [
    {"label": "CWE-22", "date": "2026-11-13",
     "criterion": "CWE-22 valid = inserting traversal sequences or manipulating file names "
                  "to influence which file the server resolves, including probes of whether "
                  "such sequences are neutralized.",
     "note": "Refined during the first audit (Stage 5.6 Gate 2) because of match "
             "20261113T053039Z-4645 round 10, a traversal probe that resolves inside /ftp; "
             "the refinement was made while auditing, after seeing that round, and that "
             "round is marked valid as a borderline case."},
]


class AuditError(ValueError):
    pass


def _rel(p: Path) -> str:
    try:
        return str(p.resolve().relative_to(REPO))
    except ValueError:
        return str(p)


def _jl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] \
        if p.is_file() else []


def match_id_of(match_dir: Path) -> str:
    """The match id of a match folder, or of a replay folder's source match (D17)."""
    if (match_dir / "match.json").is_file():
        return json.loads((match_dir / "match.json").read_text(encoding="utf-8"))["match_id"]
    if (match_dir / "replay.json").is_file():
        return json.loads((match_dir / "replay.json").read_text(
            encoding="utf-8"))["source"]["match_id"]
    raise AuditError(f"{match_dir} is neither a match (match.json) nor a replay (replay.json)")


def scripted_rounds(match_dir: Path) -> set[int]:
    """Rounds valid by construction (scripted Red labels, D16)."""
    return ms.scripted_rounds(_jl(match_dir / "red_attacks.jsonl"))


def audit_path(match_id: str, audits: Path | None = None, golden: Path | None = None) -> Path:
    """The committed golden audit wins; otherwise the dev location (may not exist).
    Locations are read at call time (module globals), so tests can redirect them."""
    audits, golden = audits or AUDITS, golden or GOLDEN_AUDITS
    g = golden / f"{match_id}.jsonl"
    return g if g.is_file() else audits / f"{match_id}.jsonl"


def load_audit(match_dir: Path, audits: Path | None = None, golden: Path | None = None
               ) -> tuple[Path, list[dict]]:
    p = audit_path(match_id_of(match_dir), audits, golden)
    return p, _jl(p)


def validate_rows(rows: list[dict], match_id: str, rounds: list[dict],
                  scripted: set[int] | frozenset = frozenset()) -> list[str]:
    """One line per AI-labeled round, exactly. Scripted rounds (valid by construction)
    must not appear."""
    errors = []
    for i, row in enumerate(rows, start=1):
        errors += [f"line {i}: {e.message}" for e in SCHEMA.iter_errors(row)]
        if row.get("match_id") != match_id:
            errors.append(f"line {i}: match_id {row.get('match_id')!r} is not {match_id!r}")
    seen = [r.get("round") for r in rows]
    dupes = sorted({x for x in seen if seen.count(x) > 1})
    if dupes:
        errors.append(f"duplicate rounds {dupes}")
    on_scripted = sorted(set(seen) & set(scripted))
    if on_scripted:
        errors.append(f"rounds {on_scripted} carry scripted labels: valid by construction, "
                      f"never audited (D16)")
    want = {r["round"] for r in rounds} - set(scripted)
    extra = set(seen) - want - set(scripted)
    if extra:
        errors.append(f"rounds not in the match: {sorted(extra)}")
    if want - set(seen):
        errors.append(f"rounds missing from the audit: {sorted(want - set(seen))}")
    return errors


def scaffold(match_dir: Path, golden: bool = False, audits: Path | None = None,
             golden_dir: Path | None = None) -> Path:
    audits, golden_dir = audits or AUDITS, golden_dir or GOLDEN_AUDITS
    mid = match_id_of(match_dir)
    for existing in (audits / f"{mid}.jsonl", golden_dir / f"{mid}.jsonl"):
        if existing.exists():
            raise AuditError(f"refusing to overwrite an existing audit: {existing}")
    rounds = _jl(match_dir / "rounds.jsonl")
    if not rounds:
        raise AuditError(f"no rounds.jsonl in {match_dir} (the Judge must have run)")
    scripted = scripted_rounds(match_dir)
    rows = [{"schema_version": "0.1", "match_id": mid, "round": r["round"],
             "verdict": "unaudited", "reason": "", "auditor": None, "date": None}
            for r in sorted(rounds, key=lambda r: r["round"]) if r["round"] not in scripted]
    if not rows:
        raise AuditError(f"{match_dir}: every round carries a scripted label, valid by "
                         f"construction (D16); there is nothing to audit")
    errors = validate_rows(rows, mid, rounds, scripted)
    if errors:
        raise AuditError(f"scaffold would be invalid: {errors}")  # a bug, never data
    out = (golden_dir if golden else audits) / f"{mid}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return out


def _rate(r: ms.Rate) -> dict:
    return {"num": r.num, "den": r.den, "pct": r.pct, "excluded": r.excluded}


def summary(match_dir: Path, audits: Path | None = None, golden: Path | None = None) -> dict:
    """Raw and audited numbers, recomputed from the match folder + the audit file."""
    rounds = _jl(match_dir / "rounds.jsonl")
    benign = _jl(match_dir / "benign_results.jsonl")
    challenge_map = json.loads(CHALLENGE_MAP.read_text(encoding="utf-8"))
    path, rows = load_audit(match_dir, audits, golden)
    mid = match_id_of(match_dir)
    scripted = scripted_rounds(match_dir)
    if rows:
        errors = validate_rows(rows, mid, rounds, scripted)
        if errors:
            raise AuditError(f"{path}: {errors}")
    view = ms.apply_audit(rounds, rows, scripted)

    def block(rs: list[dict]) -> dict:
        s, b = ms.compute(rs), ms.compute_benign(rs, benign)
        split = ms.by_source(rs, benign)
        return {"landing": _rate(s["landing"]), "detection": _rate(s["detection"]),
                "type_accuracy": _rate(s["type_accuracy"]), "fp": _rate(b["fp"]),
                "precision": _rate(b["precision"]),
                "by_source": {p: {"detection": _rate(x["detection"]), "fp": _rate(x["fp"]),
                                  "type_accuracy": _rate(x["type_accuracy"]),
                                  "attack_lines": x["attack_lines"],
                                  "benign_lines": x["benign_lines"]}
                              for p, x in split.items()}}
    return {"match_id": mid, "audit_file": _rel(path) if rows else None,
            "raw": block(rounds),
            "audited": None if view["rounds"] is None else block(view["rounds"]),
            "audited_excludes_label_invalid": view["invalid"],
            "valid": view["valid"], "unaudited": view["unaudited"],
            "valid_by_construction": view["valid_by_construction"],
            "audit_first": {str(k): v for k, v in ms.audit_first(rounds, challenge_map).items()}}


def _fmt(rate: dict) -> str:
    pct = "n/a" if rate["pct"] is None else f"{rate['pct']:.0f}%"
    return f"{rate['num']}/{rate['den']} ({pct})"


def print_summary(s: dict) -> None:
    print(f"match {s['match_id']}  audit {s['audit_file'] or '(none)'}")
    for name in ("landing", "detection", "type_accuracy", "fp", "precision"):
        raw = _fmt(s["raw"][name])
        aud = _fmt(s["audited"][name]) if s["audited"] else "—"
        print(f"  {name:14} raw {raw:14} audited {aud}")
    if s["audited"] is None:
        print(f"  audited: incomplete ({len(s['unaudited'])} unaudited: {s['unaudited']})")
    print(f"  audited excludes label_invalid {s['audited_excludes_label_invalid']}  "
          f"(excluded, never relabeled)")
    if s["valid_by_construction"]:
        print(f"  valid by construction (scripted labels, D16) {s['valid_by_construction']}")
    print("  audit first    " + (", ".join(f"round {k} {v}" for k, v in s["audit_first"].items())
                                 or "none") + "  (advisory; excludes nothing)")


# -- the generated, read-only sheet ------------------------------------------

def _esc(x) -> str:
    return str(x).replace("|", "\\|").replace("\n", " ")


def sheet(match_dirs: list[Path], audits: Path | None = None, golden: Path | None = None) -> str:
    challenge_map = json.loads(CHALLENGE_MAP.read_text(encoding="utf-8"))
    head = ["# Red label audit sheet (D16) — GENERATED, READ-ONLY", "",
            "Generated by `tools/audit_match.py sheet` from each match's artifacts. "
            "**Do not edit this file**: verdicts and reasons are read from the audit files "
            "(`data/audits/<match_id>.jsonl`, or `data/golden/audits/` for committed golden "
            "matches), the single source of truth; empty where unaudited. Fill in the audit "
            "file, then regenerate. An `invalid` label is excluded from the audited "
            "statistics, never corrected. `audit first` marks a round that solved a challenge "
            "outside `config/challenge_map.json` (advisory; it excludes nothing). `landed`, "
            "`newly_solved` and `Blue verdict` are the Judge's facts.", "",
            "Label criteria (D16, `docs/stage5_decisions.md`):"]
    head += [f"- **{c['label']}** ({c['date']}): {c['criterion']} {c['note']}"
             for c in LABEL_CRITERIA]
    head += ["", "Matches:"]
    rows = []
    for n, d in enumerate(match_dirs, start=1):
        m = json.loads((d / "match.json").read_text(encoding="utf-8"))
        rp = m.get("red_params") or {}
        path, audit = load_audit(d, audits, golden)
        head.append(f"- {n}: `{m['match_id']}` — red {m.get('red_engine')} "
                    f"{rp.get('model', '')} prompt v{rp.get('prompt_version', '-')}, blue "
                    f"{m['blue_engine']}, seed {m['traffic']['seed']}; audit "
                    f"`{_rel(path)}`" + ("" if audit else " (missing)"))
        verdicts = {a["round"]: a for a in audit}
        scripted = scripted_rounds(d)
        proxy = {x["request_id"]: x for x in _jl(d / "proxy.jsonl") if x.get("request_id")}
        rounds = {x["request_id"]: x for x in _jl(d / "rounds.jsonl")}
        flagged = ms.audit_first(list(rounds.values()), challenge_map)
        items = []
        for a in _jl(d / "red_attacks.jsonl"):
            px, r = proxy.get(a["request_id"], {}), rounds.get(a["request_id"], {})
            target = px.get("path", a["endpoint"]) + (f"?{px['query']}" if px.get("query") else "")
            if not px and a["payload"].startswith("/"):
                target = a["payload"]
            body = px.get("body", "" if a["payload"].startswith("/") else a["payload"])
            v = verdicts.get(a["round"], {})
            decided = v.get("verdict") in ("valid", "invalid")
            items.append((a["round"], [
                str(n), str(a["round"]), "sent", a["method"], f"`{_esc(target)}`",
                f"`{_esc(body)}`" if body else "", a["label"], _esc(a.get("rationale") or ""),
                _esc(f"{r.get('landed')}" + (f" ({r['landed_reason']})" if r.get("landed_reason") else "")),
                _esc(", ".join(r.get("newly_solved") or []) or "—"), _esc(r.get("verdict", "—")),
                "yes" if a["round"] in flagged else "",
                "valid (scripted)" if a["round"] in scripted else v["verdict"] if decided else "",
                "designer-written label, valid by construction (D16)" if a["round"] in scripted
                else _esc(v.get("reason", "")) if decided else ""]))
        for u in _jl(d / "red_unsent.jsonl"):
            p = u.get("proposed") or {}
            items.append((u["round"], [
                str(n), str(u["round"]), f"unsent: {u['kind']}/{u['reason']}",
                p.get("method", "—"), f"`{_esc(p['path'])}`" if p.get("path") else "—",
                f"`{_esc(p['body'])}`" if p.get("body") else "", p.get("label", "—"),
                _esc(p.get("rationale") or u.get("detail") or "—"), "— (not sent)", "—",
                "— (not sent)", "", "n/a (not a round)", ""]))
        rows += [cells for _, cells in sorted(items, key=lambda t: t[0])]
    cols = ["match", "round", "status", "method", "path", "body", "label", "rationale",
            "landed", "newly_solved", "Blue verdict", "audit first", "designer verdict",
            "reason"]
    out = head + ["", "| " + " | ".join(cols) + " |", "|" + "|".join(["---"] * len(cols)) + "|"]
    out += ["| " + " | ".join(c) + " |" for c in rows]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scaffold")
    p.add_argument("match_dir", type=Path)
    p.add_argument("--golden", action="store_true",
                   help="write to data/golden/audits/ (a committed golden match)")
    p = sub.add_parser("validate")
    p.add_argument("match_dir", type=Path)
    p = sub.add_parser("apply")
    p.add_argument("match_dir", type=Path)
    p.add_argument("--json", action="store_true", help="write the summary to stdout as JSON")
    p = sub.add_parser("sheet")
    p.add_argument("match_dirs", type=Path, nargs="+")
    p.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "scaffold":
            out = scaffold(args.match_dir, args.golden)
            print(f"scaffolded {_rel(out)} (all rounds unaudited)")
        elif args.cmd == "validate":
            path, rows = load_audit(args.match_dir)
            if not rows:
                raise AuditError(f"no audit file at {path}")
            errors = validate_rows(rows, match_id_of(args.match_dir),
                                   _jl(args.match_dir / "rounds.jsonl"),
                                   scripted_rounds(args.match_dir))
            if errors:
                for e in errors:
                    print(f"INVALID {_rel(path)}: {e}")
                return 1
            counts = {k: sum(r["verdict"] == k for r in rows)
                      for k in ("valid", "invalid", "unaudited")}
            print(f"{_rel(path)}: valid ({len(rows)} rounds, {counts})")
        elif args.cmd == "apply":
            s = summary(args.match_dir)
            if args.json:
                print(json.dumps(s, indent=2))
            else:
                print_summary(s)
        else:
            args.out.write_text(sheet(args.match_dirs), encoding="utf-8")
            print(f"wrote {args.out}")
    except AuditError as exc:
        print(f"REFUSED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
