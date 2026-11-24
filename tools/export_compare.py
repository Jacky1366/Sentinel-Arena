"""Export a Compare bundle (Stage 7 #15; D52; contract 6.18): N Blue arms over the SAME frozen
traffic, joined by request_id. Read-only, zero tokens; never writes into a source folder.

    ARENA_GO=<token> .venv/bin/python tools/export_compare.py --name freeplay \\
        --arm original:"Original Blue (live, default)":original:<3 match folders> \\
        --arm open:"Open Blue (replay, analysis only)":open:<3 replay folders>

Each arm lists one folder per match, in the same match order (a match folder, or a replay
of it). Per Red round (rounds.jsonl, joined by request_id): the Red record (label,
technique, method, path), the free-play binary audit (attack attempt yes / no), landing
(newly solved + catalog category) and each arm's verdict. Aggregates come from
stats/free_play.summary (detection over audited attempts) and stats/match_stats.fp_rate
(in-match benign FP), so they equal the committed free-play stats.

Gate (D59 + GO): every folder is classified by its manifest first; if any is test data or
unknown, the export refuses unless ARENA_GO holds a well-formed token. The optional
--fp-check <arm>:<folder> adds the D42 2c prompt-FP panel (holdout + fixture: test data).

Writes dashboard/public/compare/<name>.json and rewrites dashboard/public/compare/compare.js
(window.ARENA_COMPARE[name]; a classic script, so the dashboard works from file://).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from runner import go_token  # noqa: E402
from stats import free_play  # noqa: E402
from stats import match_stats as ms  # noqa: E402
from stats import test_data  # noqa: E402
from tools import free_play as free_play_tool  # noqa: E402

OUT = REPO / "dashboard" / "public" / "compare"
TEXT_MAX = 400
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
ARM_RE = re.compile(r"^[a-z0-9_]{1,32}$")
SCHEMA = Draft202012Validator(json.loads(
    (REPO / "schemas" / "compare_bundle.schema.json").read_text(encoding="utf-8")))


def _jl(p: Path) -> list[dict]:
    return ms.read_rounds(p)


def _cut(s):
    if s is None:
        return None
    return s if len(s) <= TEXT_MAX else s[:TEXT_MAX] + "…"


def _rel(p: Path) -> str:
    try:
        return Path(p).resolve().relative_to(REPO).as_posix()
    except ValueError:
        return Path(p).as_posix()


def _manifest(d: Path) -> dict:
    for n in ("match.json", "replay.json"):
        if (d / n).is_file():
            return json.loads((d / n).read_text(encoding="utf-8"))
    raise ValueError(f"{d} is not a frozen match or replay folder")


def source_match_id(d: Path) -> str:
    m = _manifest(d)
    return m.get("match_id") if "match_id" in m else m["source"]["match_id"]


def gate(folders: list[Path], env=None, registry=None) -> str | None:
    registry = registry if registry is not None else test_data.load_registry()
    kinds = [test_data.classify(d, registry).kind for d in folders]
    guarded = sum(k != test_data.NOT_TEST for k in kinds)
    if guarded == 0 or go_token.valid((os.environ if env is None else env).get(go_token.ENV)):
        return None
    return (f"REFUSED: {guarded} of {len(kinds)} folders are test data or unknown (D59). "
            f"Exporting them needs the designer's GO: set ARENA_GO=<token> for this command.")


def _audit_path(mid: str, audits: Path | None) -> Path | None:
    p = (Path(audits) / f"{mid}.freeplay.jsonl") if audits else free_play_tool.audit_path(mid)
    return p if p.is_file() else None


def build(name: str, title: str, arms: list[dict], audits: Path | None = None,
          fp_check: dict[str, Path] | None = None) -> dict:
    """arms: [{"id", "label", "blue", "folders": [Path, ...]}], same match order per arm."""
    if len(arms) < 2:
        raise ValueError("a Compare bundle needs at least two arms")
    n = {len(a["folders"]) for a in arms}
    if len(n) != 1:
        raise ValueError("every arm needs one folder per match, in the same order")
    ids = [a["id"] for a in arms]
    if len(set(ids)) != len(ids) or not all(ARM_RE.match(i) for i in ids):
        raise ValueError(f"bad or duplicate arm ids {ids}")
    matches, rows = [], []
    agg = {a["id"]: {"detected": 0, "attempts": 0, "benign_fp": 0, "benign": 0,
                     "landed_detected": 0} for a in arms}
    for mi in range(n.pop()):
        dirs = {a["id"]: Path(a["folders"][mi]) for a in arms}
        mids = {aid: source_match_id(d) for aid, d in dirs.items()}
        if len(set(mids.values())) != 1:
            raise ValueError(f"match {mi + 1}: arms are not the same traffic: {mids}")
        mid = next(iter(mids.values()))
        audit = _audit_path(mid, audits)
        base = dirs[arms[0]["id"]]
        reds = {r["request_id"]: r for r in _jl(base / "red_attacks.jsonl")}
        fp_rows = {r["round"]: r for r in free_play.rows(base, audit)}
        per_arm_rounds = {aid: {r["request_id"]: r for r in _jl(d / "rounds.jsonl")}
                          for aid, d in dirs.items()}
        per_match = {}
        for a in arms:
            s = free_play.summary(dirs[a["id"]], audit)
            fp = ms.fp_rate(_jl(dirs[a["id"]] / "benign_results.jsonl"))
            per_match[a["id"]] = {"detection": s["detection"], "audited": s["audited"],
                                  "benign_fp": {"num": fp.num, "den": fp.den}}
            if s["detection"]:
                agg[a["id"]]["detected"] += s["detection"]["num"]
                agg[a["id"]]["attempts"] += s["detection"]["den"]
            agg[a["id"]]["benign_fp"] += fp.num
            agg[a["id"]]["benign"] += fp.den
        for rid, rr in sorted(per_arm_rounds[arms[0]["id"]].items(), key=lambda x: x[1]["round"]):
            red = reds.get(rid, {})
            f = fp_rows.get(rr["round"], {})
            verdicts = {}
            for a in arms:
                x = per_arm_rounds[a["id"]].get(rid)
                verdicts[a["id"]] = None if x is None else {
                    "verdict": x.get("verdict"), "detected": x.get("detected"),
                    "source": x.get("verdict_source"),
                    "reason": x.get("detected_reason")}
            attempt = f.get("attack_attempt", "unaudited")
            solved = f.get("newly_solved", [])
            det = {aid: (v or {}).get("detected") for aid, v in verdicts.items()}
            for aid, d in det.items():
                if attempt == "yes" and solved and d is True:
                    agg[aid]["landed_detected"] += 1
            rows.append({
                "match": mi + 1, "match_id": mid, "round": rr["round"], "request_id": rid,
                "label": red.get("label", rr.get("label")),
                "technique": _cut(red.get("technique")),
                "method": red.get("method"), "path": _cut(red.get("endpoint")),
                "payload": _cut(red.get("payload")),
                "headers_set": sorted((red.get("headers") or {}).keys()),
                "attack_attempt": attempt,
                "landed": bool(solved), "solved": solved,
                "verdicts": verdicts,
                "divergent": len({v for v in det.values()}) > 1,
            })
        m = _manifest(base)
        matches.append({"match": mi + 1, "match_id": mid, "audit": None if audit is None
                        else _rel(audit), "per_arm": per_match,
                        "folders": {aid: _rel(d) for aid, d in dirs.items()},
                        "red_model": ((m.get("models") or {}).get("red") or {}).get("model")})
    landed_attempts = sum(1 for r in rows if r["attack_attempt"] == "yes" and r["landed"])
    doc = {
        "schema_version": "0.1", "name": name, "kind": "compare", "title": title,
        "arms": [{"id": a["id"], "label": a["label"], "blue": a["blue"]} for a in arms],
        "matches": matches, "rows": rows,
        "aggregate": {aid: {**v, "landed_attempts": landed_attempts} for aid, v in agg.items()},
        "fp_check": None,
        "notes": {"selection": "The per-match table is an illustrative selection; the header "
                               "aggregates all matches.",
                  "instability": "Open Blue's verdicts vary run to run (D42 2c).",
                  "audit_timing": "The free-play audit was done after open-Blue results were "
                                  "known (disclosed limitation, D52).",
                  "roles": "Original Blue is the default defender; open Blue is analysis "
                           "only and never pooled (D44)."},
    }
    if fp_check:
        doc["fp_check"] = {}
        for aid, d in fp_check.items():
            keys: dict[tuple, bool] = {}
            for line in _jl(Path(d) / "fp_verdicts.jsonl"):
                k = (line.get("set"), line.get("benign_id"))
                keys[k] = keys.get(k, False) or line.get("false_positive") is True
            doc["fp_check"][aid] = {"fp": sum(keys.values()), "n": len(keys),
                                    "folder": _rel(Path(d))}
    errors = [e.message for e in SCHEMA.iter_errors(doc)]
    if errors:
        raise RuntimeError(f"compare bundle is schema-invalid: {errors[:3]}")
    return doc


def pack(out_dir: Path = OUT) -> Path:
    parts = ["// GENERATED by tools/export_compare.py — do not edit.",
             "window.ARENA_COMPARE = window.ARENA_COMPARE || {};"]
    for p in sorted(Path(out_dir).glob("*.json")):
        doc = json.loads(p.read_text(encoding="utf-8"))
        parts.append(f"window.ARENA_COMPARE[{json.dumps(doc['name'])}] = "
                     f"{json.dumps(doc, ensure_ascii=False, separators=(',', ':'))};")
    js = Path(out_dir) / "compare.js"
    js.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return js


def export(doc: dict, sources: list[Path], out_dir: Path = OUT) -> Path:
    if not NAME_RE.match(doc["name"]):
        raise ValueError(f"bad bundle name {doc['name']!r}")
    out_dir = Path(out_dir)
    for d in sources:
        if out_dir.resolve() == Path(d).resolve() or Path(d).resolve() in out_dir.resolve().parents:
            raise ValueError("refusing to write into a source folder")
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"{doc['name']}.json"
    p.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    pack(out_dir)
    return p


def _arm(spec: str) -> dict:
    aid, label, blue, *folders = spec.split(":")
    return {"id": aid, "label": label, "blue": blue, "folders": [Path(f) for f in folders]}


def main(argv: list[str] | None = None, env=None) -> int:
    ap = argparse.ArgumentParser(description="Export a Compare bundle (zero tokens).")
    ap.add_argument("--name", required=True)
    ap.add_argument("--title", default="Same traffic, different Blues")
    ap.add_argument("--arm", action="append", required=True,
                    help="id:label:blue:folder[:folder...] (one folder per match)")
    ap.add_argument("--fp-check", action="append", default=[], help="arm_id:folder")
    ap.add_argument("--audits", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    arms = [_arm(s) for s in args.arm]
    fpc = dict(s.split(":", 1) for s in args.fp_check)
    folders = [d for a in arms for d in a["folders"]] + [Path(p) for p in fpc.values()]
    refusal = gate(folders, env)
    if refusal:
        print(refusal)
        return 2
    try:
        doc = build(args.name, args.title, arms, args.audits,
                    {k: Path(v) for k, v in fpc.items()} or None)
        p = export(doc, folders, args.out)
    except (ValueError, OSError) as exc:
        print(f"REFUSED: {exc}")
        return 2
    agg = ", ".join(f"{a}: {v['detected']}/{v['attempts']}" for a, v in doc["aggregate"].items())
    print(f"wrote {_rel(p)} (+ compare.js): {len(doc['rows'])} rows; detection {agg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
