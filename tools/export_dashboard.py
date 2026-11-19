"""Export one frozen match or replay folder into a single dashboard bundle (Stage 6.4, M8;
contract §6.14). A pure reader: every value is copied from an artifact (the Red record,
the proxy line, the Judge's round / benign result, Blue's verdict, api_calls.jsonl priced
by stats/cost.py). Nothing is judged here. Never writes into the source folder. Zero
tokens.

    .venv/bin/python tools/export_dashboard.py data/golden/train-6.1b-gate1-match1 \\
        --name train-gate1-match1

Writes dashboard/public/data/<name>.json, then rewrites dashboard/public/data/bundles.js
(every *.json there wrapped as `window.ARENA_BUNDLES[...]`), so the built dashboard works
from file:// with no network at all.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from stats import cost as cost_mod  # noqa: E402
from stats import match_stats as ms  # noqa: E402

OUT = REPO / "dashboard" / "public" / "data"
TEXT_MAX = 400  # long payloads / rationales are cut for display (marked with …)
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "dashboard_bundle.schema.json")
                                         .read_text(encoding="utf-8")))
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")


def _jl(p: Path) -> list[dict]:
    return ms.read_rounds(p)


def _cut(s: str | None) -> str | None:
    if s is None:
        return None
    return s if len(s) <= TEXT_MAX else s[:TEXT_MAX] + "…"


def _rel(p: Path) -> str:
    p = Path(p).resolve()
    try:
        return p.relative_to(REPO).as_posix()
    except ValueError:
        return p.as_posix()


def _cost(calls: list[dict], prices: dict) -> dict:
    s = cost_mod.summarize(calls, prices)
    return {"calls": s["attempts"], "usd": s["total_usd"], "tokens": s["tokens"]}


def bundle(d: Path, name: str, prices: dict | None = None) -> dict:
    d = Path(d)
    prices = prices if prices is not None else cost_mod.load_prices()
    if (d / "replay.json").is_file():
        man, kind = json.loads((d / "replay.json").read_text(encoding="utf-8")), "replay"
        run_id, match_id = man["replay_id"], man["source"]["match_id"]
        red_engine, purpose, seed = man["source"].get("red_engine", "scripted"), None, None
    elif (d / "match.json").is_file():
        man, kind = json.loads((d / "match.json").read_text(encoding="utf-8")), "match"
        run_id = match_id = man["match_id"]
        # manifests before 0.5 have no red_engine (scripted Red) and may have no traffic
        red_engine, purpose = man.get("red_engine", "scripted"), man.get("purpose")
        seed = (man.get("traffic") or {}).get("seed")
    else:
        raise ValueError(f"{d} is not a frozen match or replay folder")
    bp = man.get("blue_params") or {}
    lib = bp.get("library")
    red = {a["request_id"]: a for a in _jl(d / "red_attacks.jsonl")}
    benign_req = {b["request_id"]: b for b in _jl(d / "benign_requests.jsonl")}
    rounds = {r["request_id"]: r for r in _jl(d / "rounds.jsonl")}
    benign = {b["request_id"]: b for b in _jl(d / "benign_results.jsonl")}
    verdicts = {v["request_id"]: v for v in _jl(d / "verdicts.jsonl")}
    calls = _jl(d / "api_calls.jsonl")
    lines = [l for l in _jl(d / "proxy.jsonl") if l.get("request_id")]

    steps, max_round = [], 0
    for i, line in enumerate(lines, start=1):
        rid = line["request_id"]
        v = verdicts.get(rid)
        seq = v["log_seq"] if v is not None else i
        if rid in red:
            a, r = red[rid], rounds.get(rid, {})
            max_round = max(max_round, a["round"])
            red_view = {"kind": "attack", "round": a["round"], "label": a["label"],
                        "source": a.get("source", "scripted"), "rationale": _cut(a.get("rationale"))}
            judge = {"kind": "attack", "landed": r.get("landed"),
                     "landed_reason": r.get("landed_reason"),
                     "newly_solved": r.get("newly_solved", []), "detected": r.get("detected"),
                     "type_correct": r.get("type_correct"),
                     "detected_reason": r.get("detected_reason")}
        elif rid in benign_req:
            b, br = benign_req[rid], benign.get(rid, {})
            red_view = {"kind": "benign", "benign_id": b["benign_id"], "category": b["category"]}
            judge = {"kind": "benign", "false_positive": br.get("false_positive"),
                     "fp_reason": br.get("fp_reason")}
        else:  # a logged request with no Red / benign record (never happens in a frozen run)
            red_view, judge = {"kind": "unknown"}, {"kind": "unknown"}
        blue = None if v is None else {
            "verdict": v["verdict"], "source": v.get("source"), "rule_origin": v.get("rule_origin"),
            "fired_rule_ids": v.get("fired_rule_ids", []), "rationale": _cut(v.get("rationale")),
            "no_verdict_reason": v.get("no_verdict_reason")}
        last = i == len(lines)
        so_far = [c for c in calls if last
                  or (c["agent"] == "blue" and (c.get("log_seq_last") or 0) <= seq)
                  or (c["agent"] != "blue" and (c.get("round") or 0) <= max_round)]
        steps.append({"log_seq": seq, "request_id": rid,
                      "request": {"method": line["method"], "path": _cut(line["path"]),
                                  "query": _cut(line["query"]), "body": _cut(line["body"]),
                                  "status": line.get("status")},
                      "red": red_view, "judge": judge, "blue": blue,
                      "cost_so_far": _cost(so_far, prices)})

    rules = [{**r["rule"], "origin": "match"} for r in _jl(d / "rules.jsonl")]
    if (d / "library.json").is_file():
        doc = json.loads((d / "library.json").read_text(encoding="utf-8"))
        rules = [{**e["rule"], "rule_id": e["library_id"], "origin": "library"}
                 for e in doc["entries"]] + rules
    out = {
        "schema_version": "0.1", "name": name, "kind": kind, "run_id": run_id,
        "match_id": match_id, "source_path": _rel(d),
        "meta": {"red_engine": red_engine, "blue_engine": man.get("blue_engine"),
                 "models": man.get("models"), "purpose": purpose, "seed": seed,
                 "rules_mode": (bp.get("rules") or {}).get("mode"),
                 "library": None if lib is None else {
                     "library_version": lib["library_version"], "entries": lib["entries"],
                     "sha256": lib["sha256"]},
                 "judge_version": man.get("judge_version"), "git": man.get("git"),
                 "status": man.get("status")},
        "steps": steps,
        "unsent": [{"round": u["round"], "kind": u["kind"], "reason": u.get("reason")}
                   for u in _jl(d / "red_unsent.jsonl")],
        "rules": [{"rule_id": r["rule_id"], "cwe": r["cwe"], "origin": r["origin"],
                   "conditions": r["conditions"], "created_match": r.get("created_match"),
                   "created_at_log_seq": r.get("created_at_log_seq")} for r in rules],
        "anomalies": [{"kind": a["kind"], "request_id": a.get("request_id"),
                       "detail": a.get("detail")} for a in _jl(d / "anomalies.jsonl")],
        "counts": ms.counts(list(rounds.values())),
        "total_cost": _cost(calls, prices),
    }
    errors = [e.message for e in SCHEMA.iter_errors(out)]
    if errors:
        raise RuntimeError(f"bundle is schema-invalid: {errors[:3]}")
    return out


def pack(out_dir: Path = OUT) -> Path:
    """bundles.js: every bundle JSON in out_dir as window.ARENA_BUNDLES[name] (sorted)."""
    parts = ["// GENERATED by tools/export_dashboard.py — do not edit.",
             "window.ARENA_BUNDLES = window.ARENA_BUNDLES || {};"]
    for p in sorted(Path(out_dir).glob("*.json")):
        doc = json.loads(p.read_text(encoding="utf-8"))
        parts.append(f"window.ARENA_BUNDLES[{json.dumps(doc['name'])}] = "
                     f"{json.dumps(doc, ensure_ascii=False, separators=(',', ':'))};")
    js = Path(out_dir) / "bundles.js"
    js.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return js


def export(d: Path, name: str, out_dir: Path = OUT, prices: dict | None = None) -> Path:
    if not NAME_RE.match(name):
        raise ValueError(f"bad bundle name {name!r} (lowercase letters, digits, '.', '-')")
    doc = bundle(d, name, prices)
    out_dir = Path(out_dir)
    if out_dir.resolve() == Path(d).resolve() or Path(d).resolve() in out_dir.resolve().parents:
        raise ValueError("refusing to write into the source folder")
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"{name}.json"
    p.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    pack(out_dir)
    return p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("folder", type=Path, help="a frozen match or replay folder")
    ap.add_argument("--name", required=True, help="bundle name (file name and menu entry)")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    try:
        p = export(args.folder, args.name, args.out)
    except (ValueError, OSError) as exc:
        print(f"REFUSED: {exc}")
        return 2
    print(f"wrote {_rel(p)} (+ bundles.js)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
