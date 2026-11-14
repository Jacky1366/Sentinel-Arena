"""Stage 5.5 gate (Part F): 12 Blue replays with REAL, PAID calls (designer GO only).

    .venv/bin/python tools/stage5_5_check.py              # prints the plan, calls nothing
    .venv/bin/python tools/stage5_5_check.py --real-calls # runs the 12 replays

The 3 audited AI-Red golden matches plus scripted-baseline-benign-match, each replayed
with claude Blue (config/llm.json agents.blue: Haiku 5.5) in rules mode off, shadow and
on (tools/replay_blue.py, D17). Each replay starts with zero rules (D7: cross-match
memory is Stage 6). on vs shadow isolates the hot-load effect; shadow vs off isolates
the prompt change (v1 -> v2).

Per replay it prints: raw and audited detection and FP rate, split by verdict source
(rule path: line counts, type accuracy, FP rate; never a detection rate); rules proposed / stored / rejected with every reason; facts 3 and 4b
per rule; AI calls saved; cost. Every invented rule and every rejected proposal is
printed in full for the designer's review. Output goes to data/replays/<gate id>/
(git-ignored); the golden folders are never written (checked by hash).

Refuses without --real-calls, and on a dirty git tree (a gate runs from a clean,
committed tree so replay.json's git commit identifies the code). Exit 0 iff every
replay completed and every golden folder is unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import audit_match  # noqa: E402
import replay_blue  # noqa: E402
import run_match  # noqa: E402
from stats import match_stats as ms  # noqa: E402

GOLDEN = REPO / "data" / "golden"
SOURCES = ["ai-red-luna-gate2-match1", "ai-red-luna-gate2-match2", "ai-red-luna-gate2-match3",
           "scripted-baseline-benign-match"]
MODES = ("off", "shadow", "on")


def tree(d: Path) -> dict[str, str]:
    return {p.relative_to(d).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(d.rglob("*")) if p.is_file()}


def fmt(rate: dict | None) -> str:
    if rate is None:
        return "—"
    pct = "n/a" if rate["pct"] is None else f"{rate['pct']:.0f}%"
    return f"{rate['num']}/{rate['den']} ({pct})"


def jl(p: Path) -> list[dict]:
    return ms.read_rounds(p)


def report(rdir: Path) -> dict:
    """Print one replay's numbers and rules; return a row for the final table."""
    m = json.loads((rdir / "replay.json").read_text(encoding="utf-8"))
    s = audit_match.summary(rdir)
    rounds, benign = jl(rdir / "rounds.jsonl"), jl(rdir / "benign_results.jsonl")
    rules = ms.rules_summary(jl(rdir / "rules.jsonl"), jl(rdir / "rule_rejections.jsonl"),
                             jl(rdir / "verdicts.jsonl"), jl(rdir / "rule_results.jsonl"),
                             rounds, benign)
    mode = m["blue_params"]["rules"]["mode"]
    print(f"\n=== {m['source']['path']}  mode {mode}  replay {m['replay_id']}  "
          f"status {m['status']}  -> {replay_blue._rel(rdir)}")
    if m["status"] == "failed":
        print(f"FAILED at {m['failed_step']}: {m['error']}")
    print(f"cost ${m['cost']['total_usd']:.4f}  attempts {m['cost']['attempts']}  "
          f"refused {m['cost']['refused']}  stopped_by {m['budget']['stopped_by']}")
    for view in ("raw", "audited"):
        b = s[view]
        if b is None:
            print(f"  {view:8} incomplete audit (unaudited {s['unaudited']})")
            continue
        r, a = b["by_source"]["rule"], b["by_source"]["ai"]
        print(f"  {view:8} whole match: detection {fmt(b['detection']):12} FP "
              f"{fmt(b['fp']):12} type acc. {fmt(b['type_accuracy']):12}| rule path: "
              f"{r['attack_lines']} attack + {r['benign_lines']} benign lines, type acc. "
              f"{fmt(r['type_accuracy'])} FP {fmt(r['fp'])} | AI path: "
              f"{a['attack_lines']} attack + {a['benign_lines']} benign lines")
    if s["audited_excludes_label_invalid"]:
        print(f"  audited excludes label-invalid rounds {s['audited_excludes_label_invalid']}")
    verdicts = jl(rdir / "verdicts.jsonl")
    nv = sum(v["verdict"] is None for v in verdicts)
    details: dict[str, int] = {}
    for v in verdicts:
        if v.get("failure_detail"):
            details[v["failure_detail"]] = details.get(v["failure_detail"], 0) + 1
    hard = ms.compute_benign(rounds, benign)["fp_hard"].fmt() if benign else "—"
    print(f"  FP hard negatives {hard}  no-verdict lines {nv}/{len(verdicts)} "
          f"{details or ''}  max_tokens stops {details.get('max_tokens', 0)}")
    if mode != "off":
        print("\n".join(ms.format_rules(rules, ms.by_source(rounds, benign), mode)))
    for a in jl(rdir / "anomalies.jsonl"):
        print(f"  ANOMALY {a['kind']} {a['request_id'][:8]} {json.dumps(a['detail'])}")
    return {"source": m["source"]["path"].split("/")[-1], "mode": mode, "status": m["status"],
            "raw_det": fmt(s["raw"]["detection"]), "raw_fp": fmt(s["raw"]["fp"]),
            "aud_det": fmt(s["audited"]["detection"]) if s["audited"] else "—",
            "fp_hard": hard, "no_verdict": f"{nv}/{len(verdicts)}",
            "calls": m["cost"]["attempts"], "max_tokens": details.get("max_tokens", 0),
            "proposed": rules["proposed"], "stored": rules["stored"],
            "saved": rules["ai_calls_saved"], "usd": m["cost"]["total_usd"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--real-calls", action="store_true",
                    help="actually run the 12 replays (REAL, PAID Blue calls)")
    args = ap.parse_args(argv)
    plan = [(src, mode) for src in SOURCES for mode in MODES]
    print(f"Stage 5.5 gate: {len(plan)} replays (claude Blue, config/llm.json agents.blue)")
    for src, mode in plan:
        print(f"  {src:32} {mode}")
    if not args.real_calls:
        print("REFUSED: pass --real-calls (designer GO only). Nothing was called.")
        return 2
    git = run_match.Ops().git_info()
    if git["dirty"]:
        print("REFUSED: the git tree is dirty; commit first so replay.json identifies the "
              "code.")
        return 2
    gate_id = run_match.new_match_id()
    root = replay_blue.REPLAYS / f"gate-5.5-{gate_id}"
    before = {src: tree(GOLDEN / src) for src in SOURCES}
    rows, ok = [], True
    for src, mode in plan:
        code, rdir = replay_blue.replay(GOLDEN / src, root / f"{src}-{mode}", engine="claude",
                                         rules_mode=mode, out_fn=lambda *_: None)
        if rdir is None:
            print(f"\n=== {src} {mode}: REFUSED (exit {code})")
            ok = False
            continue
        ok &= code in (0, 4)
        rows.append(report(rdir))
    unchanged = all(tree(GOLDEN / src) == before[src] for src in SOURCES)
    print("\n=== summary")
    print(f"{'source':32} {'mode':6} {'status':9} {'raw det':12} {'raw FP':12} "
          f"{'audited det':12} {'hard FP':10} {'no-verd':8} calls prop stored saved "
          f"maxtok  cost")
    for r in rows:
        print(f"{r['source']:32} {r['mode']:6} {r['status']:9} {r['raw_det']:12} "
              f"{r['raw_fp']:12} {r['aud_det']:12} {r['fp_hard']:10} {r['no_verdict']:8} "
              f"{r['calls']:>5} {r['proposed']:>4} {r['stored']:>6} {r['saved']:>5} "
              f"{r['max_tokens']:>6}  ${r['usd']:.4f}")
    print(f"total cost ${sum(r['usd'] for r in rows):.4f}")
    print(f"golden folders unchanged: {'PASS' if unchanged else 'FAIL'}")
    ok &= unchanged
    print(f"RESULT: {'PASS' if ok else 'FAIL'} ({len(rows)}/{len(plan)} replays) -> "
          f"{replay_blue._rel(root)}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
