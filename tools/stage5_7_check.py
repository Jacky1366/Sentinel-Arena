"""Stage 5.7 Gates 2 and 3 (REAL, PAID calls; each only after the designer's GO).

    .venv/bin/python tools/stage5_7_check.py --gate 2               # plan only, calls nothing
    .venv/bin/python tools/stage5_7_check.py --gate 2 --real-calls  # caching effect, rules on
    .venv/bin/python tools/stage5_7_check.py --gate 2 --rules-mode off --real-calls  # Gate 2b
    .venv/bin/python tools/stage5_7_check.py --gate 3 --real-calls  # first AI-vs-AI matches

Gate 2 (caching effect, D17 clean comparison): the four gate-5.5 sources replayed with
claude Blue, rules mode on, caching ON (same inputs as the committed
data/golden/replays/gate-5.5/*-on replays). Per source:
  PRIMARY    this run's cost vs the same run priced as uncached (usd + net savings):
             the same calls, so it isolates caching exactly;
  SECONDARY  this run's cost vs the committed gate-5.5 "on" cost (mixes the caching
             effect with run-to-run variation: rule-answered lines, and so calls, differ);
  plus cost per AI call for both runs, cache read / write tokens, net savings.
`--rules-mode off` (Gate 2b) does the same with rules mode off (prompt v1) against the
committed *-off replays, completing the 2x2 (rules off/on x caching off/on).
Output: data/replays/gate2-5.7-<id>/ (gate2b-5.7-<id>/ for rules off; git-ignored).

Gate 3 (AI vs AI): three live matches, --red ai --blue claude, Blue rules on, caching on
for both, the Stage 5.2 seed (fixes the benign schedule only; AI Red is not seeded).
Per match: attacks sent, red_unsent, landed, raw detection, FP, rules proposed /
stored, AI calls saved, cost and net cache savings per agent, the four-facts check
(PASS / N/A (no rules) / FAIL), max_tokens stops. Then scaffolds the D16 audit files
(data/audits/<match_id>.jsonl) and writes the audit sheet (docs/audits/). Stage 5 is
done when at least one match reaches four facts PASS. Needs Docker (the stack) and
both keys.

Both refuse without --real-calls and on a dirty git tree.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import audit_match  # noqa: E402
import four_facts  # noqa: E402
import replay_blue  # noqa: E402
import run_match  # noqa: E402
from stats import cost as cost_stats  # noqa: E402
from stats import match_stats as ms  # noqa: E402

GOLDEN = REPO / "data" / "golden"
GATE55 = GOLDEN / "replays" / "gate-5.5"
SOURCES = ["ai-red-luna-gate2-match1", "ai-red-luna-gate2-match2", "ai-red-luna-gate2-match3",
           "scripted-baseline-benign-match"]
SEED = json.loads((REPO / "tools" / "stage5_2_expected.json").read_text())["seed"]
RUNS = 3


def jl(p: Path) -> list[dict]:
    return ms.read_rounds(p)


def manifest_of(d: Path) -> dict:
    name = "match.json" if (d / "match.json").exists() else "replay.json"
    return json.loads((d / name).read_text(encoding="utf-8"))


def caching_numbers(calls: list[dict], prices: dict, agent: str | None = None) -> dict:
    rows = [c for c in calls if agent is None or c["agent"] == agent]
    s = cost_stats.summarize(rows, prices)
    return {"usd": s["total_usd"], "savings": s["cache_savings_usd"],
            "uncached": round(s["total_usd"] + s["cache_savings_usd"], 6),
            "calls": s["attempts"], "read": s["tokens"]["cached_input"],
            "write": s["tokens"]["cache_write"], "unpriced": s["unpriced_usage"]}


def max_tokens_stops(d: Path) -> dict:
    v = sum(x.get("failure_detail") == "max_tokens" for x in jl(d / "verdicts.jsonl"))
    r = sum(u.get("reason") == "max_tokens" for u in jl(d / "red_unsent.jsonl"))
    return {"blue": v, "red": r}


# -- Gate 2 --------------------------------------------------------------------

def gate2_report(rdir: Path, src: str, prices: dict, mode: str = "on") -> dict:
    now = caching_numbers(jl(rdir / "api_calls.jsonl"), prices)
    old_dir = GATE55 / f"{src}-{mode}"
    old = caching_numbers(jl(old_dir / "api_calls.jsonl"), prices)
    m = manifest_of(rdir)
    rules = len(jl(rdir / "rules.jsonl"))
    saved = sum(v.get("source") == "rule" for v in jl(rdir / "verdicts.jsonl"))
    ff = four_facts.check(rdir)
    per = (lambda n: n["usd"] / n["calls"] if n["calls"] else 0.0)
    print(f"\n=== {src}  (rules {mode}, caching on)  status {m['status']}  -> "
          f"{replay_blue._rel(rdir)}")
    print(f"  PRIMARY   cost ${now['usd']:.6f}  vs same run uncached ${now['uncached']:.6f}"
          f"  -> net savings ${now['savings']:+.6f} "
          f"({(now['savings'] / now['uncached'] * 100) if now['uncached'] else 0:+.1f}%)")
    print(f"  cache     read {now['read']} tok  write {now['write']} tok  calls {now['calls']}"
          f"  rules stored {rules}  AI calls saved {saved}"
          f"{'  UNPRICED USAGE' if now['unpriced'] else ''}")
    print(f"  SECONDARY committed gate-5.5 '{mode}' cost ${old['usd']:.6f} ({old['calls']} calls)"
          f"  -> difference ${now['usd'] - old['usd']:+.6f}")
    print(f"  per call  now ${per(now):.6f}  committed ${per(old):.6f}")
    print(f"  {four_facts.format_result(ff).splitlines()[0]}  max_tokens {max_tokens_stops(rdir)}")
    return {"source": src, "status": m["status"], **now, "old_usd": old["usd"],
            "old_calls": old["calls"], "saved": saved}


def gate2(prices: dict, mode: str = "on") -> int:
    gid = run_match.new_match_id()
    root = replay_blue.REPLAYS / f"{'gate2' if mode == 'on' else 'gate2b'}-5.7-{gid}"
    rows, ok = [], True
    for src in SOURCES:
        code, rdir = replay_blue.replay(GOLDEN / src, root / f"{src}-{mode}-cached",
                                        engine="claude", rules_mode=mode, caching="on",
                                        out_fn=lambda *_: None)
        if rdir is None:
            print(f"\n=== {src}: REFUSED (exit {code})")
            ok = False
            continue
        ok &= code in (0, 4)
        rows.append(gate2_report(rdir, src, prices, mode))
    print(f"\n=== Gate 2{'' if mode == 'on' else 'b'} summary, rules {mode} (PRIMARY = same "
          f"run priced uncached)")
    print(f"{'source':32} {'cost':>9} {'uncached':>9} {'net sav.':>9} {'read':>6} "
          f"{'write':>6} {'calls':>5} | {'5.5 cost':>9} {'calls':>5}")
    for r in rows:
        print(f"{r['source']:32} {r['usd']:>9.6f} {r['uncached']:>9.6f} {r['savings']:>+9.6f} "
              f"{r['read']:>6} {r['write']:>6} {r['calls']:>5} | {r['old_usd']:>9.6f} "
              f"{r['old_calls']:>5}")
    t = {k: sum(r[k] for r in rows) for k in ("usd", "uncached", "savings", "old_usd")}
    print(f"{'total':32} {t['usd']:>9.6f} {t['uncached']:>9.6f} {t['savings']:>+9.6f} "
          f"{'':>6} {'':>6} {'':>5} | {t['old_usd']:>9.6f}")
    print(f"RESULT: {'PASS' if ok else 'FAIL'} ({len(rows)}/{len(SOURCES)} replays) -> "
          f"{replay_blue._rel(root)}")
    return 0 if ok else 1


# -- Gate 3 --------------------------------------------------------------------

def gate3_report(d: Path, prices: dict) -> dict:
    m = manifest_of(d)
    rounds, benign = jl(d / "rounds.jsonl"), jl(d / "benign_results.jsonl")
    unsent = jl(d / "red_unsent.jsonl")
    calls = jl(d / "api_calls.jsonl")
    s, b = ms.compute(rounds), ms.compute_benign(rounds, benign)
    rules = ms.rules_summary(jl(d / "rules.jsonl"), jl(d / "rule_rejections.jsonl"),
                             jl(d / "verdicts.jsonl"), jl(d / "rule_results.jsonl"),
                             rounds, benign)
    ff = four_facts.check(d)
    stops = max_tokens_stops(d)
    print(f"\n=== {d.name}  status {m['status']}  seed {m['traffic']['seed']}")
    print(f"  attacks sent {len(jl(d / 'red_attacks.jsonl'))}  red_unsent {len(unsent)} "
          f"{dict(Counter(u['kind'] for u in unsent))}  landed "
          f"{sum(r['landed'] is True for r in rounds)}")
    print(f"  raw detection {s['detection'].fmt()}  FP {b['fp'].fmt()}  "
          f"(hard negatives {b['fp_hard'].fmt()})  type acc. {s['type_accuracy'].fmt()}")
    print(f"  rules proposed {rules['proposed']}  stored {rules['stored']}  rejected "
          f"{rules['rejected']} {rules['rejection_codes'] or ''}  AI calls saved "
          f"{rules['ai_calls_saved']}")
    for agent in ("red", "blue"):
        n = caching_numbers(calls, prices, agent)
        print(f"  {agent:4} cost ${n['usd']:.6f}  calls {n['calls']}  cache read {n['read']} / "
              f"write {n['write']} tok  net savings ${n['savings']:+.6f}  (uncached "
              f"${n['uncached']:.6f}){'  UNPRICED' if n['unpriced'] else ''}")
    print(f"  max_tokens stops blue {stops['blue']} red {stops['red']}")
    print("  " + four_facts.format_result(ff).replace("\n", "\n  "))
    return {"match": d.name, "status": m["status"], "four_facts": ff["status"],
            "usd": m["cost"]["total_usd"]}


def gate3(prices: dict) -> int:
    dirs, rows, ok = [], [], True
    for i in range(1, RUNS + 1):
        print(f"\n##### Gate 3 match {i}/{RUNS} (seed {SEED}, --red ai --blue claude, "
              f"rules on, caching on for both)")
        code, d = run_match.run_match(seed=SEED, red_engine="ai", engine="claude",
                                      blue_rules_mode="on", blue_caching="on",
                                      red_caching="on")
        if d is None:
            print(f"  REFUSED at preflight (exit {code})")
            ok = False
            continue
        ok &= code in (0, 4)
        dirs.append(d)
        rows.append(gate3_report(d, prices))
    print("\n=== D16 audit files (AI-Red labels must be audited before audited numbers count)")
    for d in dirs:
        try:
            print(f"  scaffolded {audit_match._rel(audit_match.scaffold(d))}")
        except audit_match.AuditError as exc:
            print(f"  {d.name}: {exc}")
    if dirs:
        sheet = REPO / "docs" / "audits" / f"stage5_7_gate3_{dirs[0].name}.md"
        sheet.write_text(audit_match.sheet(dirs), encoding="utf-8")
        print(f"  sheet {audit_match._rel(sheet)}")
    print("\n=== Gate 3 summary")
    for r in rows:
        print(f"  {r['match']}  {r['status']}  four facts {r['four_facts']}  ${r['usd']:.6f}")
    done = any(r["four_facts"] == four_facts.PASS for r in rows)
    print(f"Stage 5 done-when (>= 1 match four facts PASS): {'YES' if done else 'NO'}")
    print(f"RESULT: {'PASS' if ok and done else 'FAIL'} ({len(rows)}/{RUNS} matches)")
    return 0 if ok and done else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--gate", type=int, choices=(2, 3), required=True)
    ap.add_argument("--rules-mode", choices=("off", "on"), default="on",
                    help="Gate 2 only: Blue rules mode (off = Gate 2b, the 2x2 control)")
    ap.add_argument("--real-calls", action="store_true",
                    help="actually run the gate (REAL, PAID calls; designer GO only)")
    args = ap.parse_args(argv)
    if args.gate == 2:
        print(f"Stage 5.7 Gate 2{'' if args.rules_mode == 'on' else 'b'}: {len(SOURCES)} "
              f"replays, claude Blue, rules {args.rules_mode}, caching on")
        for src in SOURCES:
            print(f"  {src}  vs committed {GATE55.relative_to(REPO)}/{src}-{args.rules_mode}")
    else:
        print(f"Stage 5.7 Gate 3: {RUNS} live matches, --red ai --blue claude, rules on, "
              f"caching on (both), seed {SEED}")
    if not args.real_calls:
        print("REFUSED: pass --real-calls (designer GO only). Nothing was called.")
        return 2
    if run_match.Ops().git_info()["dirty"]:
        print("REFUSED: the git tree is dirty; commit first.")
        return 2
    prices = cost_stats.load_prices()
    return gate2(prices, args.rules_mode) if args.gate == 2 else gate3(prices)


if __name__ == "__main__":
    raise SystemExit(main())
