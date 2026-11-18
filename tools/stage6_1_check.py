"""Stage 6.1b gates (Gates 1 and 2: REAL, PAID calls; each only after the designer's GO, from
a clean committed tree) and the zero-token steps around them.

    .venv/bin/python tools/stage6_1_check.py --gate 1                 # plan only
    .venv/bin/python tools/stage6_1_check.py --gate 1 --real-calls    # K train matches
    .venv/bin/python tools/stage6_1_check.py --promote <match> ...    # zero token, in order
    .venv/bin/python tools/stage6_1_check.py --predict --library L    # zero token (pre-register)
    .venv/bin/python tools/stage6_1_check.py --gate 2 --library L --real-calls   # M5 replays

Gate 1 (D28): K = 5 independent TRAIN matches (run_match.py --purpose train), --red ai
--blue claude, Blue rules on, caching on for both, dev models (D12), seeds 6101..6105
(the seed fixes the benign schedule only), NO library loaded. Refuses unless the holdout
and fixture_v2_offline are sealed (D27: pre-registration). Then it scaffolds the D30 audits
(the source rounds of candidate rules only) and writes the audit sheet.

--promote (zero token): after the designer's audits, promotes the given train matches in
ascending match_id order, each into the next library version (tools/promote_rules.py),
starting from the newest library in data/library/.

--predict (zero token, run BEFORE Gate 2 and recorded in docs/progress.md): which lines of
each Gate 3 source the library ALONE would answer (rules/hotload.py with the library
preloaded and no in-match rule), split into attack and benign lines.

Gate 2 (M5, D29): the 3 Gate 3 sources (TEST data, S6-1) replayed with claude Blue, rules
on, caching on, once with the empty library v0000 and once with the given library, all
else identical (tools/replay_blue.py --library: read-only, S6-3). PRIMARY: AI calls and
cost (plus the same run priced uncached). SECONDARY: whole-match detection and FP, raw and
audited; rule coverage by rule_origin; and holdout hits per library rule (offline, the
sealed holdout: TEST data, read here only for scoring).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import run_match  # noqa: E402
from rules import engine, hotload, library as rule_library  # noqa: E402
from stats import cost as cost_stats  # noqa: E402
from stats import match_stats as ms  # noqa: E402
from tools import audit_match, build_holdout, promote_rules, replay_blue  # noqa: E402

GOLDEN = REPO / "data" / "golden"
LIBRARY_DIR = REPO / "data" / "library"
EMPTY = LIBRARY_DIR / "rule_library_v0000.json"
SOURCES = ["ai-vs-ai-gate3-match1", "ai-vs-ai-gate3-match2", "ai-vs-ai-gate3-match3"]
SEEDS = (6101, 6102, 6103, 6104, 6105)
HOLDOUT = REPO / "benign" / "holdout_v1.jsonl"


def jl(p: Path) -> list[dict]:
    return ms.read_rounds(p)


def sealed_ok() -> list[str]:
    """Problems that block Gate 1 (empty = the offline files are sealed and intact)."""
    ts = json.loads((REPO / "config" / "test_set.json").read_text(encoding="utf-8"))
    problems = [f"{s['path']} is not sealed" for s in ts["sealed"] if s["sha256"] is None]
    return problems + build_holdout.check_sealed()


# -- Gate 1 ---------------------------------------------------------------------------

def gate1(prices: dict, k: int = len(SEEDS), sheet_dir: Path | None = None,
          audits: Path | None = None, **run_kw) -> int:
    """run_kw (tests only): ops / live_dir / runs_dir passed to run_match.run_match."""
    dirs, ok = [], True
    for i, seed in enumerate(SEEDS[:k], start=1):
        print(f"\n##### train match {i}/{k} (seed {seed}, --purpose train, --red ai --blue "
              f"claude, rules on, caching on for both, no library)")
        code, d = run_match.run_match(seed=seed, red_engine="ai", engine="claude",
                                      blue_rules_mode="on", blue_caching="on",
                                      red_caching="on", purpose="train", **run_kw)
        if d is None:
            print(f"  REFUSED at preflight (exit {code})")
            ok = False
            continue
        ok &= code in (0, 4)
        dirs.append(d)
        m = json.loads((d / "match.json").read_text(encoding="utf-8"))
        print(f"  {m['match_id']} {m['status']} rules stored {len(jl(d / 'rules.jsonl'))} "
              f"cost ${m['cost']['total_usd']:.6f}")
    print("\n=== D30 audits: the source rounds of candidate rules only")
    for d in dirs:
        try:
            print(f"  scaffolded {audit_match._rel(audit_match.scaffold(d, audits=audits))} "
                  f"rounds {sorted(audit_match.audit_scope(d) or [])}")
        except audit_match.AuditError as exc:
            print(f"  {d.name}: {exc}")
    if dirs:
        sheet = (sheet_dir or REPO / "docs" / "audits") / f"stage6_1_gate1_{dirs[0].name}.md"
        sheet.write_text(audit_match.sheet(dirs, audits=audits), encoding="utf-8")
        print(f"  sheet {audit_match._rel(sheet)}")
    total = sum(json.loads((d / "match.json").read_text())["cost"]["total_usd"] for d in dirs)
    print(f"\nRESULT: {'PASS' if ok and len(dirs) == k else 'FAIL'} ({len(dirs)}/{k} train "
          f"matches, ${total:.6f}). Next: audit, then --promote in order.")
    return 0 if ok and len(dirs) == k else 1


# -- promotion ------------------------------------------------------------------------

def newest_library(library_dir: Path = LIBRARY_DIR) -> Path:
    return sorted(library_dir.glob("rule_library_v*.json"))[-1]


def promote_all(match_dirs: list[Path]) -> int:
    ordered = sorted(match_dirs, key=lambda d: json.loads((d / "match.json").read_text())
                     ["match_id"])
    for d in ordered:
        code = promote_rules.promote(d, newest_library())
        if code != 0:
            return code
    print(f"library now {audit_match._rel(newest_library())}")
    return 0


# -- prediction (zero token) -----------------------------------------------------------

def predict(lib: rule_library.Library, sources=SOURCES) -> dict[str, list[dict]]:
    out = {}
    for src in sources:
        d = GOLDEN / src
        red = {a["request_id"]: a for a in jl(d / "red_attacks.jsonl")}
        benign = {b["request_id"]: b for b in jl(d / "benign_requests.jsonl")}
        hl = hotload.HotLoad(lib.entries)
        lines = [l for l in jl(d / "proxy.jsonl") if l.get("request_id")]
        hits = []
        for seq, line in enumerate(lines, start=1):
            f = hl.fire(engine.Request.from_log(line), seq)
            if f.rule_ids:
                rid = line["request_id"]
                kind = (f"attack {red[rid]['label']} round {red[rid]['round']}" if rid in red
                        else f"benign {benign[rid]['benign_id']}" if rid in benign else "?")
                hits.append({"log_seq": seq, "rule_ids": f.rule_ids, "cwe": f.cwe,
                             "line": kind, "attack": rid in red})
        out[src] = hits
    return out


def print_prediction(lib: rule_library.Library, pred: dict[str, list[dict]]) -> None:
    print(f"Prediction (zero token): library v{lib.library_version} ({len(lib)} rules, "
          f"sha256 {lib.sha256[:12]}) alone, on the Gate 3 sources")
    for src, hits in pred.items():
        n_lines = len([l for l in jl(GOLDEN / src / "proxy.jsonl") if l.get("request_id")])
        att = sum(h["attack"] for h in hits)
        print(f"  {src}: {len(hits)}/{n_lines} lines answered by the library "
              f"({att} attack, {len(hits) - att} benign)")
        for h in hits:
            print(f"    log_seq {h['log_seq']:3} {h['cwe']:7} {','.join(h['rule_ids']):20} "
                  f"{h['line']}")


# -- Gate 2 ---------------------------------------------------------------------------

def holdout_hits(lib: rule_library.Library) -> dict[str, list[str]]:
    rows = [json.loads(l) for l in HOLDOUT.read_text(encoding="utf-8").splitlines() if l.strip()]
    forms = [(r["benign_id"], engine.forms(engine.Request.from_log(r))) for r in rows]
    return {lr.library_id: [bid for bid, f in forms if engine.fires(lr.validated, f)]
            for lr in lib.entries}


def replay_report(rdir: Path, prices: dict) -> dict:
    calls = jl(rdir / "api_calls.jsonl")
    s = cost_stats.summarize(calls, prices)
    v = jl(rdir / "verdicts.jsonl")
    cov = Counter((x["source"], x.get("rule_origin")) for x in v)
    aud = audit_match.summary(rdir)
    return {"calls": s["attempts"], "usd": s["total_usd"],
            "uncached": round(s["total_usd"] + s["cache_savings_usd"], 6),
            "lines": len(v), "library_lines": cov[("rule", "library")],
            "match_lines": cov[("rule", "match")], "ai_lines": cov[("ai", None)],
            "raw": aud["raw"], "audited": aud["audited"]}


def gate2(prices: dict, lib_path: Path, root: Path | None = None, ops=None) -> int:
    """ops (tests only): the run_match.Ops the replays use (fake provider)."""
    gid = run_match.new_match_id()
    root = root or replay_blue.REPLAYS / f"gate2-6.1-{gid}"
    rows, ok = [], True
    for src in SOURCES:
        for arm, path in (("empty", EMPTY), ("library", lib_path)):
            code, rdir = replay_blue.replay(GOLDEN / src, root / f"{src}-{arm}",
                                            engine="claude", rules_mode="on", caching="on",
                                            library=path, out_fn=lambda *_: None,
                                            ops=ops)
            if rdir is None:
                print(f"=== {src} {arm}: REFUSED (exit {code})")
                ok = False
                continue
            ok &= code in (0, 4)
            r = replay_report(rdir, prices)
            rows.append({"source": src, "arm": arm, **r})
            fmt = lambda b, k: b[k]["num"].__str__() + "/" + b[k]["den"].__str__() if b else "—"
            print(f"=== {src:24} {arm:8} calls {r['calls']:3}  ${r['usd']:.6f} (uncached "
                  f"${r['uncached']:.6f})  lines: library {r['library_lines']} match "
                  f"{r['match_lines']} ai {r['ai_lines']} / {r['lines']}  detection raw "
                  f"{fmt(r['raw'], 'detection')} audited {fmt(r['audited'], 'detection')}  FP "
                  f"{fmt(r['raw'], 'fp')}")
    print("\n=== M5 summary (PRIMARY: AI calls and cost, library vs empty; all else identical)")
    for src in SOURCES:
        a = {r["arm"]: r for r in rows if r["source"] == src}
        if {"empty", "library"} <= set(a):
            e, l_ = a["empty"], a["library"]
            print(f"  {src:24} calls {e['calls']} -> {l_['calls']} ({l_['calls'] - e['calls']:+d})"
                  f"  cost ${e['usd']:.6f} -> ${l_['usd']:.6f} "
                  f"({l_['usd'] - e['usd']:+.6f})")
    tot = {arm: (sum(r["calls"] for r in rows if r["arm"] == arm),
                 sum(r["usd"] for r in rows if r["arm"] == arm)) for arm in ("empty", "library")}
    print(f"  total calls {tot['empty'][0]} -> {tot['library'][0]}  cost "
          f"${tot['empty'][1]:.6f} -> ${tot['library'][1]:.6f}")
    lib = rule_library.load(lib_path)
    print("\n=== Holdout hits per library rule (offline; TEST data, scoring only)")
    for lid, hits in holdout_hits(lib).items():
        print(f"  {lid}: {len(hits)} {hits if hits else ''}")
    print(f"RESULT: {'PASS' if ok and len(rows) == 2 * len(SOURCES) else 'FAIL'} "
          f"({len(rows)}/{2 * len(SOURCES)} replays) -> {replay_blue._rel(root)}")
    return 0 if ok and len(rows) == 2 * len(SOURCES) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--gate", type=int, choices=(1, 2))
    g.add_argument("--predict", action="store_true")
    g.add_argument("--promote", type=Path, nargs="+", metavar="MATCH")
    ap.add_argument("--library", type=Path, default=None)
    ap.add_argument("--real-calls", action="store_true",
                    help="actually run the gate (REAL, PAID calls; designer GO only)")
    args = ap.parse_args(argv)
    if args.promote:
        return promote_all(args.promote)
    if args.predict or args.gate == 2:
        if args.library is None:
            print("REFUSED: --library <file> is required")
            return 2
        lib = rule_library.load(args.library)
        if args.predict:
            print_prediction(lib, predict(lib))
            return 0
        print(f"Stage 6.1 Gate 2 (M5): {len(SOURCES)} Gate 3 sources x {{v0000 empty, "
              f"library v{lib.library_version} ({len(lib)} rules)}} = {2 * len(SOURCES)} "
              f"replays, claude Blue, rules on, caching on")
    else:
        print(f"Stage 6.1 Gate 1: {len(SEEDS)} train matches (seeds {SEEDS}), --purpose train, "
              f"--red ai --blue claude, rules on, caching on (both), no library")
        problems = sealed_ok()
        if problems:
            print(f"REFUSED: the offline benign files are not sealed (D27): {problems}")
            return 2
    if not args.real_calls:
        print("REFUSED: pass --real-calls (designer GO only). Nothing was called.")
        return 2
    if run_match.Ops().git_info()["dirty"]:
        print("REFUSED: the git tree is dirty; commit first.")
        return 2
    prices = cost_stats.load_prices()
    return gate1(prices) if args.gate == 1 else gate2(prices, args.library)


if __name__ == "__main__":
    raise SystemExit(main())
