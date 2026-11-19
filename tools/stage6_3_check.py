"""Stage 6.3 flagship gate (M7). Every real path is token-gated (ARENA_GO) and runs only
after the designer's GO, from a clean committed tree. Plan: docs/plans/stage6_3_step0.md;
decisions D33-D37.

    .venv/bin/python tools/stage6_3_check.py --gate A --estimate            # zero token
    .venv/bin/python tools/stage6_3_check.py --gate A --probe --real-calls  # 2 calls (gate-6.3-A)
    .venv/bin/python tools/stage6_3_check.py --gate B --real-calls          # 3 eval matches (gate-6.3-B)
    .venv/bin/python tools/stage6_3_check.py --gate C --matches D1 D2 D3 --real-calls  # 6 replays (gate-6.3-C)

Gate A: the designer verifies the gpt-6.1-sol and claude-sonnet-5-5 prices (the verified
flag in config/prices.json is designer-owned); --estimate prices Gates B and C from the
token profile of the committed Gate 1 TRAIN matches (same configuration; no test-set read)
plus a worst case from the caps; --probe makes ONE Sol Red proposal (dry run, nothing sent)
and ONE Sonnet Blue call (prompt v2) on a non-test golden line.

Gate B (D33-D36): 3 live matches, Red = gpt-6.1-sol at effort medium (the one treatment
variable), everything else the Gate 3 configuration; Blue = Haiku 5.5, rules on, caching on,
library v5 READ-ONLY; purpose eval (TEST data by purpose). Afterwards the match ids are added
to config/test_set.json, FULL D16 audits are scaffolded (every Red round) and the sheet is
written.

Gate C (D34): each Gate B log replayed twice: Sonnet 5.5 + library v5 (thinking disabled,
same prompt and request), and Haiku 5.5 + the EMPTY library v0000 (isolates the transfer).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import run_match  # noqa: E402
from agents import llm_client as lc  # noqa: E402
from blue import claude_engine  # noqa: E402
from red import ai_red  # noqa: E402
from runner import go_token  # noqa: E402
from stats import cost as cost_stats  # noqa: E402
from tools import audit_match, replay_blue, stage5_7_check, stage6_1_check  # noqa: E402

SEEDS = (6301, 6302, 6303)
RED_MODEL, RED_EFFORT = "gpt-6.1-sol", "medium"
BLUE_LIVE, BLUE_STRONG = "claude-haiku-5-5", "claude-sonnet-5-5"
LIB_DIR = REPO / "data" / "library"
LIB_V5 = LIB_DIR / "rule_library_v0005.json"
LIB_V5_SHA = "324a1eceace9499606284230f4997cb961da39af6ec67ab2a6d7c4e70a168bc7"
EMPTY = LIB_DIR / "rule_library_v0000.json"
TEST_SET = REPO / "config" / "test_set.json"
PROFILE = [REPO / "data" / "golden" / f"train-6.1b-gate1-match{i}" for i in range(1, 6)]
PROBE_LOG = REPO / "data" / "golden" / "scripted-baseline-benign-match" / "proxy.jsonl"
OUTPUT_MULTS = (1, 3)  # Sol at effort medium: reasoning tokens unknown until the probe


def jl(p: Path) -> list[dict]:
    return cost_stats.read_calls(p)


# --------------------------------------------------------------------------
# Gate A: prices and the estimate (zero token)
# --------------------------------------------------------------------------

def price_problems(prices: dict, models=(RED_MODEL, BLUE_STRONG, BLUE_LIVE)) -> list[str]:
    out = []
    for m in models:
        e = cost_stats.entry_for(prices, m)
        if e is None:
            out.append(f"{m}: no price entry")
        elif e.get("verified") is not True:
            out.append(f"{m}: price not designer-verified (config/prices.json)")
    return out


def _reprice(calls: list[dict], model: str, prices: dict, out_mult: float = 1.0) -> float:
    usd = 0.0
    for c in calls:
        if not cost_stats.is_sent(c):
            continue
        c2 = {**c, "model": model, "output_tokens": round((c.get("output_tokens") or 0) * out_mult)}
        usd += cost_stats.call_cost(c2, prices)["usd"]
    return usd


def estimate(prices: dict, cfg: dict, profile: list[Path] = PROFILE) -> dict:
    """Expected cost of Gates B and C from the Gate 1 train-match token profile, repriced,
    plus the worst case the caps allow. Zero tokens."""
    calls = [c for d in profile for c in jl(d / "api_calls.jsonl")]
    red = [c for c in calls if c["agent"] == "red"]
    blue = [c for c in calls if c["agent"] == "blue"]
    n = len(profile)
    per_match = {f"red_sol_x{m}": _reprice(red, RED_MODEL, prices, m) / n for m in OUTPUT_MULTS}
    per_match["blue_haiku"] = _reprice(blue, BLUE_LIVE, prices) / n
    per_match["blue_sonnet"] = _reprice(blue, BLUE_STRONG, prices) / n
    k = len(SEEDS)
    caps = cfg["caps"]
    match_worst = min(caps["red"]["max_usd"] + caps["blue"]["max_usd"],
                      caps["match"]["max_usd"] or float("inf"))
    replay_worst = min(caps["blue"]["max_usd"], caps["match"]["max_usd"] or float("inf"))
    return {
        "profile": [d.name for d in profile], "profile_calls": {"red": len(red) / n,
                                                                "blue": len(blue) / n},
        "per_match": {k_: round(v, 6) for k_, v in per_match.items()},
        "gate_b_expected": {f"x{m}": round(k * (per_match[f"red_sol_x{m}"]
                                                + per_match["blue_haiku"]), 6)
                            for m in OUTPUT_MULTS},
        "gate_c_expected": round(k * (per_match["blue_sonnet"] + per_match["blue_haiku"]), 6),
        "gate_b_worst": round(k * match_worst, 6),
        "gate_c_worst": round(2 * k * replay_worst, 6),
        "unverified": price_problems(prices),
    }


def print_estimate(e: dict) -> None:
    print(f"Stage 6.3 cost estimate (zero token). Token profile: {len(e['profile'])} committed "
          f"Gate 1 train matches (Luna Red / Haiku Blue, rules on, caching on), per match "
          f"{e['profile_calls']['red']:.1f} Red + {e['profile_calls']['blue']:.1f} Blue calls; "
          f"repriced per call (tiers respected).")
    pm = e["per_match"]
    for m in OUTPUT_MULTS:
        print(f"  Red  {RED_MODEL} per match, output tokens x{m}: ${pm[f'red_sol_x{m}']:.6f}")
    print(f"  Blue {BLUE_LIVE} per match / replay: ${pm['blue_haiku']:.6f}")
    print(f"  Blue {BLUE_STRONG} per replay (no library answers assumed): "
          f"${pm['blue_sonnet']:.6f}")
    for m in OUTPUT_MULTS:
        print(f"  Gate B expected (3 matches, Sol output x{m}): ${e['gate_b_expected'][f'x{m}']:.6f}")
    print(f"  Gate C expected (3 Sonnet + 3 Haiku replays): ${e['gate_c_expected']:.6f}")
    print(f"  worst case under the caps: Gate B ${e['gate_b_worst']:.2f}, Gate C "
          f"${e['gate_c_worst']:.2f} (config/llm.json caps; a refused call stops the agent)")
    for p in e["unverified"]:
        print(f"  PRICE NOT VERIFIED: {p}")


def gate_config(base: dict | None = None) -> dict:
    """The D33 Red treatment over the config: Sol at effort medium, caching on (Gate 3)."""
    cfg = base if base is not None else lc.load_config()
    cfg = lc.with_caching(cfg, "red", "on")
    cfg = lc.with_effort(cfg, "red", RED_EFFORT)
    cfg = json.loads(json.dumps(cfg))
    cfg["agents"]["red"]["model"] = RED_MODEL
    return cfg


def probe(out_root: Path | None = None, client_factory=None) -> int:
    """ONE Sol Red proposal (dry run, nothing sent) + ONE Sonnet Blue call (prompt v2)."""
    base_make = client_factory or (lambda cfg: lc.LLMClient(config=cfg))
    errors: list[str] = []  # the client's key-redacted error text, never written to disk

    class _Seen:
        def __init__(self, client):
            self._c = client

        def __getattr__(self, name):
            return getattr(self._c, name)

        def complete(self, *a, **kw):
            r = self._c.complete(*a, **kw)
            if not r.ok and r.error:
                errors.append(f"{a[0] if a else kw.get('agent')}: {r.error}")
            return r

    def make(cfg):
        return _Seen(base_make(cfg))
    mid = run_match.new_match_id()
    root = out_root or REPO / "data" / "runs" / f"probe-6.3-{mid}"
    red_dir, blue_dir = root / "red", root / "blue"
    red_dir.mkdir(parents=True)
    blue_dir.mkdir(parents=True)
    cfg = gate_config()
    red = ai_red.AIRed(make(cfg), RED_MODEL, red_dir, mid, round_cap=1)
    p = red.propose(None, 1)
    bcfg = lc.with_caching(lc.load_config(), "blue", "on")
    _, system, _, schema = claude_engine.PROMPTS["on"]
    line = claude_engine.read_judged_lines(PROBE_LOG)[0]
    make(bcfg).complete("blue", BLUE_STRONG, system, claude_engine.build_messages([line], system),
                        run_dir=blue_dir, log_seq_first=1, log_seq_last=1, match_id=mid,
                        output_schema=schema)
    ok = True
    for agent, d in (("red", red_dir), ("blue", blue_dir)):
        for c in jl(d / lc.API_CALLS):
            print(f"  {agent} {c['model']} ok={c['ok']} stop={c.get('stop_reason')} in "
                  f"{c.get('input_tokens')} cached {c.get('cached_input_tokens')} write "
                  f"{c.get('cache_write_tokens')} out {c.get('output_tokens')} "
                  f"(max_output_tokens {lc.agent_max_output_tokens(cfg if agent == 'red' else bcfg, agent)})")
            ok &= c["ok"] is True and c.get("stop_reason") not in ("max_tokens", "max_output_tokens",
                                                                     "incomplete")
    print(f"  Red proposal: {p.kind}{'' if p.kind != 'instrument_failure' else ' ' + str(p.reason)}")
    for e in errors:  # already redacted by llm_client (keys never reach here)
        print(f"  error {e}")
    print(f"RESULT: {'PASS' if ok else 'CHECK'} -> {root.relative_to(REPO) if root.is_relative_to(REPO) else root}")
    return 0 if ok else 1


# --------------------------------------------------------------------------
# Gate B: 3 live eval matches
# --------------------------------------------------------------------------

def register_test_ids(ids: list[str], path: Path = TEST_SET) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    for i in ids:
        if i not in doc["match_ids"]:
            doc["match_ids"].append(i)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def library_ok(path: Path = LIB_V5) -> list[str]:
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return [] if actual == LIB_V5_SHA else [f"{path}: sha256 {actual} != recorded v5 {LIB_V5_SHA}"]


def gate_b(prices: dict, sheet_dir: Path | None = None, audits: Path | None = None,
           test_set: Path = TEST_SET, library: Path = LIB_V5, **run_kw) -> int:
    """run_kw (tests only): ops / live_dir / runs_dir for run_match.run_match."""
    dirs, ok = [], True
    for i, seed in enumerate(SEEDS, start=1):
        print(f"\n##### eval match {i}/{len(SEEDS)} (seed {seed}, Red {RED_MODEL} effort "
              f"{RED_EFFORT}, Blue {BLUE_LIVE} rules on, library v5 read-only)")
        code, d = run_match.run_match(seed=seed, red_engine="ai", red_model=RED_MODEL,
                                      red_effort=RED_EFFORT, red_caching="on", engine="claude",
                                      blue_model=BLUE_LIVE, blue_rules_mode="on",
                                      blue_caching="on", purpose="eval", library=library,
                                      **run_kw)
        if d is None:
            print(f"  REFUSED at preflight (exit {code})")
            ok = False
            continue
        ok &= code in (0, 4)
        dirs.append(d)
    ids = [json.loads((d / "match.json").read_text())["match_id"] for d in dirs]
    if ids:
        register_test_ids(ids, test_set)
        print(f"\n=== registered as TEST data in {test_set.name}: {ids}")
    for d in dirs:
        stage5_7_check.gate3_report(d, prices)
    print("\n=== D16 audits: FULL (every Red round; eval matches are scored, D36)")
    for d in dirs:
        try:
            print(f"  scaffolded {audit_match._rel(audit_match.scaffold(d, audits=audits))}")
        except audit_match.AuditError as exc:
            print(f"  {d.name}: {exc}")
    if dirs:
        sheet = (sheet_dir or REPO / "docs" / "audits") / f"stage6_3_gateB_{dirs[0].name}.md"
        sheet.write_text(audit_match.sheet(dirs, audits=audits), encoding="utf-8")
        print(f"  sheet {audit_match._rel(sheet)}")
    total = sum(json.loads((d / "match.json").read_text())["cost"]["total_usd"] for d in dirs)
    good = ok and len(dirs) == len(SEEDS)
    print(f"\nRESULT: {'PASS' if good else 'FAIL'} ({len(dirs)}/{len(SEEDS)} eval matches, "
          f"${total:.6f}). Next: the designer's full audit, then Gate C.")
    return 0 if good else 1


# --------------------------------------------------------------------------
# Gate C: replays of the Gate B logs
# --------------------------------------------------------------------------

ARMS_C = (("sonnet-v5", BLUE_STRONG, "v5"), ("haiku-empty", BLUE_LIVE, "empty"))


def check_sources(match_dirs: list[Path]) -> list[str]:
    out = []
    for d in match_dirs:
        p = Path(d) / "match.json"
        if not p.is_file():
            out.append(f"{d}: not a frozen match")
            continue
        m = json.loads(p.read_text())
        if m.get("purpose") != "eval" or m.get("status") != "completed":
            out.append(f"{d}: purpose {m.get('purpose')!r} status {m.get('status')!r} "
                       f"(Gate C replays completed eval matches only)")
        elif (m["models"]["red"] or {}).get("model") != RED_MODEL:
            out.append(f"{d}: Red model {(m['models']['red'] or {}).get('model')!r}, not {RED_MODEL}")
    return out


def gate_c(prices: dict, match_dirs: list[Path], root: Path | None = None, ops=None,
           library: Path = LIB_V5) -> int:
    gid = run_match.new_match_id()
    root = root or replay_blue.REPLAYS / f"gate-6.3-C-{gid}"
    rows, ok = [], True
    for d in match_dirs:
        for arm, model, lib in ARMS_C:
            code, rdir = replay_blue.replay(Path(d), root / f"{Path(d).name}-{arm}",
                                            engine="claude", model=model, rules_mode="on",
                                            caching="on",
                                            library=library if lib == "v5" else EMPTY,
                                            out_fn=lambda *_: None, ops=ops)
            if rdir is None:
                print(f"=== {Path(d).name} {arm}: REFUSED (exit {code})")
                ok = False
                continue
            ok &= code in (0, 4)
            r = stage6_1_check.replay_report(rdir, prices)
            rows.append({"source": Path(d).name, "arm": arm, **r})
            fmt = lambda b, k: f"{b[k]['num']}/{b[k]['den']}" if b else "—"  # noqa: E731
            print(f"=== {Path(d).name:28} {arm:12} calls {r['calls']:3}  ${r['usd']:.6f}  "
                  f"lines: library {r['library_lines']} match {r['match_lines']} ai "
                  f"{r['ai_lines']} / {r['lines']}  detection raw {fmt(r['raw'], 'detection')}"
                  f"  audited {fmt(r['audited'], 'detection')}  FP {fmt(r['raw'], 'fp')}")
    want = len(match_dirs) * len(ARMS_C)
    print(f"RESULT: {'PASS' if ok and len(rows) == want else 'FAIL'} ({len(rows)}/{want} "
          f"replays) -> {replay_blue._rel(root)}. Tables: tools/autonomy_table.py over the "
          f"Gate B matches and these replays.")
    return 0 if ok and len(rows) == want else 1


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--gate", choices=("A", "B", "C"), required=True)
    ap.add_argument("--estimate", action="store_true", help="Gate A: zero-token cost estimate")
    ap.add_argument("--probe", action="store_true", help="Gate A: 2 real calls (token gate-6.3-A)")
    ap.add_argument("--matches", type=Path, nargs="+", default=None, help="Gate C: Gate B folders")
    ap.add_argument("--real-calls", action="store_true",
                    help="actually run (REAL, PAID calls; designer GO only)")
    args = ap.parse_args(argv)
    prices = cost_stats.load_prices()
    if args.gate == "A" and args.estimate:
        print_estimate(estimate(prices, lc.load_config()))
        return 0
    if args.gate == "A" and not args.probe:
        print("REFUSED: Gate A is --estimate (zero token) or --probe --real-calls")
        return 2
    if args.gate == "C" and not args.matches:
        print("REFUSED: Gate C needs --matches <the 3 Gate B match folders>")
        return 2
    plan = {"A": f"probe: 1 {RED_MODEL} Red proposal (dry run) + 1 {BLUE_STRONG} Blue call",
            "B": f"{len(SEEDS)} eval matches, Red {RED_MODEL} effort {RED_EFFORT} vs Blue "
                 f"{BLUE_LIVE} + library v5 (read-only), seeds {SEEDS}",
            "C": f"{2 * len(args.matches or [])} replays: {BLUE_STRONG} + v5, {BLUE_LIVE} + v0000"}
    print(f"Stage 6.3 Gate {args.gate}: {plan[args.gate]}")
    if not args.real_calls:
        print("REFUSED: pass --real-calls (designer GO only). Nothing was called.")
        return 2
    refusal = go_token.check(f"gate-6.3-{args.gate}")
    if refusal:
        print(refusal)
        return 2
    problems = price_problems(prices, (RED_MODEL, BLUE_STRONG) if args.gate == "A" else
                              (RED_MODEL, BLUE_LIVE) if args.gate == "B" else
                              (BLUE_STRONG, BLUE_LIVE))
    if args.gate in ("B", "C"):
        problems += library_ok()
    if args.gate == "C":
        problems += check_sources(args.matches)
    if problems:
        print(f"REFUSED: {problems}")
        return 2
    if run_match.Ops().git_info()["dirty"]:
        print("REFUSED: the git tree is dirty; commit first.")
        return 2
    if args.gate == "A":
        return probe()
    return gate_b(prices) if args.gate == "B" else gate_c(prices, args.matches)


if __name__ == "__main__":
    raise SystemExit(main())
