"""Stage 5.7 Gate 1: verify the CACHED-token usage mapping (REAL, PAID calls; GO only).

    .venv/bin/python tools/stage5_7_gate1.py                # prints the plan, calls nothing
    .venv/bin/python tools/stage5_7_gate1.py --real-calls   # runs it

Blue (Anthropic, config/llm.json agents.blue, caching ON, 5-minute TTL):
  1. prompt v2 (rules shadow/on), golden line 1   -> expect a cache WRITE of the prefix
  2. prompt v2, golden line 2 (same prefix)       -> expect a cache READ of that prefix
  3. prompt v1 (rules off), golden line 3         -> does v1 reach the 512-token minimum?
     (C1: v1 is never padded; the result is recorded either way)
Red (OpenAI, agents.red, caching ON, 30-minute TTL): a DRY-RUN generation of N turns
through ai_red.AIRed. NOTHING is sent to the Target: each turn's feedback is a fixed,
honest dry-run text. Expected: no cache below OpenAI's 1,024-token minimum per
prefix, then cache reads growing turn by turn.

Prints, per call: the provider's raw usage object, the api_calls.jsonl line, its cost
(and the per-turn cached tokens for Red), for the designer's dashboard comparison.
Output: data/replays/gate1-5.7-<id>/{blue,red}/api_calls.jsonl (git-ignored). Refuses
without --real-calls and on a dirty git tree. One attempt per call (no retries), so
every dashboard row maps to one printed line.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import run_match  # noqa: E402
from agents import llm_client as lc  # noqa: E402
from blue import claude_engine  # noqa: E402
from red import ai_red  # noqa: E402
from stats import cost as cost_stats  # noqa: E402

GOLDEN_LOG = REPO / "data" / "golden" / "scripted-baseline-benign-match" / "proxy.jsonl"
OUT_ROOT = REPO / "data" / "replays"
DEFAULT_RED_TURNS = 5  # designer decision C2; --red-turns 10 shows growing reads (see D18 notes)
DRY_RUN_FEEDBACK = ("Dry run: your request was not sent, so there is no HTTP response. "
                    "Propose your next request.")


class Recorder:
    """Wraps LLMClient.complete and keeps every Result (raw usage is Gate 1 evidence;
    it is never written to an artifact)."""

    def __init__(self, client: lc.LLMClient):
        self.client = client
        self.results: list[lc.Result] = []

    def complete(self, *a, **kw) -> lc.Result:
        r = self.client.complete(*a, **kw)
        self.results.append(r)
        return r


def gate_config() -> dict:
    cfg = copy.deepcopy(lc.load_config())
    cfg["max_retries"] = 0
    cfg = lc.with_caching(cfg, "blue", "on")
    return lc.with_caching(cfg, "red", "on")


def show(calls: list[dict], results: list[lc.Result], prices: dict, label) -> None:
    for i, (c, r) in enumerate(zip(calls, results), 1):
        cc = cost_stats.call_cost(c, prices)
        print(f"\n[{label(i)}]")
        print(f"  raw usage        {json.dumps(r.raw_usage, sort_keys=True)}")
        print(f"  api_calls line   {json.dumps(c, sort_keys=True)}")
        print(f"  mapped           input {c['input_tokens']}  cached {c['cached_input_tokens']}"
              f"  write {c['cache_write_tokens']}  unpriced_write "
              f"{c['unpriced_cache_write_tokens']}  output {c['output_tokens']}  "
              f"stop {c['stop_reason']}")
        print(f"  cost             ${cc['usd']:.6f}  net cache savings ${cc['savings_usd']:+.6f}"
              f"{'  UNPRICED' if cc['unpriced_usage'] else ''}")


def run_blue(cfg: dict, out: Path, match_id: str) -> int:
    out.mkdir(parents=True)
    rec = Recorder(lc.LLMClient(config=cfg))
    model = cfg["agents"]["blue"]["model"]
    lines = claude_engine.read_judged_lines(GOLDEN_LOG)[:3]
    plan = [("on", 1), ("on", 2), ("off", 3)]  # (rules mode -> prompt), log_seq
    for mode, seq in plan:
        _, system, _, schema = claude_engine.PROMPTS[mode]
        rec.complete("blue", model, system, claude_engine.build_messages([lines[seq - 1]],
                                                                        system),
                     run_dir=out, log_seq_first=seq, log_seq_last=seq, match_id=match_id,
                     output_schema=schema)
    calls = cost_stats.read_calls(out / lc.API_CALLS)
    names = {1: "Blue call 1: prompt v2, line 1 (expect write)",
             2: "Blue call 2: prompt v2, line 2 (expect read)",
             3: "Blue call 3: prompt v1, line 3 (does v1 cache at all?)"}
    show(calls, rec.results, rec.client.prices, names.get)
    v1 = calls[2] if len(calls) > 2 else None
    if v1 is not None:
        cached = v1["cached_input_tokens"] + v1["cache_write_tokens"]
        print(f"\n  C1 (prompt v1): {'caches' if cached else 'NOT cached'} "
              f"(write {v1['cache_write_tokens']}, read {v1['cached_input_tokens']}; total "
              f"prompt {v1['input_tokens'] + cached} tokens)")
    print(f"\n  Blue: {cost_stats.format_cost_line(cost_stats.summarize(calls, rec.client.prices))}")
    return 0 if len(calls) == 3 and all(c["ok"] for c in calls) else 1


def run_red(cfg: dict, out: Path, match_id: str, turns: int) -> int:
    out.mkdir(parents=True)
    rec = Recorder(lc.LLMClient(config=cfg))
    model = cfg["agents"]["red"]["model"]
    red = ai_red.AIRed(rec, model, out, match_id, round_cap=turns)
    feedback = None
    for turn in range(1, turns + 1):
        p = red.propose(feedback, turn)
        feedback = DRY_RUN_FEEDBACK  # nothing was sent: no real response exists
        if p.kind == "instrument_failure":
            print(f"\n  turn {turn}: instrument failure {p.reason} {p.detail}")
            break
    calls = cost_stats.read_calls(out / lc.API_CALLS)
    show(calls, rec.results, rec.client.prices, lambda i: f"Red turn {i} (dry run)")
    print("\n  Red per-turn cache (prompt = input + cached + write):")
    print(f"  {'turn':>4} {'prompt':>7} {'cached':>7} {'write':>6} {'uncached':>8}")
    for i, c in enumerate(calls, 1):
        if c["ok"]:
            total = c["input_tokens"] + c["cached_input_tokens"] + c["cache_write_tokens"]
            print(f"  {i:>4} {total:>7} {c['cached_input_tokens']:>7} "
                  f"{c['cache_write_tokens']:>6} {c['input_tokens']:>8}")
    reads = [c["cached_input_tokens"] for c in calls if c["ok"]]
    growing = [r for r in reads if r > 0]
    print(f"  reads growing turn by turn: "
          f"{'YES' if len(growing) >= 2 and growing == sorted(growing) else 'NO'} "
          f"(non-zero reads on {len(growing)} turn(s))")
    print(f"\n  Red: {cost_stats.format_cost_line(cost_stats.summarize(calls, rec.client.prices))}")
    return 0 if calls and all(c["ok"] for c in calls) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--real-calls", action="store_true",
                    help="actually make the calls (REAL, PAID; designer GO only)")
    ap.add_argument("--red-turns", type=int, default=DEFAULT_RED_TURNS,
                    help=f"Red dry-run turns (default {DEFAULT_RED_TURNS})")
    ap.add_argument("--only", choices=("blue", "red"), default=None)
    args = ap.parse_args(argv)
    print(f"Stage 5.7 Gate 1: Blue 3 calls (v2, v2, v1; caching on) + Red dry run "
          f"{args.red_turns} turns (caching on, nothing sent)")
    if not args.real_calls:
        print("REFUSED: pass --real-calls (designer GO only). Nothing was called.")
        return 2
    if run_match.Ops().git_info()["dirty"]:
        print("REFUSED: the git tree is dirty; commit first.")
        return 2
    cfg = gate_config()
    match_id = run_match.new_match_id()
    root = OUT_ROOT / f"gate1-5.7-{match_id}"
    print(f"output {root.relative_to(REPO)}  blue caching {lc.caching_params(cfg, 'blue')}  "
          f"red caching {lc.caching_params(cfg, 'red')}")
    code = 0
    if args.only in (None, "blue"):
        print("\n=== Blue")
        code |= run_blue(cfg, root / "blue", match_id)
    if args.only in (None, "red"):
        print("\n=== Red (dry run: NOTHING is sent to the Target)")
        code |= run_red(cfg, root / "red", match_id, args.red_turns)
    print(f"\nRESULT: {'all calls answered' if code == 0 else 'SOME CALLS FAILED'} -> "
          f"{root.relative_to(REPO)}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
