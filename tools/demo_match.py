"""Stage 7 #18: the demo's three matchups (D61) as code, so scripts/demo.sh never retypes them.

  1 taxonomy  ARENA_GO=… .venv/bin/python -u tools/demo_match.py --matchup taxonomy [--red luna]
  2 freeplay  ARENA_GO=… .venv/bin/python -u tools/demo_match.py [--red luna]
  3 open      ARENA_GO=… .venv/bin/python -u tools/demo_match.py --open-replay
  probe       ARENA_GO=… .venv/bin/python -u tools/demo_match.py [--matchup …] [--red …] --one-turn
  config      .venv/bin/python tools/demo_match.py --print-config [--matchup …] [--red …]   (zero cost)

1 and 2 run one live match each, against original Blue (D44 default). 3 runs no match: open
Blue (prompt v3-open, as in the gate-6.3-C-open replays, D42) re-judges the frozen log of the
LATEST completed free-play demo match (a replay, D44, D17). All are purpose dev: never
evidence (D45). --one-turn: ONE Red proposal on the matchup's config, dry run (nothing sent,
no Docker, no Blue); prints accepted / refused and the redacted reply diagnosis.

ARENA_GO always comes from the caller; this tool never sets or defaults it and refuses a
paid mode without a well-formed token (the single exit, agents/llm_client.py, checks it
again)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from agents import llm_client  # noqa: E402
from red import ai_red, red_guard  # noqa: E402
from runner import go_token  # noqa: E402
from stats import test_data  # noqa: E402
import run_match  # noqa: E402

LIB_V5 = REPO / "data" / "library" / "rule_library_v0005.json"
RUNS = REPO / "data" / "runs"
BLUE = "claude-haiku-5-5"
# Final (#14, closed 2026-11-26): the peak-window run's slowest Red call was 57.0 s for
# 5,236 output tokens (off-peak max 22.0 s), 0 timeouts in 20 calls. Retries: default.
DEMO_RED_TIMEOUT_S = 120.0
MATCHUPS = ("taxonomy", "freeplay")
# Blue = the D44 default (original Blue): rules on, caching on, library v5 read-only.
COMMON = {"red_engine": "ai", "red_caching": "on", "engine": "claude", "blue_model": BLUE,
          "blue_rules_mode": "on", "blue_caching": "on", "purpose": "dev"}
FREEPLAY_CAPS = {"red": {"max_usd": 0.40}, "match": {"max_usd": 0.40}}
REDS = {
    # 1 taxonomy: Gate B-deepseek (prompt v1, 8192 tokens, config caps).
    ("taxonomy", "deepseek"): {"red_model": "deepseek-v4-pro", "red_provider": "deepseek",
                               "red_effort": "max", "red_prompt_version": "1",
                               "red_max_output_tokens": 8192, "caps": None},
    # backup: Gate B exactly (D38: Luna, effort high, 8192 tokens, prompt v1).
    ("taxonomy", "luna"): {"red_model": "gpt-6-luna", "red_provider": "openai",
                           "red_effort": "high", "red_prompt_version": "1",
                           "red_max_output_tokens": 8192, "caps": None},
    # 2 free-play: D46 = Gate B-freeplay (prompt v3, 16384 tokens, caps $0.40).
    ("freeplay", "deepseek"): {"red_model": "deepseek-v4-pro", "red_provider": "deepseek",
                               "red_effort": "max", "red_prompt_version": "3",
                               "red_max_output_tokens": 16384, "caps": FREEPLAY_CAPS},
    # backup: D38 strength with free-play prompt v3 (accepted by Luna in the #18 one-turn
    # check, 2026-11-25; else prompt "1").
    ("freeplay", "luna"): {"red_model": "gpt-6-luna", "red_provider": "openai",
                           "red_effort": "high", "red_prompt_version": "3",
                           "red_max_output_tokens": 8192, "caps": FREEPLAY_CAPS},
}
# 3 open: the gate-6.3-C-open replay settings (tools/stage6_3_check.gate_c_open).
OPEN_REPLAY = {"engine": "claude", "model": BLUE, "rules_mode": "on", "caching": "on",
               "blue_prompt": "open"}


def demo_kwargs(red: str = "deepseek", red_timeout_s: float = DEMO_RED_TIMEOUT_S,
                seed: int | None = None, matchup: str = "freeplay") -> dict:
    return {**COMMON, **REDS[(matchup, red)], "red_timeout_s": red_timeout_s, "seed": seed,
            "library": LIB_V5}


def red_config(kw: dict) -> dict:
    """The llm config the match would build for Red (same with_* steps as run_match)."""
    cfg = llm_client.load_config()
    cfg = llm_client.with_caching(cfg, "red", kw["red_caching"])
    cfg = llm_client.with_effort(cfg, "red", kw["red_effort"])
    cfg = llm_client.with_max_output_tokens(cfg, "red", kw["red_max_output_tokens"])
    cfg = llm_client.with_provider(cfg, "red", kw["red_provider"])
    cfg = llm_client.with_timeout(cfg, "red", kw["red_timeout_s"])
    return llm_client.with_caps(cfg, kw["caps"])


# ---- matchup 3: the source --------------------------------------------------------------

def is_demo_match(m: dict, prompt_version: str) -> bool:
    """A completed dev match with a demo matchup's configuration (any demo Red)."""
    rp = m.get("red_params") or {}
    bp = m.get("blue_params") or {}
    red = ((m.get("models") or {}).get("red") or {}).get("model")
    blue = ((m.get("models") or {}).get("blue") or {}).get("model")
    return (m.get("status") == "completed" and m.get("purpose") == "dev"
            and m.get("red_engine") == "ai" and rp.get("prompt_version") == prompt_version
            and red in {k["red_model"] for k in REDS.values()}
            and m.get("blue_engine") == "claude" and blue == BLUE
            and (bp.get("rules") or {}).get("mode") == "on")


def latest_freeplay(runs: Path = RUNS) -> Path | None:
    """The latest completed free-play demo match under `runs`. Folders are classified by
    their manifest first (D59); test data and unknown folders are never opened further."""
    cands = [p for p in sorted(Path(runs).iterdir()) if (p / "match.json").is_file()]
    best = None
    for d in test_data.scannable(cands).folders:
        try:
            m = json.loads((d / "match.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if is_demo_match(m, "3") and (best is None or m["started_at"] > best[0]):
            best = (m["started_at"], d)
    return best[1] if best else None


def open_replay(runs: Path = RUNS, out_fn=print, **replay_kw) -> int:
    from tools import replay_blue
    src = latest_freeplay(runs)
    if src is None:
        out_fn("REFUSED: no completed free-play demo match yet: run matchup 2 first "
               "(scripts/demo.sh)")
        return 2
    out_fn(f"matchup 3: open Blue re-judges free-play match {src.name} (same traffic)")
    code, _ = replay_blue.replay(src, out_fn=out_fn, library=LIB_V5,
                                 **{**OPEN_REPLAY, **replay_kw})
    return code


# ---- the one-turn probe -----------------------------------------------------------------

def one_turn(kw: dict, client_factory=None, out_root: Path | None = None, out=print) -> int:
    """One Red proposal, dry run. 0 = accepted (a request was proposed; the guard verdict
    is printed too), 1 = not accepted (refusal / unusable reply / call failed)."""
    from stats import cost as cost_stats
    cfg = red_config(kw)
    prices = cost_stats.load_prices()
    make = client_factory or (lambda c: llm_client.LLMClient(config=c, prices=prices))
    mid = run_match.new_match_id()
    d = out_root or RUNS / f"demo-check-{mid}"
    d.mkdir(parents=True, exist_ok=False)
    red = ai_red.AIRed(make(cfg), kw["red_model"], d, mid, round_cap=1,
                       prompt_version=kw["red_prompt_version"])
    p = red.propose(None, 1)
    out(f"one turn: Red {kw['red_model']} effort {kw['red_effort']} prompt v"
        f"{kw['red_prompt_version']} timeout {kw['red_timeout_s']:g} s -> {d}")
    if p.kind == "attack":
        a = p.attack
        g = red_guard.check(a["method"], a["path"], a["body"], a["label"],
                            free_play=red.free_play, headers=a.get("headers"))
        out(f"ACCEPTED: proposed {a['method']} {ai_red.redact(a['path'])[:120]!r} "
            f"label {a['label']} technique {a.get('technique')!r}; guard "
            f"{'allow' if g.ok else 'block ' + str(g.reason)} (nothing sent)")
        rc = 0
    elif p.kind == "brain_failure":
        out(f"NOT ACCEPTED: brain_failure {p.reason}"
            + (" (the model refused)" if p.reason == "refusal" else ""))
        out(f"red diagnosis: round 1 {p.reason}: {p.diagnosis}")
        rc = 1
    else:
        out(f"NOT ACCEPTED: instrument_failure {p.reason} {p.detail}")
        rc = 1
    for c in _jl(d / llm_client.API_CALLS):
        out(f"  call ok={c['ok']} stop={c.get('stop_reason')} attempts={c.get('attempt')} "
            f"latency={c.get('latency_ms')} ms output_tokens={c.get('output_tokens')}")
    return rc


def _jl(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--matchup", choices=MATCHUPS, default="freeplay",
                    help="1 taxonomy or 2 freeplay (live matches); 3 is --open-replay")
    ap.add_argument("--red", choices=("deepseek", "luna"), default="deepseek")
    ap.add_argument("--red-timeout-s", type=float, default=DEMO_RED_TIMEOUT_S)
    ap.add_argument("--seed", type=int, default=None, help="default: a new seed")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--open-replay", action="store_true",
                      help="matchup 3: open Blue re-judges the latest free-play demo match")
    mode.add_argument("--one-turn", action="store_true",
                      help="one Red proposal, dry run (paid: one call)")
    mode.add_argument("--print-config", action="store_true", help="print the config (zero cost)")
    args = ap.parse_args(argv)
    kw = demo_kwargs(args.red, args.red_timeout_s, args.seed, args.matchup)
    if args.print_config:
        print(json.dumps({k: (str(v) if isinstance(v, Path) else v) for k, v in kw.items()},
                         indent=1, sort_keys=True))
        return 0
    if not go_token.valid(os.environ.get(go_token.ENV)):
        print(f"REFUSED: a paid mode needs {go_token.ENV}=<the designer's token> on this "
              f"command (never set by this tool)", file=sys.stderr)
        return 2
    if args.open_replay:
        return open_replay()
    if args.one_turn:
        return one_turn(kw)
    code, _ = run_match.run_match(**kw)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
