"""Stage 7 #18: the live demo match (D46) as code, so scripts/demo.sh never retypes it.

  ARENA_GO=manual-<what> .venv/bin/python -u tools/demo_match.py [--red deepseek|luna]
  ARENA_GO=manual-<what> .venv/bin/python -u tools/demo_match.py --red luna --one-turn
  .venv/bin/python tools/demo_match.py --print-config [--red luna]       (zero cost)

Default: one full match, D46 config, purpose dev (never evidence, D45), new seed.
--one-turn: ONE Red proposal on the demo config, dry run (nothing sent, no Docker, no
Blue); prints accepted / refused and the redacted reply diagnosis. Its ledger goes to
data/runs/demo-check-<id>/.

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
import run_match  # noqa: E402

LIB_V5 = REPO / "data" / "library" / "rule_library_v0005.json"
# Provisional until the #18 peak-window run (#14, designer 2026-11-24); retries default.
DEMO_RED_TIMEOUT_S = 120.0
# D46: Blue = the D44 default; caps as in the free-play arm.
COMMON = {"red_engine": "ai", "red_caching": "on", "engine": "claude",
          "blue_model": "claude-haiku-5-5", "blue_rules_mode": "on", "blue_caching": "on",
          "caps": {"red": {"max_usd": 0.40}, "match": {"max_usd": 0.40}}, "purpose": "dev"}
REDS = {
    # D46 primary: the Gate B-freeplay Red (D41).
    "deepseek": {"red_model": "deepseek-v4-pro", "red_provider": "deepseek",
                 "red_effort": "max", "red_prompt_version": "3",
                 "red_max_output_tokens": 16384},
    # D46 backup: the Gate B Red strength (D38: Luna, effort high, 8192 tokens), free-play
    # prompt v3: accepted by Luna in the #18 one-turn check, 2026-11-25 (else prompt "1").
    "luna": {"red_model": "gpt-6-luna", "red_provider": "openai", "red_effort": "high",
             "red_prompt_version": "3", "red_max_output_tokens": 8192},
}


def demo_kwargs(red: str = "deepseek", red_timeout_s: float = DEMO_RED_TIMEOUT_S,
                seed: int | None = None) -> dict:
    return {**COMMON, **REDS[red], "red_timeout_s": red_timeout_s, "seed": seed,
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


def one_turn(kw: dict, client_factory=None, out_root: Path | None = None, out=print) -> int:
    """One Red proposal, dry run. 0 = accepted (a request was proposed; the guard verdict
    is printed too), 1 = not accepted (refusal / unusable reply / call failed)."""
    from stats import cost as cost_stats
    cfg = red_config(kw)
    prices = cost_stats.load_prices()
    make = client_factory or (lambda c: llm_client.LLMClient(config=c, prices=prices))
    mid = run_match.new_match_id()
    d = out_root or REPO / "data" / "runs" / f"demo-check-{mid}"
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
    ap.add_argument("--red", choices=sorted(REDS), default="deepseek")
    ap.add_argument("--red-timeout-s", type=float, default=DEMO_RED_TIMEOUT_S)
    ap.add_argument("--seed", type=int, default=None, help="default: a new seed")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--one-turn", action="store_true",
                      help="one Red proposal, dry run (paid: one call)")
    mode.add_argument("--print-config", action="store_true", help="print the config (zero cost)")
    args = ap.parse_args(argv)
    kw = demo_kwargs(args.red, args.red_timeout_s, args.seed)
    if args.print_config:
        print(json.dumps({k: (str(v) if isinstance(v, Path) else v) for k, v in kw.items()},
                         indent=1, sort_keys=True))
        return 0
    if not go_token.valid(os.environ.get(go_token.ENV)):
        print(f"REFUSED: a paid mode needs {go_token.ENV}=<the designer's token> on this "
              f"command (never set by this tool)", file=sys.stderr)
        return 2
    if args.one_turn:
        return one_turn(kw)
    code, _ = run_match.run_match(**kw)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
