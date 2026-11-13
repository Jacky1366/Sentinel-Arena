"""Stage 5.6 Gate 1: ONE AI Red generation, with NO request sent (dry run).

    .venv/bin/python tools/stage5_6_smoke.py --real-call   # only after the designer's GO

Exactly one OpenAI call (max_retries 0 for this tool), through agents/llm_client.py
with the committed config/llm.json and config/prices.json. Needs ARENA_OPENAI_API_KEY.
No Docker, no HTTP to the Target: the proposed attack is printed and guarded, never
sent. Prints the provider's raw usage, the api_calls.jsonl line, the cost, and the
proposed attack (with the guard verdict), for comparison with the OpenAI dashboard.

Writes into a NEW scratch folder data/runs/<match_id>/ (git-ignored; not a match:
no match.json, no proxy traffic): api_calls.jsonl only. Exits 0 iff a reply came back
and parsed into a proposal.
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
from red import ai_red, red_guard  # noqa: E402
from stats import cost as cost_stats  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--real-call", action="store_true",
                    help="required: confirms this makes one real, paid OpenAI call")
    args = ap.parse_args(argv)
    if not args.real_call:
        print("refusing: pass --real-call (one real, paid OpenAI call; Gate 1 needs the "
              "designer's GO). Nothing is sent to the Target.")
        return 2

    cfg = copy.deepcopy(lc.load_config())
    cfg["max_retries"] = 0
    model = args.__dict__.get("model") or cfg["agents"]["red"]["model"]
    if not model:
        raise SystemExit("no Red model: set agents.red.model in config/llm.json")
    match_id = run_match.new_match_id()
    out = REPO / "data" / "runs" / match_id
    out.mkdir(parents=True, exist_ok=False)
    print(f"scratch folder {out.relative_to(REPO)} (dry run: NOTHING is sent to the Target)")
    print(f"model {model}  request {lc.agent_request(cfg, 'red')}  "
          f"max_output_tokens {lc.agent_max_output_tokens(cfg, 'red')}  "
          f"prompt v{ai_red.RED_PROMPT_VERSION} sha256 {ai_red.SYSTEM_PROMPT_SHA256[:12]}")

    client = lc.LLMClient(config=cfg)
    red = ai_red.AIRed(client, model, out, match_id, round_cap=1)
    proposal = red.propose(None, 1)

    calls = cost_stats.read_calls(out / lc.API_CALLS)
    print("\napi_calls.jsonl:")
    for c in calls:
        print("  " + json.dumps(c, sort_keys=True))
    if proposal.kind == "instrument_failure":
        print(f"\nNO REPLY: {proposal.reason} ({proposal.detail})")
        return 1
    reply = calls[-1] if calls else {}
    print(f"\nstop reason (from api_calls): n/a; cost:")
    summary = cost_stats.summarize(calls, client.prices)
    print(f"  {cost_stats.format_cost_line(summary)}")
    if calls:
        last = calls[-1]
        print(f"  tokens input={last['input_tokens']} cached={last['cached_input_tokens']} "
              f"cache_write={last['cache_write_tokens']} output={last['output_tokens']} "
              f"stop_reason={last['stop_reason']}")

    if proposal.kind == "brain_failure":
        print(f"\nbrain failure: {proposal.reason} (no usable request)")
        return 0
    a = proposal.attack
    g = red_guard.check(a["method"], a["path"], a["body"], a["label"])
    print(f"\nproposed attack (NOT sent):")
    print(f"  method   {a['method']}")
    print(f"  path     {a['path']}")
    print(f"  body     {a['body']}")
    print(f"  label    {a['label']}")
    print(f"  rationale {a['rationale']}")
    print(f"  guard    {'ALLOW' if g.ok else f'BLOCK ({g.reason}: {g.detail})'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
