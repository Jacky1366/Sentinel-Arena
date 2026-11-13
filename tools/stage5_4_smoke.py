"""Stage 5.4 Gate 1: ONE real AI Blue call on ONE golden proxy line.

    .venv/bin/python tools/stage5_4_smoke.py --real-call        # only after the designer's GO

Exactly one Anthropic call (max_retries 0 for this tool, so a failure is not
retried), through agents/llm_client.py with the committed config/llm.json and
config/prices.json. Needs ARENA_ANTHROPIC_API_KEY (environment or .env). No Docker.

Writes into a NEW scratch folder data/runs/<match_id>/ (git-ignored; never a match
folder: no match.json, no traffic): proxy.jsonl (the one line), api_calls.jsonl,
verdicts.jsonl. Prints:

  - the provider's raw usage object (to verify the usage mapping, contract §6.3)
  - the api_calls.jsonl line, the stop reason, and the cost from stats/cost.py
  - the validated verdict row (or no_verdict with its failure_detail)

Exits 0 only if the call was sent and a reply came back (any verdict, or a
no_verdict, is a result to report; a refusal by the body or an API failure is not).
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
from blue import claude_engine as ce  # noqa: E402
from blue import run_blue  # noqa: E402
from stats import cost as cost_stats  # noqa: E402

GOLDEN = REPO / "data" / "golden" / "scripted-baseline-benign-match" / "proxy.jsonl"


def pick_line(path: Path, log_seq: int) -> dict:
    lines = ce.read_judged_lines(path)
    if not 1 <= log_seq <= len(lines):
        raise SystemExit(f"--log-seq must be 1..{len(lines)}")
    return lines[log_seq - 1]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--real-call", action="store_true",
                    help="required: confirms this makes one real, paid API call")
    ap.add_argument("--log-seq", type=int, default=1,
                    help="which judged line of the golden benign match (default 1)")
    args = ap.parse_args(argv)
    if not args.real_call:
        print("refusing: pass --real-call (one real, paid Anthropic call; Gate 1 needs "
              "the designer's GO)")
        return 2

    cfg = copy.deepcopy(lc.load_config())
    cfg["max_retries"] = 0  # Gate 1 is exactly one attempt
    model = run_blue.blue_model(cfg)
    match_id = run_match.new_match_id()
    out = REPO / "data" / "runs" / match_id
    out.mkdir(parents=True, exist_ok=False)
    line = pick_line(GOLDEN, args.log_seq)
    (out / "proxy.jsonl").write_text(json.dumps(line) + "\n", encoding="utf-8")
    print(f"scratch folder {out.relative_to(REPO)} (not a match: no match.json)")
    print(f"model {model}  request {lc.agent_request(cfg, 'blue')}  "
          f"max_output_tokens {lc.agent_max_output_tokens(cfg, 'blue')}  "
          f"prompt v{ce.PROMPT_VERSION} sha256 {ce.SYSTEM_PROMPT_SHA256[:12]}")
    print(f"line: {json.dumps(ce.request_view(1, line), ensure_ascii=False)}")

    client = lc.LLMClient(config=cfg)
    result = client.complete("blue", model, ce.SYSTEM_PROMPT, ce.build_messages([line]),
                             run_dir=out, log_seq_first=1, log_seq_last=1,
                             match_id=match_id, output_schema=ce.OUTPUT_SCHEMA)
    calls = cost_stats.read_calls(out / lc.API_CALLS)
    print("\napi_calls.jsonl:")
    for c in calls:
        print("  " + json.dumps(c, sort_keys=True))
    if not result.ok:
        print(f"\nNO REPLY: {result.error}")
        return 1
    print(f"\nraw usage (provider): {json.dumps(result.raw_usage, sort_keys=True)}")
    print(f"mapped usage:         {result.usage}")
    print(f"stop_reason:          {result.stop_reason}")
    summary = cost_stats.summarize(calls, client.prices)
    print(f"cost:                 {cost_stats.format_cost_line(summary)}")

    verdicts, detail = ce.validate_reply(result.text, result.stop_reason, 1)
    if verdicts is None:
        row = ce._row(match_id, 1, line["request_id"], no_verdict_reason="no_verdict",
                      failure_detail=detail)
    else:
        label, rationale = verdicts[1]
        row = ce._row(match_id, 1, line["request_id"], verdict=label, source="ai",
                      rationale=rationale)
    (out / "verdicts.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    print(f"verdict row:          {json.dumps(row, ensure_ascii=False)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
