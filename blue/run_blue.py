"""Blue v0 defender.

Reads ONLY the proxy log and writes one verdict per logged request. This is the
whole of Blue's world: it never opens the Red attack records, the challenge
snapshots, the landed facts, or the challenge map, and it never uses the request
id or any header as a classification feature (the request id is only copied through
as the Judge's join key).

Two engines write the same verdict format (contract §4, schema_version 0.2):

  scripted  deterministic generic signatures (signatures.py), source "signature"
  claude    AI Blue (Stage 5.4, blue/claude_engine.py), one model call per line
            through agents/llm_client.py, source "ai"; model and request settings
            from config/llm.json (agents.blue), --model overrides the model

Usage:
    .venv/bin/python blue/run_blue.py --engine scripted --match-id m001 --run-dir data/runs/<match_id>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agents import llm_client
from blue import claude_engine, signatures

REPO = Path(__file__).resolve().parent.parent
LIVE = REPO / "data" / "runs" / "live"

UUID4 = __import__("re").compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def scripted_engine(path: str, query: str, body: str) -> str:
    return signatures.classify(path, query, body)


ENGINES = {"scripted": scripted_engine}  # per-line classifiers (no AI)
ENGINE_NAMES = ("claude", "scripted")     # what --engine / run_match --blue accept


def _reason(verdict: str) -> str:
    if verdict == "benign":
        return "no attack signature matched path/query/body"
    return f"{verdict} signature matched (generic, decoded path/query/body)"


def classify_log(proxy_log: Path, match_id: str, engine: str) -> list[dict]:
    """Produce verdict records from the proxy log. A line with a missing/empty
    request_id is stray traffic and is skipped. `log_seq` is Blue's own 1-based
    index over the lines it judged, never the Red round."""
    classify = ENGINES[engine]
    verdicts: list[dict] = []
    log_seq = 0
    with proxy_log.open(encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            line = json.loads(raw)
            request_id = line.get("request_id", "")
            if not request_id or not UUID4.match(request_id):
                continue  # stray traffic: skip (never classified, never crashes)
            log_seq += 1
            verdict = classify(line.get("path", ""), line.get("query", ""), line.get("body", ""))
            verdicts.append({
                "schema_version": "0.2",
                "match_id": match_id,
                "log_seq": log_seq,
                "request_id": request_id,
                "verdict": verdict,
                "source": "signature",
                "no_verdict_reason": None,
                "failure_detail": None,
                "reason": _reason(verdict),
            })
    return verdicts


def blue_model(cfg: dict, override: str | None = None) -> str:
    model = override or cfg["agents"]["blue"]["model"]
    if not model:
        raise llm_client.ConfigError("no Blue model: set agents.blue.model in "
                                     "config/llm.json or pass --model")
    return model


def blue_chunk_size(cfg: dict) -> int:
    return cfg["agents"]["blue"].get("chunk_size") or 1


def run(engine: str, proxy_log: Path, match_id: str, run_dir: Path, *,
        client: llm_client.LLMClient | None = None, model: str | None = None,
        unscored: bool = False) -> list[dict]:
    """Verdict rows for one proxy log. For `claude`, `client` defaults to the real
    body (llm_client.LLMClient()); tests pass a fake-provider client."""
    if engine == "scripted":
        return classify_log(proxy_log, match_id, engine)
    if engine != "claude":
        raise ValueError(f"unknown Blue engine {engine!r}")
    client = client or llm_client.LLMClient()
    return claude_engine.classify_log(proxy_log, match_id, client,
                                      blue_model(client.cfg, model), run_dir,
                                      chunk_size=blue_chunk_size(client.cfg),
                                      unscored=unscored)


def main(argv: list[str] | None = None, client: llm_client.LLMClient | None = None) -> int:
    parser = argparse.ArgumentParser(description="Blue: classify proxy-log requests.")
    parser.add_argument("--engine", choices=ENGINE_NAMES, default="scripted")
    parser.add_argument("--model", default=None,
                        help="claude engine: model id (default: config/llm.json agents.blue)")
    parser.add_argument("--unscored", action="store_true",
                        help="claude engine: allow chunk_size > 1 (exploratory runs only; "
                             "run_match.py never passes this)")
    parser.add_argument("--match-id", default="m001")
    parser.add_argument("--run-dir", type=Path, default=LIVE,
                        help="run directory: reads <run-dir>/proxy.jsonl, writes "
                             "<run-dir>/verdicts.jsonl (default: data/runs/live)")
    parser.add_argument("--proxy-log", type=Path, default=None,
                        help="override the proxy log path (default: <run-dir>/proxy.jsonl)")
    parser.add_argument("--out", type=Path, default=None,
                        help="override the verdicts path (default: <run-dir>/verdicts.jsonl)")
    args = parser.parse_args(argv)
    args.proxy_log = args.proxy_log or args.run_dir / "proxy.jsonl"
    args.out = args.out or args.run_dir / "verdicts.jsonl"

    verdicts = run(args.engine, args.proxy_log, args.match_id, args.run_dir, client=client,
                   model=args.model, unscored=args.unscored)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for v in verdicts:
            fh.write(json.dumps(v) + "\n")

    counts: dict[str, int] = {}
    for v in verdicts:
        key = v["verdict"] or f"{v['no_verdict_reason']} ({v['failure_detail']})"
        counts[key] = counts.get(key, 0) + 1
    print(f"{len(verdicts)} verdicts -> {args.out}")
    for label in sorted(counts):
        print(f"  {label}: {counts[label]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
