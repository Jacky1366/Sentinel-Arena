"""Blue v0 defender.

Reads ONLY the proxy log and writes one verdict per logged request. This is the
whole of Blue's world: it never opens the Red attack records, the challenge
snapshots, the landed facts, or the challenge map, and it never uses the request
id or any header as a classification feature (the request id is only copied through
as the Judge's join key).

Engines are pluggable so a future `--engine claude` can be added without touching
the Judge or the verdict format:

    verdict = ENGINES[name](path, query, body)   # -> taxonomy label

v0 ships the deterministic `scripted` engine (generic signatures in signatures.py).

Usage:
    .venv/bin/python blue/run_blue.py --engine scripted --match-id m001 --run-dir data/runs/<match_id>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from blue import signatures

REPO = Path(__file__).resolve().parent.parent
LIVE = REPO / "data" / "runs" / "live"

UUID4 = __import__("re").compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def scripted_engine(path: str, query: str, body: str) -> str:
    return signatures.classify(path, query, body)


ENGINES = {"scripted": scripted_engine}


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
                "schema_version": "0.1",
                "match_id": match_id,
                "log_seq": log_seq,
                "request_id": request_id,
                "verdict": verdict,
                "reason": _reason(verdict),
            })
    return verdicts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Blue v0: classify proxy-log requests.")
    parser.add_argument("--engine", choices=sorted(ENGINES), default="scripted")
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

    verdicts = classify_log(args.proxy_log, args.match_id, args.engine)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for v in verdicts:
            fh.write(json.dumps(v) + "\n")

    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
    print(f"{len(verdicts)} verdicts -> {args.out}")
    for label in sorted(counts):
        print(f"  {label}: {counts[label]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
