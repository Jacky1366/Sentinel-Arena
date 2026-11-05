"""Scripted Red for Stage 2.

Fires a fixed, data-driven set of attacks (red/payloads.json) through the arena
proxy (127.0.0.1:8080). Per the contract:

- The Red attack record is written FIRST, then the request is sent. If the send
  fails, the record stays and the round becomes an orphan (no proxy line).
- Every request carries X-Arena-Request-Id and is sent by the same HTTP client.
- One round = one attack = one request. No retries in Stage 2. Timeouts always.

This module is imported by runner/stage2_run.py (which interleaves challenge
snapshots around each send). It can also be run standalone to fire the whole set
without snapshots:  .venv/bin/python red/scripted_red.py
"""

from __future__ import annotations

import argparse
import http.client
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

REPO = Path(__file__).resolve().parent.parent
PAYLOADS = REPO / "red" / "payloads.json"
OUT_DIR = REPO / "data" / "runs" / "live"
ARENA_HOST, ARENA_PORT = "127.0.0.1", 8080
DEFAULT_MATCH = "m001"
DEFAULT_TIMEOUT = 15.0


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def load_attacks(path: Path = PAYLOADS) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["attacks"]


def request_target(attack: dict) -> str:
    """The exact request-line target (path, raw, plus any query). Never re-encoded:
    percent-sequences such as %2500 must reach the Target verbatim."""
    target = attack["endpoint"]
    if attack.get("query_params"):
        target += "?" + urlencode(attack["query_params"])
    elif attack.get("raw_query"):
        target += "?" + attack["raw_query"]
    return target


def red_record(attack: dict, request_id: str, match_id: str, round_num: int) -> dict:
    body = attack.get("json_body")
    if body is not None:
        payload = json.dumps(body, separators=(",", ":"))
    elif attack.get("query_params"):
        payload = urlencode(attack["query_params"])
    elif attack.get("raw_query"):
        payload = attack["raw_query"]
    else:
        payload = attack["endpoint"]
    return {
        "schema_version": "0.1",
        "match_id": match_id,
        "round": round_num,
        "request_id": request_id,
        "label": attack["label"],
        "payload": payload,
        "endpoint": attack["endpoint"],
        "method": attack["method"],
        "timestamp": utc_now(),
    }


def send_one(attack: dict, match_id: str, round_num: int, out_dir: Path = OUT_DIR,
             timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Write the Red record, then fire one attack. Returns a result dict; on a send
    failure `status` is None and `error` is set (the record stays -> orphan)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    request_id = str(uuid.uuid4())
    record = red_record(attack, request_id, match_id, round_num)

    # Record FIRST, so a crash or network failure still leaves ground truth.
    with (out_dir / "red_attacks.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    headers = {"X-Arena-Request-Id": request_id}
    body = None
    if attack.get("json_body") is not None:
        body = json.dumps(attack["json_body"])
        headers["Content-Type"] = "application/json"

    status, error = None, None
    conn = http.client.HTTPConnection(ARENA_HOST, ARENA_PORT, timeout=timeout)
    try:
        conn.request(attack["method"], request_target(attack), body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        status = resp.status
    except Exception as exc:  # noqa: BLE001 - any failure -> orphan, no retry
        error = f"{type(exc).__name__}: {exc}"
    finally:
        conn.close()

    return {
        "request_id": request_id,
        "round": round_num,
        "label": attack["label"],
        "status": status,
        "error": error,
        "expected_landed": attack.get("expected_landed"),
        "expected_reason": attack.get("expected_reason"),
        "note": attack.get("note", ""),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fire the scripted Red attack set.")
    parser.add_argument("--match-id", default=DEFAULT_MATCH)
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    parser.add_argument("--payloads", type=Path, default=PAYLOADS)
    args = parser.parse_args(argv)

    attacks = load_attacks(args.payloads)
    for i, attack in enumerate(attacks, start=1):
        res = send_one(attack, args.match_id, i, args.out_dir)
        where = res["status"] if res["error"] is None else res["error"]
        print(f"round {i} {res['label']:7} {res['request_id']} -> {where}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
