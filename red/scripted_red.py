"""Scripted Red for Stage 2.

Fires a fixed, data-driven set of attacks (red/payloads.json) through the arena
proxy (127.0.0.1:8080). Per the contract:

- The Red attack record is written FIRST, then the request is sent. If the send
  fails, the record stays and the round becomes an orphan (no proxy line).
- Every request carries X-Arena-Request-Id and is sent by the shared arena client
  (runner/arena_client.py), the same one benign traffic uses.
- One round = one attack = one request. No retries. Timeouts always.

Red is callable ONE STEP AT A TIME (ScriptedRed.next_attack): the orchestrator's
scheduler interleaves Red and benign slots, and Stage 5.6's AI Red will decide each
attack from its previous responses through the same interface.

This module is imported by runner/match_ops.py (which brackets each send with
challenge snapshots). It can also be run standalone to fire the whole set without
snapshots:  .venv/bin/python red/scripted_red.py
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from runner import arena_client  # noqa: E402

PAYLOADS = REPO / "red" / "payloads.json"
OUT_DIR = REPO / "data" / "runs" / "live"
DEFAULT_MATCH = "m001"
DEFAULT_TIMEOUT = arena_client.DEFAULT_TIMEOUT


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
        "schema_version": "0.2",
        "match_id": match_id,
        "round": round_num,
        "request_id": request_id,
        "label": attack["label"],
        "payload": payload,
        "endpoint": attack["endpoint"],
        "method": attack["method"],
        "timestamp": utc_now(),
        "source": "scripted",
        "rationale": None,
    }


def send_request(method: str, target: str, request_id: str, body: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT) -> int:
    """Status only, via the shared arena client (kept for harness probes)."""
    return arena_client.send(method, target, request_id, body=body, timeout=timeout).status


class ScriptedRed:
    """Red, one step at a time. next_attack() returns the next attack (or None
    when Red is done). `last_status` is the previous response, Red's only
    feedback (D6); scripted Red ignores it, AI Red (5.6) will not."""

    def __init__(self, attacks: list[dict]):
        self._attacks = list(attacks)
        self._i = 0

    def next_attack(self, last_status: int | None = None) -> dict | None:
        if self._i >= len(self._attacks):
            return None
        self._i += 1
        return self._attacks[self._i - 1]


def write_and_send(record: dict, method: str, target: str, body: str | None,
                   out_dir: Path, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Write one Red record (ground truth), THEN send its request through the shared
    arena client. The record carries request_id. Returns the HTTP result; on a send
    failure `status` is None and `error` is set (the record stays -> orphan). Used by
    scripted Red and AI Red, so both write the same way and send the same way."""
    out_dir.mkdir(parents=True, exist_ok=True)
    request_id = record["request_id"]
    with (out_dir / "red_attacks.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    status, error, incomplete, body_text = None, None, False, ""
    try:
        resp = arena_client.send(method, target, request_id, body=body, timeout=timeout)
        status, incomplete, body_text = resp.status, resp.body_incomplete, resp.body_text
    except Exception as exc:  # noqa: BLE001 - any failure -> orphan, no retry
        error = f"{type(exc).__name__}: {exc}"
    return {"request_id": request_id, "round": record["round"], "label": record["label"],
            "status": status, "body_incomplete": incomplete, "error": error,
            "body_text": body_text}


def send_one(attack: dict, match_id: str, round_num: int, out_dir: Path = OUT_DIR,
             timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Write the scripted Red record, then fire one attack."""
    request_id = arena_client.new_request_id()
    record = red_record(attack, request_id, match_id, round_num)
    body = None
    if attack.get("json_body") is not None:
        body = json.dumps(attack["json_body"])
    res = write_and_send(record, attack["method"], request_target(attack), body, out_dir,
                         timeout)
    return {**res, "expected_landed": attack.get("expected_landed"),
            "expected_reason": attack.get("expected_reason"), "note": attack.get("note", "")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fire the scripted Red attack set.")
    parser.add_argument("--match-id", default=DEFAULT_MATCH)
    parser.add_argument("--run-dir", type=Path, default=OUT_DIR,
                        help="where red_attacks.jsonl is written (default: data/runs/live)")
    parser.add_argument("--payloads", type=Path, default=PAYLOADS)
    args = parser.parse_args(argv)

    attacks = load_attacks(args.payloads)
    for i, attack in enumerate(attacks, start=1):
        res = send_one(attack, args.match_id, i, args.run_dir)
        where = res["status"] if res["error"] is None else res["error"]
        print(f"round {i} {res['label']:7} {res['request_id']} -> {where}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
