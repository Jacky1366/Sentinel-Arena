"""The benign traffic set: load and validate (Stage 5.2, D1 layer 1).

Benign entries are ground truth by the SENDER'S intent (contract §10): a person
named O'Brien logging in is benign even if the server breaks on the apostrophe.
An entry may declare `expected_solves`, the challenges it is known to solve; they
may only be challenges outside config/challenge_map.json, so a benign request can
never change any Red round's landing. Blue must never read this module's data.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from red.scripted_red import request_target  # noqa: E402  (same target builder as Red)
from runner import arena_client  # noqa: E402
BENIGN_SET = REPO / "benign" / "benign_set.json"
SCHEMA = REPO / "schemas" / "benign_set.schema.json"
CHALLENGE_MAP = REPO / "config" / "challenge_map.json"


class BenignSetError(ValueError):
    """The benign set is invalid; a match must not start with it."""


def validate_set(data: dict, challenge_map: dict) -> list[str]:
    """Every problem with the set (empty list = valid). Beyond the schema:
    unique ids, expected_solves outside the challenge map, requires points to an
    EARLIER entry."""
    errors = [e.message for e in Draft202012Validator(
        json.loads(SCHEMA.read_text(encoding="utf-8"))).iter_errors(data)]
    if errors:
        return errors
    mapped = {name for names in challenge_map.values() for name in names}
    seen: list[str] = []
    for e in data["entries"]:
        bid = e["benign_id"]
        if bid in seen:
            errors.append(f"{bid}: duplicate benign_id")
        bad = sorted(set(e.get("expected_solves", [])) & mapped)
        if bad:
            errors.append(f"{bid}: expected_solves {bad} are in config/challenge_map.json; "
                          f"a benign request may never be expected to solve a mapped challenge")
        req = e.get("requires")
        if req is not None and req not in seen:
            errors.append(f"{bid}: requires {req!r}, which is not an earlier entry")
        seen.append(bid)
    return errors


def load_set(path: Path = BENIGN_SET, challenge_map_path: Path = CHALLENGE_MAP) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_set(data, json.loads(challenge_map_path.read_text(encoding="utf-8")))
    if errors:
        raise BenignSetError(f"{path.name} is invalid: " + "; ".join(errors))
    return data


def set_sha256(path: Path = BENIGN_SET) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def benign_record(entry: dict, request_id: str, match_id: str) -> dict:
    """One benign_requests.jsonl line (contract §2.1). Ground truth: Blue never
    reads it. Carries expected_solves so the Judge is self-contained."""
    return {
        "schema_version": "0.1",
        "match_id": match_id,
        "request_id": request_id,
        "benign_id": entry["benign_id"],
        "category": entry["category"],
        "expected_solves": sorted(entry.get("expected_solves", [])),
        "sent_at": utc_now(),
    }


def send_one(entry: dict, match_id: str, out_dir: Path,
             timeout: float = arena_client.DEFAULT_TIMEOUT) -> dict:
    """Write the benign record FIRST (same rule as Red), then send the request
    through the shared arena client. A send failure keeps the record (-> orphan
    if nothing was logged)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    request_id = arena_client.new_request_id()
    with (out_dir / "benign_requests.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(benign_record(entry, request_id, match_id)) + "\n")
    body = json.dumps(entry["json_body"]) if entry.get("json_body") is not None else None
    status, error, incomplete = None, None, False
    try:
        resp = arena_client.send(entry["method"], request_target(entry), request_id,
                                 body=body, timeout=timeout)
        status, incomplete = resp.status, resp.body_incomplete
    except Exception as exc:  # noqa: BLE001 - any failure -> orphan, no retry
        error = f"{type(exc).__name__}: {exc}"
    return {"request_id": request_id, "benign_id": entry["benign_id"],
            "category": entry["category"], "status": status,
            "body_incomplete": incomplete, "error": error}
