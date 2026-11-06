"""Judge fact 2: did Blue detect each attack, and get the type right?

PURE CODE. Reads artifacts only; no network. Inputs:

  - data/runs/<run>/red_attacks.jsonl   (ground-truth label per request_id; the spine)
  - data/runs/<run>/proxy.jsonl         (which request_ids were actually logged)
  - data/runs/<run>/verdicts.jsonl      (Blue's classification per request_id)

For each Red record (contract 6, field-relationship table):

  no proxy line (orphan) -> detected=null,  type_correct=null, reason="orphan",  verdict=null
  proxy line, no verdict -> detected=false, type_correct=null, reason="no_verdict", verdict=null
  verdict present        -> detected=(verdict!="benign");
                            type_correct=(verdict==label) if detected else null;
                            reason=null; verdict=verdict

Rules:
  - Verdicts whose request_id has no Red record are IGNORED (benign traffic is
    scored by fact 4 in Stage 5).
  - TWO verdicts for one request_id is a contract violation -> raise. Never pick one.
"""

from __future__ import annotations

import json
from pathlib import Path

UUID4 = __import__("re").compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def detected_fields(label: str, proxy_present: bool, verdict: str | None) -> dict:
    """Pure branch logic for one Red record. `verdict` is None when Blue produced
    no verdict for this request_id."""
    if not proxy_present:
        return {"verdict": None, "detected": None, "type_correct": None,
                "detected_reason": "orphan"}
    if verdict is None:
        return {"verdict": None, "detected": False, "type_correct": None,
                "detected_reason": "no_verdict"}
    detected = verdict != "benign"
    return {
        "verdict": verdict,
        "detected": detected,
        "type_correct": (verdict == label) if detected else None,
        "detected_reason": None,
    }


def verdicts_by_request_id(verdicts: list[dict]) -> dict[str, str]:
    """Map request_id -> verdict label, raising on duplicate request_ids."""
    out: dict[str, str] = {}
    for v in verdicts:
        rid = v["request_id"]
        if rid in out:
            raise ValueError(
                f"duplicate verdict for request_id {rid}: contract violation "
                f"(one round = one request = one verdict). Refusing to pick one.")
        out[rid] = v["verdict"]
    return out


def compute_fact2(run_dir: Path) -> dict[str, dict]:
    """Return {request_id: detected-fields} for every Red record (the spine).
    Verdicts with no matching Red record are ignored."""
    red = _read_jsonl(run_dir / "red_attacks.jsonl")
    proxy_ids = {
        line["request_id"] for line in _read_jsonl(run_dir / "proxy.jsonl")
        if UUID4.match(line.get("request_id", "") or "")
    }
    verdicts = verdicts_by_request_id(_read_jsonl(run_dir / "verdicts.jsonl"))

    out: dict[str, dict] = {}
    for record in red:
        rid = record["request_id"]
        out[rid] = detected_fields(record["label"], rid in proxy_ids, verdicts.get(rid))
    return out
