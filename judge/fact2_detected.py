"""Judge fact 2: did Blue detect each attack, and get the type right?

PURE CODE. Reads artifacts only; no network. Inputs:

  - data/runs/<run>/red_attacks.jsonl   (ground-truth label per request_id; the spine)
  - data/runs/<run>/proxy.jsonl         (which request_ids were actually logged)
  - data/runs/<run>/verdicts.jsonl      (Blue's classification per request_id;
                                         0.1, 0.2 and 0.3 rows, dispatched on version)
  - data/runs/<run>/api_calls.jsonl     (only to cross-check instrument_failure)
  - data/runs/<run>/rules.jsonl, rule_rejections.jsonl
                                        (only to cross-check rule verdicts, Stage 5.5)

For each Red record (contract 6, field-relationship table):

  no proxy line (orphan)      -> detected=null,  reason="orphan",             verdict=null
  instrument failure (D13)    -> detected=null,  reason="instrument_failure", verdict=null
  proxy line, no verdict      -> detected=false, reason="no_verdict",         verdict=null
  verdict present             -> detected=(verdict!="benign");
                                 type_correct=(verdict==label) if detected else null;
                                 reason=null; verdict=verdict
  (type_correct is null in every row but the last; verdict_source is the
  verdict's source, null iff verdict is null)

Rules:
  - Verdicts whose request_id has no Red record are not scored here: fact 4a
    (judge/fact4_benign.py) matches them against benign records, and a verdict
    matching neither becomes an `unmatched_verdict` anomaly (never scored).
  - TWO verdicts for one request_id is a contract violation -> raise. Never pick one.
  - A schema-invalid verdict row (by its own schema_version) -> raise.
  - Every instrument_failure row is cross-checked against api_calls.jsonl, which
    only the body writes (contract §4): a mismatch in EITHER direction -> raise.
    Blue cannot exclude a line from the stats by declaring it a harness failure.
    A rule verdict (source "rule") made no call, so it is exempt from the
    "a refused call covers this line" direction: rules keep answering after a
    refusal (Stage 5.5). That exemption is safe only because every rule verdict
    is itself cross-checked (judge/rule_verdicts.py): the hot-loaded rules must
    really fire on the line, and nothing else may claim source "rule".
  - A 0.1 verdict row counts as source "signature" (scripted Blue was the only
    engine before Stage 5.4).
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from judge import rule_verdicts

REPO = Path(__file__).resolve().parent.parent
VERDICT_SCHEMAS = {
    v: Draft202012Validator(json.loads((REPO / "schemas" / f"{name}.schema.json")
                                       .read_text(encoding="utf-8")))
    for v, name in (("0.1", "verdict_v0_1"), ("0.2", "verdict_v0_2"), ("0.3", "verdict"))}

UUID4 = __import__("re").compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def detected_fields(label: str, proxy_present: bool, verdict: str | None,
                    no_verdict_reason: str | None = None, source: str | None = None) -> dict:
    """Pure branch logic for one Red record. `verdict` is None when Blue produced
    no verdict for this request_id (`no_verdict_reason` says why; a missing row
    counts as no_verdict)."""
    if not proxy_present:
        return {"verdict": None, "verdict_source": None, "detected": None,
                "type_correct": None, "detected_reason": "orphan"}
    if verdict is None:
        if no_verdict_reason == "instrument_failure":
            return {"verdict": None, "verdict_source": None, "detected": None,
                    "type_correct": None, "detected_reason": "instrument_failure"}
        return {"verdict": None, "verdict_source": None, "detected": False,
                "type_correct": None, "detected_reason": "no_verdict"}
    detected = verdict != "benign"
    return {
        "verdict": verdict,
        "verdict_source": source,
        "detected": detected,
        "type_correct": (verdict == label) if detected else None,
        "detected_reason": None,
    }


def normalize_verdict(row: dict) -> dict:
    """Validate one verdicts.jsonl row by its own schema_version and return the
    fields the Judge reads. Raises on an unknown version or a schema-invalid row."""
    validator = VERDICT_SCHEMAS.get(row.get("schema_version"))
    if validator is None:
        raise ValueError(f"verdict log_seq {row.get('log_seq')}: unknown schema_version "
                         f"{row.get('schema_version')!r}")
    errors = [e.message for e in validator.iter_errors(row)]
    if errors:
        raise ValueError(f"verdict log_seq {row.get('log_seq')} is schema-invalid: "
                         f"{'; '.join(errors)}")
    if row["schema_version"] == "0.1":
        return {"request_id": row["request_id"], "log_seq": row["log_seq"],
                "match_id": row["match_id"], "verdict": row["verdict"],
                "source": "signature", "no_verdict_reason": None, "fired_rule_ids": []}
    out = {k: row[k] for k in ("request_id", "log_seq", "match_id", "verdict", "source",
                               "no_verdict_reason")}
    out["fired_rule_ids"] = list(row.get("fired_rule_ids", []))  # 0.3 only
    return out


def verdicts_by_request_id(verdicts: list[dict]) -> dict[str, dict]:
    """Map request_id -> normalized verdict row, raising on duplicate request_ids."""
    out: dict[str, dict] = {}
    for v in verdicts:
        rid = v["request_id"]
        if rid in out:
            raise ValueError(
                f"duplicate verdict for request_id {rid}: contract violation "
                f"(one round = one request = one verdict). Refusing to pick one.")
        out[rid] = v
    return out


def instrument_failure_seqs(calls: list[dict]):
    """A predicate over log_seq: True iff that line is an instrument failure by the
    body's own record. The last Blue api_calls line covering it has ok false (an
    API failure after the retries, or a refusal), or a Blue call at or before it
    was refused (Blue stops calling after the first refusal, contract §6.2)."""
    blue = [c for c in calls if c.get("agent") == "blue" and c.get("log_seq_first") is not None]
    refused = [c["log_seq_first"] for c in blue if c.get("refusal") is not None]
    first_refused = min(refused) if refused else None

    def is_failure(seq: int) -> bool:
        if first_refused is not None and seq >= first_refused:
            return True
        last = None
        for c in blue:
            if c["log_seq_first"] <= seq <= c["log_seq_last"]:
                last = c
        return last is not None and last["ok"] is False
    return is_failure


def check_instrument_failures(rows: list[dict], calls: list[dict]) -> None:
    """Raise on any mismatch, in either direction, between Blue's instrument_failure
    rows and api_calls.jsonl (ambiguous data: the Judge never guesses)."""
    is_failure = instrument_failure_seqs(calls)
    for r in rows:
        claimed = r["no_verdict_reason"] == "instrument_failure"
        actual = is_failure(r["log_seq"]) and r["source"] != "rule"  # rules make no call
        if claimed and not actual:
            raise ValueError(f"verdict log_seq {r['log_seq']} claims instrument_failure, but "
                             f"api_calls.jsonl records no failed or refused Blue call for it")
        if actual and not claimed:
            raise ValueError(f"verdict log_seq {r['log_seq']}: api_calls.jsonl records a "
                             f"failed or refused Blue call, but the row is not an "
                             f"instrument_failure")


def load_verdicts(run_dir: Path) -> list[dict]:
    """verdicts.jsonl as normalized rows: validated by version, no duplicate
    request_ids, instrument failures cross-checked against api_calls.jsonl, rule
    verdicts and rule artifacts cross-checked against the hot-load sequence."""
    rows = [normalize_verdict(v) for v in _read_jsonl(run_dir / "verdicts.jsonl")]
    verdicts_by_request_id(rows)  # raises on duplicates
    check_instrument_failures(rows, _read_jsonl(run_dir / "api_calls.jsonl"))
    rule_verdicts.check(run_dir, rows)
    return rows


def compute_fact2(run_dir: Path) -> dict[str, dict]:
    """Return {request_id: detected-fields} for every Red record (the spine).
    Verdicts with no matching Red record are ignored."""
    red = _read_jsonl(run_dir / "red_attacks.jsonl")
    proxy_ids = {
        line["request_id"] for line in _read_jsonl(run_dir / "proxy.jsonl")
        if UUID4.match(line.get("request_id", "") or "")
    }
    verdicts = verdicts_by_request_id(load_verdicts(run_dir))

    out: dict[str, dict] = {}
    for record in red:
        rid = record["request_id"]
        v = verdicts.get(rid) or {}
        out[rid] = detected_fields(record["label"], rid in proxy_ids, v.get("verdict"),
                                   v.get("no_verdict_reason"), v.get("source"))
    return out
