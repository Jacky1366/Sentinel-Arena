"""Shared anomaly-writing helper (Stage 5.6). PURE.

Several Judge steps emit harness-self-check anomalies into the one
`anomalies.jsonl` (contract 6.6): fact 4a (benign traffic) and red_facts
(label_mismatch). Each validates its rows against schemas/anomaly.schema.json with
this helper before writing, so no step writes a schema-invalid anomaly.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
ANOMALIES = "anomalies.jsonl"
_SCHEMA = Draft202012Validator(json.loads(
    (REPO / "schemas" / "anomaly.schema.json").read_text(encoding="utf-8")))


def validate(rows: list[dict]) -> None:
    for row in rows:
        errors = list(_SCHEMA.iter_errors(row))
        if errors:
            raise ValueError(f"anomaly for {row.get('request_id')} is schema-invalid: "
                             f"{'; '.join(e.message for e in errors)}")


def append(run_dir: Path, rows: list[dict]) -> None:
    """Validate, then append rows to anomalies.jsonl (created by the fact-4a step)."""
    validate(rows)
    with (run_dir / ANOMALIES).open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
