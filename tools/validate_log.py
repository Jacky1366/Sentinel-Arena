"""Validate a proxy log (JSONL) against schemas/proxy_log.schema.json.

Each non-blank line is classified as:

  valid    passes the schema
  stray    request_id missing or empty (traffic without X-Arena-Request-Id);
           skipped and counted, per the contract's Traffic rule
  invalid  anything else that fails: a non-empty request_id with a bad line,
           a malformed request_id, non-UTF-8 bytes, or not a JSON object

Prints each invalid line's errors, then the counts. The last line of output is
always machine-readable: "valid=N stray=N invalid=N".

Exit codes: 0 = no invalid lines, 1 = at least one invalid line, 2 = usage error.

Usage: .venv/bin/python tools/validate_log.py [path/to/proxy.jsonl]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO / "schemas" / "proxy_log.schema.json"
DEFAULT_LOG = REPO / "data" / "runs" / "live" / "proxy.jsonl"

VALID, STRAY, INVALID = "valid", "stray", "invalid"


def load_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def classify(raw: bytes, validator: Draft202012Validator) -> tuple[str, list[str]]:
    """Return (category, errors) for one raw log line (without the newline)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return INVALID, [f"not UTF-8: {exc}"]
    try:
        record = json.loads(text)
    except json.JSONDecodeError as exc:
        return INVALID, [f"not valid JSON: {exc}"]
    if not isinstance(record, dict):
        return INVALID, [f"not a JSON object (got {type(record).__name__})"]

    if record.get("request_id", "") == "":
        return STRAY, []

    errors = sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path))
    if not errors:
        return VALID, []
    return INVALID, [
        f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errors
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("log", nargs="?", type=Path, default=DEFAULT_LOG,
                        help=f"JSONL file (default: {DEFAULT_LOG.relative_to(REPO)})")
    args = parser.parse_args(argv)

    if not args.log.is_file():
        print(f"error: log file not found: {args.log}", file=sys.stderr)
        return 2

    validator = load_validator()
    counts = {VALID: 0, STRAY: 0, INVALID: 0}
    with args.log.open("rb") as fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.rstrip(b"\r\n")
            if not raw.strip():
                continue
            category, errors = classify(raw, validator)
            counts[category] += 1
            if category == INVALID:
                print(f"line {lineno}: INVALID")
                for err in errors:
                    print(f"  - {err}")

    print(f"{args.log}: {counts[VALID]} valid, {counts[STRAY]} stray, "
          f"{counts[INVALID]} invalid")
    print(f"valid={counts[VALID]} stray={counts[STRAY]} invalid={counts[INVALID]}")
    return 1 if counts[INVALID] else 0


if __name__ == "__main__":
    sys.exit(main())
