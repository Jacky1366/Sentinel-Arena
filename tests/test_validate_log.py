"""Tests for tools/validate_log.py line classification (valid / stray / invalid)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("validate_log", REPO / "tools" / "validate_log.py")
validate_log = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate_log)

GOOD = {
    "timestamp": "2026-11-02T22:15:03Z",
    "request_id": "3f2b8c1e-9a4d-4e7f-8b2a-1c5d6e7f8a9b",
    "method": "POST",
    "path": "/rest/user/login",
    "query": "",
    "body": "{\"email\":\"o'brien@juice-sh.op\",\"password\":\"say \\\"hi\\\"\"}",
    "status": 401,
}


@pytest.fixture(scope="module")
def validator():
    return validate_log.load_validator()


def line(**overrides) -> bytes:
    rec = {**GOOD, **overrides}
    rec = {k: v for k, v in rec.items() if v is not _DROP}
    return json.dumps(rec).encode()


_DROP = object()


def test_good_line_is_valid(validator):
    assert validate_log.classify(line(), validator) == ("valid", [])


@pytest.mark.parametrize("raw", [line(request_id=""), line(request_id=_DROP)])
def test_missing_or_empty_request_id_is_stray(validator, raw):
    assert validate_log.classify(raw, validator)[0] == "stray"


def test_stray_even_if_other_fields_are_broken(validator):
    assert validate_log.classify(line(request_id="", status="200"), validator)[0] == "stray"


@pytest.mark.parametrize(
    "raw",
    [
        line(request_id="not-a-uuid"),
        line(request_id=GOOD["request_id"].upper()),
        line(timestamp="2026-11-02T22:15:03+00:00"),
        line(path="ftp/x"),
        line(status="200"),
        line(method="PROPFIND"),
        line(extra="leak"),
        b"not json",
        b"[1, 2]",
        b'{"request_id": "\xff"}',
    ],
)
def test_bad_lines_are_invalid(validator, raw):
    category, errors = validate_log.classify(raw, validator)
    assert category == "invalid"
    assert errors


def test_main_counts_and_exit_code(tmp_path, capsys):
    log = tmp_path / "proxy.jsonl"
    log.write_bytes(b"\n".join([line(), line(), line(request_id=""), b""]) + b"\n")
    assert validate_log.main([str(log)]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "valid=2 stray=1 invalid=0"

    log.write_bytes(line() + b"\n" + line(status=42) + b"\n")
    assert validate_log.main([str(log)]) == 1
    out = capsys.readouterr().out
    assert "line 2: INVALID" in out
    assert out.splitlines()[-1] == "valid=1 stray=0 invalid=1"


def test_missing_file_is_usage_error(tmp_path):
    assert validate_log.main([str(tmp_path / "nope.jsonl")]) == 2
