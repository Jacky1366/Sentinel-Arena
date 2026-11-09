"""benign/fixture_v1.jsonl: the fact-4b fixture, verbatim from the frozen golden log."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
import build_benign_fixture as bf  # noqa: E402

GOLDEN = REPO / "data" / "golden" / "scripted-baseline-benign-match"
LINES = [json.loads(l) for l in bf.FIXTURE.read_text().splitlines()]
META = json.loads(bf.META.read_text())


def test_rebuild_from_the_golden_match_is_identical():
    assert bf.main(["--check"]) == 0


def test_meta_sha_and_count():
    assert META["sha256"] == hashlib.sha256(bf.FIXTURE.read_bytes()).hexdigest()
    assert META["entries"] == len(LINES) == 17 and META["fixture_version"] == "1"
    m = json.loads((GOLDEN / "match.json").read_text())
    assert META["source"]["proxy_sha256"] == m["artifacts"]["proxy.jsonl"]["sha256"]


def test_lines_are_verbatim_proxy_fields():
    proxy = {l["request_id"]: l for l in map(json.loads, (GOLDEN / "proxy.jsonl").read_text().splitlines())}
    benign = [json.loads(l) for l in (GOLDEN / "benign_requests.jsonl").read_text().splitlines()]
    v = Draft202012Validator(json.loads((REPO / "schemas" / "benign_fixture.schema.json").read_text()))
    for line, b in zip(LINES, benign):
        v.validate(line)
        p = proxy[b["request_id"]]
        assert line == {"benign_id": b["benign_id"], "category": b["category"],
                        **{k: p[k] for k in ("method", "path", "query", "body")}}


def test_no_forbidden_fields_in_the_fixture():
    for line in LINES:
        assert not {"request_id", "status", "timestamp"} & set(line)
