"""Unit tests for Blue v0: decoding, generic classification, and the information
wall (Blue may read ONLY the proxy log). No Docker.
"""

from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
import sys  # noqa: E402
sys.path.insert(0, str(REPO))
from blue import run_blue, signatures  # noqa: E402

VERDICT_SCHEMA = Draft202012Validator(
    json.loads((REPO / "schemas" / "verdict.schema.json").read_text()))
RID = "3f2b8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c"
RID2 = "4a5b8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c"

FORBIDDEN = ["red_attacks.jsonl", "challenge_snapshots.jsonl", "landed.jsonl",
             "challenge_map.json", "payloads.json", "rounds.jsonl"]


# ---- decoding ------------------------------------------------------------

def test_double_encoded_null_byte_decodes():
    assert signatures._decode_all("%2500") == "\x00"
    # A double-encoded NUL in a path is caught as traversal.
    assert signatures.classify("/ftp/x.bak%2500.md", "", "") == "CWE-22"


def test_single_encoded_query_decoded_before_match():
    # UNION SELECT hidden by percent-encoding in the query is still caught.
    q = "q=a%27%29%29%20UNION%20SELECT%20id%20FROM%20Users--"
    assert signatures.classify("/rest/products/search", q, "") == "CWE-89"


# ---- generic classification ----------------------------------------------

@pytest.mark.parametrize("path,query,body,expected", [
    ("/rest/user/login", "", '{"email":"x","password":"\' OR 1=1--"}', "CWE-89"),
    ("/x/..%2f..%2fetc/passwd", "", "", "CWE-22"),
    ("/p", "q=<script>alert(1)</script>", "", "CWE-79"),
    ("/", "", "", "benign"),
    ("/rest/products/search", "q=apple", "", "benign"),
])
def test_classify_representatives(path, query, body, expected):
    assert signatures.classify(path, query, body) == expected


# ---- classify_log behaviour ----------------------------------------------

def _proxy_line(request_id, path="/", query="", body="", status=200):
    return {"timestamp": "2026-11-05T00:00:00Z", "request_id": request_id,
            "method": "GET", "path": path, "query": query, "body": body, "status": status}


def test_stray_lines_skipped_and_output_schema_valid(tmp_path):
    log = tmp_path / "proxy.jsonl"
    log.write_text("\n".join(json.dumps(x) for x in [
        _proxy_line(RID, path="/rest/products/search", query="q=1 UNION SELECT a"),
        _proxy_line("", path="/"),          # stray: empty request_id -> skipped
        _proxy_line(RID2, path="/"),         # benign
    ]) + "\n", encoding="utf-8")
    verdicts = run_blue.classify_log(log, "m001", "scripted")
    assert [v["request_id"] for v in verdicts] == [RID, RID2]  # stray dropped
    assert [v["log_seq"] for v in verdicts] == [1, 2]
    assert verdicts[0]["verdict"] == "CWE-89" and verdicts[1]["verdict"] == "benign"
    for v in verdicts:
        VERDICT_SCHEMA.validate(v)


def test_request_id_is_not_a_classification_feature(tmp_path):
    # Same request, two different request_ids -> identical verdict.
    log_a = tmp_path / "a.jsonl"
    log_b = tmp_path / "b.jsonl"
    payload = dict(path="/p", query="q=<iframe src=javascript:alert(1)>")
    log_a.write_text(json.dumps(_proxy_line(RID, **payload)) + "\n", encoding="utf-8")
    log_b.write_text(json.dumps(_proxy_line(RID2, **payload)) + "\n", encoding="utf-8")
    va = run_blue.classify_log(log_a, "m001", "scripted")[0]
    vb = run_blue.classify_log(log_b, "m001", "scripted")[0]
    assert va["verdict"] == vb["verdict"] == "CWE-79"


# ---- information wall -----------------------------------------------------

def test_blue_reads_only_the_proxy_log(tmp_path, monkeypatch):
    log = tmp_path / "proxy.jsonl"
    log.write_text(json.dumps(_proxy_line(RID, query="q=1 UNION SELECT a")) + "\n",
                   encoding="utf-8")

    opened: list[str] = []
    real_builtin_open = builtins.open
    real_path_open = Path.open

    def recording_builtin_open(file, *args, **kwargs):
        opened.append(str(file))
        return real_builtin_open(file, *args, **kwargs)

    def recording_path_open(self, *args, **kwargs):
        opened.append(str(self))
        return real_path_open(self, *args, **kwargs)

    # Capture both routes to a file: Path.open (what Blue uses) and builtins.open.
    monkeypatch.setattr(builtins, "open", recording_builtin_open)
    monkeypatch.setattr(Path, "open", recording_path_open)
    run_blue.classify_log(log, "m001", "scripted")
    monkeypatch.undo()

    # The proxy log was read...
    assert any(str(log) == p for p in opened), opened
    # ...and nothing from the forbidden set was ever opened.
    for p in opened:
        assert not any(name in p for name in FORBIDDEN), f"Blue opened forbidden file: {p}"
