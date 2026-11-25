"""#18: a Red brain failure prints ONE short, redacted diagnosis line to stdout (the tee'd
transcript). Diagnosis only (scope freeze, D40): the prompt and validate_reply are
unchanged, the line never reaches an artifact, Red's feedback or the dashboard, and the
live tailer ignores it."""

from __future__ import annotations

import json

from llm_fakes import lc
from liveserver import tailer
from red import ai_red
from runner import match_ops
from runner.schedule import Schedule

from test_run_match_red import M, ScriptClient, attack_json, no_target, result  # noqa: F401


def _secret_samples() -> dict[str, str]:
    # Built at runtime: fixtures must never hold key-shaped literals (CLAUDE.md).
    return {"key": "sk" + "-" + "a1B2" * 6, "jwt": "eyJ" + "x" * 10 + ".eyJ" + "y" * 10 + ".zzzz",
            "bearer": "Bearer " + "q" * 20, "hex": "ab" * 20}


def test_shape_names_the_extra_field_that_made_it_invalid():
    text = json.dumps({"method": "GET", "path": "/x", "label": "other", "notes": {"a": 1}})
    assert ai_red.validate_reply(text, "completed", free_play=True) == (None, "invalid_shape")
    d = ai_red.reply_diagnosis(text, "completed")
    assert "shape={label:str, method:str, notes:dict, path:str}" in d
    assert d.startswith("stop=completed chars=")


def test_not_json_and_empty():
    assert "shape=not JSON" in ai_red.reply_diagnosis("I can't help with that", "completed")
    d = ai_red.reply_diagnosis(None, "max_tokens")
    assert "stop=max_tokens chars=0 shape=not JSON" in d and 'excerpt=""' in d


def test_redacted_before_cut_one_line_and_capped():
    s = _secret_samples()
    text = ("{\n  \"x\": \"" + " ".join(s.values()) + "\"\n}") + " pad" * 200
    d = ai_red.reply_diagnosis(text, "completed")
    for v in s.values():
        assert v not in d and v[:12] not in d
    assert "[redacted]" in d and "\n" not in d
    excerpt = json.loads(d.split("excerpt=", 1)[1])
    assert len(excerpt) == ai_red.EXCERPT_MAX + 1 and excerpt.endswith("…")


def test_secret_straddling_the_cut_is_still_redacted():
    key = _secret_samples()["key"]
    text = "x" * (ai_red.EXCERPT_MAX - 10) + key
    d = ai_red.reply_diagnosis(text, "completed")
    assert key[:10] not in d and "[redacted]"[:5] in d


def test_brain_failure_prints_diagnosis_only_to_stdout(no_target, tmp_path):  # noqa: F811
    bad = json.dumps({"method": "GET", "path": "/x", "label": "CWE-89", "extra": [1]})
    client = ScriptClient([result(bad), result(attack_json())])
    red = ai_red.AIRed(client, "deepseek-v4-pro", tmp_path, M, round_cap=2)
    driver = match_ops.AIDriver(red)
    lines: list[str] = []
    match_ops.run_traffic(M, tmp_path, [], [], Schedule(2, [], 1), settle=0,
                          log=lines.append, red_driver=driver)
    diag = [l for l in lines if l.startswith("red diagnosis:")]
    assert diag == [l for l in diag if "round 1 invalid_shape: stop=completed" in l]
    assert len(diag) == 1 and "extra:list" in diag[0]
    # never in an artifact
    unsent = [json.loads(l) for l in (tmp_path / "red_unsent.jsonl").read_text().splitlines()]
    assert unsent[0]["detail"] is None and "extra" not in json.dumps(unsent)
    # never in Red's feedback (the next turn is the unchanged brain-failure text)
    assert driver._feedback is None or "extra" not in driver._feedback
    assert ai_red.feedback_brain("invalid_shape") == (
        "Your previous response was not a valid request (invalid_shape). Respond with "
        "valid structured output. Propose a request.")
    # the line precedes the slot line and matches no transcript pattern of the live tailer
    i = lines.index(diag[0])
    assert lines[i + 1].startswith("slot  1 round 1 RED brain_failure")
    for rx in (tailer.RE_MATCH, tailer.RE_SEED, tailer.RE_RESET, tailer.RE_SLOT, tailer.RE_FAILED):
        assert not rx.match(diag[0])


def test_no_diagnosis_for_instrument_failures_or_attacks(no_target, tmp_path):  # noqa: F811
    err = lc.Result(ok=False, text=None, usage=lc.Usage(0, 0, 0, 0), attempts=4,
                    stop_reason=None, error_type="timeout", error="timed out")
    client = ScriptClient([err, result(attack_json())])
    red = ai_red.AIRed(client, "deepseek-v4-pro", tmp_path, M, round_cap=2)
    lines: list[str] = []
    match_ops.run_traffic(M, tmp_path, [], [], Schedule(2, [], 1), settle=0,
                          log=lines.append, red_driver=match_ops.AIDriver(red))
    assert not [l for l in lines if l.startswith("red diagnosis:")]
