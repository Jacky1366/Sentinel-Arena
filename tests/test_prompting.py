"""agents/prompting.py: stable-prefix-first prompts (D11) and the JSON helper. Pure."""

from __future__ import annotations

import pytest

from llm_fakes import lc
from agents.prompting import PromptBuilder, parse_json

SYSTEM = "You are Blue. Classify each HTTP request as CWE-89, CWE-79, CWE-22 or benign."


def two_rounds():
    b = PromptBuilder(SYSTEM)
    b.add("user", "lines 1-20: GET /rest/products/search?q=apple")
    first = (b.render(), b.messages())
    b.add("assistant", '{"verdicts": []}')
    b.add("user", "lines 21-40: POST /rest/user/login")
    return first, (b.render(), b.messages())


def test_consecutive_rounds_share_a_byte_identical_prefix():
    (r1, m1), (r2, m2) = two_rounds()
    assert r2.startswith(r1) and len(r2) > len(r1)
    assert m2[:len(m1)] == m1


def test_provider_request_prefix_is_stable_too():
    # What the client sends: same system, history only grows at the end.
    (_, m1), (_, m2) = two_rounds()
    assert m2[0] == m1[0] and m2[-1]["content"].startswith("lines 21-40")


def test_messages_returns_a_copy_history_is_append_only():
    b = PromptBuilder(SYSTEM)
    b.add("user", "hello")
    b.messages()[0]["content"] = "tampered"
    b.messages().append({"role": "user", "content": "x"})
    assert b.messages() == [{"role": "user", "content": "hello"}]


@pytest.mark.parametrize("volatile", [
    "Match 20261109T153012Z-a1b2 begins.",
    "Legacy match m001.",
    "Now is 2026-11-09T15:30:12Z.",
    "Now is 2026-11-09 15:30.",
    "request 3f2b8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c",
])
def test_system_prompt_rejects_volatile_values(volatile):
    with pytest.raises(ValueError, match="volatile"):
        PromptBuilder(SYSTEM + " " + volatile)


def test_system_prompt_forbidden_strings():
    with pytest.raises(ValueError, match="forbidden"):
        PromptBuilder("Attack 127.0.0.1:8081", forbidden=("8081",))
    PromptBuilder("Attack 127.0.0.1:8080", forbidden=("8081",))


def test_turns_alternate_starting_with_user():
    b = PromptBuilder(SYSTEM)
    with pytest.raises(ValueError):
        b.add("assistant", "x")
    b.add("user", "x")
    with pytest.raises(ValueError):
        b.add("user", "y")
    with pytest.raises(ValueError):
        b.add("system", "y")


def test_prompt_hash_changes_with_any_byte():
    (_, m1), (_, m2) = two_rounds()
    assert lc.canonical_prompt("m", SYSTEM, m1) != lc.canonical_prompt("m", SYSTEM, m2)
    assert lc.canonical_prompt("m", SYSTEM, m1) == lc.canonical_prompt("m", SYSTEM, list(m1))


# ---- JSON helper ------------------------------------------------------------

@pytest.mark.parametrize("text,value", [
    ('{"verdict": "CWE-89"}', {"verdict": "CWE-89"}),
    ('```json\n{"verdict": "CWE-89"}\n```', {"verdict": "CWE-89"}),
    ('```\n{"a": 1}\n```', {"a": 1}),
    ('  ```JSON\n{"a": [1, 2]}\n```  ', {"a": [1, 2]}),
    ('Here you go:\n```json\n{"a": 1}\n```\nDone.', {"a": 1}),
])
def test_parse_json_accepts_plain_and_fenced(text, value):
    r = parse_json(text)
    assert r.ok and r.value == value and r.error is None


@pytest.mark.parametrize("text,fragment", [
    (None, "empty"),
    ("   ", "empty"),
    ("not json at all", "invalid JSON"),
    ('{"a": 1,}', "invalid JSON"),
    ("```json\n{broken\n```", "invalid JSON"),
    ("[1, 2]", "expected a JSON object"),
    ("```json\n{}\n```\n```json\n{}\n```", "2 fenced blocks"),
    ("[" * 100000 + "]" * 100000, "JSON"),
])
def test_parse_json_returns_structured_error_never_raises(text, fragment):
    r = parse_json(text)
    assert not r.ok and r.value is None and fragment in r.error


def test_parse_json_error_does_not_echo_the_text():
    r = parse_json("secret-looking-garbage {")
    assert "secret-looking-garbage" not in r.error


def test_parse_json_arrays_allowed_when_asked():
    assert parse_json("[1]", expect_object=False).value == [1]
