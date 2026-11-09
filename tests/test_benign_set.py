"""benign/benign_set.json: the designer-approved benign set, and its validator."""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from benign import send_benign  # noqa: E402
from red import scripted_red  # noqa: E402

DATA = json.loads(send_benign.BENIGN_SET.read_text())
CMAP = json.loads(send_benign.CHALLENGE_MAP.read_text())
ENTRIES = DATA["entries"]


def test_committed_set_is_valid():
    assert send_benign.validate_set(DATA, CMAP) == []
    assert send_benign.load_set()["set_version"] == "1"


def test_ids_unique_and_about_one_third_hard_negatives():
    ids = [e["benign_id"] for e in ENTRIES]
    assert len(ids) == len(set(ids)) == 17
    hard = sum(e["category"] == "hard_negative" for e in ENTRIES)
    assert 0.25 <= hard / len(ENTRIES) <= 0.45


def test_endpoints_are_the_ones_red_attacks_plus_registration():
    # Same endpoints Red attacks (login, search, /ftp, track-order). Registration
    # (n10) is the designer-approved exception that makes a 200 login benign too.
    def family(path):
        return "/ftp" if path.startswith("/ftp") else \
            "/rest/track-order" if path.startswith("/rest/track-order") else path
    red = {family(a["endpoint"]) for a in scripted_red.load_attacks()}
    benign = {family(e["endpoint"]) for e in ENTRIES}
    assert benign - red == {"/api/Users"}
    assert red <= benign


def test_register_precedes_login_and_requires_says_so():
    ids = [e["benign_id"] for e in ENTRIES]
    n11 = ENTRIES[ids.index("n11")]
    assert n11["requires"] == "n10" and ids.index("n10") < ids.index("n11")


def test_only_h06_expects_a_solve_and_it_is_unmapped():
    expecting = {e["benign_id"]: e["expected_solves"] for e in ENTRIES if e.get("expected_solves")}
    assert expecting == {"h06": ["Error Handling"]}
    mapped = {n for names in CMAP.values() for n in names}
    assert "Error Handling" not in mapped


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d["entries"][0].update(expected_solves=["Login Admin"]), "challenge_map"),
    (lambda d: d["entries"][1].update(benign_id="n01"), "duplicate"),
    (lambda d: d["entries"][0].update(requires="n11"), "not an earlier entry"),
    (lambda d: d["entries"][0].update(category="hard_negative"), "does not match"),
])
def test_validator_rejects(mutate, msg):
    d = copy.deepcopy(DATA)
    mutate(d)
    errors = send_benign.validate_set(d, CMAP)
    assert errors and any(msg in e for e in errors), errors
    p = REPO / "benign" / "benign_set.json"
    with pytest.raises(send_benign.BenignSetError):
        tmp = Path(__import__("tempfile").mkdtemp()) / "set.json"
        tmp.write_text(json.dumps(d))
        send_benign.load_set(tmp)
    assert p.exists()


def test_no_key_shaped_strings():
    text = send_benign.BENIGN_SET.read_text()
    assert not re.search(r"sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}", text)


def test_verification_record_matches_the_committed_set():
    rec = json.loads((REPO / "benign" / "verification.json").read_text())
    assert rec["set_sha256"] == send_benign.set_sha256()
    by_id = {r["benign_id"]: r for r in rec["results"]}
    assert set(by_id) == {e["benign_id"] for e in ENTRIES}
    assert all(r["solves_match"] for r in by_id.values())
    assert [i for i, r in by_id.items() if r["server_error"]] == ["h06"]
    assert by_id["n08"]["body_incomplete"] is True and by_id["n08"]["status"] == 200
    assert [q["benign_id"] for q in rec["known_target_quirks"]] == ["n08"]
