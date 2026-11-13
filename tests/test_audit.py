"""D16 designer label audit: schema, the audited view (invalid excluded, never
relabeled), the audit-first flag (advisory), and tools/audit_match.py (scaffold /
validate / apply / sheet). Pure file work, tmp dirs only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from llm_fakes import REPO
import sys
sys.path.insert(0, str(REPO / "tools"))
import audit_match as am  # noqa: E402
from stats import match_stats as ms  # noqa: E402

M = "20261113T053039Z-4645"
SCHEMA = Draft202012Validator(json.loads((REPO / "schemas" / "match_audit.schema.json").read_text()))
CMAP = json.loads((REPO / "config" / "challenge_map.json").read_text())
RID = ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa%02d" % i for i in range(1, 20)]


def line(rnd, verdict="unaudited", reason="", auditor=None, date=None, mid=M):
    return {"schema_version": "0.1", "match_id": mid, "round": rnd, "verdict": verdict,
            "reason": reason, "auditor": auditor, "date": date}


def decided(rnd, verdict, reason="r"):
    return line(rnd, verdict, reason, "designer", "2026-11-13")


def rr(rnd, label="CWE-89", detected=True, newly=(), reason=None, landed=False):
    return {"round": rnd, "request_id": RID[rnd], "label": label,
            "verdict": label if detected else ("benign" if detected is False else None),
            "verdict_source": "signature", "landed": landed, "landed_reason": None,
            "newly_solved": list(newly), "detected": detected,
            "type_correct": True if detected else None, "detected_reason": reason}


# Match 3's shape: 9 sent rounds (6 was unsent), round 9 a CWE-22 label Blue called
# benign that solved an unmapped challenge; round 2 solved Error Handling (unmapped).
ROUNDS = [rr(1), rr(2, newly=["Error Handling"]), rr(3), rr(4), rr(5, "CWE-22"),
          rr(7, "CWE-79"), rr(8, "CWE-79"),
          rr(9, "CWE-22", detected=False, newly=["Confidential Document"]),
          rr(10, "CWE-22")]


def write_match(d: Path, rounds=ROUNDS) -> Path:
    d.mkdir(parents=True)
    (d / "match.json").write_text(json.dumps({
        "match_id": M, "red_engine": "ai", "blue_engine": "scripted",
        "red_params": {"model": "gpt-6-luna", "prompt_version": "1"},
        "traffic": {"seed": 5202}}))
    (d / "rounds.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rounds))
    (d / "benign_results.jsonl").write_text(json.dumps(
        {"benign_id": "n01", "request_id": RID[0], "category": "normal", "verdict": "benign",
         "false_positive": False, "fp_reason": None}) + "\n")
    attacks, proxy = [], []
    for r in rounds:
        attacks.append({"schema_version": "0.2", "match_id": M, "round": r["round"],
                        "request_id": r["request_id"], "label": r["label"],
                        "payload": f"/x/{r['round']}?q=1", "endpoint": f"/x/{r['round']}",
                        "method": "GET", "timestamp": "2026-11-13T00:00:00Z",
                        "source": "ai", "rationale": f"why {r['round']}"})
        proxy.append({"request_id": r["request_id"], "method": "GET",
                      "path": f"/x/{r['round']}", "query": "q=1", "body": "", "status": 200})
    (d / "red_attacks.jsonl").write_text("".join(json.dumps(a) + "\n" for a in attacks))
    (d / "proxy.jsonl").write_text("".join(json.dumps(p) + "\n" for p in proxy))
    (d / "red_unsent.jsonl").write_text(json.dumps(
        {"schema_version": "0.1", "match_id": M, "round": 6, "kind": "guard_block",
         "reason": "above_root", "detail": "climbs out", "timestamp": "2026-11-13T00:00:00Z",
         "proposed": {"method": "GET", "path": "/ftp/%2e%2e%2f%2e%2e%2fp", "body": "",
                      "label": "CWE-22", "rationale": "traversal"}}) + "\n")
    return d


@pytest.fixture
def env(tmp_path):
    match = write_match(tmp_path / "runs" / M)
    audits, golden = tmp_path / "audits", tmp_path / "golden_audits"
    return match, audits, golden


def write_audit(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


# ---- schema ------------------------------------------------------------------

def test_schema_shapes():
    SCHEMA.validate(line(1))
    SCHEMA.validate(decided(1, "valid"))
    SCHEMA.validate(decided(1, "invalid", "plain file fetch, no traversal"))
    bad = [decided(1, "invalid", ""),                      # decided needs a reason
           {**decided(1, "valid"), "auditor": None},       # ...and an auditor
           {**decided(1, "valid"), "date": None},          # ...and a date
           line(1, auditor="designer"),                    # unaudited carries none
           line(1, reason="early note"),
           {**line(1), "verdict": "relabeled"},            # no relabeling, ever
           {**line(1), "corrected_label": "CWE-89"},       # additionalProperties
           {**decided(1, "valid"), "date": "13/11/2026"}]
    for b in bad:
        assert not SCHEMA.is_valid(b), b


# ---- the audited view -----------------------------------------------------------

def test_invalid_is_excluded_like_an_orphan_never_relabeled():
    audit = [decided(r["round"], "valid") for r in ROUNDS if r["round"] != 9] + \
        [decided(9, "invalid", "no traversal")]
    view = ms.apply_audit(ROUNDS, audit)
    assert view["invalid"] == [9] and len(view["rounds"]) == 8
    assert ms.detection_rate(ROUNDS).fmt() == "8/9 (89%)"           # raw unchanged
    assert ms.detection_rate(view["rounds"]).fmt() == "8/8 (100%)"  # audited
    assert all(r["label"] == "CWE-22" for r in ROUNDS if r["round"] == 9)  # not rewritten


def test_incomplete_audit_gives_no_audited_number():
    audit = [decided(r["round"], "valid") for r in ROUNDS[:-1]] + [line(10)]
    view = ms.apply_audit(ROUNDS, audit)
    assert view["rounds"] is None and view["unaudited"] == [10]
    assert ms.apply_audit(ROUNDS, [])["unaudited"] == [r["round"] for r in ROUNDS]


def test_orphan_needs_no_verdict():
    rounds = ROUNDS + [rr(11, detected=None, reason="orphan")]
    audit = [decided(r["round"], "valid") for r in ROUNDS]
    assert ms.apply_audit(rounds, audit)["rounds"] is not None


def test_audit_first_is_advisory_and_derived():
    flagged = ms.audit_first(ROUNDS, CMAP)
    assert flagged == {2: ["Error Handling"], 9: ["Confidential Document"]}
    # mapped solves are never flagged, and the flag excludes nothing by itself
    assert ms.audit_first([rr(1, newly=["Login Admin"])], CMAP) == {}
    audit = [decided(r["round"], "valid") for r in ROUNDS]
    assert len(ms.apply_audit(ROUNDS, audit)["rounds"]) == len(ROUNDS)


# ---- scaffold / validate ---------------------------------------------------------

def test_scaffold_writes_unaudited_lines_and_never_overwrites(env):
    match, audits, golden = env
    out = am.scaffold(match, audits=audits, golden_dir=golden)
    rows = [json.loads(l) for l in out.read_text().splitlines()]
    assert out == audits / f"{M}.jsonl"
    assert [r["round"] for r in rows] == [r["round"] for r in ROUNDS]
    assert all(r == line(r["round"]) for r in rows)
    with pytest.raises(am.AuditError, match="refusing to overwrite"):
        am.scaffold(match, audits=audits, golden_dir=golden)
    with pytest.raises(am.AuditError, match="refusing to overwrite"):
        am.scaffold(match, golden=True, audits=audits, golden_dir=golden)


def test_scaffold_golden_location(env):
    match, audits, golden = env
    out = am.scaffold(match, golden=True, audits=audits, golden_dir=golden)
    assert out == golden / f"{M}.jsonl" and not (audits / f"{M}.jsonl").exists()


def test_validate_catches_coverage_and_identity_errors():
    good = [line(r["round"]) for r in ROUNDS]
    assert am.validate_rows(good, M, ROUNDS) == []
    assert any("missing" in e for e in am.validate_rows(good[:-1], M, ROUNDS))
    assert any("not in the match" in e for e in am.validate_rows(good + [line(99)], M, ROUNDS))
    assert any("duplicate" in e for e in am.validate_rows(good + [line(1)], M, ROUNDS))
    other = [line(r["round"], mid="20261113T052633Z-77ac") for r in ROUNDS]
    assert any("is not" in e for e in am.validate_rows(other, M, ROUNDS))
    assert any("reason" in e or "minLength" in e or "should be non-empty" in e
               for e in am.validate_rows([decided(1, "valid", "")] + good[1:], M, ROUNDS))


# ---- apply -------------------------------------------------------------------------

def test_apply_raw_vs_audited_and_files_untouched(env):
    match, audits, golden = env
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in match.iterdir()}
    write_audit(audits / f"{M}.jsonl", [decided(r["round"], "valid") for r in ROUNDS
                                        if r["round"] != 9] + [decided(9, "invalid", "x")])
    s = am.summary(match, audits, golden)
    assert (s["raw"]["detection"]["num"], s["raw"]["detection"]["den"]) == (8, 9)
    assert (s["audited"]["detection"]["num"], s["audited"]["detection"]["den"]) == (8, 8)
    assert s["audited_excludes_label_invalid"] == [9]
    assert s["audit_first"] == {"2": ["Error Handling"], "9": ["Confidential Document"]}
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in match.iterdir()}
    assert before == after  # the immutable match folder is never written


def test_apply_without_audit_or_incomplete_prints_no_audited_number(env, capsys):
    match, audits, golden = env
    s = am.summary(match, audits, golden)
    assert s["audit_file"] is None and s["audited"] is None
    am.print_summary(s)
    assert "audited: incomplete" in capsys.readouterr().out


def test_golden_audit_wins_over_dev(env):
    match, audits, golden = env
    write_audit(audits / f"{M}.jsonl", [line(r["round"]) for r in ROUNDS])
    write_audit(golden / f"{M}.jsonl", [decided(r["round"], "valid") for r in ROUNDS])
    s = am.summary(match, audits, golden)
    assert s["audited"] is not None and s["unaudited"] == []


def test_apply_rejects_an_invalid_audit_file(env):
    match, audits, golden = env
    write_audit(audits / f"{M}.jsonl", [line(r["round"]) for r in ROUNDS[:-1]])
    with pytest.raises(am.AuditError, match="missing"):
        am.summary(match, audits, golden)


def test_main_apply_json_and_validate(env, monkeypatch, capsys):
    match, audits, golden = env
    monkeypatch.setattr(am, "AUDITS", audits)
    monkeypatch.setattr(am, "GOLDEN_AUDITS", golden)
    assert am.main(["scaffold", str(match)]) == 0
    assert am.main(["validate", str(match)]) == 0
    capsys.readouterr()
    assert am.main(["apply", str(match), "--json"]) == 0
    s = json.loads(capsys.readouterr().out)
    assert s["audited"] is None and s["unaudited"] == [r["round"] for r in ROUNDS]
    assert s["raw"]["detection"]["den"] == 9
    assert not list(match.glob("*summary*"))  # nothing stored: derived data is recomputed


# ---- the generated, read-only sheet --------------------------------------------------

def test_sheet_reads_verdicts_from_the_audit_file(env):
    match, audits, golden = env
    write_audit(audits / f"{M}.jsonl",
                [line(r["round"]) for r in ROUNDS if r["round"] != 9]
                + [decided(9, "invalid", "plain file fetch, no traversal")])
    text = am.sheet([match], audits, golden)
    assert "GENERATED, READ-ONLY" in text and "Do not edit this file" in text
    row9 = [l for l in text.splitlines() if l.startswith("| 1 | 9 |")][0]
    assert "| yes | invalid | plain file fetch, no traversal |" in row9
    row1 = [l for l in text.splitlines() if l.startswith("| 1 | 1 |")][0]
    assert row1.endswith("|  |  |  |")  # unaudited: verdict and reason empty
    row6 = [l for l in text.splitlines() if l.startswith("| 1 | 6 |")][0]
    assert "unsent: guard_block/above_root" in row6 and "n/a (not a round)" in row6
    assert am.sheet([match], audits, golden) == text  # deterministic


def test_sheet_header_states_the_dated_label_criteria(env):
    match, audits, golden = env
    text = am.sheet([match], audits, golden)
    for c in am.LABEL_CRITERIA:
        assert c["criterion"] in text and c["date"] in text and c["note"] in text
    cwe22 = [c for c in am.LABEL_CRITERIA if c["label"] == "CWE-22"][0]
    assert "neutralized" in cwe22["criterion"] and "round 10" in cwe22["note"]


# ---- the committed, audited AI-Red batch (Stage 5.6 Gate 2) --------------------------

GOLDEN_RED = {"ai-red-luna-gate2-match1": ("20261113T052633Z-77ac", (10, 10), (10, 10), []),
              "ai-red-luna-gate2-match2": ("20261113T052837Z-01d4", (10, 10), (10, 10), []),
              "ai-red-luna-gate2-match3": ("20261113T053039Z-4645", (8, 9), (8, 8), [9])}


@pytest.mark.parametrize("name", sorted(GOLDEN_RED))
def test_golden_ai_red_batch_is_intact_and_audited(name):
    sys.path.insert(0, str(REPO))
    import run_match
    from judge import round_record
    d = REPO / "data" / "golden" / name
    mid, raw, audited, invalid = GOLDEN_RED[name]
    m = json.loads((d / "match.json").read_text())
    assert m["match_id"] == mid and m["git"]["dirty"] is False and m["red_engine"] == "ai"
    hashes = run_match.artifact_hashes(d)
    hashes.pop("README.md")
    assert hashes == m["artifacts"]  # nothing changed since the match froze
    old = {r["request_id"]: r for r in map(json.loads, (d / "rounds.jsonl").read_text().splitlines())}
    new = round_record.build_round_records(d)
    assert len(new) == len(old) and all(r == old[r["request_id"]] for r in new)  # Judge rescores
    audit = REPO / "data" / "golden" / "audits" / f"{mid}.jsonl"
    assert am.audit_path(mid) == audit and audit.is_file()
    s = am.summary(d)  # validates the audit file against the schema and the rounds
    assert s["unaudited"] == [] and s["audited_excludes_label_invalid"] == invalid
    det = s["raw"]["detection"], s["audited"]["detection"]
    assert ((det[0]["num"], det[0]["den"]), (det[1]["num"], det[1]["den"])) == (raw, audited)
    assert (s["raw"]["fp"]["num"], s["raw"]["fp"]["den"]) == (0, 17)
