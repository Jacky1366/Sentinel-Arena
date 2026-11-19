"""Promote a TRAIN match's rules into the rule library (Stage 6.1, M1/M2, S6-3, D23, D26,
D30). Zero tokens, no network. The ONLY code path that writes a library file.

    .venv/bin/python tools/promote_rules.py --match data/runs/<train match> \
        --library data/library/rule_library_v0003.json [--seed 0]

Refuses (exit 2, nothing written) unless ALL of these hold (D26):
  - the folder is a frozen MATCH (match.json; a replay folder is never a source) with
    schema_version 0.8+, purpose "train", status completed, from a clean tree
    (git.dirty false), and every file it reads matches its match.json sha256
  - the match is not test data (not in config/test_set.json) and not a committed golden
    match (not under data/golden/)
  - pre-registration (D27): every sealed file in config/test_set.json has its sha256, the
    file on disk matches it, AND it exists with that hash at the match's recorded git
    commit (`git show <commit>:<path>`): no train match can predate the seal
  - claude Blue stored its rules (rules.jsonl + rule_results.jsonl present)
  - the D16 audit of the candidate source rounds is complete (D30: every candidate's source
    round audited valid or invalid; tools/audit_match.py scaffolds exactly those rounds)
  - the parent library loads (rules/library.py), this match was not promoted into its
    lineage yet, and promotion is in ascending match_id order
  - data/library/retention/<match_id>/ does not exist yet

Then (judge/variants.py, judge/retention.py, both pure) it writes, under
data/library/retention/<match_id>/: variants.jsonl, retention.jsonl, then the NEW library
file (library/writer.py: version = parent + 1, exclusive create, never overwrites), and
retention.json LAST. The holdout set is never opened (S6-1).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import run_match  # noqa: E402
from judge import JUDGE_VERSION, retention, rule_facts, variants  # noqa: E402
from library import writer  # noqa: E402
from rules import library as rule_library  # noqa: E402
from rules import normalize  # noqa: E402
from runner import match_ops  # noqa: E402
from tools import audit_match  # noqa: E402

TEST_SET = REPO / "config" / "test_set.json"
GOLDEN = REPO / "data" / "golden"
RETENTION_DIR = writer.LIBRARY_DIR / "retention"
FIXTURE_V2 = REPO / "benign" / "fixture_v2_offline.jsonl"
READS = ("proxy.jsonl", "red_attacks.jsonl", "rules.jsonl", "rule_results.jsonl")


def _schema(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((REPO / "schemas" / f"{name}.schema.json")
                                           .read_text(encoding="utf-8")))


VARIANT, ROW, MANIFEST, LINE, TS = (_schema("variant"), _schema("retention_row"),
                                    _schema("retention_manifest"), _schema("benign_holdout"),
                                    _schema("test_set"))


class Refused(Exception):
    """Not a promotable train match, or the library / outputs are not acceptable."""


def _rel(p: Path) -> str:
    try:
        return Path(p).resolve().relative_to(REPO).as_posix()
    except ValueError:
        return str(Path(p).resolve())


def _jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] \
        if p.is_file() else []


def _sha(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def git_show_sha256(commit: str, rel_path: str) -> str | None:
    """sha256 of a file as committed at `commit`, or None if it is not there."""
    r = subprocess.run(["git", "show", f"{commit}:{rel_path}"], cwd=REPO,
                       capture_output=True, check=False)
    return hashlib.sha256(r.stdout).hexdigest() if r.returncode == 0 else None


def check_match(match_dir: Path, test_set: dict) -> dict:
    """The match.json of a promotable train match. Raises Refused."""
    match_dir = match_dir.resolve()
    if (match_dir / "replay.json").exists():
        raise Refused(f"{match_dir} is a replay folder: a replay is never a library source "
                      f"(S6-3)")
    mpath = match_dir / "match.json"
    if not mpath.is_file():
        raise Refused(f"{match_dir} is not a frozen match (no match.json)")
    if match_dir == GOLDEN.resolve() or GOLDEN.resolve() in match_dir.parents:
        raise Refused(f"{match_dir} is under data/golden/: committed golden matches are never "
                      f"a library source (S6-1)")
    m = json.loads(mpath.read_text(encoding="utf-8"))
    errors = run_match.validate_manifest(m)
    if errors:
        raise Refused(f"{mpath} is schema-invalid: {errors}")
    if m.get("purpose") != "train":
        raise Refused(f"match {m['match_id']} has purpose {m.get('purpose')!r} (manifest "
                      f"{m['schema_version']}): only a train match can feed the library (D26)")
    if m["match_id"] in test_set["match_ids"]:
        raise Refused(f"match {m['match_id']} is test data (config/test_set.json)")
    if m["status"] != "completed":
        raise Refused(f"match status is {m['status']!r}: only a completed match is promoted")
    if m["git"]["dirty"]:
        raise Refused("the train match ran from a dirty tree (D26)")
    for name in READS:
        rec = m["artifacts"].get(name)
        if rec is None:
            raise Refused(f"{name} is not in the match (claude Blue with rules must have run)")
        if _sha(match_dir / name) != rec["sha256"]:
            raise Refused(f"{name}: sha256 differs from match.json (the frozen match changed)")
    return m


def check_seal(test_set: dict, commit: str) -> list[dict]:
    """Pre-registration (D27): every sealed file exists with its hash on disk and at the
    train match's commit. Returns [{path, sha256}]. Raises Refused."""
    out = []
    for s in test_set["sealed"]:
        if s["sha256"] is None:
            raise Refused(f"{s['path']} is not sealed yet (config/test_set.json): no train "
                          f"match is promoted before the seal (D27)")
        p = REPO / s["path"]
        if not p.is_file() or _sha(p) != s["sha256"]:
            raise Refused(f"{s['path']} on disk does not match its sealed sha256")
        if git_show_sha256(commit, s["path"]) != s["sha256"]:
            raise Refused(f"{s['path']} is not committed with its sealed sha256 at the train "
                          f"match's commit {commit[:12]}: the match predates the seal (D27)")
        out.append({"path": s["path"], "sha256": s["sha256"]})
    return out


def load_offline_fixture() -> list[dict]:
    rows = _jsonl(FIXTURE_V2)
    for r in rows:
        LINE.validate(r)
    return rows


def promote(match_dir: Path, library_path: Path, base_seed: int = 0,
            library_dir: Path | None = None, retention_dir: Path | None = None,
            test_set_path: Path = TEST_SET, audits: Path | None = None,
            golden_audits: Path | None = None, out=print) -> int:
    library_dir = library_dir or writer.LIBRARY_DIR
    retention_root = retention_dir or library_dir / "retention"
    try:
        test_set = json.loads(Path(test_set_path).read_text(encoding="utf-8"))
        TS.validate(test_set)
        m = check_match(match_dir, test_set)
        mid = m["match_id"]
        seal = check_seal(test_set, m["git"]["commit"])
        parent = rule_library.load(library_path, display=_rel(library_path))
        parent_doc = json.loads(Path(library_path).read_text(encoding="utf-8"))
        if mid in parent_doc["promoted_matches"]:
            raise Refused(f"match {mid} was already promoted into this library lineage")
        if parent_doc["promoted_matches"] and mid < parent_doc["promoted_matches"][-1]:
            raise Refused(f"match {mid} is older than the last promoted match "
                          f"{parent_doc['promoted_matches'][-1]} (ascending order)")
        target = Path(library_dir) / writer.file_name(parent.library_version + 1)
        if target.exists():
            raise Refused(f"{_rel(target)} already exists: promote from the newest library")
        out_dir = Path(retention_root) / mid
        if out_dir.exists():
            raise Refused(f"{_rel(out_dir)} already exists")
        rules = [r for r in _jsonl(match_dir / "rules.jsonl")]
        results = {r["rule_id"]: r for r in _jsonl(match_dir / rule_facts.RESULTS)}
        red = {a["request_id"]: a for a in _jsonl(match_dir / "red_attacks.jsonl")}
        proxy = {l["request_id"]: l for l in _jsonl(match_dir / "proxy.jsonl")
                 if l.get("request_id")}
        scope = audit_match.audit_scope(match_dir) or set()
        apath = audit_match.audit_path(mid, audits, golden_audits)
        audit = _jsonl(apath)
        if scope:
            if not audit:
                raise Refused(f"no audit at {_rel(apath)}: audit the candidate source rounds "
                              f"first (D30; tools/audit_match.py scaffold)")
            errors = audit_match.validate_rows(audit, mid, _jsonl(match_dir / "rounds.jsonl"),
                                               audit_match.scripted_rounds(match_dir), scope)
            if errors:
                raise Refused(f"{_rel(apath)}: {errors}")
            pending = sorted(a["round"] for a in audit if a["verdict"] == "unaudited")
            if pending:
                raise Refused(f"{_rel(apath)}: rounds {pending} are unaudited (D30)")
        by_round = {a["round"]: a["verdict"] for a in audit}
        # Scripted Red labels are designer-written ground truth: valid by construction (D16).
        by_round.update({r: "valid" for r in audit_match.scripted_rounds(match_dir)})
        offline = load_offline_fixture()
        fixture_v1, fx1_sha = rule_facts.load_fixture()
    except (Refused, ValueError, OSError, KeyError) as exc:
        out(f"REFUSED: {exc}")
        return 2

    # Variants, per source request (shared by rules with the same source).
    per_source: dict[str, list[variants.Variant]] = {}
    variant_rows: list[dict] = []
    candidates: list[retention.Candidate] = []
    for row in rules:
        rule = row["rule"]
        src = rule["source_request_id"]
        a = red.get(src)
        label = a["label"] if a else None
        if src not in per_source:
            per_source[src] = (variants.generate(proxy[src], label, base_seed, mid, src)
                               if a is not None and src in proxy and label in variants.BY_CWE
                               else [])
            variant_rows += [variants.row(v, mid, src, label, base_seed)
                             for v in per_source[src]]
        candidates.append(retention.Candidate(
            rule_row=row, result=results[rule["rule_id"]],
            source_round=a["round"] if a else None, source_label=label,
            audit_verdict=by_round.get(a["round"]) if a else None,
            variants=per_source[src]))
    corpus = [l for l in _jsonl(match_dir / "proxy.jsonl") if l.get("request_id")] \
        + fixture_v1 + offline + [v["request"] for v in variant_rows]
    rows = retention.decide(mid, candidates, parent, offline, corpus, base_seed)
    for r in variant_rows:
        VARIANT.validate(r)
    for r in rows:
        ROW.validate(r)

    out_dir.mkdir(parents=True)
    vpath, rpath = out_dir / "variants.jsonl", out_dir / "retention.jsonl"
    vpath.write_text("".join(json.dumps(r) + "\n" for r in variant_rows), encoding="utf-8")
    rpath.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    retained = [{"rule": c.rule_row["rule"],
                 "promoted_from": {"match_id": mid, "rule_id": c.rule_row["rule"]["rule_id"]},
                 "retention_ref": {"path": _rel(rpath), "line": i}}
                for i, (c, r) in enumerate(zip(candidates, rows), start=1)
                if r["decision"] == "retained"]
    fixtures = [{"path": _rel(rule_facts.FIXTURE), "sha256": fx1_sha},
                {"path": _rel(FIXTURE_V2), "sha256": _sha(FIXTURE_V2)}]
    doc = writer.next_doc(parent_doc, parent.path, parent.sha256, mid, retained,
                          match_ops.utc_now(), fixtures)
    for e, r in zip(doc["entries"][len(parent.entries):],
                    [r for r in rows if r["decision"] == "retained"]):
        if e["library_id"] != r["library_id"]:  # retention and writer must agree
            raise RuntimeError(f"library id mismatch {e['library_id']} vs {r['library_id']}")
    lib_path = writer.write(doc, library_dir)
    reasons: dict[str, int] = {}
    for r in rows:
        for x in r["reasons"]:
            reasons[x["code"]] = reasons.get(x["code"], 0) + 1
    manifest = {
        "schema_version": "0.1", "match_id": mid, "promoted_at": match_ops.utc_now(),
        "judge_version": JUDGE_VERSION,
        "normalization_version": normalize.NORMALIZATION_VERSION,
        "mutator_version": variants.MUTATOR_VERSION,
        "retention_version": retention.RETENTION_VERSION, "base_seed": base_seed,
        "match": {"path": _rel(match_dir), "match_json_sha256": _sha(match_dir / "match.json"),
                  "purpose": "train", "git_commit": m["git"]["commit"]},
        "audit": {"path": _rel(apath), "sha256": _sha(apath)} if audit else None,
        "parent_library": {"path": parent.path, "sha256": parent.sha256,
                           "library_version": parent.library_version},
        "fixtures": fixtures, "seal": seal,
        "outputs": {"variants": {"path": _rel(vpath), "sha256": _sha(vpath)},
                    "retention": {"path": _rel(rpath), "sha256": _sha(rpath)},
                    "library": {"path": _rel(lib_path), "library_version": doc["library_version"]}},
        "summary": {"candidates": len(rows),
                    "retained": sum(r["decision"] == "retained" for r in rows),
                    "rejected": sum(r["decision"] == "rejected" for r in rows),
                    "reasons": reasons, "variants": len(variant_rows),
                    "counting_variants": sum(r["counting"] for r in variant_rows)}}
    MANIFEST.validate(manifest)
    (out_dir / "retention.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                            encoding="utf-8")
    for r in rows:
        why = ", ".join(x["code"] for x in r["reasons"]) or ""
        out(f"{r['rule_id']} {r['cwe']:7} {r['decision']:8} {r['library_id'] or '':9} "
            f"variants {len(r['variants_blocked'])}/{len(r['variants_counting'])} blocked  "
            f"encoding {len(r['variants_encoding_blocked'])}/{len(r['variants_encoding'])}  {why}"
            + (f"  (behaves like {r['behavioural_duplicate_of']})"
               if r["behavioural_duplicate_of"] else ""))
    s = manifest["summary"]
    out(f"{mid}: {s['retained']} retained, {s['rejected']} rejected -> {_rel(lib_path)} "
        f"(v{doc['library_version']}, {len(doc['entries'])} rules)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--match", type=Path, required=True, help="frozen TRAIN match folder")
    ap.add_argument("--library", type=Path, required=True, help="the parent library file")
    ap.add_argument("--seed", type=int, default=0, help="mutator base seed (recorded)")
    args = ap.parse_args(argv)
    return promote(args.match, args.library, args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
