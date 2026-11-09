"""Score a rules file against a FROZEN match: Judge facts 3 and 4b (Stage 5.3).

    .venv/bin/python tools/score_rules.py --rules <rules.json> \
        --match data/golden/scripted-baseline-benign-match --out <new dir>

Writes into --out ONLY (which must not exist yet, or be an empty directory, and
must not be or lie inside a match folder): rule_results.jsonl, anomalies.jsonl and,
last, rule_score.json. Frozen match artifacts are immutable: this tool never
writes into a match folder. Every line is schema-validated before anything is
written. Exit 0 on success, 2 on bad input or a refused output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from judge import JUDGE_VERSION, rule_facts  # noqa: E402
from rules import normalize  # noqa: E402

FIXTURE = REPO / "benign" / "fixture_v1.jsonl"
SCHEMAS = REPO / "schemas"


class Refused(Exception):
    """The input or output location is not acceptable."""


def _jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return str(p)


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((SCHEMAS / f"{name}.schema.json").read_text(
        encoding="utf-8")))


def check_out_dir(out: Path) -> None:
    """Refuse any output directory that is, or is inside, a match folder (a
    directory holding match.json), or that already has content."""
    out = out.resolve()
    for d in (out, *out.parents):
        if (d / "match.json").exists():
            raise Refused(f"refusing to write into match folder {d}: frozen match "
                          f"artifacts are immutable")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise Refused(f"refusing to write into {out}: it exists and is not an empty directory")


def load_match(match_dir: Path) -> rule_facts.MatchView:
    manifest_path = match_dir / "match.json"
    if not manifest_path.is_file():
        raise Refused(f"{match_dir} is not a frozen match (no match.json)")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return rule_facts.MatchView(
        match_id=manifest["match_id"],
        red_labels={r["request_id"]: r["label"] for r in _jsonl(match_dir / "red_attacks.jsonl")},
        benign_ids={b["request_id"]: b["benign_id"]
                    for b in _jsonl(match_dir / "benign_requests.jsonl")},
        proxy={l["request_id"]: l for l in _jsonl(match_dir / "proxy.jsonl")
               if l.get("request_id")})


def load_rules(path: Path) -> list:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not (isinstance(data, dict) and data.get("schema_version") == "0.1"
            and isinstance(data.get("rules"), list)):
        raise Refused(f"{path} is not a rules file (need {{schema_version: '0.1', rules: [...]}}); "
                      f"individual rules may be invalid, the wrapper may not")
    return data["rules"]


def run(rules_path: Path, match_dir: Path, out: Path, fixture_path: Path = FIXTURE,
        now=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        ) -> dict:
    check_out_dir(out)
    rules = load_rules(rules_path)
    match = load_match(match_dir)
    fixture = _jsonl(fixture_path)
    for f in fixture:
        _validator("benign_fixture").validate(f)
    fx_sha = _sha(fixture_path)
    results, anomalies = rule_facts.score(rules, match, fixture, fx_sha)
    for row in results:
        _validator("rule_result").validate(row)
    for row in anomalies:
        _validator("anomaly").validate(row)
    meta_path = fixture_path.with_name(fixture_path.name.replace(".jsonl", ".meta.json"))
    version = json.loads(meta_path.read_text(encoding="utf-8"))["fixture_version"] \
        if meta_path.is_file() else "unversioned"
    manifest = {
        "schema_version": "0.1", "match_id": match.match_id,
        "match_json_sha256": _sha(match_dir / "match.json"),
        "rules": {"path": _rel(rules_path), "sha256": _sha(rules_path), "count": len(rules)},
        "fixture": {"path": _rel(fixture_path), "version": version, "sha256": fx_sha,
                    "entries": len(fixture)},
        "judge_version": JUDGE_VERSION,
        "normalization_version": normalize.NORMALIZATION_VERSION,
        "re2_version": importlib.metadata.version("google-re2"),
        "scored_at": now(),
        "summary": {
            "valid": sum(r["valid"] for r in results),
            "invalid": sum(not r["valid"] for r in results),
            "replay_fires": sum(r["replay_fires"] is True for r in results),
            "replay_misses": sum(r["replay_fires"] is False for r in results),
            "replay_null": sum(r["replay_fires"] is None for r in results),
            "rules_with_fixture_hits": sum(bool(r["fixture_fires"]) for r in results),
            "anomalies": len(anomalies)}}
    _validator("rule_score").validate(manifest)
    out.mkdir(parents=True, exist_ok=True)
    for name, rows in (("rule_results.jsonl", results), ("anomalies.jsonl", anomalies)):
        (out / name).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (out / "rule_score.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rules", type=Path, required=True)
    ap.add_argument("--match", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--fixture", type=Path, default=FIXTURE)
    args = ap.parse_args(argv)
    try:
        m = run(args.rules, args.match, args.out, args.fixture)
    except (Refused, OSError, ValueError) as exc:
        print(f"REFUSED: {exc}")
        return 2
    for r in _jsonl(args.out / "rule_results.jsonl"):
        why = ",".join(x["code"] for x in r["invalid_reasons"])
        print(f"{r['rule_index']:>2} {str(r['rule_id']):6} valid={str(r['valid']):5} "
              f"replay={str(r['replay_fires']):5} {str(r['replay_reason'] or ''):16} "
              f"cwe_ok={str(r['cwe_matches_source']):5} fixture={r['fixture_benign_ids']} {why}")
    for a in _jsonl(args.out / "anomalies.jsonl"):
        print(f"ANOMALY {a['kind']} {a['request_id'][:8]} {a['detail']}")
    print(f"summary {m['summary']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
