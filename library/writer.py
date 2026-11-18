"""The ONE writer of rule library files (Stage 6.1, D20, D26, S6-3).

Imported only by tools/promote_rules.py (tested). A library file is immutable: every
promotion writes a NEW file `rule_library_vNNNN.json` (version = parent + 1) with an
exclusive create, so an existing version can never be overwritten, and no file is ever
deleted. Version 0 is the empty library (`empty_doc`).

The document is checked with the read side's own checks (rules/library.py `check`)
before anything is written, so the writer can never produce a file the reader rejects.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from judge import JUDGE_VERSION
from rules import library as rule_library
from rules import normalize

REPO = Path(__file__).resolve().parent.parent
LIBRARY_DIR = REPO / "data" / "library"
GOLDEN = REPO / "data" / "golden"


def file_name(version: int) -> str:
    return f"rule_library_v{version:04d}.json"


def _versions() -> dict:
    from judge import retention, variants  # late: keeps the writer's import graph small
    return {"judge_version": JUDGE_VERSION,
            "normalization_version": normalize.NORMALIZATION_VERSION,
            "mutator_version": variants.MUTATOR_VERSION,
            "retention_version": retention.RETENTION_VERSION}


def empty_doc(created_at: str) -> dict:
    """Library version 0: no parent, no entries, no promoted matches."""
    doc = {"schema_version": "0.1", "library_version": 0, "parent": None,
           "created_at": created_at, **_versions(), "fixtures": [],
           "promoted_matches": [], "entries": []}
    rule_library.check(doc)
    return doc


def next_doc(parent_doc: dict, parent_path: str, parent_sha256: str, match_id: str,
             retained: list[dict], created_at: str, fixtures: list[dict]) -> dict:
    """The next library version: the parent's entries unchanged, then `retained` (each
    {rule, promoted_from, retention_ref}) as new entries with the next library ids. The
    promoted match is appended to promoted_matches (even with no retained rule)."""
    version = parent_doc["library_version"] + 1
    if match_id in parent_doc["promoted_matches"]:
        raise ValueError(f"match {match_id} was already promoted into this lineage")
    if parent_doc["promoted_matches"] and match_id < parent_doc["promoted_matches"][-1]:
        raise ValueError(f"match {match_id} is older than the last promoted match "
                         f"{parent_doc['promoted_matches'][-1]}: promotion is in ascending "
                         f"match_id order")
    entries = [dict(e) for e in parent_doc["entries"]]
    for r in retained:
        entries.append({"library_id": f"lib-{len(entries) + 1:04d}",
                        "canonical_sha256": rule_library.canonical_sha256(r["rule"]),
                        "rule": r["rule"], "promoted_from": r["promoted_from"],
                        "promoted_in_version": version, "retention_ref": r["retention_ref"]})
    doc = {"schema_version": "0.1", "library_version": version,
           "parent": {"path": parent_path, "sha256": parent_sha256,
                      "library_version": parent_doc["library_version"]},
           "created_at": created_at, **_versions(), "fixtures": fixtures,
           "promoted_matches": [*parent_doc["promoted_matches"], match_id],
           "entries": entries}
    rule_library.check(doc)
    return doc


def write(doc: dict, library_dir: Path = LIBRARY_DIR) -> Path:
    """Write a NEW library file; never overwrites (exclusive create). Refuses any
    location under data/golden/ (committed evidence is never written)."""
    rule_library.check(doc)
    library_dir = Path(library_dir).resolve()
    if library_dir == GOLDEN.resolve() or GOLDEN.resolve() in library_dir.parents:
        raise ValueError(f"refusing to write a library under {GOLDEN}")
    library_dir.mkdir(parents=True, exist_ok=True)
    path = library_dir / file_name(doc["library_version"])
    data = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
    with path.open("xb") as fh:  # FileExistsError: a version is never overwritten
        fh.write(data)
    return path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
