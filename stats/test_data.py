"""Which folders are TEST data (D59): the one check every scan over match or replay folders
uses before it opens anything else in a folder.

A folder is classified by its manifest, never by its name (D59; on 2026-11-24 a folder-name
filter opened ledgers in 9 test-set folders, because golden eval folders are not named by
match id):

  - test      match.json `match_id` is registered in config/test_set.json `match_ids`, or its
              `purpose` is in `test_purposes` (D35: an eval match is test data from the
              moment it exists, registered or not); or replay.json `source.match_id` is a
              registered test match (a replay carries its source's traffic).
  - not_test  a readable manifest that is none of the above.
  - unknown   no manifest (probe folders, live/), an unreadable or malformed one. Skipped by
              default: nothing proves it is not test data.

Only the manifest fields `match_id`, `purpose` and `source.match_id` are read. Pure reads,
no writes; imports nothing from library/, blue/, red/ or judge/.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEST_SET = REPO / "config" / "test_set.json"

TEST, NOT_TEST, UNKNOWN = "test", "not_test", "unknown"
KINDS = (TEST, NOT_TEST, UNKNOWN)


@dataclass(frozen=True)
class Registry:
    match_ids: frozenset[str]
    test_purposes: frozenset[str]
    sealed_paths: frozenset[str]


@dataclass(frozen=True)
class Verdict:
    kind: str
    match_id: str | None
    reason: str


@dataclass
class ScanPlan:
    folders: list[Path] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=lambda: {TEST: 0, UNKNOWN: 0})


def load_registry(path: Path = TEST_SET) -> Registry:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Registry(match_ids=frozenset(data["match_ids"]),
                    test_purposes=frozenset(data.get("test_purposes", [])),
                    sealed_paths=frozenset(s["path"] for s in data.get("sealed", [])))


def _manifest(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def classify(folder: Path, registry: Registry) -> Verdict:
    """The folder's kind, from its manifest only (never its name)."""
    folder = Path(folder)
    match_json, replay_json = folder / "match.json", folder / "replay.json"
    if replay_json.is_file():
        m = _manifest(replay_json)
        source = m.get("source") if m is not None else None
        sid = source.get("match_id") if isinstance(source, dict) else None
        if not isinstance(sid, str) or not sid:
            return Verdict(UNKNOWN, None, "replay.json unreadable or without source.match_id")
        if sid in registry.match_ids:
            return Verdict(TEST, sid, "replay of a registered test match")
        return Verdict(NOT_TEST, sid, "replay of an unregistered match")
    if match_json.is_file():
        m = _manifest(match_json)
        mid = m.get("match_id") if m is not None else None
        if not isinstance(mid, str) or not mid:
            return Verdict(UNKNOWN, None, "match.json unreadable or without match_id")
        if mid in registry.match_ids:
            return Verdict(TEST, mid, "match_id registered in config/test_set.json")
        purpose = m.get("purpose")
        if purpose in registry.test_purposes:
            return Verdict(TEST, mid, f"purpose {purpose!r} is test data by construction (D35)")
        return Verdict(NOT_TEST, mid, "unregistered match, non-test purpose")
    return Verdict(UNKNOWN, None, "no match.json or replay.json")


def scannable(folders, registry: Registry | None = None,
              allow_unknown: bool = False) -> ScanPlan:
    """The folders a scan may open, plus how many were skipped per kind. `unknown` folders
    are skipped unless allow_unknown (e.g. probe folders, which carry no manifest)."""
    registry = registry if registry is not None else load_registry()
    plan = ScanPlan()
    for folder in folders:
        kind = classify(folder, registry).kind
        if kind == NOT_TEST or (kind == UNKNOWN and allow_unknown):
            plan.folders.append(Path(folder))
        else:
            plan.skipped[kind] += 1
    return plan


def is_sealed(path: str | Path, registry: Registry | None = None) -> bool:
    """True for a sealed offline benign file (the holdout and fixture), repo-relative."""
    registry = registry if registry is not None else load_registry()
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(REPO)
        except ValueError:
            return False
    return p.as_posix() in registry.sealed_paths
