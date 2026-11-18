"""The rule library, READ-ONLY side (Stage 6.1, D20, D21, D26). PURE apart from reading
one file.

A library file (`data/library/rule_library_vNNNN.json`, schemas/rule_library.schema.json)
is Blue's cross-match rule memory. This module can only READ and check one: it has no
write path at all. The one writer is library/writer.py, imported only by
tools/promote_rules.py (train matches only, S6-3), so any code that imports only this
module (run_match.py, tools/replay_blue.py, blue/, judge/rule_verdicts.py) cannot change a
library by construction (tested in tests/test_train_test_wall.py).

Also here, because the writer and the checks must agree byte for byte:

  canonical(rule)         the dedup form (D25): cwe + conditions sorted by
                          (field, op, pattern, case_insensitive); contains / equals
                          patterns lowercased when case_insensitive (the engine
                          lowercases them anyway); a regex pattern is NEVER rewritten
                          (lowercasing would turn \\S into \\s)
  canonical_sha256(rule)  sha256 of the canonical JSON (sorted keys, no spaces)

Lives in the neutral rules/ package: Blue's body loads a library to preload its rules,
the Judge loads the same snapshot to cross-check rule verdicts. Any behaviour change here
is governed by judge.JUDGE_VERSION.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from rules import validator

LIBRARY_ID = re.compile(r"^lib-[0-9]{4,}$")
MAX_ENTRIES = 50
SNAPSHOT = "library.json"  # the copy inside a match / replay folder

_SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"


def _schema(name: str) -> dict:
    return json.loads((_SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8"))


_REGISTRY = Registry().with_resources(
    [(s["$id"], Resource.from_contents(s)) for s in (_schema("rule"),)])
SCHEMA = Draft202012Validator(_schema("rule_library"), registry=_REGISTRY)


class LibraryError(ValueError):
    """The file is not a valid, self-consistent rule library."""


@dataclass(frozen=True)
class LibraryRule:
    library_id: str
    validated: validator.Validated

    @property
    def cwe(self) -> str:
        return self.validated.rule["cwe"]


@dataclass(frozen=True)
class Library:
    path: str
    sha256: str
    library_version: int
    entries: tuple[LibraryRule, ...]

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        """A loaded library is always "present", even with no entries (v0000 is a real,
        explicitly loaded library, not the absence of one: M5's empty arm, D29)."""
        return True

    def params(self) -> dict:
        """The provenance block recorded in match.json / replay.json blue_params.library."""
        return {"path": self.path, "sha256": self.sha256,
                "library_version": self.library_version, "entries": len(self.entries)}


def canonical(rule: dict) -> dict:
    conds = []
    for c in rule["conditions"]:
        pat = c["pattern"]
        if c["case_insensitive"] and c["op"] in ("contains", "equals"):
            pat = pat.lower()
        conds.append({"field": c["field"], "op": c["op"], "pattern": pat,
                      "case_insensitive": c["case_insensitive"]})
    conds.sort(key=lambda c: (c["field"], c["op"], c["pattern"], c["case_insensitive"]))
    return {"cwe": rule["cwe"], "conditions": conds}


def canonical_sha256(rule: dict) -> str:
    text = json.dumps(canonical(rule), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check(doc: dict) -> list[LibraryRule]:
    """Validate a parsed library document completely; returns its rules in order.
    Raises LibraryError on any problem (the schema, a rule the validator rejects, a
    duplicate or out-of-order library_id, a wrong canonical hash, a duplicate canonical
    form, or a promotion version newer than the library)."""
    errors = [e.message for e in SCHEMA.iter_errors(doc)]
    if errors:
        raise LibraryError(f"schema-invalid library: {errors}")
    out: list[LibraryRule] = []
    seen_ids: set[str] = set()
    seen_canon: dict[str, str] = {}
    for i, e in enumerate(doc["entries"]):
        lid = e["library_id"]
        if lid in seen_ids:
            raise LibraryError(f"duplicate library_id {lid}")
        if int(lid.split("-")[1]) != i + 1:
            raise LibraryError(f"entry {i} has library_id {lid}: ids are lib-0001, "
                               f"lib-0002, ... in promotion order")
        seen_ids.add(lid)
        v = validator.validate_rule(i, e["rule"], set())  # rule_ids repeat across matches
        if not v.valid:
            raise LibraryError(f"{lid}: rule rejected by the validator: "
                               f"{[r['code'] for r in v.reasons]}")
        canon = canonical_sha256(e["rule"])
        if canon != e["canonical_sha256"]:
            raise LibraryError(f"{lid}: canonical_sha256 does not match its rule")
        if canon in seen_canon:
            raise LibraryError(f"{lid}: exact duplicate of {seen_canon[canon]}")
        seen_canon[canon] = lid
        if e["promoted_in_version"] > doc["library_version"]:
            raise LibraryError(f"{lid}: promoted_in_version {e['promoted_in_version']} > "
                               f"library_version {doc['library_version']}")
        out.append(LibraryRule(lid, v))
    if sorted(doc["promoted_matches"]) != doc["promoted_matches"]:
        raise LibraryError("promoted_matches is not in ascending match_id order")
    for lr, e in zip(out, doc["entries"]):
        if e["promoted_from"]["match_id"] not in doc["promoted_matches"]:
            raise LibraryError(f"{lr.library_id}: promoted from "
                               f"{e['promoted_from']['match_id']}, which is not in "
                               f"promoted_matches")
        if e["rule"]["created_match"] != e["promoted_from"]["match_id"]:
            raise LibraryError(f"{lr.library_id}: rule created_match is not its "
                               f"promoted_from match")
    if doc["library_version"] == 0 and (out or doc["parent"] is not None
                                        or doc["promoted_matches"]):
        raise LibraryError("library version 0 is the empty library with no parent")
    if doc["library_version"] > 0 and doc["parent"] is None:
        raise LibraryError("a library version > 0 needs its parent")
    return out


def load(path: Path, display: str | None = None) -> Library:
    """Read and check one library file. `display` is the path recorded in provenance
    (default: the path as given)."""
    data = Path(path).read_bytes()
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LibraryError(f"{path}: not JSON: {exc}") from exc
    rules = check(doc)
    return Library(display or str(path), hashlib.sha256(data).hexdigest(),
                   doc["library_version"], tuple(rules))
