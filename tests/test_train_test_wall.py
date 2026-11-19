"""The train / test wall (Stage 6.1, S6-1, S6-3, D26), checked structurally:

  - the ONE library writer (library/writer.py) is imported only by tools/promote_rules.py,
    and nothing reachable from the in-match / replay code paths imports it: a match or a
    replay has no writer to call, in any mode (S6-3)
  - the read side (rules/library.py) has no write call at all
  - no library file's provenance names test data: every promoted match is outside
    config/test_set.json and, where its folder is present, is a purpose-train match (S6-1)
  - config/test_set.json lists exactly the audited AI-Red golden matches
  - selection code (retention, variants, the writer) never names the holdout
Pure file and AST reads."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from llm_fakes import REPO
from rules import library as rule_library  # noqa: E402

ENTRY_POINTS = ["run_match.py", "tools/replay_blue.py", "blue/run_blue.py",
                "blue/claude_engine.py", "blue/rule_invention.py", "judge/rule_verdicts.py",
                "judge/fact2_detected.py", "judge/round_record.py", "judge/rule_facts.py",
                "runner/match_ops.py"]
WRITER_MODULES = {"library", "library.writer", "tools.promote_rules"}
TEST_SET = json.loads((REPO / "config" / "test_set.json").read_text())


def _module_file(name: str) -> Path | None:
    base = REPO.joinpath(*name.split("."))
    for p in (base.with_suffix(".py"), base / "__init__.py"):
        if p.is_file():
            return p
    return None


def _imports(path: Path) -> set[str]:
    """Repo-local modules imported anywhere in a file (also inside functions)."""
    out: set[str] = set()
    for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(n, ast.Import):
            names = [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            names = [n.module] + [f"{n.module}.{a.name}" for a in n.names]
        else:
            continue
        out |= {x for x in names if _module_file(x) is not None}
    return out


def closure(start: list[str]) -> set[str]:
    seen: set[str] = set()
    todo = [p.removesuffix(".py").replace("/", ".") for p in start]
    while todo:
        m = todo.pop()
        if m in seen:
            continue
        seen.add(m)
        f = _module_file(m)
        if f is not None:
            todo += sorted(_imports(f) - seen)
    return seen


def test_no_in_match_or_replay_code_can_reach_the_writer():
    reach = closure(ENTRY_POINTS)
    assert "rules.library" in reach  # they DO read libraries
    assert not reach & WRITER_MODULES, sorted(reach & WRITER_MODULES)


def test_only_promote_rules_imports_the_writer():
    users = []
    for f in sorted(REPO.rglob("*.py")):
        rel = f.relative_to(REPO).as_posix()
        if rel.startswith((".venv/", "tests/", "library/")):
            continue
        if {"library", "library.writer"} & _imports(f):
            users.append(rel)
    assert users == ["tools/promote_rules.py"]


WRITE_CALLS = {"write_text", "write_bytes", "mkdir", "unlink", "rename", "replace", "touch",
               "rmdir", "chmod", "copyfile", "copy", "move", "dump"}


def test_the_read_side_has_no_write_path():
    tree = ast.parse((REPO / "rules" / "library.py").read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            fn = n.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            assert name not in WRITE_CALLS, name
            if name == "open":
                modes = [a.value for a in n.args[1:2] if isinstance(a, ast.Constant)]
                modes += [k.value.value for k in n.keywords
                          if k.arg == "mode" and isinstance(k.value, ast.Constant)]
                assert all(set(m) <= set("rb") for m in modes), modes


def _library_files() -> list[Path]:
    return sorted({*REPO.glob("data/library/rule_library_v*.json"),
                   *REPO.glob("data/golden/**/rule_library_v*.json")})


@pytest.mark.parametrize("path", _library_files(), ids=lambda p: p.relative_to(REPO).as_posix())
def test_no_library_was_built_from_test_data(path):
    """The leak test: fails if any library file present names a test match, or a match
    whose own manifest is not purpose train."""
    rule_library.load(path)
    doc = json.loads(path.read_text())
    test_ids = set(TEST_SET["match_ids"])
    for mid in doc["promoted_matches"]:
        assert mid not in test_ids, f"{path.name} was built from test match {mid}"
        for folder in (*REPO.glob(f"data/runs/{mid}"), *REPO.glob("data/golden/**/match.json")):
            mpath = folder / "match.json" if folder.is_dir() else folder
            if mpath.is_file() and json.loads(mpath.read_text()).get("match_id") == mid:
                assert json.loads(mpath.read_text()).get("purpose") == "train", mid
    for e in doc["entries"]:
        assert e["promoted_from"]["match_id"] not in test_ids
        assert e["rule"]["created_match"] not in test_ids


def test_the_test_set_is_exactly_the_audited_ai_red_golden_matches():
    """Every committed AI-Red golden match is TEST data, except the committed TRAIN
    evidence (purpose "train", Stage 6.1b Gate 1), which is train data by definition. The
    Stage 6.3 eval matches (purpose "eval") are TEST data by purpose (D35)."""
    ai_red = set()
    for m in REPO.glob("data/golden/*/match.json"):
        doc = json.loads(m.read_text())
        if doc.get("red_engine") == "ai" and doc.get("purpose") != "train":
            ai_red.add(doc["match_id"])
            assert (REPO / "data" / "golden" / "audits" / f"{doc['match_id']}.jsonl").is_file()
    # 6 audited AI-Red golden matches (5.6 Gate 2, 5.7 Gate 3) + 3 eval matches (6.3 Gate B)
    # + 3 eval matches (6.3 Gate B-deepseek) + 3 eval matches (6.3 Gate B-evasion)
    assert set(TEST_SET["match_ids"]) == ai_red and len(ai_red) == 15
    assert {s["path"] for s in TEST_SET["sealed"]} == {"benign/holdout_v1.jsonl",
                                                       "benign/fixture_v2_offline.jsonl"}


@pytest.mark.parametrize("rel", ["judge/retention.py", "judge/variants.py", "library/writer.py"])
def test_selection_code_never_names_the_holdout(rel):
    src = (REPO / rel).read_text(encoding="utf-8")
    code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
    tree = ast.parse(code)
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
               and isinstance(n.value, str)]
    doc = ast.get_docstring(tree, clean=False) or ""
    assert not any("holdout" in s for s in strings if s != doc)
