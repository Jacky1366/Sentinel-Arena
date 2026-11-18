"""rules/paths.py: the single above-root predicate (Stage 6.1, D32). Pure, no network."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from llm_fakes import REPO
from rules import paths

ABOVE = ["/../etc/passwd", "/a/../../x", "/%2e%2e/%2e%2e/etc/passwd",
         "/ftp/..%2f..%2fetc/passwd", "/a/%2e%2e/%2e%2e/%2e%2e/b", "/%252e%252e/x"]
INSIDE = ["/a/../b", "/a/b/../c", "/./a", "/ftp/../ftp/x", "/ftp/..%2fftp%2flegal.md",
          "/rest/products/search?q=../../../x", "/", ""]


@pytest.mark.parametrize("path", ABOVE)
def test_above_root(path):
    assert paths.above_root(path)


@pytest.mark.parametrize("path", INSIDE)
def test_inside_root(path):
    assert not paths.above_root(path)


def test_red_guard_uses_the_single_definition():
    """red_guard defines no predicate of its own: it calls rules.paths.above_root."""
    tree = ast.parse((REPO / "red" / "red_guard.py").read_text(encoding="utf-8"))
    defs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert not any("root" in d for d in defs)
    assert "paths.above_root(" in (REPO / "red" / "red_guard.py").read_text(encoding="utf-8")
    assert "paths.above_root(" in (REPO / "tools" / "verify_red_guard.py").read_text(
        encoding="utf-8")


def test_judge_never_imports_red():
    for f in sorted((REPO / "judge").glob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            names = ([a.name for a in n.names] if isinstance(n, ast.Import) else
                     [n.module or ""] if isinstance(n, ast.ImportFrom) else [])
            assert not any(x == "red" or x.startswith("red.") for x in names), f.name
