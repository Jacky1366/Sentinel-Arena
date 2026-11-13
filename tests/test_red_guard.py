"""red/red_guard.py: the rules of engagement (Stage 5.6, D15). Pure, no network."""

from __future__ import annotations

import pytest

from llm_fakes import REPO  # noqa: F401  (adds repo to sys.path)
from red import red_guard as rg


def ok(method="GET", path="/rest/products/search?q=1", body="", label="CWE-89"):
    return rg.check(method, path, body, label)


def test_a_normal_request_passes():
    assert ok().ok
    assert ok(method="POST", path="/rest/user/login", body='{"email":"a"}', label="CWE-89").ok
    # Traversal that stays inside the web root is allowed (CWE-22 is a category).
    assert ok(path="/ftp/coupons.md.bak", label="CWE-22").ok
    assert ok(path="/ftp/..%2fftp%2flegal.md", label="CWE-22").ok  # resolves inside root


@pytest.mark.parametrize("label", ["benign", "CWE-78", "XSS", ""])
def test_invalid_label(label):
    r = ok(label=label)
    assert not r.ok and r.reason == "invalid_label"


@pytest.mark.parametrize("method", ["PUT", "DELETE", "HEAD", "get", "TRACE"])
def test_method_not_allowed(method):
    r = ok(method=method)
    assert not r.ok and r.reason == "method_not_allowed"


@pytest.mark.parametrize("path", [
    "http://evil.example/x",       # scheme + host
    "https://127.0.0.1:8081/x",    # scheme + host + port
    "//evil.example/x",            # authority only
    "rest/products",               # no leading slash
    "/\\x",                        # backslash, read as authority by some parsers
])
def test_scope_violation(path):
    r = ok(path=path)
    assert not r.ok and r.reason in ("scope_violation", "invalid_encoding")
    # the clearly-authority cases are scope, never silently allowed
    if path.startswith(("http", "//")) or not path.startswith("/"):
        assert r.reason == "scope_violation"


@pytest.mark.parametrize("path", ["/a b", "/a%2", "/a%zz", "/a\tb", "/café"])
def test_invalid_encoding(path):
    r = ok(path=path)
    assert not r.ok and r.reason == "invalid_encoding"


@pytest.mark.parametrize("path", [
    "/../etc/passwd",
    "/a/../../x",
    "/%2e%2e/%2e%2e/etc/passwd",      # encoded ..
    "/ftp/..%2f..%2fetc/passwd",      # Juice Shop shape that climbs out
    "/a/%2e%2e/%2e%2e/%2e%2e/b",
])
def test_above_root_blocked(path):
    r = ok(path=path, label="CWE-22")
    assert not r.ok and r.reason == "above_root"


@pytest.mark.parametrize("path", ["/a/../b", "/a/b/../c", "/./a", "/ftp/../ftp/x"])
def test_dot_segments_that_stay_in_root_are_allowed(path):
    assert ok(path=path, label="CWE-22").ok


def test_size_caps():
    assert ok(path="/" + "a" * rg.MAX_PATH_CHARS).reason == "path_too_large"
    assert ok(path="/" + "a" * (rg.MAX_PATH_CHARS - 1)).ok
    assert ok(body="x" * (rg.MAX_BODY_CHARS + 1)).reason == "body_too_large"


def test_reason_order_is_stable():
    # label is checked before method before size before scope before encoding.
    assert ok(method="PUT", label="benign").reason == "invalid_label"
    assert ok(method="PUT", path="//x").reason == "method_not_allowed"
    big = "/" + "a" * rg.MAX_PATH_CHARS
    assert ok(method="PUT", path=big).reason == "method_not_allowed"
