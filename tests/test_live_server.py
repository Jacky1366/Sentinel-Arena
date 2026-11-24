"""liveserver/server.py (Stage 7 #12): a fake match streams every event type, in order, to a
test SSE client; reconnect with Last-Event-ID; static files; read-only; loopback only."""

from __future__ import annotations

import http.client
import json
import time

import pytest

from live_fakes import PRICES, lab, play  # noqa: F401 (fixture)
from liveserver import server as S


@pytest.fixture
def srv(lab, tmp_path):
    live, runs, transcript = lab
    dist = tmp_path / "dist"
    (dist / "data").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>dash</title>")
    (dist / "data" / "bundles.js").write_text("window.B=[];")
    (tmp_path / "secret.txt").write_text("outside dist")
    s = S.LiveServer(port=0, live_dir=live, runs_dir=runs, transcript=transcript, dist=dist,
                     prices=PRICES, interval=0.002, keepalive_s=0.1).start()
    yield s
    s.close()


def get(port, path, method="GET", host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest(method, path, skip_host=True)
    c.putheader("Host", host or f"127.0.0.1:{port}")
    c.endheaders()
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, r.getheader("Content-Type"), body


def stream(port, until, headers=None, path="/events", timeout=10.0):
    """Read SSE events until until(events) is true."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    c.request("GET", path, headers=headers or {})
    r = c.getresponse()
    assert r.status == 200 and r.getheader("Content-Type") == "text/event-stream"
    events, cur, deadline = [], {}, time.monotonic() + timeout
    while not until(events) and time.monotonic() < deadline:
        line = r.fp.readline().decode().rstrip("\n")
        if line.startswith("id: "):
            cur["id"] = int(line[4:])
        elif line.startswith("data: "):
            cur["data"] = json.loads(line[6:])
        elif line == "" and "data" in cur:
            assert cur["id"] == cur["data"]["id"]
            events.append(cur["data"])
            cur = {}
    c.close()
    return events


def done(events):
    return bool(events) and events[-1]["type"] == "lock_released"


def test_a_fake_match_streams_every_event_type_in_order(srv, lab):
    code, match_dir = play(lab)
    assert code == 0
    events = stream(srv.port, done)
    assert done(events)
    assert events == srv.log.since(None)  # the client gets exactly the log, in order
    ids = [e["id"] for e in events]
    assert ids == sorted(ids) and len(set(ids)) == len(ids)
    types = set(e["type"] for e in events)
    assert {"match_started", "match_plan", "target_reset", "red_turn_start", "api_call",
            "red_unsent", "red_attack", "benign_request", "proxy_line", "snapshot",
            "slot_done", "proxy_frozen", "landed", "verdict", "rule", "round_record",
            "benign_result", "anomaly", "rule_result", "match_finished",
            "lock_released"} <= types


def test_live_client_connected_before_the_match(srv, lab):
    import threading
    got = {}
    t = threading.Thread(target=lambda: got.setdefault("ev", stream(srv.port, done)))
    t.start()
    time.sleep(0.1)  # connected and idle (keepalives only)
    code, _ = play(lab)
    t.join(15)
    assert code == 0 and done(got["ev"])
    assert got["ev"][0]["type"] == "match_started"


def test_reconnect_resumes_after_last_event_id(srv, lab):
    play(lab)
    full = stream(srv.port, done)
    k = full[9]["id"]
    rest = stream(srv.port, done, headers={"Last-Event-ID": str(k)})
    assert rest == full[10:]
    rest_q = stream(srv.port, done, path=f"/events?last_id={k}")
    assert rest_q == full[10:]
    # an id from an earlier server run (beyond the log) replays the whole match
    again = stream(srv.port, done, headers={"Last-Event-ID": "999999"})
    assert again == full


def test_static_files_from_dist_only(srv):
    status, ctype, body = get(srv.port, "/")
    assert status == 200 and ctype == "text/html" and b"dash" in body
    status, _, body = get(srv.port, "/data/bundles.js")
    assert status == 200 and body == b"window.B=[];"
    for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/data/../../secret.txt",
                 "/nope.html", "/data"):
        status, _, body = get(srv.port, path)
        assert status == 404 and b"outside dist" not in body, path


def test_read_only_and_loopback_host_only(srv):
    for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        assert get(srv.port, "/events", method=method)[0] == 405
    assert get(srv.port, "/", host="evil.example")[0] == 403
    assert get(srv.port, "/", host=f"localhost:{srv.port}")[0] == 200
    assert get(srv.port, "/", method="HEAD")[0] == 200
    assert srv.httpd.server_address[0] == "127.0.0.1"


@pytest.mark.parametrize("port", sorted(S.LAB_PORTS))
def test_lab_ports_are_refused(port):
    with pytest.raises(ValueError, match="lab stack"):
        S.LiveServer(port=port)


def test_the_server_writes_nothing(srv, lab):
    live, runs, transcript = lab
    play(lab)
    stream(srv.port, done)
    before = {p: p.stat().st_mtime_ns for p in runs.rglob("*") if p.is_file()}
    stream(srv.port, done)  # a second client re-reads everything
    time.sleep(0.05)
    after = {p: p.stat().st_mtime_ns for p in runs.rglob("*") if p.is_file()}
    assert before == after


def test_no_imports_from_the_paid_or_judge_side():
    import ast
    from pathlib import Path
    for f in (Path(S.__file__).parent).glob("*.py"):
        tree = ast.parse(f.read_text())
        mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        mods |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not {m for m in mods if m and m.split(".")[0] in
                    ("agents", "judge", "blue", "red", "library", "run_match")}, f.name
