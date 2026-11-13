"""runner/arena_client.py: the ONE sender for Red and benign traffic.

A raw local socket server plays the Target, so each case is exact: a body shorter
than its Content-Length, a connection closed before the headers, a truncated
chunked body. No Docker.
"""

from __future__ import annotations

import http.client
import json
import socket
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from benign import send_benign  # noqa: E402
from red import scripted_red  # noqa: E402
from runner import arena_client  # noqa: E402

UUID4 = __import__("re").compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


class RawServer:
    """Accepts connections; for each, reads the full request, records it, and
    writes `reply` (bytes) or calls reply(conn)."""

    def __init__(self, reply=OK):
        self.reply = reply
        self.requests: list[bytes] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _read_request(self, conn) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return data
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"content-length":
                length = int(v.strip())
        while len(rest) < length:
            rest += conn.recv(65536)
        return head + b"\r\n\r\n" + rest

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                self.requests.append(self._read_request(conn))
                if callable(self.reply):
                    self.reply(conn)
                else:
                    conn.sendall(self.reply)

    def close(self):
        self.sock.close()


@pytest.fixture
def server(monkeypatch):
    servers = []

    def make(reply=OK):
        s = RawServer(reply)
        servers.append(s)
        monkeypatch.setattr(arena_client, "ARENA_PORT", s.port)
        return s
    yield make
    for s in servers:
        s.close()


# ---- the one tolerated case ---------------------------------------------------

def test_body_shorter_than_content_length_returns_status_with_flag(server):
    # Juice Shop's /ftp/ listing: Content-Length 11343, 11284 bytes sent.
    server(b"HTTP/1.1 200 OK\r\nContent-Length: 11343\r\nConnection: close\r\n\r\n"
           + b"x" * 11284)
    resp = arena_client.send("GET", "/ftp/", arena_client.new_request_id())
    assert resp == arena_client.Response(200, body_incomplete=True)


def test_complete_body_is_not_flagged(server):
    server()
    assert arena_client.send("GET", "/", arena_client.new_request_id()) == \
        arena_client.Response(200, body_incomplete=False)


# ---- everything else still raises ---------------------------------------------

def test_connection_closed_before_headers_raises(server):
    server(lambda conn: None)  # read the request, close without a byte
    with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
        arena_client.send("GET", "/", arena_client.new_request_id())


def test_partial_status_line_raises(server):
    server(b"HTTP/1.1 20")
    with pytest.raises(http.client.HTTPException):
        arena_client.send("GET", "/", arena_client.new_request_id())


def test_truncated_chunked_body_still_raises(server):
    server(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
           b"10\r\nonly-five")
    with pytest.raises(http.client.IncompleteRead):
        arena_client.send("GET", "/", arena_client.new_request_id())


def test_timeout_raises(server):
    import time
    server(lambda conn: time.sleep(1.0))
    with pytest.raises(TimeoutError):
        arena_client.send("GET", "/", arena_client.new_request_id(), timeout=0.2)


# ---- Red and benign are indistinguishable at the HTTP level --------------------

def _profile(raw: bytes) -> tuple[list[tuple[str, str]], str]:
    """(headers without the request id's value, request id)."""
    head = raw.partition(b"\r\n\r\n")[0].decode()
    headers, rid = [], ""
    for line in head.split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if k.lower() == "x-arena-request-id":
            rid, v = v.strip(), "<id>"
        elif k.lower() in ("content-length", "host"):
            v = "<varies>"  # length depends on the body; host on the test port
        headers.append((k, v.strip()))
    return headers, rid


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_red_and_benign_header_profiles_are_identical(server, tmp_path, method):
    srv = server()
    red_attack = {"label": "CWE-89", "method": method, "endpoint": "/rest/user/login"}
    benign = {"benign_id": "n01", "category": "normal", "method": method,
              "endpoint": "/rest/user/login", "note": "x"}
    if method == "POST":
        red_attack["json_body"] = {"email": "' OR 1=1--", "password": "x"}
        benign["json_body"] = {"email": "alice@example.com", "password": "y"}
    else:
        red_attack["query_params"] = {"q": "x' OR 1=1--"}
        benign["query_params"] = {"q": "apple"}
    r = scripted_red.send_one(red_attack, "m001", 1, tmp_path)
    b = send_benign.send_one(benign, "m001", tmp_path)
    assert r["error"] is None and b["error"] is None
    (red_headers, red_id), (ben_headers, ben_id) = map(_profile, srv.requests)
    assert red_headers == ben_headers
    assert [k for k, _ in red_headers] == [k for k, _ in ben_headers]  # same order
    assert UUID4.match(red_id) and UUID4.match(ben_id) and red_id != ben_id
    assert red_id == r["request_id"] and ben_id == b["request_id"]
    assert not any(k.lower() == "user-agent" for k, _ in red_headers)  # neither sends one


def test_benign_record_is_written_before_the_send(server, tmp_path):
    seen = {}

    def reply(conn):
        seen["lines"] = (tmp_path / "benign_requests.jsonl").read_text().splitlines()
        conn.sendall(OK)
    server(reply)
    entry = {"benign_id": "h06", "category": "hard_negative", "method": "GET",
             "endpoint": "/", "expected_solves": ["Error Handling"], "note": "x"}
    res = send_benign.send_one(entry, "m001", tmp_path)
    [line] = [json.loads(l) for l in seen["lines"]]
    assert line["request_id"] == res["request_id"] and line["benign_id"] == "h06"
    assert line["expected_solves"] == ["Error Handling"]


def test_benign_send_failure_keeps_the_record(server, tmp_path):
    server(lambda conn: None)
    entry = {"benign_id": "n04", "category": "normal", "method": "GET", "endpoint": "/",
             "note": "x"}
    res = send_benign.send_one(entry, "m001", tmp_path)
    assert res["status"] is None and res["error"]
    assert len((tmp_path / "benign_requests.jsonl").read_text().splitlines()) == 1


# ---- Stage 5.6: response body text for AI Red's feedback --------------------

def test_body_text_is_captured_and_capped(server):
    server(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n"
           + "é".encode() + b"y" * 4998)
    resp = arena_client.send("GET", "/", arena_client.new_request_id())
    assert resp.body_text.startswith("éy") and len(resp.body_text.encode()) <= 4096


def test_short_body_still_returns_its_partial_text(server):
    server(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\nConnection: close\r\n\r\npartial")
    resp = arena_client.send("GET", "/ftp/", arena_client.new_request_id())
    assert resp.body_incomplete and resp.body_text == "partial"
