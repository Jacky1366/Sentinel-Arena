"""The Stage 7 live server (D48): stdlib only, bound to 127.0.0.1, read-only.

    .venv/bin/python -m liveserver [--port 8765] [--transcript <tee'd stdout file>]

Serves dashboard/dist/ and GET /events (Server-Sent Events) from liveserver/tailer.py. It
makes no decision, computes no score, cannot start a match and accepts no request body: GET
and HEAD only. The match is launched from a terminal with ARENA_GO (the only path to a paid
call stays agents/llm_client.py). Requests whose Host header is not this loopback address
are refused (DNS-rebinding guard). Lab-stack ports are refused as the server's own port.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from liveserver import tailer as tailer_mod

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DIST = tailer_mod.REPO / "dashboard" / "dist"
LAB_PORTS = {8080, 8081, 3000}  # arena proxy, Judge admin, Juice Shop: never ours
KEEPALIVE_S = 15.0


class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelArenaLive/1"
    log: tailer_mod.EventLog
    dist: Path
    keepalive_s: float = KEEPALIVE_S

    def log_message(self, fmt, *args):  # quiet: the terminal belongs to the match
        pass

    def _host_ok(self) -> bool:
        port = self.server.server_address[1]
        return self.headers.get("Host") in {f"{HOST}:{port}", f"localhost:{port}"}

    def _refuse(self, code: int, text: str) -> None:
        body = (text + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self._host_ok():
            return self._refuse(403, "forbidden host")
        url = urlsplit(self.path)
        if url.path == "/events":
            return self._events(url)
        return self._static(url.path)

    def _method_not_allowed(self):
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _method_not_allowed

    def _static(self, path: str):
        rel = path.lstrip("/") or "index.html"
        root = self.dist.resolve()
        target = (root / rel).resolve()
        if root not in target.parents and target != root or not target.is_file():
            return self._refuse(404, "not found")
        data = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _events(self, url):
        last = self.headers.get("Last-Event-ID") or (parse_qs(url.query).get("last_id")
                                                     or [None])[0]
        try:
            last_id = int(last) if last is not None else None
        except ValueError:
            last_id = None
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            self.wfile.write(b"retry: 2000\n\n")
            self.wfile.flush()
            while not getattr(self.server, "closing", False):
                events = self.log.wait(last_id, self.keepalive_s)
                if not events:
                    self.wfile.write(b": keepalive\n\n")
                for ev in events:
                    self.wfile.write(f"id: {ev['id']}\ndata: {json.dumps(ev)}\n\n".encode())
                    last_id = ev["id"]
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return


class LiveServer:
    """The server plus its tailer thread. `port=0` picks a free port (tests)."""

    def __init__(self, port: int = DEFAULT_PORT, live_dir: Path = tailer_mod.LIVE,
                 runs_dir: Path = tailer_mod.RUNS, transcript: Path | None = None,
                 dist: Path = DIST, prices: dict | None = None, interval: float = 0.25,
                 keepalive_s: float = KEEPALIVE_S):
        if port in LAB_PORTS:
            raise ValueError(f"port {port} belongs to the lab stack; pick another")
        self.log = tailer_mod.EventLog()
        self.tailer = tailer_mod.Tailer(self.log, live_dir, runs_dir, transcript, prices)
        self.interval = interval
        handler = type("BoundHandler", (Handler,), {"log": self.log, "dist": Path(dist),
                                                    "keepalive_s": keepalive_s})
        self.httpd = ThreadingHTTPServer((HOST, port), handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self._threads: list[threading.Thread] = []

    def start(self) -> "LiveServer":
        for target in (lambda: self.tailer.run(self.interval), self.httpd.serve_forever):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)
        return self

    def close(self) -> None:
        self.httpd.closing = True
        self.tailer.stop()
        self.httpd.shutdown()
        self.httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read-only live server for the dashboard "
                                             "(127.0.0.1 only).")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--transcript", type=Path, default=None,
                    help="the match's stdout, tee'd to a file (enables match_plan, "
                         "slot_done and the derived red_turn_start events)")
    ap.add_argument("--live-dir", type=Path, default=tailer_mod.LIVE)
    ap.add_argument("--runs-dir", type=Path, default=tailer_mod.RUNS)
    args = ap.parse_args(argv)
    srv = LiveServer(args.port, args.live_dir, args.runs_dir, args.transcript).start()
    print(f"live server: http://{HOST}:{srv.port}/  (events: /events; Ctrl-C to stop)", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.close()
    return 0
