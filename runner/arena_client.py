"""THE arena HTTP client: the one sender for ALL arena traffic (Red attacks, benign
requests, harness probes). Same code, same headers, same request-id generator, so
attack and benign traffic differ only in content (CLAUDE.md principle 8, contract
§0 Traffic rule). No User-Agent is sent by anyone (designer decision, Stage 5.2).

Known Target quirk (contract §9): Juice Shop's /ftp/ directory listing declares a
Content-Length 59 bytes longer than the body it sends. That ONE case is tolerated
here: the status line and headers were fully received and the body is shorter
than its Content-Length -> the status is returned with body_incomplete=True.
Everything else stays an error (connection closed or reset before the headers,
timeouts, malformed responses): the catch is deliberately narrow.

Stage 5.6: the response body's first BODY_CAPTURE bytes are returned as text
(`body_text`, decoded with replacement) for AI Red's feedback (D6: its only
feedback is its own HTTP result). Reading the body is what the client always did;
the request (method, target, headers, body) is unchanged for every sender.
"""

from __future__ import annotations

import http.client
import uuid
from dataclasses import dataclass, field

ARENA_HOST, ARENA_PORT = "127.0.0.1", 8080
DEFAULT_TIMEOUT = 15.0
BODY_CAPTURE = 4096  # bytes of the response body kept as text (AI Red feedback)


def _text(raw: bytes) -> str:
    return raw[:BODY_CAPTURE].decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Response:
    status: int
    body_incomplete: bool = False
    # Not part of equality: the status (and the short-body flag) is the result.
    body_text: str = field(default="", compare=False)


def new_request_id() -> str:
    """The request-id generator for every sender: a lowercase uuid4 (contract §0)."""
    return str(uuid.uuid4())


def build_headers(request_id: str, body: str | None) -> dict[str, str]:
    """The header profile. One function, so Red and benign cannot drift apart."""
    headers = {"X-Arena-Request-Id": request_id}
    if body is not None:
        headers["Content-Type"] = "application/json"
    return headers


def send(method: str, target: str, request_id: str, body: str | None = None,
         timeout: float = DEFAULT_TIMEOUT, host: str | None = None,
         port: int | None = None) -> Response:
    """Send one request. `target` is the exact request-line target, never
    re-encoded. Raises on any send failure except a short body (see module doc)."""
    # Module globals are read at call time, so a test can point every sender at
    # a local capture server in one place.
    conn = http.client.HTTPConnection(host or ARENA_HOST, port or ARENA_PORT,
                                      timeout=timeout)
    try:
        conn.request(method, target, body=body, headers=build_headers(request_id, body))
        resp = conn.getresponse()  # raises unless the status line + headers arrived
        try:
            raw = resp.read()
        except http.client.IncompleteRead as exc:
            # Only a body shorter than a declared Content-Length is tolerated;
            # a chunked body cut short is a malformed response and still raises.
            if resp.chunked or resp.getheader("Content-Length") is None:
                raise
            return Response(resp.status, body_incomplete=True, body_text=_text(exc.partial))
        return Response(resp.status, body_text=_text(raw))
    finally:
        conn.close()
