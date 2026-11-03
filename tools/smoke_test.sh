#!/usr/bin/env bash
# Stage 1 smoke test. Requires the stack to be up:
#   docker compose up -d --wait
#
# Sends six requests through the proxy, then validates ONLY the log lines they
# produced (the live log is never truncated):
#   (a) GET / with a request id                              -> valid
#   (b) POST /rest/user/login, JSON body with ' and "        -> valid, body round-trips
#   (c) GET /ftp/..%2fftp/legal.md?x=1 (in-root traversal)   -> valid, raw path kept
#   (d) GET / with NO request id                             -> stray
#   (e) GET /ftp/..%2f..%2fetc/passwd (above-root) with id   -> stray: nginx rejects it
#       while parsing the request line, before reading headers (contract §9)
#   (f) GET /ftp/package.json.bak%2500.md with an id         -> valid, raw path kept,
#       forwarded to Juice Shop (null-byte /ftp challenge)
# Expected: valid=4 stray=2 invalid=0.
#
# NOTE: (f) may solve a Juice Shop challenge. Juice Shop keeps challenges solved,
# so restart it before a scored run: docker compose restart juice-shop
set -euo pipefail

cd "$(dirname "$0")/.."
PY=.venv/bin/python
PROXY_HOST=127.0.0.1
PROXY_PORT=8080
PROXY="http://${PROXY_HOST}:${PROXY_PORT}"
LOG=data/runs/live/proxy.jsonl

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$PY" ] || fail "$PY not found (see README: Setup and tests)"

# Plain TCP connect, no HTTP request, so the check itself adds no log line.
if ! (exec 3<>"/dev/tcp/${PROXY_HOST}/${PROXY_PORT}") 2>/dev/null; then
  fail "nothing listening on ${PROXY_HOST}:${PROXY_PORT}; run: docker compose up -d --wait"
fi
[ -f "$LOG" ] || fail "$LOG does not exist; is the nginx log volume mounted?"

before=$(wc -l < "$LOG" | tr -d ' ')

uuid4() { "$PY" -c 'import uuid; print(uuid.uuid4())'; }
ID_A=$(uuid4); ID_B=$(uuid4); ID_C=$(uuid4); ID_E=$(uuid4); ID_F=$(uuid4)
# Raw JSON body: a single quote, and a double quote (JSON-escaped as \").
BODY_B='{"email":"o'\''brien@juice-sh.op","password":"say \"hi\""}'
PATH_C='/ftp/..%2fftp/legal.md'
PATH_E='/ftp/..%2f..%2fetc/passwd'
PATH_F='/ftp/package.json.bak%2500.md'

send() { # label, curl args...
  local label=$1; shift
  printf '%-42s -> HTTP ' "$label"
  curl -sS -o /dev/null --max-time 10 -w '%{http_code}\n' "$@"
}

send "(a) GET /" -H "X-Arena-Request-Id: ${ID_A}" "${PROXY}/"
send "(b) POST /rest/user/login" -H "X-Arena-Request-Id: ${ID_B}" \
  -H 'Content-Type: application/json' --data-binary "$BODY_B" "${PROXY}/rest/user/login"
send "(c) GET ${PATH_C}?x=1" -H "X-Arena-Request-Id: ${ID_C}" \
  --path-as-is "${PROXY}${PATH_C}?x=1"
send "(d) GET / (no request id)" "${PROXY}/"
send "(e) GET ${PATH_E}" -H "X-Arena-Request-Id: ${ID_E}" \
  --path-as-is "${PROXY}${PATH_E}"
send "(f) GET ${PATH_F}" -H "X-Arena-Request-Id: ${ID_F}" \
  --path-as-is "${PROXY}${PATH_F}"

# nginx writes the log line after the response; give it a moment.
for _ in $(seq 1 25); do
  [ "$(wc -l < "$LOG" | tr -d ' ')" -ge $((before + 6)) ] && break
  sleep 0.2
done

NEW=$(mktemp "${TMPDIR:-/tmp}/arena_smoke.XXXXXX")
trap 'rm -f "$NEW"' EXIT
tail -n +"$((before + 1))" "$LOG" > "$NEW"

echo
echo "--- validate_log.py (new lines only) ---"
set +e
summary=$("$PY" tools/validate_log.py "$NEW")
rc=$?
set -e
echo "$summary"
[ $rc -eq 0 ] || fail "validate_log.py reported invalid lines (exit $rc)"
[ "$(echo "$summary" | tail -n 1)" = "valid=4 stray=2 invalid=0" ] \
  || fail "expected 'valid=4 stray=2 invalid=0'"

echo
echo "--- field checks ---"
export ID_A ID_B ID_C ID_E ID_F BODY_B PATH_C PATH_F
"$PY" - "$NEW" <<'PYEOF'
import json, os, sys

lines = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
by_id = {l["request_id"]: l for l in lines if l.get("request_id")}
strays = [l for l in lines if not l.get("request_id")]
env = os.environ
problems = []

def check(name, cond, detail=""):
    print(("ok   " if cond else "FAIL ") + name)
    if not cond:
        problems.append(f"{name}: {detail}")

a, b, c, e, f = (by_id.get(env[k]) for k in ("ID_A", "ID_B", "ID_C", "ID_E", "ID_F"))
check("(a) line present", a is not None, "no line with ID_A")
check("(b) line present", b is not None, "no line with ID_B")
if b:
    check("(b) body round-trips exactly (quotes escaped correctly)",
          b["body"] == env["BODY_B"], f"got {b['body']!r}")
    check("(b) method is POST", b["method"] == "POST", f"got {b['method']!r}")
check("(c) line present", c is not None, "no line with ID_C")
if c:
    check(f"(c) path is raw {env['PATH_C']!r}", c["path"] == env["PATH_C"], f"got {c['path']!r}")
    check("(c) query is 'x=1'", c["query"] == "x=1", f"got {c['query']!r}")
check("(d) stray GET / line present",
      any(s["path"] == "/" and s["status"] == 200 for s in strays), f"strays: {strays}")
check("(e) request id NOT logged (rejected before headers are read)", e is None, f"got {e}")
check("(e) stray 400 line with empty path present",
      any(s["path"] == "" and s["status"] == 400 for s in strays), f"strays: {strays}")
check("(f) line present", f is not None, "no line with ID_F")
if f:
    check(f"(f) path is raw {env['PATH_F']!r}", f["path"] == env["PATH_F"], f"got {f['path']!r}")
    check("(f) forwarded to Juice Shop (not an nginx 400)", f["status"] != 400,
          f"got {f['status']}")
    print(f"     (f) Juice Shop returned HTTP {f['status']}")
if problems:
    sys.exit("\n".join(problems))
PYEOF

echo
echo "PASS: 4 valid, 2 stray, 0 invalid"
