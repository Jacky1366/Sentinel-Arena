#!/usr/bin/env bash
# Stage 7 demo launcher (#18; checklist: docs/demo.md).
#
#   ARENA_GO=manual-<what> scripts/demo.sh           live match, D46 config (DeepSeek Red)
#   ARENA_GO=manual-<what> scripts/demo.sh --luna    the same with the backup Red (gpt-6-luna)
#   scripts/demo.sh --replay                         the golden run from file:// (no GO, no network, no cost)
#
# Live modes: preflight (Docker stack healthy, data/runs/live/ clean, no stale lock, dashboard
# built, ARENA_GO given), then caffeinate for the whole session, the live server on
# 127.0.0.1:8765 if not already running, the dashboard opened in the browser, and the match
# (tools/demo_match.py: D46 config, red_timeout_s from DEMO_RED_TIMEOUT_S there) with
# python -u, its stdout tee'd to the transcript the server follows.
#
# ARENA_GO always comes from the caller, for that one command. This script never sets,
# defaults or stores it, and refuses a live mode without it.
# DEMO_NO_OPEN=1 prints the URL instead of opening the browser.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
PY=.venv/bin/python
PORT=8765
URL="http://127.0.0.1:${PORT}/"
DEMO_DIR=data/runs/demo
TX="$DEMO_DIR/transcript.log"
LIVE=data/runs/live
DIST=dashboard/dist
GOLDEN_URL="file://${REPO}/${DIST}/index.html#src=bundle:golden-run&tab=battle"

die() { echo "DEMO STOP: $*" >&2; exit 1; }
ok() { echo "  ok    $*"; }

usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; }

mode=live
red=deepseek
[ $# -le 1 ] || die "one option at most (got: $*)"
case "${1:-}" in
  "") ;;
  --luna) red=luna ;;
  --replay) mode=replay ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; die "unknown option $1" ;;
esac

open_url() {
  if [ -n "${DEMO_NO_OPEN:-}" ]; then echo "  open  $1"; else open "$1"; ok "opened $1"; fi
}

start_caffeinate() {
  mkdir -p "$DEMO_DIR"
  if pgrep -f "caffeinate -dims" >/dev/null; then
    ok "caffeinate -dims already running"
  else
    nohup caffeinate -dims >/dev/null 2>&1 &
    echo $! > "$DEMO_DIR/caffeinate.pid"
    ok "caffeinate -dims started for the session (end it: kill \$(cat $DEMO_DIR/caffeinate.pid))"
  fi
}

# ---- replay: no GO, no network, no cost ----------------------------------------------
if [ "$mode" = replay ]; then
  echo "Sentinel Arena demo: REPLAY (recorded golden run; announce it as recorded, D45)"
  [ -f "$DIST/index.html" ] || die "dashboard not built: $DIST/index.html missing"
  [ -f "$DIST/data/golden-run.json" ] \
    || die "no golden run yet: export one with  $PY tools/export_golden.py data/runs/<match_id>"
  start_caffeinate
  open_url "$GOLDEN_URL"
  exit 0
fi

# ---- live: preflight ------------------------------------------------------------------
echo "Sentinel Arena demo: LIVE ($red Red) — preflight"
[ -x "$PY" ] || die "no project venv at $PY"
[ -n "${ARENA_GO:-}" ] || die "ARENA_GO is not set. A live match is paid: run  ARENA_GO=<token> scripts/demo.sh${1:+ $1}"
"$PY" -c 'import os, sys; from runner import go_token; sys.exit(0 if go_token.valid(os.environ.get("ARENA_GO")) else 1)' \
  || die "ARENA_GO is not a well-formed token (gate-<id> or manual-<what>)"
ok "ARENA_GO given by the caller"

command -v docker >/dev/null || die "docker not found"
ps_out="$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>&1)" \
  || die "docker compose ps failed: $ps_out (start: docker compose up -d --wait)"
for svc in juice-shop nginx; do
  line="$(printf '%s\n' "$ps_out" | awk -v s="$svc" '$1 == s')"
  state="$(printf '%s' "$line" | awk '{print $2}')"
  health="$(printf '%s' "$line" | awk '{print $3}')"
  [ "$state" = running ] || die "Docker service $svc is '${state:-absent}' (start: docker compose up -d --wait)"
  [ -z "$health" ] || [ "$health" = healthy ] || die "Docker service $svc is $health (wait, or: docker compose up -d --wait)"
done
ok "Docker stack: juice-shop and nginx running"

[ ! -e "$LIVE/match.lock" ] \
  || die "stale lock $LIVE/match.lock (a match is running, or one crashed: check, then remove it by hand)"
extra="$(ls -A "$LIVE" 2>/dev/null | grep -vx -e proxy.jsonl -e archive || true)"
[ -z "$extra" ] || die "$LIVE/ must hold only proxy.jsonl and archive/; found: $(echo $extra)"
ok "$LIVE/ clean, no lock"

[ -f "$DIST/index.html" ] || die "dashboard not built: $DIST/index.html missing"
ok "dashboard built"

# ---- session: caffeinate, live server, browser -----------------------------------------
mkdir -p "$DEMO_DIR/transcripts"
start_caffeinate

if [ -s "$TX" ]; then  # one transcript per match; the server follows the path (new inode)
  mv "$TX" "$DEMO_DIR/transcripts/$(date -u +%Y%m%dT%H%M%SZ).log"
fi

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$URL" || true)"
if [ "$code" = 200 ]; then
  pgrep -f "liveserver --port $PORT --transcript $TX" >/dev/null \
    || die "port $PORT is served by something else (not the demo live server on $TX): stop it first"
  ok "live server already running on $URL"
else
  nohup "$PY" -u -m liveserver --port "$PORT" --transcript "$TX" > "$DEMO_DIR/liveserver.log" 2>&1 &
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 0.5
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$URL" || true)"
    [ "$code" = 200 ] && break
  done
  [ "$code" = 200 ] || die "live server did not start (see $DEMO_DIR/liveserver.log)"
  ok "live server started on $URL (log $DEMO_DIR/liveserver.log)"
fi
open_url "$URL"

# ---- the match -------------------------------------------------------------------------
echo "Sentinel Arena demo: starting the match ($red Red; transcript $TX)"
set +e
"$PY" -u tools/demo_match.py --red "$red" 2>&1 | tee "$TX"
status=${PIPESTATUS[0]}
set -e
mid="$(sed -n 's/^match \([^ ]*\) -> .*/\1/p' "$TX" | head -1)"
echo
if [ "$status" = 0 ]; then
  echo "DEMO MATCH DONE: ${mid:-?} (exit 0). The dashboard keeps showing it."
  [ -z "$mid" ] || echo "  golden-run candidate check:  $PY tools/export_golden.py data/runs/$mid --check"
else
  echo "DEMO MATCH FAILED (exit $status): ${mid:-no match id}. Fallback: scripts/demo.sh --replay (docs/demo.md)" >&2
fi
exit "$status"
