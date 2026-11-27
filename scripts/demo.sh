#!/usr/bin/env bash
# Stage 7 demo launcher (#18; D61 three matchups; checklist: docs/demo.md).
#
#   ARENA_GO=manual-<what> scripts/demo.sh --taxonomy        1 · limited attacker vs limited defender (live)
#   ARENA_GO=manual-<what> scripts/demo.sh                   2 · free attacker vs limited defender (live)
#   ARENA_GO=manual-<what> scripts/demo.sh --open-replay     3 · free attacker vs free defender (open Blue re-judges 2)
#   add --luna to 1 or 2                                     backup Red gpt-6-luna (D46)
#   scripts/demo.sh --replay taxonomy|freeplay|open          a recorded golden run (no GO, no network, no cost)
#   scripts/demo.sh --new-session                            start the demo session: from now on the stage
#                                                            shows only new runs, and 3 picks only from them
#
# Live modes: preflight (ARENA_GO given; for 1 and 2 also the Docker stack healthy,
# data/runs/live/ clean and the Red provider reachable with its key; for all three the Blue
# provider reachable with its key (free: models endpoint, no tokens); no stale lock;
# dashboard built), then caffeinate for the whole
# session, the live server on 127.0.0.1:8765 if not already running, the dashboard opened in
# the browser, and tools/demo_match.py with python -u, its stdout tee'd to the transcript the
# server follows.
#
# ARENA_GO always comes from the caller, for that one command. This script never sets,
# defaults or stores it, and refuses a live mode without it.
# DEMO_DRY=1 prints the URL instead of opening the browser and skips caffeinate (tests).
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

die() { echo "DEMO STOP: $*" >&2; exit 1; }
# No silent exits: any command that fails outside a `|| die` (set -e) prints a DEMO STOP too.
# Not inherited by functions or $(...) (no set -E), so one failure prints one line. Removed
# around the run itself, whose exit status is reported below.
trap 'rc=$?; echo "DEMO STOP: unexpected failure (exit $rc) at scripts/demo.sh line $LINENO: $BASH_COMMAND -- a launcher bug, please report it. Fallback: the matchup'"'"'s --replay (docs/demo.md)" >&2; exit $rc' ERR
ok() { echo "  ok    $*"; }
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }

# ---- options -------------------------------------------------------------------------
matchup=freeplay   # taxonomy | freeplay | open
red=deepseek
replay=""
session=""
given="$*"
while [ $# -gt 0 ]; do
  case "$1" in
    --taxonomy) matchup=taxonomy ;;
    --open-replay) matchup=open ;;
    --luna) red=luna ;;
    --new-session) session=new ;;
    --replay)
      [ $# -ge 2 ] || die "--replay needs one of: taxonomy freeplay open"
      replay="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option $1" ;;
  esac
  shift
done
if [ -n "$session" ]; then
  [ $# -eq 0 ] && [ "$given" = "--new-session" ] || die "--new-session takes no other option"
  [ -x "$PY" ] || die "no project venv at $PY"
  exec "$PY" tools/demo_match.py --new-session
fi
if [ -n "$replay" ]; then
  case "$replay" in taxonomy|freeplay|open) ;; *) die "--replay needs one of: taxonomy freeplay open (got '$replay')" ;; esac
  [ "$matchup" = freeplay ] && [ "$red" = deepseek ] || die "--replay takes no other option"
fi
[ "$matchup" != open ] || [ "$red" = deepseek ] \
  || die "--luna is the backup Red for matchups 1 and 2; matchup 3 has no Red (it re-judges matchup 2)"

open_url() {
  if [ -n "${DEMO_DRY:-}" ]; then echo "  open  $1"; else open "$1"; ok "opened $1"; fi
}

start_caffeinate() {
  if [ -n "${DEMO_DRY:-}" ]; then echo "  dry   caffeinate skipped"; return; fi
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
if [ -n "$replay" ]; then
  echo "Sentinel Arena demo: REPLAY golden-$replay (recorded; announce it as recorded, D45)"
  [ -f "$DIST/index.html" ] || die "dashboard not built: $DIST/index.html missing"
  [ -f "$DIST/data/golden-$replay.json" ] \
    || die "no golden-$replay run yet: export one with  $PY tools/export_golden.py <match or replay folder>"
  start_caffeinate
  open_url "file://${REPO}/${DIST}/index.html#src=bundle:golden-${replay}&tab=battle"
  exit 0
fi

# ---- live: preflight ------------------------------------------------------------------
case "$matchup" in
  taxonomy) title="1 · Limited attacker vs limited defender"; args=(--matchup taxonomy --red "$red") ;;
  freeplay) title="2 · Free attacker vs limited defender"; args=(--matchup freeplay --red "$red") ;;
  open) title="3 · Free attacker vs free defender (same attacks as 2)"; args=(--open-replay) ;;
esac
[ "$matchup" = open ] || title="$title — $red Red"
echo "Sentinel Arena demo: LIVE $title — preflight"
[ -x "$PY" ] || die "no project venv at $PY"
[ -n "${ARENA_GO:-}" ] || die "ARENA_GO is not set. This is paid: run  ARENA_GO=<token> scripts/demo.sh $given"
"$PY" -c 'import os, sys; from runner import go_token; sys.exit(0 if go_token.valid(os.environ.get("ARENA_GO")) else 1)' \
  || die "ARENA_GO is not a well-formed token (gate-<id> or manual-<what>)"
ok "ARENA_GO given by the caller"

if [ "$matchup" != open ]; then  # matchup 3 is a replay: no Target, no live log
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
  extra="$(ls -A "$LIVE" 2>/dev/null | grep -vx -e proxy.jsonl -e archive -e match.lock || true)"
  [ -z "$extra" ] || die "$LIVE/ must hold only proxy.jsonl and archive/; found: $(echo $extra)"
fi
[ ! -e "$LIVE/match.lock" ] \
  || die "stale lock $LIVE/match.lock (a match is running, or one crashed: check, then remove it by hand)"
ok "no match running (no $LIVE/match.lock)"
if [ "$matchup" != open ]; then  # free: the Red provider's models endpoint, with its key; no tokens
  if red_out="$("$PY" -u tools/demo_match.py "${args[@]}" --check-red 2>&1)"; then
    ok "$red_out"
  else
    flag=""; [ "$matchup" = taxonomy ] && flag=" --taxonomy"
    if [ "$red" = deepseek ]; then
      fb="ARENA_GO=<token> scripts/demo.sh${flag} --luna  (or the recording: scripts/demo.sh --replay $matchup)"
    else
      fb="scripts/demo.sh --replay $matchup  (recorded run, no network)"
    fi
    die "$(printf '%s' "$red_out" | tail -1). Fallback: $fb"
  fi
fi
# Blue (all three matchups; 3 is Blue only). --luna does not help: Blue is the same.
if blue_out="$("$PY" -u tools/demo_match.py --check-blue 2>&1)"; then
  ok "$blue_out"
else
  die "$(printf '%s' "$blue_out" | tail -1). Fallback: scripts/demo.sh --replay $matchup  (recorded run, no network)"
fi
# No sessions file yet (before the first --new-session) is a WARN, not a stop: guard it, as a
# missing file makes sed fail and pipefail + set -e would exit here silently.
sess=""
if [ -e "$DEMO_DIR/sessions.jsonl" ]; then
  sess="$(sed -n '$p' "$DEMO_DIR/sessions.jsonl" | sed -n 's/.*"session_id": *"\([^"]*\)".*/\1/p')" \
    || die "cannot read $DEMO_DIR/sessions.jsonl (check it, or start a session: scripts/demo.sh --new-session)"
fi
if [ -n "$sess" ]; then
  ok "demo session $sess (the stage shows only its runs)"
else
  echo "  WARN  no demo session: start one first with  scripts/demo.sh --new-session  (rehearsal runs stay visible)"
fi

[ -f "$DIST/index.html" ] || die "dashboard not built: $DIST/index.html missing"
ok "dashboard built"

# ---- session: caffeinate, live server, browser -----------------------------------------
mkdir -p "$DEMO_DIR/transcripts"
start_caffeinate

if [ -s "$TX" ]; then  # one transcript per run; the server follows the path (new inode)
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

# ---- the run ---------------------------------------------------------------------------
echo "Sentinel Arena demo: starting $title (transcript $TX)"
trap - ERR  # the run's own exit status is reported below, not as a launcher failure
set +e
"$PY" -u tools/demo_match.py "${args[@]}" 2>&1 | tee "$TX"
status=${PIPESTATUS[0]}
set -e
# best effort (|| true): a SIGPIPE from head under pipefail must not end the script silently
if [ "$matchup" = open ]; then
  folder="$(sed -n 's/^replay [^ ]* of [^ ]* -> \(.*\)$/\1/p' "$TX" | head -1 | sed 's/ .*//' || true)"
else
  folder="$(sed -n 's/^match [^ ]* -> \(.*\)$/\1/p' "$TX" | head -1 || true)"
fi
echo
if [ "$status" = 0 ]; then
  echo "DEMO RUN DONE: ${folder:-?} (exit 0). The dashboard keeps showing it."
  [ -z "$folder" ] || echo "  golden-run candidate check:  $PY tools/export_golden.py $folder --check"
else
  echo "DEMO RUN FAILED (exit $status): ${folder:-nothing started}. Fallback: docs/demo.md" >&2
fi
exit "$status"
