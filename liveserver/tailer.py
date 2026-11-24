"""Tail a running match's artifacts and turn them into events (Stage 7, D47/D48/D50).

READ-ONLY: this module never writes, renames or deletes anything, never touches the
network, and computes no score. Every event comes from a line or file that exists on disk;
the two derived events (`match_plan.planned`, `red_turn_start`) are computed from the
transcript's seed line with the orchestrator's own pure schedule function and are marked
`derived: true`.

Sources, polled every `interval` seconds (stdlib only, no inotify):

  live/match.lock              -> match_started (match_id, pid, started_at); its removal,
                                  after match.json, -> lock_released
  <run>/api_calls.jsonl        -> api_call (+ usd from stats/cost.py, the same pricing as
                                  match.json; D39 rate_window when present)
  <run>/red_unsent.jsonl       -> red_unsent (guard_block / brain_failure / instrument_failure)
  <run>/red_attacks.jsonl      -> red_attack
  <run>/benign_requests.jsonl  -> benign_request
  proxy.jsonl (live/, then <run>/ after freeze) -> proxy_line; freeze -> proxy_frozen
  <run>/challenge_snapshots.jsonl -> snapshot (+ newly_solved = after - before)
  <run>/library.json, challenge_catalog.json -> library_loaded, challenge_catalog
  <run>/landed, verdicts, rules, rule_rejections, rounds, benign_results, anomalies,
        rule_results .jsonl -> one event per line (Blue and the Judge: after traffic, D47)
  <run>/match.json             -> match_finished (status, failed_step, cost total)
  optional tee'd stdout transcript -> match_plan, target_reset, slot_done, red_turn_start
                                  (derived), match_failed

Order within one poll follows causality: Red call -> Red record -> proxy line -> snapshot,
and all traffic before Blue and the Judge. A proxy line is emitted only after the record
carrying its request_id (records are written before the send, so this only waits out a
partially read record); lines with an empty request_id are stray and counted; lines whose
id never appears (e.g. the previous match's log before rotation) are counted as unknown.
"""

from __future__ import annotations

import json
import re
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from runner import schedule as schedule_mod  # noqa: E402  (pure)
from stats import cost as cost_stats  # noqa: E402  (pure)

RUNS = REPO / "data" / "runs"
LIVE = RUNS / "live"
LOCK = "match.lock"
PENDING_POLLS = 40  # polls a proxy line may wait for its record before it counts as unknown

# Traffic files, in causal order (see the module docstring).
TRAFFIC = [("api_calls.jsonl", "api_call"), ("red_unsent.jsonl", "red_unsent"),
           ("red_attacks.jsonl", "red_attack"), ("benign_requests.jsonl", "benign_request")]
AFTER_PROXY = [("challenge_snapshots.jsonl", "snapshot")]
# Written after traffic (Blue, then the Judge), in the orchestrator's order.
RESULTS = [("landed.jsonl", "landed"), ("verdicts.jsonl", "verdict"), ("rules.jsonl", "rule"),
           ("rule_rejections.jsonl", "rule_rejection"), ("rounds.jsonl", "round_record"),
           ("benign_results.jsonl", "benign_result"), ("anomalies.jsonl", "anomaly"),
           ("rule_results.jsonl", "rule_result")]

RE_MATCH = re.compile(r"^match (\S+) -> ")
RE_SEED = re.compile(r"^seed (\d+) \((\w+)\): (\d+) Red \+ (\d+) benign slots")
RE_RESET = re.compile(r"^target reset: (\d+) challenges solved")
RE_SLOT = re.compile(r"^slot\s+(\d+) (?:round (\d+)|benign (\S+))")
RE_FAILED = re.compile(r"^MATCH FAILED at step '([^']*)': (.*)$")


class EventLog:
    """Thread-safe event history of the CURRENT match. Ids increase across matches; a new
    match clears the history (clients reset on match_started)."""

    def __init__(self):
        self._cond = threading.Condition()
        self._events: list[dict] = []
        self._next_id = 1

    def append(self, etype: str, data: dict) -> dict:
        with self._cond:
            if etype == "match_started":
                self._events = []
            ev = {"id": self._next_id, "type": etype,
                  "observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                  .replace("+00:00", "Z"), **data}
            self._next_id += 1
            self._events.append(ev)
            self._cond.notify_all()
            return ev

    def since(self, last_id: int | None) -> list[dict]:
        """Events after last_id; the whole current match if last_id is older than it."""
        with self._cond:
            if (last_id is None or not self._events or last_id < self._events[0]["id"] - 1
                    or last_id > self._events[-1]["id"]):  # a client of an earlier server run
                return list(self._events)
            return [e for e in self._events if e["id"] > last_id]

    def wait(self, last_id: int | None, timeout: float) -> list[dict]:
        with self._cond:
            if not self.since(last_id):
                self._cond.wait(timeout)
            return self.since(last_id)

    def types(self) -> list[str]:
        with self._cond:
            return [e["type"] for e in self._events]


@dataclass
class _File:
    offset: int = 0
    buf: bytes = b""
    inode: int | None = None


def _read_lines(path: Path, st: _File) -> list[str]:
    """Complete new lines of `path` since the last read (a partial last line waits)."""
    try:
        with path.open("rb") as fh:
            fh.seek(st.offset)
            chunk = fh.read()
    except FileNotFoundError:
        return []
    st.offset += len(chunk)
    data = st.buf + chunk
    *lines, st.buf = data.split(b"\n")
    return [ln.decode("utf-8", "replace") for ln in lines if ln.strip()]


def _inode(path: Path) -> int | None:
    try:
        return path.stat().st_ino
    except FileNotFoundError:
        return None


class Match:
    """Per-match tail state."""

    def __init__(self, match_id: str, run_dir: Path):
        self.match_id = match_id
        self.run_dir = run_dir
        self.files: dict[str, _File] = {}
        self.proxy = _File()
        self.proxy_frozen = False
        self.known_ids: set[str] = set()
        self.pending: list[tuple[dict, int]] = []
        self.counts = {"stray": 0, "unknown": 0, "malformed": 0}
        self.seen_once: set[str] = set()
        self.planned: list[str] | None = None
        self.turns_started: set[int] = set()
        self.derive = True
        self.finished = False

    def f(self, name: str) -> _File:
        return self.files.setdefault(name, _File())


class Tailer:
    def __init__(self, log: EventLog, live_dir: Path = LIVE, runs_dir: Path = RUNS,
                 transcript: Path | None = None, prices: dict | None = None):
        self.log = log
        self.live_dir = Path(live_dir)
        self.runs_dir = Path(runs_dir)
        self.transcript = Path(transcript) if transcript is not None else None
        self.prices = prices if prices is not None else cost_stats.load_prices()
        self.match: Match | None = None
        self._tx = _File()
        self._tx_match: str | None = None
        self._tx_backlog: list[str] = []   # lines of a match not started here yet
        self._tx_ready: list[str] = []     # lines of the current match, not yet applied
        self._stop = threading.Event()

    # -- the loop -----------------------------------------------------------------
    def run(self, interval: float = 0.25) -> None:
        while not self._stop.is_set():
            self.poll()
            self._stop.wait(interval)

    def stop(self) -> None:
        self._stop.set()

    def poll(self) -> None:
        """One pass. Reads go in REVERSE causal order (effects first: transcript, results,
        snapshots, proxy, records, calls), so anything a later file shows has its causes
        already complete on disk when the earlier file is read; events are then emitted in
        causal order. A stdout line is printed only after the artifacts it reports."""
        lock = self._lock()
        if lock is not None and (self.match is None or lock["match_id"] != self.match.match_id):
            self._start(lock["match_id"], lock)
        self._read_transcript()
        self._apply_transcript(pre_traffic_only=True)  # plan + reset precede any artifact
        if self.match is not None and not self.match.finished:
            self._poll_files(self.match)
        self._apply_transcript()
        m = self.match
        if m is None or m.finished:
            return
        if (lock is None or lock["match_id"] != m.match_id) and \
                (m.run_dir / "match.json").is_file():
            self._read_transcript()  # drain anything written just before match.json
            self._poll_files(m)
            self._apply_transcript()
            self._finish(m)

    # -- match lifecycle ------------------------------------------------------------
    def _lock(self) -> dict | None:
        try:
            lock = json.loads((self.live_dir / LOCK).read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):  # absent, or still being written
            return None
        return lock if isinstance(lock, dict) and isinstance(lock.get("match_id"), str) else None

    def _start(self, match_id: str, lock: dict | None) -> None:
        self.match = Match(match_id, self.runs_dir / match_id)
        if self._tx_match != match_id:
            self._tx_backlog = []  # lines of another match
        self.log.append("match_started", {
            "match_id": match_id, "pid": (lock or {}).get("pid"),
            "started_at": (lock or {}).get("started_at"),
            "source": "match.lock" if lock is not None else "transcript"})
        self._tx_ready += self._tx_backlog
        self._tx_backlog = []

    def _finish(self, m: Match) -> None:
        try:
            manifest = json.loads((m.run_dir / "match.json").read_text(encoding="utf-8"))
        except ValueError:
            return  # still being written: next poll
        m.finished = True
        m.counts["unknown"] += len(m.pending)
        m.pending = []
        self.log.append("match_finished", {
            "match_id": m.match_id, "status": manifest.get("status"),
            "failed_step": manifest.get("failed_step"), "error": manifest.get("error"),
            "started_at": manifest.get("started_at"), "finished_at": manifest.get("finished_at"),
            "cost_usd": (manifest.get("cost") or {}).get("total_usd"),
            "tail_counts": dict(m.counts)})
        self.log.append("lock_released", {"match_id": m.match_id})

    # -- files ------------------------------------------------------------------
    def _rows(self, m: Match, name: str) -> list[dict]:
        rows = []
        for line in _read_lines(m.run_dir / name, m.f(name)):
            row = self._parse(m, line, name)
            if row is not None:
                rows.append(row)
        return rows

    def _emit(self, m: Match, etype: str, rows: list[dict]) -> None:
        for row in rows:
            if etype == "red_attack" or etype == "benign_request":
                m.known_ids.add(row.get("request_id", ""))
            if (etype in ("red_attack", "red_unsent") or
                    (etype == "api_call" and row.get("agent") == "red")) and \
                    isinstance(row.get("round"), int):
                self._turn(m, row["round"], source="round_event")
            extra = {}
            if etype == "api_call":
                cc = cost_stats.call_cost(row, self.prices)
                extra = {"usd": cc["usd"], "usd_lower_bound": cc["lower_bound"]}
            elif etype == "snapshot":
                extra = {"newly_solved": sorted(set(row.get("after_solved") or [])
                                                - set(row.get("before_solved") or []))}
            self.log.append(etype, {"match_id": m.match_id, "row": row, **extra})

    def _parse(self, m: Match, line: str, name: str) -> dict | None:
        try:
            row = json.loads(line)
        except ValueError:
            row = None
        if not isinstance(row, dict):
            m.counts["malformed"] += 1
            self.log.append("tail_warning", {"match_id": m.match_id, "file": name,
                                             "detail": "malformed line skipped"})
            return None
        return row

    def _poll_files(self, m: Match) -> None:
        # read: effects first (see poll)
        results = {name: self._rows(m, name) for name, _ in reversed(RESULTS)}
        catalog = self._load_once(m, "challenge_catalog.json")
        after = {name: self._rows(m, name) for name, _ in AFTER_PROXY}
        proxy_lines, newly_frozen = self._read_proxy(m)
        traffic = {name: self._rows(m, name) for name, _ in reversed(TRAFFIC)}
        library = self._load_once(m, "library.json")
        calls = traffic.pop("api_calls.jsonl")
        # emit: causes first
        if library is not None:
            self.log.append("library_loaded", {
                "match_id": m.match_id, "library_version": library.get("library_version"),
                "n_rules": len(library.get("rules") or [])})
        self._emit(m, "api_call", [c for c in calls if c.get("agent") == "red"])
        for name, etype in TRAFFIC:
            if name in traffic:
                self._emit(m, etype, traffic[name])
        self._proxy_lines(m, proxy_lines)
        for name, etype in AFTER_PROXY:
            self._emit(m, etype, after[name])
        if newly_frozen:
            self.log.append("proxy_frozen", {"match_id": m.match_id})
        if catalog is not None:
            self.log.append("challenge_catalog", {"match_id": m.match_id, "categories": catalog})
        for name, etype in RESULTS:
            if name == "verdicts.jsonl":  # Blue's calls come before its verdicts file
                self._emit(m, "api_call", [c for c in calls if c.get("agent") != "red"])
            self._emit(m, etype, results[name])

    def _load_once(self, m: Match, name: str):
        p = m.run_dir / name
        if name in m.seen_once or not p.is_file():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return None  # still being written
        m.seen_once.add(name)
        return data

    def _read_proxy(self, m: Match) -> tuple[list[str], bool]:
        """New proxy lines, following the move at freeze; and whether it froze just now."""
        frozen = m.run_dir / "proxy.jsonl"
        if frozen.is_file():
            ino = _inode(frozen)
            if ino != m.proxy.inode:  # not the file we were reading: start it from 0
                m.proxy = _File(inode=ino)
            newly = not m.proxy_frozen
            m.proxy_frozen = True
            return _read_lines(frozen, m.proxy), newly
        live = self.live_dir / "proxy.jsonl"
        ino = _inode(live)
        if ino is None:
            return [], False
        if ino != m.proxy.inode:  # rotation (or first sight): a new file
            m.proxy = _File(inode=ino)
        return _read_lines(live, m.proxy), False

    def _proxy_lines(self, m: Match, lines: list[str]) -> None:
        waiting, m.pending = m.pending, []
        for row, age in waiting:
            self._proxy_row(m, row, age + 1)
        for line in lines:
            row = self._parse(m, line, "proxy.jsonl")
            if row is not None:
                self._proxy_row(m, row, 0)

    def _proxy_row(self, m: Match, row: dict, age: int) -> None:
        rid = row.get("request_id") or ""
        if not rid:
            m.counts["stray"] += 1
        elif rid in m.known_ids:
            self.log.append("proxy_line", {"match_id": m.match_id, "row": row})
        elif age < PENDING_POLLS:
            m.pending.append((row, age))
        else:
            m.counts["unknown"] += 1

    # -- transcript -------------------------------------------------------------
    def _read_transcript(self) -> None:
        if self.transcript is None:
            return
        ino = _inode(self.transcript)
        if ino is None:
            return
        if ino != self._tx.inode:
            self._tx = _File(inode=ino)
        for line in _read_lines(self.transcript, self._tx):
            mm = RE_MATCH.match(line)
            if mm:
                self._tx_match = mm.group(1)
                if self.match is None or self.match.match_id != self._tx_match:
                    if (self.runs_dir / self._tx_match).is_dir():
                        self._start(self._tx_match, self._lock())
                continue
            if self.match is not None and self._tx_match == self.match.match_id:
                self._tx_ready.append(line)
            elif self._tx_match is not None:  # its match has not started here yet
                self._tx_backlog.append(line)

    def _apply_transcript(self, pre_traffic_only: bool = False) -> None:
        """Apply ready transcript lines. pre_traffic_only: only the leading lines before the
        first slot / failure line (the seed and reset lines are printed before traffic)."""
        ready, self._tx_ready = self._tx_ready, []
        for k, line in enumerate(ready):
            if pre_traffic_only and (RE_SLOT.match(line) or RE_FAILED.match(line)):
                self._tx_ready = ready[k:]
                return
            self._transcript_line(line)

    def _transcript_line(self, line: str) -> None:
        m = self.match
        if m is None:
            return
        if mm := RE_SEED.match(line):
            seed, source, n_red, n_benign = int(mm[1]), mm[2], int(mm[3]), int(mm[4])
            try:
                m.planned = schedule_mod.plan(n_red, [""] * n_benign, seed)
            except ValueError:
                m.planned, m.derive = None, False
            self.log.append("match_plan", {"match_id": m.match_id, "seed": seed,
                                           "seed_source": source, "n_red": n_red,
                                           "n_benign": n_benign, "planned": m.planned,
                                           "derived": True})
        elif mm := RE_RESET.match(line):
            self.log.append("target_reset", {"match_id": m.match_id, "solved": int(mm[1])})
            self._next_turn(m, 0)
        elif mm := RE_SLOT.match(line):
            slot = int(mm[1])
            kind = "red" if mm[2] is not None else "benign"
            self.log.append("slot_done", {
                "match_id": m.match_id, "slot": slot, "kind": kind,
                "round": int(mm[2]) if mm[2] else None, "benign_id": mm[3], "text": line})
            if m.planned is not None and m.derive:
                if slot > len(m.planned) or m.planned[slot - 1] != kind:
                    m.derive = False
                    self.log.append("schedule_mismatch", {"match_id": m.match_id,
                                                          "slot": slot, "kind": kind})
                else:
                    self._next_turn(m, slot)
        elif mm := RE_FAILED.match(line):
            self.log.append("match_failed", {"match_id": m.match_id, "step": mm[1],
                                             "error": mm[2]})

    def _next_turn(self, m: Match, done: int) -> None:
        """After `done` slots, if the next planned slot is Red, Red's turn starts now."""
        if m.planned is None or not m.derive or done >= len(m.planned):
            return
        if m.planned[done] == "red":
            self._turn(m, m.planned[:done + 1].count("red"), source="transcript",
                       slot=done + 1)

    def _turn(self, m: Match, rnd: int, source: str, slot: int | None = None) -> None:
        """Exactly one red_turn_start per Red round, always before the round's first event.
        source "transcript": when the previous slot ended (from the schedule); source
        "round_event": the round's own first line arrived first (no thinking time known)."""
        if rnd in m.turns_started:
            return
        m.turns_started.add(rnd)
        if slot is None and m.planned is not None and m.derive:
            reds = [i for i, k in enumerate(m.planned) if k == "red"]
            slot = reds[rnd - 1] + 1 if rnd <= len(reds) else None
        self.log.append("red_turn_start", {"match_id": m.match_id, "round": rnd, "slot": slot,
                                           "source": source, "derived": True})
