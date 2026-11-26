"""liveserver/tailer.py (Stage 7 #12): a fake match (real orchestrator + traffic loop, fake
provider) is tailed while it runs, and again after it ends (late start / catch-up). Every
artifact line becomes exactly one event, in causal order."""

from __future__ import annotations

import threading
import time

from live_fakes import PRICES, RED_TEXTS, SEED, jsonl, lab, play  # noqa: F401 (fixture)
from liveserver import tailer as T
from runner import schedule as schedule_mod

FILE_EVENTS = {n: e for n, e in T.TRAFFIC + T.AFTER_PROXY + T.RESULTS}


def tail_live(lab, with_transcript=True, **kw):
    live, runs, transcript = lab
    log = T.EventLog()
    tl = T.Tailer(log, live, runs, transcript if with_transcript else None, prices=PRICES)
    th = threading.Thread(target=tl.run, args=(0.002,), daemon=True)
    th.start()
    code, match_dir = play(lab, **kw)
    deadline = time.monotonic() + 10
    while "lock_released" not in log.types() and time.monotonic() < deadline:
        time.sleep(0.01)
    tl.stop()
    th.join(2)
    return code, match_dir, log.since(None)


def idx(events, pred) -> int:
    return next(i for i, e in enumerate(events) if pred(e))


def check(events, match_dir):
    types = [e["type"] for e in events]
    # every artifact line -> exactly one event of its type
    for name, etype in FILE_EVENTS.items():
        assert types.count(etype) == len(jsonl(match_dir / name)), (name, etype)
    proxy = [r for r in jsonl(match_dir / "proxy.jsonl") if r["request_id"]]
    assert types.count("proxy_line") == len(proxy) > 0
    assert {e["row"]["request_id"] for e in events if e["type"] == "proxy_line"} == \
        {r["request_id"] for r in proxy}  # the previous match's line never leaks in
    for once in ("match_started", "match_plan", "target_reset", "proxy_frozen",
                 "match_finished", "lock_released"):
        assert types.count(once) == 1, once
    assert types[0] == "match_started" and types[-2:] == ["match_finished", "lock_released"]

    # the plan is the orchestrator's schedule, and every slot is reported done
    import json
    m = json.loads((match_dir / "match.json").read_text())
    plan = next(e for e in events if e["type"] == "match_plan")
    assert plan["seed"] == SEED and plan["derived"] is True
    assert plan["planned"] == [s.split(":")[0] for s in m["traffic"]["schedule"]]
    assert plan["planned"] == schedule_mod.plan(plan["n_red"], [""] * plan["n_benign"], SEED)
    assert types.count("slot_done") == len(plan["planned"])
    assert "schedule_mismatch" not in types

    # one red_turn_start per Red round, before anything else of that round
    turns = [e for e in events if e["type"] == "red_turn_start"]
    assert sorted(e["round"] for e in turns) == list(range(1, len(RED_TEXTS) + 1))
    for t in turns:
        first = idx(events, lambda e: e["type"] in ("api_call", "red_unsent", "red_attack")
                    and e["row"].get("round") == t["round"]
                    and (e["type"] != "api_call" or e["row"]["agent"] == "red"))
        assert events.index(t) < first

    # Red call -> record -> proxy line -> snapshot, per sent round
    for e in events:
        if e["type"] != "red_attack":
            continue
        rid, rnd = e["row"]["request_id"], e["row"]["round"]
        call = max(i for i, x in enumerate(events) if x["type"] == "api_call"
                   and x["row"]["agent"] == "red" and x["row"]["round"] == rnd)
        rec = events.index(e)
        px = idx(events, lambda x: x["type"] == "proxy_line" and x["row"]["request_id"] == rid)
        sn = idx(events, lambda x: x["type"] == "snapshot" and x["row"]["request_id"] == rid)
        assert call < rec < px < sn
    # failures are ordinary events
    unsent = [e["row"]["kind"] for e in events if e["type"] == "red_unsent"]
    assert unsent == ["brain_failure", "guard_block"]
    # the landed burst comes from the snapshot
    assert any(e["newly_solved"] == ["Login Admin"] for e in events if e["type"] == "snapshot")

    # all traffic, then Blue's calls, then verdicts, then the Judge (D47)
    last_traffic = max(i for i, e in enumerate(events)
                       if e["type"] in ("red_attack", "benign_request", "proxy_line", "snapshot")
                       or (e["type"] == "api_call" and e["row"]["agent"] == "red"))
    blue = [i for i, e in enumerate(events) if e["type"] == "api_call"
            and e["row"]["agent"] == "blue"]
    assert blue and last_traffic < min(blue)
    assert max(blue) < idx(events, lambda e: e["type"] == "verdict") \
        < idx(events, lambda e: e["type"] == "round_record") < types.index("match_finished")
    assert all("usd" in e for e in events if e["type"] == "api_call")
    fin = events[-2]
    assert fin["status"] == m["status"] and fin["cost_usd"] == m["cost"]["total_usd"]
    assert fin["started_at"] == m["started_at"] and fin["finished_at"] == m["finished_at"]
    # the plan precedes every traffic event, also when one poll sees everything (catch-up)
    assert types.index("match_plan") < min(types.index(t) for t in
                                            ("red_attack", "benign_request", "api_call"))
    assert fin["tail_counts"]["malformed"] == 0


def test_tail_while_the_match_runs(lab):
    code, match_dir, events = tail_live(lab)
    assert code == 0
    check(events, match_dir)


def test_catch_up_after_the_match_matches_live_order(lab):
    live, runs, transcript = lab
    code, match_dir = play(lab)
    assert code == 0
    log = T.EventLog()
    T.Tailer(log, live, runs, transcript, prices=PRICES).poll()  # one poll sees everything
    events = log.since(None)
    check(events, match_dir)
    # without a lock, a late tailer finds the match through the transcript
    assert events[0]["source"] == "transcript"


def test_without_transcript_turns_come_from_round_events(lab):
    code, match_dir, events = tail_live(lab, with_transcript=False)
    assert code == 0
    types = [e["type"] for e in events]
    assert not {"match_plan", "slot_done", "target_reset"} & set(types)
    turns = [e for e in events if e["type"] == "red_turn_start"]
    assert [t["round"] for t in turns] == list(range(1, len(RED_TEXTS) + 1))
    assert all(t["source"] == "round_event" and t["slot"] is None for t in turns)
    # each turn start comes right before its round's first event
    for t in turns:
        nxt = events[events.index(t) + 1]
        assert nxt["row"]["round"] == t["round"]
    assert types[-2:] == ["match_finished", "lock_released"]


def test_finished_match_without_lock_or_transcript_is_not_announced(lab):
    live, runs, _ = lab
    code, _ = play(lab)
    assert code == 0
    log = T.EventLog()
    T.Tailer(log, live, runs, None, prices=PRICES).poll()
    assert log.since(None) == []


def test_previous_log_lines_are_counted_not_emitted(lab):
    code, match_dir, events = tail_live(lab)
    counts = events[-2]["tail_counts"]
    # the previous match's stray line and old id are read only if the tailer saw the log
    # before rotation; either way they never become events
    assert counts["stray"] in (0, 1) and counts["unknown"] in (0, 1)
    assert all(e["row"]["path"] != "/old" for e in events if e["type"] == "proxy_line")


def test_failed_match_reports_failure_then_finish(lab):
    code, match_dir, events = tail_live(lab, fail_blue=True)
    assert code != 0
    types = [e["type"] for e in events]
    fail = next(e for e in events if e["type"] == "match_failed")
    assert fail["step"] == "blue" and "blue fell over" in fail["error"]
    assert types.index("match_failed") < types.index("match_finished")
    assert events[-2]["status"] == "failed" and events[-2]["failed_step"] == "blue"
    assert "verdict" not in types


def test_partial_lines_wait_for_their_newline(tmp_path):
    p = tmp_path / "f.jsonl"
    st = T._File()
    p.write_text('{"a": 1}\n{"b"')
    assert T._read_lines(p, st) == ['{"a": 1}']
    with p.open("a") as fh:
        fh.write(': 2}\n')
    assert T._read_lines(p, st) == ['{"b": 2}']


def test_event_log_reconnect_semantics():
    log = T.EventLog()
    for i in range(3):
        log.append("x", {"i": i})
    assert [e["id"] for e in log.since(1)] == [2, 3]
    assert [e["id"] for e in log.since(3)] == []
    assert [e["id"] for e in log.since(999)] == [1, 2, 3]  # client of an earlier server run
    log.append("match_started", {})
    assert [e["type"] for e in log.since(2)] == ["match_started"]  # older match: full replay


# ---- D61 matchup 3: a Blue replay followed from its transcript line --------------------

def test_follows_a_replay_from_its_transcript_line(lab, tmp_path):  # noqa: F811
    from live_fakes import LiveOps, tee
    from tools import replay_blue
    live, runs, transcript = lab
    code, src = play(lab)
    assert code == 0
    replays = tmp_path / "replays"
    tx2 = tmp_path / "replay.transcript.log"
    log = T.EventLog()
    tl = T.Tailer(log, live, runs, tx2, prices=PRICES, replays_dir=replays)
    th = threading.Thread(target=tl.run, args=(0.002,), daemon=True)
    th.start()
    out = tee(tx2)
    rcode, rdir = replay_blue.replay(src, replays / "r1", ops=LiveOps(live, out), out_fn=out,
                                     engine="claude", rules_mode="on")
    deadline = time.monotonic() + 10
    while "lock_released" not in log.types() and time.monotonic() < deadline:
        time.sleep(0.01)
    tl.stop()
    th.join(2)
    assert rcode == 0
    events = log.since(None)
    types = [e["type"] for e in events]
    start = events[0]
    assert start["type"] == "match_started" and start["kind"] == "replay"
    assert start["source_match_id"] == src.name and start["match_id"] != src.name
    for name, etype in FILE_EVENTS.items():   # every replay artifact line -> one event
        assert types.count(etype) == len(jsonl(rdir / name)), (name, etype)
    # the same end markers as a match (the dashboard's end signal; a replay takes no lock)
    assert types.count("match_finished") == 1 and types[-2:] == ["match_finished", "lock_released"]
    assert events[-2]["status"] == "completed"


def test_a_replay_line_outside_the_replays_dir_is_never_followed(lab, tmp_path):  # noqa: F811
    live, runs, _ = lab
    other = tmp_path / "elsewhere" / "r9"
    other.mkdir(parents=True)
    tx = tmp_path / "t.log"
    tx.write_text(f"replay r9 of m1 -> {other}\nreplay r8 of m1 -> ../../etc\n")
    log = T.EventLog()
    tl = T.Tailer(log, live, runs, tx, prices=PRICES, replays_dir=tmp_path / "replays")
    tl.poll()
    assert log.types() == []
