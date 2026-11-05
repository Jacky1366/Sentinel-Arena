"""Tests for runner.stage2_run.snapshot_after stability polling.

A single attack can solve several challenges at slightly different times (round 4
solves two). snapshot_after must keep polling until the solved set stops changing,
so a late-registering challenge lands in THIS round's diff rather than leaking into
the next round and being misattributed. No Docker/network: poll/sleep/clock are
injected.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("stage2_run", REPO / "runner" / "stage2_run.py")
stage2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stage2)


class FakeClock:
    """A clock advanced only by sleep_fn, so timing is deterministic."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, d):
        self.t += d


def make_poll_fn(values):
    """Return successive values on each call; repeat the last once exhausted."""
    it = iter(values)
    state = {"last": None}

    def poll():
        try:
            state["last"] = next(it)
        except StopIteration:
            pass
        return state["last"]

    return poll


def run(before, values, settle=100.0, stable_polls=3):
    clk = FakeClock()
    return stage2.snapshot_after(
        before, settle=settle, poll=0.25, stable_polls=stable_polls,
        poll_fn=make_poll_fn(values), sleep_fn=clk.sleep, clock=clk,
    )


def test_staggered_two_challenge_solve_captured_in_one_round():
    # Round-4 shape: before holds the CWE-89 solves; the attack solves two CWE-22
    # challenges, the second appearing a poll later.
    before = ["Login Admin", "User Credentials"]
    values = [
        ["Login Admin", "Poison Null Byte", "User Credentials"],                       # A appears
        ["Forgotten Developer Backup", "Login Admin", "Poison Null Byte", "User Credentials"],  # B appears late
        # then stable repeats of the full set:
        ["Forgotten Developer Backup", "Login Admin", "Poison Null Byte", "User Credentials"],
    ]
    after = run(before, values)
    newly = sorted(set(after) - set(before))
    assert newly == ["Forgotten Developer Backup", "Poison Null Byte"], newly


def test_no_change_returns_before():
    before = ["Login Admin"]
    # The solved set never changes from `before`.
    after = run(before, [["Login Admin"]], settle=2.0)
    assert after == before


def test_single_change_then_stable():
    before = []
    after = run(before, [["Login Admin"], ["Login Admin"]])
    assert after == ["Login Admin"]


def test_keeps_waiting_through_a_later_change():
    # A third challenge appears several polls after the first two: still captured.
    before = []
    values = [
        ["A"],
        ["A", "B"],
        ["A", "B"],
        ["A", "B", "C"],   # late third solve, before stability was reached
        ["A", "B", "C"],
    ]
    after = run(before, values)
    assert sorted(after) == ["A", "B", "C"]


def test_capped_by_settle():
    # If the set never stabilizes, the deadline stops the loop (no infinite wait).
    before = []
    # Alternating values never produce `stable_polls` consecutive equal reads.
    values = [["A"], ["A", "B"], ["A"], ["A", "B"], ["A"], ["A", "B"]]
    after = run(before, values, settle=1.0)  # ~4 polls then deadline
    assert set(after) <= {"A", "B"}  # returns whatever the last read was, no hang
