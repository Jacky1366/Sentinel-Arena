"""runner/schedule.py: seeded interleaving that preserves BOTH sequences' order."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from runner import schedule  # noqa: E402

BENIGN = ["n01", "n02", "n10", "n11", "h01", "h06"]


def drain(s: schedule.Schedule) -> list[schedule.Slot]:
    out = []
    while (slot := s.next()) is not None:
        out.append(slot)
    return out


def test_same_seed_same_schedule():
    a = drain(schedule.Schedule(7, BENIGN, seed=5202))
    b = drain(schedule.Schedule(7, BENIGN, seed=5202))
    assert a == b


def test_different_seeds_interleave_differently():
    labels = {tuple(schedule.Schedule(7, BENIGN, seed=s).planned_labels())
              for s in range(20)}
    assert len(labels) > 10


@pytest.mark.parametrize("seed", range(50))
def test_both_sequences_keep_their_order(seed):
    slots = drain(schedule.Schedule(7, BENIGN, seed=seed))
    assert [s.round for s in slots if s.kind == "red"] == list(range(1, 8))
    assert [s.benign_id for s in slots if s.kind == "benign"] == BENIGN
    ids = [s.benign_id for s in slots]
    assert ids.index("n10") < ids.index("n11")  # register before log in
    assert [s.slot for s in slots] == list(range(1, len(BENIGN) + 8))


def test_every_slot_exactly_once_and_matches_the_plan():
    s = schedule.Schedule(7, BENIGN, seed=1)
    slots = drain(s)
    assert len(slots) == 7 + len(BENIGN)
    assert [x.label() for x in slots] == s.planned_labels()
    assert s.next() is None


def test_red_finishing_early_drops_its_slots_and_benign_still_goes():
    s = schedule.Schedule(7, BENIGN, seed=3)
    slots = []
    while (slot := s.next()) is not None:
        slots.append(slot)
        if slot.kind == "red" and slot.round == 2:
            s.red_done()
    assert [x.round for x in slots if x.kind == "red"] == [1, 2]
    assert [x.benign_id for x in slots if x.kind == "benign"] == BENIGN
    assert [x.slot for x in slots] == list(range(1, len(slots) + 1))


def test_seed_bounds():
    with pytest.raises(ValueError):
        schedule.Schedule(1, [], seed=-1)
    with pytest.raises(ValueError):
        schedule.Schedule(1, [], seed=2**32)
    for _ in range(20):
        assert 0 <= schedule.new_seed() <= schedule.SEED_MAX


def test_no_benign_is_red_only_in_order():
    assert schedule.Schedule(3, [], seed=9).planned_labels() == ["red:1", "red:2", "red:3"]


def test_red_exhausted_retracts_the_unfilled_slot():
    s = schedule.Schedule(7, BENIGN, seed=11)
    slots = []
    while (slot := s.next()) is not None:
        if slot.kind == "red" and slot.round == 3:
            s.red_exhausted()  # Red had no third attack
            continue
        slots.append(slot)
    assert [x.round for x in slots if x.kind == "red"] == [1, 2]
    assert [x.benign_id for x in slots if x.kind == "benign"] == BENIGN
    assert [x.slot for x in slots] == list(range(1, len(slots) + 1))
    assert s.executed == slots


def test_red_exhausted_only_after_a_red_slot():
    s = schedule.Schedule(0, ["n01"], seed=1)
    s.next()
    with pytest.raises(RuntimeError):
        s.red_exhausted()
