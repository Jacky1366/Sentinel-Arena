"""The match schedule: how Red and benign traffic interleave (Stage 5.2). PURE.

A seeded shuffle decides ONLY the interleaving. The internal order of BOTH
sequences is preserved: Red's attacks keep their order (round 5's already_solved
depends on round 4), and benign entries keep the benign set's order (n10 register
always precedes n11 log in). The benign set's `requires` field is a second
guarantee checked by its validator; this ordering is the mechanism.

The orchestrator drives one slot at a time (`next()`), so Red is asked for exactly
one attack per Red slot. That is the interface Stage 5.6's AI Red needs: it
decides each attack from its previous responses. If Red finishes early
(`red_done()`, or `red_exhausted()` when it had nothing for the slot it was
just given), its remaining slots are dropped and the benign requests still go.

    sched = Schedule(n_red=7, benign_ids=["n01", ...], seed=1234)
    while (slot := sched.next()) is not None:
        ...  # slot.kind == "red" -> slot.round; "benign" -> slot.benign_id
"""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass

SEED_MAX = 2**32 - 1


def new_seed() -> int:
    """A fresh seed for a match run without --seed (recorded in match.json)."""
    return secrets.randbelow(SEED_MAX + 1)


@dataclass(frozen=True)
class Slot:
    slot: int                    # 1-based position in the executed schedule
    kind: str                    # "red" | "benign"
    round: int | None = None     # Red's own round number (red slots)
    benign_id: str | None = None  # benign slots

    def label(self) -> str:
        return f"red:{self.round}" if self.kind == "red" else f"benign:{self.benign_id}"


def plan(n_red: int, benign_ids: list[str], seed: int) -> list[str]:
    """The kinds in schedule order, e.g. ["benign", "red", "red", "benign", ...].
    Only the kinds are shuffled, so each sequence keeps its own order."""
    if not 0 <= seed <= SEED_MAX:
        raise ValueError(f"seed must be in 0..{SEED_MAX}, not {seed}")
    kinds = ["red"] * n_red + ["benign"] * len(benign_ids)
    random.Random(seed).shuffle(kinds)
    return kinds


class Schedule:
    def __init__(self, n_red: int, benign_ids: list[str], seed: int):
        self.seed = seed
        self._kinds = plan(n_red, benign_ids, seed)
        self._benign = list(benign_ids)
        self._pos = 0
        self._red_round = 0
        self._benign_i = 0
        self._red_done = False
        self.executed: list[Slot] = []

    def planned_labels(self) -> list[str]:
        """The full planned schedule (what match.json records)."""
        out, r, b = [], 0, 0
        for k in self._kinds:
            if k == "red":
                r += 1
                out.append(f"red:{r}")
            else:
                out.append(f"benign:{self._benign[b]}")
                b += 1
        return out

    def red_done(self) -> None:
        """Red has no more attacks: drop its remaining slots."""
        self._red_done = True

    def red_exhausted(self) -> None:
        """Red had no attack for the red slot just issued: retract that slot (so
        slot numbers stay contiguous) and drop Red's remaining slots."""
        if not self.executed or self.executed[-1].kind != "red":
            raise RuntimeError("red_exhausted() must follow a red slot from next()")
        self.executed.pop()
        self._red_round -= 1
        self._red_done = True

    def next(self) -> Slot | None:
        while self._pos < len(self._kinds):
            kind = self._kinds[self._pos]
            self._pos += 1
            if kind == "red":
                if self._red_done:
                    continue
                self._red_round += 1
                slot = Slot(len(self.executed) + 1, "red", round=self._red_round)
            else:
                slot = Slot(len(self.executed) + 1, "benign",
                            benign_id=self._benign[self._benign_i])
                self._benign_i += 1
            self.executed.append(slot)
            return slot
        return None
