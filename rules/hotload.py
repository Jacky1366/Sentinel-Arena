"""Hot-loaded rules (Stage 5.5, D4, D9). PURE and deterministic.

An ordered set of validated rules, each tagged with the log_seq of the line it was
created on. `fire(req, log_seq)` evaluates ONLY rules created on an EARLIER line
(created_at_log_seq < log_seq): a rule never applies to the line that produced it
(D4, hot-load applies from the next line).

Tie-break: when the firing rules disagree on the CWE, the EARLIEST hot-loaded rule
wins (deterministic, explainable, and an AI cannot win by stacking similar rules).
`conflict` is true iff the fired rules name more than one distinct CWE.

Library rules (Stage 6.1, D21): rules from a cross-match library are PRELOADED. They
were created in an earlier match, so they are live from line 1 (every log_seq >= 1),
and they come FIRST in the tie-break, in library order, ahead of every in-match rule
(they are the oldest). Their ids are the library ids (lib-NNNN), so `rule_ids` may mix
lib-NNNN and r-NNN; `origin` names where the tie-break winner came from ("library" or
"match"; None iff nothing fired). Without preloaded rules the behaviour is exactly
Stage 5.5's.

Lives in the neutral rules/ package so Blue (which applies the rules) and the Judge
(which re-runs the sequence to cross-check Blue's rule verdicts) share ONE code
path. Any behaviour change here is governed by judge.JUDGE_VERSION.
"""

from __future__ import annotations

from dataclasses import dataclass

from collections.abc import Sequence

from rules import engine
from rules.library import LibraryRule
from rules.validator import Validated


@dataclass(frozen=True)
class Firing:
    rule_ids: list[str]        # every rule that fired, in hot-load order
    cwe: str | None            # the tie-break winner's CWE; None iff nothing fired
    conflict: bool             # fired rules name more than one distinct CWE
    origin: str | None = None  # "library" | "match" (the winner's); None iff nothing fired


class HotLoad:
    def __init__(self, preloaded: Sequence[LibraryRule] = ()) -> None:
        self._rules: list[tuple[int, Validated]] = []
        for lr in preloaded:
            if not lr.validated.valid:
                raise ValueError(f"library rule {lr.library_id} is not valid")
        self._pre: tuple[LibraryRule, ...] = tuple(preloaded)

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def preloaded(self) -> int:
        return len(self._pre)

    def add(self, rule: Validated) -> None:
        """Hot-load a VALID rule. Rules are added in creation order; a rule created on
        an earlier line than the last one added is a caller bug."""
        if not rule.valid:
            raise ValueError("only validated rules can be hot-loaded")
        seq = rule.rule["created_at_log_seq"]
        if self._rules and seq < self._rules[-1][0]:
            raise ValueError(f"rule {rule.rule_id} created at log_seq {seq} after a rule "
                             f"created at {self._rules[-1][0]}: rules must be added in order")
        self._rules.append((seq, rule))

    def fire(self, req: engine.Request, log_seq: int) -> Firing:
        live = [r for seq, r in self._rules if seq < log_seq]
        if not live and not self._pre:
            return Firing([], None, False)
        f = engine.forms(req)
        fired = [(lr.library_id, lr.validated) for lr in self._pre
                 if engine.fires(lr.validated, f)]
        n_library = len(fired)
        fired += [(r.rule_id, r) for r in live if engine.fires(r, f)]
        if not fired:
            return Firing([], None, False)
        cwes = {v.rule["cwe"] for _, v in fired}
        return Firing([rid for rid, _ in fired], fired[0][1].rule["cwe"], len(cwes) > 1,
                      "library" if n_library else "match")
