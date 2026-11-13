"""Hot-loaded rules (Stage 5.5, D4, D9). PURE and deterministic.

An ordered set of validated rules, each tagged with the log_seq of the line it was
created on. `fire(req, log_seq)` evaluates ONLY rules created on an EARLIER line
(created_at_log_seq < log_seq): a rule never applies to the line that produced it
(D4, hot-load applies from the next line).

Tie-break: when the firing rules disagree on the CWE, the EARLIEST hot-loaded rule
wins (deterministic, explainable, and an AI cannot win by stacking similar rules).
`conflict` is true iff the fired rules name more than one distinct CWE.

Lives in the neutral rules/ package so Blue (which applies the rules) and the Judge
(which re-runs the sequence to cross-check Blue's rule verdicts) share ONE code
path. Any behaviour change here is governed by judge.JUDGE_VERSION.
"""

from __future__ import annotations

from dataclasses import dataclass

from rules import engine
from rules.validator import Validated


@dataclass(frozen=True)
class Firing:
    rule_ids: list[str]        # every rule that fired, in hot-load order
    cwe: str | None            # the tie-break winner's CWE; None iff nothing fired
    conflict: bool             # fired rules name more than one distinct CWE


class HotLoad:
    def __init__(self) -> None:
        self._rules: list[tuple[int, Validated]] = []

    def __len__(self) -> int:
        return len(self._rules)

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
        if not live:
            return Firing([], None, False)
        f = engine.forms(req)
        fired = [r for r in live if engine.fires(r, f)]
        if not fired:
            return Firing([], None, False)
        cwes = {r.rule["cwe"] for r in fired}
        return Firing([r.rule_id for r in fired], fired[0].rule["cwe"], len(cwes) > 1)
