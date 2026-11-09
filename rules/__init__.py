"""Neutral rule machinery shared by Blue and the Judge (Stage 5.3).

Lives outside blue/ on purpose: the Judge must never import the subject's code.
Blue (signatures, and from 5.5 its rules) and the Judge (facts 3 and 4b) both use
this package, so a request is normalized and a rule is evaluated in exactly one
way. ANY behaviour change in this package is governed by judge.JUDGE_VERSION
(and normalization changes also by normalize.NORMALIZATION_VERSION).
"""
