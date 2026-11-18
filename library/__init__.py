"""The rule library's WRITE side (Stage 6.1, D26). Imported ONLY by tools/promote_rules.py.

Nothing that runs during a match or a replay may import this package: run_match.py,
tools/replay_blue.py, blue/ and judge/ read libraries through the read-only
rules/library.py. tests/test_train_test_wall.py checks the import graph, so the in-match
and replay code paths have no writer to call, in any mode (S6-3).
"""
