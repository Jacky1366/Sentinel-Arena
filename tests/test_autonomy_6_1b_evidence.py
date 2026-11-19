"""The committed Stage 6.1b autonomy table (data/golden/stats/autonomy_6.1b.{json,md}).
Read-only integrity check (designer GO for the 6.1b replay folders and the holdout,
2026-11-18): regenerating the table from the committed replay folders, library v5 and the
offline benign sets gives both files byte for byte."""

from __future__ import annotations

import json

from llm_fakes import REPO
from stats import autonomy  # noqa: E402
from tools import autonomy_table  # noqa: E402

STATS = REPO / "data" / "golden" / "stats"
R = REPO / "data" / "golden" / "replays"
SRC = ("ai-vs-ai-gate3-match1", "ai-vs-ai-gate3-match2", "ai-vs-ai-gate3-match3")
ARMS = [("rules off", [R / "gate-6.1b-2b" / f"{s}-off" for s in SRC]),
        ("rules on, empty v0000", [R / "gate-6.1b-2" / f"{s}-empty" for s in SRC]),
        ("rules on, library v5", [R / "gate-6.1b-2" / f"{s}-library" for s in SRC])]
TITLE = "Stage 6.1b autonomy table: the three M5 arms on the Gate 3 sources"


def test_the_committed_table_regenerates_byte_for_byte(tmp_path):
    doc = autonomy_table.build(ARMS, TITLE, REPO / "data" / "library" / "rule_library_v0005.json")
    j, m = autonomy_table.write(doc, tmp_path / "autonomy_6.1b")
    assert j.read_bytes() == (STATS / "autonomy_6.1b.json").read_bytes()
    assert m.read_bytes() == (STATS / "autonomy_6.1b.md").read_bytes()


def test_headline_numbers():
    doc = json.loads((STATS / "autonomy_6.1b.json").read_text())
    tot = {a: doc["arms"][a]["rows"]["total"] for a in doc["arms"]}
    assert [tot[a]["ai_calls"] for a, _ in ARMS] == [79, 70, 52]
    assert [tot[a]["cost_usd"] for a, _ in ARMS] == [0.003945, 0.004831, 0.002933]
    lib = tot["rules on, library v5"]["rule_coverage"]
    assert (lib["library"]["k"], lib["library"]["n"]) == (27, 79)
    assert all(t["verdict_fp"]["k"] == 0 for t in tot.values())
    assert all(r["holdout_v1"]["k"] == 0 and r["holdout_v1"]["n"] == 40
               for r in doc["library_fp"]["rules"].values())
    assert autonomy.fmt_rate(tot["rules off"]["verdict_fp"]) == "0/51 (0%) ≤7.0%"
