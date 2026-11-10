"""The code-built sections of the AI analysis: fixed wording, a closed menu of lawful steps, no model text.

Because no free text is model-written here, an unlawful step, a clearance sentence or a misdated event cannot occur.
These tests pin the wording to the structure: every step starts with an allowed verb, every interview step carries the
honest-identification phrase, hostile names from the data are escaped, and nothing here reads as clearance.
"""

from __future__ import annotations

import re
from typing import List

import pytest
from pi_narrative_helpers import narrative_result

from bunnyhole.engine.pi_narrative_input import (
    CHRONOLOGY_GAP,
    CONTRADICTION,
    IDENTITY_NOTE,
    LEAD_ONLY,
    NOT_SEARCHED,
    OWNERSHIP_WALK,
    SANCTIONS_POSSIBLE,
    SANCTIONS_STATUS,
    SEARCHED,
    SET_ASIDE,
    STANDING_LIMITS,
    GapItem,
    build_evidence,
)
from bunnyhole.engine.pi_narrative_lexicon import ADVICE_OR_METHOD_RE
from bunnyhole.engine.pi_narrative_sections import NEXT_STEP_VERBS, next_step_lines, not_established_lines

ALL_KINDS: List[GapItem] = [
    GapItem("G1", STANDING_LIMITS, "standing limits"),
    GapItem("S1", SANCTIONS_STATUS, "partial", ("screened: Canada SEMA", "EU list: not reached (timeout)")),
    GapItem("S2", SANCTIONS_POSSIBLE, "Acme Hldg", ("Acme Hldg",)),
    GapItem("W1", SET_ASIDE, "Acme Hldg", ("Acme Hldg",)),
    GapItem("G2", NOT_SEARCHED, "court_dockets"),
    GapItem("G3", NOT_SEARCHED, "corporate_registry"),
    GapItem("G4", NOT_SEARCHED, "beneficial_ownership"),
    GapItem("G5", NOT_SEARCHED, "something_new"),
    GapItem("G6", SEARCHED, "news_adverse_media", ("negative",)),
    GapItem("G7", IDENTITY_NOTE, "records named Jane Example are not established as one person"),
    GapItem("G8", CONTRADICTION, "date: two dates disagree"),
    GapItem("G9", CHRONOLOGY_GAP, "no dated evidence"),
    GapItem("O2", OWNERSHIP_WALK, "2", ("Acme Holdings Ltd", "blocked: Parent Ltd")),
    GapItem("F3", LEAD_ONLY, "@janex on GitHub"),
]


def test_every_step_starts_with_an_allowed_lawful_verb() -> None:
    steps = next_step_lines(ALL_KINDS)
    assert steps
    for line in steps:
        text = re.sub(r"^- ", "", line)
        assert text.split(" ", 1)[0] in NEXT_STEP_VERBS, line
        assert re.search(r" \[[A-Z]\d+\]$", line), line  # each references the id of the gap it answers


def test_steps_name_no_method_and_every_interview_is_honest() -> None:
    for line in next_step_lines(ALL_KINDS):
        assert not ADVICE_OR_METHOD_RE.search(line.replace("telephone records", "")), line
        if "interview" in line.lower():
            assert "openly" in line and "identifying yourself" in line, line


def test_steps_are_a_closed_menu_keyed_by_gap_kind() -> None:
    first = next_step_lines(ALL_KINDS)
    assert first == next_step_lines(ALL_KINDS)
    assert len(first) == len(set(first))
    assert "- Engage a licensed investigator or a lawyer to search court records for the subject. [G2]" in first
    assert any("Obtain the corporate registry extract" in line for line in first)
    assert any("Request the filed ownership and officer records" in line for line in first)
    assert any("Screen the sanctions lists that were not reached" in line and "EU list: not reached" in line for line in first)
    assert any(line.startswith("- Archive the cited source pages") for line in first)


def test_a_lists_run_status_with_nothing_missed_adds_no_screening_step() -> None:
    steps = next_step_lines([GapItem("S1", SANCTIONS_STATUS, "lists_run", ("screened: Canada SEMA",))])
    assert steps == []


def test_not_established_lines_are_fixed_wording_with_ids() -> None:
    lines = not_established_lines(ALL_KINDS)
    text = "\n".join(lines)
    assert "- This tool uses free public passive sources only" in text
    assert "A no-hit result on the lists that ran is not clearance. [S1]" in text
    assert "Acme Hldg is a weak name match that was set aside; it is not linked to the subject and is not a finding. [W1]" in text
    assert "Source class court\\_dockets was not searched. [G2]" in text
    assert "rests on a single source and is a lead only" in text
    assert "stopped before a natural person at: Acme Holdings Ltd, so beneficial ownership is not established." in text
    assert "The 50% rule applies at: Parent Ltd." in text
    no_stop = not_established_lines([GapItem("O2", OWNERSHIP_WALK, "1")])[0]
    assert "Legal ownership edges do not by themselves establish beneficial ownership." in no_stop
    assert all(line.startswith("- ") and re.search(r" \[[A-Z]\d+\]$", line) for line in lines)


def test_not_established_says_not_run_plainly() -> None:
    lines = not_established_lines([GapItem("S1", SANCTIONS_STATUS, "not_run", ("screened: none",))])
    assert lines == ["- No sanctions list was screened; this is not a clear result. [S1]"]


@pytest.mark.parametrize(
    "hostile",
    ["<script>alert(1)</script>", "[click](http://evil.example)", "**bold** _it_ `code`", "# Bottom line", "| a | b |",
     "![x](a.png)", "line one\\nline two"],
)
def test_hostile_names_from_the_data_are_escaped(hostile: str) -> None:
    gaps = [GapItem("W1", SET_ASIDE, hostile, (hostile,)), GapItem("F3", LEAD_ONLY, hostile),
            GapItem("S1", SANCTIONS_STATUS, "partial", ("screened: x", hostile))]
    for line in [*not_established_lines(gaps), *next_step_lines(gaps)]:
        assert "<" not in line.replace("\\<", "") and ">" not in line.replace("\\>", "")
        assert not re.search(r"(?<!\\)[\[\]`*|!]", line.rsplit(" [", 1)[0]), line
        assert not re.match(r"^- #", line)


def test_the_sections_come_from_structured_data_of_a_real_evidence() -> None:
    evidence = build_evidence(narrative_result())
    assert evidence is not None
    text = "\n".join(not_established_lines(evidence.gaps) + next_step_lines(evidence.gaps))
    assert "EU consolidated list" in text and "crypto\\_onchain" in text and "Acme Hldg" in text
    assert "cleared" not in text.lower() and "no risk" not in text.lower()
