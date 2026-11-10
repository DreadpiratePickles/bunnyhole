"""Round 3: the code-built sections never silently drop a critical line, and their wording is outcome-specific.

Critical lines (the sanctions not-screened / not-clearance line, the standing limits, the ownership-walk stop, the
set-aside notice) come first and are never dropped. Many lead findings collapse into one line listing the ids. If
anything non-critical is still dropped, an explicit omission line says how many. Pure: no network, no model.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List

import pytest
from pi_narrative_helpers import narrative_result

from bunnyhole.engine import pi_narrative
from bunnyhole.engine.llm_providers import LLMOutcome
from bunnyhole.engine.pi_narrative_input import (
    CONTRADICTION,
    NOT_SEARCHED,
    OWNERSHIP_WALK,
    SANCTIONS_STATUS,
    SEARCHED,
    SET_ASIDE,
    STANDING_LIMITS,
    GapItem,
    build_evidence,
)
from bunnyhole.engine.pi_narrative_sections import MAX_LINES, next_step_lines, not_established_lines

OMITTED = re.compile(r"^- (\d+) further lines omitted; see the full code-built report above\.$")


def many_leads(count: int) -> Dict[str, Any]:
    result = copy.deepcopy(narrative_result())
    base = result["pi"]["findings"][0]
    result["pi"]["findings"] = [
        dict(base, node_id=f"x:{i}", label=f"Lead Item {i}", finding_label="lead", source_count=1, relevance="related")
        for i in range(count)
    ]
    return result


def assert_critical_lines(not_established: List[str], steps: List[str]) -> None:
    text = "\n".join(not_established)
    assert "were not screened or not reached" in text and "is not clearance" in text
    assert "free public passive sources only" in text
    assert "The ownership walk covered" in text and "establish beneficial ownership" in text
    assert "weak name match that was set aside" in text
    joined = "\n".join(steps)
    assert "Screen the sanctions lists that were not reached" in joined
    assert "licensed investigator or a lawyer for court records beyond the public portals" in joined
    assert "Obtain the shareholder register" in joined
    assert "Seek a second anchor" in joined


@pytest.mark.parametrize("count", [30, 100])
def test_many_lead_findings_keep_every_critical_line_and_collapse_the_leads(count: int) -> None:
    evidence = build_evidence(many_leads(count))
    assert evidence is not None
    not_established, steps = not_established_lines(evidence.gaps), next_step_lines(evidence.gaps)
    assert_critical_lines(not_established, steps)
    assert len(not_established) <= MAX_LINES and len(steps) <= MAX_LINES
    leads = [line for line in not_established if "lead only" in line or "leads only" in line]
    assert len(leads) == 1 and leads[0].endswith("]") and ", " in leads[0].rsplit("[", 1)[1]
    second = [line for line in steps if "second independent source" in line]
    assert len(second) == 1 and second[0].startswith("- Seek a second independent source")
    assert evidence.key["F1"].description  # the citation key still resolves every collapsed id


def test_critical_lines_come_before_everything_else() -> None:
    evidence = build_evidence(many_leads(30))
    assert evidence is not None
    lines = not_established_lines(evidence.gaps)
    first_lead = next(i for i, line in enumerate(lines) if "leads only" in line)
    for marker in ("not clearance", "free public passive", "The ownership walk", "set aside"):
        assert next(i for i, line in enumerate(lines) if marker in line) < first_lead


def test_few_lead_findings_stay_one_line_each() -> None:
    evidence = build_evidence(many_leads(3))
    assert evidence is not None
    assert sum("rests on a single source" in line for line in not_established_lines(evidence.gaps)) == 3


def many_gaps(count: int) -> List[GapItem]:
    critical = [
        GapItem("G1", STANDING_LIMITS, "standing limits"),
        GapItem("S1", SANCTIONS_STATUS, "partial", ("screened: A", "B: not reached (timeout)")),
        GapItem("W1", SET_ASIDE, "Some Name", ("Some Name",)),
        GapItem("O1", OWNERSHIP_WALK, "2", ("Holdco",)),
    ]
    filler = [GapItem(f"G{i + 10}", SEARCHED, f"class_{i}", ("negative",)) for i in range(count)]
    filler += [GapItem(f"G{i + 200}", NOT_SEARCHED, f"unique_class_{i}") for i in range(count)]
    filler += [GapItem(f"G{i + 400}", CONTRADICTION, f"date: dispute {i}") for i in range(count)]
    return [*filler, *critical]  # the critical gaps arrive LAST on purpose


def test_an_overflow_keeps_critical_lines_and_says_how_many_lines_were_omitted() -> None:
    gaps = many_gaps(40)
    lines = not_established_lines(gaps)
    text = "\n".join(lines)
    assert "is not clearance" in text and "free public passive" in text and "The ownership walk" in text
    assert "set aside" in text
    note = OMITTED.match(lines[-1])
    assert note is not None, lines[-1]
    assert int(note.group(1)) == 120 - (MAX_LINES - 4)
    assert len(lines) == MAX_LINES + 1
    steps = next_step_lines(gaps)
    assert OMITTED.match(steps[-1]) is not None
    assert "Screen the sanctions lists that were not reached" in "\n".join(steps)


def test_no_omission_line_when_nothing_was_dropped() -> None:
    assert not any(OMITTED.match(line) for line in not_established_lines(many_gaps(1)))


def test_the_citation_key_resolves_ids_of_a_collapsed_line() -> None:
    evidence = build_evidence(many_leads(30))
    assert evidence is not None
    text = "### Connections\n- [F1,F2] Lead Item 0 and Lead Item 1 appear in separate records here.\n"
    section = pi_narrative._section(text, evidence, LLMOutcome(text="x", provider="p", model="m"))
    key = section.split("**Citation key**", 1)[1]
    assert "- F20:" in key and "- F25:" in key


# ------------------------------------------------------------------------------------- wording


@pytest.mark.parametrize(
    "outcome,expected,forbidden",
    [
        ("hit", "returned records; the records are cited above", "proof of absence"),
        ("negative", "returned nothing; absence from this source is not proof of absence", "records are cited"),
        ("unavailable", "could not be checked", "proof of absence"),
        ("unknown", "could not be checked", "proof of absence"),
    ],
)
def test_searched_wording_depends_on_the_outcome(outcome: str, expected: str, forbidden: str) -> None:
    line = not_established_lines([GapItem("G2", SEARCHED, "court_dockets", (outcome,))])[0]
    assert expected in line and forbidden not in line, line


def test_the_standing_limits_step_does_not_claim_court_records_need_legal_process() -> None:
    step = next_step_lines([GapItem("G1", STANDING_LIMITS, "standing limits")])[0]
    assert "court records beyond the public portals searched" in step
    assert "only legal process can reach (court" not in step and step.startswith("- Engage")


def test_a_long_identity_note_is_whole_to_300_characters_and_cut_at_a_word_with_an_ellipsis_beyond() -> None:
    def note_line(text: str) -> str:
        result = copy.deepcopy(narrative_result())
        result["pi"]["identity_notes"] = [text]
        evidence = build_evidence(result)
        assert evidence is not None
        return next(line for line in not_established_lines(evidence.gaps) if "Identity note" in line)

    words = " ".join(f"word{i}" for i in range(200))
    whole = words[:290].rsplit(" ", 1)[0]
    assert whole in note_line(whole) and "…" not in note_line(whole)
    cut = note_line(words)
    assert cut.count("…") == 1 and "word0" in cut
    body = cut.split("program: ", 1)[1].rsplit("…", 1)[0]
    assert len(body) <= 300 and re.fullmatch(r"(?:word\d+ )*word\d+", body.strip()), body
