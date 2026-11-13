"""The casework loop on a real orchestrator in a scripted public record. No network.

The clock is fixed, so two runs dump the same case file. The world is ``pi_case_world``: a UK trading company,
its Dutch parent, and a Cypriot nominee company at the top of the chain.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, List

import pytest
from pi_case_world import SUBJECT, run_case

from bunnyhole.engine.pi import CaseType, StopReason
from bunnyhole.engine.pi_casework_guide import GuideDecision, ProposedLead
from bunnyhole.engine.pi_dispatch import BLOCKED_IN_CASEWORK, PI_DISPATCH

_BOARD_PATH = "/tmp/pi_case_board.json"


def _lead(board: Any, kind: str, target: str) -> Any:
    return next(lead for lead in board.leads if lead.kind == kind and lead.target == target)


def test_the_case_follows_the_ownership_chain_it_finds() -> None:
    orch, world = run_case()
    board = orch._pi_case_board
    assert board.stop_reason is StopReason.DEAD_END
    assert "ownership (partial)" in board.stop_detail
    walked = [lead.target for lead in board.leads if lead.kind == "ownership"]
    assert walked == ["Borealis Holdings B.V.", "Kestrel Nominees Ltd"]
    # each owner was opened by the lead whose result named it, not planned up front
    assert _lead(board, "ownership", "Borealis Holdings B.V.").opened_by == "L1"
    borealis = _lead(board, "ownership", "Borealis Holdings B.V.")
    assert _lead(board, "ownership", "Kestrel Nominees Ltd").opened_by == borealis.lead_id
    # the parent's registry record hangs off the parent's node, never off the subject
    gleif_calls = {value: origin for source, value, origin in world.calls if source == "gleif"}
    assert gleif_calls["Borealis Holdings B.V."].startswith("lei:")
    assert gleif_calls[SUBJECT].startswith("company:")


def test_every_node_of_the_chain_is_screened_after_the_subject() -> None:
    orch, world = run_case()
    board = orch._pi_case_board
    screened = [value for source, value, _origin in world.calls if source == "ofac_sdn"]
    assert screened == [SUBJECT, "Borealis Holdings B.V.", "Kestrel Nominees Ltd"]
    sanctions = next(q for q in board.questions if q.key == "sanctions")
    assert sanctions.status == "answered"
    assert "3 of 3 name(s)" in sanctions.answer
    assert "not clearance" in sanctions.answer
    assert all(lead.mandatory for lead in board.leads if lead.kind == "screen")


def test_questions_carry_the_answer_and_what_is_still_needed() -> None:
    orch, _world = run_case()
    questions = {q.key: q for q in orch._pi_case_board.questions}
    assert questions["identity"].status == "answered"
    assert "NORTHGATE TRADING LTD" in questions["identity"].answer
    assert questions["ownership"].status == "partial"
    assert "stops at Kestrel Nominees Ltd" in questions["ownership"].answer
    assert "Companies House" in questions["ownership"].missing  # the source that was not reached, and why
    assert questions["structure"].status == "answered"
    assert "registered in CY" in questions["structure"].answer
    assert questions["litigation"].status == "partial"
    assert "CourtListener" in questions["litigation"].missing
    result = orch.compile_full_result()
    assert result["pi"]["loop_mode"] == "casework"
    assert result["pi"]["done_status"] == "not_met"


def test_a_natural_person_in_the_chain_gets_role_relevant_checks_only() -> None:
    orch, world = run_case(psc_key=True)
    board = orch._pi_case_board
    person = _lead(board, "screen", "Marta Ilves")
    assert person.target_type == "person"
    assert set(person.sources) <= {
        "opensanctions", "ca_sanctions", "ofac_sdn", "un_consolidated", "uk_sanctions_list", "news_narrative",
    }
    touched = {source for source, value, _origin in world.calls if value == "Marta Ilves"}
    assert touched <= set(person.sources)
    ownership = next(q for q in board.questions if q.key == "ownership")
    assert "Marta Ilves" in ownership.answer


def test_a_sanctions_hit_on_a_parent_stops_the_case_for_counsel() -> None:
    orch, world = run_case(sanctioned=["Kestrel Nominees Ltd"])
    board = orch._pi_case_board
    assert board.stop_reason is StopReason.ESCALATED
    assert "compliance counsel" in board.stop_detail
    assert not any(source in ("court_dockets", "news_narrative") for source, _v, _o in world.calls)
    unworked = [lead for lead in board.leads if lead.status == "not_worked"]
    assert unworked and all("compliance counsel" in lead.outcome for lead in unworked)
    sanctions = next(q for q in board.questions if q.key == "sanctions")
    assert sanctions.status == "answered"
    assert "Soft name match" in sanctions.answer and "Kestrel Nominees Ltd" in sanctions.answer
    with pytest.raises(ValueError, match="not reopened"):
        asyncio.run(orch.chase_pi_leads([unworked[0].lead_id]))


def test_the_budget_stops_the_case_and_is_never_exceeded() -> None:
    orch, world = run_case(budget=10)
    board = orch._pi_case_board
    assert board.stop_reason is StopReason.BUDGET
    assert board.calls_used == 10 == len(world.calls)
    assert any(lead.status == "not_worked" and "budget" in lead.outcome for lead in board.leads)
    assert orch.compile_full_result()["pi"]["case_board"]["stop_reason"] == "budget_spent"


def test_only_dispatchable_sources_are_ever_called() -> None:
    _orch, world = run_case(psc_key=True)
    called = {source for source, _value, _origin in world.calls}
    assert called <= set(PI_DISPATCH)
    assert called.isdisjoint(BLOCKED_IN_CASEWORK)


def test_a_person_subject_is_worked_as_a_case_too() -> None:
    orch, world = run_case(
        seeds=[("company", "Jane Q Example"), ("email", "jane@example.org")],
        engagement_overrides={
            "case_type": CaseType.LOCATE, "subject_is_person": True, "matter_ref": "CV-24-00123456",
            "purpose_category": "service_of_process",
        },
    )
    board = orch._pi_case_board
    assert board.questions and {q.key for q in board.questions} >= {"identity", "address", "courts"}
    name_sources = {source for source, value, _origin in world.calls if value == "Jane Q Example"}
    # a person's name never goes to a company registry or a complaint database
    assert name_sources.isdisjoint({"gleif", "uk_psc", "cfpb_complaints", "nonprofit_990s"})
    assert "court_dockets" in name_sources
    status = next(q for q in board.questions if q.key == "status")
    assert status.status == "out_of_reach" and "by hand" in status.missing
    guessed = next(lead for lead in board.leads if lead.kind == "pivot" and lead.target == "jane")
    assert "two-anchor rule" in guessed.why


class _Officer:
    """A scripted AI case officer: proposes two leads once the nominee turns up, one of them out of bounds."""

    name = "llm"

    def __init__(self) -> None:
        self.phases: List[str] = []
        self.proposed = False

    async def advise(self, *, board: Any, block: Any, offered: Any, phase: str, targets: Any = (), last: Any = None) -> GuideDecision:
        self.phases.append(phase)
        names = {target.name for target in targets}
        if last is not None and "Kestrel Nominees Ltd" in names and not self.proposed:
            self.proposed = True
            return GuideDecision(
                read="The chain ends at a nominee company in Cyprus, so the press on that company is worth a look.",
                new_leads=[
                    ProposedLead(target="Kestrel Nominees Ltd", sources=["news_narrative", "holehe"], why="Who stands behind the nominee?"),
                    ProposedLead(target="Somebody Invented", sources=["osint_identity"], why="A name the evidence never gave."),
                ],
            )
        return GuideDecision()


def test_an_ai_case_officer_opens_leads_inside_the_limits_code_enforces() -> None:
    officer = _Officer()
    orch, world = run_case(guide=officer)
    board = orch._pi_case_board
    assert board.guide_name == "llm"
    assert officer.phases[0] == "plan" and all(p.startswith("debrief:") for p in officer.phases[1:])
    opened = [lead for lead in board.leads if "case officer" in lead.opened_by]
    assert [lead.target for lead in opened] == ["Kestrel Nominees Ltd"]
    assert opened[0].sources == ["news_narrative"]  # the blocked source it named was dropped
    assert ("news_narrative", "Kestrel Nominees Ltd") in {(s, v) for s, v, _o in world.calls}
    assert not any(value == "Somebody Invented" for _s, value, _o in world.calls)
    refused = [log.detail for log in orch.graph.logs if log.action == "PI_OFFICER_REFUSED"]
    assert refused == ["'Somebody Invented': not a name in the evidence"]
    note = next(note for note in board.notes if "nominee company in Cyprus" in note.counsel)
    assert "Case officer opened" in note.next


def test_a_model_stop_cannot_skip_the_screening_of_the_chain() -> None:
    class _Quitter:
        name = "llm"

        async def advise(self, **_kwargs: Any) -> GuideDecision:
            return GuideDecision(request_stop="done")

    orch, world = run_case(guide=_Quitter())
    board = orch._pi_case_board
    screened = [value for source, value, _origin in world.calls if source == "ofac_sdn"]
    assert screened == [SUBJECT, "Borealis Holdings B.V.", "Kestrel Nominees Ltd"]
    assert board.stop_reason is StopReason.DONE and "case officer recommended stopping" in board.stop_detail
    assert any(lead.status == "not_worked" for lead in board.leads)  # the optional corroboration was dropped


def test_chasing_a_lead_reopens_the_case_and_works_it() -> None:
    orch, world = run_case(budget=10)
    board = orch._pi_case_board
    assert board.stop_reason is StopReason.BUDGET
    chaseable = orch.pi_chaseable_leads()
    assert chaseable
    before = len(world.calls)
    result = asyncio.run(orch.chase_pi_leads([chaseable[0].lead_id], extra_budget=20))
    after = orch._pi_case_board
    assert after.chase_rounds == 1 and after.budget == 30
    assert len(world.calls) > before
    assert next(lead for lead in after.leads if lead.lead_id == chaseable[0].lead_id).status != "not_worked"
    assert result["pi"]["case_board"]["chase_rounds"] == 1
    with pytest.raises(ValueError, match="No lead to chase"):
        asyncio.run(orch.chase_pi_leads(["L999"]))


def test_case_board_json_is_byte_identical() -> None:
    first = run_case()[0]._pi_case_board.model_dump(mode="json")
    second = run_case()[0]._pi_case_board.model_dump(mode="json")
    encoded = json.dumps(first, sort_keys=True)
    assert encoded == json.dumps(second, sort_keys=True)
    assert "bh_" not in encoded
    with open(_BOARD_PATH, "w", encoding="utf-8") as handle:
        handle.write(encoded)


def test_a_case_officer_reading_that_clears_the_subject_is_withheld() -> None:
    class _Clearer:
        name = "llm"

        async def advise(self, *, last: Any = None, **_kwargs: Any) -> GuideDecision:
            return GuideDecision(read="The lists came back empty, so the company is clean." if last else "")

    orch, _world = run_case(guide=_Clearer())
    readings = {note.counsel for note in orch._pi_case_board.notes}
    assert len(readings) == 1 and "reading withheld" in readings.pop()
