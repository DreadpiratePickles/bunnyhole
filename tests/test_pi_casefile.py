"""The case file's pure parts: the opening lead sheet, pivots, questions, chasing and the case officer's limits."""

from __future__ import annotations

from typing import Any, List

from pi_case_world import engagement, run_case

from bunnyhole.engine.pi import CaseBoard, CaseLead, CaseType
from bunnyhole.engine.pi_casefile import (
    CHASEABLE,
    MAX_PROPOSALS_PER_TURN,
    Proposal,
    Subject,
    admit_proposals,
    chaseable_leads,
    close_remaining,
    known_targets,
    open_leads,
    open_questions,
    plan_leads,
    question_specs,
    questions_settled,
    reopen_leads,
    retire_unneeded,
    set_aside_leads,
)
from bunnyhole.engine.pi_dispatch import PI_DISPATCH, SOURCE_ACCEPTS
from bunnyhole.engine.pi_reference import playbook_for


def _lead(lead_id: str, **overrides: Any) -> CaseLead:
    fields: dict[str, Any] = {
        "lead_id": lead_id, "kind": "pivot", "target": "Acme Ltd", "target_type": "company", "why": "why",
        "sources": ["gleif"], "questions": ["ownership"],
    }
    fields.update(overrides)
    return CaseLead(**fields)


def _board(leads: List[CaseLead], **overrides: Any) -> CaseBoard:
    return CaseBoard(hypotheses=[], budget=50, leads=leads, **overrides)


def test_the_opening_sheet_is_the_playbook_order_on_what_the_client_gave() -> None:
    subjects = [Subject("company", "Acme Holdings Ltd", "company:acme"), Subject("domain", "acme.example", "domain:acme.example")]
    leads, blocked = plan_leads(playbook_for(CaseType.DUE_DILIGENCE), subjects, engagement())
    assert blocked == []
    steps = [lead for lead in leads if lead.kind == "playbook" and lead.target == "Acme Holdings Ltd"]
    assert [lead.step_order for lead in steps] == [1, 2, 3, 4, 5]
    assert [lead.priority for lead in steps] == sorted((lead.priority for lead in steps), reverse=True)
    assert all(lead.mandatory and lead.opened_by == "intake" for lead in leads)
    for lead in leads:  # no source is ever planned on a kind of target it does not take
        assert all(lead.target_type in SOURCE_ACCEPTS[source] and source in PI_DISPATCH for source in lead.sources)
    domain = [lead for lead in leads if lead.target == "acme.example"]
    assert {source for lead in domain for source in lead.sources} == {"wayback", "osint_domain"}
    assert any(lead.kind == "selector" for lead in domain)


def test_a_person_plan_keeps_blocked_probes_off_the_sheet_and_logs_them() -> None:
    subjects = [Subject("person", "Jane Q Example", "person:jane"), Subject("email", "jane@example.org", "email:jane")]
    person = engagement(case_type=CaseType.LOCATE, subject_is_person=True)
    leads, blocked = plan_leads(playbook_for(CaseType.LOCATE), subjects, person)
    assert ("holehe", "Jane Q Example") in blocked  # named by the playbook, never run: logged as skipped
    assert all("holehe" not in lead.sources for lead in leads)
    assert all(source not in ("gleif", "uk_psc", "cfpb_complaints") for lead in leads for source in lead.sources)


def test_every_case_type_has_questions_for_both_kinds_of_subject() -> None:
    for case_type in CaseType:
        for is_person in (True, False):
            specs = question_specs(case_type, is_person)
            assert len(specs) >= 4 and len({spec.key for spec in specs}) == len(specs)
            questions = open_questions(case_type, is_person)
            assert all(question.status == "open" for question in questions)
    assert questions_settled([]) is False


def test_open_leads_come_out_by_priority_then_by_the_order_they_were_opened() -> None:
    board = _board([_lead("L1", priority=50), _lead("L2", priority=80), _lead("L3", priority=80), _lead("L4", priority=99, status="worked")])
    assert [lead.lead_id for lead in open_leads(board)] == ["L2", "L3", "L1"]


def test_an_optional_lead_is_retired_once_its_question_is_settled() -> None:
    questions = open_questions(CaseType.DUE_DILIGENCE, False)
    settled = [q.model_copy(update={"status": "answered"}) if q.key == "ownership" else q for q in questions]
    board = _board(
        [
            _lead("L1"), _lead("L2", mandatory=True), _lead("L3", questions=["sanctions"]),
            _lead("L4", opened_by="L2 (case officer)"),
        ],
        questions=settled,
    )
    statuses = {lead.lead_id: lead.status for lead in retire_unneeded(board).leads}
    assert statuses == {"L1": "not_worked", "L2": "open", "L3": "open", "L4": "open"}


def test_chasing_reopens_what_time_cut_off_and_never_what_scope_closed() -> None:
    board = _board([
        _lead("L1", status="not_worked"), _lead("L2", status="suggested"), _lead("L3", status="set_aside"),
        _lead("L4", status="worked"), _lead("L5", status="not_reached"), _lead("L6", status="suggested", sources=[]),
    ])
    assert [lead.lead_id for lead in chaseable_leads(board)] == ["L1", "L2", "L5"]
    assert all(lead.status in CHASEABLE for lead in chaseable_leads(board))
    reopened_board, reopened, refused = reopen_leads(board, ["l1", "L3", "L4", "L9"])
    assert [lead.lead_id for lead in reopened] == ["L1"]
    assert reopened[0].status == "open" and reopened[0].mandatory
    assert refused == [
        "L3: set aside on scope grounds, not available to chase",
        "L4: already worked",
        "L9: no such lead on the sheet",
    ]
    assert [lead.lead_id for lead in open_leads(reopened_board)] == ["L1"]


def test_close_remaining_can_keep_the_mandatory_leads_open() -> None:
    board = _board([_lead("L1"), _lead("L2", mandatory=True)])
    kept = close_remaining(board, "quiet", keep_mandatory=True)
    assert [lead.status for lead in kept.leads] == ["not_worked", "open"]
    assert [lead.status for lead in close_remaining(board, "stop").leads] == ["not_worked", "not_worked"]


def test_the_case_officer_cannot_set_aside_a_mandatory_lead() -> None:
    board = _board([_lead("L1"), _lead("L2", mandatory=True), _lead("L3", status="worked")])
    after, done = set_aside_leads(board, {"l1": "adds nothing", "L2": "skip the screen", "L3": "x", "L8": "x"})
    assert done == ["L1"]
    assert after.leads[0].status == "set_aside" and "case officer: adds nothing" in after.leads[0].outcome
    assert after.leads[1].status == "open"


def test_a_proposed_lead_must_target_a_name_in_the_evidence_with_a_source_that_fits() -> None:
    orch, _world = run_case(psc_key=True)
    board = orch._pi_case_board
    snapshot, view = orch._case_view
    subjects = orch._case_subjects
    targets = known_targets(snapshot, view, subjects)
    assert {"northgate trading ltd", "borealis holdings b.v.", "kestrel nominees ltd", "marta ilves"} <= set(targets)
    assert targets["marta ilves"].target_type == "person" and not targets["marta ilves"].is_subject
    proposals = [
        Proposal("Kestrel Nominees Ltd", ("court_dockets", "hudsonrock"), "dockets on the nominee"),
        Proposal("Marta Ilves", ("osint_identity", "email_pivots", "court_dockets"), "find her accounts"),
        Proposal("Nobody In Evidence", ("gleif",), "invented"),
        Proposal("Borealis Holdings B.V.", ("gleif",), "a fourth proposal in one turn"),
    ]
    admitted, refused = admit_proposals(board, proposals, snapshot, view, subjects, orch._case_done, opened_by="L3")
    assert len(proposals[:MAX_PROPOSALS_PER_TURN]) == 3
    assert [(lead.target, lead.sources, lead.opened_by) for lead in admitted] == [
        ("Kestrel Nominees Ltd", ["court_dockets"], "L3 (case officer)"),
    ]
    assert refused == [
        "'Marta Ilves': none of the sources named may run on a person",  # no accounts or contact points
        "'Nobody In Evidence': not a name in the evidence",
    ]


def test_a_persons_case_never_opens_a_lead_on_another_person() -> None:
    orch, _world = run_case(psc_key=True)
    snapshot, view = orch._case_view
    person_case = snapshot.model_copy(update={
        "engagement": snapshot.engagement.model_copy(update={"subject_is_person": True, "case_type": CaseType.BACKGROUND}),
    })
    _admitted, refused = admit_proposals(
        orch._pi_case_board, [Proposal("Marta Ilves", ("ofac_sdn",), "screen her")], person_case, view,
        orch._case_subjects, set(), opened_by="L1",
    )
    assert refused == ["'Marta Ilves': another person is outside this engagement"]


def test_the_subject_is_screened_on_every_list_even_when_the_playbook_names_one() -> None:
    subjects = [Subject("company", "Acme Holdings Ltd", "company:acme")]
    fraud = engagement(case_type=CaseType.FRAUD_SCREEN)
    leads, _blocked = plan_leads(playbook_for(CaseType.FRAUD_SCREEN), subjects, fraud)
    planned = {source for lead in leads for source in lead.sources}
    assert {"ofac_sdn", "un_consolidated", "uk_sanctions_list", "ca_sanctions", "opensanctions"} <= planned
    screen = next(lead for lead in leads if lead.kind == "screen")
    assert screen.mandatory and "opensanctions" not in screen.sources  # the playbook step already runs that one
    # a case type with no sanctions question does not screen
    locate = engagement(case_type=CaseType.LOCATE, subject_is_person=True)
    person = [Subject("person", "Jane Q Example", "person:jane")]
    assert not [lead for lead in plan_leads(playbook_for(CaseType.LOCATE), person, locate)[0] if lead.kind == "screen"]
