"""Stop precedence for the casework loop. No network."""

from __future__ import annotations

from bunnyhole.engine.pi import (
    CaseBoard,
    CaseType,
    Custodian,
    EscalationTrigger,
    OwnershipBlock,
    PIBlock,
    PIEngagement,
    SanctionsScreening,
    StopReason,
)
from bunnyhole.engine.pi_casework import CASE_ENDING_STOP_KEYS, STOP_EVALUATORS, step_stop_decision, stop_check
from bunnyhole.engine.pi_reference import PLAYBOOKS, STOP_KEYS, playbook_for


def _engagement(case_type: CaseType = CaseType.DUE_DILIGENCE) -> PIEngagement:
    return PIEngagement.model_construct(
        engagement_id="pi_stop_test",
        case_type=case_type,
        purpose="Counterparty review for a filed matter.",
        purpose_category="counterparty_due_diligence",
        subject_is_person=False,
        passive_only=True,
        created_at_utc="2026-01-01T00:00:00+00:00",
    )


def _block(case_type: CaseType = CaseType.DUE_DILIGENCE, **overrides: object) -> PIBlock:
    payload: dict = {"engagement": _engagement(case_type)}
    payload.update(overrides)
    return PIBlock(**payload)


def _always(_block: PIBlock) -> bool:
    return True


def _never(_block: PIBlock) -> bool:
    return False


def test_stop_check_precedence_is_escalation_then_done_then_budget_then_no_progress() -> None:
    playbook = playbook_for(CaseType.DUE_DILIGENCE)
    sanction_text = next(text for text, key in playbook.escalate_keys.items() if key == "sanctions_or_50_rule")
    other_text = next(text for text, key in playbook.escalate_keys.items() if key != "sanctions_or_50_rule")
    step = playbook.steps[0]
    assert step.stop_key == ""
    block = _block()
    spent = CaseBoard(hypotheses=[], calls_used=5, budget=5)
    fired = [
        EscalationTrigger(trigger=other_text, fired=True, why="nominee"),
        EscalationTrigger(trigger=sanction_text, fired=True, why="listed party"),
    ]
    quiet = [EscalationTrigger(trigger=sanction_text, fired=False, why="listed party")]

    assert stop_check(spent, step, block, fired, done_eval=_always, no_progress=True) == (
        StopReason.ESCALATED,
        "refer to compliance counsel: listed party",
    )
    assert stop_check(spent, step, block, quiet, done_eval=_always, no_progress=True) == (
        StopReason.DONE,
        "done-when check met",
    )
    assert stop_check(spent, step, block, quiet, done_eval=_never, no_progress=True) == (
        StopReason.BUDGET,
        "calls 5/5",
    )
    under = spent.model_copy(update={"calls_used": 1})
    assert stop_check(under, step, block, quiet, done_eval=_never, no_progress=True) == (
        StopReason.NO_PROGRESS,
        "no new findings and no hypothesis change",
    )
    assert stop_check(under, step, block, quiet, done_eval=_never, no_progress=False) is None


def test_sanctions_counsel_step_escalates_before_done() -> None:
    step = next(item for item in playbook_for(CaseType.DUE_DILIGENCE).steps if item.stop_key == "sanctions_counsel")
    block = _block(
        sanctions=SanctionsScreening(status="lists_run", hits=[{"list": "OFAC SDN", "name": "Acme"}]),
        ownership=OwnershipBlock(blocked_by_50_rule=["company:blocked"]),
    )
    board = CaseBoard(hypotheses=[], calls_used=0, budget=10)
    reason, detail = stop_check(board, step, block, [], done_eval=_always)  # type: ignore[misc]
    assert reason is StopReason.ESCALATED
    assert detail.startswith("refer to compliance counsel")
    assert "sanctions hits" in detail and "50% rule block" in detail
    clear = _block()
    assert stop_check(board, step, clear, [], done_eval=_never) is None


def test_cash_out_found_does_not_end_the_case() -> None:
    step = next(item for item in playbook_for(CaseType.ASSET_SEARCH).steps if item.stop_key == "cash_out_found")
    custodian = Custodian(
        finding="wallet:abc",
        custodian="KYC Exchange",
        instrument="subpoena",
        jurisdiction="us",
        note="cash-out point",
    )
    block = _block(CaseType.ASSET_SEARCH, custodians=[custodian])
    board = CaseBoard(hypotheses=[], calls_used=0, budget=10)
    assert stop_check(board, step, block, [], done_eval=_never, no_progress=False) is None
    assert step_stop_decision(step, block) == "stop:cash_out_found"
    assert step_stop_decision(step, _block(CaseType.ASSET_SEARCH)) == "continue"
    counsel = next(item for item in playbook_for(CaseType.DUE_DILIGENCE).steps if item.stop_key == "sanctions_counsel")
    assert step_stop_decision(counsel, block) == "continue"
    assert "cash_out_found" not in CASE_ENDING_STOP_KEYS


def test_every_playbook_stop_key_is_registered() -> None:
    found = {step.stop_key for playbook in PLAYBOOKS.values() for step in playbook.steps if step.stop_key}
    assert found == set(STOP_KEYS)
    assert found == {"sanctions_counsel", "cash_out_found"}
    for key in found:
        assert key in STOP_EVALUATORS
    assert STOP_EVALUATORS["sanctions_counsel"](_block())[0] is False
    assert STOP_EVALUATORS["cash_out_found"](_block())[0] is False
