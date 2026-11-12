"""Case board opening and hypothesis scoring. No network."""

from __future__ import annotations

import pytest

from bunnyhole.engine.pi import (
    CaseType,
    EntityProfile,
    EvidenceLink,
    Finding,
    FindingLabel,
    HypothesisStatus,
    OwnershipBlock,
    OwnershipEdge,
    PIBlock,
    PIEngagement,
    SanctionsScreening,
)
from bunnyhole.engine.pi_casework import (
    DECISIVE_REFUTES,
    open_case_board,
    score_hypotheses,
)
from bunnyhole.engine.pi_reference import playbook_for


def _engagement(case_type: CaseType) -> PIEngagement:
    return PIEngagement.model_construct(
        engagement_id="pi_casework_test",
        case_type=case_type,
        purpose="Counterparty review for a filed matter.",
        purpose_category="counterparty_due_diligence",
        subject_is_person=False,
        passive_only=True,
        created_at_utc="2026-01-01T00:00:00+00:00",
    )


def _finding(node_id: str, label: str, **overrides: object) -> Finding:
    payload: dict = {
        "node_id": node_id,
        "label": label,
        "finding_label": FindingLabel.LEAD,
        "source_count": 1,
        "freshness": "unknown",
        "relevance": "subject",
    }
    payload.update(overrides)
    return Finding(**payload)


def _block(case_type: CaseType = CaseType.DUE_DILIGENCE, **overrides: object) -> PIBlock:
    payload: dict = {"engagement": _engagement(case_type)}
    payload.update(overrides)
    return PIBlock(**payload)


def test_open_case_board_copies_due_diligence_hypotheses() -> None:
    playbook = playbook_for(CaseType.DUE_DILIGENCE)
    board = open_case_board(_engagement(CaseType.DUE_DILIGENCE), playbook, budget=5)
    assert [hypothesis.text for hypothesis in board.hypotheses] == list(playbook.typical_hypotheses)
    assert [hypothesis.key for hypothesis in board.hypotheses] == [
        "dd_operating_business",
        "dd_shell_nominee",
        "dd_exposed_affiliate",
    ]
    assert all(
        hypothesis.status is HypothesisStatus.OPEN and hypothesis.score == 0.0 and hypothesis.evidence == []
        for hypothesis in board.hypotheses
    )
    assert board.calls_used == 0
    assert board.budget == 5
    assert board.guide_name == "playbook"
    assert board.log == []
    assert board.stop_reason is None


def test_open_case_board_keys_the_other_entity_playbooks_and_slugifies_the_rest() -> None:
    expected = {
        CaseType.ASSET_SEARCH: ["as_nominee_abroad", "as_dissipated", "as_judgment_proof"],
        CaseType.FRAUD_SCREEN: ["fs_fraudulent", "fs_poorly_run", "fs_cloned"],
    }
    for case_type, keys in expected.items():
        playbook = playbook_for(case_type)
        board = open_case_board(_engagement(case_type), playbook, budget=2)
        assert [hypothesis.text for hypothesis in board.hypotheses] == list(playbook.typical_hypotheses)
        assert [hypothesis.key for hypothesis in board.hypotheses] == keys
    locate = playbook_for(CaseType.LOCATE)
    board = open_case_board(_engagement(CaseType.LOCATE), locate, budget=1)
    assert board.hypotheses[0].text == locate.typical_hypotheses[0]
    assert board.hypotheses[0].key == "the_subject_still_lives_at_the_last_known_address"


def _operating_block(*, status: str = "Active") -> PIBlock:
    return _block(
        entity_profile=EntityProfile(status=status, lei="549300TESTLEI000001"),
        findings=[_finding("sec:10-k", "annual filing", freshness="fresh")],
    )


def test_score_hypotheses_is_idempotent() -> None:
    playbook = playbook_for(CaseType.DUE_DILIGENCE)
    board = open_case_board(_engagement(CaseType.DUE_DILIGENCE), playbook, budget=4)
    block = _operating_block()
    before = board.model_dump()
    once, _changed = score_hypotheses(board, block, CaseType.DUE_DILIGENCE)
    twice, changed_again = score_hypotheses(board, block, CaseType.DUE_DILIGENCE)
    again, changed_from_scored = score_hypotheses(once, block, CaseType.DUE_DILIGENCE)
    assert [hypothesis.model_dump() for hypothesis in once.hypotheses] == [
        hypothesis.model_dump() for hypothesis in twice.hypotheses
    ]
    assert [hypothesis.model_dump() for hypothesis in once.hypotheses] == [
        hypothesis.model_dump() for hypothesis in again.hypotheses
    ]
    assert changed_again == changed_from_scored or changed_from_scored == []
    assert changed_from_scored == []
    assert board.model_dump() == before


def test_operating_business_is_supported_by_registry_lei_and_filings() -> None:
    playbook = playbook_for(CaseType.DUE_DILIGENCE)
    board = open_case_board(_engagement(CaseType.DUE_DILIGENCE), playbook, budget=4)
    scored, changed = score_hypotheses(board, _operating_block(), CaseType.DUE_DILIGENCE)
    hypothesis = next(item for item in scored.hypotheses if item.key == "dd_operating_business")
    supports = [link for link in hypothesis.evidence if link.direction == "supports"]
    assert {link.signal for link in supports} == {"registry_active", "lei_issued", "filings_recent"}
    assert hypothesis.score == pytest.approx(1.0)
    assert sum(link.weight for link in supports) == pytest.approx(0.4 + 0.3 + 0.3)
    assert len(supports) == 3
    assert hypothesis.status is HypothesisStatus.SUPPORTED
    assert "dd_operating_business" in changed


def test_registry_dissolved_rules_out_operating_business_even_with_supports() -> None:
    playbook = playbook_for(CaseType.DUE_DILIGENCE)
    board = open_case_board(_engagement(CaseType.DUE_DILIGENCE), playbook, budget=4)
    scored, _changed = score_hypotheses(board, _operating_block(status="Dissolved"), CaseType.DUE_DILIGENCE)
    hypothesis = next(item for item in scored.hypotheses if item.key == "dd_operating_business")
    assert any(link.signal == "registry_dissolved" and link.direction == "refutes" for link in hypothesis.evidence)
    assert any(link.direction == "supports" for link in hypothesis.evidence)
    assert hypothesis.status is HypothesisStatus.RULED_OUT


def test_clear_sanctions_screen_does_not_rule_out_exposed_affiliate() -> None:
    assert "sanctions_lists_run_no_hit" not in set().union(*DECISIVE_REFUTES.values())
    playbook = playbook_for(CaseType.DUE_DILIGENCE)
    board = open_case_board(_engagement(CaseType.DUE_DILIGENCE), playbook, budget=4)
    block = _block(sanctions=SanctionsScreening(status="lists_run", hits=[]))
    scored, _changed = score_hypotheses(board, block, CaseType.DUE_DILIGENCE)
    hypothesis = next(item for item in scored.hypotheses if item.key == "dd_exposed_affiliate")
    assert any(link.signal == "sanctions_lists_run_no_hit" for link in hypothesis.evidence)
    assert hypothesis.score == pytest.approx(-0.3)
    assert hypothesis.status is HypothesisStatus.OPEN
    assert hypothesis.status is not HypothesisStatus.RULED_OUT


def test_two_non_decisive_refutes_weaken_without_ruling_out() -> None:
    playbook = playbook_for(CaseType.DUE_DILIGENCE)
    board = open_case_board(_engagement(CaseType.DUE_DILIGENCE), playbook, budget=4)
    block = _block(
        findings=[_finding("sec:10-k", "annual filing", freshness="fresh")],
        ownership=OwnershipBlock(
            levels_walked=2,
            edges=[OwnershipEdge(child="company:acme", parent="person:jane")],
            unresolved=[],
        ),
    )
    scored, _changed = score_hypotheses(board, block, CaseType.DUE_DILIGENCE)
    hypothesis = next(item for item in scored.hypotheses if item.key == "dd_shell_nominee")
    refutes = [link for link in hypothesis.evidence if link.direction == "refutes"]
    assert {link.signal for link in refutes} == {"ubo_natural_person_reached", "filings_recent"}
    assert hypothesis.score == pytest.approx(-0.7)
    assert hypothesis.score <= -0.6
    assert hypothesis.status is HypothesisStatus.WEAKENED
    assert hypothesis.status is not HypothesisStatus.RULED_OUT


def test_unknown_case_type_clears_evidence_and_stays_open() -> None:
    playbook = playbook_for(CaseType.LOCATE)
    board = open_case_board(_engagement(CaseType.LOCATE), playbook, budget=2)
    poisoned = board.hypotheses[0].model_copy(
        update={
            "status": HypothesisStatus.SUPPORTED,
            "score": 3.0,
            "evidence": [EvidenceLink(signal="stale", direction="supports", weight=3.0, detail="prior")],
        }
    )
    board = board.model_copy(update={"hypotheses": [poisoned, *board.hypotheses[1:]]})
    scored, changed = score_hypotheses(board, _block(CaseType.LOCATE), CaseType.LOCATE)
    assert scored.hypotheses[0].status is HypothesisStatus.OPEN
    assert scored.hypotheses[0].evidence == []
    assert scored.hypotheses[0].score == 0.0
    assert changed == [poisoned.key]
