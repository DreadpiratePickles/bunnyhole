"""Report and bottom-line behaviour that appears only when a case board is present.

A sweep block keeps the sixteen headings, the human "done when" sentence, and no Case bullet.
Casework sections are checked once the case-board models exist.
"""

from __future__ import annotations

from typing import Any

import pytest
from pi_helpers import report_block, report_sections

from bunnyhole.engine.pi import PIBlock, PlaybookProgress
from bunnyhole.engine.pi_report import build_pi_report


def _result(block: PIBlock) -> dict[str, Any]:
    return {"pi": block.model_dump(mode="json"), "seed_query": "Acme Holdings Ltd"}


def test_sweep_report_has_no_investigation_log_and_keeps_the_human_done_when() -> None:
    block = report_block(
        done_when="Registry, ownership and sanctions are each addressed",
        playbook_progress=[PlaybookProgress(order=1, action="Registry lookup", sources=["gleif"], status="done")],
    )
    report = build_pi_report(_result(block))
    sections = report_sections(report)
    assert "Investigation log" not in sections
    assert "Done when (judged by a human, not by Bunnyhole):" in sections["Playbook progress"]
    assert "**Case:**" not in sections["Bottom line"]
    assert "| Step | Action | Sources | Status | Evidence |" in sections["Playbook progress"]


def _models() -> Any:
    from bunnyhole.engine import pi

    if not hasattr(pi, "CaseBoard") or "case_board" not in PIBlock.model_fields:
        pytest.skip("case-board models are not on PIBlock yet")
    return pi


def test_casework_report_adds_the_log_and_the_hypothesis_table() -> None:
    pi = _models()
    board = pi.CaseBoard(
        budget=120,
        guide_name="playbook",
        stop_reason=pi.StopReason.DONE,
        stop_detail="done-when check met",
        calls_used=6,
        hypotheses=[
            pi.CaseHypothesis(
                key="dd_operating_business",
                text="The counterparty is a legitimate operating business.",
                status=pi.HypothesisStatus.SUPPORTED,
                score=1.2,
                evidence=[
                    pi.EvidenceLink(
                        signal="registry_active", direction="supports", weight=0.6,
                        detail="active", node_ids=["lei:example"],
                    )
                ],
            )
        ],
        log=[
            pi.CaseStepRecord(
                order=1, label="Registry lookup", tasks=["playbook:gleif:abcd1234"],
                new_findings=1, decision="continue", elapsed_s=0.0,
            ),
            pi.CaseStepRecord(
                order=101, label="follow-up: gleif corroborate the lead company:acme",
                tasks=["corroborate_lead:gleif:abcd1234"],
                new_findings=0, decision="stop:done", elapsed_s=0.0,
            ),
        ],
    )
    block = report_block(
        done_when="Registry, ownership and sanctions are each addressed",
        playbook_progress=[
            PlaybookProgress(order=1, action="Registry lookup", sources=["gleif"], status="done", evidence="1 hit")
        ],
        falsifiers=[
            "A second independent source that contradicts, or corroborates, the single-source lead "
            "'Acme Holdings Ltd' (company:acme)."
        ],
        source_log=[{
            "source": "gleif", "target": "Acme Holdings Ltd", "status": "hit",
            "detail": "company:acme", "at_utc": "2026-11-12T00:00:00+00:00",
        }],
        loop_mode="casework",
        case_board=board,
        done_status="met",
    )
    report = build_pi_report(_result(block))
    sections = report_sections(report)
    assert list(sections).index("Investigation log") == list(sections).index("Playbook progress") + 1
    assert "The counterparty is a legitimate operating business." in sections["Client theory vs. evidence"]
    assert "H1 " not in sections["Client theory vs. evidence"]
    assert "Done when: met (automated check)" in sections["Playbook progress"]
    assert "| Decision |" in sections["Playbook progress"]
    assert "attempted (gleif, hit)" in sections["What would change this conclusion"]
    assert "stop done" in sections["Bottom line"]
    assert sections["Bottom line"].startswith("- **Case:**")
