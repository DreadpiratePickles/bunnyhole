"""Follow-up task order, identity, and caps. No network."""

from __future__ import annotations

import hashlib

from bunnyhole.engine.pi import (
    CaseType,
    Contradiction,
    Finding,
    FindingLabel,
    OwnershipBlock,
    PIBlock,
    PIEngagement,
)
from bunnyhole.engine.pi_casework import follow_up_tasks, playbook_tasks, task_id
from bunnyhole.engine.pi_reference import playbook_for


def _engagement() -> PIEngagement:
    return PIEngagement.model_construct(
        engagement_id="pi_followup_test",
        case_type=CaseType.DUE_DILIGENCE,
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
        "relevance": "subject",
        "freshness": "unknown",
    }
    payload.update(overrides)
    return Finding(**payload)


def _block(**overrides: object) -> PIBlock:
    payload: dict = {"engagement": _engagement()}
    payload.update(overrides)
    return PIBlock(**payload)


def _lead_block() -> PIBlock:
    return _block(
        findings=[
            _finding("person:jane", "Jane Ltd", relevance="subject"),
            _finding("company:acme_ltd", "Acme Ltd", relevance="subject"),
        ]
    )


def _mixed_block() -> PIBlock:
    return _block(
        findings=[
            _finding("company:holdco", "🏢 Holdco Ltd", relevance="related"),
            _finding("company:acme_ltd", "Acme Ltd", relevance="subject"),
        ],
        ownership=OwnershipBlock(unresolved=["company:holdco (max_levels reached)"]),
        contradictions=[
            Contradiction(kind="registry_mismatch", description="lei differs", node_ids=["lei:5493", "company:acme"])
        ],
    )


def test_subject_lead_on_a_company_is_corroborated_by_four_sources() -> None:
    tasks = follow_up_tasks(_lead_block(), set(), limit=20)
    assert [(task.origin, task.source, task.target) for task in tasks] == [
        ("corroborate_lead", "gleif", "Acme Ltd"),
        ("corroborate_lead", "uk_psc", "Acme Ltd"),
        ("corroborate_lead", "sec_edgar", "Acme Ltd"),
        ("corroborate_lead", "news_narrative", "Acme Ltd"),
    ]
    assert tasks[0].why == "corroborate single-source lead 'Acme Ltd' (company:acme_ltd)"
    assert all(task.task_id == task_id(task.origin, task.source, task.target) for task in tasks)
    assert all("person:jane" not in task.why for task in tasks)


def test_unresolved_ownership_tasks_precede_lead_tasks() -> None:
    tasks = follow_up_tasks(_mixed_block(), set(), limit=20)
    digest = hashlib.sha1(b"Holdco Ltd").hexdigest()[:8]
    assert tasks[0].task_id == f"extend_ownership:uk_psc:{digest}"
    assert tasks[1].task_id == f"extend_ownership:gleif:{digest}"
    assert [task.origin for task in tasks[:2]] == ["extend_ownership", "extend_ownership"]
    assert [task.source for task in tasks[:2]] == ["uk_psc", "gleif"]
    assert tasks[0].target == "Holdco Ltd"
    assert "company:holdco" in tasks[0].why
    assert [task.origin for task in tasks[2:6]] == ["corroborate_lead"] * 4
    assert tasks[2].target == "Acme Ltd"
    assert tasks[-1].origin == "resolve_contradiction"
    assert tasks[-1].source == "gleif"
    assert tasks[-1].target == "lei:5493"
    assert "registry_mismatch" in tasks[-1].why


def test_done_task_ids_are_omitted() -> None:
    tasks = follow_up_tasks(_mixed_block(), set(), limit=20)
    done = {tasks[0].task_id, tasks[2].task_id}
    filtered = follow_up_tasks(_mixed_block(), done, limit=20)
    assert all(task.task_id not in done for task in filtered)
    assert len(filtered) == len(tasks) - 2
    assert [task.task_id for task in filtered] == [task.task_id for task in tasks if task.task_id not in done]


def test_limit_caps_the_list_and_zero_returns_nothing() -> None:
    block = _mixed_block()
    assert follow_up_tasks(block, set(), limit=0) == []
    capped = follow_up_tasks(block, set(), limit=3)
    assert len(capped) == 3
    assert capped == follow_up_tasks(block, set(), limit=20)[:3]
    assert [task.source for task in capped] == ["uk_psc", "gleif", "gleif"]


def test_the_same_inputs_produce_the_same_task_ids() -> None:
    block = _mixed_block()
    done = {"playbook:gleif:deadbeef"}
    first = [task.task_id for task in follow_up_tasks(block, done, limit=8)]
    second = [task.task_id for task in follow_up_tasks(block, done, limit=8)]
    assert first == second
    assert "playbook:gleif:deadbeef" not in first


def test_playbook_tasks_expand_mapped_recorders_in_source_order() -> None:
    step = next(item for item in playbook_for(CaseType.DUE_DILIGENCE).steps if "OpenSanctions" in item.sources)
    tasks = playbook_tasks(step, ["  Acme Ltd  ", "", "   "])
    assert [task.target for task in tasks] == ["Acme Ltd"] * len(tasks)
    assert tasks[0].origin == "playbook"
    assert tasks[0].step_order == step.order
    assert tasks[0].why == step.action
    assert "opensanctions" in [task.source for task in tasks]
    assert all(task.task_id == task_id("playbook", task.source, "Acme Ltd") for task in tasks)
    again = playbook_tasks(step, ["Acme Ltd"])
    assert [task.task_id for task in tasks] == [task.task_id for task in again]
