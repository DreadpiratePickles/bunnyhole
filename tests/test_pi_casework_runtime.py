"""The casework loop on a real orchestrator with scripted sources. No network.

The clock is fixed, so two runs dump the same case board. Dispatch goes through the
methods ``fake_orchestrator`` already replaced with async mocks, except the one test
that plants an OFAC receipt.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from pi_helpers import fake_orchestrator

from bunnyhole.engine.models import DomainCategory, EntityType, EvidenceReceipt, GraphNode
from bunnyhole.engine.orchestrator import PERSON_CASEWORK_NOTE
from bunnyhole.engine.pi import CaseType, PIEngagement, StopReason
from bunnyhole.engine.pi_casework import playbook_tasks
from bunnyhole.engine.pi_casework_guide import DeterministicGuide
from bunnyhole.engine.pi_reference import playbook_for

_BOARD_PATH = "/tmp/pi_case_board.json"


def _engagement(**overrides: Any) -> PIEngagement:
    payload: dict[str, Any] = {
        "engagement_id": "pi_casework_runtime",
        "case_type": CaseType.DUE_DILIGENCE,
        "purpose": "Counterparty review for a filed matter.",
        "purpose_category": "counterparty_due_diligence",
        "subject_is_person": False,
        "passive_only": True,
        "created_at_utc": "2026-01-01T00:00:00+00:00",
    }
    payload.update(overrides)
    return PIEngagement.model_construct(**payload)


def _run(engagement: PIEngagement, *, budget: int = 10) -> Any:
    orch = fake_orchestrator(
        engagement, pi_loop="casework", pi_budget=budget, pi_guide=DeterministicGuide(),
    )
    orch._pi_clock = lambda: 0.0
    lead_type, root = orch._create_seed_node(orch.seed_query)
    orch._pi_start_case([(lead_type, orch.seed_query)])
    asyncio.run(orch._run_pi_casework([(lead_type, orch.seed_query, root)]))
    return orch


def test_playbook_order_stops_when_the_budget_is_spent() -> None:
    orch = _run(_engagement(), budget=10)
    board = orch._pi_case_board
    assert board is not None
    assert board.stop_reason is StopReason.BUDGET
    assert board.calls_used == 10
    assert board.calls_used <= board.budget
    orders = [step.order for step in board.log]
    assert orders == sorted(orders)
    assert orders == [step.order for step in board.log if step.order < 100]
    playbook = playbook_for(CaseType.DUE_DILIGENCE)
    spent = 0
    ran_orders: list[int] = []
    for step in playbook.steps:
        tasks = playbook_tasks(step, ["Acme Holdings Ltd"])
        if spent >= 10:
            break
        ran_orders.append(step.order)
        spent += min(len(tasks), 10 - spent)
    assert [step.order for step in board.log] == ran_orders
    assert ran_orders[-1] < playbook.steps[-1].order
    result = orch.compile_full_result()
    assert result["pi"]["loop_mode"] == "casework"
    assert result["pi"]["case_board"]["stop_reason"] == "budget_spent"
    assert result["pi"]["done_status"] in ("met", "not_met")


def test_a_sanctions_receipt_stops_the_case_before_later_steps() -> None:
    orch = fake_orchestrator(
        _engagement(), pi_loop="casework", pi_budget=120, pi_guide=DeterministicGuide(),
    )
    orch._pi_clock = lambda: 0.0

    async def _ofac(value: str, origin: str, hop: int) -> None:
        del value, origin, hop
        orch.graph.upsert_node(GraphNode(
            id="sanction:acme-holdings",
            label="Acme Holdings Ltd",
            entity_type=EntityType.ORGANIZATION,
            domain=DomainCategory.FIAT,
            receipts=[EvidenceReceipt(
                tool="ofac_sdn",
                domain=DomainCategory.FIAT,
                source_url="https://example.com/ofac",
                extracted_fact="soft name match on the SDN list",
            )],
        ))

    orch.pi_sources.screen_ofac_sdn = _ofac  # type: ignore[method-assign]
    lead_type, root = orch._create_seed_node(orch.seed_query)
    orch._pi_start_case([(lead_type, orch.seed_query)])
    asyncio.run(orch._run_pi_casework([(lead_type, orch.seed_query, root)]))
    board = orch._pi_case_board
    playbook = playbook_for(CaseType.DUE_DILIGENCE)
    sanctions = next(step for step in playbook.steps if step.stop_key == "sanctions_counsel")
    assert board.stop_reason is StopReason.ESCALATED
    assert [step.order for step in board.log] == [step.order for step in playbook.steps if step.order <= sanctions.order]
    assert "compliance counsel" in board.stop_detail


def test_a_person_subject_stays_on_the_sweep() -> None:
    orch = fake_orchestrator(
        _engagement(subject_is_person=True, matter_ref="MSA-2026-114"),
        pi_loop="casework",
        pi_budget=30,
    )
    assert orch._use_pi_casework() is False
    skips = [entry for entry in orch.pi_recorder.entries if entry.source == "casework"]
    assert len(skips) == 1
    assert skips[0].detail == PERSON_CASEWORK_NOTE
    assert orch._use_pi_casework() is False
    assert len([entry for entry in orch.pi_recorder.entries if entry.source == "casework"]) == 1


def test_case_board_json_is_byte_identical() -> None:
    first = _run(_engagement(), budget=10)._pi_case_board.model_dump(mode="json")
    second = _run(_engagement(), budget=10)._pi_case_board.model_dump(mode="json")
    encoded = json.dumps(first, sort_keys=True)
    assert encoded == json.dumps(second, sort_keys=True)
    assert "bh_" not in encoded
    with open(_BOARD_PATH, "w", encoding="utf-8") as handle:
        handle.write(encoded)
