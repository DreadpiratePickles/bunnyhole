"""Offline checks for the casework guide. The model call is monkeypatched."""

from __future__ import annotations

import asyncio

from bunnyhole.engine.llm_providers import LLMOutcome
from bunnyhole.engine.pi import (
    CaseBoard,
    CaseTask,
    CaseType,
    CoverageRow,
    OwnershipBlock,
    PIBlock,
    PIEngagement,
    SanctionsScreening,
    StopReason,
)
from bunnyhole.engine.pi_casework_guide import (
    DeterministicGuide,
    GuideDecision,
    LLMGuide,
    apply_guide,
    build_guide_prompt,
    guide_may_stop,
    make_case_guide,
    parse_guide_reply,
)


def _task(task_id: str, source: str = "gleif") -> CaseTask:
    return CaseTask.model_construct(task_id=task_id, source=source, target="Acme", why="registry")


def _board() -> CaseBoard:
    return CaseBoard.model_construct(
        case_type=CaseType.DUE_DILIGENCE,
        calls_used=3,
        budget=12,
        hypotheses=[{"key": "h1", "status": "open", "score": 1, "text": "Acme owns the domain"}],
    )


def _block() -> PIBlock:
    engagement = PIEngagement.model_construct(
        engagement_id="pi_test",
        case_type=CaseType.DUE_DILIGENCE,
        purpose="PURPOSE_SECRET_SENTINEL",
        client="CLIENT_SECRET_SENTINEL",
        matter_ref="MATTER_SECRET_SENTINEL",
        created_at_utc="2026-01-01T00:00:00+00:00",
    )
    return PIBlock.model_construct(
        engagement=engagement,
        coverage=[CoverageRow(source_class="registry", searched=True)],
        sanctions=SanctionsScreening(status="lists_run", hits=[{"list": "OFAC", "name": "HIT_PAYLOAD_SENTINEL"}]),
        ownership=OwnershipBlock(unresolved=["lei:unresolved-parent"]),
    )


def test_apply_guide_empty_ids_runs_every_task_in_order() -> None:
    tasks = [_task("a"), _task("b"), _task("c")]
    kept = apply_guide(tasks, GuideDecision())
    assert kept is not tasks
    assert [task.task_id for task in kept] == ["a", "b", "c"]


def test_apply_guide_keeps_known_ids_in_offered_order() -> None:
    tasks = [_task("a"), _task("b"), _task("c")]
    kept = apply_guide(tasks, GuideDecision(run_task_ids=["c", "a", "missing"]))
    assert [task.task_id for task in kept] == ["a", "c"]


def test_apply_guide_unknown_ids_fall_back_to_every_task() -> None:
    tasks = [_task("a"), _task("b")]
    kept = apply_guide(tasks, GuideDecision(run_task_ids=["nope", "also-nope"]))
    assert [task.task_id for task in kept] == ["a", "b"]


def test_guide_may_stop_cannot_waive_a_hard_stop() -> None:
    decision = GuideDecision(request_stop="done")
    assert guide_may_stop(decision, StopReason.ESCALATED) is StopReason.ESCALATED


def test_guide_may_stop_maps_model_stops_and_ignores_code_stops() -> None:
    assert guide_may_stop(GuideDecision(request_stop="done"), None) == StopReason("done")
    assert guide_may_stop(GuideDecision(request_stop="dead_end"), None) == StopReason("dead_end")
    assert guide_may_stop(GuideDecision(request_stop="no_progress"), None) == StopReason("no_progress")
    assert guide_may_stop(GuideDecision(request_stop="escalated"), None) is None
    assert guide_may_stop(GuideDecision(request_stop="budget_spent"), None) is None
    assert guide_may_stop(GuideDecision(), None) is None


def test_parse_guide_reply_reads_a_fence_and_rejects_garbage() -> None:
    counsel = "C" * 450
    blob = (
        "note to ignore\n```json\n"
        "{\n"
        f'  "counsel": "{counsel}",\n'
        '  "run_task_ids": ["keep-me", 3, null, "also"],\n'
        '  "request_stop": "done",\n'
        '  "leading_read": "The registry lead is ahead",\n'
        '  "score": 99,\n'
        '  "source": "holehe"\n'
        "}\n```\n"
    )
    decision = parse_guide_reply(blob)
    assert decision.counsel == "C" * 400
    assert decision.run_task_ids == ["keep-me", "also"]
    assert decision.request_stop == "done"
    assert decision.leading_read == "The registry lead is ahead"
    assert set(decision.model_dump()) == {"counsel", "run_task_ids", "request_stop", "leading_read"}
    coerced = parse_guide_reply('{"request_stop": "escalated", "counsel": "leave it"}')
    assert coerced.request_stop == ""
    assert coerced.counsel == "leave it"
    assert parse_guide_reply("```json\n{not json}\n```") == GuideDecision()
    assert parse_guide_reply("not json at all") == GuideDecision()


def test_prompt_has_the_case_shape_and_not_the_secrets() -> None:
    task = _task("playbook:gleif:abc")
    system, user = build_guide_prompt(_board(), _block(), [task], "sweep")
    blob = system + "\n" + user
    for secret in (
        "PURPOSE_SECRET_SENTINEL",
        "CLIENT_SECRET_SENTINEL",
        "MATTER_SECRET_SENTINEL",
        "HIT_PAYLOAD_SENTINEL",
        "holehe",
        "hudsonrock",
    ):
        assert secret not in blob
    assert "cannot name a new source" in system
    assert "case_type: due_diligence" in user
    assert "phase: sweep" in user
    assert "budget: 3/12" in user
    assert "h1 | open | 1 | Acme owns the domain" in user
    assert "playbook:gleif:abc | gleif | Acme | registry" in user
    assert "registry | True" in user
    assert "sanctions_status: lists_run" in user
    assert "sanctions_hit_count: 1" in user
    assert "lei:unresolved-parent" in user
    assert "stop_reason:" not in user


def test_llm_guide_keeps_counsel_and_selects_the_offered_id(monkeypatch) -> None:
    seen: dict[str, object] = {}

    async def fake(system: str, user: str, **kwargs: object) -> LLMOutcome:
        seen["system"] = system
        seen["user"] = user
        seen["kwargs"] = kwargs
        return LLMOutcome(
            text='{"run_task_ids":["playbook:gleif:abc"],"counsel":"Check the registry.","request_stop":"done"}',
            provider="anthropic",
            model="claude-test",
            reason="ok",
        )

    monkeypatch.setattr("bunnyhole.engine.pi_casework_guide.complete_with_fallback", fake)
    offered = [_task("playbook:gleif:abc"), _task("playbook:news:def", source="news_narrative")]
    decision = asyncio.run(LLMGuide(None).advise(board=_board(), block=_block(), offered=offered, phase="sweep"))
    assert decision.counsel == "Check the registry."
    assert decision.run_task_ids == ["playbook:gleif:abc"]
    assert decision.request_stop == "done"
    assert [task.task_id for task in apply_guide(offered, decision)] == ["playbook:gleif:abc"]
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["fast"] is True
    assert kwargs["max_tokens"] == 800
    assert kwargs["timeout"] == 45
    assert kwargs["purpose"] == "PI casework guide"
    assert kwargs["graph"] is None
    assert "Check the registry." not in str(seen["user"])


def test_deterministic_guide_and_provider_switch(monkeypatch) -> None:
    task = _task("a")
    decision = asyncio.run(
        DeterministicGuide().advise(board=_board(), block=_block(), offered=[task], phase="sweep")
    )
    assert decision == GuideDecision()
    assert [item.task_id for item in apply_guide([task], decision)] == ["a"]

    monkeypatch.setattr("bunnyhole.engine.pi_casework_guide.configured_providers", lambda: [])
    assert isinstance(make_case_guide(), DeterministicGuide)
    monkeypatch.setattr("bunnyhole.engine.pi_casework_guide.configured_providers", lambda: ["anthropic"])
    guide = make_case_guide(object())
    assert isinstance(guide, LLMGuide)
    assert guide.graph is not None
