"""The case officer chooses among offered tasks. It does not score anyone or clear anyone.

A code stop (sanctions, budget, escalation) always wins over the model. When no provider is
configured, or the reply is empty or unusable, the playbook runs every offered task.
"""

from __future__ import annotations

import json
import logging
import re
from enum import Enum
from typing import Any, List, Protocol, Sequence

from pydantic import BaseModel, Field

from bunnyhole.engine.llm_providers import LLMOutcome, complete_with_fallback, configured_providers
from bunnyhole.engine.models import DomainCategory
from bunnyhole.engine.pi import CaseBoard, CaseTask, PIBlock, StopReason

_log = logging.getLogger(__name__)

#: Stops the model is allowed to request. Sanctions, budget, and escalation stay in code.
_GUIDE_STOPS = frozenset({"done", "dead_end", "no_progress"})
_NOTE_MAX = 400
_JSON_FENCE = re.compile(r"```(?:\s*json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)

_SYSTEM = (
    "You are the case officer on a passive, lawful desk. "
    "Choose which of the offered task ids to run. "
    "You cannot name a new source, waive a sanctions stop, or declare a person or company clear. "
    "Absence from a list is not innocence. Complaints are unverified. A nominee is not a beneficial owner. "
    "Recommend request_stop only as done, dead_end, or no_progress, and only when the evidence supports it. "
    "Return one JSON object and nothing else, with only these keys: "
    "counsel (one short plain-text investigator note), "
    "run_task_ids (array of offered task id strings; an empty array means run every offered task), "
    "request_stop (an empty string, done, dead_end, or no_progress), "
    "leading_read (one line on the leading hypothesis; not a score)."
)


class GuideDecision(BaseModel):
    """What the case officer may change. Empty fields mean 'do not change the playbook'."""

    counsel: str = ""
    run_task_ids: List[str] = Field(default_factory=list)
    request_stop: str = ""
    leading_read: str = ""


class CaseGuide(Protocol):
    """Something that can advise a case step. ``name`` is ``playbook`` or ``llm``."""

    name: str

    async def advise(
        self,
        *,
        board: CaseBoard,
        block: PIBlock,
        offered: Sequence[CaseTask],
        phase: str,
    ) -> GuideDecision: ...


class DeterministicGuide:
    """Run every offered task. No model, no stop, no counsel."""

    name = "playbook"

    async def advise(
        self,
        *,
        board: CaseBoard,
        block: PIBlock,
        offered: Sequence[CaseTask],
        phase: str,
    ) -> GuideDecision:
        del board, block, offered, phase
        return GuideDecision()


def apply_guide(offered: Sequence[CaseTask], decision: GuideDecision) -> List[CaseTask]:
    """Keep the offered tasks the officer named, in offered order.

    An empty ``run_task_ids``, or a list that names nothing offered, runs every offered task.
    Unknown ids are ignored. This never invents a task and never adds a source.
    """
    if not decision.run_task_ids:
        return list(offered)
    wanted = set(decision.run_task_ids)
    kept = [task for task in offered if task.task_id in wanted]
    if not kept:
        return list(offered)
    return kept


def guide_may_stop(decision: GuideDecision, hard_stop: StopReason | None) -> StopReason | None:
    """Return the stop that actually applies.

    ``hard_stop`` wins even when the model asked to finish: the model cannot waive a sanctions
    hit, a spent budget, or any other stop the code already decided. A model may only request
    ``done``, ``dead_end``, or ``no_progress``.
    """
    if hard_stop is not None:
        return hard_stop
    if decision.request_stop not in _GUIDE_STOPS:
        return None
    return StopReason(decision.request_stop)


def _note(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value[:_NOTE_MAX]


def _task_ids(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _request_stop(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = value.strip()
    return cleaned if cleaned in _GUIDE_STOPS else ""


def parse_guide_reply(text: str) -> GuideDecision:
    """Parse one JSON object, optionally inside a ```json fence. Anything else is an empty decision."""
    try:
        stripped = text.strip()
        fence = _JSON_FENCE.search(stripped)
        payload = fence.group(1).strip() if fence is not None else stripped
        data = json.loads(payload)
    except (json.JSONDecodeError, AttributeError, TypeError, ValueError):
        return GuideDecision()
    if not isinstance(data, dict):
        return GuideDecision()
    return GuideDecision(
        counsel=_note(data.get("counsel", "")),
        run_task_ids=_task_ids(data.get("run_task_ids", [])),
        request_stop=_request_stop(data.get("request_stop", "")),
        leading_read=_note(data.get("leading_read", "")),
    )


def _plain(value: Any) -> str:
    """One line of plain text. Enums contribute their value, not the class name.

    A ``str`` enum is still a ``str``, so the enum check has to come first.
    """
    if value is None:
        return ""
    text = str(value.value) if isinstance(value, Enum) else str(value)
    return " ".join(text.split())


def _case_type(board: CaseBoard, block: PIBlock) -> str:
    raw = getattr(board, "case_type", None)
    text = _plain(raw) if raw not in (None, "") else ""
    if text:
        return text
    engagement = getattr(block, "engagement", None)
    if engagement is None:
        return ""
    return _plain(getattr(engagement, "case_type", ""))


def _budget(board: CaseBoard) -> str:
    """``calls_used/budget`` from the board, or from a nested budget object."""
    calls = getattr(board, "calls_used", None)
    cap = getattr(board, "budget", None)
    if cap is not None and not isinstance(cap, (int, float, str, bool)):
        if calls is None:
            calls = getattr(cap, "calls_used", None)
        nested = getattr(cap, "budget", None)
        if not isinstance(nested, (int, float, str, bool)):
            nested = getattr(cap, "limit", None)
        cap = nested
    calls_text = "0" if calls is None else _plain(calls)
    cap_text = "0" if cap is None else _plain(cap)
    return f"{calls_text}/{cap_text}"


def _hypothesis_lines(board: CaseBoard) -> List[str]:
    raw = getattr(board, "hypotheses", None)
    if not raw:
        return []
    items = list(raw.values()) if isinstance(raw, dict) else list(raw)
    lines: List[str] = []
    for item in items:
        if isinstance(item, dict):
            key = item.get("key", "")
            status = item.get("status", "")
            score = item.get("score", "")
            text = item.get("text", "")
        else:
            key = getattr(item, "key", "")
            status = getattr(item, "status", "")
            score = getattr(item, "score", "")
            text = getattr(item, "text", "")
        lines.append(f"- {_plain(key)} | {_plain(status)} | {_plain(score)} | {_plain(text)}")
    return lines


def _task_line(task: CaseTask) -> str:
    return " | ".join(
        (
            _plain(getattr(task, "task_id", "")),
            _plain(getattr(task, "source", "")),
            _plain(getattr(task, "target", "")),
            _plain(getattr(task, "why", "")),
        )
    )


def _stop_reason(board: CaseBoard) -> str:
    raw = getattr(board, "stop_reason", None)
    if raw is None or raw == "":
        return ""
    return _plain(raw)


def build_guide_prompt(
    board: CaseBoard,
    block: PIBlock,
    offered: Sequence[CaseTask],
    phase: str,
) -> tuple[str, str]:
    """System and user text for one advice call.

    The user text is case type, phase, budget, hypotheses, offered tasks, coverage class and
    searched flag, sanctions status and hit count, unresolved ownership ids, and a stop reason
    when one is already set. It does not include the client, purpose, matter reference, receipts,
    snippets, or sanctions hit payloads, and it does not name a source that was not offered.
    """
    lines = [
        f"case_type: {_case_type(board, block)}",
        f"phase: {_plain(phase)}",
        f"budget: {_budget(board)}",
        "hypotheses:",
    ]
    lines.extend(_hypothesis_lines(board) or ["- none"])
    lines.append("tasks:")
    lines.extend(f"- {_task_line(task)}" for task in offered)
    if not offered:
        lines.append("- none")
    lines.append("coverage:")
    coverage = getattr(block, "coverage", None) or []
    if coverage:
        lines.extend(f"- {_plain(row.source_class)} | {_plain(row.searched)}" for row in coverage)
    else:
        lines.append("- none")
    sanctions = getattr(block, "sanctions", None)
    status = getattr(sanctions, "status", "not_run") if sanctions is not None else "not_run"
    hits = getattr(sanctions, "hits", None) if sanctions is not None else None
    hit_count = len(hits) if isinstance(hits, list) else 0
    lines.append(f"sanctions_status: {_plain(status)}")
    lines.append(f"sanctions_hit_count: {hit_count}")
    lines.append("ownership_unresolved:")
    ownership = getattr(block, "ownership", None)
    unresolved = getattr(ownership, "unresolved", None) if ownership is not None else None
    if unresolved:
        lines.extend(f"- {_plain(item)}" for item in unresolved)
    else:
        lines.append("- none")
    stop = _stop_reason(board)
    if stop:
        lines.append(f"stop_reason: {stop}")
    return _SYSTEM, "\n".join(lines)


class LLMGuide:
    """Ask the configured provider which offered tasks to run. Falls back to the playbook."""

    name = "llm"

    def __init__(self, graph: Any | None = None) -> None:
        self.graph = graph

    def _log_outcome(self, outcome: LLMOutcome) -> None:
        """Provider, model, and reason only. The prompt and the reply can contain case data."""
        provider = outcome.provider or "none"
        model = outcome.model or "none"
        reason = outcome.reason
        _log.info("pi casework guide provider=%s model=%s reason=%s", provider, model, reason)
        graph = self.graph
        if graph is None or not hasattr(graph, "log"):
            return
        try:
            graph.log(
                DomainCategory.SKEPTIC,
                "PI_CASE_GUIDE",
                provider,
                f"model={model} reason={reason}",
                level="info",
            )
        except Exception:
            _log.debug("pi casework guide graph log failed", exc_info=True)

    async def advise(
        self,
        *,
        board: CaseBoard,
        block: PIBlock,
        offered: Sequence[CaseTask],
        phase: str,
    ) -> GuideDecision:
        try:
            system, user = build_guide_prompt(board, block, offered, phase)
            outcome = await complete_with_fallback(
                system,
                user,
                fast=True,
                max_tokens=800,
                timeout=45,
                purpose="PI casework guide",
                graph=self.graph,
            )
        except Exception:
            return GuideDecision()
        self._log_outcome(outcome)
        text = outcome.text
        if not isinstance(text, str) or not text.strip():
            return GuideDecision()
        try:
            return parse_guide_reply(text)
        except Exception:
            return GuideDecision()


def make_case_guide(graph: Any | None = None) -> CaseGuide:
    """An :class:`LLMGuide` when any provider key is set, otherwise the playbook."""
    if configured_providers():
        return LLMGuide(graph)
    return DeterministicGuide()


__all__ = [
    "CaseGuide",
    "DeterministicGuide",
    "GuideDecision",
    "LLMGuide",
    "apply_guide",
    "build_guide_prompt",
    "guide_may_stop",
    "make_case_guide",
    "parse_guide_reply",
]
