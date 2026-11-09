"""Engine audit M2 + M4: finished work survives stage failures; swallowed agent errors are surfaced."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

from bunnyhole.engine.orchestrator import BunnyholeOrchestrator

_AGENT_METHODS = {
    "accountant": ["investigate_gleif_corporate_hierarchy", "investigate_opensanctions", "investigate_sec_edgar",
                   "investigate_nonprofit_990s_and_usaspending", "investigate_aircraft_adsb"],
    "journalist": ["investigate_news_and_narrative", "investigate_court_dockets", "investigate_wikipedia_revisions",
                   "investigate_openalex_academic_and_grants", "investigate_hackernews_archive",
                   "investigate_wayback_ghost_edits"],
    "onchain": ["investigate_dexscreener_tokens"],
    "osint": ["investigate_identity_and_handle", "investigate_credential_combo", "investigate_email_pivots",
              "investigate_domain_infrastructure"],
}


def _orch() -> BunnyholeOrchestrator:
    orch = BunnyholeOrchestrator("Acme Holdings Ltd", max_depth=1)
    for agent_name, methods in _AGENT_METHODS.items():
        agent = getattr(orch, agent_name, None)
        if agent is None:
            continue
        for method in methods:
            setattr(agent, method, AsyncMock(return_value=None))
    orch.synthesizer.synthesize_investigation = AsyncMock(return_value={})
    orch.council.run_full_council = AsyncMock(return_value={})
    return orch


def test_agent_exception_is_logged_and_counted_not_swallowed() -> None:
    orch = _orch()
    orch.accountant.investigate_sec_edgar = AsyncMock(side_effect=RuntimeError("edgar boom"))
    result = asyncio.run(orch.run_investigation())
    assert result["deep_research"]["agent_errors"] >= 1
    assert any(lg["action"] == "AGENT_TASK_ERROR" for lg in result["logs"])
    # The run still finished with a full result.
    assert result["case_id"] and "synthesis" in result


def test_cross_case_failure_becomes_stage_error_and_run_still_returns() -> None:
    orch = _orch()
    orch.case_store.correlate_cross_case_entities = lambda *a, **k: (_ for _ in ()).throw(OSError("db locked"))
    result = asyncio.run(orch.run_investigation())
    assert "OSError: db locked" in result["stage_errors"]["cross_case"]
    assert result["cross_case_hits"] == []
    assert "synthesis" in result  # deterministic brief still present


def test_synthesizer_failure_falls_back_and_is_recorded() -> None:
    orch = _orch()
    orch.synthesizer.synthesize_investigation = AsyncMock(side_effect=RuntimeError("llm down"))
    result = asyncio.run(orch.run_investigation())
    assert "RuntimeError: llm down" in result["stage_errors"]["synthesis"]
    assert result["synthesis"]  # deterministic brief fallback populated the field


def test_save_failure_is_reported_not_silent() -> None:
    orch = _orch()
    orch.case_store.save_case = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk full"))
    result = asyncio.run(orch.run_investigation())
    assert "RuntimeError: disk full" in result["persist_error"]
