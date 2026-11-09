"""Agents identify themselves with the operator-configurable research User-Agent, never a fake contact address."""

from __future__ import annotations

import pytest

from bunnyhole.agents.accountant import DEFAULT_SEC_USER_AGENT
from bunnyhole.agents.pi_sources import PISourcesAgent
from bunnyhole.engine.graph import InvestigationGraph


def test_pi_sources_user_agent_defaults_to_the_project_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BUNNYHOLE_SEC_USER_AGENT", raising=False)
    agent = PISourcesAgent(InvestigationGraph("ua", "x"))
    assert agent.std_headers["User-Agent"] == DEFAULT_SEC_USER_AGENT
    assert "bunnyhole.local" not in agent.std_headers["User-Agent"]


def test_pi_sources_user_agent_honours_the_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUNNYHOLE_SEC_USER_AGENT", "Jane Analyst jane@example.org")
    agent = PISourcesAgent(InvestigationGraph("ua", "x"))
    assert agent.std_headers["User-Agent"] == "Jane Analyst jane@example.org"
    assert agent.std_headers["Accept"] == "application/json"
