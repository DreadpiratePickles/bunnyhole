"""CourtListener now answers HTTP 401 without a token: optional COURTLISTENER_API_TOKEN, clear skip on 401/403.

All HTTP is mocked with respx. The token value never appears in logs, receipts or node attributes.
"""

from __future__ import annotations

import asyncio
from typing import Any, List

import httpx
import pytest
import respx

from bunnyhole.agents.journalist import JournalistAgent
from bunnyhole.arsenal import manager as arsenal_manager
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EntityType, GraphNode, SelectorStrength

SEARCH_URL = "https://www.courtlistener.com/api/rest/v4/search/"
TOKEN = "cl-test-token-0123456789"


@pytest.fixture(autouse=True)
def _no_token(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("COURTLISTENER_API_TOKEN", raising=False)


def _agent() -> tuple[JournalistAgent, InvestigationGraph, str]:
    g = InvestigationGraph("test_courtlistener", "Acme Holdings")
    origin = GraphNode(
        id="org:origin",
        label="Acme Holdings",
        entity_type=EntityType.ORGANIZATION,
        domain=DomainCategory.JOURNALISM,
        selector_strength=SelectorStrength.SOFT,
    )
    g.upsert_node(origin)
    return JournalistAgent(g), g, origin.id


def _run(agent: JournalistAgent, origin: str) -> None:
    asyncio.run(agent.investigate_court_dockets("Acme Holdings", origin, 1))


def _hit() -> dict:
    return {
        "results": [
            {
                "caseName": "Acme v. Smith",
                "docketNumber": "1:24-cv-0001",
                "court": "nysd",
                "dateFiled": "2024-05-01",
                "absolute_url": "/docket/1/acme-v-smith/",
            }
        ]
    }


def test_no_token_sends_no_authorization_header_and_behaves_as_before():
    agent, g, origin = _agent()
    seen: List[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_hit())

    with respx.mock as router:
        router.get(SEARCH_URL).mock(side_effect=respond)
        _run(agent, origin)
    assert len(seen) == 1 and "authorization" not in {k.lower() for k in seen[0].headers}
    assert any(n.id.startswith("docket:") for n in g.nodes.values())


def test_token_from_env_is_sent_as_token_scheme_authorization_header(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("COURTLISTENER_API_TOKEN", f"  {TOKEN}  ")
    agent, g, origin = _agent()
    seen: List[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_hit())

    with respx.mock as router:
        router.get(SEARCH_URL).mock(side_effect=respond)
        _run(agent, origin)
    assert seen[0].headers["authorization"] == f"Token {TOKEN}"
    assert "User-Agent" in seen[0].headers or "user-agent" in seen[0].headers
    assert any(n.id.startswith("docket:") for n in g.nodes.values())


def test_token_is_read_at_call_time_and_does_not_mutate_the_agent_headers(monkeypatch: pytest.MonkeyPatch):
    agent, g, origin = _agent()
    before = dict(agent.headers)
    monkeypatch.setenv("COURTLISTENER_API_TOKEN", TOKEN)
    with respx.mock as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(200, json={"results": []}))
        _run(agent, origin)
    assert agent.headers == before and "Authorization" not in agent.headers


def test_blank_token_is_treated_as_unset(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("COURTLISTENER_API_TOKEN", "   ")
    agent, g, origin = _agent()
    seen: List[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"results": []})

    with respx.mock as router:
        router.get(SEARCH_URL).mock(side_effect=respond)
        _run(agent, origin)
    assert "authorization" not in {k.lower() for k in seen[0].headers}


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failure_logs_a_clear_skip_without_the_token(status: int, monkeypatch: pytest.MonkeyPatch):
    agent, g, origin = _agent()
    with respx.mock as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(status))
        _run(agent, origin)
    skips = [e for e in g.logs if e.action == "COURTLISTENER_SKIP"]
    assert len(skips) == 1
    assert skips[0].level == "warning"
    assert f"HTTP {status}" in skips[0].detail and "COURTLISTENER_API_TOKEN" in skips[0].detail
    assert "free" in skips[0].detail.lower()
    assert set(g.nodes) == {origin}


def test_rejected_token_skip_does_not_echo_the_token(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("COURTLISTENER_API_TOKEN", TOKEN)
    agent, g, origin = _agent()
    with respx.mock as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(401))
        _run(agent, origin)
    skips = [e for e in g.logs if e.action == "COURTLISTENER_SKIP"]
    assert skips and "rejected" in skips[0].detail
    assert all(TOKEN not in e.detail and TOKEN not in e.target for e in g.logs)


@pytest.mark.parametrize("status", [404, 429, 500])
def test_other_http_errors_keep_the_old_silent_behaviour(status: int):
    agent, g, origin = _agent()
    with respx.mock as router:
        router.get(SEARCH_URL).mock(return_value=httpx.Response(status))
        _run(agent, origin)
    assert not [e for e in g.logs if e.action == "COURTLISTENER_SKIP"]
    assert set(g.nodes) == {origin}


def test_key_is_in_the_arsenal_catalog_and_loadable():
    entry: Any = next(item for item in arsenal_manager.API_KEYS_REGISTRY if item["key"] == "COURTLISTENER_API_TOKEN")
    assert entry["url"] == "https://www.courtlistener.com/help/api/rest/"
    assert entry["note"] == "Free account token; unauthenticated API returns 401"
    assert entry["category"]
    assert "COURTLISTENER_API_TOKEN" in arsenal_manager.ALLOWED_KEY_NAMES
