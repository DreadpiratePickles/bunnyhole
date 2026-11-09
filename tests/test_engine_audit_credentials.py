"""Engine audit H1: a plaintext credential never leaks in a NON-PI run.

The sentinel secret must not appear in the result JSON, the saved case rows, the dossier markdown, the
agent logs, or any outbound request URL/body. The real value may still reach the credential-combo
agent in memory.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import respx

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.intake import AnchorMode, CaseIntakePacket
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator
from bunnyhole.engine.storage import CaseStore

SECRET = "Hunter2-sentinel-9z7q"
CREDENTIAL = f"ceo@acme.com:{SECRET}"

_AGENT_METHODS = {
    "accountant": ["investigate_gleif_corporate_hierarchy", "investigate_opensanctions", "investigate_sec_edgar",
                   "investigate_nonprofit_990s_and_usaspending", "investigate_aircraft_adsb"],
    "journalist": ["investigate_news_and_narrative", "investigate_court_dockets", "investigate_wikipedia_revisions",
                   "investigate_openalex_academic_and_grants", "investigate_hackernews_archive",
                   "investigate_wayback_ghost_edits"],
    "onchain": ["investigate_dexscreener_tokens", "investigate_evm_address", "investigate_bitcoin_utxo"],
    "osint": ["investigate_identity_and_handle", "investigate_email_pivots", "investigate_domain_infrastructure",
              "investigate_hudsonrock_infostealer", "investigate_ip_shodan_and_ripestat", "investigate_phone_number"],
}


def _mock_agents(orch: BunnyholeOrchestrator) -> AsyncMock:
    for agent_name, methods in _AGENT_METHODS.items():
        agent = getattr(orch, agent_name, None)
        if agent is None:
            continue
        for method in methods:
            setattr(agent, method, AsyncMock(return_value=None))
    combo = AsyncMock(return_value={"pwd_node_id": "", "pwned_count": 0})
    orch.osint.investigate_credential_combo = combo
    orch.synthesizer.synthesize_investigation = AsyncMock(return_value={})
    orch.council.run_full_council = AsyncMock(return_value={})
    # Co-occurrence must never be driven with a credential; stub it so a real call would be visible.
    orch.link_sleuth.verify_interconnection_cooccurrence = AsyncMock(return_value=None)
    return combo


def test_non_pi_credential_is_masked_everywhere_and_combo_still_runs() -> None:
    orch = BunnyholeOrchestrator("intake", max_depth=1)
    combo = _mock_agents(orch)
    packet = CaseIntakePacket(
        organizations=["Acme Holdings Ltd"],
        credentials=[CREDENTIAL],
        anchor_mode=AnchorMode.LOCKED_PROFILE,
    )
    result = asyncio.run(orch.run_intake_investigation(packet))

    blob = json.dumps(result, default=str)
    assert SECRET not in blob                      # not in the result JSON (incl. receipts, logs, packet)
    assert "****" in json.dumps(result["intake_packet"]["credentials"])

    # The credential-combo agent still received the REAL secret (kept in memory only).
    combo.assert_awaited()
    assert any(SECRET in str(call.args) for call in combo.await_args_list)

    # Dossier markdown must not carry the secret (Raw Excerpt etc.).
    assert SECRET not in orch.graph.export_markdown_dossier()

    # Saved case rows (result_json, seed_query, labels) must not carry the secret either.
    saved = CaseStore().get_case(orch.graph.case_id)
    assert saved is not None
    assert SECRET not in json.dumps(saved, default=str)


def test_convergence_cooccurrence_never_receives_a_credential_root() -> None:
    orch = BunnyholeOrchestrator("intake", max_depth=1)
    _mock_agents(orch)
    probe = orch.link_sleuth.verify_interconnection_cooccurrence  # AsyncMock
    packet = CaseIntakePacket(
        organizations=["Acme Holdings Ltd"],
        credentials=[CREDENTIAL],
        anchor_mode=AnchorMode.CONVERGENCE,
    )
    asyncio.run(orch.run_intake_investigation(packet))
    # No co-occurrence probe was built from the credential value.
    for call in probe.await_args_list:
        assert SECRET not in str(call.args)


def test_link_sleuth_cooccurrence_refuses_credential_without_outbound_request() -> None:
    g = InvestigationGraph("c", "q")
    from bunnyhole.agents.link_sleuth import LinkSleuthAgent

    sleuth = LinkSleuthAgent(g)
    with respx.mock(assert_all_called=False) as router:
        news = router.get(url__startswith="https://news.google.com").mock(return_value=respx.MockResponse(200, text="<rss/>"))
        court = router.get(url__startswith="https://www.courtlistener.com").mock(return_value=respx.MockResponse(200, json={"results": []}))
        edge = asyncio.run(
            sleuth.verify_interconnection_cooccurrence(CREDENTIAL, "a", "other-entity", "b", hop_depth=1)
        )
    assert edge is None
    assert not news.called and not court.called  # nothing left the process carrying the secret
