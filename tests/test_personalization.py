"""Tests for personalization: investigator personas, the remembered-context profile + watchlist,
and the keyless-first OpenSanctions sanctions/PEP data source.

Pure logic (personas/profile) is tested directly; the OpenSanctions agent method is tested with
HTTP mocked via respx so no network is touched.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from bunnyhole.agents.accountant import AccountantAgent
from bunnyhole.engine import netutil, personas, profile
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EntityType, GearMode, GraphNode, SelectorStrength
from bunnyhole.engine.personas import Persona
from bunnyhole.engine.profile import InvestigatorProfile

# ----------------------------------------------------------------------------------------------
# Personas
# ----------------------------------------------------------------------------------------------

def test_all_personas_present_and_distinct():
    all_p = personas.list_personas()
    assert {p.key for p in all_p} == set(Persona)
    assert len(all_p) == 6  # intentional: PI persona added (PI stream spec s4)
    # the compliance + crypto personas lean on sanctions screening; journalist/threat-intel don't
    assert personas.get_persona(Persona.COMPLIANCE).emphasize_sanctions is True
    assert personas.get_persona(Persona.CRYPTO_TRACER).emphasize_sanctions is True
    assert personas.get_persona(Persona.JOURNALIST).emphasize_sanctions is False


def test_persona_defaults_differ_by_lens():
    comp = personas.get_persona("compliance")
    journo = personas.get_persona("journalist")
    assert comp.default_gear == GearMode.DEEP
    assert comp.default_depth == 3
    assert journo.default_gear == GearMode.FAST
    assert comp.analyst_framing and journo.analyst_framing
    assert comp.analyst_framing != journo.analyst_framing


def test_pi_persona_profile():
    pp = personas.get_persona("pi")
    assert pp.key == Persona.PRIVATE_INVESTIGATOR
    assert pp.display_name == "Private Investigator (PI)"
    assert (pp.default_gear, pp.default_depth, pp.default_breadth) == (GearMode.DEEP, 3, 4)
    assert pp.priority_domains == [DomainCategory.FIAT, DomainCategory.OSINT, DomainCategory.JOURNALISM]
    assert pp.emphasize_sanctions is True
    assert "Leads, not verdicts" in pp.analyst_framing


def test_coerce_persona_defaults_to_generalist():
    assert personas.coerce_persona("nonsense") == Persona.GENERALIST
    assert personas.coerce_persona(None) == Persona.GENERALIST
    assert personas.coerce_persona("CRYPTO_TRACER") == Persona.CRYPTO_TRACER


# ----------------------------------------------------------------------------------------------
# Profile: run-param resolution, watchlist, persistence
# ----------------------------------------------------------------------------------------------

def test_effective_run_params_uses_persona_then_overrides():
    p = InvestigatorProfile(persona=Persona.COMPLIANCE)
    assert p.effective_run_params() == (GearMode.DEEP, 3, 4)
    p.depth_override = 1
    p.gear_override = GearMode.FAST
    assert p.effective_run_params() == (GearMode.FAST, 1, 4)


def test_resolve_run_params_fills_only_unset():
    p = InvestigatorProfile(persona=Persona.CRYPTO_TRACER)  # deep/3/5
    # caller specifies depth only; gear+breadth come from the persona
    assert profile.resolve_run_params(p, gear=None, depth=2, breadth=None) == (GearMode.DEEP, 2, 5)
    # caller specifies everything -> caller wins
    assert profile.resolve_run_params(p, gear=GearMode.FAST, depth=1, breadth=8) == (GearMode.FAST, 1, 8)


def test_match_watchlist_flags_recurring_targets():
    nodes = [
        {"id": "domain:acme.io", "label": "🎯 acme.io", "domain": "osint", "smoke_score": 50},
        {"id": "wallet:0xabc", "label": "0xABC", "domain": "onchain", "smoke_score": 40},
        {"id": "lei:123", "label": "Unrelated Corp", "domain": "fiat", "smoke_score": 10},
    ]
    hits = profile.match_watchlist(nodes, ["acme.io", "0xabc"])
    terms = sorted(h["term"] for h in hits)
    assert terms == ["0xabc", "acme.io"]
    assert profile.match_watchlist(nodes, []) == []


def test_add_remove_watch_dedup_and_case_insensitive():
    p = InvestigatorProfile()
    profile.add_watch(p, ["acme.io", "ACME.IO", "vitalik.eth"])
    assert p.watchlist == ["acme.io", "vitalik.eth"]
    profile.remove_watch(p, ["VITALIK.ETH"])
    assert p.watchlist == ["acme.io"]


def test_profile_save_load_roundtrip(tmp_path):
    path = tmp_path / "profile.json"
    p = InvestigatorProfile(persona=Persona.THREAT_INTEL, display_name="Nat", watchlist=["x.io"])
    profile.save_profile(p, path=path)
    assert path.exists()
    loaded = profile.load_profile(path=path)
    assert loaded.persona == Persona.THREAT_INTEL
    assert loaded.display_name == "Nat"
    assert loaded.watchlist == ["x.io"]


def test_load_profile_missing_or_corrupt_returns_default(tmp_path):
    missing = tmp_path / "nope.json"
    assert profile.load_profile(path=missing).persona == Persona.GENERALIST
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    assert profile.load_profile(path=bad).persona == Persona.GENERALIST


# ----------------------------------------------------------------------------------------------
# OpenSanctions sanctions/PEP source (HTTP mocked)
# ----------------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_proxy_state():
    netutil.set_default_proxy(None)
    yield
    netutil.set_default_proxy(None)


def _accountant_with_origin():
    g = InvestigationGraph("test_sanctions", "john bad")
    origin = GraphNode(
        id="org:john_bad",
        label="John Bad",
        entity_type=EntityType.ORGANIZATION,
        domain=DomainCategory.FIAT,
        selector_strength=SelectorStrength.SOFT,
    )
    g.upsert_node(origin)
    return AccountantAgent(g), g, origin.id


def test_opensanctions_flags_sanctioned_and_pep_and_skips_noise():
    body = {
        "results": [
            {
                "id": "NK-sanc",
                "caption": "John Bad",
                "schema": "Person",
                "datasets": ["us_ofac_sdn"],
                "properties": {"topics": ["sanction"], "country": ["ru"]},
            },
            {
                "id": "pep-1",
                "caption": "Jane Politician",
                "schema": "Person",
                "datasets": ["peps"],
                "properties": {"topics": ["role.pep"]},
            },
            {
                "id": "noise",
                "caption": "Acme Inc",
                "schema": "Company",
                "datasets": [" x "],
                "properties": {"topics": []},
            },
        ]
    }
    agent, g, origin_id = _accountant_with_origin()
    with respx.mock:
        respx.route(host="api.opensanctions.org", path="/search/default").mock(
            return_value=httpx.Response(200, json=body)
        )
        asyncio.run(agent.investigate_opensanctions("john bad", origin_id, 1))

    sanction_nodes = {nid: n for nid, n in g.nodes.items() if nid.startswith("sanction:")}
    assert set(sanction_nodes) == {"sanction:NK-sanc", "sanction:pep-1"}  # noise (no risk topic) dropped

    sanc = sanction_nodes["sanction:NK-sanc"]
    assert "OFAC_EU_UN_SANCTIONS_LIST_MATCH" in sanc.risk_flags
    assert "SOFT_NAME_MATCH_VERIFY" in sanc.risk_flags
    assert sanc.selector_strength == SelectorStrength.SOFT  # a name match, not a strong selector
    assert sanc.smoke_score >= 85.0

    pep = sanction_nodes["sanction:pep-1"]
    assert "POLITICALLY_EXPOSED_PERSON_PEP" in pep.risk_flags


def test_opensanctions_degrades_gracefully_without_access():
    agent, g, origin_id = _accountant_with_origin()
    with respx.mock:
        respx.route(host="api.opensanctions.org", path="/search/default").mock(
            return_value=httpx.Response(401, json={"detail": "auth required"})
        )
        asyncio.run(agent.investigate_opensanctions("john bad", origin_id, 1))
    assert not [nid for nid in g.nodes if nid.startswith("sanction:")]  # no nodes, no crash


def test_opensanctions_ignores_too_short_query():
    agent, g, origin_id = _accountant_with_origin()
    # No respx route registered: if it tried to call out, respx (if active) would raise. It must no-op.
    asyncio.run(agent.investigate_opensanctions("ab", origin_id, 1))
    assert not [nid for nid in g.nodes if nid.startswith("sanction:")]


if __name__ == "__main__":
    import unittest

    unittest.main()
