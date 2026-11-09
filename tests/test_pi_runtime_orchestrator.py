"""Tests for the PI orchestrator wiring: PI mode only with an engagement, a raw credential never reaches an outbound request, the log or the result (D2), breach/infostealer contents are never collected in PI mode (D3), and no token-name noise for company/person leads (D6a).

Everything is offline. Graph dicts are hand-built, agents are faked with coroutines or ``AsyncMock``.
"""

# Replaces: test_pi_runtime.py (consolidated 2026-11-09).

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock

import pytest
from pi_helpers import FakeCaseStore as _FakeCaseStore
from pi_helpers import built_engagement as _engagement
from pi_helpers import fake_orchestrator as _orchestrator

from bunnyhole.engine import pi_runtime
from bunnyhole.engine.models import DomainCategory
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator
from bunnyhole.engine.personas import Persona
from bunnyhole.engine.pi import PIBlock, PIEngagement
from bunnyhole.engine.pi_runtime import (
    PIRunRecorder,
)
from bunnyhole.engine.profile import InvestigatorProfile

# ----------------------------------------------------------------------------------------------
# orchestrator wiring
# ----------------------------------------------------------------------------------------------


def test_orchestrator_without_engagement_has_no_pi_machinery_and_no_pi_key():
    orch = _orchestrator(None)
    assert orch.engagement is None and orch.pi_sources is None and orch.pi_recorder is None
    result = asyncio.run(orch.run_investigation())
    assert "pi" not in result


def test_orchestrator_pi_mode_records_negatives_credential_skip_and_validates_block():
    eng = _engagement()
    orch = _orchestrator(eng)
    assert orch.pi_sources is not None and orch.pi_recorder is not None

    async def go() -> dict:
        _, node = orch._create_seed_node("Acme Holdings Ltd", hop_depth=0)
        await orch._execute_lead("company", "Acme Holdings Ltd", node.id, 1)
        await orch._execute_lead("credential", "a@b.co:hunter2", node.id, 1)
        await orch._execute_lead("email", "a@b.co", node.id, 1)
        return orch.compile_full_result()

    result = asyncio.run(go())
    block = PIBlock.model_validate(result["pi"])
    by_source = {e.source: e for e in block.source_log}
    for name in ("gleif", "opensanctions", "sec_edgar", "court_dockets", "news_narrative", "uk_psc",
                 "ca_sanctions", "cfpb_complaints", "wikidata"):
        assert by_source[name].status == "negative", name  # ran, found nothing: still logged
    cred = by_source["credential_combo"]
    assert cred.status == "skipped" and "not used in PI mode" in cred.detail
    orch.osint.investigate_credential_combo.assert_not_called()
    assert "hunter2" not in str(result["pi"])
    orch.pi_sources.investigate_companies_house_psc.assert_awaited_once()
    assert block.engagement.objective
    assert block.notices
    corp = {r.source_class: r for r in block.coverage}["corporate_registry"]
    assert corp.searched and corp.outcome == "negative"


def test_orchestrator_pi_mode_blocks_holehe_for_email_leads_when_passive_only():
    orch = _orchestrator(_engagement())

    async def go() -> None:
        _, node = orch._create_seed_node("a@b.co", hop_depth=0)
        await orch._execute_lead("email", "a@b.co", node.id, 1)

    asyncio.run(go())
    # investigate_email_pivots is mocked, so holehe is never reached; the instance override is what matters
    assert asyncio.run(orch.osint._run_local_arsenal_holehe("a@b.co", "email:a", 1)) is None
    assert any(e.source == "holehe" and e.status == "skipped" for e in orch.pi_recorder.entries)


def test_orchestrator_pi_mode_wraps_exceptions_and_still_finishes():
    orch = _orchestrator(_engagement())
    orch.accountant.investigate_sec_edgar = AsyncMock(side_effect=RuntimeError("edgar down"))

    async def go() -> dict:
        _, node = orch._create_seed_node("Acme Holdings Ltd", hop_depth=0)
        await orch._execute_lead("company", "Acme Holdings Ltd", node.id, 1)
        return orch.compile_full_result()

    result = asyncio.run(go())
    edgar = next(e for e in result["pi"]["source_log"] if e["source"] == "sec_edgar")
    assert edgar["status"] == "error" and "RuntimeError: edgar down" in edgar["detail"]


def test_orchestrator_pi_mode_collects_psc_links_into_the_ownership_block():
    orch = _orchestrator(_engagement())
    links = [{"child_id": "company:uk:1", "parent_id": "psc:uk:1:jane", "parent_name": "Jane", "pct": 75.0,
              "is_natural_person": True, "source": "https://ch/psc", "as_of": "2024-01-01"}]
    orch.pi_sources.investigate_companies_house_psc = AsyncMock(return_value=links)

    async def go() -> dict:
        _, node = orch._create_seed_node("Acme Holdings Ltd", hop_depth=0)
        await orch._execute_lead("company", "Acme Holdings Ltd", node.id, 1)
        return orch.compile_full_result()

    result = asyncio.run(go())
    assert {(e["child"], e["parent"]) for e in result["pi"]["ownership"]["edges"]} == {("company:uk:1", "psc:uk:1:jane")}


def test_orchestrator_runs_the_conflict_check_first_and_stores_prior_cases():
    orch = _orchestrator(_engagement())
    result = asyncio.run(orch.run_investigation())
    store = orch.case_store
    assert "Acme Holdings Ltd" in store.queries
    assert [p["case_id"] for p in result["pi"]["prior_cases"]] == ["bh_prior"]
    assert orch._pi_prior_cases
    # delegating run_investigation -> run_intake_investigation must not run the check twice
    assert store.queries.count("Acme Holdings Ltd") == 1


def test_orchestrator_conflict_check_failure_is_logged_not_fatal():
    orch = _orchestrator(_engagement())

    class Boom(_FakeCaseStore):
        def search_entity_memory(self, query: str, limit: int = 25) -> List[dict]:
            raise OSError("disk full")

    orch.case_store = Boom()
    result = asyncio.run(orch.run_investigation())
    entry = next(e for e in result["pi"]["source_log"] if e["source"] == "conflict_check")
    assert entry["status"] == "error" and "OSError: disk full" in entry["detail"]
    assert result["pi"]["prior_cases"] == []


@pytest.mark.parametrize("seed", ["Acme Holdings Ltd"])
def test_orchestrator_intake_path_also_produces_pi_block(seed: str):
    from bunnyhole.engine.intake import CaseIntakePacket

    orch = _orchestrator(_engagement())
    packet = CaseIntakePacket(organizations=[seed], emails=["a@b.co"])
    result = asyncio.run(orch.run_intake_investigation(packet))
    block = PIBlock.model_validate(result["pi"])
    assert block.source_log  # sources were recorded on the multi-selector path too


# ----------------------------------------------------------------------------------------------
# D2: a raw credential never reaches an outbound request, the log, or the result
# ----------------------------------------------------------------------------------------------

SECRET = "Hunter2-secret-9z"
CREDENTIAL = f"ceo@acme.com:{SECRET}"


def _real_orchestrator(engagement: Optional[PIEngagement], **kw: Any) -> BunnyholeOrchestrator:
    """An orchestrator with REAL agents (HTTP is mocked at the transport by respx); only the LLM stages are faked."""
    orch = BunnyholeOrchestrator(
        "Acme Holdings Ltd", max_depth=1, profile=InvestigatorProfile(persona=Persona.PRIVATE_INVESTIGATOR),
        **({"engagement": engagement} if engagement is not None else {}), **kw,
    )
    orch.case_store = _FakeCaseStore()
    orch.synthesizer.synthesize_investigation = AsyncMock(return_value={})
    orch.council.run_full_council = AsyncMock(return_value={})
    return orch


def _record_outbound(mock_router: Any) -> List[Any]:
    import httpx

    requests: List[Any] = []

    def handler(request: Any) -> Any:
        requests.append(request)
        return httpx.Response(200, json={})

    mock_router.route().mock(side_effect=handler)
    return requests


def _blob(request: Any) -> str:
    return f"{request.method} {request.url} {dict(request.headers)} {request.content!r}"


def _assert_secret_absent(result: dict, requests: List[Any], orch: BunnyholeOrchestrator) -> None:
    import json

    assert SECRET not in json.dumps(result, default=str), "secret leaked into the result JSON"
    assert SECRET not in json.dumps(result["logs"], default=str)
    assert not [r for r in requests if SECRET in _blob(r) or "Hunter2" in _blob(r)], "secret reached an outbound request"
    assert SECRET not in str(orch.intake_packet)
    assert SECRET not in str(orch.seed_query) and SECRET not in str(orch.graph.seed_query)
    assert SECRET not in repr(orch.pi_recorder.entries)


def test_pi_mode_credentials_in_the_intake_packet_are_dropped_before_any_run_logic():
    import respx

    from bunnyhole.engine.intake import CaseIntakePacket

    orch = _real_orchestrator(_engagement())
    with respx.mock(assert_all_called=False) as router:
        requests = _record_outbound(router)
        packet = CaseIntakePacket(organizations=["Acme Holdings Ltd"], credentials=[CREDENTIAL])
        result = asyncio.run(orch.run_intake_investigation(packet))
    assert requests, "the run must still do its (credential-free) work"
    _assert_secret_absent(result, requests, orch)
    assert result["intake_packet"]["credentials"] == []
    skips = [e for e in result["pi"]["source_log"] if e["source"] == "credentials"]
    assert len(skips) == 1 and skips[0]["status"] == "skipped"
    assert "not used in PI mode" in skips[0]["detail"]
    assert SECRET not in skips[0]["detail"] and "ceo@acme.com" not in skips[0]["detail"]


def test_pi_mode_credential_only_packet_leaks_nothing_and_makes_no_cooccurrence_probe():
    import respx

    from bunnyhole.engine.intake import CaseIntakePacket

    orch = _real_orchestrator(_engagement())
    with respx.mock(assert_all_called=False) as router:
        requests = _record_outbound(router)
        result = asyncio.run(orch.run_intake_investigation(CaseIntakePacket(credentials=[CREDENTIAL])))
    _assert_secret_absent(result, requests, orch)
    assert not [r for r in requests if "ceo%40acme.com" in str(r.url)]


def test_pi_mode_credential_pasted_into_free_text_is_scrubbed_from_every_copy():
    import respx

    from bunnyhole.engine.intake import CaseIntakePacket

    orch = _real_orchestrator(_engagement())
    with respx.mock(assert_all_called=False) as router:
        requests = _record_outbound(router)
        packet = CaseIntakePacket(raw_omni_text=f"Acme Holdings Ltd {CREDENTIAL} please check", raw_omni_input="")
        result = asyncio.run(orch.run_intake_investigation(packet))
    _assert_secret_absent(result, requests, orch)
    assert SECRET not in result["intake_packet"]["raw_omni_text"]
    assert SECRET not in result["intake_packet"]["raw_omni_input"]
    assert "Acme Holdings Ltd" in result["intake_packet"]["raw_omni_text"]  # the rest of the text survives
    assert [e for e in result["pi"]["source_log"] if e["source"] == "credentials" and e["status"] == "skipped"]


def test_pi_mode_credential_in_the_constructor_packet_and_seed_is_scrubbed_too():
    import respx

    from bunnyhole.engine.intake import CaseIntakePacket

    orch = BunnyholeOrchestrator(
        f"Acme Holdings Ltd {CREDENTIAL}", max_depth=1,
        profile=InvestigatorProfile(persona=Persona.PRIVATE_INVESTIGATOR), engagement=_engagement(),
        intake_packet=CaseIntakePacket(organizations=["Acme Holdings Ltd"], credentials=[CREDENTIAL]),
    )
    orch.case_store = _FakeCaseStore()
    orch.synthesizer.synthesize_investigation = AsyncMock(return_value={})
    orch.council.run_full_council = AsyncMock(return_value={})
    with respx.mock(assert_all_called=False) as router:
        requests = _record_outbound(router)
        result = asyncio.run(orch.run_investigation())
    _assert_secret_absent(result, requests, orch)
    assert len([e for e in result["pi"]["source_log"] if e["source"] == "credentials"]) == 1  # recorded once


def test_pi_mode_refuses_a_seed_that_is_only_a_credential():
    with pytest.raises(ValueError, match="credential"):
        BunnyholeOrchestrator(
            CREDENTIAL, profile=InvestigatorProfile(persona=Persona.PRIVATE_INVESTIGATOR), engagement=_engagement()
        )


def test_final_result_is_redacted_even_if_a_secret_slipped_into_the_graph():
    orch = _real_orchestrator(_engagement())
    orch._pi_redactions.append(CREDENTIAL)
    orch.graph.log(DomainCategory.SKEPTIC, "LEAKY", CREDENTIAL, f"probing {CREDENTIAL} now")
    import json

    result = orch.compile_full_result()
    assert SECRET not in json.dumps(result, default=str)


def test_without_an_engagement_credentials_are_masked_not_leaked():
    # H1 fix: a non-PI run must not persist/return the raw credential. The identifier is kept but the
    # secret is masked; the real value still reaches the credential-combo agent in memory.
    import json

    from bunnyhole.engine.intake import CaseIntakePacket

    orch = _orchestrator(None)
    packet = CaseIntakePacket(organizations=["Acme Holdings Ltd"], credentials=[CREDENTIAL])
    result = asyncio.run(orch.run_intake_investigation(packet))
    assert result["intake_packet"]["credentials"] == ["ceo@acme.com:****"]
    assert SECRET not in json.dumps(result, default=str)
    orch.osint.investigate_credential_combo.assert_awaited()


# ----------------------------------------------------------------------------------------------
# D3: breach / infostealer contents are never collected in PI mode
# ----------------------------------------------------------------------------------------------

_BREACH_METHODS = ("investigate_hudsonrock_infostealer", "_scan_leakcheck", "_lookup_emailrep")


@pytest.fixture
def breach_mocks(monkeypatch: pytest.MonkeyPatch) -> Dict[str, AsyncMock]:
    """Class-level spies on the OSINT breach methods. PI mode must shadow them on the instance, so never call them."""
    from bunnyhole.agents.osint import OSINTAgent

    mocks = {name: AsyncMock(return_value=None) for name in _BREACH_METHODS}
    for name, mock in mocks.items():
        monkeypatch.setattr(OSINTAgent, name, mock)
    # keep the other network-heavy internals of the real OSINT methods out of the way
    for name in ("_run_local_arsenal_holehe", "_scan_crt_sh", "_scan_mnemonic_pdns", "_scrape_and_fingerprint_site",
                 "_scan_urlscan_and_otx", "_run_local_arsenal_domain_tools", "_scan_securitytrails",
                 "_scan_hunter_footprint", "search_darkweb_ahmia", "_lookup_keybase_proofs",
                 "_investigate_github_and_pol_timezone", "_run_local_arsenal_username_tools",
                 "investigate_ip_shodan_and_ripestat"):
        monkeypatch.setattr(OSINTAgent, name, AsyncMock(return_value=None))
    monkeypatch.setattr(OSINTAgent, "_resolve_dns_sync", lambda self, d: ([], [], None))
    return mocks


@pytest.mark.parametrize(
    "lead_type,value",
    [("email", "ceo@acme.com"), ("domain", "acme.com"), ("ip", "203.0.113.9"), ("username", "acmeceo")],
)
def test_pi_mode_never_invokes_breach_content_methods(lead_type: str, value: str, breach_mocks: Dict[str, AsyncMock]):
    import respx

    orch = _real_orchestrator(_engagement())

    async def go() -> None:
        _, node = orch._create_seed_node(value, hop_depth=0)
        await orch._execute_lead(lead_type, value, node.id, 1)

    with respx.mock(assert_all_called=False) as router:
        _record_outbound(router)
        asyncio.run(go())
    for name, mock in breach_mocks.items():
        assert not mock.await_count and not mock.call_count, f"{name} was invoked in PI mode for a {lead_type} lead"
    skipped = {e.source for e in orch.pi_recorder.entries if e.status == "skipped"}
    expected = {"ip": {"hudsonrock"}, "email": {"emailrep", "hudsonrock", "leakcheck"},
                "domain": {"hudsonrock", "leakcheck"}, "username": {"hudsonrock"}}[lead_type]
    assert expected <= skipped, (lead_type, skipped)
    for entry in orch.pi_recorder.entries:
        if entry.source in {"hudsonrock", "leakcheck", "emailrep"}:
            assert "not used in PI mode" in entry.detail


@pytest.mark.parametrize(
    "lead_type,value,called",
    [("email", "ceo@acme.com", {"investigate_hudsonrock_infostealer", "_scan_leakcheck", "_lookup_emailrep"}),
     ("domain", "acme.com", {"investigate_hudsonrock_infostealer", "_scan_leakcheck"}),
     ("ip", "203.0.113.9", {"investigate_hudsonrock_infostealer"}),
     ("username", "acmeceo", {"investigate_hudsonrock_infostealer"})],
)
def test_without_an_engagement_the_breach_methods_are_still_invoked(
    lead_type: str, value: str, called: set, breach_mocks: Dict[str, AsyncMock]
):
    import respx

    orch = _real_orchestrator(None)

    async def go() -> None:
        _, node = orch._create_seed_node(value, hop_depth=0)
        await orch._execute_lead(lead_type, value, node.id, 1)

    with respx.mock(assert_all_called=False) as router:
        _record_outbound(router)
        asyncio.run(go())
    for name in called:
        assert breach_mocks[name].await_count >= 1, f"{name} must still run when engagement is None"


def test_breach_blocker_never_logs_the_secret_when_blocking_the_credential_combo_method():
    rec = PIRunRecorder()
    blocker = pi_runtime.make_breach_blocker(rec, "credential_combo", target_arg=1)
    asyncio.run(blocker(CREDENTIAL, "email:origin", 1))
    entry = rec.entries[0]
    assert entry.source == "credential_combo" and entry.status == "skipped" and entry.target == "email:origin"
    assert SECRET not in repr(rec.entries)


# ----------------------------------------------------------------------------------------------
# D6a: no token-name noise for company / person leads
# ----------------------------------------------------------------------------------------------


def test_pi_mode_skips_dexscreener_token_search_for_company_person_username_and_domain_leads():
    orch = _orchestrator(_engagement())

    async def go() -> None:
        _, node = orch._create_seed_node("Acme Holdings Ltd", hop_depth=0)
        await orch._execute_lead("company", "Acme Holdings Ltd", node.id, 1)
        await orch._execute_lead("username", "acmeceo", node.id, 1)
        await orch._execute_lead("domain", "acme-holdings.com", node.id, 1)

    asyncio.run(go())
    orch.onchain.investigate_dexscreener_tokens.assert_not_called()
    skipped = [e for e in orch.pi_recorder.entries if e.source == "dexscreener"]
    assert len(skipped) >= 3 and all(e.status == "skipped" for e in skipped)
    assert all("PI mode" in e.detail for e in skipped)
    coverage = {r["source_class"]: r for r in orch.compile_full_result()["pi"]["coverage"]}
    if "crypto_onchain" in coverage:
        assert not coverage["crypto_onchain"]["searched"]


def test_without_an_engagement_dexscreener_still_runs_for_company_leads():
    orch = _orchestrator(None)

    async def go() -> None:
        _, node = orch._create_seed_node("Acme Holdings Ltd", hop_depth=0)
        await orch._execute_lead("company", "Acme Holdings Ltd", node.id, 1)

    asyncio.run(go())
    orch.onchain.investigate_dexscreener_tokens.assert_awaited()
