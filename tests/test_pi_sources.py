"""Tests for the PI-stream network sources (Companies House PSC, GAC SEMA sanctions, CFPB, Wikidata).

All HTTP is mocked with respx; nothing touches the network. The GAC fixture is a tiny synthetic file
that uses the real element names of the Global Affairs Canada SEMA XML, never the live download.
"""

from __future__ import annotations

import asyncio
import base64
import time
from typing import Any, Dict, List, Tuple

import httpx
import pytest
import respx

from bunnyhole.agents import pi_sources
from bunnyhole.agents.pi_sources import PISourcesAgent, names_match, normalize_name_tokens
from bunnyhole.engine import netutil
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    GraphNode,
    RelationType,
    SelectorStrength,
)

CH_HOST = "api.company-information.service.gov.uk"
CFPB_HOST = "www.consumerfinance.gov"
WD_HOST = "www.wikidata.org"
GAC_HOST = "www.international.gc.ca"
GAC_PATH = (
    "/world-monde/assets/office_docs/international_relations-relations_internationales/sanctions/sema-lmes.xml"
)


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch):
    netutil.set_default_proxy(None)
    PISourcesAgent.reset_sema_cache()
    monkeypatch.delenv("COMPANIES_HOUSE_API_KEY", raising=False)
    yield
    PISourcesAgent.reset_sema_cache()
    netutil.set_default_proxy(None)


def _agent_with_origin(label: str = "Acme Holdings") -> Tuple[PISourcesAgent, InvestigationGraph, str]:
    g = InvestigationGraph("test_pi_sources", label)
    origin = GraphNode(
        id="org:origin",
        label=label,
        entity_type=EntityType.ORGANIZATION,
        domain=DomainCategory.FIAT,
        selector_strength=SelectorStrength.SOFT,
    )
    g.upsert_node(origin)
    return PISourcesAgent(g), g, origin.id


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _actions(g: InvestigationGraph) -> List[str]:
    return [e.action for e in g.logs]


def _new_nodes(g: InvestigationGraph, origin_id: str) -> Dict[str, GraphNode]:
    return {nid: n for nid, n in g.nodes.items() if nid != origin_id}


# ----------------------------------------------------------------------------------------------
# Name matching (pure)
# ----------------------------------------------------------------------------------------------


def test_normalize_strips_accents_case_punctuation_and_legal_suffixes():
    assert normalize_name_tokens("José  O'Brien-Smith") == frozenset({"jose", "o", "brien", "smith"})
    assert normalize_name_tokens("ACME Holdings Ltd.") == frozenset({"acme", "holdings"})


def test_names_match_is_token_subset_either_direction():
    assert names_match("Dmitry Balaba", "Balaba Dmitry Vladimirovich")  # query subset of record
    assert names_match("Mr Dmitry Vladimirovich Balaba Jr", "Dmitry Vladimirovich Balaba")  # record subset of query
    assert not names_match("Dmitry Ivanov", "Dmitry Balaba")


def test_names_match_refuses_lone_token_unless_whole_name_equal():
    assert not names_match("Balaba", "Dmitry Balaba")  # one common token is not a match
    assert names_match("Rosneft", "Rosneft")  # the whole (single-token) name is identical
    assert names_match("Acme LLC", "Acme")  # legal suffix ignored, whole core name equal
    assert not names_match("Acme", "Acme Holdings")


def test_names_match_empty_inputs_never_match():
    assert not names_match("", "Acme")
    assert not names_match("Acme", "   ")


# ----------------------------------------------------------------------------------------------
# Companies House PSC
# ----------------------------------------------------------------------------------------------

CH_SEARCH = {
    "items": [
        {"title": "ACME HOLDINGS LIMITED", "company_number": "01234567", "company_status": "active"},
        {"title": "ACME HOLDINGS (UK) LIMITED", "company_number": "07654321", "company_status": "dissolved"},
        {"title": "../EVIL", "company_number": "../etc/passwd"},  # hostile number must never reach a URL path
    ]
}
CH_PSC_1 = {
    "items": [
        {
            "name": "Mr Jane Q Doe",
            "kind": "individual-person-with-significant-control",
            "natures_of_control": ["ownership-of-shares-50-to-75-percent", "voting-rights-50-to-75-percent"],
            "notified_on": "2016-04-06",
            "country_of_residence": "England",
        },
        {
            "name": "Shell Parent Ltd",
            "kind": "corporate-entity-person-with-significant-control",
            "natures_of_control": ["ownership-of-shares-25-to-50-percent"],
            "notified_on": "2018-01-01",
        },
        {
            "name": "Old Holder",
            "kind": "individual-person-with-significant-control",
            "natures_of_control": ["ownership-of-shares-75-to-100-percent"],
            "notified_on": "2010-01-01",
            "ceased_on": "2015-05-05",
        },
    ]
}
CH_PSC_2 = {
    "items": [
        {
            "name": "Beta Trust Corp",
            "kind": "legal-person-person-with-significant-control",
            "natures_of_control": ["ownership-of-shares-75-to-100-percent"],
            "notified_on": "2020-02-02",
        },
        {
            "name": "Control Only Person",
            "kind": "individual-person-with-significant-control",
            "natures_of_control": ["right-to-appoint-and-remove-directors"],
            "notified_on": "2021-03-03",
        },
    ]
}


def _mock_ch_ok(router: respx.MockRouter) -> None:
    router.route(host=CH_HOST, path="/search/companies").mock(return_value=httpx.Response(200, json=CH_SEARCH))
    router.route(host=CH_HOST, path="/company/01234567/persons-with-significant-control").mock(
        return_value=httpx.Response(200, json=CH_PSC_1)
    )
    router.route(host=CH_HOST, path="/company/07654321/persons-with-significant-control").mock(
        return_value=httpx.Response(200, json=CH_PSC_2)
    )


def test_ch_without_key_logs_skip_returns_empty_and_makes_no_http_call():
    agent, g, origin = _agent_with_origin()
    with respx.mock(assert_all_called=False) as router:
        catch_all = router.route().mock(return_value=httpx.Response(200, json={}))
        result = _run(agent.investigate_companies_house_psc("Acme Holdings", origin, 1))
    assert result == []
    assert catch_all.call_count == 0
    skips = [e for e in g.logs if e.action == "UK_PSC_SKIP"]
    assert skips and "COMPANIES_HOUSE_API_KEY not set" in skips[0].detail
    assert not _new_nodes(g, origin)


def test_ch_whitespace_only_key_counts_as_no_key(monkeypatch: pytest.MonkeyPatch):
    agent, g, origin = _agent_with_origin()
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "   ")
    with respx.mock(assert_all_called=False) as router:
        catch_all = router.route().mock(return_value=httpx.Response(200, json={}))
        assert _run(agent.investigate_companies_house_psc("Acme Holdings", origin, 1)) == []
    assert catch_all.call_count == 0


def test_ch_happy_path_nodes_edges_receipts_and_owner_dicts(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "test-key-123")
    agent, g, origin = _agent_with_origin()
    with respx.mock as router:
        _mock_ch_ok(router)
        search_route = router.routes[0]
        owners = _run(agent.investigate_companies_house_psc("Acme Holdings", origin, 1))

        # HTTP basic auth: API key as username, empty password; search is capped at 3 results.
        req = search_route.calls.last.request
        assert req.headers["authorization"] == "Basic " + base64.b64encode(b"test-key-123:").decode()
        assert req.url.params["q"] == "Acme Holdings"
        assert req.url.params["items_per_page"] == "3"

    by_parent = {o["parent_name"]: o for o in owners}
    # The ceased PSC is not a current owner; the hostile company number was never fetched.
    assert set(by_parent) == {"Mr Jane Q Doe", "Shell Parent Ltd", "Beta Trust Corp", "Control Only Person"}
    assert by_parent["Mr Jane Q Doe"]["pct"] == 62.5
    assert by_parent["Shell Parent Ltd"]["pct"] == 37.5
    assert by_parent["Beta Trust Corp"]["pct"] == 87.5
    assert by_parent["Control Only Person"]["pct"] is None
    assert by_parent["Mr Jane Q Doe"]["is_natural_person"] is True
    assert by_parent["Shell Parent Ltd"]["is_natural_person"] is False
    assert by_parent["Mr Jane Q Doe"]["as_of"] == "2016-04-06"
    assert all(o["source"].startswith("https://") for o in owners)
    assert all(isinstance(o["pct"], float) or o["pct"] is None for o in owners)

    company_nodes = [n for nid, n in g.nodes.items() if nid.startswith("company:uk:")]
    assert {n.id for n in company_nodes} == {"company:uk:01234567", "company:uk:07654321"}
    for node in g.nodes.values():
        if node.id == origin:
            continue
        assert node.selector_strength == SelectorStrength.SOFT
        assert "SOFT_NAME_MATCH_VERIFY" in node.risk_flags
        assert node.receipts and all(r.admiralty_code == "B2" for r in node.receipts)
        assert all(r.tool == "companies_house" for r in node.receipts)
        assert all(r.source_url.startswith("https://") for r in node.receipts)

    for edge in g.edges.values():
        assert edge.confidence <= 0.55
        assert edge.receipts

    # origin -> company soft link exists, and PSC -> company ownership edges exist.
    relations = {(e.source_id, e.target_id, e.relation) for e in g.edges.values()}
    assert (origin, "company:uk:01234567", RelationType.LINKED_IDENTITY) in relations
    assert any(r == RelationType.OWNS and t == "company:uk:01234567" for _, t, r in relations)


def test_ch_returned_dicts_carry_ids_for_ownership_walker(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "k")
    agent, g, origin = _agent_with_origin()
    with respx.mock as router:
        _mock_ch_ok(router)
        owners = _run(agent.investigate_companies_house_psc("Acme Holdings", origin, 1))
    assert owners
    for o in owners:
        assert o["parent_id"] in g.nodes
        assert o["child_id"] in {"company:uk:01234567", "company:uk:07654321"}


@pytest.mark.parametrize("status", [401, 403])
def test_ch_rejected_key_is_clean_skip(monkeypatch: pytest.MonkeyPatch, status: int):
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "bad")
    agent, g, origin = _agent_with_origin()
    with respx.mock as router:
        router.route(host=CH_HOST, path="/search/companies").mock(return_value=httpx.Response(status))
        assert _run(agent.investigate_companies_house_psc("Acme Holdings", origin, 1)) == []
    assert "UK_PSC_SKIP" in _actions(g)
    assert not _new_nodes(g, origin)


def test_ch_psc_fetch_failure_for_one_company_does_not_lose_the_other(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "k")
    agent, g, origin = _agent_with_origin()
    with respx.mock as router:
        router.route(host=CH_HOST, path="/search/companies").mock(return_value=httpx.Response(200, json=CH_SEARCH))
        router.route(host=CH_HOST, path="/company/01234567/persons-with-significant-control").mock(
            return_value=httpx.Response(500)
        )
        router.route(host=CH_HOST, path="/company/07654321/persons-with-significant-control").mock(
            return_value=httpx.Response(200, json=CH_PSC_2)
        )
        owners = _run(agent.investigate_companies_house_psc("Acme Holdings", origin, 1))
    assert {o["parent_name"] for o in owners} == {"Beta Trust Corp", "Control Only Person"}
    assert "UK_PSC_SKIP" in _actions(g)  # the failed company is visible, not silent


def test_ch_company_without_matching_name_flag_still_soft(monkeypatch: pytest.MonkeyPatch):
    """Even an exact title match stays soft: a registry name is not proof of the same real-world entity."""
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "k")
    agent, g, origin = _agent_with_origin("ACME HOLDINGS LIMITED")
    with respx.mock as router:
        _mock_ch_ok(router)
        _run(agent.investigate_companies_house_psc("ACME HOLDINGS LIMITED", origin, 1))
    edge = next(e for e in g.edges.values() if e.source_id == origin)
    assert edge.confidence <= 0.55


def test_ch_ceased_psc_recorded_with_flag_but_not_returned(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "k")
    agent, g, origin = _agent_with_origin()
    with respx.mock as router:
        _mock_ch_ok(router)
        owners = _run(agent.investigate_companies_house_psc("Acme Holdings", origin, 1))
    assert "Old Holder" not in {o["parent_name"] for o in owners}
    ceased = [n for n in g.nodes.values() if n.label.endswith("Old Holder") or n.label == "Old Holder"]
    assert ceased and "CEASED_PSC" in ceased[0].risk_flags


def test_ch_short_query_is_a_noop(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "k")
    agent, g, origin = _agent_with_origin()
    with respx.mock(assert_all_called=False) as router:
        catch_all = router.route().mock(return_value=httpx.Response(200, json={}))
        assert _run(agent.investigate_companies_house_psc("ab", origin, 1)) == []
    assert catch_all.call_count == 0


# ----------------------------------------------------------------------------------------------
# GAC SEMA sanctions (synthetic fixture with the real element names)
# ----------------------------------------------------------------------------------------------

SEMA_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<data-set xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
\t<record>
\t\t<Country-Pays>Belarus / Bélarus</Country-Pays>
\t\t<LastName-NomDeFamille>Balaba</LastName-NomDeFamille>
\t\t<GivenName-Prenom>Dmitry Vladimirovich</GivenName-Prenom>
\t\t<DateOfBirthOrShipBuildDate-DateDeNaissanceOuDateDeConstructionDuNavire>1972</DateOfBirthOrShipBuildDate-DateDeNaissanceOuDateDeConstructionDuNavire>
\t\t<Schedule-Annexe>1, Part 1</Schedule-Annexe>
\t\t<Item-NumeroDarticle>2</Item-NumeroDarticle>
\t\t<DateOfListing-DateDinscription>2020-09-28</DateOfListing-DateDinscription>
\t</record>
\t<record>
\t\t<Country-Pays>Belarus / Bélarus</Country-Pays>
\t\t<EntityOrShip-EntiteOuNavire>LLC Aktualnye Resheniya Bezopasnosti</EntityOrShip-EntiteOuNavire>
\t\t<Aliases-Alias>Aktualnye Reshenia Security Group</Aliases-Alias>
\t\t<Schedule-Annexe>1, Part 2</Schedule-Annexe>
\t\t<Item-NumeroDarticle>41</Item-NumeroDarticle>
\t\t<DateOfListing-DateDinscription>2022-11-17</DateOfListing-DateDinscription>
\t</record>
\t<record>
\t\t<Country-Pays>Russia / Russie</Country-Pays>
\t\t<LastName-NomDeFamille>Oleksin</LastName-NomDeFamille>
\t\t<GivenName-Prenom>Aleksey</GivenName-Prenom>
\t\t<Aliases-Alias>Aliaksei Aleksin</Aliases-Alias>
\t\t<Schedule-Annexe>1, Part 1</Schedule-Annexe>
\t\t<Item-NumeroDarticle>56</Item-NumeroDarticle>
\t\t<DateOfListing-DateDinscription>2021-06-17</DateOfListing-DateDinscription>
\t</record>
\t<record>
\t\t<Country-Pays>Russia / Russie</Country-Pays>
\t\t<EntityOrShip-EntiteOuNavire>SEA STAR</EntityOrShip-EntiteOuNavire>
\t\t<ShipIMONumber-NumeroOMIDuNavire>9999999</ShipIMONumber-NumeroOMIDuNavire>
\t\t<TitleOrShipType-TitreOuTypeDeNavire>Oil tanker</TitleOrShipType-TitreOuTypeDeNavire>
\t\t<Schedule-Annexe>1, Part 2</Schedule-Annexe>
\t\t<Item-NumeroDarticle>99</Item-NumeroDarticle>
\t\t<DateOfListing-DateDinscription>2023-02-24</DateOfListing-DateDinscription>
\t</record>
</data-set>
"""

BILLION_LAUGHS = (
    '<?xml version="1.0"?>\n<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>\n'
    "<data-set><record><LastName-NomDeFamille>&lol2;</LastName-NomDeFamille></record></data-set>"
)


def _gac_ok(router: respx.MockRouter, xml: str = SEMA_XML) -> respx.Route:
    return router.route(host=GAC_HOST, path=GAC_PATH).mock(
        return_value=httpx.Response(200, content=xml.encode("utf-8"), headers={"content-type": "text/xml"})
    )


def test_gac_person_match_is_soft_with_official_source_and_receipt():
    agent, g, origin = _agent_with_origin("Dmitry Balaba")
    with respx.mock as router:
        _gac_ok(router)
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
    nodes = _new_nodes(g, origin)
    assert len(nodes) == 1
    node = next(iter(nodes.values()))
    assert node.id.startswith("sanction:ca:")
    assert node.entity_type == EntityType.PERSON
    assert node.selector_strength == SelectorStrength.SOFT
    assert "SOFT_NAME_MATCH_VERIFY" in node.risk_flags
    assert "CANADA_SEMA_SANCTIONS_LIST_MATCH" in node.risk_flags
    rcpt = node.receipts[0]
    assert rcpt.tool == "gac_sema_sanctions"
    assert rcpt.source_url.startswith("https://www.international.gc.ca/")
    assert rcpt.admiralty_code == "B2"
    assert rcpt.selector_strength == SelectorStrength.SOFT
    assert "Part 1" in rcpt.extracted_fact and "Belarus" in rcpt.extracted_fact
    edge = next(iter(g.edges.values()))
    assert edge.source_id == origin and edge.target_id == node.id
    assert edge.relation == RelationType.LINKED_IDENTITY
    assert edge.confidence <= 0.55 and edge.receipts


def test_gac_entity_and_alias_matching():
    agent, g, origin = _agent_with_origin("Aktualnye Resheniya")
    with respx.mock as router:
        _gac_ok(router)
        _run(agent.screen_canadian_sanctions("Aktualnye Resheniya Bezopasnosti", origin, 1))
    nodes = _new_nodes(g, origin)
    assert len(nodes) == 1
    assert next(iter(nodes.values())).entity_type == EntityType.ORGANIZATION

    # A match through an alias only.
    agent2, g2, origin2 = _agent_with_origin("Aliaksei Aleksin")
    with respx.mock as router:
        _gac_ok(router)
        _run(agent2.screen_canadian_sanctions("Aliaksei Aleksin", origin2, 1))
    assert len(_new_nodes(g2, origin2)) == 1


def test_gac_ship_records_are_matched_by_name():
    agent, g, origin = _agent_with_origin("Sea Star")
    with respx.mock as router:
        _gac_ok(router)
        _run(agent.screen_canadian_sanctions("SEA STAR", origin, 1))
    assert len(_new_nodes(g, origin)) == 1


def test_gac_no_match_is_negative_not_error():
    agent, g, origin = _agent_with_origin("Nobody Special")
    with respx.mock as router:
        _gac_ok(router)
        _run(agent.screen_canadian_sanctions("Nobody Special", origin, 1))
    assert not _new_nodes(g, origin)
    assert "CA_SANCTIONS_INFO" in _actions(g)


def test_gac_single_common_token_does_not_match_full_name():
    agent, g, origin = _agent_with_origin("Balaba")
    with respx.mock as router:
        _gac_ok(router)
        _run(agent.screen_canadian_sanctions("Balaba", origin, 1))
    assert not _new_nodes(g, origin)


def test_gac_downloads_once_per_process_across_queries_and_agents():
    agent, g, origin = _agent_with_origin("Dmitry Balaba")
    other_agent, g2, origin2 = _agent_with_origin("Aliaksei Aleksin")
    with respx.mock as router:
        route = _gac_ok(router)
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
        _run(agent.screen_canadian_sanctions("Nobody Special", origin, 1))
        _run(other_agent.screen_canadian_sanctions("Aliaksei Aleksin", origin2, 1))
        assert route.call_count == 1
    assert len(_new_nodes(g2, origin2)) == 1


@pytest.mark.parametrize(
    "payload",
    [
        BILLION_LAUGHS,
        '<?xml version="1.0"?><!doctype x [<!entity a "b">]><data-set/>',
        '<?xml version="1.0"?><data-set><!ENTITY a "b"></data-set>',
    ],
)
def test_gac_refuses_dtd_and_entity_payloads_before_parsing(payload: str, monkeypatch: pytest.MonkeyPatch):
    parser_calls: List[int] = []

    def spy(*_a: Any, **_k: Any) -> Any:
        parser_calls.append(1)
        raise ValueError("parser reached")

    monkeypatch.setattr(pi_sources.ET, "fromstring", spy)
    agent, g, origin = _agent_with_origin("Dmitry Balaba")
    with respx.mock as router:
        _gac_ok(router, payload)
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
    assert parser_calls == [], "a DTD/entity payload must be refused before it is parsed"
    assert not _new_nodes(g, origin)
    skips = [e for e in g.logs if e.action == "CA_SANCTIONS_SKIP"]
    assert skips and "DOCTYPE/ENTITY" in skips[0].detail


def test_gac_refuses_nul_byte_payload_that_could_hide_a_doctype():
    agent, g, origin = _agent_with_origin("Dmitry Balaba")
    hidden = "<?xml version='1.0'?><!DOCTYPE x>".encode("utf-16-le")
    with respx.mock as router:
        router.route(host=GAC_HOST, path=GAC_PATH).mock(return_value=httpx.Response(200, content=hidden))
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
    assert not _new_nodes(g, origin)
    assert "CA_SANCTIONS_SKIP" in _actions(g)


def test_gac_rejects_oversized_declared_content_length():
    agent, g, origin = _agent_with_origin("Dmitry Balaba")
    with respx.mock as router:
        router.route(host=GAC_HOST, path=GAC_PATH).mock(
            return_value=httpx.Response(200, content=b"<data-set/>", headers={"content-length": str(11 * 1024 * 1024)})
        )
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
    skips = [e for e in g.logs if e.action == "CA_SANCTIONS_SKIP"]
    assert skips and "10 MB" in skips[0].detail


def test_gac_rejects_oversized_streamed_body_without_content_length():
    agent, g, origin = _agent_with_origin("Dmitry Balaba")

    async def chunks():
        for _ in range(11):
            yield b"x" * (1024 * 1024)

    with respx.mock as router:
        router.route(host=GAC_HOST, path=GAC_PATH).mock(return_value=httpx.Response(200, content=chunks()))
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
    skips = [e for e in g.logs if e.action == "CA_SANCTIONS_SKIP"]
    assert skips and "10 MB" in skips[0].detail
    assert not _new_nodes(g, origin)


def test_gac_malformed_xml_is_clean_skip():
    agent, g, origin = _agent_with_origin("Dmitry Balaba")
    with respx.mock as router:
        _gac_ok(router, "<data-set><record>")
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
    assert not _new_nodes(g, origin)
    assert "CA_SANCTIONS_SKIP" in _actions(g)


def test_gac_failure_is_cooled_down_then_retried():
    agent, g, origin = _agent_with_origin("Dmitry Balaba")
    with respx.mock as router:
        route = router.route(host=GAC_HOST, path=GAC_PATH).mock(return_value=httpx.Response(500))
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
        assert route.call_count == 1  # second call is inside the cooldown: no repeat download

        PISourcesAgent._sema_failed_at = time.monotonic() - 10_000  # cooldown elapsed
        route.mock(return_value=httpx.Response(200, content=SEMA_XML.encode("utf-8")))
        _run(agent.screen_canadian_sanctions("Dmitry Balaba", origin, 1))
        assert route.call_count == 2
    assert len(_new_nodes(g, origin)) == 1


def test_gac_short_query_is_a_noop():
    agent, g, origin = _agent_with_origin()
    with respx.mock(assert_all_called=False) as router:
        route = _gac_ok(router)
        _run(agent.screen_canadian_sanctions("ab", origin, 1))
    assert route.call_count == 0


# ----------------------------------------------------------------------------------------------
# CFPB complaints
# ----------------------------------------------------------------------------------------------

CFPB_PATH = "/data-research/consumer-complaints/search/api/v1/"


def _cfpb_body(total: int = 42) -> Dict[str, Any]:
    def hit(issue: str, product: str, state: str, date: str, company: str = "ACME BANK, N.A.") -> Dict[str, Any]:
        return {
            "_source": {
                "company": company,
                "issue": issue,
                "product": product,
                "state": state,
                "date_received": date,
            }
        }

    return {
        "hits": {
            "total": {"value": total, "relation": "eq"},
            "hits": [
                hit("Problem with a purchase shown on your statement", "Credit card", "NY", "2024-01-05"),
                hit("Problem with a purchase shown on your statement", "Credit card", "CA", "2024-02-09"),
                hit("Managing an account", "Checking account", "TX", "2023-12-01"),
                hit("Incorrect information on your report", "Credit reporting", "FL", "2023-11-11", "OTHER CO"),
            ],
        }
    }


def test_cfpb_happy_path_summarises_count_and_top_issues_flagged_unverified():
    agent, g, origin = _agent_with_origin("Acme Bank")
    with respx.mock as router:
        route = router.route(host=CFPB_HOST, path=CFPB_PATH).mock(return_value=httpx.Response(200, json=_cfpb_body()))
        _run(agent.investigate_cfpb_complaints("Acme Bank", origin, 1))
        params = route.calls.last.request.url.params
        assert params["search_term"] == "Acme Bank"
        assert params["size"] == "5"
        assert params["no_aggs"] == "true"
    nodes = _new_nodes(g, origin)
    assert len(nodes) == 1
    node = next(iter(nodes.values()))
    assert "UNVERIFIED_CONSUMER_CLAIMS" in node.risk_flags
    assert node.selector_strength == SelectorStrength.SOFT
    assert node.attributes["total_hits"] == 42
    assert node.attributes["top_issues"][0] == "Problem with a purchase shown on your statement"
    assert "42" in node.label or "42" in node.receipts[0].extracted_fact
    rcpt = node.receipts[0]
    assert rcpt.tool == "cfpb_complaints"
    assert rcpt.source_url.startswith("https://www.consumerfinance.gov/")
    assert "unverified" in rcpt.extracted_fact.lower()
    # A hit whose company field is a different firm is not attributed to the target.
    assert "Incorrect information on your report" not in node.attributes["top_issues"]
    edge = next(iter(g.edges.values()))
    assert edge.source_id == origin and edge.confidence <= 0.55


def test_cfpb_zero_hits_is_negative():
    agent, g, origin = _agent_with_origin("Acme Bank")
    body = {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}
    with respx.mock as router:
        router.route(host=CFPB_HOST, path=CFPB_PATH).mock(return_value=httpx.Response(200, json=body))
        _run(agent.investigate_cfpb_complaints("Acme Bank", origin, 1))
    assert not _new_nodes(g, origin)
    assert "CFPB_COMPLAINTS_INFO" in _actions(g)


def test_cfpb_hits_for_other_companies_only_is_negative():
    agent, g, origin = _agent_with_origin("Acme Bank")
    body = _cfpb_body()
    for h in body["hits"]["hits"]:
        h["_source"]["company"] = "SOMEONE ELSE INC"
    with respx.mock as router:
        router.route(host=CFPB_HOST, path=CFPB_PATH).mock(return_value=httpx.Response(200, json=body))
        _run(agent.investigate_cfpb_complaints("Acme Bank", origin, 1))
    assert not _new_nodes(g, origin)


def test_cfpb_short_query_is_a_noop():
    agent, g, origin = _agent_with_origin()
    with respx.mock(assert_all_called=False) as router:
        route = router.route(host=CFPB_HOST).mock(return_value=httpx.Response(200, json={}))
        _run(agent.investigate_cfpb_complaints("ab", origin, 1))
    assert route.call_count == 0


# ----------------------------------------------------------------------------------------------
# Wikidata
# ----------------------------------------------------------------------------------------------

WD_BODY = {
    "search": [
        {
            "id": "Q95",
            "label": "Google",
            "description": "American technology company",
            "concepturi": "http://www.wikidata.org/entity/Q95",
        },
        {
            "id": "Q1234",
            "label": "Google Ireland",
            "description": "Irish subsidiary",
            "concepturi": "http://www.wikidata.org/entity/Q1234",
        },
        {"id": "garbage-id", "label": "x", "description": "bad id must be dropped"},
    ]
}


def test_wikidata_happy_path_records_qid_url_description_and_caveat():
    agent, g, origin = _agent_with_origin("Google")
    with respx.mock as router:
        route = router.route(host=WD_HOST, path="/w/api.php").mock(return_value=httpx.Response(200, json=WD_BODY))
        _run(agent.investigate_wikidata_entity("Google", origin, 1))
        req = route.calls.last.request
        assert req.url.params["action"] == "wbsearchentities"
        assert req.url.params["search"] == "Google"
        assert req.url.params["limit"] == "3"
        assert req.url.params["format"] == "json"
        assert "bunnyhole" in req.headers["user-agent"].lower()
    nodes = _new_nodes(g, origin)
    assert set(nodes) == {"wikidata:Q95", "wikidata:Q1234"}  # malformed id dropped
    node = nodes["wikidata:Q95"]
    assert node.attributes["qid"] == "Q95"
    assert node.attributes["description"] == "American technology company"
    assert node.selector_strength == SelectorStrength.SOFT
    assert "ENTITY_RESOLUTION_AID_VERIFY" in node.risk_flags
    rcpt = node.receipts[0]
    assert rcpt.tool == "wikidata"
    assert rcpt.source_url == "https://www.wikidata.org/wiki/Q95"
    assert "primary registry" in rcpt.extracted_fact.lower()
    assert rcpt.admiralty_code[0] in "CD"  # community-edited: never rated above C
    for edge in g.edges.values():
        assert edge.confidence <= 0.55


def test_wikidata_empty_result_is_negative_and_api_error_body_is_skip():
    agent, g, origin = _agent_with_origin("Zzyzx Corp")
    with respx.mock as router:
        router.route(host=WD_HOST, path="/w/api.php").mock(return_value=httpx.Response(200, json={"search": []}))
        _run(agent.investigate_wikidata_entity("Zzyzx Corp", origin, 1))
    assert not _new_nodes(g, origin)
    assert "WIKIDATA_INFO" in _actions(g)

    agent2, g2, origin2 = _agent_with_origin("Zzyzx Corp")
    with respx.mock as router:
        router.route(host=WD_HOST, path="/w/api.php").mock(
            return_value=httpx.Response(200, json={"error": {"code": "maxlag", "info": "slow"}})
        )
        _run(agent2.investigate_wikidata_entity("Zzyzx Corp", origin2, 1))
    assert not _new_nodes(g2, origin2)
    assert "WIKIDATA_SKIP" in _actions(g2)


def test_wikidata_short_query_is_a_noop():
    agent, g, origin = _agent_with_origin()
    with respx.mock(assert_all_called=False) as router:
        route = router.route(host=WD_HOST).mock(return_value=httpx.Response(200, json={}))
        _run(agent.investigate_wikidata_entity("ab", origin, 1))
    assert route.call_count == 0


# ----------------------------------------------------------------------------------------------
# Every source: no failure mode may raise, and each leaves a visible skip, never a node
# ----------------------------------------------------------------------------------------------

FailureMode = Tuple[str, Any]
FAILURES: List[FailureMode] = [
    ("http_500", httpx.Response(500, text="boom")),
    ("http_429", httpx.Response(429)),
    ("http_401", httpx.Response(401)),
    ("http_403", httpx.Response(403)),
    ("bad_json", httpx.Response(200, content=b"{not json", headers={"content-type": "application/json"})),
    ("wrong_shape", httpx.Response(200, json=["a", "list", "not", "an", "object"])),
    ("timeout", httpx.ReadTimeout("slow")),
    ("connect_error", httpx.ConnectError("refused")),
    ("empty_body", httpx.Response(200, content=b"")),
]

SOURCES: List[Tuple[str, str, str, str, str]] = [
    # (method, query, host, path, skip action)
    ("investigate_companies_house_psc", "Acme Holdings", CH_HOST, "/search/companies", "UK_PSC_SKIP"),
    ("screen_canadian_sanctions", "Dmitry Balaba", GAC_HOST, GAC_PATH, "CA_SANCTIONS_SKIP"),
    ("investigate_cfpb_complaints", "Acme Bank", CFPB_HOST, CFPB_PATH, "CFPB_COMPLAINTS_SKIP"),
    ("investigate_wikidata_entity", "Google", WD_HOST, "/w/api.php", "WIKIDATA_SKIP"),
]


@pytest.mark.parametrize("failure_name,failure", FAILURES, ids=[f[0] for f in FAILURES])
@pytest.mark.parametrize("method,query,host,path,skip_action", SOURCES, ids=[s[0] for s in SOURCES])
def test_no_source_ever_raises_and_failures_leave_no_nodes(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    query: str,
    host: str,
    path: str,
    skip_action: str,
    failure_name: str,
    failure: Any,
):
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "k")
    agent, g, origin = _agent_with_origin(query)
    with respx.mock as router:
        route = router.route(host=host, path=path)
        if isinstance(failure, Exception):
            route.mock(side_effect=failure)
        else:
            route.mock(return_value=failure)
        result = _run(getattr(agent, method)(query, origin, 1))  # must not raise
    if method == "investigate_companies_house_psc":
        assert result == []
    else:
        assert result is None
    assert not _new_nodes(g, origin), f"{failure_name} must not create nodes"
    # Every failure is visible as a logged skip or a logged negative, never silent.
    assert any(e.action in (skip_action, skip_action.replace("_SKIP", "_INFO")) for e in g.logs)


# ----------------------------------------------------------------------------------------------
# netutil / proxy conventions
# ----------------------------------------------------------------------------------------------


def test_all_sources_build_their_client_through_netutil(monkeypatch: pytest.MonkeyPatch):
    """--tor/--proxy only work if every outbound call goes through netutil.new_async_client."""
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "k")
    built: List[Dict[str, Any]] = []
    real = netutil.new_async_client

    def spy(**kwargs: Any) -> httpx.AsyncClient:
        built.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(pi_sources, "new_async_client", spy)
    agent, g, origin = _agent_with_origin("Acme Holdings")
    with respx.mock as router:
        router.route(host=CH_HOST).mock(return_value=httpx.Response(200, json={"items": []}))
        router.route(host=GAC_HOST).mock(return_value=httpx.Response(200, content=SEMA_XML.encode("utf-8")))
        router.route(host=CFPB_HOST).mock(return_value=httpx.Response(200, json={"hits": {"hits": []}}))
        router.route(host=WD_HOST).mock(return_value=httpx.Response(200, json={"search": []}))
        _run(agent.investigate_companies_house_psc("Acme Holdings", origin, 1))
        _run(agent.screen_canadian_sanctions("Acme Holdings", origin, 1))
        _run(agent.investigate_cfpb_complaints("Acme Holdings", origin, 1))
        _run(agent.investigate_wikidata_entity("Acme Holdings", origin, 1))
    assert len(built) == 4
    assert all("timeout" in kw for kw in built)
    # Redirects stay off (netutil default): a registry must not bounce us to another host.
    assert not any(kw.get("follow_redirects") for kw in built)


def test_default_proxy_is_inherited_by_the_clients(monkeypatch: pytest.MonkeyPatch):
    netutil.set_default_proxy("http://127.0.0.1:8899")
    seen: List[Dict[str, Any]] = []
    real_client = httpx.AsyncClient

    def recording_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        seen.append(dict(kwargs))
        return real_client(*args, **kwargs)

    monkeypatch.setattr(netutil.httpx, "AsyncClient", recording_client)
    agent, g, origin = _agent_with_origin("Google")
    _run(agent.investigate_wikidata_entity("Google", origin, 1))  # may fail to connect: must still not raise
    assert seen and seen[0].get("proxy") == "http://127.0.0.1:8899"
