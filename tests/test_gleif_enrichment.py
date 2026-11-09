"""GLEIF enrichment: the LEI node carries the registry facts the PI entity profile reads.

All HTTP is mocked with respx. ``AccountantAgent.investigate_gleif_corporate_hierarchy`` keeps its node ids, edges
and confidence; it adds registration status, legal form, a joined headquarters address and the Level-2 reporting
exceptions (why an entity reports no parent) as plain-string node attributes. Every new request degrades to a logged
skip: a 404 means "none", and a 5xx, a timeout or an unmocked route never raises or removes the node.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, List, Optional

import httpx
import pytest
import respx

from bunnyhole.agents import accountant as accountant_module
from bunnyhole.agents.accountant import AccountantAgent
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EntityType, GraphNode, SelectorStrength
from bunnyhole.engine.pi import CaseType, PIEngagement
from bunnyhole.engine.pi_runtime import assemble_pi_block

API = "https://api.gleif.org/api/v1"
SEARCH = rf"^{API}/lei-records\?"
LEI = "W7L3VLU8EHQY34Z36697"
ROSNEFT_LEI = "253400JT3MQWNDKMJE44"
NOW = "2026-11-09T00:00:00+00:00"


def _record(lei: str = LEI, name: str = "BOMBARDIER INC.", *, country: str = "CA", city: str = "Dorval",
            lines: Optional[List[str]] = None, status: Optional[str] = "ACTIVE",
            registration: Optional[Dict[str, Any]] = None, sparse: bool = False) -> Dict[str, Any]:
    address = {"addressLines": lines or ["400, chemin de la Cote-Vertu Ouest"], "city": city, "country": country}
    entity: Dict[str, Any] = {
        "legalName": {"name": name}, "jurisdiction": f"{country}-QC" if country == "CA" else country,
        "legalAddress": dict(address), "headquartersAddress": dict(address, addressLines=["400 Cote-Vertu Ouest"]),
        "legalForm": {"id": "UG3Z", "other": None},
    }
    if status:
        entity["status"] = status
    attributes: Dict[str, Any] = {"entity": entity}
    if not sparse:
        attributes["registration"] = registration or {"status": "ISSUED"}
    return {"id": lei, "type": "lei-records", "attributes": attributes}


def _exception(lei: str, level: str, reason: str) -> Dict[str, Any]:
    return {"data": {"type": "reporting-exceptions", "id": f"{lei}|{level}", "attributes": {
        "lei": lei, "category": f"{level}_ACCOUNTING_CONSOLIDATION_PARENT", "reason": reason, "reference": None}}}


def _agent(seed: str = "Bombardier Inc") -> tuple[AccountantAgent, InvestigationGraph, str]:
    graph = InvestigationGraph("test_gleif_enrichment", seed)
    origin = GraphNode(id="org:origin", label=seed, entity_type=EntityType.ORGANIZATION,
                       domain=DomainCategory.FIAT, selector_strength=SelectorStrength.SOFT)
    graph.upsert_node(origin)
    return AccountantAgent(graph), graph, origin.id


def _run(agent: AccountantAgent, origin: str, name: str = "Bombardier Inc") -> None:
    asyncio.run(agent.investigate_gleif_corporate_hierarchy(name, origin, 1))


def _mock_all(router: respx.MockRouter, records: List[Dict[str, Any]], *, lei: str = LEI,
              ultimate: Callable[[], httpx.Response] = lambda: httpx.Response(404),
              ultimate_exc: Callable[[], httpx.Response] = lambda: httpx.Response(404),
              direct_exc: Callable[[], httpx.Response] = lambda: httpx.Response(404)) -> None:
    router.get(url__regex=SEARCH).mock(return_value=httpx.Response(200, json={"data": records}))
    router.get(f"{API}/lei-records/{lei}/ultimate-parent").mock(side_effect=lambda _r: ultimate())
    router.get(f"{API}/lei-records/{lei}/ultimate-parent-reporting-exception").mock(side_effect=lambda _r: ultimate_exc())
    router.get(f"{API}/lei-records/{lei}/direct-parent-reporting-exception").mock(side_effect=lambda _r: direct_exc())


def _json(payload: Dict[str, Any]) -> Callable[[], httpx.Response]:
    return lambda: httpx.Response(200, json=payload)


def _node_attrs(graph: InvestigationGraph, lei: str = LEI) -> Dict[str, Any]:
    return graph.nodes[f"lei:{lei}"].attributes


def _skips(graph: InvestigationGraph) -> List[str]:
    return [e.detail for e in graph.logs if e.action == "GLEIF_ENRICH_SKIP"]


# ---------------------------------------------------------------- happy path


def test_enrichment_writes_registry_facts_and_reporting_exceptions_onto_the_lei_node():
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record()],
                  ultimate_exc=_json(_exception(LEI, "ULTIMATE", "NON_CONSOLIDATING")),
                  direct_exc=_json(_exception(LEI, "DIRECT", "NON_CONSOLIDATING")))
        _run(agent, origin)
    attrs = _node_attrs(graph)
    assert attrs["status"] == "ACTIVE"
    assert attrs["registration_status"] == "ISSUED"
    assert attrs["legal_form"] == "UG3Z"
    assert attrs["headquarters_address"] == "400 Cote-Vertu Ouest, Dorval, CA"
    assert attrs["registered_address"] == "400, chemin de la Cote-Vertu Ouest, Dorval, CA"
    # The Level-2 exception is stored as the plain reason string the PI entity profile reads.
    assert attrs["ultimate_parent_exception"] == "NON_CONSOLIDATING"
    assert attrs["direct_parent_exception"] == "NON_CONSOLIDATING"
    assert _skips(graph) == []


def test_node_ids_edges_confidence_and_existing_attributes_are_unchanged():
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record()], ultimate_exc=_json(_exception(LEI, "ULTIMATE", "NO_KNOWN_PERSON")))
        _run(agent, origin)
    assert set(graph.nodes) == {origin, f"lei:{LEI}", "loc:400_chemin_de_la_cote_vertu_ouest_dorval_ca"}
    attrs = _node_attrs(graph)
    assert {k: attrs[k] for k in ("lei", "legal_name", "jurisdiction", "hq_city", "hq_country")} == {
        "lei": LEI, "legal_name": "BOMBARDIER INC.", "jurisdiction": "CA-QC", "hq_city": "Dorval", "hq_country": "CA"}
    edges = {(e.source_id, e.target_id, e.relation.value): e.confidence for e in graph.edges.values()}
    assert edges[(origin, f"lei:{LEI}", "LINKED_IDENTITY")] == 0.95
    assert edges[(f"lei:{LEI}", "loc:400_chemin_de_la_cote_vertu_ouest_dorval_ca", "REGISTERED_AT")] == 0.90


def test_the_exception_attribute_is_the_reason_not_the_parent_level_category():
    """GLEIF's ``category`` names the parent level (ULTIMATE_ACCOUNTING_CONSOLIDATION_PARENT); ``reason`` is the exception."""
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record()], ultimate_exc=_json(_exception(LEI, "ULTIMATE", "NATURAL_PERSONS")))
        _run(agent, origin)
    assert _node_attrs(graph)["ultimate_parent_exception"] == "NATURAL_PERSONS"
    assert "direct_parent_exception" not in _node_attrs(graph)


def test_only_one_exception_present_writes_only_that_key():
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record()], direct_exc=_json(_exception(LEI, "DIRECT", "NO_LEI")))
        _run(agent, origin)
    attrs = _node_attrs(graph)
    assert attrs["direct_parent_exception"] == "NO_LEI" and "ultimate_parent_exception" not in attrs


# ---------------------------------------------------------------- 404 means none; failures degrade to skips


def test_404_on_both_exception_endpoints_means_none_and_is_not_a_skip():
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record()])
        _run(agent, origin)
    attrs = _node_attrs(graph)
    assert attrs["registration_status"] == "ISSUED" and attrs["headquarters_address"]
    assert "ultimate_parent_exception" not in attrs and "direct_parent_exception" not in attrs
    assert _skips(graph) == []


def test_500_on_exception_endpoints_is_a_logged_skip_and_the_node_survives():
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record()], ultimate_exc=lambda: httpx.Response(500), direct_exc=lambda: httpx.Response(503))
        _run(agent, origin)
    attrs = _node_attrs(graph)
    assert attrs["status"] == "ACTIVE" and attrs["registration_status"] == "ISSUED"
    assert "ultimate_parent_exception" not in attrs and "direct_parent_exception" not in attrs
    assert len(_skips(graph)) == 2 and any("500" in s for s in _skips(graph))


def test_timeout_on_exception_endpoints_is_a_logged_skip_and_the_node_survives():
    agent, graph, origin = _agent()

    def timeout() -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    with respx.mock as router:
        _mock_all(router, [_record()], ultimate_exc=timeout, direct_exc=timeout)
        _run(agent, origin)
    assert f"lei:{LEI}" in graph.nodes and _node_attrs(graph)["registration_status"] == "ISSUED"
    assert len(_skips(graph)) == 2


def test_unmocked_exception_routes_never_break_the_node():
    """An unmocked respx route raises; the enrichment catches it, so tests that mock only the old requests still pass."""
    agent, graph, origin = _agent()
    with respx.mock as router:
        router.get(url__regex=SEARCH).mock(return_value=httpx.Response(200, json={"data": [_record()]}))
        _run(agent, origin)
    assert f"lei:{LEI}" in graph.nodes
    assert _node_attrs(graph)["registration_status"] == "ISSUED"
    assert len(_skips(graph)) == 2


def test_a_malformed_exception_body_is_a_skip_not_an_attribute():
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record()], ultimate_exc=lambda: httpx.Response(200, text="<html>not json</html>"),
                  direct_exc=_json({"data": {"attributes": {"reason": "free text, not a category"}}}))
        _run(agent, origin)
    attrs = _node_attrs(graph)
    assert "ultimate_parent_exception" not in attrs and "direct_parent_exception" not in attrs
    assert len(_skips(graph)) >= 1


# ---------------------------------------------------------------- the ultimate-parent node is enriched too


def _parent_record() -> Dict[str, Any]:
    return _record(ROSNEFT_LEI, "Rosneft Oil Company PJSC", country="RU", city="Moscow", lines=["Sofiyskaya nab. 26/1"],
                   registration={"status": "ISSUED"})


def test_the_ultimate_parent_node_gets_status_address_and_its_own_reporting_exceptions():
    """The subject of a PI case is often the parent LEI found via a subsidiary; it must not stay a three-field stub."""
    agent, graph, origin = _agent("Rosneft Deutschland")
    child = _record("391200PKEUF3Y2NUMW25", "Rosneft Deutschland GmbH", country="DE", city="Berlin")
    with respx.mock as router:
        _mock_all(router, [child], lei="391200PKEUF3Y2NUMW25",
                  ultimate=lambda: httpx.Response(200, json={"data": _parent_record()}))
        router.get(f"{API}/lei-records/{ROSNEFT_LEI}/ultimate-parent-reporting-exception").mock(
            return_value=httpx.Response(200, json=_exception(ROSNEFT_LEI, "ULTIMATE", "NO_KNOWN_PERSON")))
        router.get(f"{API}/lei-records/{ROSNEFT_LEI}/direct-parent-reporting-exception").mock(
            return_value=httpx.Response(200, json=_exception(ROSNEFT_LEI, "DIRECT", "NO_KNOWN_PERSON")))
        _run(agent, origin, "Rosneft Deutschland")
    attrs = _node_attrs(graph, ROSNEFT_LEI)
    assert attrs["lei"] == ROSNEFT_LEI and attrs["jurisdiction"] == "RU" and attrs["legal_name"] == "Rosneft Oil Company PJSC"
    assert attrs["status"] == "ACTIVE" and attrs["registration_status"] == "ISSUED" and attrs["legal_form"] == "UG3Z"
    assert attrs["hq_city"] == "Moscow" and attrs["hq_country"] == "RU"
    assert attrs["registered_address"] == "Sofiyskaya nab. 26/1, Moscow, RU"
    assert attrs["headquarters_address"] == "400 Cote-Vertu Ouest, Moscow, RU"
    assert attrs["ultimate_parent_exception"] == "NO_KNOWN_PERSON" and attrs["direct_parent_exception"] == "NO_KNOWN_PERSON"
    # existing parent edge and flags are untouched
    assert graph.nodes[f"lei:{ROSNEFT_LEI}"].risk_flags == ["GLEIF_ULTIMATE_PARENT"]
    assert any(e.relation.value == "ULTIMATE_PARENT_OF" and e.confidence == 0.99 for e in graph.edges.values())


def test_a_failing_parent_exception_lookup_leaves_the_parent_node_in_place():
    agent, graph, origin = _agent("Rosneft Deutschland")
    child = _record("391200PKEUF3Y2NUMW25", "Rosneft Deutschland GmbH", country="DE", city="Berlin")
    with respx.mock as router:
        _mock_all(router, [child], lei="391200PKEUF3Y2NUMW25",
                  ultimate=lambda: httpx.Response(200, json={"data": _parent_record()}))
        # the parent's exception routes are not mocked at all
        _run(agent, origin, "Rosneft Deutschland")
    attrs = _node_attrs(graph, ROSNEFT_LEI)
    assert attrs["status"] == "ACTIVE" and "ultimate_parent_exception" not in attrs
    assert len(_skips(graph)) == 2


# ---------------------------------------------------------------- sparse search record -> one full-record fetch


def test_a_sparse_search_record_triggers_one_full_record_fetch():
    agent, graph, origin = _agent()
    full = _record()
    with respx.mock as router:
        _mock_all(router, [_record(status=None, sparse=True)])
        full_route = router.get(f"{API}/lei-records/{LEI}").mock(return_value=httpx.Response(200, json={"data": full}))
        _run(agent, origin)
    assert full_route.call_count == 1
    attrs = _node_attrs(graph)
    assert attrs["status"] == "ACTIVE" and attrs["registration_status"] == "ISSUED"


def test_a_complete_search_record_makes_no_extra_full_record_request():
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record()])
        full_route = router.get(f"{API}/lei-records/{LEI}").mock(return_value=httpx.Response(200, json={}))
        _run(agent, origin)
    assert full_route.call_count == 0


def test_a_failed_full_record_fetch_keeps_the_search_record_behaviour():
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record(status=None, sparse=True)])
        router.get(f"{API}/lei-records/{LEI}").mock(return_value=httpx.Response(500))
        _run(agent, origin)
    attrs = _node_attrs(graph)
    assert attrs["lei"] == LEI and "registration_status" not in attrs
    assert len(_skips(graph)) >= 1


# ---------------------------------------------------------------- proxy / tor routing


def test_requests_use_the_proxy_aware_client_factory(monkeypatch: pytest.MonkeyPatch):
    calls: List[Dict[str, Any]] = []
    real = accountant_module.new_async_client

    def spy(**kwargs: Any) -> httpx.AsyncClient:
        calls.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(accountant_module, "new_async_client", spy)
    agent, graph, origin = _agent()
    with respx.mock as router:
        _mock_all(router, [_record()])
        _run(agent, origin)
    assert len(calls) == 1 and calls[0]["headers"] == agent.std_headers
    assert f"lei:{LEI}" in graph.nodes


# ---------------------------------------------------------------- PI entity profile


def _engagement() -> PIEngagement:
    return PIEngagement(engagement_id="pi_0123456789", case_type=CaseType.DUE_DILIGENCE,
                        purpose="Vet a counterparty before signing a supply contract",
                        subject_is_person=False, created_at_utc=NOW)


@pytest.mark.parametrize(("reason", "meaning"), [
    ("NO_KNOWN_PERSON", "GLEIF: no known ultimate parent"),
    ("NON_CONSOLIDATING", "GLEIF: the entity is not consolidated by a parent"),
])
def test_the_pi_entity_profile_shows_status_address_and_the_reporting_exception(reason: str, meaning: str):
    agent, graph, origin = _agent("Bombardier Inc")
    with respx.mock as router:
        _mock_all(router, [_record()], ultimate_exc=_json(_exception(LEI, "ULTIMATE", reason)))
        _run(agent, origin)
    block = assemble_pi_block(_engagement(), graph.to_dict(), [], now_iso=NOW)
    profile = block.entity_profile
    assert profile is not None
    assert profile.lei == LEI
    assert profile.status == "ACTIVE"
    assert "Dorval" in profile.registered_address
    assert f"Reporting exception: {reason} ({meaning})" in profile.parents
